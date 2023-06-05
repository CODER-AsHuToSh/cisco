/*
 * A domain list is represented as a sorted list of reversed domain
 * names ("example.com" is stored as "moc.elpmaxe".) with all
 * subdomains removed (unless LOADFLAGS_DL_EXACT is given).
 * Together with a similarly-reversed search key and an appropriate
 * comparison routine, this makes it possible to test for membership
 * (either direct or as a subdomain) with bsearch().
 */

#include <ctype.h>
#include <errno.h>
#include <kit-alloc.h>
#include <mockfail.h>

#include "conf-loader.h"
#include "dns-name.h"
#include "domainlist-private.h"
#include "object-hash.h"
#include "uup-counters.h"
#include "xray.h"

#define CONSTCONF2DL(confp) (const struct domainlist *)((confp) ? (const char *)(confp) - offsetof(struct domainlist, conf) : NULL)
#define CONF2DL(confp)      (struct domainlist *)((confp) ? (char *)(confp) - offsetof(struct domainlist, conf) : NULL)

#define NAME_OFFSET(sz, val, i) ((sz) == 1 ? *((const uint8_t *)(val) + (i)) : (sz) == 2 ? *((const uint16_t *)(val) + (i)) : *((const uint32_t *)(val) + (i)))

#define DOMAINLIST_OBJECT_HASH_ROWS  (1 << 18)    /* 262,144 rows with 7 usable cells per row = 1,835,008 cells and 16MB RAM */
#define DOMAINLIST_OBJECT_HASH_LOCKS 32

enum domainlist_caller {
    DOMAINLIST_CALLER_BSEARCH,
    DOMAINLIST_CALLER_QSORT,
};

static __thread const char              *compar_name_bundle;      /* used by compar_*() & qsort()             */
static __thread unsigned                 compar_name_offset_size; /* 1, 2, or 4; see struct domainlist        */
static __thread enum  domainlist_caller  compar_caller;
static __thread enum  domainlist_match   compar_matchtype;

module_conf_t CONF_ADDR_NS;               // Probe for support of the Cloudflare ADDR query if your NS's domain matches
module_conf_t CONF_DNAT_NS;
module_conf_t CONF_DNS_TUNNELING_EXCLUSION;
module_conf_t CONF_DNSCRYPT_BLOCKLIST;
module_conf_t CONF_DOMAIN_ALLOWLIST;
module_conf_t CONF_DOMAIN_DROPLIST;
module_conf_t CONF_DOMAIN_FREEZELIST;
module_conf_t CONF_DO_NOT_PROXY;          // Don't proxy these high volume domains
module_conf_t CONF_REPORT_EXCLUSIONS;
module_conf_t CONF_SSL_DOMAIN_ALLOWLIST;
module_conf_t CONF_TYPO_EXCEPTIONS;
module_conf_t CONF_MINIMIZATION_EXCEPTIONS;
module_conf_t CONF_URL_PROXY;
module_conf_t CONF_URL_PROXY_HTTPS;

static struct conf *domainlist_allocate(const struct conf_info *info, struct conf_loader *cl);
static void domainlist_free(struct conf *base);

static const struct conf_type dlct = {
    "domainlist",
    domainlist_allocate,
    domainlist_free,
};
static const struct conf_type *dlctp = &dlct;

void
domainlist_get_real_type_internals(struct conf_type *copy)
{
    /* Only used by tests - to get the original domainlist type contents */
    *copy = dlct;
}

void
domainlist_set_type_internals(const struct conf_type *replacement)
{
    /* Only used by tests - to hijack the original domainlist type contents */
    dlctp = replacement ?: &dlct;
}

void
domainlist_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(dlctp, NULL, name, fn, loadable, LOADFLAGS_DL_LINEFEED_REQUIRED, NULL, 0);
}

void
domainlist_register_exact(module_conf_t *m, const char *name, const char *fn, bool loadable)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    *m = conf_register(dlctp, NULL, name, fn, loadable, LOADFLAGS_DL_LINEFEED_REQUIRED | LOADFLAGS_DL_EXACT, NULL, 0);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

const struct domainlist *
domainlist_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == dlctp, "domainlist_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2DL(base);
}

/*
 * KEY and MEMBER are domain names represented as reversed strings,
 * with '.'  separating labels.
 *
 * If compar_matchtype is DOMAINLIST_MATCH_SUBDOMAIN:
 *   If KEY is a subdomain of MEMBER, zero is returned.
 */
static int
compar_domains(const void *key, const void *member)
{
    const uint8_t *k2;
    int result = 0;
    unsigned ki;

    SXEA6(1 == compar_name_offset_size || 2 == compar_name_offset_size || 4 == compar_name_offset_size,
          "Internal error: unexpected compar_name_offset_size: %u", compar_name_offset_size);

    unsigned mi = NAME_OFFSET(compar_name_offset_size, member, 0);
    const uint8_t *m2 = (const uint8_t *)&compar_name_bundle[mi];

    if (compar_caller == DOMAINLIST_CALLER_QSORT) {
        ki = NAME_OFFSET(compar_name_offset_size, key, 0);
        k2 = (const uint8_t *) &compar_name_bundle[ki];
    } else
        k2 = *(const uint8_t *const *)key;

    const uint8_t *k = k2;
    const uint8_t *m = m2;

    if (compar_matchtype == DOMAINLIST_MATCH_SUBDOMAIN && *m == 0)
        goto SXE_EARLY_OUT;

    /* loop until strings don't match or key is exhausted */
    while (*k != 0 && dns_tolower[*k] == dns_tolower[*m]) {
        k++;
        m++;
    }

    if (compar_matchtype == DOMAINLIST_MATCH_SUBDOMAIN)
        if (*k == '.' && *m == 0) /* found sub-domain match? e.g. *k=moc.nozama[.]www\0, *m=moc.nozama[\0] */
            goto SXE_EARLY_OUT;

    /* here we want to special case '.' to help with label matches */
    if (*k == '.' && *m != '.')
        result = 1 - dns_tolower[*m];
    else if (*k != '.' && *m == '.')
        result = dns_tolower[*k] - 1;
    else
        result = dns_tolower[*k] - dns_tolower[*m];

SXE_EARLY_OUT:

    if (compar_caller != DOMAINLIST_CALLER_QSORT)
        SXEL7("%s(key=%p=%s, member=%p=compar_name_bundle[%u]=%s){} // result=%d, caller=DOMAINLIST_CALLER_BSEARCH, match_subdomain=%s, compar_name_bundle=%p",
              __FUNCTION__, key, k2, member, mi, m2, result, compar_matchtype == DOMAINLIST_MATCH_SUBDOMAIN ? "yes" : "no", compar_name_bundle);

    return result;
}

void
mem_reverse(void *s, size_t n)
{
    uint8_t *head = s, *tail = (uint8_t *)s + n - 1, tmp;

    while (head < tail) {
        tmp = *head;
        *head++ = *tail;
        *tail-- = tmp;
    }
}

static size_t
separators(const char *data, size_t len, bool *lf)
{
    size_t n;

    for (*lf = false, n = 0; n < len; n++)
        if (data[n] == '\n')
            *lf = true;
        else if (!isspace(data[n]))
            break;

    return n;
}

static bool
domainlist_hash_use(void *v, void **vp)
{
    struct domainlist *candidate = *vp;
    struct object_fingerprint *of = v;
    void *cfp;

    if (object_hash_magic(of->hash))
        cfp = candidate->fingerprint;
    else if (candidate->name_bundle_len == of->len)
        cfp = candidate->name_bundle;
    else
        return false;                        /* zero-magic hash items of different lengths don't compare */

    if (memcmp(cfp, of->fp, of->len) == 0) {
        domainlist_refcount_inc(candidate);
        return true;
    }
    return false;
}

/* Domains are separated by a single separator character. */
static struct domainlist *
domainlist_parse(char *name_bundle, int name_bundle_len, struct object_fingerprint *of, uint32_t loadflags)
{
    struct domainlist *existing_domainlist, *me, tmp;
    int i, j, len, skip, skipchars_at_start, start;
    struct object_fingerprint myof;
    bool junk, lf, trim;

    SXEE7("(name_bundle=%p, name_bundle_len=%d, of=%p, loadflags=0x%" PRIX32 ")", name_bundle, name_bundle_len, of, loadflags);
    SXEA6(name_bundle_len > 0, "Invalid len %d", name_bundle_len);
    /* SXED7(name_bundle, name_bundle_len - 1); */

    /* Jump past leading separators */
    skipchars_at_start = separators(name_bundle, name_bundle_len - 1, &lf);
    SXEL7("skipping %d leading chars, new name_bundle_len %d", skipchars_at_start, name_bundle_len);

    me = NULL;
    tmp.name_bundle = name_bundle;
    tmp.name_bundle_len = name_bundle_len;
    tmp.name_offset_size = name_bundle_len < 256 ? 1 : name_bundle_len < 65536 ? 2 : 4;
    tmp.name_amount = 0;
    for (start = i = skipchars_at_start, junk = trim = false; i < name_bundle_len; i++) {
        if (i > skipchars_at_start && (skip = separators(name_bundle + i, name_bundle_len - i - 1, &lf)) > 0) {
            if (junk) {
                memset(name_bundle + start, ' ', i - start);    /* We won't be needing the junk! */
                SXEL7("Ignoring junk domain at offset %d-%d", start, i);
                junk = false;
                if (start == skipchars_at_start)
                    skipchars_at_start = i + skip;
            } else
                tmp.name_amount++;
            i += skip;
            if (i == name_bundle_len - 1)
                break;
            if (loadflags & LOADFLAGS_DL_LINEFEED_REQUIRED && !lf) {
                SXEL3("Invalid embedded whitespace found (offset %d-%d) on a single line", i - skip, i);
                goto SXE_EARLY_OUT;
            }
            start = i;
            trim = false;
            SXEL7("skipping %d separator chars while counting, have %d, new position %d of %d", skip, tmp.name_amount, start, name_bundle_len);
        }
        if (i == name_bundle_len - 1) {
            if (junk)
                tmp.name_bundle_len = name_bundle_len = start + 1;
            else if (i > skipchars_at_start)
                tmp.name_amount++;
        } else if (trim || (loadflags & LOADFLAGS_DL_TRIM_URLS && name_bundle[i] == '/')) {
            name_bundle[i] = ' ';
            trim = true;
        } else if (!dns_tohost[(uint8_t)name_bundle[i]]) {
            if (!(loadflags & LOADFLAGS_DL_IGNORE_JUNK)) {
                SXEL3("Invalid domain character (0x%02x) found (offset %d)", (unsigned)name_bundle[i], i);
                goto SXE_EARLY_OUT;
            }
            junk = true;
        }
    }

    SXEL7("found %d name%s in the buffer", tmp.name_amount, tmp.name_amount == 1 ? "" : "s");

    if (!(loadflags & LOADFLAGS_DL_ALLOW_EMPTY) && !tmp.name_amount) {
        SXEL2("Cannot load a domainlist with no names");
        goto SXE_EARLY_OUT;
    }

    if ((tmp.name_offset = MOCKFAIL(DOMAINLIST_PARSE, NULL, kit_malloc(tmp.name_amount * tmp.name_offset_size))) == NULL) {
        SXEL2("Failed to allocate %u domainlist name_offset bytes", tmp.name_amount * tmp.name_offset_size);
        goto SXE_EARLY_OUT;
    }
    SXEL7("malloc() bytes for *name_offset: %u == %u * %u", tmp.name_amount * tmp.name_offset_size, tmp.name_amount, tmp.name_offset_size);
    if ((me = MOCKFAIL(DOMAINLIST_NEW_INDEX, NULL, kit_malloc(sizeof(*me) + (of && of->hash ? of->len : 0)))) == NULL) {
        SXEL2("Failed to allocate domainlist");
        kit_free(tmp.name_offset);
        goto SXE_EARLY_OUT;
    }
    me->exact = loadflags & LOADFLAGS_DL_EXACT ? 1 : 0;
    SXEL7("malloc() bytes for *me         : %zu", sizeof(*me));
    SXEL7("reversing & normalizing names:");
    for (j = 0, start = i = skipchars_at_start; i < name_bundle_len; i++, skip = 0)
        if (i > skipchars_at_start && (i == name_bundle_len - 1 || (skip = separators(name_bundle + i, name_bundle_len - i - 1, &lf)) > 0)) {
            /* Normalize names by removing leading and trailing dots */
            while (start < i && name_bundle[start] == '.')
                start++;
            len = i - start;
            while (len > 1 && name_bundle[start + len - 1] == '.')
                len--;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            name_bundle[start + len] = '\0';
            SXEL7("name_offset[%u]=%u // [%d]=%.*s", j, start, len, (int)len, name_bundle + start);
            if (1 == tmp.name_offset_size)
                tmp.name_offset_08[j++] = (uint8_t)start;
            else if (2 == tmp.name_offset_size)
                tmp.name_offset_16[j++] = (uint16_t)start;
            else if (4 == tmp.name_offset_size)
                tmp.name_offset_32[j++] = (uint32_t)start;
            else
                SXEA1(0, "Internal error: unexpected tmp.name_offset_size: %u", tmp.name_offset_size); /* COVERAGE EXCLUSION: todo: how to trigger assert without adding 2^32 bytes of domains? */
            mem_reverse(name_bundle + start, len);

            if (i < name_bundle_len - 1) {
                i += skip;
                SXEL7("skipping %d chars while creating, new position %d of %d", skip, i, name_bundle_len);
                start = i;
            }
        }

    SXEL7("qsorting using compar_domains(): // tmp.name_offset_08=%p, tmp.name_amount=%u, tmp.name_offset_size=%u",
          tmp.name_offset_08, tmp.name_amount, tmp.name_offset_size);
    compar_name_bundle      = tmp.name_bundle;
    compar_name_offset_size = tmp.name_offset_size;
    compar_caller           = DOMAINLIST_CALLER_QSORT;
    if (tmp.name_amount > 1) {
        compar_matchtype = DOMAINLIST_MATCH_EXACT;
        qsort(tmp.name_offset_08, tmp.name_amount, tmp.name_offset_size, compar_domains);
    }

    if (!me->exact) {
        SXEL7("removing subdomains from name_offset[]:");
        compar_caller           = DOMAINLIST_CALLER_QSORT;
        compar_matchtype        = DOMAINLIST_MATCH_SUBDOMAIN;
        #define DOMAINLIST_REMOVE_SUBDOMAINS(bits)                                              \
            do {                                                                                \
                for (i = 0, j = 1; j < tmp.name_amount; j++)                                    \
                    if (compar_domains(&tmp.name_offset_##bits[j], &tmp.name_offset_##bits[i])) \
                        tmp.name_offset_##bits[++i] = tmp.name_offset_##bits[j];                \
            } while (0)
        if (1 == tmp.name_offset_size)
            DOMAINLIST_REMOVE_SUBDOMAINS(08);
        else if (2 == tmp.name_offset_size)
            DOMAINLIST_REMOVE_SUBDOMAINS(16);
        else if (4 == tmp.name_offset_size)
            DOMAINLIST_REMOVE_SUBDOMAINS(32);
        else
            SXEA1(0, "Internal error: unexpected tmp.name_offset_size: %u", tmp.name_offset_size); /* COVERAGE EXCLUSION: todo: how to trigger assert without adding 2^32 bytes of domains? */

        SXEL7("removed names: %d", tmp.name_amount - (i + 1));
        if (tmp.name_amount > 0)
            tmp.name_amount = i + 1;
    }

#if SXE_DEBUG
    #define DOMAINLIST_DUMP_SORTED_NAME(bits) \
        do {                                                                                                                                          \
            for (i = 0; i < tmp.name_amount; i++)                                                                                                     \
                SXEL7("debug: dump sorted name #%d at offset %u is '%s'", i, tmp.name_offset_##bits[i], &tmp.name_bundle[tmp.name_offset_##bits[i]]); \
        } while (0)
    if (1 == tmp.name_offset_size)
        DOMAINLIST_DUMP_SORTED_NAME(08);
    else if (2 == tmp.name_offset_size)
        DOMAINLIST_DUMP_SORTED_NAME(16);
    else if (4 == tmp.name_offset_size)
        DOMAINLIST_DUMP_SORTED_NAME(32);
    else
        SXEA1(0, "Internal error: unexpected tmp.name_offset_size: %u", tmp.name_offset_size);
#endif

    /*
     * come here if the newly created domainlist is ready to deploy in memory
     * but before deploying check to see if such a list already exists
     */
    conf_setup(&me->conf, dlctp);
    me->name_bundle = tmp.name_bundle;
    me->name_bundle_len = tmp.name_bundle_len;
    me->name_offset = tmp.name_offset;
    me->name_offset_size = tmp.name_offset_size;
    me->name_amount = tmp.name_amount;
    me->oh = of ? of->hash : NULL;
    if (me->oh) {
        if (of->len)
            memcpy(me->fingerprint, of->fp, of->len);
        else {
            myof.hash = of->hash;
            myof.fp = (uint8_t *)me->name_bundle;
            myof.len = me->name_bundle_len;
            of = &myof;
            if ((existing_domainlist = object_hash_action(of->hash, of->fp, of->len, domainlist_hash_use, of)) != NULL) {
                kit_free(me->name_bundle);
                kit_free(me->name_offset);
                kit_free(me);
                me = existing_domainlist;
                goto SXE_EARLY_OUT;
            }
        }

        if (object_hash_add(me->oh, me, of->fp, of->len) == NULL) {
            SXEL2("Failed to hash domainlist object; memory exhaustion?");
            me->oh = NULL;
        }
    }

SXE_EARLY_OUT:
    SXER7("return %p", me);
    return me;
}

/*
 * domainlist_new_from_buffer() is called to parse a domainlist
 * separated by a space char, e.g.: * "foo.com bar.com"
 */
struct domainlist *
domainlist_new_from_buffer(const char *buf, int len, struct object_fingerprint *of, uint32_t loadflags)
{
    struct domainlist *result;
    unsigned magic;
    char *buf2;

    result = NULL;
    if (of) {
        /* fingerprints with a zero length are only processed post-domainlist-creation */
        if (of->hash == NULL)
            of->hash = object_hash_new(DOMAINLIST_OBJECT_HASH_ROWS, of->len ? DOMAINLIST_OBJECT_HASH_LOCKS : 0, of->len);
        else if ((magic = object_hash_magic(of->hash)) != of->len) {
            SXEL2("Invalid domainlist fingerprint; hex length should be %u, not %u", magic * 2, of->len * 2);
            return NULL;
        } else if (of->len)
            result = object_hash_action(of->hash, of->fp, of->len, domainlist_hash_use, of);
        kit_counter_incr(result ? COUNTER_UUP_OBJECT_HASH_HIT : COUNTER_UUP_OBJECT_HASH_MISS);
    }

    if (result == NULL) {
        SXEA6(!len || buf[len - 1], "Unexpected NUL included at the end of the input string");
        if ((buf2 = MOCKFAIL(DOMAINLIST_NEW_FROM_BUFFER, NULL, kit_malloc(len + 1))) == NULL) {
            SXEL2("Couldn't allocate domainlist buffer of %d bytes", len + 1);
            result = NULL;
        } else {
            memcpy(buf2, buf, len);
            buf2[len] = ' ';

            if ((result = domainlist_parse(buf2, len + 1, of, loadflags)) == NULL)
                kit_free(buf2);    /* No names found */
        }
    }

    SXEL7("%s(buf[%d]=\"%.*s%s\", loadflags=0x%" PRIX32 "){} // result=%p [%u]=%.*s[,..]",
          __FUNCTION__, len, len > 50 ? 47 : len, buf, len > 50 ? "..." : "",
          loadflags, result, result ? result->name_bundle_len : 0,
          result ? result->name_bundle_len : 0, result ? result->name_bundle : "");
    return result;
}

void
domainlist_refcount_inc(struct domainlist *me)
{
    CONF_REFCOUNT_INC(me);
}

void
domainlist_refcount_dec(struct domainlist *me)
{
    CONF_REFCOUNT_DEC(me);
    SXEL7("%s(domainlist=%p) {}", __FUNCTION__, me);
}

struct domainlist *
domainlist_new(struct conf_loader *cl, unsigned maxlines, uint32_t loadflags)
{
    struct domainlist *me = NULL;
    size_t buf_len;
    char *buf;

    SXEE7("(cl=?, maxlines=%u, loadflags=0x%" PRIX32 ") // path=%s", maxlines, loadflags, conf_loader_path(cl));

    if ((buf = conf_loader_readfile(cl, &buf_len, maxlines)) != NULL && (me = domainlist_parse(buf, buf_len + 1, NULL, loadflags)) == NULL)
        kit_free(buf);    /* No names found */

    SXER7("return %p", me);

    if (me == NULL)
        errno = EINVAL;

    return me;
}

static struct conf *
domainlist_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct domainlist *me;

    SXEA6(info->type == dlctp, "%s() with unexpected conf_type %s", __FUNCTION__, info->type->name);
    me = domainlist_new(cl, 0, info->loadflags);

    return me ? &me->conf : NULL;
}

static bool
domainlist_hash_remove(void *v, void **vp)
{
    struct domainlist *candidate = *vp;
    struct domainlist *me = v;

    if (me == candidate && me->conf.refcount == 0) {
        *vp = NULL;
        return true;
    }
    return false;
}

static void
domainlist_free(struct conf *base)
{
    struct domainlist *me = CONF2DL(base);
    unsigned fplen, magic;
    uint8_t *fp;

    SXEA6(base->type == dlctp, "domainlist_free() with unexpected conf_type %s", base->type->name);

    if (me->oh) {
        magic = object_hash_magic(me->oh);
        fp = magic ? me->fingerprint : (uint8_t *)me->name_bundle;
        fplen = magic ?: me->name_bundle_len;
        if (!object_hash_action(me->oh, fp, fplen, domainlist_hash_remove, me)) {
            /*-
             * XXX: It's unusal to get here...
             *      1. This thread gets into domainlist_free()
             *      2. Other thread gets a reference to me through the object-hash
             *      3. This thread fails the object_hash_action(..., domainlist_hash_remove, ...)
             *      4. Other thread releases its reference
             * When we get to this point, the other thread will delete (or already has deleted) the object internals,
             * so in fact, the object_hash_action() failure implies that the object is now somebody else's problem.
             */
            SXEL6("Failed to remove domainlist from its hash (refcount %d); another thread raced to get a reference", me->conf.refcount);
            return;
        }
    }
    SXEL7("%s(me=%p){} // free()ing %u names in name_bundle & pointers to those names", __FUNCTION__, me, me->name_amount);
    kit_free(me->name_bundle);
    kit_free(me->name_offset);
    kit_free(me);
}

const char *
domainlist_sscan(const char *str, const char *delim, uint32_t loadflags, struct domainlist **dl)
{
    int len;

    if ((len = strcspn(str, delim)) == 0)
        *dl = NULL;
    else if ((*dl = domainlist_new_from_buffer(str, len, NULL, loadflags)) == NULL)
        return NULL;
    return str + len;
}

const uint8_t *
domainlist_match(const struct domainlist *dl, const uint8_t *name, enum domainlist_match matchtype, struct xray *x, const char *listname)
{
    char           string[DNS_MAXLEN_STRING + 1];
    char          *string_ptr = string;
    const uint8_t *result;
    size_t         string_len;

    result = NULL;

    if (dl == NULL || !dns_name_to_buf(name, string, sizeof(string), &string_len, DNS_NAME_DEFAULT))
        SXEL7("%s(dl=%p, name=%s, matchtype=%s, x=?, listname=%s){} // %p",
              __FUNCTION__, dl, dns_name_to_str1(name), matchtype == DOMAINLIST_MATCH_SUBDOMAIN ? "subdomain" : "exact", listname, result);
    else {
        if (string_len == 1 && *string == '.')
            string[--string_len] = '\0';
        mem_reverse(string, string_len);
        compar_name_bundle      = dl->name_bundle;
        compar_name_offset_size = dl->name_offset_size;
        compar_caller           = DOMAINLIST_CALLER_BSEARCH;
        compar_matchtype        = matchtype;
        result = bsearch(&string_ptr, dl->name_offset, dl->name_amount, dl->name_offset_size, compar_domains);
        SXEL7("%s(dl=%p, name=%s, matchtype=%s, x=?, listname=%s){} // %p=bsearch(string=%s, "
              "dl->name_offset=?, dl->name_amount=%d, dl->name_offset_size=%d, compar_domains)",
              __FUNCTION__, dl, dns_name_to_str1(name), matchtype == DOMAINLIST_MATCH_SUBDOMAIN ? "subdomain" : "exact",
              listname, result, string, dl->name_amount, dl->name_offset_size);
        if (result != NULL) {
            unsigned mi = NAME_OFFSET(compar_name_offset_size, result, 0);
            const char *match = compar_name_bundle + mi;
            size_t mlen = strlen(match);

            if (dl->exact && matchtype == DOMAINLIST_MATCH_SUBDOMAIN) {
                /*-
                 * We were created with LOADFLAGS_DL_EXACT - we need to
                 * find the *best* match!
                 * Our bsearch() will have found an arbitrary match, so if we're
                 * looking for a.bob.c.d and the list contains bob.c.d and c.d and d,
                 * the sorting will have put them in this order:
                 *     d
                 *     d.c
                 *     d.c.albatros
                 *     d.c.b
                 *     d.c.bob
                 *     d.c.bobby
                 *     d.c.boy
                 *     d.c.dog
                 * The best match is the longest match, so we search forward
                 * 'till we have no more matches.
                 */
                const uint8_t *limit = dl->name_offset_08 + dl->name_offset_size * dl->name_amount;
                const char *next_match;
                size_t i, next_mlen;
                int cmp;

                SXEL7("Looking for %s. Found %s, mlen %zu", string, match, mlen);
                while ((result += dl->name_offset_size) < limit) {
                    mi = NAME_OFFSET(compar_name_offset_size, result, 0);
                    next_match = compar_name_bundle + mi;
                    next_mlen = strlen(next_match);
                    if (compar_domains(&string_ptr, result) != 0) {
                        /*-
                         * If the match length 'i' is greater than mlen, we have
                         * to keep looking; skipping over 'd.c.b' to find
                         * 'd.c.bob'.
                         * This in fact means that we have to visit all the
                         * 'd.c' entries 'till we either run out of 'd.c'
                         * entries or we find the 'd.c.bob' entry...
                         */
                        for (i = 0; i < next_mlen && i < (size_t)string_len; i++)
                            if ((cmp = (int)next_match[i] - (int)string[i]) != 0)
                                break;
                        SXEL7("    Checking %s: No comparison, this_mlen is %zu or greater.... compare (for continue) if > mlen %zu and cmp(%d) <= 0",
                              next_match, i, mlen, cmp);
                        if (i > mlen && cmp <= 0)
                            /*-
                             * Having 'mlen + 1' character matches means we're
                             * looking 'd.c.bob' in 'd.c.<something>', not in
                             * 'd.c<something>' where mlen is 3 (strlen("d.c")).
                             * The 'cmp' bit breaks out of the loop when we have
                             * seen 'd.c' looking for 'd.c.bob' and visit
                             * 'd.c.boc'.... we'll never find a better match
                             * than 'd.c'.
                             */
                            continue;
                        break;
                    }
                    /* This is a better match! */
                    match = next_match;
                    mlen = next_mlen;
                    SXEL7("    Checking %s: Overriding with mlen %zu", match, mlen);
                }
            }

            /*-
             * We now have something like:
             *     match="moc.nozama"
             *     mlen=10; strlen("moc.nozama")
             *     name="\003www\006amazon\003com",
             *     string_len=14; strlen("www.amazon.com")
             * Make the result point into the search name!
             */
            result = name + string_len + !*match - !*name - mlen;
            SXEA6(result >= name, "oops, result points before name");
            SXEA6(result < name + dns_name_len(name), "oops, result points after name");
            SXEA6(dns_name_len(result) == mlen + 2 - !*match, "that's not a dns name!");

            XRAY6(x, "%s match: found %s (%s)",
                  listname, dns_name_to_str1(result), matchtype == DOMAINLIST_MATCH_SUBDOMAIN ? "subdomain" : "exact");
        }
    }

    return result;
}

size_t
domainlist_buf_size(const struct domainlist *me)
{
    return me ? me->name_bundle_len : 0;
}

char *
domainlist_to_buf(const struct domainlist *me, char *buf, size_t sz, size_t *len_out)
{
    size_t len, pos;
    unsigned offset;
    int i;

    pos = 0;
    *buf = '\0';

    for (i = 0; me && i < me->name_amount; i++) {
        offset = NAME_OFFSET(me->name_offset_size, me->name_offset, i);
        SXEA1(1 == me->name_offset_size || 2 == me->name_offset_size || 4 == me->name_offset_size,
              "Internal error: unexpected me->name_offset_size: %u", me->name_offset_size);
        len = strlen(&me->name_bundle[offset]);

        if (pos + len + !!i >= sz)
            return NULL;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

        if (pos)
            buf[pos++] = ' ';

        strcpy(buf + pos, &me->name_bundle[offset]);
        mem_reverse(buf + pos, len);
        pos += len;
    }

    if (len_out)
        *len_out = pos;

    return buf;
}

static int
#ifdef __linux__
ordered_domains(const void *a, const void *b, void *v)
#else
ordered_domains(void *v, const void *a, const void *b)
#endif
{
    const uint8_t *data = (const uint8_t *)(*(const struct domainlist **)v)->name_bundle;
    unsigned starta = *(const unsigned *)a;
    unsigned enda = starta + strlen((const char *)data + starta);
    unsigned startb = *(const unsigned *)b;
    unsigned endb = startb + strlen((const char *)data + startb);
    int cmp = 0;

    while (enda > starta && endb > startb && (cmp = dns_tolower[data[--enda]] - dns_tolower[data[--endb]]) == 0)
        ;
    if (cmp)
        return cmp;

    return enda != starta ? 1 : endb != startb ? -1 : 0;
}

ssize_t
domainlist_to_sorted_ascii(const struct domainlist *me, char *buf, size_t sz)
{
    unsigned *offset;
    size_t len, pos;
    char *ptr;
    int i;

    pos = 0;
    *buf = '\0';

    if (me) {
        offset = alloca(me->name_amount * sizeof(*offset));

        for (i = 0; me && i < me->name_amount; i++)
            offset[i] = NAME_OFFSET(me->name_offset_size, me->name_offset, i);
#ifdef __linux__
        qsort_r(offset, me->name_amount, sizeof(*offset), ordered_domains, &me);
#else
        qsort_r(offset, me->name_amount, sizeof(*offset), &me, ordered_domains);
#endif
        for (i = 0; i < me->name_amount; i++) {
            ptr = me->name_bundle + offset[i];
            len = strlen(ptr);
            if (pos + len + !!i >= sz)
                return -1;
            if (pos)
                buf[pos++] = ' ';
            strcpy(buf + pos, ptr);
            mem_reverse(buf + pos, len);
            pos += len;
        }
    }

    return pos;
}
