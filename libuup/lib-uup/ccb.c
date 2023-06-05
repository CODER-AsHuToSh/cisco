/* Content category bitmask
 *
 * This file controls the mapping of category bits to handling types (i.e. actions).
 */

#include <ctype.h>
#include <errno.h>
#include <kit-alloc.h>
#include <mockfail.h>

#include "ccb.h"
#include "conf-loader.h"
#include "pref.h"

/*
 * These mappings are assumed in various parts of the code, so they're the default!
 * If we try to load a ccb file that doesn't match these expectations, we fail.
 *
 * These QUERY_HANDLING_* values are also the only handling values that can be used
 * by the ccb file, and this array defines their order of importance for address
 * lookups.
 *
 * Non-address lookups that need categorization do not use this table.  They only
 * check for QUERY_HANDLING_ALLOWLISTED by looking up AT_LIST_*ALLOW preflists and
 * if not found use QUERY_HANDLING_NORMAL.
 */
struct {
    int handling;
    int bit[2];
} ccb_baseline[] = {
    { QUERY_HANDLING_ALLOWLISTED, { CATEGORY_BIT_ALLOWLIST, CATEGORY_BIT_ALLOWAPP } },
    { CCB_HANDLING_PROXY_ALLOWAPP, { } },              /* Proxy due to an application allowlist URL match */
    { QUERY_HANDLING_SECURITY, { } },
    { QUERY_HANDLING_BLOCKED, { CATEGORY_BIT_BLOCKLIST } },
    { CCB_HANDLING_PROXY_ORG_BLOCK_GREYLIST, { } },    /* Proxy due to an org greylist match (urlprefs, blocks only) */
    { QUERY_HANDLING_BOTNET, { CATEGORY_BIT_BOTNET, CATEGORY_BIT_BOTNET2 } },
    { QUERY_HANDLING_MALWARE, { CATEGORY_BIT_MALWARE, CATEGORY_BIT_MALWARE2 } },    /* SHOULD be after CCB_HANDLING_PROXY_URL_PROXY!! */
    { CCB_HANDLING_PROXY_URL_PROXY_HTTPS, { } },       /* Proxy due to a url-proxy-https greylist match */
    { CCB_HANDLING_PROXY_URL_PROXY, { } },             /* Proxy due to a url-proxy greylist match */
    { QUERY_HANDLING_PHISH, { CATEGORY_BIT_PHISH } },
    { QUERY_HANDLING_SINKHOLE, { CATEGORY_BIT_SINKHOLE } },
    { QUERY_HANDLING_SUSPICIOUS, { CATEGORY_BIT_SUSPICIOUS } },
    { QUERY_HANDLING_APPLICATION, { CATEGORY_BIT_BLOCKAPP } },
    { CCB_HANDLING_PROXY_BLOCKAPP, { } },              /* Proxy due to an application blocklist URL match */
    { QUERY_HANDLING_DOMAINTAGGING, { } },
    { CCB_HANDLING_PROXY_NSD, { } },                   /* Proxy due to a newly-seen-domains match */
    { QUERY_HANDLING_NORMAL, { CATEGORY_BIT_GLOBAL_ALLOWLIST } },
};

const unsigned ccb_handling_entries = (sizeof(ccb_baseline) / sizeof(*ccb_baseline));

int
ccb_pos2handling(unsigned pos)
{
    return pos < ccb_handling_entries ? ccb_baseline[pos].handling : -1;
}

struct ccb {
    struct conf conf;
    uint8_t version;
    struct {
        char *label;
        int handling;
        unsigned ismasked : 1;    /* Or maybe this should be spelt "flags" */
    } *bit_map[PREF_CATEGORIES_MAX_BITS];
    pref_categories_t handling_map[sizeof(ccb_baseline) / sizeof(*ccb_baseline)];
    pref_categories_t masked;
    const char *allowlisted_txt;
};

#define CONSTCONF2CCB(confp) (const struct ccb *)((confp) ? (const char *)(confp) - offsetof(struct ccb, conf) : NULL)
#define CONF2CCB(confp)      (struct ccb *)((confp) ? (char *)(confp) - offsetof(struct ccb, conf) : NULL)

static enum ccb_parse_result
ccb_parse_headers(struct conf_loader *cl, unsigned *count, uint8_t *version)
{
    enum ccb_parse_result result = CCB_PARSE_FAIL;
    const char *line;

    if ((line = conf_loader_readline(cl)) == NULL && conf_loader_eof(cl)) {
        SXEL2("%s(): %s:%u: Empty CCB file", __FUNCTION__, conf_loader_path(cl), conf_loader_line(cl));
        result = CCB_PARSE_EOF;
        goto SXE_EARLY_OUT;
    }

    if (line == NULL || (sscanf(line, "ccb %hhu\n", version) != 1)) {
        SXEL2("%s(): %s:%u: Invalid headers", __FUNCTION__, conf_loader_path(cl), conf_loader_line(cl));
        goto SXE_EARLY_OUT;
    }

    if (*version != CCB_VERSION) {
        SXEL2("%s(): %s: v%u: Invalid version (must be %d)", __FUNCTION__, conf_loader_path(cl), *version, CCB_VERSION);
        goto SXE_EARLY_OUT;
    }

    if ((line = conf_loader_readline(cl)) == NULL || sscanf(line, "count %u\n", count) != 1) {
        SXEL2("%s(): %s:%u: Invalid 'count' header", __FUNCTION__, conf_loader_path(cl), conf_loader_line(cl));
        goto SXE_EARLY_OUT;
    }
    result = CCB_PARSE_OK;

SXE_EARLY_OUT:
    if (result != CCB_PARSE_OK)
        *count = 0;

    SXEL6("%s(cl=?){} // file=%s, count=%d, result %s", __FUNCTION__, conf_loader_path(cl), *count,
          result == CCB_PARSE_OK ? "CCB_PARSE_OK" :
          result == CCB_PARSE_EOF ? "CCB_PARSE_EOF" :
          result == CCB_PARSE_FAIL ? "CCB_PARSE_FAIL" : "<unknown>");
    return result;
}

static enum ccb_parse_result
parse_category(const char *line, char **keyword, int *bit, unsigned *hpos, unsigned *masked, const char **allowlisted_txt)
{
    enum ccb_parse_result result = CCB_PARSE_FAIL;
    const char *label, *p;
    int len, consumed;

    SXEE6("(line=\"%s\", keyword=?, bit=?, hpos=?)", line);

    *keyword = NULL;
    *bit = 0;
    *hpos = ccb_handling_entries;
    *masked = 0;

    /* Advance to key's beginning. */
    while (isspace(*line))
        line++;
    if (*line == '\0') {
        SXEL2("%s(): The line only had space characters, which is invalid", __FUNCTION__);
        goto OUT;
    }

    /* Get the key */
    p = line;
    while (*line != ':' && *line != '\0' && *line != '\n')
        line++;
    if (line == p) {
        SXEL2("%s(): missing key field", __FUNCTION__);
        goto OUT;
    }

    len = line - p;
    if ((*keyword = MOCKFAIL(CCB_PARSE_CATEGORY, NULL, kit_malloc(len + 1))) == NULL) {
        SXEL2("Failed to allocate %d keyword bytes", len + 1);
        goto OUT;
    }
    memcpy(*keyword, p, len);
    (*keyword)[len] = '\0';
    line++;

    if (*line == '\0' || *line == '\n') {
        SXEL2("%s(): There is no bit, handling or masked value for this category", __FUNCTION__);
        goto OUT;
    }

    /* Get the bit */
    if (sscanf(line, "%d:%n", bit, &consumed) != 1)
        goto OUT;

    /* Get the handling string (not all categories have handling, i.e. Attack) */
    line += consumed;
    p = line;
    while (isalnum((unsigned char)*line) || *line == '-')
        line++;

    /* Verify query handling - we need a QUERY_HANDLING_* handling string match */
    len = line - p;
    if (len) {
        if (len == 11 && (strncmp(p, "allowlisted", 11) == 0 || strncmp(p, "whitelisted", 11) == 0)) {
            *allowlisted_txt = *p == 'a' ? "allowlisted" : NULL;
            *hpos = 0;    /* CCB may use either of these strings for now... */
        } else for (*hpos = 0; *hpos < ccb_handling_entries; (*hpos)++)
            if (ccb_baseline[*hpos].handling <= QUERY_HANDLING_MAX) {
                label = query_handling_str(ccb_baseline[*hpos].handling);
                if (label && strncmp(label, p, len) == 0 && label[len] == '\0')
                    break;
            }

        if (*hpos == ccb_handling_entries) {
            SXEL2("%s():  The handing '%s' for this category is invalid", __FUNCTION__, p);
            goto OUT;
        }
    }

    if (!*line || *line++ != ':') {
        SXEL2("%s(): %s: Missing handling/masked separator", __FUNCTION__, *keyword);
        goto OUT;
    }
    if (!*line) {
        SXEL2("%s(): Missing masked value", __FUNCTION__);
        goto OUT;
    }
    if (!strchr("01", *line)) {
        SXEL2("%s(): Invalid masked value '%c'", __FUNCTION__, *line);
        goto OUT;
    }
    *masked = *line++ == '1';

    if (*line && strcmp(line, "\n") != 0) {
        SXEL2("%s(): Trailing garbage found after handling/masked value", __FUNCTION__);
        goto OUT;
    }

    result = CCB_PARSE_OK;

OUT:
    if (result != CCB_PARSE_OK && *keyword) {
        kit_free(*keyword);
        *keyword = NULL;
    }

    SXER6("return %s // keyword=%s, handling=%s", result == CCB_PARSE_OK ? "CCB_PARSE_OK" :
          result == CCB_PARSE_EOF ? "CCB_PARSE_EOF" :
          result == CCB_PARSE_FAIL ? "CCB_PARSE_FAIL" : "<unknown>", *keyword,
          *hpos < ccb_handling_entries ? query_handling_str(ccb_baseline[*hpos].handling) : "<none>");

    return result;
}

module_conf_t CONF_CCB;

static struct conf *ccb_allocate(const struct conf_info *info, struct conf_loader *cl);
static void ccb_free(struct conf *base);

static const struct conf_type ccbct = {
    "ccb",
    ccb_allocate,
    ccb_free,
};

void
ccb_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(&ccbct, NULL, name, fn, loadable, LOADFLAGS_NONE, NULL, 0);
}

static struct ccb *
ccb_create(struct conf_loader *cl, const struct conf_type *type)
{
    unsigned count, hpos, i, num_entries;
    struct ccb *me, *retme;
    int bit, err, prevbit;
    const char *line;
    unsigned masked;
    char *keyword;

    SXEE6("(cl=?, type=?) // path=%s", conf_loader_path(cl));
    prevbit = -1;
    keyword = NULL;
    retme = NULL;

    if ((me = MOCKFAIL(CCB_CREATE, NULL, kit_calloc(1, sizeof(*me)))) == NULL) {
        SXEL2("Failed to allocate %zu ccb bytes", sizeof(*me));
        goto OUT;
    }
    conf_setup(&me->conf, type);
    me->allowlisted_txt = NULL;

    if (ccb_parse_headers(cl, &num_entries, &me->version) != CCB_PARSE_OK)
        goto OUT;

    count = num_entries;
    while ((line = conf_loader_readline(cl)) != NULL && count > 0) {
        SXEL6("ccb:: // parsing category: %s", line);
        /* Read and verify the line %s:%d: */
        if (parse_category(line, &keyword, &bit, &hpos, &masked, &me->allowlisted_txt) != CCB_PARSE_OK) {
            SXEL2("%s(): %s:%u: Unable to parse ccb line", __FUNCTION__, conf_loader_path(cl), conf_loader_line(cl));
            goto OUT;
        }

        if (bit >= PREF_CATEGORIES_MAX_BITS || bit < 0) {
            SXEL2("%s(): %s:%u: category bit '%d' is not within the range of '0 to %d'",
                  __FUNCTION__, conf_loader_path(cl), conf_loader_line(cl), bit, PREF_CATEGORIES_MAX_BITS - 1);
            goto OUT;
        }

        if (prevbit != -1 && (bit - prevbit) <= 0) {
            SXEL2("%s(): %s:%u: category bit '%d' is duplicate or not sorted (prevbit: %d)",
                  __FUNCTION__, conf_loader_path(cl), conf_loader_line(cl), bit, prevbit);
            goto OUT;
        }

        prevbit = bit;

        if ((me->bit_map[bit] = MOCKFAIL(CCB_CREATE_BITMAP, NULL, kit_malloc(sizeof(**me->bit_map)))) == NULL) {
            SXEL2("Failed to allocate %zu bit_map bytes", sizeof(**me->bit_map));
            goto OUT;
        }
        me->bit_map[bit]->label = keyword;
        me->bit_map[bit]->handling = hpos < ccb_handling_entries ? ccb_baseline[hpos].handling : -1;
        if ((me->bit_map[bit]->ismasked = !!masked))
            pref_categories_setbit(&me->masked, bit);
        keyword = NULL;

        /* Update the category_handlers with the category */
        if (hpos < ccb_handling_entries)
            pref_categories_setbit(me->handling_map + hpos, bit);

        count--;
    }

    if (conf_loader_eof(cl) && count == 0) {
#if SXE_DEBUG
        SXEL6("The CCB is version %u and has %u entries.", me->version, num_entries);
        for (int k = 0; k < PREF_CATEGORIES_MAX_BITS; k++)
            if (me->bit_map[k])
                SXEL6("     bit: %d   label(%p): %s   handling: %s   masked: %u", k,
                        me->bit_map[k]->label, me->bit_map[k]->label,
                        me->bit_map[k]->handling != -1 ? query_handling_str(me->bit_map[k]->handling) : "",
                        me->bit_map[k]->ismasked);

        SXEL6(" The categories for handling are:");
        for (hpos = 0; hpos < ccb_handling_entries; hpos++)
            SXEL6("     %s: 0x%s", query_handling_str(ccb_baseline[hpos].handling), pref_categories_idstr(me->handling_map + hpos));
#endif
        for (err = 0, hpos = 0; hpos < ccb_handling_entries; hpos++)
            for (i = 0; i < 2; i++)
                if ((bit = ccb_baseline[hpos].bit[i]) && !pref_categories_getbit(me->handling_map + hpos, bit)) {
                    SXEL2("%s: category bit '%d' must have handling '%s'", conf_loader_path(cl),
                          bit, query_handling_str(ccb_baseline[hpos].handling));
                    err++;
                }
        if (!err)
            retme = me;
    } else
        SXEL2("%s(): %s:%u: The value of count header is %s than number of category entries", __FUNCTION__,
                conf_loader_path(cl), conf_loader_line(cl), !count ? "less" : "more");

OUT:
    if (retme != me) {
        if (keyword)
            kit_free(keyword);
        ccb_refcount_dec(me);
    }
    SXER6("return %p", retme);

    if (retme == NULL)
        errno = EINVAL;

    return retme;
}

struct ccb *
ccb_new(struct conf_loader *cl)
{
    return ccb_create(cl, &ccbct);
}

static struct conf *
ccb_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct ccb *me;

    SXEA6(info->type == &ccbct, "%s() with unexpected conf_type %s", __FUNCTION__, info->type->name);
    if ((me = ccb_create(cl, info->type)) != NULL)
        conf_report_load(info->type->name, me->version);

    return me ? &me->conf : NULL;
}

static void
ccb_free(struct conf *base)
{
    struct ccb *me = CONF2CCB(base);
    int i;

    SXEA6(base->type == &ccbct, "ccb_free() with unexpected conf_type %s", base->type->name);

    for (i = 0; i < PREF_CATEGORIES_MAX_BITS; i++)
        if (me->bit_map[i]) {
            kit_free(me->bit_map[i]->label);
            kit_free(me->bit_map[i]);
        }
    kit_free(me);
}

bool
ccb_handling_pos_intersects(const struct ccb *me, pref_categories_t *ret, unsigned hpos, const pref_categories_t *cat)
{
    return me && hpos < ccb_handling_entries && pref_categories_intersect(ret, me->handling_map + hpos, cat);
}

const char *
ccb_label(const struct ccb *me, unsigned bit)
{
    return me && bit < PREF_CATEGORIES_MAX_BITS && me->bit_map[bit] ? me->bit_map[bit]->label : NULL;
}

const char *
ccb_allowlisted_txt(const struct ccb *me)
{
    return me && me->allowlisted_txt ? me->allowlisted_txt : "whitelisted";
}

bool
ccb_ismasked(const struct ccb *me, unsigned bit)
{
    return me && bit < PREF_CATEGORIES_MAX_BITS && me->bit_map[bit] ? me->bit_map[bit]->ismasked : 0;
}

void
ccb_masked(const struct ccb *me, pref_categories_t *ret)
{
    if (me)
        *ret = me->masked;
    else
        pref_categories_setnone(ret);
}

const struct conf *
ccb_conf(const struct ccb *me)
{
    return me ? &me->conf : NULL;
}

uint8_t
ccb_version(const struct ccb *me)
{
    return me ? me->version : 0;
}

static struct ccb default_ccb;

void
ccb_refcount_inc(struct ccb *me)
{
    if (me != &default_ccb)
        CONF_REFCOUNT_INC(me);
}

void
ccb_refcount_dec(struct ccb *me)
{
    if (me != &default_ccb)
        CONF_REFCOUNT_DEC(me);
}

static pthread_mutex_t initlock = PTHREAD_MUTEX_INITIALIZER;
static bool default_initialized;

void
ccb_deinitialize(void)
{
    unsigned b;

    if (default_initialized) {
        pthread_mutex_lock(&initlock);
        if (default_initialized) {
            for (b = 0; b < PREF_CATEGORIES_MAX_BITS; b++)
                if (default_ccb.bit_map[b]) {
                    kit_free(default_ccb.bit_map[b]);
                    default_ccb.bit_map[b] = NULL;
                }
            default_initialized = false;
        }
        pthread_mutex_unlock(&initlock);
    }
}

const struct ccb *
ccb_conf_get(const struct confset *set, module_conf_t m)
{
    pref_categories_t dt, *dtp;
    const struct conf *base;
    unsigned b, hpos, i;

    if ((base = confset_get(set, m)) != NULL) {
        SXEA6(base->type == &ccbct, "ccb_conf_get() with unexpected conf_type %s", base->type->name);
        return CONSTCONF2CCB(base);
    }

    if (!default_initialized) {
        pthread_mutex_lock(&initlock);
        if (!default_initialized) {
            /* The default is all categories are set as domaintagging */
            default_initialized = true;
            default_ccb.version = CCB_VERSION;
            default_ccb.conf.type = &ccbct;
            dtp = &dt;
            pref_categories_setall(dtp);
            for (hpos = 0; hpos < ccb_handling_entries; hpos++) {
                if (ccb_baseline[hpos].handling == QUERY_HANDLING_DOMAINTAGGING) {
                    default_ccb.handling_map[hpos] = dt;
                    dtp = default_ccb.handling_map + hpos;
                }
                for (i = 0; i < 2; i++)
                    if ((b = ccb_baseline[hpos].bit[i])) {
                        SXEA1(ccb_baseline[hpos].handling <= QUERY_HANDLING_MAX, "Invalid bit associated with CCB_HANDLING_*");
                        SXEA1(default_ccb.bit_map[b] == NULL, "Internal error - ccb initialized twice");
                        SXEA1(default_ccb.bit_map[b] = kit_malloc(sizeof(**default_ccb.bit_map)), "Failed to allocate %zu bytes", sizeof(**default_ccb.bit_map));
                        default_ccb.bit_map[b]->label = NULL;
                        default_ccb.bit_map[b]->handling = ccb_baseline[hpos].handling;
                        default_ccb.bit_map[b]->ismasked = 0;
                        pref_categories_setbit(default_ccb.handling_map + hpos, b);
                        pref_categories_unsetbit(dtp, b);
                    }
            }
        }
        pthread_mutex_unlock(&initlock);
    }

    return &default_ccb;
}

const char *
ccb_pref_categories_str(const struct ccb *ccb, const pref_categories_t *cat)
{
    static __thread unsigned bufsize;
    static __thread char *buf;
    unsigned sz, bit, bpos;
    char *nbuf, bittag[7];    /* 'bit' + <86-127> + '\0' */
    const char *tag;

    if (cat == NULL && ccb == NULL) {    // Allow cleanups
        kit_free(buf);
        buf     = NULL;
        bufsize = 0;
        return NULL;
    }

    if (!buf && (buf = MOCKFAIL(CCB_PREF_CATEGORIES_STR, NULL, kit_malloc(bufsize = 512))) == NULL) {
        SXEL2("Couldn't allocate %u pref-categories-str bytes", bufsize);
        return "<pref-categories-allocation-error>";
    }

    buf[bpos = 0] = '\0';

    for (bit = 0; bit < PREF_CATEGORIES_MAX_BITS; bit++) {
        if (pref_categories_getbit(cat, bit)) {
            if ((tag = ccb_label(ccb, bit)) == NULL) {
                sz = snprintf(bittag, sizeof(bittag), "bit%d", bit);
                tag = bittag;
                SXEL7("ccb_pref_categories_str // get category for bit: %d - none", bit);
            } else {
                sz = strlen(tag);
                SXEL7("ccb_pref_categories_str // get category for bit: %d - %s", bit, tag);
            }

            /* Check if there is enough room in buffer */
            if (sz + 2 >= bufsize - bpos) {
                if ((nbuf = MOCKFAIL(CCB_PREF_CATEGORIES_STR_EXTEND, NULL, kit_realloc(buf, bufsize + sz + 128))) == NULL) {
                    SXEL2("Couldn't realloc %u pref-categories-str bytes", bufsize + sz + 128);
                    return "<pref-categories-reallocation-error>";
                }

                buf = nbuf;
                bufsize += sz + 128;
            }

            bpos += snprintf(buf + bpos, bufsize - bpos, "%s%s", bpos ? ", " : "", tag);
        }
    }

    return buf;
}

const char *
ccb_handling_str(int handling)
{
    const char *ret;

    switch (handling) {
    case CCB_HANDLING_PROXY_ALLOWAPP:
    case CCB_HANDLING_PROXY_BLOCKAPP:
        ret = "application";
        break;
    case CCB_HANDLING_PROXY_NSD:
        ret = "nsd";
        break;
    case CCB_HANDLING_PROXY_URL_PROXY:
        ret = "http-greylist";
        break;
    case CCB_HANDLING_PROXY_URL_PROXY_HTTPS:
        ret = "https-greylist";
        break;
    case CCB_HANDLING_PROXY_ORG_BLOCK_GREYLIST:
        ret = "org-https-greylist";
        break;
    default:
        ret = "unknown";
    }

    return ret;
}
