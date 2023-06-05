#include <errno.h>
#include <kit-alloc.h>
#include <kit-random.h>
#include <mockfail.h>

#if __FreeBSD__
#include <sys/socket.h>
#endif

#include "cidr-ipv4.h"
#include "cidr-ipv6.h"
#include "cidrlist.h"
#include "conf-loader.h"
#include "object-hash.h"
#include "uup-counters.h"
#include "xray.h"

#define CIDRLIST_REALLOC_LEN      20    /* Additional capacity to add on realloc() */
#define CONSTCONF2CIDRLIST(confp) (const struct cidrlist *)((confp) ? (const char *)(confp) - offsetof(struct cidrlist, conf) : NULL)
#define CONF2CIDRLIST(confp)      (struct cidrlist *)((confp) ? (char *)(confp) - offsetof(struct cidrlist, conf) : NULL)

#define CIDRLIST_OBJECT_HASH_ROWS  (1 << 14)    /* 16,384 rows with 7 usable cells per row = 114,688 cells and 1MB RAM */
#define CIDRLIST_OBJECT_HASH_LOCKS 32

module_conf_t CONF_DNAT_SERVERS;
module_conf_t CONF_IPALLOWLIST;
module_conf_t CONF_IPBLOCKLIST;
module_conf_t CONF_RATELIMIT_ALLOWLIST;
module_conf_t CONF_TRUSTED_NETWORKS;
module_conf_t CONF_LOCAL_ADDRESSES;
module_conf_t CONF_IPPROXY;

static struct conf *cidrlist_allocate(const struct conf_info *info, struct conf_loader *cl);
static void cidrlist_free(struct conf *base);

static const struct conf_type clct = {
    "cidrlist",
    cidrlist_allocate,
    cidrlist_free,
};

static const struct conf_type *clctp = &clct;

/* Only used by tests - to get the original cidrlist type contents
 */
const struct conf_type *
cidrlist_get_real_type_internals(struct conf_type *copy)
{
    if (copy)
        *copy = clct;

    return &clct;
}

void
cidrlist_set_type_internals(const struct conf_type *replacement)
{
    /* Only used by tests - to hijack the original cidrlist type contents */
    clctp = replacement ?: &clct;
}

void
cidrlist_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(clctp, NULL, name, fn, loadable, LOADFLAGS_NONE, NULL, 0);
}

void
iplist_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(clctp, NULL, name, fn, loadable, LOADFLAGS_CIDRLIST_IP, NULL, 0);
}

const struct cidrlist *
cidrlist_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == clctp, "cidrlist_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2CIDRLIST(base);
}

/**
 * Get the cidrlist, which the additional constraint that it be an IP list
 */
const struct cidrlist *
iplist_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    const struct cidrlist *me = CONSTCONF2CIDRLIST(base);

    SXEA6(!base || base->type == clctp, "iplist_conf_get() with unexpected conf_type %s", base->type->name);
    SXEA6(!me || me->how == PARSE_IP_ONLY, "iplist_conf_get() with cidrlist, not iplist");
    return me;
}

static struct cidrlist *
cidrlist_new_empty(unsigned extra)
{
    struct cidrlist *me;

    if ((me = MOCKFAIL(cidrlist_new, NULL, kit_calloc(1, sizeof(*me) + extra))) == NULL)
        SXEL2("Failed to allocate cidrlist of %zu bytes", sizeof(*me));
    else
        conf_setup(&me->conf, clctp);

    return me;
}

struct cidrlist *
cidrlist_new(enum cidr_parse how)
{
    struct cidrlist *me;

    if ((me = cidrlist_new_empty(0)) != NULL)
        me->how = how;

    return me;
}

static void
reduce_loaded_data(struct cidrlist *me)
{
    size_t sz;

    /* Don't leave excessive memory allocated */
    if (me->in4.count != me->in4.alloc) {
        sz = sizeof(*me->in4.cidr) * me->in4.count;
        SXEA1(me->in4.cidr = kit_realloc(me->in4.cidr, sz), "Failed to realloc cidrlist IPv4 data down to %zu", sz);
        me->in4.alloc = me->in4.count;
    }

    if (me->in6.count != me->in6.alloc) {
        sz = sizeof(*me->in6.cidr) * me->in6.count;
        SXEA1(me->in6.cidr = kit_realloc(me->in6.cidr, sz), "Failed to realloc cidrlist IPv6 data down to %zu", sz);
        me->in6.alloc = me->in6.count;
    }
}

static void
sort_loaded_data(struct cidrlist *me, int sortv4, int sortv6)
{
    int collision;
    unsigned i;

    /*
     * The strategy when loading data is to compare each cidr with
     * the previous one while loading to determine if it needs to be
     * sorted at all.  If it doesn't need to be sorted, then we've done
     * N-1 comparisons.  The alternative of sorting already sorted data
     * is that for 10 records we'd do 15 comparisons and for 100 records
     * we'd do over 300 comparisons.  So, ideally, to keep things optimal,
     * the maintainer of the list should keep it sorted.
     */

    if (sortv4) {
        collision = 0;
#ifdef __linux__
        qsort_r(me->in4.cidr, me->in4.count, sizeof(*me->in4.cidr), cidr_ipv4_sort_compar_r, &collision);
#else
        qsort_r(me->in4.cidr, me->in4.count, sizeof(*me->in4.cidr), &collision, cidr_ipv4_sort_compar_r);
#endif

        /*
         * If there were any collisions, trawl through the entire
         * list resolving them.  This is ok to do as a cidrlist has
         * no associated data - the search routine returns boolean,
         * colliding CIDRs can be reduced by removing the smaller one.
         */
        if (collision)
            for (i = 1; i < me->in4.count; i++)
                if (CIDR_IPV4_COLLIDES(me->in4.cidr + i - 1, me->in4.cidr + i)) {
                    memmove(me->in4.cidr + i, me->in4.cidr + i + 1, (me->in4.count - i - 1) * sizeof(*me->in4.cidr));
                    i--;
                    me->in4.count--;
                }
    }

    if (sortv6) {
        collision = 0;
#ifdef __linux__
        qsort_r(me->in6.cidr, me->in6.count, sizeof(*me->in6.cidr), cidr_ipv6_sort_compar_r, &collision);
#else
        qsort_r(me->in6.cidr, me->in6.count, sizeof(*me->in6.cidr), &collision, cidr_ipv6_sort_compar_r);
#endif

        /* If there were any collisions, trawl through the entire list resolving them */
        if (collision)
            for (i = 1; i < me->in6.count; i++)
                if (cidr_ipv6_collides(me->in6.cidr + i - 1, me->in6.cidr + i)) {
                    memmove(me->in6.cidr + i, me->in6.cidr + i + 1, (me->in6.count - i - 1) * sizeof(*me->in6.cidr));
                    i--;
                    me->in6.count--;
                }
    }
}

void
cidrlist_sort(struct cidrlist *me)
{
    if (me) {
        sort_loaded_data(me, 1, 1);
        reduce_loaded_data(me);
    }
}

static const char *
cidrlist_add(struct cidrlist *me, const char *str, const char *delims, int *sortedv4, int *sortedv6)
{
    struct cidr_ipv6 tmpv6, *nv6;
    struct cidr_ipv4 tmpv4, *nv4;
    size_t nalloc, sz;
    const char *pos;

    while (*str && strchr(delims, *str))
        str++;
    while (*str) {
        pos = str;
        if ((str = cidr_ipv4_sscan(&tmpv4, pos, me->how)) != NULL) {
            if (me->in4.count == me->in4.alloc) {
                nalloc = me->in4.alloc + CIDRLIST_REALLOC_LEN;
                sz = sizeof(*me->in4.cidr) * nalloc;
                if ((nv4 = MOCKFAIL(CIDRLIST_ADD4, NULL, kit_realloc(me->in4.cidr, sz))) == NULL) {
                    SXEL2("Failed to realloc %zu bytes", sz);
                    return NULL;
                }
                me->in4.alloc = nalloc;
                me->in4.cidr = nv4;
            }
            me->in4.cidr[me->in4.count] = tmpv4;
            if (me->in4.count && *sortedv4 && cidr_ipv4_find_compare(me->in4.cidr + me->in4.count - 1, &tmpv4) >= 0)
                *sortedv4 = 0;
            me->in4.count++;
        } else if ((str = cidr_ipv6_sscan(&tmpv6, pos, me->how)) != NULL) {
            if (me->in6.count == me->in6.alloc) {
                nalloc = me->in6.alloc + CIDRLIST_REALLOC_LEN;
                sz = sizeof(*me->in6.cidr) * nalloc;
                if ((nv6 = MOCKFAIL(CIDRLIST_ADD6, NULL, kit_realloc(me->in6.cidr, sz))) == NULL) {
                    SXEL2("Failed to realloc %zu bytes", sz);
                    return NULL;
                }
                me->in6.alloc = nalloc;
                me->in6.cidr = nv6;
            }
            me->in6.cidr[me->in6.count] = tmpv6;
            if (me->in6.count && *sortedv6 && cidr_ipv6_find_compare(me->in6.cidr + me->in6.count - 1, &tmpv6) >= 0)
                *sortedv6 = 0;
            me->in6.count++;
        } else
            return pos;
        while (*str && strchr(delims, *str))
            str++;
    }

    return str;
}

bool
cidrlist_append(struct cidrlist *me, const struct cidrlist *cl)
{
    struct cidr_ipv6 *nv6;
    struct cidr_ipv4 *nv4;
    size_t nalloc, sz;

    if (!me && cl && (cl->in4.count || cl->in6.count)) {
        SXEL2("Cannot append data to a NULL list");
        return false;
    }

    if (cl && cl->in4.count) {
        nalloc = me->in4.count + cl->in4.count;
        sz = sizeof(*me->in4.cidr) * nalloc;
        if ((nv4 = MOCKFAIL(CIDRLIST_APPEND4, NULL, kit_realloc(me->in4.cidr, sz))) == NULL) {
            SXEL2("Failed to realloc %zu bytes", sz);
            return false;
        }
        me->in4.alloc = nalloc;
        me->in4.cidr = nv4;
        memcpy(me->in4.cidr + me->in4.count, cl->in4.cidr, sizeof(*cl->in4.cidr) * cl->in4.count);
        me->in4.count = nalloc;
    }

    if (cl && cl->in6.count) {
        nalloc = me->in6.count + cl->in6.count;
        sz = sizeof(*me->in6.cidr) * nalloc;
        if ((nv6 = MOCKFAIL(CIDRLIST_APPEND6, NULL, kit_realloc(me->in6.cidr, sz))) == NULL) {
            SXEL2("Failed to realloc %zu bytes", sz);
            return false;
        }
        me->in6.alloc = nalloc;
        me->in6.cidr = nv6;
        memcpy(me->in6.cidr + me->in6.count, cl->in6.cidr, sizeof(*cl->in6.cidr) * cl->in6.count);
        me->in6.count = nalloc;
    }

    return true;
}

static bool
cidrlist_hash_use(void *v, void **vp)
{
    struct object_fingerprint *of = v;
    struct cidrlist *candidate = *vp;

    if (memcmp(candidate->fingerprint, of->fp, of->len) == 0) {
        cidrlist_refcount_inc(candidate);
        return true;
    }
    return false;
}

struct cidrlist *
cidrlist_new_from_string(const char *str, const char *delims, const char **endptr, struct object_fingerprint *of, enum cidr_parse how)
{
    int success, sortedv4, sortedv6;
    struct cidrlist *me;
    unsigned magic;

    me = NULL;
    if (of) {
        if (of->hash == NULL)
            of->hash = object_hash_new(CIDRLIST_OBJECT_HASH_ROWS, CIDRLIST_OBJECT_HASH_LOCKS, of->len);
        else if ((magic = object_hash_magic(of->hash)) != of->len) {
            SXEL2("Invalid cidrlist fingerprint; length should be %u, not %u", magic, of->len);
            return NULL;
        } else
            me = object_hash_action(of->hash, of->fp, of->len, cidrlist_hash_use, of);

        kit_counter_incr(me ? COUNTER_UUP_OBJECT_HASH_HIT : COUNTER_UUP_OBJECT_HASH_MISS);
    }

    if (me == NULL) {
        success = 0;
        if ((me = cidrlist_new_empty(of && of->hash ? of->len : 0)) == NULL)
            goto SXE_EARLY_OUT;
        me->how = how;

        sortedv4 = sortedv6 = 1;
        *endptr = cidrlist_add(me, str, delims, &sortedv4, &sortedv6);

        if ((*endptr == NULL) || (me->in4.count == 0 && me->in6.count == 0))
            goto SXE_EARLY_OUT;

        sort_loaded_data(me, !sortedv4, !sortedv6);
        reduce_loaded_data(me);

        if (of && of->hash) {
            me->oh = of->hash;
            memcpy(me->fingerprint, of->fp, of->len);
            if (object_hash_add(me->oh, me, of->fp, of->len) == NULL) {
                SXEL2("Failed to hash cidrlist object; memory exhaustion?");
                me->oh = NULL;
            }
        }
    } else {
        /* We don't know how much we parsed, cause we're using the fingerprint
         * but there isn't a great way to communicate that... */
        *endptr = str + strlen(str);
    }
    success = 1;

SXE_EARLY_OUT:
    if (!success) {
        CONF_REFCOUNT_DEC(me);
        me = NULL;
    }

    SXEL6("%s(str=?, how=%s) {} // %u IPv4 cidrs and %u IPv6 cidrs loaded", __FUNCTION__, CIDR_PARSE_TXT(how), me ? me->in4.count : 0, me ? me->in6.count : 0);

    return me;
}

struct cidrlist *
cidrlist_new_from_file(struct conf_loader *cl, enum cidr_parse how)
{
    int sortedv4, sortedv6, success;
    const char *consumed;
    struct cidrlist *me;
    const char *line;

    success = 0;
    line = NULL;
    me = NULL;

    if ((me = cidrlist_new_empty(0)) == NULL)
        goto SXE_EARLY_OUT;
    me->how = how;

    sortedv4 = sortedv6 = 1;
    while ((line = conf_loader_readline(cl)) != NULL)
        if ((consumed = cidrlist_add(me, line, ", \t\n", &sortedv4, &sortedv6)) == NULL || *consumed != '\0') {
            SXEL2("%s(): %s: %u: failed to parse address", __FUNCTION__, conf_loader_path(cl), conf_loader_line(cl));
            goto SXE_EARLY_OUT;
        }

    if (conf_loader_eof(cl)) {
        sort_loaded_data(me, !sortedv4, !sortedv6);
        reduce_loaded_data(me);
        success = 1;
    }

SXE_EARLY_OUT:
    if (!success) {
        CONF_REFCOUNT_DEC(me);
        me = NULL;
    }

    SXEL6("%s(cl=?, how=%s) {} // %u IPv4 cidrs and %u IPv6 cidrs loaded from %s", __FUNCTION__, CIDR_PARSE_TXT(how), me ? me->in4.count : 0, me ? me->in6.count : 0, conf_loader_path(cl));

    if (me == NULL)
        errno = EINVAL;

    return me;
}

static struct conf *
cidrlist_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct cidrlist *me;

    SXEA6(info->type == clctp, "%s() with unexpected conf_type %s", __FUNCTION__, info->type->name);
    me = cidrlist_new_from_file(cl, info->loadflags == LOADFLAGS_CIDRLIST_CIDR ? PARSE_CIDR_ONLY :
                                    info->loadflags == LOADFLAGS_CIDRLIST_IP ? PARSE_IP_ONLY :
                                    PARSE_IP_OR_CIDR);

    return me ? &me->conf : NULL;
}

static bool
cidrlist_hash_remove(void *v, void **vp)
{
    struct cidrlist *candidate = *vp;
    struct cidrlist *me = v;

    if (me == candidate && me->conf.refcount == 0) {
        *vp = NULL;
        return true;
    }
    return false;
}

static void
cidrlist_free(struct conf *base)
{
    struct cidrlist *me = CONF2CIDRLIST(base);

    SXEA6(base->type == clctp, "cidrlist_free() with unexpected conf_type %s", base->type->name);

    if (me->oh && !object_hash_action(me->oh, me->fingerprint, object_hash_magic(me->oh), cidrlist_hash_remove, me)) {
        /*-
         * XXX: It's unusal to get here...
         *      1. This thread gets into cidrlist_free()
         *      2. Other thread gets a reference to me through the object-hash
         *      3. This thread fails the object_hash_action(..., cidrlist_hash_remove, ...)
         *      4. Other thread releases its reference
         * When we get to this point, the other thread will delete (or already has deleted) the object internals,
         * so in fact, the object_hash_action() failure implies that the object is now somebody else's problem.
         */
        SXEL6("Failed to remove cidrlist from its hash (refcount %d); another thread raced to get a reference", me->conf.refcount);
    } else {
        kit_free(me->in4.cidr);
        kit_free(me->in6.cidr);
        kit_free(me);
    }
}

void
cidrlist_refcount_inc(struct cidrlist *me)
{
    CONF_REFCOUNT_INC(me);
}

void
cidrlist_refcount_dec(struct cidrlist *me)
{
    CONF_REFCOUNT_DEC(me);
}

/**
 * Search for a matching CIDR in a CIDR list.
 *
 * @param me       urllist to search in
 * @param addr     netaddr to search for
 * @param x        xray pointer or NULL
 * @param listname name of the list being searched or NULL (used only by xray and debug build)
 *
 * @return 0 if no match, the number of bits in the matching CIDR, or CIDR_MATCH_ALL if the matching CIDR was 0.0.0.0/0
 */
unsigned
cidrlist_search(const struct cidrlist *me, const struct netaddr *addr, struct xray *x, const char *listname)
{
    struct cidr_ipv6  cidr_ipv6;
    struct cidr_ipv6 *match_ipv6;
    struct cidr_ipv4  cidr_ipv4;
    struct cidr_ipv4 *match_ipv4;
    unsigned          result = 0;

    if (me != NULL) {
        switch (addr->family) {
        case AF_INET6:
            cidr_ipv6.addr     = addr->in6_addr;
            cidr_ipv6.maskbits = 128;
            match_ipv6 = bsearch(&cidr_ipv6, me->in6.cidr, me->in6.count, sizeof(*me->in6.cidr), cidr_ipv6_find_compare);
            result     = !match_ipv6 ? 0 : match_ipv6->maskbits ?: CIDR_MATCH_ALL;

            if (result || NETADDRV6_DWORD(*addr, 0) || NETADDRV6_DWORD(*addr, 1)
             || (NETADDRV6_DWORD(*addr, 2) && ntohl(NETADDRV6_DWORD(*addr, 2)) != 0xffff)
             || ntohl(NETADDRV6_DWORD(*addr, 3)) == 1)
                break;    /* Non RFC 5156 IPv4 mapped/compatible addresses */

            /* RFC 5156 IPv4 mapped/compatible addresses fall thru to compare against the IPv4 tree */
            cidr_ipv4.addr = ntohl(NETADDRV6_DWORD(*addr, 3));

            /* FALLTHRU */
        case AF_INET:
            if (addr->family == AF_INET)
                cidr_ipv4.addr = ntohl(addr->in_addr.s_addr);

            cidr_ipv4.mask = 0xffffffff;
            match_ipv4 = bsearch(&cidr_ipv4, me->in4.cidr, me->in4.count, sizeof(*me->in4.cidr), cidr_ipv4_find_compare);
            result = !match_ipv4 ? 0 : cidr_ipv4_maskbits(match_ipv4) ?: CIDR_MATCH_ALL;
            break;
        }
    }

    if (result && listname)
        XRAY6(x, "%s match: found %s", listname, netaddr_to_str(addr));

    return result;
}

char *
cidrlist_to_buf(const struct cidrlist *me, char *buf, size_t sz, size_t *len_out)
{
    size_t len, pos;
    const char *txt;
    unsigned i;

    buf[pos = 0] = '\0';

    for (i = 0; me && i < me->in4.count; i++) {
        txt = cidr_ipv4_to_str(me->in4.cidr + i, me->how != PARSE_CIDR_ONLY);
        SXEA6(me->how != PARSE_IP_ONLY || strchr(txt, '/') == NULL, "Didn't expect to find netmask data in a PARSE_IP_ONLY list");
        len = strlen(txt);

        if (pos + len + !!i >= sz)
            return NULL;

        if (pos)
            buf[pos++] = ' ';

        strcpy(buf + pos, txt);
        pos += len;
    }

    for (i = 0; me && i < me->in6.count; i++) {
        txt = cidr_ipv6_to_str(me->in6.cidr + i, me->how != PARSE_CIDR_ONLY);
        SXEA6(me->how != PARSE_IP_ONLY || strchr(txt, '/') == NULL, "Didn't expect to find prefixlen data in a PARSE_IP_ONLY list");
        len = strlen(txt);

        if (pos + len + !!i >= sz)
            return NULL;

        if (pos)
            buf[pos++] = ' ';

        strcpy(buf + pos, txt);
        pos += len;
    }

    if (len_out)
        *len_out = pos;

    return buf;
}

/**
 *  Return the worst case buffer size needed to convert the cidrlist into a string
 */
size_t
cidrlist_buf_size(const struct cidrlist *me)
{
    size_t sz;

    sz = me ? me->in6.count * (INET6_ADDRSTRLEN + (me->how != PARSE_IP_ONLY) * (sizeof("[]/128") - 1))
            + me->in4.count * (INET_ADDRSTRLEN + (me->how != PARSE_IP_ONLY) * (sizeof("/32") - 1)) : 0;
    return sz ?: 1;
}

/**
 * Deallocate a index randomization list
 */
void
iplist_random_free(struct random_list_index **rli_ptr)
{
    SXEA6(*rli_ptr, "Should only try freeing non-null lists");
    SXEL6("%s(): Free list=%p count=%d", __FUNCTION__, *rli_ptr, (*rli_ptr)->count);

    kit_free(*rli_ptr);
    *rli_ptr = NULL;
}

/**
 * Generate a new index randomization list for a cidrlist if needed
 *
 * @param me      Cidrlist to index
 * @param rli_ptr Pointer to a pointer in which the allocated index is kept; *rli_ptr == NULL if no index has been created
 *
 * @return The index didn't need to be updated or was updated successfully
 */
static bool
iplist_random_check_build(const struct cidrlist *me, struct random_list_index **rli_ptr)
{
    unsigned i, n, tmp;
    unsigned count = me->in4.count + me->in6.count;

    if (*rli_ptr) {
        /*
         * Check if the current list needs to be replaced, which only needs
         * to happen if the number of items in the cidrlist has changed.
         */
        if (count == (*rli_ptr)->count)
            return true;

        /* Free the current random index list */
        iplist_random_free(rli_ptr);
    }

    struct random_list_index *random_list;
    if ((random_list = MOCKFAIL(iplist_random, NULL,
                                kit_malloc(sizeof(*random_list) + count * sizeof(*random_list->item)))) == NULL) {
        SXEL2("Couldn't allocate iplist random index");
        return false;
    }
    *rli_ptr = random_list;

    random_list->count = random_list->n = 0;
    for (i = 0; i < me->in4.count; i++) {
        random_list->item[random_list->count++] = i;
    }
    for (i = 0; i < me->in6.count; i++) {
        random_list->item[random_list->count++] = me->in4.count + i;
    }

    /* Shuffle the index list */
    i = random_list->count;
    while (i > 1) {
        n = kit_random32() % i--;
        tmp = random_list->item[n];
        random_list->item[n] = random_list->item[i];
        random_list->item[i] = tmp;
    }

    SXEL6("%s(cidrlist=%p rli_ptr=%p): Allocated list=%p count=%d", __FUNCTION__, me, rli_ptr, random_list, random_list->count);

    return true;
}

/**
 * Use the randomization index list to choose a item from the provided cidrlist
 * which is not also on the ignore list.
 */
static bool
iplist_random_get(const struct cidrlist *me, struct random_list_index *random_list, struct netsock *sock,
                  struct cidrlist *ignore, struct xray *x, const char *listname)
{
    unsigned i, index, n;
    in_addr_t ip4;
    struct netsock tmpsock;

    for (i = 0; i < random_list->count; i++) {
        n = (random_list->n + i) % random_list->count;

        index = random_list->item[n];
        if (index >= me->in4.count) {
            index -= me->in4.count;
            netsock_init(&tmpsock, AF_INET6, &me->in6.cidr[index].addr, sock->port);
        } else {
            ip4 = htonl(me->in4.cidr[index].addr);
            netsock_init(&tmpsock, AF_INET, &ip4, sock->port);
        }

        /* Check against the ignore list if present */
        if (!cidrlist_search(ignore, &tmpsock.a, x, "ignore")) {
            random_list->n = (n + 1) % random_list->count;

            memcpy(sock, &tmpsock, sizeof(tmpsock));
            if (listname)
                XRAY6(x, "%s match: selected random address %s", listname, netaddr_to_str(&sock->a));
            return true;
        }
    }

    if (listname)
        XRAY6(x, "%s match: no address available", listname);
    return false;
}

/**
 * Lookup a random IP from the provided list, excluding any IPs in an ignore list.
 */
bool
iplist_random(const struct cidrlist *me, struct random_list_index **rli_ptr, struct netsock *sock, struct cidrlist *ignore,
              struct xray *x, const char *listname)
{
    if (me) {
        SXEA6(rli_ptr, "Random list pointer should be initialized");
        SXEA6(sock, "Netsock pointer should be initialized");
        if (!iplist_random_check_build(me, rli_ptr)) {
            return false;
        }

        return iplist_random_get(me, *rli_ptr, sock, ignore, x, listname);
    }

    return false;
}
