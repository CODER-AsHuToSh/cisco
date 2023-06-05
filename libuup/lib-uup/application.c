#include <kit-alloc.h>
#include <mockfail.h>

#include "application-private.h"
#include "conf-meta.h"
#include "dns-name.h"
#include "domainlist-private.h"       /* We point our super indices inside our application-lists' domainlists */
#include "urllist.h"
#include "xray.h"

#define CONSTCONF2APPLICATION(confp)  (const struct application *)((confp) ? (const char *)(confp) - offsetof(struct application, conf) : NULL)
#define CONF2APPLICATION(confp)       (struct application *)((confp) ? (char *)(confp) - offsetof(struct application, conf) : NULL)

static __thread struct {
    struct application_lists **al;
    unsigned lookup : 1;              /* This is a lookup - 'a' is a reversed domain */
    unsigned subdomain : 1;           /* subdomain matches ('a' is a subdomain of 'b') return 0 */
    unsigned proxy : 1;               /* This is proxy (pdl) data, not domain (dl) data */
} compar_data;

static void application_free(struct conf *base);

static const struct conf_type appct = {
    "application",
    NULL,                     /* allocate is never called for managed files */
    application_free,
};

static void
application_free(struct conf *base)
{
    struct application *me = CONF2APPLICATION(base);
    unsigned i;

    SXEA6(base->type == &appct, "application_free() with unexpected conf_type %s", base->type->name);
    kit_free(me->dindex.ref);
    kit_free(me->pindex.ref);
    for (i = 0; i < me->count; i++)
        application_lists_refcount_dec(me->al[i]);
    kit_free(me->al);
    kit_free(me);
}

static struct conf *
application_clone(struct conf *obase)
{
    struct application *me, *ome;
    unsigned i;

    if ((me = MOCKFAIL(APPLICATION_CLONE, NULL, kit_malloc(sizeof(*me)))) == NULL)
        SXEL2("Couldn't allocate an application structure");
    else {
        conf_setup(&me->conf, &appct);
        me->count = 0;
        me->mtime = 0;
        me->al = NULL;

        /* We don't copy the super-indices.  They'll be setup in application_loaded() */
        me->dindex.ref = me->pindex.ref = NULL;
        me->dindex.count = me->pindex.count = 0;

        ome = CONF2APPLICATION(obase);
        if (ome && ome->count) {
            me->count = (ome->count + 9) / 10 * 10;
            if ((me->al = MOCKFAIL(APPLICATION_CLONE_DOMAINLISTS, NULL, kit_malloc(me->count * sizeof(*me->al)))) == NULL) {
                SXEL2("Couldn't allocate %u new application domainlist slots", me->count);
                kit_free(me);
                me = NULL;
            } else {
                me->count = ome->count;
                for (i = 0; i < me->count; i++) {
                    application_lists_refcount_inc(me->al[i] = ome->al[i]);
                    if (me->mtime < me->al[i]->cs.mtime)
                        me->mtime = me->al[i]->cs.mtime;
                }
            }
        }
    }

    return me ? &me->conf : NULL;
}

static time_t
application_settimeatleast(struct conf *base, time_t t)
{
    struct application *me = CONF2APPLICATION(base);

    if (me->mtime < t)
        me->mtime = t;

    return me->mtime;
}

static unsigned
application_lists_slot(struct application_lists *const *const me, uint32_t appid, unsigned count)
{
    return conf_segment_slot((void *const *const)me, appid, count, offsetof(struct application_lists, cs));
}

static unsigned
application_appid2slot(const struct conf *base, uint32_t appid)
{
    const struct application *me = CONSTCONF2APPLICATION(base);

    return application_lists_slot(me->al, appid, me->count);
}

static const struct conf_segment *
application_slot2segment(const struct conf *base, unsigned slot)
{
    const struct application *me = CONSTCONF2APPLICATION(base);

    return slot < me->count ? &me->al[slot]->cs : NULL;
}

static void
application_slotfailedload(struct conf *base, unsigned slot, bool value)
{
    struct application *me = CONF2APPLICATION(base);
    if (slot < me->count) {
        me->al[slot]->cs.failed_load = value;
    }
}

static bool
application_slotisempty(const struct conf *base, unsigned slot)
{
    const struct application *me = CONSTCONF2APPLICATION(base);

    return slot >= me->count || (me->al[slot]->dl == NULL && me->al[slot]->pdl == NULL);
}

static void
application_freeslot(struct conf *base, unsigned slot)
{
    struct application *me = CONF2APPLICATION(base);

    SXEA1(slot < me->count, "Cannot free application domainlist slot %u (count %u)", slot, me->count);
    application_lists_refcount_dec(me->al[slot]);
    memmove(me->al + slot, me->al + slot + 1, (me->count - slot - 1) * sizeof(*me->al));
    me->count--;
}

static bool
application_usedomainlist(struct conf *base, void *val, unsigned slot, uint64_t *alloc)
{
    struct application *me = CONF2APPLICATION(base);
    struct application_lists *al = val;
    struct application_lists **alp;

    SXEA6(slot <= me->count, "Oops, Insertion point is at pos %u of %u", slot, me->count);
    if (!(me->count % 10)) {
        if ((alp = MOCKFAIL(APPLICATION_MOREDOMAINLISTS, NULL, kit_realloc(me->al, (me->count + 10) * sizeof(*me->al)))) == NULL) {
            SXEL2("Couldn't reallocate %u application domainlist slots", me->count + 10);
            return false;
        }
        me->al = alp;
    }

    application_settimeatleast(base, al->cs.mtime);
    *alloc += al->cs.alloc;
    if (slot < me->count) {
        SXEA6(me->al[slot]->cs.id >= al->cs.id, "Landed on unexpected appid %" PRIu32 " when looking for app %" PRIu32, me->al[slot]->cs.id, al->cs.id);
        if (me->al[slot]->cs.id > al->cs.id) {
            SXEL7("Existing domainlist slot %u appid %" PRIu32 " exceeds application id %" PRIu32, slot, me->al[slot]->cs.id, al->cs.id);
            memmove(me->al + slot + 1, me->al + slot, (me->count - slot) * sizeof(*me->al));
            me->count++;
        } else {
            SXEL7("Existing application-lists slot %u already contains application id %" PRIu32, slot, al->cs.id);
            *alloc -= me->al[slot]->cs.alloc;
            application_lists_refcount_dec(me->al[slot]);
        }
    } else
        me->count++;
    me->al[slot] = al;

    return true;
}

static int
compar_index(const void *va, const void *vb)
{
    const struct application_index *ai;
    struct domainlist *dl;
    const uint8_t *a, *b;

    if (compar_data.lookup)
        a = va;     /* We're doing a lookup - va points to a (reversed) domain string */
    else {
        ai = va;    /* We're sorting, va points to an application index entry */
        dl = compar_data.proxy ? compar_data.al[ai->slot]->pdl : compar_data.al[ai->slot]->dl;
        SXEA6(dl, "Cannot reference through NULL for lhs");
        a = (const uint8_t *)dl->name_bundle + ai->offset;
    }
    ai = vb;
    dl = compar_data.proxy ? compar_data.al[ai->slot]->pdl : compar_data.al[ai->slot]->dl;
    SXEA6(dl, "Cannot reference through NULL for rhs");
    b = (const uint8_t *)dl->name_bundle + ai->offset;

    for (; *b && dns_tolower[*a] == dns_tolower[*b]; a++, b++)
        ;

    if (compar_data.subdomain && *a == '.' && !*b)
        return 0;    /* If this is a lookup, and 'a' is a subdomain of 'b', then it's a match! */

    return dns_tolower[*a] - dns_tolower[*b];
}

static void
application_loaded(struct conf *base)
{
    struct application *me = CONF2APPLICATION(base);
    struct application_index *tgt, *src;
    unsigned *count, i, n, proxy, slot;
    struct application_index **ref;
    struct domainlist *dl;

    if (me && me->count)
        conf_report_load("application", APPLICATION_VERSION);

    /* Now create our super-indices */
    for (proxy = 0; proxy < 2; proxy++) {
        count = proxy ? &me->pindex.count : &me->dindex.count;
        ref = proxy ? &me->pindex.ref : &me->dindex.ref;

        for (*count = slot = 0; slot < me->count; slot++)
            if ((dl = proxy ? me->al[slot]->pdl : me->al[slot]->dl)) {
                SXEA6(dl, "Cannot reference through NULL");
                *count += dl->name_amount;
            }

        SXEA1(*ref = kit_malloc(*count * sizeof(**ref)), "Cannot allocate a super-index of %u entries", *count);

        for (i = slot = 0; slot < me->count; slot++)
            if ((dl = proxy ? me->al[slot]->pdl : me->al[slot]->dl)) {
                SXEA6(dl, "Cannot reference through NULL");
                for (n = 0; n < (unsigned)dl->name_amount; n++, i++) {
                    ref[0][i].slot = slot;
                    ref[0][i].offset = DOMAINLIST_NAME_OFFSET(dl, n);
                }
            }
        SXEA6(i == *count, "Oops, i=%u, not %u", i, *count);

        if (i > 1) {
            /* Sort the super-index */
            compar_data.al = me->al;
            compar_data.lookup = 0;
            compar_data.subdomain = 0;
            compar_data.proxy = proxy;
            qsort(*ref, *count, sizeof(**ref), compar_index);

            if (!proxy) {
                /* Remove super-domain-index subdomains */
                compar_data.al = me->al;
                compar_data.lookup = 0;
                compar_data.subdomain = !proxy;
                compar_data.proxy = proxy;
                for (tgt = *ref, src = *ref + 1; src < *ref + *count; src++)
                    if (compar_index(src, tgt))
                        *++tgt = *src;
                *count = tgt - *ref + 1;
            }
        }
    }
}

static const struct conf_segment_ops application_segment_ops = {
    application_clone,
    application_settimeatleast,
    application_appid2slot,
    application_slot2segment,
    application_slotisempty,
    application_slotfailedload,
    application_freeslot,
    application_lists_new,
    application_lists_refcount_dec,
    application_usedomainlist,
    application_loaded,
};

void
application_register_resolver(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    SXEA1(strstr(fn, "%u"), "Attempted to register %s without a %%u part", name);
    *m = conf_register(&appct, &application_segment_ops, name, fn, loadable, LOADFLAGS_APPLICATION_URLS_AS_PROXY, NULL, 0);
}

void
application_register_proxy(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    SXEA1(strstr(fn, "%u"), "Attempted to register %s without a %%u part", name);
    *m = conf_register(&appct, &application_segment_ops, name, fn, loadable, LOADFLAGS_APPLICATION_IGNORE_DOMAINS, NULL, 0);
}

void
application_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    SXEA1(strstr(fn, "%u"), "Attempted to register %s without a %%u part", name);
    *m = conf_register(&appct, &application_segment_ops, name, fn, loadable, LOADFLAGS_NONE, NULL, 0);
}

const struct application *
application_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &appct, "application_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2APPLICATION(base);
}

static bool
application_lookup_domainlist(const struct application *me, const uint8_t *name, bool proxy, struct xray *x, const char *listname)
{
    char domain[DNS_MAXLEN_STRING + 1];
    struct application_index *result;
    struct application_index *ref;
    const uint8_t *suffix;
    struct domainlist *dl;
    const char *match;
    unsigned count;
    size_t   dlen;

    if (me && dns_name_to_buf(name, domain, sizeof(domain), &dlen, DNS_NAME_DEFAULT)) {
        mem_reverse(domain, dlen);

        compar_data.al = me->al;
        compar_data.lookup = 1;
        compar_data.subdomain = !proxy;
        compar_data.proxy = proxy;

        count = proxy ? me->pindex.count : me->dindex.count;
        ref = proxy ? me->pindex.ref : me->dindex.ref;

        if ((result = bsearch(domain, ref, count, sizeof(*ref), compar_index)) != NULL) {
            dl = proxy ? me->al[result->slot]->pdl : me->al[result->slot]->dl;
            SXEA6(dl, "Cannot reference through NULL");
            match = dl->name_bundle + result->offset;
            suffix = name + dlen + !*match - !*name - strlen(match);

            XRAY6(x, "%s %s match: found %s", listname, proxy ? "exact" : "subdomain", dns_name_to_str1(suffix));
            return true;
        } else
            SXEL7("Couldn't find \"%s\" in %s", domain, listname);
    }
    return false;
}

bool
application_match_domain(const struct application *me, const uint8_t *name, struct xray *x, const char *listname)
{
    return application_lookup_domainlist(me, name, false, x, listname);
}

bool
application_proxy(const struct application *me, const uint8_t *name, struct xray *x, const char *listname)
{
    return application_lookup_domainlist(me, name, true, x, listname);
}

const uint8_t *
application_lookup_domainlist_byid(const struct application *me, uint32_t appid, const uint8_t *name, bool proxy, struct xray *x)
{
    struct application_lists *al;
    struct domainlist *dl;
    const uint8_t *ret;
    char appname[50];
    unsigned slot;

    ret = NULL;
    if (me) {
        slot = application_appid2slot(&me->conf, appid);
        al = slot < me->count ? me->al[slot] : NULL;
        if (al && al->cs.id == appid && (dl = proxy ? al->pdl : al->dl)) {
            if (al->cm && al->cm->name)
                snprintf(appname, sizeof(appname), "%s %s", al->cm->name, proxy ? "proxy" : "domain");
            else
                snprintf(appname, sizeof(appname), "application-%u %s", appid, proxy ? "proxy" : "domain");
            ret = domainlist_match(dl, name, proxy ? DOMAINLIST_MATCH_EXACT : DOMAINLIST_MATCH_SUBDOMAIN, x, appname);
        }
    }

    return ret;
}

const uint8_t *
application_match_domain_byid(const struct application *me, uint32_t appid, const uint8_t *name, struct xray *x)
{
    return application_lookup_domainlist_byid(me, appid, name, false, x);
}

const uint8_t *
application_proxy_byid(const struct application *me, uint32_t appid, const uint8_t *name, struct xray *x)
{
    return application_lookup_domainlist_byid(me, appid, name, true, x);
}

bool
application_match_url_byid(const struct application *me, uint32_t appid, const char *url, unsigned urllen)
{
    struct application_lists *al;
    unsigned slot;
    bool ret;

    ret = false;
    if (me) {
        slot = application_appid2slot(&me->conf, appid);
        al = slot < me->count ? me->al[slot] : NULL;
        if (al && al->cs.id == appid && al->ul)
            ret = urllist_match(al->ul, url, urllen);
    }

    return ret;
}
