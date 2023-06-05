/*
 * Description of the format of this config file:
 *   https://confluence.office.opendns.com/display/trac3/configuration-prefs-format
 */

#include <kit-alloc.h>
#include <mockfail.h>

#include "urlprefs-org.h"
#include "urlprefs-private.h"

#define CONSTCONF2URLPREFS(confp)  (const struct urlprefs *)((confp) ? (const char *)(confp) - offsetof(struct urlprefs, conf) : NULL)
#define CONF2URLPREFS(confp)       (struct urlprefs *)((confp) ? (char *)(confp) - offsetof(struct urlprefs, conf) : NULL)

static void urlprefs_free(struct conf *base);

static const struct conf_type urlprefsct = {
    "urlprefs",
    NULL,                     /* allocate is never called for per-org prefs */
    urlprefs_free,
};

static void
urlprefs_free(struct conf *base)
{
    struct urlprefs *me = CONF2URLPREFS(base);
    unsigned i;

    SXEA6(base->type == &urlprefsct, "urlprefs_free() with unexpected conf_type %s", base->type->name);
    for (i = 0; i < me->count; i++)
        prefs_org_refcount_dec(me->org[i]);
    kit_free(me->org);
    kit_free(me);
}

static struct conf *
urlprefs_clone(struct conf *obase)
{
    struct urlprefs *me, *ome;
    unsigned i;

    if ((me = MOCKFAIL(URLPREFS_CLONE, NULL, kit_malloc(sizeof(*me)))) == NULL)
        SXEL2("Couldn't allocate a urlprefs structure");
    else {
        conf_setup(&me->conf, &urlprefsct);
        me->count = 0;
        me->mtime = 0;
        me->org = NULL;

        ome = CONF2URLPREFS(obase);
        if (ome && ome->count) {
            me->count = (ome->count + 9) / 10 * 10;
            if ((me->org = MOCKFAIL(URLPREFS_CLONE_ORGS, NULL, kit_malloc(me->count * sizeof(*me->org)))) == NULL) {
                SXEL2("Couldn't allocate %u new urlprefs org slots", me->count);
                kit_free(me);
                me = NULL;
            } else {
                me->count = ome->count;
                for (i = 0; i < me->count; i++) {
                    prefs_org_refcount_inc(me->org[i] = ome->org[i]);
                    if (me->mtime < me->org[i]->cs.mtime)
                        me->mtime = me->org[i]->cs.mtime;
                }
            }
        }
    }

    return me ? &me->conf : NULL;
}

static time_t
urlprefs_settimeatleast(struct conf *base, time_t t)
{
    struct urlprefs *me = CONF2URLPREFS(base);

    if (me->mtime < t)
        me->mtime = t;
    return me->mtime;
}

static unsigned
urlprefs_orgid2slot(const struct conf *base, uint32_t orgid)
{
    const struct urlprefs *me = CONSTCONF2URLPREFS(base);

    return prefs_org_slot(me->org, orgid, me->count);
}

static const struct conf_segment *
urlprefs_slot2segment(const struct conf *base, unsigned slot)
{
    const struct urlprefs *me = CONSTCONF2URLPREFS(base);

    return slot < me->count ? &me->org[slot]->cs : NULL;
}

static void
urlprefs_slotfailedload(struct conf *base, unsigned slot, bool value)
{
    struct urlprefs *me = CONF2URLPREFS(base);
    if (slot < me->count) {
        me->org[slot]->cs.failed_load = value;
    }
}

bool
urlprefs_slotisempty(const struct conf *base, unsigned slot)
{
    const struct urlprefs *me = CONSTCONF2URLPREFS(base);

    return slot >= me->count || &me->org[slot]->fp.total == 0;
}

static void
urlprefs_freeslot(struct conf *base, unsigned slot)
{
    struct urlprefs *me = CONF2URLPREFS(base);

    SXEA1(slot < me->count, "Cannot free urlprefs org slot %u (count %u)", slot, me->count);
    prefs_org_refcount_dec(me->org[slot]);
    memmove(me->org + slot, me->org + slot + 1, (me->count - slot - 1) * sizeof(*me->org));
    me->count--;
}

static bool
urlprefs_useorg(struct conf *base, void *vupo, unsigned slot, uint64_t *alloc)
{
    struct urlprefs *me = CONF2URLPREFS(base);
    struct prefs_org *upo = vupo;
    struct prefs_org **upop;

    SXEA6(slot <= me->count, "Oops, Insertion point is at pos %u of %u", slot, me->count);
    if (!(me->count % 10)) {
        if ((upop = MOCKFAIL(URLPREFS_MOREORGS, NULL, kit_realloc(me->org, (me->count + 10) * sizeof(*me->org)))) == NULL) {
            SXEL2("Couldn't reallocate %u urlprefs org slots", me->count + 10);
            return false;
        }
        me->org = upop;
    }

    if (!(upo->fp.loadflags & LOADFLAGS_FP_FAILED)) {
        urlprefs_settimeatleast(base, upo->cs.mtime);
    }

    return prefs_org_fill_slot(upo, me->org, &me->count, slot, alloc);
}

static void
urlprefs_loaded(struct conf *base)
{
    struct urlprefs *me = CONF2URLPREFS(base);

    if (me && me->count)
        conf_report_load(me->org[0]->fp.ops->type, me->org[0]->fp.version);
}

static const struct conf_segment_ops urlprefs_segment_ops = {
    urlprefs_clone,
    urlprefs_settimeatleast,
    urlprefs_orgid2slot,
    urlprefs_slot2segment,
    urlprefs_slotisempty,
    urlprefs_slotfailedload,
    urlprefs_freeslot,
    urlprefs_org_new,
    prefs_org_refcount_dec,
    urlprefs_useorg,
    urlprefs_loaded,
};

void
urlprefs_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    SXEA1(strstr(fn, "%u"), "Attempted to register %s without a %%u part", name);
    *m = conf_register(&urlprefsct, &urlprefs_segment_ops, name, fn, loadable,
                       LOADFLAGS_FP_ALLOW_BUNDLE_EXTREFS | LOADFLAGS_FP_ELEMENTTYPE_URL
                       | LOADFLAGS_FP_ELEMENTTYPE_APPLICATION | LOADFLAGS_FP_SEGMENTED, NULL, 0);
}

const struct urlprefs *
urlprefs_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &urlprefsct, "urlprefs_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2URLPREFS(base);
}

const struct prefblock *
urlprefs_get_prefblock(const struct urlprefs *me, uint32_t orgid)
{
    unsigned i;

    if (me == NULL || (i = prefs_org_slot(me->org, orgid, me->count)) == me->count || me->org[i]->cs.id != orgid)
        return NULL;

    return me->org[i]->fp.values;
}

/* Lookup urlprefs by its org and bundle id */
bool
urlprefs_get_policy(const struct urlprefs *me, pref_t *pref, uint32_t orgid, uint32_t bundleid)
{
    uint32_t                 global_parent_org = pref_get_globalorg();
    const struct prefblock  *blk, *pblk, *gblk;
    const struct prefbundle *bundle;

    SXEE6("(pref=%p, me=%p, orgid=%u, bundleid=%u)", pref, me, orgid, bundleid);
    pref_fini(pref);

    if ((blk = urlprefs_get_prefblock(me, orgid)) == NULL) {
        SXEL6("Unable to find orgid %u in urlprefs", orgid);
        goto DONE;
    }

    if (!(bundle = prefbundle_get(blk->resource.bundle, blk->count.bundles, AT_BUNDLE, bundleid))) {
        SXEL6("Unable to find bundleid %u for orgid %u in urlprefs", bundleid, orgid);
        goto DONE;
    }

    pblk = urlprefs_get_prefblock(me, blk->resource.org->parentid);
    gblk = urlprefs_get_prefblock(me, global_parent_org);
    pref_init_bybundle(pref, blk, pblk, gblk, orgid, bundle - blk->resource.bundle);

DONE:
    SXER6("return %d // %s, pref { %p, %p, %p, %u }", PREF_VALID(pref), PREF_VALID(pref) ? "valid" : "invalid", pref->blk,
          pref->parentblk, pref->globalblk, pref->index);
    return PREF_VALID(pref);
}
