/*
 * Description of the format of this config file:
 *   https://confluence.office.opendns.com/display/trac3/configuration-prefs-format
 */
#include <kit-alloc.h>
#include <mockfail.h>

#include "cidrprefs-org.h"
#include "cidrprefs-private.h"

#define CONSTCONF2CIDRPREFS(confp)  (const struct cidrprefs *)((confp) ? (const char *)(confp) - offsetof(struct cidrprefs, conf) : NULL)
#define CONF2CIDRPREFS(confp)       (struct cidrprefs *)((confp) ? (char *)(confp) - offsetof(struct cidrprefs, conf) : NULL)

module_conf_t CONF_CIDRPREFS;
static void cidrprefs_free(struct conf *base);

static const struct conf_type cidrprefsct = {
    "cidrprefs",
    NULL,                     /* allocate is never called for per-org prefs */
    cidrprefs_free,
};

static void
cidrprefs_free(struct conf *base)
{
    struct cidrprefs *me = CONF2CIDRPREFS(base);
    unsigned i;

    SXEA6(base->type == &cidrprefsct, "cidrprefs_free() with unexpected conf_type %s", base->type->name);
    for (i = 0; i < me->count; i++)
        prefs_org_refcount_dec(me->org[i]);
    kit_free(me->org);
    kit_free(me);
}

static struct conf *
cidrprefs_clone(struct conf *obase)
{
    struct cidrprefs *me, *ome;
    unsigned i;

    if ((me = MOCKFAIL(CIDRPREFS_CLONE, NULL, kit_malloc(sizeof(*me)))) == NULL)
        SXEL2("Couldn't allocate a cidrprefs structure");
    else {
        conf_setup(&me->conf, &cidrprefsct);
        me->count = 0;
        me->mtime = 0;
        me->org = NULL;

        ome = CONF2CIDRPREFS(obase);
        if (ome && ome->count) {
            me->count = (ome->count + 9) / 10 * 10;
            if ((me->org = MOCKFAIL(CIDRPREFS_CLONE_ORGS, NULL, kit_malloc(me->count * sizeof(*me->org)))) == NULL) {
                SXEL2("Couldn't allocate %u new cidrprefs org slots", me->count);
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
cidrprefs_settimeatleast(struct conf *base, time_t t)
{
    struct cidrprefs *me = CONF2CIDRPREFS(base);

    if (me->mtime < t)
        me->mtime = t;
    return me->mtime;
}

static unsigned
cidrprefs_orgid2slot(const struct conf *base, uint32_t orgid)
{
    const struct cidrprefs *me = CONSTCONF2CIDRPREFS(base);

    return prefs_org_slot(me->org, orgid, me->count);
}

static const struct conf_segment *
cidrprefs_slot2segment(const struct conf *base, unsigned slot)
{
    const struct cidrprefs *me = CONSTCONF2CIDRPREFS(base);

    return slot < me->count ? &me->org[slot]->cs : NULL;
}

static void
cidrprefs_slotfailedload(struct conf *base, unsigned slot, bool value)
{
    struct cidrprefs *me = CONF2CIDRPREFS(base);
    if (slot < me->count) {
        me->org[slot]->cs.failed_load = value;
    }
}

bool
cidrprefs_slotisempty(const struct conf *base, unsigned slot)
{
    const struct cidrprefs *me = CONSTCONF2CIDRPREFS(base);

    return slot >= me->count || &me->org[slot]->fp.total == 0;
}

static void
cidrprefs_freeslot(struct conf *base, unsigned slot)
{
    struct cidrprefs *me = CONF2CIDRPREFS(base);

    SXEA1(slot < me->count, "Cannot free cidrprefs org slot %u (count %u)", slot, me->count);
    prefs_org_refcount_dec(me->org[slot]);
    memmove(me->org + slot, me->org + slot + 1, (me->count - slot - 1) * sizeof(*me->org));
    me->count--;
}

static bool
cidrprefs_useorg(struct conf *base, void *vcpo, unsigned slot, uint64_t *alloc)
{
    struct cidrprefs *me = CONF2CIDRPREFS(base);
    struct prefs_org *cpo = vcpo;
    struct prefs_org **cpop;

    SXEA6(slot <= me->count, "Oops, Insertion point is at pos %u of %u", slot, me->count);
    if (!(me->count % 10)) {
        if ((cpop = MOCKFAIL(CIDRPREFS_MOREORGS, NULL, kit_realloc(me->org, (me->count + 10) * sizeof(*me->org)))) == NULL) {
            SXEL2("Couldn't reallocate %u cidrprefs org slots", me->count + 10);
            return false;
        }
        me->org = cpop;
    }

    if (!(cpo->fp.loadflags & LOADFLAGS_FP_FAILED)) {
        cidrprefs_settimeatleast(base, cpo->cs.mtime);
    }
    return prefs_org_fill_slot(cpo, me->org, &me->count, slot, alloc);
}

static void
cidrprefs_loaded(struct conf *base)
{
    struct cidrprefs *me = CONF2CIDRPREFS(base);

    if (me && me->count)
        conf_report_load(me->org[0]->fp.ops->type, me->org[0]->fp.version);
}

static const struct conf_segment_ops cidrprefs_segment_ops = {
    cidrprefs_clone,
    cidrprefs_settimeatleast,
    cidrprefs_orgid2slot,
    cidrprefs_slot2segment,
    cidrprefs_slotisempty,
    cidrprefs_slotfailedload,
    cidrprefs_freeslot,
    cidrprefs_org_new,
    prefs_org_refcount_dec,
    cidrprefs_useorg,
    cidrprefs_loaded,
};

void
cidrprefs_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    SXEA1(strstr(fn, "%u"), "Attempted to register %s without a %%u part", name);
    *m = conf_register(&cidrprefsct, &cidrprefs_segment_ops, name, fn, loadable,
                       LOADFLAGS_FP_ALLOW_BUNDLE_EXTREFS | LOADFLAGS_FP_ELEMENTTYPE_CIDR
                       | LOADFLAGS_FP_SEGMENTED, NULL, 0);
}

const struct cidrprefs *
cidrprefs_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &cidrprefsct, "cidrprefs_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2CIDRPREFS(base);
}

const struct prefblock *
cidrprefs_get_prefblock(const struct cidrprefs *me, uint32_t orgid)
{
    unsigned i;

    if (me == NULL || (i = prefs_org_slot(me->org, orgid, me->count)) == me->count || me->org[i]->cs.id != orgid)
        return NULL;

    return me->org[i]->fp.values;
}

/* Lookup cidrprefs by its org and bundle id */
bool
cidrprefs_get_policy(const struct cidrprefs *me, pref_t *pref, uint32_t orgid, uint32_t bundleid)
{
    uint32_t                 global_parent_org = pref_get_globalorg();
    const struct prefblock  *blk, *pblk, *gblk;
    const struct prefbundle *bundle;

    SXEE6("(pref=%p, me=%p, orgid=%u, bundleid=%u)", pref, me, orgid, bundleid);
    pref_fini(pref);

    if ((blk = cidrprefs_get_prefblock(me, orgid)) == NULL) {
        SXEL6("Unable to find orgid %u in cidrprefs", orgid);
        goto DONE;
    }

    if (!(bundle = prefbundle_get(blk->resource.bundle, blk->count.bundles, AT_BUNDLE, bundleid))) {
        SXEL6("Unable to find bundleid %u for orgid %u in cidrprefs", bundleid, orgid);
        goto DONE;
    }

    pblk = cidrprefs_get_prefblock(me, blk->resource.org->parentid);
    gblk = cidrprefs_get_prefblock(me, global_parent_org);
    pref_init_bybundle(pref, blk, pblk, gblk, orgid, bundle - blk->resource.bundle);

DONE:
    SXER6("return %d // %s, pref { %p, %p, %p, %u }", PREF_VALID(pref), PREF_VALID(pref) ? "valid" : "invalid", pref->blk,
          pref->parentblk, pref->globalblk, pref->index);
    return PREF_VALID(pref);
}
