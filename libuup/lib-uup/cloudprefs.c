/*
 * Description of the format of this config file:
 *   https://confluence.office.opendns.com/display/trac3/configuration-prefs-format
 */
#include <kit-alloc.h>
#include <mockfail.h>

#if SXE_DEBUG
#include <kit-bool.h>
#endif

#include "cloudprefs-org.h"
#include "cloudprefs-private.h"
#include "xray.h"

#define CONSTCONF2CLOUDPREFS(confp)  (const struct cloudprefs *)((confp) ? (const char *)(confp) - offsetof(struct cloudprefs, conf) : NULL)
#define CONF2CLOUDPREFS(confp)       (struct cloudprefs *)((confp) ? (char *)(confp) - offsetof(struct cloudprefs, conf) : NULL)

module_conf_t CONF_CLOUDPREFS;
module_conf_t CONF_DNSPREFS;

static void cloudprefs_free(struct conf *base);

static const struct conf_type cloudprefsct = {
    "cloudprefs",
    NULL,                     /* allocate is never called for per-org prefs */
    cloudprefs_free,
};

static void
cloudprefs_free(struct conf *base)
{
    struct cloudprefs *me = CONF2CLOUDPREFS(base);
    unsigned i;

    SXEA6(base->type == &cloudprefsct, "cloudprefs_free() with unexpected conf_type %s", base->type->name);
    for (i = 0; i < me->count; i++)
        prefs_org_refcount_dec(me->org[i]);
    kit_free(me->org);
    kit_free(me);
}

static struct conf *
cloudprefs_clone(struct conf *obase)
{
    struct cloudprefs *me, *ome;
    unsigned i;

    if ((me = MOCKFAIL(CLOUDPREFS_CLONE, NULL, kit_malloc(sizeof(*me)))) == NULL)
        SXEL2("Couldn't allocate a cloudprefs structure");
    else {
        conf_setup(&me->conf, &cloudprefsct);
        me->count = 0;
        me->mtime = 0;
        me->org = NULL;

        ome = CONF2CLOUDPREFS(obase);
        if (ome && ome->count) {
            me->count = (ome->count + 9) / 10 * 10;
            if ((me->org = MOCKFAIL(CLOUDPREFS_CLONE_ORGS, NULL, kit_malloc(me->count * sizeof(*me->org)))) == NULL) {
                SXEL2("Couldn't allocate %u new cloudprefs org slots", me->count);
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
cloudprefs_settimeatleast(struct conf *base, time_t t)
{
    struct cloudprefs *me = CONF2CLOUDPREFS(base);

    if (me->mtime < t)
        me->mtime = t;

    return me->mtime;
}

static unsigned
cloudprefs_orgid2slot(const struct conf *base, uint32_t orgid)
{
    const struct cloudprefs *me = CONSTCONF2CLOUDPREFS(base);

    return prefs_org_slot(me->org, orgid, me->count);
}

static const struct conf_segment *
cloudprefs_slot2segment(const struct conf *base, unsigned slot)
{
    const struct cloudprefs *me = CONSTCONF2CLOUDPREFS(base);

    return slot < me->count ? &me->org[slot]->cs : NULL;
}

static void
cloudprefs_slotfailedload(struct conf *base, unsigned slot, bool value)
{
    struct cloudprefs *me = CONF2CLOUDPREFS(base);
    if (slot < me->count) {
        me->org[slot]->cs.failed_load = value;
    }
}

bool
cloudprefs_slotisempty(const struct conf *base, unsigned slot)
{
    const struct cloudprefs *me = CONSTCONF2CLOUDPREFS(base);

    return slot >= me->count || me->org[slot]->fp.total == 0;
}

static void
cloudprefs_freeslot(struct conf *base, unsigned slot)
{
    struct cloudprefs *me = CONF2CLOUDPREFS(base);

    SXEA1(slot < me->count, "Cannot free cloudprefs org slot %u (count %u)", slot, me->count);
    prefs_org_refcount_dec(me->org[slot]);
    memmove(me->org + slot, me->org + slot + 1, (me->count - slot - 1) * sizeof(*me->org));
    me->count--;
}

static bool
cloudprefs_useorg(struct conf *base, void *vcpo, unsigned slot, uint64_t *alloc)
{
    struct cloudprefs *me = CONF2CLOUDPREFS(base);
    struct prefs_org *cpo = vcpo;
    struct prefs_org **cpop;

    SXEA6(slot <= me->count, "Oops, Insertion point is at pos %u of %u", slot, me->count);

    if (!(me->count % 10)) {
        if ((cpop = MOCKFAIL(CLOUDPREFS_MOREORGS, NULL, kit_realloc(me->org, (me->count + 10) * sizeof(*me->org)))) == NULL) {
            SXEL2("Couldn't reallocate %u cloudprefs org slots", me->count + 10);
            return false;
        }
        me->org = cpop;
    }

    if (!(cpo->fp.loadflags & LOADFLAGS_FP_FAILED)) {
        cloudprefs_settimeatleast(base, cpo->cs.mtime);
    }
    return prefs_org_fill_slot(cpo, me->org, &me->count, slot, alloc);
}

static void
cloudprefs_loaded(struct conf *base)
{
    struct cloudprefs *me = CONF2CLOUDPREFS(base);

    if (me && me->count)
        conf_report_load(me->org[0]->fp.ops->type, me->org[0]->fp.version);
}

static const struct conf_segment_ops cloudprefs_segment_ops = {
    cloudprefs_clone,
    cloudprefs_settimeatleast,
    cloudprefs_orgid2slot,
    cloudprefs_slot2segment,
    cloudprefs_slotisempty,
    cloudprefs_slotfailedload,
    cloudprefs_freeslot,
    cloudprefs_org_new,
    prefs_org_refcount_dec,
    cloudprefs_useorg,
    cloudprefs_loaded,
};

void
cloudprefs_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    SXEA1(strstr(fn, "%u"), "Attempted to register %s without a %%u part", name);
    *m = conf_register(&cloudprefsct, &cloudprefs_segment_ops, name, fn, loadable,
                       LOADFLAGS_FP_ALLOW_BUNDLE_EXTREFS | LOADFLAGS_FP_ALLOW_OTHER_TYPES
                       | LOADFLAGS_FP_ELEMENTTYPE_DOMAIN | LOADFLAGS_FP_ELEMENTTYPE_APPLICATION
                       | LOADFLAGS_FP_SEGMENTED, NULL, 0);
}

void
cloudprefs_register_add_cidr(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    SXEA1(strstr(fn, "%u"), "Attempted to register %s without a %%u part", name);
    *m = conf_register(&cloudprefsct, &cloudprefs_segment_ops, name, fn, loadable,
                       LOADFLAGS_FP_ALLOW_BUNDLE_EXTREFS | LOADFLAGS_FP_ALLOW_OTHER_TYPES
                       | LOADFLAGS_FP_ELEMENTTYPE_DOMAIN | LOADFLAGS_FP_ELEMENTTYPE_APPLICATION
                       | LOADFLAGS_FP_ELEMENTTYPE_CIDR | LOADFLAGS_FP_SEGMENTED, NULL, 0);
}

const struct cloudprefs *
cloudprefs_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &cloudprefsct, "cloudprefs_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2CLOUDPREFS(base);
}

const struct prefblock *
cloudprefs_get_prefblock(const struct cloudprefs *me, uint32_t orgid)
{
    unsigned i;

    if (me == NULL || (i = prefs_org_slot(me->org, orgid, me->count)) == me->count || me->org[i]->cs.id != orgid)
        return NULL;

    return me->org[i]->fp.values;
}

/*
 * Lookup a preference based on the EDNS0 IDs.
 */
bool
cloudprefs_get(pref_t *pref, const struct cloudprefs *me, const char *name, uint32_t org_id, uint32_t origin_id, struct oolist **other_origins,
               struct xray *x)
{
    uint32_t global_parent_org = pref_get_globalorg();
    const struct prefblock *pblk, *gblk;
    const struct preforg *org;
    const char *what;
    unsigned i;

    SXEE7("(me=%p, name=%s, org_id=%u, origin_id=%u, other_origins=%p, x=%p)", me, name, org_id, origin_id, *other_origins, x);
    pref_fini(pref);

    if (me == NULL)
        goto MATCH_DONE;

    if ((i = prefs_org_slot(me->org, org_id, me->count)) == me->count || me->org[i]->cs.id != org_id) {
        XRAY6(x, "%s match: no such org", name);
        goto MATCH_DONE;
    }

    if ((what = cloudprefs_org_get(pref, me->org[i], name, origin_id, other_origins, x)) != NULL) {
        pblk = gblk = NULL;
        if ((org = PREF_ORG(pref)) != NULL && org->parentid && !PREF_PARENTORG(pref))
            pblk = cloudprefs_get_prefblock(me, org->parentid);     /* We couldn't find the parent org in the prefblock, find it in its own block */
        if (global_parent_org && !PREF_GLOBALORG(pref))
            gblk = cloudprefs_get_prefblock(me, global_parent_org); /* We couldn't find the global org in the prefblock, find it in its own block */
        if (pblk || gblk)
            pref_init_byidentity(pref, pref->blk, pblk, gblk, pref->index);
        SXEL6("%s match: using: pref %p, priority %u, origin %u for %s", name, PREF_IDENT(pref), PREF_BUNDLE(pref)->priority, PREF_IDENT(pref)->originid, what);
    }

MATCH_DONE:
    SXER7("return %s // %s, pref { %p, %p, %p, %u }", kit_bool_to_str(PREF_VALID(pref)), PREF_VALID(pref) ? "valid" : "invalid", pref->blk, pref->parentblk, pref->globalblk, pref->index);
    return PREF_VALID(pref);
}
