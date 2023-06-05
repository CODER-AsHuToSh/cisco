/*
 * Description of the format of this config file:
 *   https://confluence.office.opendns.com/display/trac3/configuration-prefs-format
 */

#include <kit-alloc.h>
#include <mockfail.h>

#if SXE_DEBUG
#include <kit-bool.h>
#endif

#include "dirprefs-private.h"
#include "odns.h"
#include "xray.h"

#define CONSTCONF2DIRPREFS(confp)  (const struct dirprefs *)((confp) ? (const char *)(confp) - offsetof(struct dirprefs, conf) : NULL)
#define CONF2DIRPREFS(confp)       (struct dirprefs *)((confp) ? (char *)(confp) - offsetof(struct dirprefs, conf) : NULL)

module_conf_t CONF_DIRPREFS;
static void dirprefs_free(struct conf *base);

static const struct conf_type dirprefsct = {
    "dirprefs",
    NULL,                     /* allocate is never called for per-org prefs */
    dirprefs_free,
};

static void
dirprefs_free(struct conf *base)
{
    struct dirprefs *me = CONF2DIRPREFS(base);
    unsigned i;

    SXEA6(base->type == &dirprefsct, "dirprefs_free() with unexpected conf_type %s", base->type->name);
    for (i = 0; i < me->count; i++)
        prefs_org_refcount_dec(me->org[i]);
    kit_free(me->org);
    kit_free(me);
}

static struct conf *
dirprefs_clone(struct conf *obase)
{
    struct dirprefs *me, *ome;
    unsigned i;

    if ((me = MOCKFAIL(DIRPREFS_CLONE, NULL, kit_malloc(sizeof(*me)))) == NULL)
        SXEL2("Couldn't allocate a dirprefs structure");
    else {
        conf_setup(&me->conf, &dirprefsct);
        me->count = 0;
        me->mtime = 0;
        me->org = NULL;

        ome = CONF2DIRPREFS(obase);
        if (ome && ome->count) {
            me->count = (ome->count + 9) / 10 * 10;
            if ((me->org = MOCKFAIL(DIRPREFS_CLONE_ORGS, NULL, kit_malloc(me->count * sizeof(*me->org)))) == NULL) {
                SXEL2("Couldn't allocate %u new dirprefs org slots", me->count);
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
dirprefs_settimeatleast(struct conf *base, time_t t)
{
    struct dirprefs *me = CONF2DIRPREFS(base);

    if (me->mtime < t)
        me->mtime = t;

    return me->mtime;
}

static unsigned
dirprefs_orgid2slot(const struct conf *base, uint32_t orgid)
{
    const struct dirprefs *me = CONSTCONF2DIRPREFS(base);

    return prefs_org_slot(me->org, orgid, me->count);
}

static const struct conf_segment *
dirprefs_slot2segment(const struct conf *base, unsigned slot)
{
    const struct dirprefs *me = CONSTCONF2DIRPREFS(base);

    return slot < me->count ? &me->org[slot]->cs : NULL;
}

static void
dirprefs_slotfailedload(struct conf *base, unsigned slot, bool value)
{
    struct dirprefs *me = CONF2DIRPREFS(base);
    if (slot < me->count) {
        me->org[slot]->cs.failed_load = value;
    }
}

bool
dirprefs_slotisempty(const struct conf *base, unsigned slot)
{
    const struct dirprefs *me = CONSTCONF2DIRPREFS(base);

    return slot >= me->count || me->org[slot]->fp.total == 0;
}

static void
dirprefs_freeslot(struct conf *base, unsigned slot)
{
    struct dirprefs *me = CONF2DIRPREFS(base);

    SXEA1(slot < me->count, "Cannot free dirprefs org slot %u (count %u)", slot, me->count);
    prefs_org_refcount_dec(me->org[slot]);
    memmove(me->org + slot, me->org + slot + 1, (me->count - slot - 1) * sizeof(*me->org));
    me->count--;
}

static bool
dirprefs_useorg(struct conf *base, void *vdpo, unsigned slot, uint64_t *alloc)
{
    struct dirprefs *me = CONF2DIRPREFS(base);
    struct prefs_org *dpo = vdpo;
    struct prefs_org **dpop;

    SXEA6(slot <= me->count, "Oops, Insertion point is at pos %u of %u", slot, me->count);
    if (!(me->count % 10)) {
        if ((dpop = MOCKFAIL(DIRPREFS_MOREORGS, NULL, kit_realloc(me->org, (me->count + 10) * sizeof(*me->org)))) == NULL) {
            SXEL2("Couldn't reallocate %u dirprefs org slots", me->count + 10);
            return false;
        }
        me->org = dpop;
    }

    if (!(dpo->fp.loadflags & LOADFLAGS_FP_FAILED)) {
        dirprefs_settimeatleast(base, dpo->cs.mtime);
    }
    return prefs_org_fill_slot(dpo, me->org, &me->count, slot, alloc);
}

static void
dirprefs_loaded(struct conf *base)
{
    struct dirprefs *me = CONF2DIRPREFS(base);

    if (me && me->count)
        conf_report_load(me->org[0]->fp.ops->type, me->org[0]->fp.version);
}

static const struct conf_segment_ops dirprefs_segment_ops = {
    dirprefs_clone,
    dirprefs_settimeatleast,
    dirprefs_orgid2slot,
    dirprefs_slot2segment,
    dirprefs_slotisempty,
    dirprefs_slotfailedload,
    dirprefs_freeslot,
    dirprefs_org_new,
    prefs_org_refcount_dec,
    dirprefs_useorg,
    dirprefs_loaded,
};

void
dirprefs_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    SXEA1(strstr(fn, "%u"), "Attempted to register %s without a %%u part", name);
    *m = conf_register(&dirprefsct, &dirprefs_segment_ops, name, fn, loadable,
                       LOADFLAGS_FP_ALLOW_BUNDLE_EXTREFS | LOADFLAGS_FP_ALLOW_OTHER_TYPES
                       | LOADFLAGS_FP_ELEMENTTYPE_DOMAIN | LOADFLAGS_FP_ELEMENTTYPE_APPLICATION
                       | LOADFLAGS_FP_SEGMENTED, NULL, 0);
}

const struct dirprefs *
dirprefs_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &dirprefsct, "dirprefs_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2DIRPREFS(base);
}

const struct prefblock *
dirprefs_get_prefblock(const struct dirprefs *me, uint32_t orgid)
{
    unsigned i;

    if (me == NULL || (i = prefs_org_slot(me->org, orgid, me->count)) == me->count || me->org[i]->cs.id != orgid)
        return NULL;

    return me->org[i]->fp.values;
}

/*
 * Lookup a preference based on the IDs passed along from the forwarder.
 */
bool
dirprefs_get(pref_t *pref, const struct dirprefs *me, const struct odns *odns, struct oolist **other_origins, enum dirprefs_type *type, struct xray *x)
{
    uint32_t global_parent_org = pref_get_globalorg();
    const struct prefblock *pblk, *gblk;
    const struct preforg *org;
    const char *what;
    unsigned i;

    SXEE7("(me=%p odns=%p other_origins=%p, type=?, x=?)", me, odns, *other_origins);
    pref_fini(pref);
    *type = DIRPREFS_TYPE_NONE;

    if (me == NULL || odns == NULL || !(odns->fields & ODNS_FIELD_ORG))
        goto MATCH_DONE;

    if ((i = prefs_org_slot(me->org, odns->org_id, me->count)) == me->count || me->org[i]->cs.id != odns->org_id)
        goto MATCH_DONE;

    if ((what = dirprefs_org_get(pref, me->org[i], odns, other_origins, type, x)) != NULL) {
        pblk = gblk = NULL;
        if ((org = PREF_ORG(pref)) != NULL && org->parentid && !PREF_PARENTORG(pref))
            pblk = dirprefs_get_prefblock(me, org->parentid);     /* We couldn't find the parent org in the prefblock, find it in its own block */
        if (global_parent_org && !PREF_GLOBALORG(pref))
            gblk = dirprefs_get_prefblock(me, global_parent_org); /* We couldn't find the global org in the prefblock, find it in its own block */
        if (pblk || gblk)
            pref_init_byidentity(pref, pref->blk, pblk, gblk, pref->index);
        SXEL6("dirprefs match: using: pref %p, priority %u, origin %u for %s", PREF_IDENT(pref), PREF_BUNDLE(pref)->priority, PREF_IDENT(pref)->originid, what);
    } else
        XRAY6(x, "dirprefs match: none");

MATCH_DONE:
    SXER7("return %s // %s, pref { %p, %p, %p, %u }", kit_bool_to_str(PREF_VALID(pref)),
          PREF_VALID(pref) ? "valid" : "invalid",
          pref->blk, pref->parentblk, pref->globalblk, pref->index);
    return PREF_VALID(pref);
}
