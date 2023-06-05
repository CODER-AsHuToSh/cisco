/* Wrapper for the groupusers files distributed by Brain.
 * Copied from: https://github.office.opendns.com/cdfw/firewall/blob/multi-tenant/src/groupsprefs.c
 */

#include <safe_lib.h>
#include <mockfail.h>

#include "groupsprefs.h"
#include "kit-alloc.h"

#define CONSTCONF2GROUPSPREFS(confp)  (const struct groupsprefs *)((confp) ? (const char *)(confp) - offsetof(struct groupsprefs, conf) : NULL)
#define CONF2GROUPSPREFS(confp)       (struct groupsprefs *)((confp) ? (char *)(confp) - offsetof(struct groupsprefs, conf) : NULL)

struct groupsprefs {
    struct conf conf;
    time_t mtime;                    /* last modification */
    unsigned count;                  /* num allocated groups_per_user_map_t entries */
    groups_per_user_map_t **gpum;    /* a block of 'count' pointers */
};

module_conf_t CONF_GROUPSPREFS;
static void groupsprefs_free(struct conf *base);

static const struct conf_type gpct = {
    "groupsprefs",
    NULL,                             /* no allocate for managed files */
    groupsprefs_free,
};

static void
groupsprefs_free(struct conf *base)
{
    struct groupsprefs *me = CONF2GROUPSPREFS(base);
    unsigned count;
    SXEA6(base, "groupsprefs_free() with NULL base");
    SXEA6(base->type == &gpct, "groupsprefs_free() with unexpected conf_type %s", base->type->name);
    for (count = 0; count < me->count; count++) {
        groups_per_user_map_refcount_dec(me->gpum[count]);
    }
    kit_free(me->gpum);
    kit_free(me);
}

static struct conf *
groupsprefs_clone(struct conf *obase)
{
    struct groupsprefs *me, *ome;
    unsigned i;

    if ((me = MOCKFAIL(GROUPSPREFS_CLONE, NULL, kit_malloc(sizeof(*me)))) == NULL) {
        SXEL2("Couldn't allocate an groupsprefs structure");
    } else {
        conf_setup(&me->conf, &gpct);
        me->count = 0;
        me->mtime = 0;
        me->gpum  = NULL;
        ome       = CONF2GROUPSPREFS(obase);

        if (ome && ome->count) {
            me->count = (ome->count + 9) / 10 * 10;

            if ((me->gpum = MOCKFAIL(GROUPSPREFS_CLONE_GPUMS, NULL, kit_malloc(me->count * sizeof(*me->gpum)))) == NULL) {
                SXEL2("Couldn't allocate %u new groups_per_user_map_t slots", me->count);
                kit_free(me);
                me = NULL;
            } else {
                me->count = ome->count;

                for (i = 0; i < me->count; i++) {
                    groups_per_user_map_refcount_inc(me->gpum[i] = ome->gpum[i]);

                    if (me->mtime < me->gpum[i]->cs.mtime) {
                        me->mtime = me->gpum[i]->cs.mtime;
                    }
                }
            }
        }
    }

    return me ? &me->conf : NULL;
}

static time_t
groupsprefs_settimeatleast(struct conf *base, time_t t)
{
    struct groupsprefs *me = CONF2GROUPSPREFS(base);
    if (me->mtime < t) {
        me->mtime = t;
    }
    return me->mtime;
}

static unsigned
groupsprefs_orgid2slot(const struct conf *base, uint32_t org_id)
{
    SXEA6(base != NULL, "groupsprefs_orgid2slot() base pointer is null");
    const struct groupsprefs *me = CONSTCONF2GROUPSPREFS(base);
    return conf_segment_slot((void *const *const)me->gpum, org_id, me->count, offsetof(groups_per_user_map_t, cs));
}

static const struct conf_segment *
groupsprefs_slot2segment(const struct conf *base, unsigned slot)
{
    SXEA6(base != NULL, "groupsprefs_slot2segment() base pointer is null");
    const struct groupsprefs *me = CONSTCONF2GROUPSPREFS(base);
    return slot < me->count ? &me->gpum[slot]->cs : NULL;
}

static bool
groupsprefs_slotisempty(const struct conf *base, unsigned slot)
{
    SXEA6(base != NULL, "groupsprefs_slotisempty() base pointer is null");
    const struct groupsprefs *me = CONSTCONF2GROUPSPREFS(base);

    // If gpu is changed to a dynamically allocated pointer in the future, have to have the following check:
    // return slot >= me->count || me->gpum[slot]->gpu == NULL;
    return slot >= me->count;
}

static void
groupsprefs_slotfailedload(struct conf *base, unsigned slot, bool value)
{
    struct groupsprefs *me = CONF2GROUPSPREFS(base);

    if (slot < me->count)
        me->gpum[slot]->cs.failed_load = value;
}

static void
groupsprefs_freeslot(struct conf *base, unsigned slot)
{
    SXEA6(base != NULL, "groupsprefs_freeslot() base pointer is null");
    struct groupsprefs *me = CONF2GROUPSPREFS(base);
    SXEA1(slot < me->count, "Cannot free groups_per_user_map_t slot %u (count %u)", slot, me->count);
    groups_per_user_map_refcount_dec(me->gpum[slot]);
    memmove_s(me->gpum + slot, (me->count - slot) * sizeof(*me->gpum),
              me->gpum + slot + 1, (me->count - slot - 1) * sizeof(*me->gpum));
    me->count--;
}

static bool
groupsprefs_use_groups_per_user_map(struct conf *base, void *vgpum, unsigned slot, uint64_t *alloc)
{
    struct groupsprefs *me = CONF2GROUPSPREFS(base);
    groups_per_user_map_t *gpum = vgpum;
    groups_per_user_map_t **gpump;
    SXEA6(me, "groupsprefs_use_groups_per_user_map() null self pointer");
    SXEA6(slot <= me->count, "Oops, Insertion point is at pos %u of %u", slot, me->count);

    if (!(me->count % 10)) {
        if ((gpump = MOCKFAIL(GROUPSPREFS_MORE_ORGS, NULL, kit_realloc(me->gpum, (me->count + 10) * sizeof(*me->gpum))))
         == NULL) {
            SXEL2("Couldn't reallocate %u groups_per_user_map_t slots", me->count + 10);
            return false;
        }

        me->gpum = gpump;
    }

    groupsprefs_settimeatleast(base, gpum->cs.mtime);
    *alloc += gpum->cs.alloc;

    if (slot < me->count) {
        SXEA6(me->gpum[slot]->cs.id >= gpum->cs.id, "Landed on unexpected org_id %" PRIu32 " when looking for org %" PRIu32,
              me->gpum[slot]->cs.id, gpum->cs.id);

        if (me->gpum[slot]->cs.id > gpum->cs.id) {
            SXEL7("Existing user_to_group_list_t slot %u org_id %" PRIu32 " exceeds groupsprefs id %" PRIu32,
                  slot, me->gpum[slot]->cs.id, gpum->cs.id);
            memmove_s(me->gpum + slot + 1, (me->count - slot + 1) * sizeof(*me->gpum),
                    me->gpum + slot, (me->count - slot) * sizeof(*me->gpum));
            me->count++;
        } else {
            SXEL7("Existing groups_per_user_map_t slot %u already contains groupsprefs id %" PRIu32, slot, gpum->cs.id);
            *alloc -= me->gpum[slot]->cs.alloc;
            groups_per_user_map_refcount_dec(me->gpum[slot]);
        }
    } else {
        me->count++;
    }

    me->gpum[slot] = gpum;
    return true;
}

static void
groupsprefs_loaded(struct conf *base)
{
    struct groupsprefs *me = CONF2GROUPSPREFS(base);

    if (me && me->count) {
        conf_report_load("groupsprefs", GROUPSPREFS_VERSION);
    }
}

const struct conf_segment_ops groupsprefs_segment_ops = {
    groupsprefs_clone,
    groupsprefs_settimeatleast,
    groupsprefs_orgid2slot,
    groupsprefs_slot2segment,
    groupsprefs_slotisempty,
    groupsprefs_slotfailedload,
    groupsprefs_freeslot,
    groups_per_user_map_new_segment,
    groups_per_user_map_refcount_dec,
    groupsprefs_use_groups_per_user_map,
    groupsprefs_loaded,
};

void
groupsprefs_register(module_conf_t *m, const char *name, const char *fn)
{
    if (fn == NULL) {
        SXEL6("path for %s is empty", name);
        return;
    }

    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    SXEA1(strstr(fn, "%u"), "Attempted to register %s without a %%u part", name);
    *m = conf_register(&gpct, &groupsprefs_segment_ops, name, fn, true, 0, NULL, 0);
}

groups_per_user_map_t *
groupsprefs_get_groups_per_user_map(const struct confset *set, module_conf_t m, uint32_t org_id)
{
    unsigned i;
    groups_per_user_map_t *gpum = NULL;

    SXEE7("(set=%p, org_id=%u)", set, org_id);

    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &gpct, "groupsprefs_conf_get() with unexpected conf_type %s", base->type->name);
    const struct groupsprefs *gp = CONSTCONF2GROUPSPREFS(base);

    if (gp == NULL)
        goto MATCH_DONE;

    i = groupsprefs_orgid2slot(base, org_id);

    if (i == gp->count || gp->gpum[i]->cs.id != org_id) {
        SXEL2("Couldn't find groupsprefs slot for org_id %u", org_id);
        goto MATCH_DONE;
    }

    gpum = gp->gpum[i];

MATCH_DONE:
    SXER7("return %p", gpum);
    return gpum;
}
