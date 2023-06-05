#include <inttypes.h>    /* Required by ubuntu */

#include "atomic.h"
#include "prefs-org.h"

unsigned
prefs_org_slot(struct prefs_org *const *const me, uint32_t id, unsigned count)
{
    return conf_segment_slot((void *const *const)me, id, count, offsetof(struct prefs_org, cs));
}

bool
prefs_org_valid(struct prefs_org *me, const char *path)
{
    if (prefblock_count_total(me->fp.values) == 0 || (me->fp.values->count.orgs == 1 && me->cs.id == me->fp.values->resource.org[0].id))
        return true;

    SXEL2("%s: Expected exactly one org (%" PRIu32 ") entry in 'orgs' section", path, me->cs.id);
    return false;
}

void
prefs_org_refcount_dec(void *obj)
{
    struct prefs_org *me = obj;

    if (me && ATOMIC_DEC_INT_NV(&me->cs.refcount) == 0)
        fileprefs_free(&me->fp);
}

void
prefs_org_refcount_inc(void *obj)
{
    struct prefs_org *me = obj;

    if (me)
        ATOMIC_INC_INT(&me->cs.refcount);
}

/*
 * Insert or replace an org in the org array.
 */
bool
prefs_org_fill_slot(struct prefs_org *po, struct prefs_org **org, unsigned *count, unsigned slot, uint64_t *alloc)
{
    *alloc += po->cs.alloc;
    if (slot < *count) {
        SXEA6(org[slot]->cs.id >= po->cs.id, "Landed on unexpected orgid %u when looking for org %u", org[slot]->cs.id, po->cs.id);
        if (org[slot]->cs.id > po->cs.id) {
            SXEL7("Existing org slot %u id %u exceeds preffile id %u", slot, org[slot]->cs.id, po->cs.id);
            memmove(org + slot + 1, org + slot, (*count - slot) * sizeof(*org));
            (*count)++;
        } else {
            /* Only replace an org if the new one doesn't indicate a failure */
            if ((po->fp.loadflags & LOADFLAGS_FP_FAILED)) {
                SXEL7("Not replacing existing org with a failed one in slot %u id %u", slot, po->cs.id);
                return false;
            }

            /* Remove the previous org */
            SXEL7("Existing org slot %u already contains id %u", slot, po->cs.id);
            *alloc -= org[slot]->cs.alloc;
            prefs_org_refcount_dec(org[slot]);
        }
    } else
        (*count)++;
    org[slot] = po;
    return true;
}
