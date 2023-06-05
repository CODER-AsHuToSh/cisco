#include <kit-alloc.h>
#include <mockfail.h>

#include "policy-private.h"
#include "conf-meta.h"
#include "dns-name.h"
#include "fileprefs.h"
#include "urllist.h"
#include "xray.h"

#define CONSTCONF2POLICY(confp)  (const struct policy *)((confp) ? (const char *)(confp) - offsetof(struct policy, conf) : NULL)
#define CONF2POLICY(confp)       (struct policy *)((confp) ? (char *)(confp) - offsetof(struct policy, conf) : NULL)

module_conf_t CONF_POLICY;

static void policy_free(struct conf *base);

static const struct conf_type policy_conf_type = {
    "rules",
    NULL,                     /* allocate is never called for managed files */
    policy_free,
};

static void
policy_free(struct conf *base)
{
    struct policy *me = CONF2POLICY(base);
    unsigned i;

    SXEA6(base->type == &policy_conf_type, "policy_free() with unexpected conf_type %s", base->type->name);

    for (i = 0; i < me->count; i++)
        policy_org_refcount_dec(me->orgs[i]);

    kit_free(me->orgs);
    kit_free(me);
}

static struct conf *
policy_clone(struct conf *obase)
{
    struct policy *me, *ome;
    unsigned i;

    if ((me = MOCKFAIL(POLICY_CLONE, NULL, kit_malloc(sizeof(*me)))) == NULL)
        SXEL2("Couldn't allocate a policy structure");
    else {
        conf_setup(&me->conf, &policy_conf_type);
        me->count = 0;
        me->mtime = 0;
        me->orgs  = NULL;
        ome       = CONF2POLICY(obase);

        if (ome && ome->count) {
            me->count = (ome->count + 9) / 10 * 10;

            if ((me->orgs = MOCKFAIL(POLICY_CLONE_POLICY_ORGS, NULL, kit_malloc(me->count * sizeof(*me->orgs)))) == NULL) {
                SXEL2("Couldn't allocate %u new policy org slots", me->count);
                kit_free(me);
                me = NULL;
            }
            else {
                me->count = ome->count;

                for (i = 0; i < me->count; i++) {
                    policy_org_refcount_inc(me->orgs[i] = ome->orgs[i]);

                    if (me->mtime < me->orgs[i]->cs.mtime)
                        me->mtime = me->orgs[i]->cs.mtime;
                }
            }
        }
    }

    return me ? &me->conf : NULL;
}

static time_t
policy_settimeatleast(struct conf *base, time_t t)
{
    struct policy *me = CONF2POLICY(base);

    if (me->mtime < t)
        me->mtime = t;

    return me->mtime;
}

static unsigned
policy_org_slot(struct policy_org *const *const me, uint32_t orgid, unsigned count)
{
    return conf_segment_slot((void *const *const)me, orgid, count, offsetof(struct policy_org, cs));
}

static unsigned
policy_orgid2slot(const struct conf *base, uint32_t orgid)
{
    const struct policy *me = CONSTCONF2POLICY(base);

    return policy_org_slot(me->orgs, orgid, me->count);
}

static const struct conf_segment *
policy_slot2segment(const struct conf *base, unsigned slot)
{
    const struct policy *me = CONSTCONF2POLICY(base);

    return slot < me->count ? &me->orgs[slot]->cs : NULL;
}

static void
policy_slotfailedload(struct conf *base, unsigned slot, bool value)
{
    struct policy *me = CONF2POLICY(base);

    if (slot < me->count)
        me->orgs[slot]->cs.failed_load = value;
}

static bool
policy_slotisempty(const struct conf *base, unsigned slot)
{
    const struct policy *me = CONSTCONF2POLICY(base);

    return slot >= me->count || (me->orgs[slot]->rules == NULL);
}

static void
policy_freeslot(struct conf *base, unsigned slot)
{
    struct policy *me = CONF2POLICY(base);

    SXEA1(slot < me->count, "Cannot free policy org slot %u (count %u)", slot, me->count);
    policy_org_refcount_dec(me->orgs[slot]);
    memmove(me->orgs + slot, me->orgs + slot + 1, (me->count - slot - 1) * sizeof(*me->orgs));
    me->count--;
}

static bool
policy_useorg(struct conf *base, void *vorg, unsigned slot, uint64_t *alloc)
{
    struct policy     *me  = CONF2POLICY(base);
    struct policy_org *org = vorg;
    struct policy_org **alp;

    SXEA6(slot <= me->count, "Oops, Insertion point is at pos %u of %u", slot, me->count);

    if (!(me->count % 10)) {
        if ((alp = MOCKFAIL(POLICY_MORE_POLICY_ORGS, NULL, kit_realloc(me->orgs, (me->count + 10) * sizeof(*me->orgs)))) == NULL) {
            SXEL2("Couldn't reallocate %u policy org slots", me->count + 10);
            return false;
        }

        me->orgs = alp;
    }

    policy_settimeatleast(base, org->cs.mtime);
    *alloc += org->cs.alloc;

    if (slot < me->count) {
        SXEA6(me->orgs[slot]->cs.id >= org->cs.id, "Landed on unexpected orgid %" PRIu32 " when looking for org %" PRIu32,
              me->orgs[slot]->cs.id, org->cs.id);

        if (me->orgs[slot]->cs.id > org->cs.id) {
            SXEL7("Existing slot %u orgid %" PRIu32 " exceeds policy id %" PRIu32, slot, me->orgs[slot]->cs.id,
                  org->cs.id);
            memmove(me->orgs + slot + 1, me->orgs + slot, (me->count - slot) * sizeof(*me->orgs));
            me->count++;
        } else {
            SXEL7("Existing policy slot %u already contains org id %" PRIu32, slot, org->cs.id);
            *alloc -= me->orgs[slot]->cs.alloc;
            policy_org_refcount_dec(me->orgs[slot]);
        }
    } else
        me->count++;

    me->orgs[slot] = org;
    return true;
}

static void
policy_loaded(struct conf *base)
{
    struct policy *me = CONF2POLICY(base);

    if (me && me->count)
        conf_report_load("rules", me->orgs[0]->version);
}

static const struct conf_segment_ops policy_segment_ops = {
    .clone          = policy_clone,
    .settimeatleast = policy_settimeatleast,
    .id2slot        = policy_orgid2slot,
    .slot2segment   = policy_slot2segment,
    .slotisempty    = policy_slotisempty,
    .slotfailedload = policy_slotfailedload,
    .freeslot       = policy_freeslot,
    .newsegment     = policy_org_new,
    .freesegment    = policy_org_refcount_dec,
    .usesegment     = policy_useorg,
    .loaded         = policy_loaded,
};

/**
 * Register a policy directory with the conf system
 *
 * @param m      Pointer to the module identifier for the policy directory
 * @param name   Name of the policy (e.g. rules for umbrella unified policy, rules-auth-latitude for posture policy)
 * @param fn     File name pattern containing a %u to be replaced by the org id
 * @param filter NULL or a string which will be used to filter the rules; currently, it is a prefix
 */
void
policy_register(module_conf_t *m, const char *name, const char *fn, const char *filter)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    SXEA1(strstr(fn, "%u"), "Attempted to register %s without a %%u part", name);
    *m = conf_register(&policy_conf_type, &policy_segment_ops, name, fn, true, LOADFLAGS_POLICY, filter,
                       filter ? strlen(filter) + 1 : 0);
}

const struct policy *
policy_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &policy_conf_type, "policy_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2POLICY(base);
}

/**
 * @return A pointer to the policy_org in 'me' with 'orgid', or NULL if not found.
 */
struct policy_org *
policy_find_org(const struct policy *me, uint32_t orgid)
{
    unsigned slot = policy_org_slot(me->orgs, orgid, me->count);

    return slot >= me->count || me->orgs[slot]->cs.id != orgid ? NULL : me->orgs[slot];
}
