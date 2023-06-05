#include <kit-alloc.h>
#include <mockfail.h>

#include "fileprefs.h"
#include "lists-private.h"

#define CONSTCONF2LISTS(confp)  (const struct lists *)((confp) ? (const char *)(confp) - offsetof(struct lists, conf) : NULL)
#define CONF2LISTS(confp)       (struct lists *)((confp) ? (char *)(confp) - offsetof(struct lists, conf) : NULL)

module_conf_t CONF_LISTS;

static void lists_free(struct conf *base);

static const struct conf_type lists_conf_type = {
    "lists",
    NULL,                     /* allocate is never called for managed files */
    lists_free,
};

static void
lists_free(struct conf *base)
{
    struct lists *me = CONF2LISTS(base);
    unsigned i;

    SXEA6(base->type == &lists_conf_type, "lists_free() with unexpected conf_type %s", base->type->name);

    for (i = 0; i < me->count; i++)
        lists_org_refcount_dec(me->orgs[i]);

    kit_free(me->orgs);
    kit_free(me);
}

static struct conf *
lists_clone(struct conf *obase)
{
    struct lists *me, *ome;
    unsigned i;

    if ((me = MOCKFAIL(LISTS_CLONE, NULL, kit_malloc(sizeof(*me)))) == NULL)
        SXEL2("Couldn't allocate a lists structure");
    else {
        conf_setup(&me->conf, &lists_conf_type);
        me->count = 0;
        me->mtime = 0;
        me->orgs  = NULL;
        ome       = CONF2LISTS(obase);

        if (ome && ome->count) {
            me->count = (ome->count + 9) / 10 * 10;

            if ((me->orgs = MOCKFAIL(LISTS_CLONE_LISTS_ORGS, NULL, kit_malloc(me->count * sizeof(*me->orgs)))) == NULL) {
                SXEL2("Couldn't allocate %u new lists org slots", me->count);
                kit_free(me);
                me = NULL;
            }
            else {
                me->count = ome->count;

                for (i = 0; i < me->count; i++) {
                    lists_org_refcount_inc(me->orgs[i] = ome->orgs[i]);

                    if (me->mtime < me->orgs[i]->cs.mtime)
                        me->mtime = me->orgs[i]->cs.mtime;
                }
            }
        }
    }

    return me ? &me->conf : NULL;
}

static time_t
lists_settimeatleast(struct conf *base, time_t t)
{
    struct lists *me = CONF2LISTS(base);

    if (me->mtime < t)
        me->mtime = t;

    return me->mtime;
}

static unsigned
lists_org_slot(struct lists_org *const *const me, uint32_t orgid, unsigned count)
{
    return conf_segment_slot((void *const *const)me, orgid, count, offsetof(struct lists_org, cs));
}

static unsigned
lists_orgid2slot(const struct conf *base, uint32_t orgid)
{
    const struct lists *me = CONSTCONF2LISTS(base);

    return lists_org_slot(me->orgs, orgid, me->count);
}

static const struct conf_segment *
lists_slot2segment(const struct conf *base, unsigned slot)
{
    const struct lists *me = CONSTCONF2LISTS(base);

    return slot < me->count ? &me->orgs[slot]->cs : NULL;
}

static void
lists_slotfailedload(struct conf *base, unsigned slot, bool value)
{
    struct lists *me = CONF2LISTS(base);

    if (slot < me->count)
        me->orgs[slot]->cs.failed_load = value;
}

static bool
lists_slotisempty(const struct conf *base, unsigned slot)
{
    const struct lists *me = CONSTCONF2LISTS(base);

    return slot >= me->count || (me->orgs[slot]->lists == NULL);
}

static void
lists_freeslot(struct conf *base, unsigned slot)
{
    struct lists *me = CONF2LISTS(base);

    SXEA1(slot < me->count, "Cannot free lists org slot %u (count %u)", slot, me->count);
    lists_org_refcount_dec(me->orgs[slot]);
    memmove(me->orgs + slot, me->orgs + slot + 1, (me->count - slot - 1) * sizeof(*me->orgs));
    me->count--;
}

static bool
lists_useorg(struct conf *base, void *vorg, unsigned slot, uint64_t *alloc)
{
    struct lists     *me  = CONF2LISTS(base);
    struct lists_org *org = vorg;
    struct lists_org **alp;

    SXEA6(slot <= me->count, "Oops, Insertion point is at pos %u of %u", slot, me->count);

    if (!(me->count % 10)) {
        if ((alp = MOCKFAIL(LISTS_MORE_LISTS_ORGS, NULL, kit_realloc(me->orgs, (me->count + 10) * sizeof(*me->orgs)))) == NULL) {
            SXEL2("Couldn't reallocate %u lists org slots", me->count + 10);
            return false;
        }

        me->orgs = alp;
    }

    lists_settimeatleast(base, org->cs.mtime);
    *alloc += org->cs.alloc;

    if (slot < me->count) {
        SXEA6(me->orgs[slot]->cs.id >= org->cs.id, "Landed on unexpected orgid %" PRIu32 " when looking for org %" PRIu32,
              me->orgs[slot]->cs.id, org->cs.id);

        if (me->orgs[slot]->cs.id > org->cs.id) {
            SXEL7("Existing slot %u orgid %" PRIu32 " exceeds lists id %" PRIu32, slot, me->orgs[slot]->cs.id,
                  org->cs.id);
            memmove(me->orgs + slot + 1, me->orgs + slot, (me->count - slot) * sizeof(*me->orgs));
            me->count++;
        } else {
            SXEL7("Existing lists slot %u already contains org id %" PRIu32, slot, org->cs.id);
            *alloc -= me->orgs[slot]->cs.alloc;
            lists_org_refcount_dec(me->orgs[slot]);
        }
    } else
        me->count++;

    me->orgs[slot] = org;
    return true;
}

static void
lists_loaded(struct conf *base)
{
    struct lists *me = CONF2LISTS(base);

    if (me && me->count)
        conf_report_load("lists", LISTS_VERSION);
}

static const struct conf_segment_ops lists_segment_ops = {
    lists_clone,
    lists_settimeatleast,
    lists_orgid2slot,
    lists_slot2segment,
    lists_slotisempty,
    lists_slotfailedload,
    lists_freeslot,
    lists_org_new,
    lists_org_refcount_dec,
    lists_useorg,
    lists_loaded,
};

// Currently, there is only one registration function

void
lists_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    SXEA1(strstr(fn, "%u"), "Attempted to register %s without a %%u part", name);
    *m = conf_register(&lists_conf_type, &lists_segment_ops, name, fn, loadable, LOADFLAGS_LISTS, NULL, 0);
}

const struct lists *
lists_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &lists_conf_type, "lists_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2LISTS(base);
}

/**
 * @return A pointer to the lists_org in 'me' with 'orgid', or NULL if not found.
 */
struct lists_org *
lists_find_org(const struct lists *me, uint32_t orgid)
{
    unsigned slot = lists_org_slot(me->orgs, orgid, me->count);

    return slot >= me->count || me->orgs[slot]->cs.id != orgid ? NULL : me->orgs[slot];
}
