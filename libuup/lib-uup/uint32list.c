#include <ctype.h>
#include <errno.h>
#include <kit-alloc.h>
#include <kit.h>
#include <mockfail.h>
#include <string.h>

#include "atomic.h"
#include "object-hash.h"
#include "uint32list.h"
#include "uup-counters.h"

#define UINT32LIST_OBJECT_HASH_ROWS  (1 << 14)    /* 16,384 rows with 7 usable cells per row = 114,688 cells and 1MB RAM */
#define UINT32LIST_OBJECT_HASH_LOCKS 32

static bool
uint32list_hash_remove(void *v, void **vp)
{
    struct uint32list *candidate = *vp;
    struct uint32list *me = v;

    if (me == candidate && me->refcount == 0) {
        *vp = NULL;
        return true;
    }
    return false;
}

static void
uint32list_free(struct uint32list *me)
{
    if (me->oh && !object_hash_action(me->oh, me->fingerprint, object_hash_magic(me->oh), uint32list_hash_remove, me)) {
        /*-
         * XXX: It's unusal to get here...
         *      1. This thread gets into uint32list_free()
         *      2. Other thread gets a reference to me through the object-hash
         *      3. This thread fails the object_hash_action(..., uint32list_hash_remove, ...)
         *      4. Other thread releases its reference
         * When we get to this point, the other thread will delete (or already has deleted) the object internals,
         * so in fact, the object_hash_action() failure implies that the object is now somebody else's problem.
         */
        SXEL6("Failed to remove uint32list from its hash (refcount %d); another thread raced to get a reference", me->refcount);
    } else {
        kit_free(me->val);
        kit_free(me);
    }
}

/* For alteration by test-object-hash-race.c only */
void (*uint32list_free_hook)(struct uint32list *me) = uint32list_free;

void
uint32list_refcount_dec(struct uint32list *me)
{
    if (me != NULL && ATOMIC_DEC_INT_NV(&me->refcount) == 0)
        uint32list_free_hook(me);
}

void
uint32list_refcount_inc(struct uint32list *me)
{
    if (me != NULL)
        ATOMIC_INC_INT(&me->refcount);
}

static bool
uint32list_hash_use(void *v, void **vp)
{
    struct uint32list *candidate = *vp;
    struct object_fingerprint *of = v;

    if (memcmp(candidate->fingerprint, of->fp, of->len) == 0) {
        uint32list_refcount_inc(candidate);
        return true;
    }
    return false;
}

struct uint32list *
uint32list_new(const char *txt, struct object_fingerprint *of)
{
    struct uint32list *me, *retme;
    unsigned long long val;
    size_t nalloc, sz;
    uint32_t *nval;
    unsigned magic;
    char *end;

    me = retme = NULL;
    if (of) {
        if (of->hash == NULL)
            of->hash = object_hash_new(UINT32LIST_OBJECT_HASH_ROWS, of->len ? UINT32LIST_OBJECT_HASH_LOCKS : 0, of->len);
        else if ((magic = object_hash_magic(of->hash)) != of->len) {
            SXEL2("Invalid domainlist fingerprint; hex length should be %u, not %u", magic * 2, of->len * 2);
            goto SXE_EARLY_OUT;
        } else if (of->len)
            me = object_hash_action(of->hash, of->fp, of->len, uint32list_hash_use, of);
        kit_counter_incr(me ? COUNTER_UUP_OBJECT_HASH_HIT : COUNTER_UUP_OBJECT_HASH_MISS);
    }

    if (me == NULL) {
        sz = sizeof(*me) + (of ? of->len : 0);
        if ((me = MOCKFAIL(UINT32LIST_NEW, NULL, kit_calloc(1, sz))) == NULL) {
            SXEL2("Failed to allocate uint32list of %zu bytes", sz);
            goto SXE_EARLY_OUT;
        }
        me->refcount = 1;

        while (*txt) {
            while (isspace(*txt))
                txt++;
            if (!*txt)
                break;
            if (me->count == me->alloc) {
                nalloc = me->alloc + (me->alloc ? 100 : strlen(txt) / 6);
                if ((nval = MOCKFAIL(UINT32LIST_REALLOC, NULL, kit_realloc(me->val, nalloc * sizeof(*me->val)))) == NULL) {
                    SXEL2("Failed to reallocate uint32list val to %zu elements", nalloc);
                    goto SXE_EARLY_OUT;
                }
                me->val = nval;
                me->alloc = nalloc;
            }
            if ((val = kit_strtoull(txt, &end, 10)) == 0 || end == txt || errno != 0 || val != (uint32_t)val) {
                SXEL2("Invalid or out-of-range uint32 found in list");
                goto SXE_EARLY_OUT;
            }
            me->val[me->count++] = val;
            txt = end;
        }
        me->val = kit_reduce(me->val, (me->alloc = me->count) * sizeof(*me->val));

        if (of && of->hash) {
            me->oh = of->hash;
            memcpy(me->fingerprint, of->fp, of->len);
            if (object_hash_add(me->oh, me, of->fp, of->len) == NULL) {
                SXEL2("Failed to hash uint32list object; memory exhaustion?");
                me->oh = NULL;
            }
        }
    }
    retme = me;

SXE_EARLY_OUT:
    if (retme == NULL)
        uint32list_refcount_dec(me);

    return retme;
}
