#include <inttypes.h>    /* Required by ubuntu */

#include "conf-loader.h"
#include "conf-segment.h"

#define CS(v, i) ((struct conf_segment *)((uint8_t *)(v)[i] + csoffset))

void
conf_segment_init(struct conf_segment *me, uint32_t id, struct conf_loader *cl, bool failed)
{
    struct conf_info info;

    me->id = id;
    me->refcount = 1;
    me->failed_load = true;

    if (failed) {
        me->loaded = false;
    } else {
        me->loaded = true;
        conf_loader_done(cl, &info);
        me->alloc = info.alloc;
        me->mtime = info.st.mtime;
        me->ctime = info.st.ctime;
        memcpy(me->digest, info.digest, sizeof(me->digest));
    }
}

unsigned
conf_segment_slot(void *const *const me, uint32_t id, unsigned count, unsigned csoffset)
{
    unsigned i, lim, pos;
    long long cmp;

    /* This is similar to bsearch(), but returns the where-it-should-be position if not found */

    for (pos = 0, lim = count; lim; lim >>= 1) {
        i = pos + (lim >> 1);
        if ((cmp = (long long)id - (long long)CS(me, i)->id) == 0) {
            pos = i;
            break;
        } else if (cmp > 0) {
            pos = i + 1;
            lim--;
        }
    }

    SXEA6(pos == count || id <= CS(me, pos)->id, "Unexpected pos %u looking for %" PRIu32 ", landed on %" PRIu32, pos, id, CS(me, pos)->id);

    SXEL7("%s(me=?, id=%" PRIu32 ", count=%u) {} // return %u, val %lld, prev %lld, next %lld", __FUNCTION__, id, count, pos,
        pos < count ? (long long)CS(me, pos)->id : -1LL,
        pos ? (long long)CS(me, pos - 1)->id : -1LL,
        pos + 1 < count ? (long long)CS(me, pos + 1)->id : -1LL);

    return pos;
}
