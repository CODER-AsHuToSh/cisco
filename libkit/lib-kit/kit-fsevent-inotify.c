#ifdef __linux__

#include "kit-fsevent.h"
#include <sxe-log.h>

void
kit_fsevent_init(struct kit_fsevent *me)
{
    SXEA1((me->fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC)) != -1, "Couldn't inotify_init()");
}

void
kit_fsevent_fini(struct kit_fsevent *me)
{
    close(me->fd);
}

int
kit_fsevent_add_watch(struct kit_fsevent *me, const char *mon, int how)
{
    return inotify_add_watch(me->fd, mon, how);
}

void
kit_fsevent_rm_watch(struct kit_fsevent *me, int fd)
{
    inotify_rm_watch(me->fd, fd);
}

void
kit_fsevent_iterator_init(struct kit_fsevent_iterator *me)
{
    me->pos = me->len = 0;
}

kit_fsevent_ev_t *
kit_fsevent_read(struct kit_fsevent *me, struct kit_fsevent_iterator *iter)
{
    kit_fsevent_ev_t *ev;

    do {
        if (iter->pos >= iter->len) {
            iter->pos = 0;
            if ((iter->len = read(me->fd, iter->buf, sizeof(iter->buf))) <= 0)
                return NULL;
        }
        ev = (kit_fsevent_ev_t *)(iter->buf + iter->pos);
        if ((iter->pos += sizeof(*ev) + ev->len) > iter->len)
            return NULL;    /* COVERAGE EXCLUSION: Good kernels only give us good data */
    } while (!KIT_FSEVENT_EV_ERROR(ev) && !ev->len);

    return ev;
}

#endif
