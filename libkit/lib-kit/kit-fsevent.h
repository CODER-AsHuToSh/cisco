#ifndef KIT_FSEVENT_H
#define KIT_FSEVENT_H

#ifdef __linux__

#include <stdio.h>
#include <sys/inotify.h>

#define KIT_FSEVENT_CREATE       IN_CREATE
#define KIT_FSEVENT_DELETE       IN_DELETE
#define KIT_FSEVENT_MOVED_TO     IN_MOVED_TO
#define KIT_FSEVENT_MOVED_FROM   IN_MOVED_FROM
#define KIT_FSEVENT_MODIFY       IN_MODIFY

typedef struct inotify_event    kit_fsevent_ev_t;

#define KIT_FSEVENT_WAIT_BUFSZ   (1024 * (sizeof(kit_fsevent_ev_t) + 16))
#define KIT_FSEVENT_ERRCHK       "check the fs.inotify.max_queued_events sysctl"

#define KIT_FSEVENT_EV_ERROR(ev)    ((ev)->mask & IN_Q_OVERFLOW)
#define KIT_FSEVENT_EV_FD(ev)       (ev)->wd
#define KIT_FSEVENT_EV_NAME(ev)     (ev)->name
#define KIT_FSEVENT_EV_ISDIR(ev)    ((ev)->mask & IN_ISDIR)
#define KIT_FSEVENT_EV_IS(ev, what) ((ev)->mask & (what))

#else

#include <sys/types.h>
#include <sys/event.h>

#define KIT_FSEVENT_CREATE       NOTE_WRITE
#define KIT_FSEVENT_DELETE       NOTE_WRITE
#define KIT_FSEVENT_MOVED_TO     NOTE_EXTEND
#define KIT_FSEVENT_MOVED_FROM   NOTE_EXTEND
#define KIT_FSEVENT_MODIFY       0

typedef struct kevent        kit_fsevent_ev_t;

#define KIT_FSEVENT_WAIT_BUFSZ   (1024 * sizeof(kit_fsevent_ev_t))
#define KIT_FSEVENT_ERRCHK       "no suggestions"

#define KIT_FSEVENT_EV_ERROR(ev)    ((ev)->flags & EV_ERROR)
#define KIT_FSEVENT_EV_FD(ev)       (ev)->ident
#define KIT_FSEVENT_EV_NAME(ev)     ".."
#define KIT_FSEVENT_EV_ISDIR(ev)    0
#define KIT_FSEVENT_EV_IS(ev, what) ((ev)->fflags & (what))

#endif

struct kit_fsevent {
    int fd;
};

struct kit_fsevent_iterator {
    char buf[KIT_FSEVENT_WAIT_BUFSZ];
    ssize_t pos, len;
};

void kit_fsevent_init(struct kit_fsevent *me);
void kit_fsevent_fini(struct kit_fsevent *me);
int kit_fsevent_add_watch(struct kit_fsevent *me, const char *mon, int how);
void kit_fsevent_rm_watch(struct kit_fsevent *me, int fd);
void kit_fsevent_iterator_init(struct kit_fsevent_iterator *me);
kit_fsevent_ev_t *kit_fsevent_read(struct kit_fsevent *me, struct kit_fsevent_iterator *iter);

#endif
