#ifndef CONF_DISPATCH_H
#define CONF_DISPATCH_H

#include <pthread.h>

enum conf_dispatch_queue {
    CONF_DISPATCH_WAIT,     /* Jobs that have just been loaded and aren't ready to be loaded again yet */
    CONF_DISPATCH_TODO,     /* Jobs that need to be done */
    CONF_DISPATCH_LIVE,     /* Jobs that are live or in progress */
    CONF_DISPATCH_DONE,     /* Jobs that are complete */
};

struct preffile;

struct conf_dispatch {
    union {                 /* Which conf we hold a ref to, or our pthread_t if CONF_DISPATCH_ISEXIT() */
        unsigned idx;
        pthread_t thr;
    };
    struct conf *data;      /* The conf to load (if info is set) or free (if info is NULL) */
    struct conf_info *info; /* user data */
    const struct preffile *segment; /* Segment data for individual segment loading */

    uint64_t wait_ms;        /* When this job started waiting */
};

#define CONF_DISPATCH_ISFREE(cd) ((cd).info == NULL && (cd).data != NULL)
#define CONF_DISPATCH_ISLOAD(cd) ((cd).info != NULL)
#define CONF_DISPATCH_ISEXIT(cd) ((cd).info == NULL && (cd).data == NULL)

struct loadjob;
typedef struct loadjob *conf_dispatch_handle_t;

#include "conf-dispatch-proto.h"

#endif
