#ifndef CONF_INFO_H
#define CONF_INFO_H

#include <md5.h>

struct pref_segments;
struct conf_type;
struct conf_segment_ops;

struct conf_stat {
    dev_t dev;
    ino_t ino;
    off_t size;
    time_t mtime;                             /* file modification time */
    time_t ctime;                             /* inode change time (creation date) */
};

struct conf_info {                            /* Persistent info about a registered file */
    uint64_t alloc;                           /* memory allocated by this object */
    uint32_t updates;                         /* # changes to this object */
    bool failed_load;
    unsigned char digest[MD5_DIGEST_LENGTH];  /* checksum */
    struct conf_stat st;
    const struct conf_type *type;
    uint32_t loadflags;                       /* flags used during file load.  LOADFLAGS_* flags are specific to the type */
    void *userdata;                           /* Likely to be loadflags specific */
    char *path;                               /* Registered path, relative to the /etc/opendnscache/root directory */
    struct pref_segments *manager;            /* Segment manager */
    const struct conf_segment_ops *seg;       /* Segment dispatch functions */

    /* refcount, registered and loadable are owned and locked by conf.c (current.lock) */
    unsigned refcount;                        /* number of confset objects using us */
    unsigned registered;                      /* number of times registered */
    unsigned loadable : 1;                    /* registered, but maybe not loadable 'till other stuff has also been registered */

    char name[];
};

#include "conf-info-proto.h"

#endif
