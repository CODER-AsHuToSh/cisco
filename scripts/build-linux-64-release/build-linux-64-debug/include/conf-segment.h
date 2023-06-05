#ifndef CONF_SEGMENT_H
#define CONF_SEGMENT_H

#include <md5.h>

struct conf_segment {
    uint32_t id;
    int refcount;
    uint64_t alloc;
    time_t mtime;
    time_t ctime;
    bool loaded;       /* Indicates whether the segment is loaded, could be from a last-good file */
    bool failed_load;  /* Indicates that the most recent load attempt failed */
    uint8_t digest[MD5_DIGEST_LENGTH];
};

struct conf_loader;

#include "conf-segment-proto.h"

#endif
