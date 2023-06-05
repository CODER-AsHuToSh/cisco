#ifndef UINT32LIST_H
#define UINT32LIST_H

struct object_hash;
struct object_fingerprint;

struct uint32list {
    uint32_t *val;             /* Array of values cidrs */
    unsigned alloc;            /* Allocated size of val array */
    unsigned count;            /* Number of addresses in val array */
    int refcount;
    struct object_hash *oh;    /* This object is a member of this hash */
    uint8_t fingerprint[];     /* Only the object hash (oh) knows the length! */
};

#include "uint32list-proto.h"

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define UINT32LIST_NEW     ((const char *)uint32list_new + 0)
#   define UINT32LIST_REALLOC ((const char *)uint32list_new + 1)
#endif

#endif
