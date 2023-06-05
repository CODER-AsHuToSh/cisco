#ifndef LISTS_PRIVATE_H
#define LISTS_PRIVATE_H

#include "lists.h"

#define LOADFLAGS_LISTS (LOADFLAGS_FP_ALLOW_OTHER_TYPES | LOADFLAGS_FP_ELEMENTTYPE_DOMAIN | LOADFLAGS_FP_ELEMENTTYPE_URL \
                       | LOADFLAGS_FP_ELEMENTTYPE_CIDR | LOADFLAGS_FP_SEGMENTED | LOADFLAGS_FP_NO_LTYPE)

struct lists_index {
    unsigned slot;
    unsigned offset;
};

struct lists {
    struct conf        conf;
    time_t             mtime;    // last modification
    unsigned           count;    // # allocated lists_org entries
    struct lists_org **orgs;     // a block of 'count' pointers to lists_orgs
};

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define LISTS_CLONE            ((const char *)lists_register + 0)
#   define LISTS_CLONE_LISTS_ORGS ((const char *)lists_register + 1)
#   define LISTS_MORE_LISTS_ORGS  ((const char *)lists_register + 2)
#endif

#endif
