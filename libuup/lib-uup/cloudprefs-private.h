#ifndef CLOUDPREFS_PRIVATE_H
#define CLOUDPREFS_PRIVATE_H

#include "cloudprefs.h"

struct cloudprefs {
    struct conf conf;
    unsigned count;            /* # allocated org entries */
    time_t mtime;              /* last modification */
    struct prefs_org **org;    /* a block of 'count' origin pointers */
};

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define CLOUDPREFS_CLONE      ((const char *)cloudprefs_register + 0)
#   define CLOUDPREFS_CLONE_ORGS ((const char *)cloudprefs_register + 1)
#   define CLOUDPREFS_MOREORGS   ((const char *)cloudprefs_register + 2)
#endif

#endif
