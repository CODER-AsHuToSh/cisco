#ifndef CIDRPREFS_PRIVATE_H
#define CIDRPREFS_PRIVATE_H

#include "cidrprefs.h"

struct cidrprefs {
    struct conf conf;
    unsigned count;           /* # allocated org entries */
    time_t mtime;             /* last modification */
    struct prefs_org **org;   /* a block of 'count' organization pointers */
};

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define CIDRPREFS_CLONE      ((const char *)cidrprefs_register + 0)
#   define CIDRPREFS_CLONE_ORGS ((const char *)cidrprefs_register + 1)
#   define CIDRPREFS_MOREORGS   ((const char *)cidrprefs_register + 2)
#endif

#endif
