#ifndef URLPREFS_PRIVATE_H
#define URLPREFS_PRIVATE_H

#include "urlprefs.h"

/*
 * A struct urlprefs is a dynamic array of urlprefs_org structure pointers
 */
struct urlprefs {
    struct conf conf;
    unsigned count;            /* # allocated org entries */
    time_t mtime;              /* last modification */
    struct prefs_org **org;    /* a block of 'count' organization pointers */
};

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define URLPREFS_CLONE      ((const char *)urlprefs_register + 0)
#   define URLPREFS_CLONE_ORGS ((const char *)urlprefs_register + 1)
#   define URLPREFS_MOREORGS   ((const char *)urlprefs_register + 2)
#endif

#endif
