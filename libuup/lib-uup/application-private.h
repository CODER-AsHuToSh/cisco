#ifndef APPLICATION_PRIVATE_H
#define APPLICATION_PRIVATE_H

#include "application.h"

struct application_index {
    unsigned slot;
    unsigned offset;
};

struct application {
    struct conf conf;
    unsigned count;                       /* # allocated application_lists entries */
    time_t mtime;                         /* last modification */
    struct application_lists **al;        /* a block of 'count' pointers */

    struct {
        struct application_index *ref;    /* A block of *index.count entries */
        unsigned count;
    } dindex, pindex;                     /* dindex is the super-domain-index, pindex is the super-proxy-index */
};

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define APPLICATION_CLONE             ((const char *)application_register_resolver + 0)
#   define APPLICATION_CLONE_DOMAINLISTS ((const char *)application_register_resolver + 1)
#   define APPLICATION_MOREDOMAINLISTS   ((const char *)application_register_resolver + 2)
#endif

#endif
