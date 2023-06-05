#ifndef CATEGORIZATION_PRIVATE_H
#define CATEGORIZATION_PRIVATE_H

#include "categorization.h"

struct catdata {
    enum categorizationtype type;    /* The type tells us how to search it */
    unsigned catbit;                 /* The bit it pertains to, or 0 for domaintagging */
    uint32_t polmask;                /* Restrict to only policies with this flag bit set */
    pref_orgflags_t orgmask;         /* Restrict to only orgs with this flag bit set */
};

struct categorization {
    struct conf conf;

    unsigned version;
    struct conf_registrar registrar;
    unsigned count;
    unsigned alloc;
    module_conf_t *module;    /* The registered confs */
    struct catdata *item;     /* And the corresponding data */
};

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define CATEGORIZATION_NEW         ((const char *)categorization_new + 0)
#   define CATEGORIZATION_ALLOC_ITEM  ((const char *)categorization_new + 1)
#   define CATEGORIZATION_ALLOC_MOD   ((const char *)categorization_new + 2)
#   define CATEGORIZATION_ALLOC_NAMES ((const char *)categorization_new + 3)
#endif

#endif
