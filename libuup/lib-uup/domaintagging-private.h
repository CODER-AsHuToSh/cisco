#ifndef DOMAINTAGGING_PRIVATE_H
#define DOMAINTAGGING_PRIVATE_H

#include "dns-name.h"
#include "domaintagging.h"

struct prefixtree;

struct domaintagging {
    struct conf conf;
    unsigned version;
    struct prefixtree *prefixtree;
    pref_categories_t *value_pool;
    uint8_t first[DNS_MAXLEN_NAME], last[DNS_MAXLEN_NAME];
};

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define DOMAINTAGGING_NEW      ((const char *)domaintagging_new + 0)
#   define DOMAINTAGGING_NEW_POOL ((const char *)domaintagging_new + 1)
#endif

#endif
