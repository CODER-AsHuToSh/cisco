#ifndef NETWORKS_PRIVATE_H
#define NETWORKS_PRIVATE_H

#include "networks.h"

struct radixtree32;
struct radixtree128;

struct networks {
    struct conf conf;
    struct network *networks;
    unsigned count;
    struct radixtree32 *radixtree32;
    struct radixtree128 *radixtree128;
};

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define NETWORKS_NEW       ((const char *)networks_new + 0)
#   define NETWORKS_ARRAY_NEW ((const char *)networks_new + 1)
#endif

#endif
