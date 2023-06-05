#ifndef NETPREFS_PRIVATE_H
#define NETPREFS_PRIVATE_H

#include "fileprefs.h"
#include "netprefs.h"

struct radixtree32;
struct radixtree128;

struct netprefs {
    struct fileprefs fp;
    struct conf conf;
    struct radixtree32 *radixtree32;
    struct radixtree128 *radixtree128;
};

#endif
