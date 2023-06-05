#ifndef PREFIXTREE_H
#define PREFIXTREE_H

struct prefixtree;

#include "prefixtree-proto.h"

static inline void *
prefixtree_prefix_get(struct prefixtree *me, const uint8_t *key, int *len)
{
    return prefixtree_prefix_choose(me, key, len, NULL, NULL);
}

#endif
