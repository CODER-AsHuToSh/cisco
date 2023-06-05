#ifndef LABELTREE_H
#define LABELTREE_H

#include "dns-name.h"

/* labeltree*get() flags */
#define LABELTREE_FLAG_NONE                 0x00
#define LABELTREE_FLAG_NO_WILDCARD_WHITEOUT 0x01

#define LABELTREE_VALUE_SET ((void *)true)    // Value for put if only using to test for a found value in get

struct labeltree;

struct labeltree_iter {
    struct labeltree *path[DNS_MAX_LABEL_CNT];    // Labeltree node at each level of the tree
    struct labeltree *parent;                     // Pointer to the parent of the last key searched if in the tree
    unsigned          i[DNS_MAX_LABEL_CNT];       // Slot of the child at each level of the tree
    unsigned          depth;                      // Number of nodes in the path
    int               cmp;                        // Whether the child is <, >, or == to the key searched for
};

typedef bool (*labeltree_walk_t)(const uint8_t *key, void *value, void *userdata);

#include "labeltree-proto.h"

static inline void *
labeltree_get(struct labeltree *me, const uint8_t *key, unsigned flags)
{
    return labeltree_get_walk(me, key, flags, NULL, NULL);
}

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define LABELTREE_NEW_INTERNAL ((const char *)labeltree_new + 0)
#   define LABELTREE_PUT_REALLOC  ((const char *)labeltree_new + 1)
#   define LABELTREE_PUT_MALLOC   ((const char *)labeltree_new + 2)
#endif

#endif
