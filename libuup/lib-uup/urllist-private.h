#ifndef URLLIST_PRIVATE_H
#define URLLIST_PRIVATE_H

#define MAX_URL_LENGTH 4096

// Super magical constant that will probably need to be tuned over time
#define AVERAGE_URL_LENGTH 100

struct urllist_hash_bucket {
    struct urllist_hash_bucket *next;
    uint32_t hash_key;
    unsigned url_len;
    char url[];
};

struct urllist {
    struct conf conf;
    unsigned hash_size;
    struct urllist_hash_bucket **hash;
    struct object_hash *oh;            /* This object is a member of this hash */
    uint8_t fingerprint[];             /* Only the object hash knows the length! */
};

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define URLLIST_HASHTABLE_ADD    ((const char *)urllist_new_from_buffer + 0)
#   define URLLIST_PARSE_URLLIST    ((const char *)urllist_new_from_buffer + 1)
#   define URLLIST_HASHTABLE_CREATE ((const char *)urllist_new_from_buffer + 2)
#endif

#include "urllist.h"

#endif
