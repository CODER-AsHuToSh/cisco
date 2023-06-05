#ifndef OBJECT_HASH_H
#define OBJECT_HASH_H

struct object_hash;

struct object_fingerprint {
    struct object_hash *hash;
    const uint8_t *fp;
    unsigned len;
};

#include "object-hash-proto.h"

#endif
