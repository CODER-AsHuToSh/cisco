#ifndef UUP_COUNTERS_H
#define UUP_COUNTERS_H

#include <kit-counters.h>

struct uup_counters {
    kit_counter_t object_hash_hit;
    kit_counter_t object_hash_miss;
    kit_counter_t object_hash_overflows;
};

extern struct uup_counters uup_counters;

#define COUNTER_UUP_OBJECT_HASH_MISS       (uup_counters.object_hash_miss)
#define COUNTER_UUP_OBJECT_HASH_HIT        (uup_counters.object_hash_hit)
#define COUNTER_UUP_OBJECT_HASH_OVERFLOWS (uup_counters.object_hash_overflows)

#include "uup-counters-proto.h"

#endif
