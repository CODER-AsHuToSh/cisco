#include "uup-counters.h"

struct uup_counters uup_counters;    /* global */

void
uup_counters_init(void)
{
    uup_counters.object_hash_hit       = kit_counter_new("uup.object-hash.hit");
    uup_counters.object_hash_miss      = kit_counter_new("uup.object-hash.miss");
    uup_counters.object_hash_overflows = kit_counter_new("uup.object-hash.overflows");
}
