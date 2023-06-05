#ifndef KIT_COUNTERS_H
#define KIT_COUNTERS_H

#define MAXCOUNTERS            600
#define INVALID_COUNTER        0       // Uninitialized counters hopefully have this value
#define COUNTER_FLAG_NONE      0x00
#define COUNTER_FLAG_SUMMARIZE 0x01

/* Special values that can be passed to kit_counter_get_data as threadnum
 */
#define KIT_THREAD_TOTAL  -1    // Get the total for all threads
#define KIT_THREAD_SHARED -2    // Get the shared count (for threads that haven't initialized per thread counters)

#include <inttypes.h>
#include <stdbool.h>

struct kit_counters {
    unsigned long long val[MAXCOUNTERS];
};

typedef unsigned kit_counter_t;
typedef void (*kit_counters_mib_callback_t)(void *, const char *, const char *);
typedef void (*kit_mibfn_t)(kit_counter_t, const char *subtree, const char *mib, void *v, kit_counters_mib_callback_t cb, int threadnum, unsigned cflags);

#include "kit-counters-proto.h"

#endif
