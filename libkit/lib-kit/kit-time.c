#include <time.h>
#include "kit.h"

/* Cache time for fast access */
static __thread uint32_t cached_seconds;
static __thread uint64_t cached_nanoseconds;

const char *
kit_clocktype(void)
{
#ifdef CLOCK_MONOTONIC
    return "monotonic";
#else
    return "timeofday";
#endif
}

/* Calculate and return current seconds and nanoseconds */
static void
kit_time_get(uint32_t *seconds, uint64_t *nanoseconds)
{
#ifdef CLOCK_MONOTONIC
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return;    /* COVERAGE EXCLUSION: todo: test clock_gettime() failure... can it fail? */

    if (seconds != NULL)
        *seconds = ts.tv_sec;

    if (nanoseconds != NULL)
        *nanoseconds = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#else
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0)
        return;

    if (seconds != NULL)
        *seconds = tv.tv_sec;

    if (nanoseconds != NULL)
        *nanoseconds = tv.tv_sec * 1000000000ULL + tv.tv_usec * 1000;
#endif
}

uint64_t
kit_time_cached_nsec(void)
{
    return cached_nanoseconds;
}

uint32_t
kit_time_cached_sec(void)
{
    return cached_seconds;
}

/* Update the cached time values */
void
kit_time_cached_update(void)
{
    kit_time_get(&cached_seconds, &cached_nanoseconds);
}

/* Return current nanoseconds */
uint64_t
kit_time_nsec(void)
{
    uint64_t nanoseconds = 0;

    kit_time_get(NULL, &nanoseconds);

    return nanoseconds;
}

/* Return current seconds */
uint32_t
kit_time_sec(void)
{
    uint32_t seconds = 0;

    kit_time_get(&seconds, NULL);

    return seconds;
}
