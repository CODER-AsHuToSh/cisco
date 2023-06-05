#include <sxe-log.h>
#include <tap.h>
#include <pthread.h>

#include "kit-counters.h"

kit_counter_t KIT_COUNT;

static void
static_thread_cleanup(void *v)
{
    if ((intptr_t)v == 2345 && kit_counter_get(KIT_COUNT) == 6)
        kit_counter_incr(KIT_COUNT);
    else
        kit_counter_zero(KIT_COUNT);
}

static void *
static_thread(void *v)
{
    static pthread_key_t cleanup_key;

    SXE_UNUSED_PARAMETER(v);

    kit_counters_init_thread(1);

    pthread_key_create(&cleanup_key, static_thread_cleanup);
    pthread_setspecific(cleanup_key, (void *)(intptr_t)2345);

    kit_counter_add(KIT_COUNT, 5);
    kit_counters_fini_thread(1);

    return NULL;
}

static void
dynamic_thread_cleanup(void *v)
{
    if ((intptr_t)v == 1234 && kit_counter_get(KIT_COUNT) == 8)
        kit_counter_incr(KIT_COUNT);
    else
        kit_counter_zero(KIT_COUNT);
}

static void *
dynamic_thread(void *v)
{
    static pthread_key_t cleanup_key;
    unsigned slot;

    SXE_UNUSED_PARAMETER(v);

    slot = kit_counters_init_dynamic_thread();

    pthread_key_create(&cleanup_key, dynamic_thread_cleanup);
    pthread_setspecific(cleanup_key, (void *)(intptr_t)1234);

    kit_counter_incr(KIT_COUNT);
    kit_counters_fini_dynamic_thread(slot);

    return NULL;
}

int
main(void)
{
    pthread_t thr;
    void *ret;

    plan_tests(6);

    kit_counters_initialize(MAXCOUNTERS, 2, false);    /* Don't allow shared counters to be used */
    KIT_COUNT = kit_counter_new("kit.counter");
    ok(kit_counter_isvalid(KIT_COUNT), "Created kit.counter");
    kit_counter_incr(KIT_COUNT);

    if (ok(pthread_create(&thr, NULL, static_thread, NULL) == 0, "Created a static thread with counters"))
        pthread_join(thr, &ret);
    is(kit_counter_get(KIT_COUNT), 7, "Static thread-specific cleanup was able to adjust counters");

    diag("Setting up for dynamic threads and creating one to bump counters by 0, 1 and 10");
    kit_counters_prepare_dynamic_threads(1);

    if (ok(pthread_create(&thr, NULL, dynamic_thread, NULL) == 0, "Created a dynamic thread with counters"))
        pthread_join(thr, &ret);
    is(kit_counter_get(KIT_COUNT), 9, "Dynamic thread-specific cleanup was able to adjust counters");

    is(kit_num_counters(), 7, "Number of counters is as expected (1 + 6 memory counters)");

    return exit_status();
}
