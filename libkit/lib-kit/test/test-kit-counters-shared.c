#include <sxe-log.h>
#include <string.h>
#include <tap.h>
#include <pthread.h>

#include "kit.h"
#include "kit-alloc.h"
#include "kit-counters.h"

#define ERROR ((void *)1)

struct mycounters {
    kit_counter_t c1;
    kit_counter_t c2;
    kit_counter_t c3;
    kit_counter_t c4;
};

unsigned long long my_handler_value;

static unsigned long long
my_combine_handler(int threadnum)
{
    /*
     * A "combine" handler gets a chance to do something "special"
     * before returning its counter value.  Usually this is a
     * function that might (say) return the min/max/avg of the
     * per-thread values.
     *
     * For our tests we simply return a global value.
     */
    return threadnum <= 0 ? my_handler_value : 0;
}

static void
mibfn_thispath(kit_counter_t c, const char *subtree, const char *mib, void *v, kit_counters_mib_callback_t cb, int threadnum, unsigned cflags)
{
    char buf[100], submib[100];
    size_t submiblen;

    /*
     * A "mibfn" handler gets a chance to vivify tree nodes
     * on the fly.  It must be careful to only vivify stuff
     * under 'subtree' - which may include some nodes and
     * exclude others!
     *
     * Here
     * - 'subtree' is what we're looking for
     *   e.g. 'this.path.has'
     *   We want to vivify everything beginging with 'subtree'.
     * - 'mib' is the key that this function is attached to
     *   Set to 'this.path' in this test
     *
     * - 'submib' is a local buffer containing the vivified key
     *   e.g. 'this.path.is.thread' or 'this.path.has.time'
     * - 'buf' is a local buffer containing the vivified value
     */

    SXEA6(kit_counters_usable(), "%s(): Not initialized!", __FUNCTION__);
    SXE_UNUSED_PARAMETER(threadnum);

    if ((submiblen = strlen(mib)) < sizeof(submib) - 16) {
        strcpy(submib, mib);
        strcpy(submib + submiblen++, ".");

        strcpy(submib + submiblen, "has.a.value");
        if (kit_mibintree(subtree, submib)) {
            SXEL7("Requested subtree '%s', my mib '%s' - vivify has.a.value", subtree, mib);
            snprintf(buf, sizeof(buf), "%llu", kit_counter_get(c));
            cb(v, submib, buf);
        }

        strcpy(submib + submiblen, "has.some.flags");
        if (kit_mibintree(subtree, submib)) {
            SXEL7("Requested subtree '%s', my mib '%s' - vivify has.some.flags", subtree, mib);
            snprintf(buf, sizeof(buf), "%u", cflags);
            cb(v, submib, buf);
        }

        strcpy(submib + submiblen, "is.thread");
        if (kit_mibintree(subtree, submib)) {
            SXEL7("Requested subtree '%s', my mib '%s' - vivify is.thread", subtree, mib);
            snprintf(buf, sizeof(buf), "%d", threadnum);
            cb(v, submib, buf);
        }

        strcpy(submib + submiblen, "has.time");
        if (kit_mibintree(subtree, submib)) {
            SXEL7("Requested subtree '%s', my mib '%s' - vivify has.time", subtree, mib);
            snprintf(buf, sizeof(buf), "%" PRIu32, kit_time_sec());
            cb(v, submib, buf);
        }
    }
}

struct counter_gather {
    unsigned long hello_world;
    unsigned long hello_city;
    unsigned long hi_there;
    unsigned long this_path_has_a_value;     /* Fabricated in mibfn_thispath() */
    unsigned long this_path_has_some_flags;  /* Fabricated in mibfn_thispath() */
    unsigned long this_path_is_thread;       /* Fabricated in mibfn_thispath() */
    unsigned long this_path_has_time;        /* Fabricated in mibfn_thispath() */
    unsigned long wtf;
};

static void
counter_callback(void *v, const char *key, const char *val)
{
    struct counter_gather *cg = v;
    unsigned i;
    char *end;

    const struct {
        const char *key;
        unsigned long *val;
    } map[] = {
        { "hello.world", &cg->hello_world },
        { "hello.city", &cg->hello_city },
        { "hi.there", &cg->hi_there },
        { "this.path.has.a.value", &cg->this_path_has_a_value },
        { "this.path.has.some.flags", &cg->this_path_has_some_flags },
        { "this.path.is.thread", &cg->this_path_is_thread },
        { "this.path.has.time", &cg->this_path_has_time },
    };

    for (i = 0; i < sizeof(map) / sizeof(*map); i++)
        if (strcmp(key, map[i].key) == 0) {
            *map[i].val = strtoul(val, &end, 0);
            if (*end)
                *map[i].val = 666;
            return;
        }

    if (strncmp(key, "memory.", sizeof("memory.") - 1) == 0)
        return;

    SXEL3("Unexpected counter_callback key '%s'", key);
    cg->wtf++;
}

static void *
static_thread(void *v)
{
    struct mycounters *my = v;

    if (kit_counters_usable())
        return ERROR;

    kit_counters_init_thread(1);

    if (!kit_counters_usable())
        return ERROR;

    kit_counter_add(my->c2, 5);
    kit_counter_add(my->c3, 3);
    kit_counters_fini_thread(1);

    return NULL;
}

static void *
dynamic_thread(void *v)
{
    struct mycounters *my = v;
    unsigned slot;

    if (kit_counters_usable())
        return ERROR;

    slot = kit_counters_init_dynamic_thread();

    if (!kit_counters_usable())
        return ERROR;

    kit_counter_incr(my->c2);
    kit_counter_add(my->c3, 10);
    kit_counters_fini_dynamic_thread(slot);

    return NULL;
}

static bool first = true;

static void *
unmanaged_thread(void *v)
{
    struct mycounters *my = v;

    if (kit_counters_usable())    // Expect unmanaged threads to return unusable
        return ERROR;

    // Perform the atomic versions of all operations
    if (first) {
        kit_counter_add(my->c3, 10);
        kit_counter_incr(my->c3);
        kit_counter_decr(my->c3);
        first = false;
    }
    else
        kit_counter_zero(my->c3);

    // Make sure diddling the shared invalid counter is done non-atomically (tested by coverage)
    kit_counter_incr(INVALID_COUNTER);
    kit_counter_decr(INVALID_COUNTER);
    kit_counter_add( INVALID_COUNTER, 0);
    return NULL;
}

int
main(void)
{
    struct counter_gather cg;
    struct mycounters my;
    pthread_t thr;
    void *thread_retval;
    unsigned i;

    plan_tests(157);

    /* Initialize counters before memory. test-kit-alloc tests the opposite order
     */
    kit_counters_initialize(MAXCOUNTERS, 2, true);    // Allow shared counters to be used
    my.c3 = kit_counter_new("hi.there");
    ok(kit_counter_isvalid(my.c3), "Created a hi.there counter");
    kit_counter_incr(my.c3);
    is(kit_counter_get(my.c3), 1, "Set hi.there => 1");
    ok(kit_counter_get_data(INVALID_COUNTER, -1), "Expect some incrementing of the invalid counter due to early memory calls");
    kit_counter_zero(INVALID_COUNTER);

    kit_memory_initialize(false);    // Call after soft initialization

    kit_counter_zero(my.c3);
    is(kit_counter_get(my.c3), 0, "Set hi.there => 0");

    my.c1 = kit_counter_new_with_combine_handler("hello.world", my_combine_handler);
    ok(kit_counter_isvalid(my.c1), "Created a hello.world counter");
    my.c2 = kit_counter_new("hello.city");
    ok(kit_counter_isvalid(my.c2), "Created a hello.city counter");
    ok(kit_counter_isvalid(my.c3), "The hi.there counter is still valid and available");
    my.c4 = kit_counter_new_with_mibfn("this.path", mibfn_thispath);
    ok(kit_counter_isvalid(my.c4), "Created a this.path mibfn counter");

    kit_counter_add(my.c4, 999);
    is(kit_counter_get(my.c4), 999, "Set this.path's counter to 999");

    memset(&cg, 0xa5, sizeof(cg));
    cg.this_path_has_time = cg.wtf = 0;
    kit_counters_mib_text("", &cg, counter_callback, -1, 123);
    is(cg.hello_world, 0, "gather: hello.world says 0");
    is(cg.hello_city, 0, "gather: hello.city says 0");
    is(cg.hi_there, 0, "gather: hi.there says 0");
    is(cg.this_path_has_a_value, 999, "gather: this.path.has.a.value says 999");
    is(cg.this_path_has_some_flags, 123, "gather: this.path.has.a.value says 123");
    is(cg.this_path_is_thread, -1, "gather: this.path.is.thread says -1");
    ok(cg.this_path_has_time, "gather: this.path.has.time says %lu", cg.this_path_has_time);
    is(cg.wtf, 0, "gather: No unexpected counter callbacks were made");

    kit_counter_incr(my.c2);
    kit_counters_mib_text("hi", &cg, counter_callback, -1, 0);
    is(cg.hello_world, 0, "gather: hello.world says 0 - not updated");
    is(cg.hello_city, 0, "gather: hello.city says 0 - changed but not updated");
    is(cg.hi_there, 0, "gather: hi.there says 0 - updated but not changed");
    is(cg.wtf, 0, "gather: No unexpected counter callbacks were made");

    kit_counter_incr(my.c3);
    is(kit_counter_get(my.c3), 1, "Set hi.there => 1");
    kit_counters_mib_text("hi", &cg, counter_callback, -1, 0);
    is(cg.hello_world, 0, "gather: hello.world says 0 - not updated");
    is(cg.hello_city, 0, "gather: hello.city says 0 - not updated");
    is(cg.hi_there, 1, "gather: hi.there says 1 - updated");
    is(cg.wtf, 0, "gather: No unexpected counter callbacks were made");

    kit_counter_add(my.c1, 240);
    is(kit_counter_get(my.c1), 0, "Set hello.world => 0 - the combine handler ignored our value");
    kit_counters_mib_text("hello", &cg, counter_callback, -1, 0);
    is(cg.hello_world, 0, "gather: hello.world says 0 - changed, but it uses a handler");
    is(cg.hello_city, 1, "gather: hello.city says 1 - finally updated");
    is(cg.hi_there, 1, "gather: hi.there says 1 - not updated");
    is(cg.wtf, 0, "gather: No unexpected counter callbacks were made");

    my_handler_value = 12345;
    kit_counters_mib_text("hello", &cg, counter_callback, -1, 0);
    is(cg.hello_world, 12345, "gather: hello.world says 12345 - uses the handler properly");
    is(cg.hello_city, 1, "gather: hello.city says 1 - finally updated");
    is(cg.hi_there, 1, "gather: hi.there says 1 - not updated");
    is(cg.wtf, 0, "gather: No unexpected counter callbacks were made");

    kit_counter_decr(my.c1);
    is(kit_counter_get(my.c1), 12345, "Decrementing hello.world doesn't do anything");
    kit_counter_decr(my.c2);
    is(kit_counter_get(my.c2), 0, "Decrementing hello.city does");
    thread_retval = ERROR;

    if (ok(pthread_create(&thr, NULL, static_thread, &my) == 0, "Created a static thread with counters"))
        pthread_join(thr, &thread_retval);

    is(thread_retval, NULL, "kit_counters_usable worked as expected in static thread");
    kit_counters_mib_text("", &cg, counter_callback, -1, 0);
    is(cg.hello_city, 5, "gather: hello.city says 5");
    is(cg.hi_there, 4, "gather: hi.there says 4");

    diag("Setting up for dynamic threads and creating one to bump counters by 0, 1 and 10");
    kit_counters_prepare_dynamic_threads(1);
    thread_retval = ERROR;

    if (ok(pthread_create(&thr, NULL, dynamic_thread, &my) == 0, "Created a dynamic thread with counters"))
        pthread_join(thr, &thread_retval);

    is(thread_retval, NULL, "kit_counters_usable worked as expected in dynamic thread");

    /* We can always change our mind about how many dynamic slots we have! */
    kit_counters_prepare_dynamic_threads(3);

    diag("Look at the counter split over threads - joined threads are still accounted for in the thread=-1 call!");
    {
        struct {
            int threadno;
            struct counter_gather exp;
        } want[] = {
            { -1, { .hello_city = 6, .hi_there = 14, .this_path_has_a_value = 999, .this_path_has_some_flags = 0xff, .this_path_is_thread = -1 } },
            { 0,  { .hello_city = 0, .hi_there = 1,  .this_path_has_a_value = 999, .this_path_has_some_flags = 0x84, .this_path_is_thread = 0 } },
            { 1,  { .hello_city = 0, .hi_there = 0,  .this_path_has_a_value = 999, .this_path_has_some_flags = 0x03, .this_path_is_thread = 1 } },
            { 2,  { .hello_city = 0, .hi_there = 0,  .this_path_has_a_value = 999, .this_path_has_some_flags = 0x05, .this_path_is_thread = 2 } },
            { 3,  { .hello_city = 0, .hi_there = 0,  .this_path_has_a_value = 999, .this_path_has_some_flags = 0x00, .this_path_is_thread = 3 } },
            { 99, { .hello_city = 0, .hi_there = 0,  .this_path_has_a_value = 999, .this_path_has_some_flags = 0x00, .this_path_is_thread = 99 } },
        };

        for (i = 0; i < sizeof(want) / sizeof(*want); i++) {
            kit_counters_mib_text("", &cg, counter_callback, want[i].threadno, want[i].exp.this_path_has_some_flags);
            is(cg.hello_city, want[i].exp.hello_city, "gather: hello.city says %lu for thread %d", want[i].exp.hello_city, want[i].threadno);
            is(cg.hi_there, want[i].exp.hi_there, "gather: hi.there says %lu for thread %d", want[i].exp.hi_there, want[i].threadno);
            is(cg.this_path_has_a_value, want[i].exp.this_path_has_a_value, "gather: this.path.has.a.value says %lu for thread %d",
                                                                       want[i].exp.this_path_has_a_value, want[i].threadno);
            is(cg.this_path_has_some_flags, want[i].exp.this_path_has_some_flags, "gather: this.path.has.a.value says 0x%02lx for thread %d",
                                                                       want[i].exp.this_path_has_some_flags, want[i].threadno);
            is(cg.this_path_is_thread, want[i].exp.this_path_is_thread, "gather: this.path.is.thread says %lu for thread %d",
                                                                       want[i].exp.this_path_is_thread, want[i].threadno);
            ok(!cg.wtf, "gather: No unexpected callbacks for thread %d", want[i].threadno);
        }
    }

    diag("Ensure that only the requested tree is produced");
    {
        struct {
            const char *subtree;
            bool hello_world_isset;
            bool hello_city_isset;
            bool hi_there_isset;
            bool this_path_has_a_value_isset;
            bool this_path_is_thread_isset;
            bool this_path_has_some_flags_isset;
            bool this_path_has_time_isset;
        } exp[] = {
            { "", true, true, true, true, true, true, true },
            { "hel", false, false, false, false, false, false, false },
            { "hello", true, true, false, false, false, false, false },
            { "hi", false, false, true, false, false, false, false },
            { "this.pat", false, false, false, false, false, false, false },
            { "this.path", false, false, false, true, true, true, true },
            { "this.path.ha", false, false, false, false, false, false, false },
            { "this.path.has", false, false, false, true, false, true, true },
        };

#define TESTCG(i, name)                                                               \
        do {                                                                          \
            if (exp[i].name ## _isset)                                                \
                ok(cg.name, "gather('%s'): " #name " is set", exp[i].subtree);        \
            else                                                                      \
                is(cg.name, 0, "gather('%s'): " #name " is not set", exp[i].subtree); \
        } while (0)

        my_handler_value = 12345;
        for (i = 0; i < sizeof(exp) / sizeof(*exp); i++) {
            memset(&cg, '\0', sizeof(cg));
            kit_counters_mib_text(exp[i].subtree, &cg, counter_callback, -1, 42);
            TESTCG(i, hello_world);
            TESTCG(i, hello_city);
            TESTCG(i, hi_there);
            TESTCG(i, this_path_has_a_value);
            TESTCG(i, this_path_is_thread);
            TESTCG(i, this_path_has_some_flags);
            TESTCG(i, this_path_has_time);
            is(cg.wtf, 0, "gather('%s'): No unexpected counter callbacks were made", exp[i].subtree);
        }
    }

    diag("Test unmanaged threads that use shared counters");
    {
        unsigned long long was = kit_counter_get(my.c3);

        if (ok(pthread_create(&thr, NULL, unmanaged_thread, &my) == 0, "Created an unmanaged thread with no counters"))
            pthread_join(thr, &thread_retval);

        is(thread_retval, NULL, "kit_counters_usable worked as expected in unmanaged thread");
        is(kit_counter_get(my.c3), was + 10, "After spawning thread that uses a shared counter, counter increased by 10");
        is(kit_counter_get_data(my.c3, KIT_THREAD_SHARED), 10, "Shared counter was 10");

        if (ok(pthread_create(&thr, NULL, unmanaged_thread, &my) == 0, "Created an unmanaged thread to zero shared counters"))
            pthread_join(thr, &thread_retval);

        is(kit_counter_get(my.c3), was, "After spawning thread that zeros the shared counter, counter is what it was");
        is(kit_counter_get_data(my.c3, KIT_THREAD_SHARED), 0, "Shared counter was 0");
    }

    diag("Test out of range counters");
    {
        unsigned non_existent_counter = kit_num_counters() + 1;

        is(kit_counter_get(non_existent_counter), 0, "Nonexistent counter starts at 0");
        kit_counter_incr(non_existent_counter);
        is(kit_counter_get(non_existent_counter), 0, "Nonexistent counter can't be incremented");
        kit_counter_decr(non_existent_counter);
        is(kit_counter_get(non_existent_counter), 0, "Nonexistent counter can't be decremented");
        kit_counter_zero(non_existent_counter);
        kit_counter_add(non_existent_counter, 2);
        is(kit_counter_get(non_existent_counter), 0, "Nonexistent counter can't be added to");
    }

    ok(kit_counters_usable(),                         "Counters are usable in the main thread");
    is(kit_num_counters(),                        10, "Number of counters is as expected (4 + 6 memory counters)");
    is(kit_counter_get_data(INVALID_COUNTER, -1), 0,  "The invalid counter has not been touched");
    return exit_status();
}
