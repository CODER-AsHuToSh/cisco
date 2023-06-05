#include <mockfail.h>
#include <sxe-util.h>
#include <string.h>
#include <tap.h>

#include "kit-alloc.h"

static void
check_counters(const char *why, int m, int c, int r, int f, int fail)
{
    is(kit_counter_get(KIT_COUNTER_MEMORY_MALLOC), m, "%s, the KIT_COUNTER_MEMORY_MALLOC value is %d", why, m);
    is(kit_counter_get(KIT_COUNTER_MEMORY_CALLOC), c, "%s, the KIT_COUNTER_MEMORY_CALLOC value is %d", why, c);
    is(kit_counter_get(KIT_COUNTER_MEMORY_REALLOC), r, "%s, the KIT_COUNTER_MEMORY_REALLOC value is %d", why, r);
    is(kit_counter_get(KIT_COUNTER_MEMORY_FREE), f, "%s, the KIT_COUNTER_MEMORY_FREE value is %d", why, f);
    is(kit_counter_get(KIT_COUNTER_MEMORY_FAIL), fail, "%s, the KIT_COUNTER_MEMORY_FAIL value is %d", why, fail);
}

struct counter_gather {
    unsigned long bytes;
    unsigned long malloc;
    unsigned long calloc;
    unsigned long realloc;
    unsigned long free;
    unsigned long fail;
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
        { "memory.bytes", &cg->bytes },
        { "memory.malloc", &cg->malloc },
        { "memory.calloc", &cg->calloc },
        { "memory.realloc", &cg->realloc },
        { "memory.free", &cg->free },
        { "memory.fail", &cg->fail },
        { NULL, &cg->wtf },
    };

    for (i = 0; i < sizeof(map) / sizeof(*map); i++)
        if (map[i].key == NULL || strcmp(key, map[i].key) == 0) {
            if (map[i].key == NULL)
                SXEL1("Unexpected counter_callback key '%s'", key);
            *map[i].val = strtoul(val, &end, 0);
            if (*end)
                *map[i].val = 666;
            break;
        }
}

static int  length = 0;
static char buffer[4096];

static __printflike(1, 2) int
test_printf(const char *format, ...)
{
    va_list ap;
    int     newlen;

    va_start(ap, format);
    newlen = vsnprintf(buffer + length, sizeof(buffer) - length, format, ap);
    va_end(ap);

    if (newlen > 0) {
        length = newlen < (int)(sizeof(buffer) - length) ? length + newlen : (int)sizeof(buffer);
    }

    return newlen;
}

int
main(void)
{
    size_t talloc1, talloc2, talloc3;
    size_t alloc1, alloc2, alloc3;
    struct counter_gather cg;
    char *ptr1, *ptr2;
    int failures;

    plan_tests(77);

    /* Initialize memory before counters. test-kit-counters tests the opposite order
     */
    kit_memory_initialize(false);    // Initialize memory with no aborts; this will call kit_memory_init_internal
    ok(kit_memory_is_initialized(),               "Memory is initialized");
    ok(kit_counter_get(KIT_COUNTER_MEMORY_BYTES), "Memory was allocated and tracked before counters were initialized");

    kit_counters_initialize(MAXCOUNTERS, 1, false);
    check_counters("After initializing the counters", 0, 0, 0, 0, 0);
    alloc1  = kit_allocated_bytes();
    talloc1 = kit_thread_allocated_bytes();

    ptr1 = kit_malloc(100);
    check_counters("After one malloc", 1, 0, 0, 0, 0);
    alloc2 = kit_allocated_bytes();
    talloc2 = kit_thread_allocated_bytes();
    ok(alloc2 - alloc1 >= 100, "kit_allocated_bytes() reports that alloc2 (%zu) is at least 100 greater than alloc1 (%zu)", alloc2, alloc1);
    ok(talloc2 - talloc1 >= 100, "kit_thread_allocated_bytes() reports that talloc2 (%zu) is at least 100 greater than talloc1 (%zu)", talloc2, talloc1);

    ptr2 = kit_malloc_diag(0, __FILE__, __LINE__);    // Call via the wrapper (used in release build by openssl)
    ok(ptr1 != NULL, "kit_malloc(0) returns a pointer");
    check_counters("After malloc(0)", 2, 0, 0, 0, 0);

    kit_free(ptr2);
    check_counters("After a free()", 2, 0, 0, 1, 0);

    ptr2 = kit_calloc(2, 100);
    check_counters("After an additional calloc", 2, 1, 0, 1, 0);
    alloc3 = kit_allocated_bytes();
    talloc3 = kit_thread_allocated_bytes();
    ok(alloc3 - alloc2 >= 200, "kit_allocated_bytes() reports that alloc3 (%zu) is at least 200 greater than alloc2 (%zu)", alloc3, alloc2);
    ok(talloc3 - talloc2 >= 200, "kit_thread_allocated_bytes() reports that talloc3 (%zu) is at least 200 greater than talloc2 (%zu)", talloc3, talloc2);

    kit_free_diag(ptr1, __FILE__, __LINE__);    // Call via the wrapper (used in release build by openssl)
    check_counters("After one free()", 2, 1, 0, 2, 0);

    ptr2 = kit_realloc(ptr2, 10);
    check_counters("After a realloc()", 2, 1, 1, 2, 0);

    ptr1 = kit_realloc(ptr2, 0);
    ok(ptr1 == NULL, "realloc(..., 0) returns NULL");
    check_counters("After a realloc(..., 0)", 2, 1, 1, 3, 0);

    ptr1 = kit_realloc_diag(NULL, 0, __FILE__, __LINE__);    // Call via the wrapper (used in release build by openssl)
    check_counters("After a realloc(NULL, 0)", 3, 1, 1, 3, 0);

    kit_free(NULL);
    check_counters("After a free(NULL)", 3, 1, 1, 3, 0);

    failures = 0;
    MOCKFAIL_START_TESTS(1, KIT_ALLOC_MANGLE(kit_reduce));
    is(kit_reduce(ptr1, 1), ptr1, "When kit_reduce() fails to realloc(), it returns the same pointer");
    failures++;
    MOCKFAIL_END_TESTS();

    kit_reduce(ptr1, 0);
    check_counters("After free()ing the last pointer", 3, 1, 1, 4, failures);

    ok(!kit_reduce(NULL, 0), "kit_reduce(NULL, 0) is a no-op");

    diag("Checking counter gatherer");
    memset(&cg, 0xa5, sizeof(cg));
    cg.wtf = 0;
    kit_counters_mib_text("memory", &cg, counter_callback, -1, 0);
    ok(cg.bytes > 200, "Allocated more than 200 bytes");
    is(cg.malloc, 3, "Malloc says 3");
    is(cg.calloc, 1, "Calloc says 1");
    is(cg.realloc, 1, "Realloc says 1");
    is(cg.free, 4, "Free says 4");
    is(cg.fail, failures, "Fail says %d", failures);
    is(cg.wtf, 0, "WTF says 0");

    void *mem = malloc(1);    // Force some glibc memory growth
    ok(kit_memory_log_growth(test_printf), "Logged growth in allocated memory");
    is_strncmp(buffer, "Maximum memory allocated via jemalloc", sizeof("Maximum memory allocated via jemalloc") - 1,
               "Expected start of output found");
    length = 0;
    ok(kit_memory_log_stats(test_printf, NULL), "Created a statistics file");
    is_strncmp(buffer, "___ Begin jemalloc statistics ___", sizeof("___ Begin jemalloc statistics ___") - 1,
               "Expected start of output found");
    free(mem);

    is(kit_counter_get_data(INVALID_COUNTER, -1), 0,  "The invalid counter has not been touched");

    return exit_status();
}
