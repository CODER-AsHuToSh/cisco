#include <kit-alloc.h>
#include <mockfail.h>
#include <tap.h>

#include "namelist.h"

#include "common-test.h"

int
main(void)
{
    uint64_t start_allocations;
    const struct namelist *tep;
    char fullpath[PATH_MAX];
    struct confset *set;
    size_t len;
    int gen;

    plan_tests(18);

    kit_memory_initialize(false);
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    gen = 0;
    conf_initialize(NULL, ".", false, NULL);
    if (getcwd(fullpath, sizeof(fullpath))) {}    /* Silence attribute warn_unused_result from getcwd */
    len = strlen(fullpath);
    snprintf(fullpath + len, sizeof(fullpath) - len, "/test-typo-exception-prefixes");
    namelist_register(&CONF_TYPO_EXCEPTION_PREFIXES, "typo-exception-prefixes", fullpath, true);
    ok(CONF_TYPO_EXCEPTION_PREFIXES, "Registered test-typo-exception-prefixes");

    diag("The main conf thread reads our config");
    {
        create_atomic_file("test-typo-exception-prefixes", "%s", "");
        ok(confset_load(NULL), "Noted an update to test-typo-exception-prefixes");
    }

    diag("The worker thread acquires our config and looks stuff up");
    {
        ok(set = confset_acquire(&gen), "Acquired the new conf set");
        skip_if(set == NULL, 2, "Cannot check content without acquiring config") {
            ok(tep = namelist_conf_get(set, CONF_TYPO_EXCEPTION_PREFIXES), "Got a handle on the (empty) typo exceptions prefix list");
            skip_if(tep == NULL, 1, "Cannot check content without a list")
                ok(!namelist_prefix_match(tep, (const uint8_t *)"\1x\7opendns\3com"), "x.opendns.com is not in the (empty) list");
            confset_release(set);
        }
    }

    diag("The main conf thread sees a bad update");
    {
        create_atomic_file("test-typo-exception-prefixes", "x\na.b\nc..d\n");
        ok(!confset_load(NULL), "Noted no update to test-typo-exception-prefixes");
    }

    diag("The main conf thread sees a good update");
    {
        MOCKFAIL_START_TESTS(1, NAMELIST_ALLOCATE);
        create_atomic_file("test-typo-exception-prefixes", "x\na.b\nc.d\n# Comment\n");
        ok(!confset_load(NULL), "Cannot see an update to test-typo-exception-prefixes when namelist_allocate() fails");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(1, NAMELIST_ALLOCATE_NODE);
        create_atomic_file("test-typo-exception-prefixes", "x\na.b\nc.d\n# Another comment\n");
        ok(!confset_load(NULL), "Cannot see an update to test-typo-exception-prefixes when namelist_allocate() fails to allocate a node");
        MOCKFAIL_END_TESTS();

        create_atomic_file("test-typo-exception-prefixes", "x\na.b\nc.d");
        ok(confset_load(NULL), "Noted an update to test-typo-exception-prefixes");
    }

    diag("The worker thread acquires our config and looks stuff up");
    {
        ok(set = confset_acquire(&gen), "Acquired the new conf set");
        skip_if(set == NULL, 6, "Cannot check content without acquiring config") {
            ok(tep = namelist_conf_get(set, CONF_TYPO_EXCEPTION_PREFIXES), "Got a handle on the typo exceptions prefix list");
            skip_if(tep == NULL, 5, "Cannot check content without a list") {
                ok(namelist_prefix_match(tep, (const uint8_t *)"\1x\7opendns\3com"), "x.opendns.com matches the list");
                ok(namelist_prefix_match(tep, (const uint8_t *)"\1a\1b\7opendns\3com"), "a.b.opendns.com matches the list");
                ok(namelist_prefix_match(tep, (const uint8_t *)"\1c\1d\7opendns\3com"), "c.d.opendns.com matches the list");
                ok(!namelist_prefix_match(tep, (const uint8_t *)"\1a\1c\7opendns\3com"), "a.c.opendns.com does not match the list");
                ok(!namelist_prefix_match(tep, (const uint8_t *)"\1d\1d\7opendns\3com"), "d.d.opendns.com does not match the list");
            }
            confset_release(set);
        }
    }

    unlink("test-typo-exception-prefixes");
    confset_unload();
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
