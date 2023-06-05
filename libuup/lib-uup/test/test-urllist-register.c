#include <kit-alloc.h>

#include "conf.h"
#include "urllist.h"

#include "common-test.h"

#define STR_AND_LEN(str) str, strlen(str)

int
main(void)
{
    module_conf_t CONF_URLLIST_BOTNET;
    uint64_t start_allocations;
    const struct urllist *ul;
    struct confset *set;
    int gen;

    plan_tests(14);

    kit_memory_initialize(false);
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");
    gen = 0;
    conf_initialize(".", ".", false, NULL);

    CONF_URLLIST_BOTNET = 0;
    urllist_register(&CONF_URLLIST_BOTNET, "botnet-urllist", "test-botnet-urllist", true);
    ok(CONF_URLLIST_BOTNET, "Registered test-botnet-urllist");

    diag("The main conf thread reads our config");
    {
        create_atomic_file("test-botnet-urllist", "totally-not-a-botnet.com/nope");
        ok(confset_load(NULL), "Noted an update to test-botnet-urllist");
    }

    diag("The worker thread acquires our config and looks stuff up");
    {
        ok(set = confset_acquire(&gen), "Acquired the new conf set");
        skip_if(set == NULL, 2, "Cannot check content without acquiring config") {
            ok(ul = urllist_conf_get(set, CONF_URLLIST_BOTNET), "Got a handle on the botnet url list");
            skip_if(ul == NULL, 1, "Cannot check content without a list") {
                ok(urllist_match(ul, STR_AND_LEN("totally-not-a-botnet.com/nope")), "Found URL in list");
            }
            confset_release(set);
        }
    }

    diag("The main conf thread sees an empty list update");
    {
        create_atomic_file("test-botnet-urllist", "\n\n!=!=!\n");
        ok(confset_load(NULL), "Noted an update to test-botnet-urllist");
    }

    diag("The main conf thread sees a good update");
    {
        create_atomic_file("test-botnet-urllist", "foo.com/abc?def awesome.com/anything");
        ok(confset_load(NULL), "Noted an update to test-botnet-urllist");
    }

    diag("The worker thread acquires our config and looks stuff up");
    {
        ok(set = confset_acquire(&gen), "Acquired the new conf set");
        skip_if(set == NULL, 6, "Cannot check content without acquiring config") {
            ok(ul = urllist_conf_get(set, CONF_URLLIST_BOTNET), "Got a handle on the botnet url list");
            skip_if(ul == NULL, 5, "Cannot check content without a list") {
                ok(urllist_match(ul,  STR_AND_LEN("foo.com/abc?def")), "Found URL in list");
                ok(urllist_match(ul,  STR_AND_LEN("awesome.com/anything")), "Found URL in list");
                ok(!urllist_match(ul, STR_AND_LEN("not-in-the-list/?not=awesome")), "Not found URL in list");
            }
            confset_release(set);
        }
    }

    unlink("test-botnet-urllist");
    confset_unload();
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
