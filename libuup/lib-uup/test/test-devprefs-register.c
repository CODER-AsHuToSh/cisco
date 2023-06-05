#include <fcntl.h>
#include <kit-alloc.h>
#include <tap.h>

#include "devprefs.h"
#include "kit-random.h"
#include "fileprefs.h"

#include "common-test.h"

#define STR_AND_LEN(str) str, strlen(str)

int
main(void)
{
    uint64_t start_allocations;
    struct confset *set;
    int gen;

    plan_tests(6);

    kit_random_init(open("/dev/urandom", O_RDONLY));

    kit_memory_initialize(false);
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");
    gen = 0;
    conf_initialize(".", ".", false, NULL);

    devprefs_register_just_cidr(&CONF_DEVPREFS, "devprefs", "test-devprefs", true);
    ok(CONF_DEVPREFS, "Registered Devprefs");

    diag("The main conf thread reads our config");
    {
        create_atomic_file("test-devprefs",
                           "devprefs %d\n"
                           "count 8\n"
                           "[lists:5]\n"
                           "0:1:domain:71:00:blocked.com\n"
                           "8:1:domain:72:01:white.com\n"
                           "8:2:cidr:72:02:8.37.234.9/32 198.45.63.0/24\n"
                           "8:2:domain:72:03:siskosocks.com\n"
                           "8:3:cidr:72:04:8.37.234.12/32\n"
                           "[bundles:1]\n"
                           "0:1383:1:2000:0::::1 2 3:::::::\n"
                           "[orgs:1]\n"
                           "234:0:0:365:0:100234:0\n"
                           "[identities:1]\n"
                           "F2232173C6CA0000:43:24:234:0:1383", DEVPREFS_VERSION);
        ok(confset_load(NULL), "Noted an update to test-devprefs");
    }

    diag("The worker thread acquires our config and looks stuff up");
    {
        ok(set = confset_acquire(&gen), "Acquired the new conf set");
        skip_if(set == NULL, 1, "Cannot check content without acquiring config") {
            const struct devprefs *dp = devprefs_conf_get(set, CONF_DEVPREFS);
            struct kit_deviceid dev;
            pref_t pr;

            kit_deviceid_from_str(&dev, "F2232173C6CA0000");
            devprefs_get(&pr, dp, "devprefs", &dev, NULL);

            const char *list = pref_sorted_list(&pr, AT_LIST_DESTALLOW);
            char sorted_list[] = "198.45.63.0/24 8.37.234.12 8.37.234.9";    // Everything but the CIDRs is removed

            is_eq(list, sorted_list, "Unexpected values in allow list");
            pref_sorted_list(NULL, AT_LIST_DESTALLOW);
            confset_release(set);
        }
    }

    unlink("test-devprefs");
    confset_unload();
    fileprefs_freehashes();
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
