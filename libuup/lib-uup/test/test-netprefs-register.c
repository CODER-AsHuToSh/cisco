#include <arpa/inet.h>
#include <fcntl.h>
#include <kit-alloc.h>
#include <tap.h>

#include "kit-random.h"
#include "fileprefs.h"
#include "netprefs.h"

#include "common-test.h"

#define STR_AND_LEN(str) str, strlen(str)

int
main(void)
{
    uint64_t start_allocations;
    struct confset *set;
    int gen;

    plan_tests(7);

    kit_memory_initialize(false);
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");
    gen = 0;
    kit_random_init(open("/dev/urandom", O_RDONLY));
    conf_initialize(".", ".", false, NULL);

    netprefs_register_just_cidr(&CONF_NETPREFS, "netprefs", "test-netprefs", true);
    ok(CONF_NETPREFS, "Registered Netprefs");

    diag("The main conf thread reads our config");
    {
        create_atomic_file("test-netprefs",
                           "netprefs %d\n"
                           "count 8\n"
                           "[lists:5]\n"
                           "0:1:domain:71:00:blocked.com\n"
                           "8:1:domain:72:01:white.com\n"
                           "8:2:cidr:72:02:8.37.234.9/32 198.45.63.0/24\n"
                           "8:2:domain:72:03:siskosocks.com\n"
                           "8:3:cidr:72:04:8.37.234.12\n"
                           "[bundles:1]\n"
                           "0:1383:1:2000:0::::1 2 3:::::::\n"
                           "[orgs:1]\n"
                           "234:0:0:365:0:100234:0\n"
                           "[identities:1]\n"
                           "1.2.3.4/32:42:1:234:0:1383", NETPREFS_VERSION);
        ok(confset_load(NULL), "Noted an update to test-netprefs");
    }

    diag("The worker thread acquires our config and looks stuff up");
    {
        ok(set = confset_acquire(&gen), "Acquired the new conf set");
        skip_if(set == NULL, 1, "Cannot check content without acquiring config") {
            struct sockaddr_in sockaddr;
            struct netsock addr;
            const char *list;
            pref_t pr;

            sockaddr.sin_family = AF_INET;
            inet_pton(AF_INET, "1.2.3.4", &sockaddr.sin_addr);
            netsock_fromsockaddr(&addr, (struct sockaddr *)&sockaddr, sizeof(sockaddr));

            const struct netprefs *np = netprefs_conf_get(set, CONF_NETPREFS);

            ok(netprefs_get(&pr, np, "netprefs", &addr.a, NULL, NULL) != -1, "netprefs_get() succeeded");

            list = pref_sorted_list(&pr, AT_LIST_DESTALLOW);
            is_eq(list, "198.45.63.0/24 8.37.234.12 8.37.234.9", "unexpected values in allow list; only CIDRS expected");
            pref_sorted_list(NULL, AT_LIST_DESTALLOW);
            confset_release(set);
        }
    }

    unlink("test-netprefs");
    confset_unload();
    fileprefs_freehashes();
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
