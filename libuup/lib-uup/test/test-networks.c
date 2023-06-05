#include <fcntl.h>
#include <kit-alloc.h>
#include <mockfail.h>
#include <tap.h>

#include "conf-loader.h"
#include "kit-random.h"
#include "networks-private.h"
#include "radixtree32.h"
#include "radixtree128.h"

#include "common-test.h"

static void
validate_network(const struct network *network, const char *cidr, uint32_t org, uint32_t origin)
{
    if (network) {
        if (network->family == AF_INET) {
            is_strstr(cidr_ipv4_to_str(&network->addr.v4, false), cidr, "Got expected CIDR");
        } else {
            is_strstr(cidr_ipv6_to_str(&network->addr.v6, false), cidr, "Got expected CIDR");
        }
        is(network->org_id, org, "Got expected org id");
        is(network->origin_id, origin, "Got expected origin id");
    }
}

int
main(void)
{
    struct conf_loader cl;
    uint64_t           start_allocations;
    struct conf_info  *info;
    struct networks   *nets;
    const char        *fn;
    unsigned           i;

    struct netaddr addr;

    plan_tests(95);

    // Clean up any files left if the test crashes
    unlink("test-networks");

    kit_random_init(open("/dev/urandom", O_RDONLY));
    conf_initialize(".", ".", false, NULL);
    kit_memory_initialize(false);
    // KIT_ALLOC_SET_LOG(1);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */

    conf_loader_init(&cl);

    diag("Test missing file load");
    {
        info = conf_info_new(NULL, "noname", "nopath", NULL, LOADFLAGS_NONE, NULL, 0);
        info->updates++;
        memset(info->digest, 0xa5, sizeof(info->digest));

        conf_loader_open(&cl, "/tmp/not-really-there", NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        ok(!nets, "Failed to read non-existent file");
        OK_SXEL_ERROR("not-really-there could not be opened: No such file or directory");
        OK_SXEL_ERROR(NULL);

        conf_loader_done(&cl, info);
        is(info->updates, 1, "conf_loader_done() didn't bump 'updates'");
        is(info->st.dev, 0, "Loading a non-existent file gives a clear stat");

        for (i = 0; i < sizeof(info->digest); i++)
            if (info->digest[i])
                break;

        is(i, sizeof(info->digest), "The digest of an empty file has %zu zeros", sizeof(info->digest));
        conf_info_free(info);
    }

    diag("Test garbage file");
    {
        fn = create_data("test-networks", "This is not the correct format\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read garbage file");
        OK_SXEL_ERROR(": 1: Invalid header; must contain 'networks'");
    }

    diag("Test V%u data load - old unsupported version", NETWORKS_VERSION - 1);
    {
        fn = create_data("test-networks", "networks %u\ncount 0\n", NETWORKS_VERSION - 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read V%u data", NETWORKS_VERSION - 1);
        OK_SXEL_ERROR(": 1: Invalid header version(s); must be numeric");    // This message will change when version > 1
    }

    diag("Test V%u data load - future version not yet supported", NETWORKS_VERSION + 1);
    {
        fn = create_data("test-networks", "networks %u\ncount 0\n", NETWORKS_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data", NETWORKS_VERSION + 1);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [%u]", NETWORKS_VERSION);
    }

    diag("Test V%u & V%u data load - doesn't contain V%u", NETWORKS_VERSION + 1, NETWORKS_VERSION + 2, NETWORKS_VERSION);
    {
        fn = create_data("test-networks", "networks %u %u\ncount 0\n", NETWORKS_VERSION + 1, NETWORKS_VERSION + 2);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u & version %u data", NETWORKS_VERSION + 1, NETWORKS_VERSION + 2);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [%u]", NETWORKS_VERSION);
    }

    diag("Test V%u data load with missing count", NETWORKS_VERSION);
    {
        fn = create_data("test-networks", "networks %u\nnocount 0\n", NETWORKS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data with missing count", NETWORKS_VERSION);
        OK_SXEL_ERROR(": 2: Invalid count; must begin with 'count '");
    }

    diag("Test V%u data load with count 0 empty file", NETWORKS_VERSION);
    {
        fn = create_data("test-networks", "networks %u\ncount 0\n", NETWORKS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(nets, "Read version %u data with count 0 and no data", NETWORKS_VERSION);
        OK_SXEL_ERROR(NULL);    // No error expected
        CONF_REFCOUNT_DEC(nets);
    }

    diag("Test V%u data load with count 1 and no section heading", NETWORKS_VERSION);
    {
        fn = create_data("test-networks", "networks %u\ncount 1\n", NETWORKS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data with count 1 and no section heading", NETWORKS_VERSION);
        OK_SXEL_ERROR(": 2: Failed to read '[networks:<count>:<version>]'");
    }

    diag("Test V%u data load with count 1 and no data", NETWORKS_VERSION);
    {
        fn = create_data("test-networks", "networks %u\ncount 1\n[networks:1:1]\n", NETWORKS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data with count 1 and no data", NETWORKS_VERSION);
        OK_SXEL_ERROR(": 3: Count 1, but only 0 networks");
    }

    diag("Test V%u data load with count 1 and 2 network:origin_id mappings", NETWORKS_VERSION);
    {
        fn = create_data("test-networks", "networks %u\ncount 1\n[networks:1:1]\n1.2.3.0/24:1234567890:0:1\n"
                                          "2.3.0.0/16:1123456789:0:0\n", NETWORKS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data with count 1 and 2 network:origin_id mappings", NETWORKS_VERSION);
        OK_SXEL_ERROR(": 5: More than 1 total line");
    }

    diag("Test V%u data load with a garbled network:origin_id mapping", NETWORKS_VERSION);
    {
        fn = create_data("test-networks", "networks %u\ncount 1\n[networks:1:1]\ngarbled\n", NETWORKS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data with a garbled network:origin_id mapping", NETWORKS_VERSION);
        OK_SXEL_ERROR(": 4: expected CIDR at start of line");
    }

    diag("Test V%u data load with invalid network ips", NETWORKS_VERSION);
    {
        fn = create_data("test-networks", "networks %u\ncount 1\n[networks:1:1]\nx.4.5.1/32:1234567890:0:1\n", NETWORKS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data with an invalid ipv4 address", NETWORKS_VERSION);
        OK_SXEL_ERROR(": 4: expected CIDR at start of line");

        fn = create_data("test-networks", "networks %u\ncount 1\n[networks:1:1]\n1.2.3.4.5/32:1234567890:0:1\n", NETWORKS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data with an invalid ipv4 address", NETWORKS_VERSION);
        OK_SXEL_ERROR(": 4: expected CIDR at start of line");

        fn = create_data("test-networks", "networks %u\ncount 1\n[networks:1:1]\n2002:68:a:g:/48:1234567890:0:1\n", NETWORKS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data with an invalid ipv6 address", NETWORKS_VERSION);
        OK_SXEL_ERROR(": 4: expected CIDR at start of line");
    }

    diag("Test V%u data load with a bad origin id", NETWORKS_VERSION);
    {
        fn = create_data("test-networks", "networks %u\ncount 1\n[networks:1:1]\n1.2.3.0/24:baddef:0:0\n", NETWORKS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data with a bad origin id", NETWORKS_VERSION);
        OK_SXEL_ERROR(": 4: Expected <origin-id>:<origin-type-id>:<organization-id>");
    }

    diag("Test V%u data load with an origin id >= 2^32", NETWORKS_VERSION);
    {
        fn = create_data("test-networks", "networks %u\ncount 1\n[networks:1:1]\n1.2.3.0/24:9999999999:0:9999999999\n", NETWORKS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data with a bad origin id", NETWORKS_VERSION);
        OK_SXEL_ERROR(": 4: Origin id 9999999999 overflows 32 bits");
    }

    diag("Test V%u data load with an invalid org id", NETWORKS_VERSION);
    {
        fn = create_data("test-networks", "networks %u\ncount 1\n[networks:1:1]\n1.2.3.0/24:1234567890:0:1x\n", NETWORKS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data with a bad org id", NETWORKS_VERSION);
        OK_SXEL_ERROR(": 4: Org id is followed by 'x', not end of line");
    }

    diag("Test V%u data load with an org id >= 2^32", NETWORKS_VERSION);
    {
        fn = create_data("test-networks", "networks %u\ncount 1\n[networks:1:1]\n1.2.3.0/24:1234567890:0:9999999999\n", NETWORKS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data with a bad org id", NETWORKS_VERSION);
        OK_SXEL_ERROR(": 4: Org id 9999999999 overflows 32 bits");
    }

    diag("Test V%u data load with garbage after the origin id", NETWORKS_VERSION);
    {
        fn = create_data("test-networks", "networks %u\ncount 1\n[networks:1:1]\n1.2.3.0/24:0:0:0:garbage\n", NETWORKS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data with garbage after the origin id", NETWORKS_VERSION);
        OK_SXEL_ERROR(": 4: Org id is followed by ':', not end of line");
    }

    diag("Test V%u + V%u load with truncated V%u data", NETWORKS_VERSION, NETWORKS_VERSION + 1, NETWORKS_VERSION + 1);
    {
        fn = create_data("test-networks", "networks 1 2\ncount 2\n[networks:1:1]\n1.2.3.0/24:1234567890:0:1\n"
                                          "[networks:1:2]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data when truncated", NETWORKS_VERSION + 1);
        OK_SXEL_ERROR(": 5: Section count 1, but only 0 lines at EOF");
    }

    diag("Test V%u + V%u load with truncated V%u data", NETWORKS_VERSION, NETWORKS_VERSION + 1, NETWORKS_VERSION + 1);
    {
        fn = create_data("test-networks", "networks 1 2\ncount 2\n[networks:1:1]\n1.2.3.0/24:1234567890:0:1\n"
                                          "[networks:1:2]\n[networks:0:3]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        nets = networks_new(&cl);
        unlink(fn);
        ok(!nets, "Failed to read version %u data when truncated", NETWORKS_VERSION + 1);
        OK_SXEL_ERROR(": 6: Section count 1 but '[networks:' found after 0 lines");
    }

    diag("Test V%u load with allocation failures", NETWORKS_VERSION);
    {
        fn = create_data("test-networks", "networks %u\ncount 1\n[networks:1:1]\n1.2.3.0/24:1234567890:0:1\n", NETWORKS_VERSION);

        MOCKFAIL_START_TESTS(2, NETWORKS_NEW);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            ok(!networks_new(&cl), "Didn't construct struct networks: failed to allocate networks structure");
            OK_SXEL_ERROR("Failed to malloc a networks structure");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(2, NETWORKS_ARRAY_NEW);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            ok(!networks_new(&cl), "Didn't construct struct networks: failed to allocate network array");
            OK_SXEL_ERROR("Failed to malloc a network array");
        MOCKFAIL_END_TESTS();

        unlink(fn);
        conf_loader_done(&cl, NULL);
    }

    diag("Test V%u load with radixtree memory failures", NETWORKS_VERSION);
    {
        fn = create_data("test-networks",
                         "networks %u\n"
                         "count 4\n"
                         "[networks:4:1]\n"
                         "1.2.0.0/16:1234567890:0:1\n"
                         "2.3.4.0/24:987654321:0:2\n"
                         "2002:68:a::/48:4567890:0:3\n"
                         "123:a:b::/48:6543210:0:4\n",
                         NETWORKS_VERSION);

        MOCKFAIL_START_TESTS(6, radixtree32_new);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            ok(!networks_new(&cl), "Couldn't construct networks due to radixtree32 create failure");
            OK_SXEL_ERROR("Couldn't allocate");
            OK_SXEL_ERROR("Failed to allocate radixtree32");

            MOCKFAIL_SET_FREQ(2);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            ok(!networks_new(&cl), "Couldn't construct networks due to radixtree32 insert failure");
            OK_SXEL_ERROR("Couldn't allocate");
            OK_SXEL_ERROR("Failed to insert a new radixtree32 node");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(6, radixtree128_new);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            ok(!networks_new(&cl), "Couldn't construct networks due to radixtree128 create failure");
            OK_SXEL_ERROR("Couldn't allocate");
            OK_SXEL_ERROR("Failed to allocate radixtree128");

            MOCKFAIL_SET_FREQ(2);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            ok(!networks_new(&cl), "Couldn't construct networks due to radixtre128 insert failure");
            OK_SXEL_ERROR("Couldn't allocate");
            OK_SXEL_ERROR("Failed to insert a new radixtree128 node");
        MOCKFAIL_END_TESTS();

        unlink(fn);
        conf_loader_done(&cl, NULL);
    }

    // Turn error log capture back off for non-error cases
    //
    OK_SXEL_ERROR(NULL);
    test_uncapture_sxel();

    diag("Test basic success cases of networks V%u", NETWORKS_VERSION);
    {
        struct confset        *conf_set;
        const struct network  *network;
        const struct networks *networks;
        int                    gen;

        networks_register(&CONF_NETWORKS, "networks", "test-networks", true);

        create_atomic_file("test-networks",
                           "networks %u\n"
                           "count 3\n"
                           "[networks:3:1]\n"
                           "1.2.0.0/16:1234567890:0:1\n"
                           "2.3.4.0/24:987654321:0:2\n"
                           "2002:68:a::/48:4567890:0:3\n",
                           NETWORKS_VERSION);
        ok(confset_load(NULL), "Loaded networks");
        ok(conf_set = confset_acquire(&gen), "Acquired the new conf set");
        if (conf_set) {
            ok(networks = networks_conf_get(conf_set, CONF_NETWORKS), "Got networks conf");

            if (networks) {
                is(networks->count, 3, "Correct number of networks");

                ok(netaddr_from_str(&addr, "4.3.2.1", AF_INET), "Converted IPv4 4.3.2.1");
                ok(!networks_get(networks, &addr, NULL), "Failed to get non-existent network from %s", netaddr_to_str(&addr));

                ok(netaddr_from_str(&addr, "1.2.3.4", AF_INET), "Converted IPv4 1.2.3.4");
                ok(network = networks_get(networks, &addr, NULL), "Got network from %s", netaddr_to_str(&addr));
                validate_network(network, "1.2.0.0/16", 1, 1234567890);

                ok(netaddr_from_str(&addr, "2.3.4.4", AF_INET), "Converted IPv4 2.3.4.4");
                ok(network = networks_get(networks, &addr, NULL), "Got network from %s", netaddr_to_str(&addr));
                validate_network(network, "2.3.4.0/24", 2, 987654321);

                ok(netaddr_from_str(&addr, "2002:68:a::6", AF_INET6), "Converted IPv4 2002:68:a::6");
                ok(network = networks_get(networks, &addr, NULL), "Got network from %s", netaddr_to_str(&addr));
                validate_network(network, "[2002:68:a::]/48", 3, 4567890);

            }

            confset_release(conf_set);
        }
        unlink("test-networks");

        create_atomic_file("test-networks",
                           "networks %u\n"
                           "count 3\n"
                           "[networks:1:1]\n"
                           "1.2.0.0/16:1234567890:0:1\n"
                           "[networks:2:2]\n"
                           "some random new format\n"
                           "with two lines\n",
                           NETWORKS_VERSION);
        ok(confset_load(NULL), "Loaded networks with multiple versions");
        ok(conf_set = confset_acquire(&gen), "Acquired the new conf set");
        if (conf_set) {
            ok(networks = networks_conf_get(conf_set, CONF_NETWORKS), "Got networks conf");
            if (networks) {
                is(networks->count, 1, "Only one network of valid version");
                ok(netaddr_from_str(&addr, "1.2.3.4", AF_INET), "Converted IPv4 1.2.3.4");
                ok(network = networks_get(networks, &addr, NULL), "Got network from %s", netaddr_to_str(&addr));
                validate_network(network, "1.2.0.0/16", 1, 1234567890);
            }
            confset_release(conf_set);
        }

        unlink("test-networks");
    }

    confset_unload();

    conf_loader_fini(&cl);
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    // KIT_ALLOC_SET_LOG(0);

    return exit_status();
}
