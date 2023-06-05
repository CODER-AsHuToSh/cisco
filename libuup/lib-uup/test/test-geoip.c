#include <fcntl.h>
#include <kit-alloc.h>
#include <kit-random.h>
#include <mockfail.h>

#include "conf-loader.h"
#include "geoip.h"
#include "radixtree32.h"
#include "radixtree128.h"

#include "common-test.h"

int
main(void)
{
    uint64_t start_allocations;
    const struct geoip *geoip;
    struct conf_loader cl;
    struct confset *set;
    const char *sxediag;
    struct netaddr addr;
    uint32_t region;
    int gen;

    plan_tests(64);

    kit_random_init(open("/dev/urandom", O_RDONLY));

    kit_memory_initialize(false);
    KIT_ALLOC_SET_LOG(1);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    conf_initialize(".", ".", false, NULL);
    conf_loader_init(&cl);
    gen = 0;
    test_capture_sxel();
    test_passthru_sxel(4);

    unlink("test-geoip");
    geoip_register(&CONF_GEOIP, "geoip", "test-geoip", true);
    ok(!confset_load(NULL), "confset_load() says there's no config there");
    create_atomic_file("test-geoip",
                       "geoip 1\n"
                       "count 0\n"
                       "# Orig - no data\n");
    ok(confset_load(NULL), "Noted an update to the config set");

    ok(set = confset_acquire(&gen), "Acquired the new config set");
    ok(geoip = geoip_conf_get(set, CONF_GEOIP), "Acquired a geoip object from the config set");
    skip_if(!geoip, 2, "Cannot check content without geoip data") {
        netaddr_from_str(&addr, "1.2.3.4", AF_INET);
        ok(!geoip_cc(geoip, &addr, NULL), "Cannot find 1.2.3.4 in geoip");

        netaddr_from_str(&addr, "1:2:3::4", AF_INET6);
        ok(!geoip_cc(geoip, &addr, NULL), "Cannot find 1:2:3::4 in geoip");
    }
    confset_release(set);

    MOCKFAIL_START_TESTS(2, GEOIP_NEW);
    create_atomic_file("test-geoip",
                       "geoip 1\n"
                       "count 0\n"
                       "# Revised - no data\n");
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't acquire a new config set when geoip_new() fails");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-geoip: Failed to calloc a geoip structure", "Got the expected error");
    MOCKFAIL_END_TESTS();

    create_atomic_file("test-geoip",
                       "geoip 1\n"
                       "count 1\n"
                       "1.2.3.4 IT\n");
    MOCKFAIL_START_TESTS(2, GEOIP_KEYS_NEW);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't acquire a new config set when geoip() fails to allocate keys");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-geoip: Failed to allocate geoip keys", "Got the expected error");
    MOCKFAIL_END_TESTS();
    ok(confset_load(NULL), "Acquired a new config set when geoip_new() works");

    create_atomic_file("test-geoip",
                       "geoipx 1\n"
                       "count 0\n"
                       "# Nothing\n");
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a geoip file with a bad header type");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "geoip: 1: Failed to read type/version", "Got the expected error");

    create_atomic_file("test-geoip",
                       "geoip 0\n"
                       "count 0\n"
                       "# Nothing\n");
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a geoip file with a bad version number (0)");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-geoip: 1: Invalid version 0", "Got the expected error");

    diag("Incorrect counts");
    {
        create_atomic_file("test-geoip",
                           "geoip 1\n"
                           "hello world\n"
                           "# Nothing\n");
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a geoip file with an invalid count line");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-geoip: 2: v1: Invalid count line", "Got the expected error");

        create_atomic_file("test-geoip",
                           "geoip 1\n"
                           "count 0\n"
                           "1.2.3.4 IT\n");
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a geoip file with an invalid count value");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-geoip: 3: v1: More entries present in the file than expected", "Got the expected error");

        create_atomic_file("test-geoip",
                           "geoip 1\n"
                           "count 1\n"
                           "# Nothing\n");
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a geoip file with an invalid count value");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-geoip: 3: v1: Expected 1 but got 0 entries", "Got the expected error");

        create_atomic_file("test-geoip",
                           "geoip 1\n"
                           "count 2\n"
                           "1.2.3.4 IT\n");
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a geoip file with an invalid (singular) count value");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-geoip: 3: v1: Expected 2 but got 1 entry", "Got the expected error");
    }

    diag("Test radixtree allocation failures");
    {
        create_atomic_file("test-geoip",
                           "geoip 1\n"
                           "count 4\n"
                           "1.2.3.4 XX\n"
                           "1:2:3::4 YY\n"
                           "5.6.7.8 XX\n"
                           "5:6:7::8 YY\n");

        MOCKFAIL_START_TESTS(4, radixtree32_new);
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't acquire a new config set when radixtree32_new fails");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-geoip: 3: Not enough memory to allocate a radixtree32", "Got the expected error");

        MOCKFAIL_SET_FREQ(2);
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't acquire a new config set when radixtree32_put fails");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-geoip: 5: Failed to insert a new radixtree32 node", "Got the expected error");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(4, radixtree128_new);
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't acquire a new config set when radixtree128_new fails");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-geoip: 4: Not enough memory to allocate a radixtree128", "Got the expected error");

        MOCKFAIL_SET_FREQ(2);
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't acquire a new config set when radixtree128_put fails");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-geoip: 6: Failed to insert a new radixtree128 node", "Got the expected error");
        MOCKFAIL_END_TESTS();

        ok(confset_load(NULL), "Acquired a new config set when radixtree works");
    }

    create_atomic_file("test-geoip",
                       "geoip 2\n"
                       "count 0\n"
                       "# Nothing\n");
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a geoip file with a bad version number (2)");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-geoip: 1: Invalid version 2", "Got the expected error");

    create_atomic_file("test-geoip",
                       "geoip 1\n"
                       "count 1\n"
                       "1:2:3::4x IT\n");
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a geoip file with garbage after the IPv6 address");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-geoip: 3: v1 lines must have two space separated columns", "Got the expected error");

    create_atomic_file("test-geoip",
                       "geoip 1\n"
                       "count 1\n"
                       "1.2.3.4x IT\n");
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a geoip file with garbage after the IPv4 address");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-geoip: 3: v1 lines must have two space separated columns", "Got the expected error");

    diag("Invalid country code");
    {
        create_atomic_file("test-geoip",
                           "geoip 1\n"
                           "count 1\n"
                           "1.2.3.4 ITx\n");
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a geoip file with a bad country code (too many characters)");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-geoip: 3: trailing garbage found", "Got the expected error");

        create_atomic_file("test-geoip",
                           "geoip 1\n"
                           "count 1\n"
                           "1.2.3.4 IT-x\n");
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a geoip file with a bad region");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-geoip: 3: trailing garbage found", "Got the expected error");

        create_atomic_file("test-geoip",
                           "geoip 1\n"
                           "count 1\n"
                           "1.2.3.4 IT-42x\n");
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a geoip file with a region with trailing junk");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-geoip: 3: trailing garbage found", "Got the expected error");

        create_atomic_file("test-geoip",
                           "geoip 1\n"
                           "count 1\n"
                           "1.2.3.4 IT-5000000000\n");
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a geoip file with a region with more than 32 bits");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-geoip: 3: trailing garbage found", "Got the expected error");

        create_atomic_file("test-geoip",
                           "geoip 1\n"
                           "count 1\n"
                           "1.2.3.4 X\n");
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a geoip file with a bad country code (too few characters)");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-geoip: 3: v1 lines must have a two character country code", "Got the expected error");

        create_atomic_file("test-geoip",
                           "geoip 1\n"
                           "count 1\n"
                           "1.2.3.4 XX\n");
        ok(confset_load(NULL), "Loaded a geoip file with a good country code");

        create_atomic_file("test-geoip",
                           "geoip 1\n"
                           "count 1\n"
                           "1.2.3.4 XX-1234\n");
        ok(confset_load(NULL), "Loaded a geoip file with a good region code");
    }

    create_atomic_file("test-geoip",
                       "geoip 1\n"
                       "count 1\n"
                       "this-is-not-a-cidr IT\n");
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a geoip file with a bad CIDR");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-geoip: 3: v1: Unrecognised line (invalid CIDR)", "Got the expected error");

    diag("Actual lookups");
    {
        create_atomic_file("test-geoip",
                           "geoip 1\n"
                           "count 8\n"
                           "1:2:3:4:5:6:7:8/128  IT\n"    // Cover having extra whitespace
                           "1:2:3::/48 IE\n"
                           "1:2:3:4::/64 IE\n"
                           "1.2.3.0/24 DE\n"
                           "1.2.0.0/16 US\n"
                           "1.0.0.0/8 CN\n"
                           "1.0.0.0/10 CA\n"
                           "6.6.6.0/24 UA-43\n");
        ok(confset_load(NULL), "Loaded geoip file that has an extra space between address and country code IT");

        ok(set = confset_acquire(&gen), "Acquired the new config set");
        ok(geoip = geoip_conf_get(set, CONF_GEOIP), "Acquired a geoip object from the config set");
        skip_if(!geoip, 5, "Cannot check content without geoip data") {
            netaddr_from_str(&addr, "2.2.3.5", AF_INET);
            ok(!geoip_cc(geoip, &addr, NULL), "Cannot find a country-code for 2.2.3.5");
            netaddr_from_str(&addr, "1.2.3.4", AF_INET);
            is_eq(geoip_cc(geoip, &addr, NULL) ?: "<NULL>", "DE", "Got country-code DE for 1.2.3.4");
            netaddr_from_str(&addr, "1.2.4.4", AF_INET);
            is_eq(geoip_cc(geoip, &addr, NULL) ?: "<NULL>", "US", "Got country-code US for 1.2.4.4");
            netaddr_from_str(&addr, "1.3.3.4", AF_INET);
            is_eq(geoip_cc(geoip, &addr, NULL) ?: "<NULL>", "CA", "Got country-code CA for 1.3.3.4");
            netaddr_from_str(&addr, "1.128.3.4", AF_INET);
            is_eq(geoip_cc(geoip, &addr, NULL) ?: "<NULL>", "CN", "Got country-code CN for 1.128.3.4");
            netaddr_from_str(&addr, "6.6.6.6", AF_INET);
            is_eq(geoip_cc(geoip, &addr, &region) ?: "<NULL>", "UA", "Got country-code UA for 6.6.6.6");
            is(region, 43, "Got region 43 for 6.6.6.6");
        }
        confset_release(set);
    }

    test_uncapture_sxel();
    confset_unload();
    conf_loader_fini(&cl);
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
