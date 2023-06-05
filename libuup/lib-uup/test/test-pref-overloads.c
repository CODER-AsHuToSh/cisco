#include <fcntl.h>
#include <kit-alloc.h>
#include <mockfail.h>
#include <tap.h>

#include "conf-loader.h"
#include "kit-random.h"
#include "pref-overloads.h"

#include "common-test.h"

int
main(void)
{
    const struct overloaded_pref *pref;
    const struct pref_overloads *po;
    uint64_t start_allocations;
    pref_categories_t all;
    struct conf_loader cl;
    struct confset *set;
    const char *sxediag;
    struct netaddr addr;
    int gen;

    plan_tests(100);

    kit_random_init(open("/dev/urandom", O_RDONLY));

    kit_memory_initialize(false);
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    conf_initialize(".", ".", false, NULL);
    conf_loader_init(&cl);
    gen = 0;
    pref_categories_setall(&all);
    test_capture_sxel();
    test_passthru_sxel(4);

    ok(pref = pref_overloads_default_listener(NULL), "Got a default pref from a NULL pref-overloads object");
    skip_if(!pref, 4, "Cannot check the pref when getting the default fails") {
        is(pref->orgflags, 0, "Got orgflags=0x00 from pref");
        is(pref->bundleflags, 0, "Got bundleflags=0x00 from pref");
        ok(pref_categories_isnone(&pref->categories), "Got categories=00 from pref");
        ok(pref_categories_equal(&pref->overridable_categories, &all), "Got overridable-categories=<all-FFs> from pref");
    }

    unlink("test-pref-overloads");
    pref_overloads_register(&CONF_PREF_OVERLOADS, "pref-overloads", "test-pref-overloads", true);
    ok(!confset_load(NULL), "confset_load() says there's no config there");
    create_atomic_file("test-pref-overloads",
                       "pref-overloads %d\n"
                       "# Orig - no data\n", PREF_OVERLOADS_VERSION);
    ok(confset_load(NULL), "Noted an update to the config set");

    ok(set = confset_acquire(&gen), "Acquired the new config set");
    ok(po = pref_overloads_conf_get(set, CONF_PREF_OVERLOADS), "Acquired a pref-overloads object from the config set");
    skip_if(!po, 4, "Cannot check content without pref-overloads data") {
        ok(pref = pref_overloads_default_listener(po), "Got a default pref from the pref-overloads object");
        skip_if(!pref, 3, "Cannot check the pref when getting the default fails") {
            is(pref->bundleflags, 0, "Got flags=0x00 from pref");
            ok(pref_categories_isnone(&pref->categories), "Got categories=00 from pref");
            ok(pref_categories_equal(&pref->overridable_categories, &all), "Got overridable-categories=<all-FFs> from pref");
        }
    }
    confset_release(set);

    MOCKFAIL_START_TESTS(2, PREF_OVERLOADS_NEW);
    create_atomic_file("test-pref-overloads",
                       "pref-overloads %d\n"
                       "# Revised - no data\n", PREF_OVERLOADS_VERSION);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't acquire a new config set when pref_overloads_allocate() fails");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-pref-overloads: Failed to calloc a pref-overloads structure", "Got the expected error");
    MOCKFAIL_END_TESTS();

    MOCKFAIL_START_TESTS(2, PREF_OVERLOADS_CC_NEW);
    create_atomic_file("test-pref-overloads",
                       "pref-overloads %d\n"
                       "country:XX:0:0:0:0:0:0\n", PREF_OVERLOADS_VERSION);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't acquire a new config set when pref_overloads_allocate() fails to allocate country prefs");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-pref-overloads: Failed to allocate country prefs", "Got the expected error");
    MOCKFAIL_END_TESTS();

    MOCKFAIL_START_TESTS(2, PREF_OVERLOADS_IP4_NEW);
    create_atomic_file("test-pref-overloads",
                       "pref-overloads %d\n"
                       "listener:1.2.3.4:0:0:0:0:0:0\n", PREF_OVERLOADS_VERSION);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't acquire a new config set when pref_overloads_allocate() fails to allocate ip4 prefs");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-pref-overloads: Failed to allocate ip4 prefs", "Got the expected error");
    MOCKFAIL_END_TESTS();

    MOCKFAIL_START_TESTS(2, PREF_OVERLOADS_IP6_NEW);
    create_atomic_file("test-pref-overloads",
                       "pref-overloads %d\n"
                       "listener:[1:2:3::4]:0:0:0:0:0:0\n", PREF_OVERLOADS_VERSION);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't acquire a new config set when pref_overloads_allocate() fails to allocate ip6 prefs");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-pref-overloads: Failed to allocate ip6 prefs", "Got the expected error");
    MOCKFAIL_END_TESTS();

    create_atomic_file("test-pref-overloads",
                       "pref-overload %d\n"
                       "listener:[1:2:3::4]:0:0:0:0:0:0\n", PREF_OVERLOADS_VERSION);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad header type");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-pref-overloads: 1: Failed to read type/version", "Got the expected error");

    create_atomic_file("test-pref-overloads",
                       "pref-overloads %d\n"
                       "listener:[1:2:3::4]:0:0:0\n", PREF_OVERLOADS_VERSION - 1);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad version number (%d)", PREF_OVERLOADS_VERSION - 1);
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-pref-overloads: 1: Invalid version 1", "Got the expected error");

    create_atomic_file("test-pref-overloads",
                       "pref-overloads %d\n"
                       "listener:[1:2:3::4]:0:0:0:0:0\n", PREF_OVERLOADS_VERSION + 1);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad version number (%d)", PREF_OVERLOADS_VERSION + 1);
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-pref-overloads: 1: Invalid version 3", "Got the expected error");

    create_atomic_file("test-pref-overloads",
                       "pref-overloads %d\n"
                       "listeners:[1:2:3::4]:0:0:0:0:0:0\n", PREF_OVERLOADS_VERSION);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad field 0 value");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-pref-overloads: 2: Field 0 invalid: Expected 'country' or 'listener'", "Got the expected error");

    diag("consumeaddr() failures");
    {
        create_atomic_file("test-pref-overloads",
                           "pref-overloads %d\n"
                           "listener:[1:2:3::4]x:0:0:0:0:0:0\n", PREF_OVERLOADS_VERSION);
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad IP number");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-pref-overloads: 2: Field 1 invalid: Expected an IP address", "Got the expected error");

        create_atomic_file("test-pref-overloads",
                           "pref-overloads %d\n"
                           "listener:1.2.3.x:0:0:0:0:0:0\n", PREF_OVERLOADS_VERSION);
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad IP number");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-pref-overloads: 2: Field 1 invalid: Expected an IP address", "Got the expected error");

        create_atomic_file("test-pref-overloads",
                           "pref-overloads %d\n"
                           "listener:1.2.3.4\n", PREF_OVERLOADS_VERSION);
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a truncated listener line");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-pref-overloads: 2: Field 1 invalid: Expected an IP address", "Got the expected error");
    }

    diag("Invalid country code");
    {
        create_atomic_file("test-pref-overloads",
                           "pref-overloads %d\n"
                           "country:XXx:0:0:0:0:0:0\n", PREF_OVERLOADS_VERSION);
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad country code (too many characters)");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-pref-overloads: 2: Field 1 invalid: Expected 2 character country code", "Got the expected error");

        create_atomic_file("test-pref-overloads",
                           "pref-overloads %d\n"
                           "country:XX-x:0:0:0:0:0:0\n", PREF_OVERLOADS_VERSION);
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad region code");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-pref-overloads: 2: Field 1 invalid: Expected a geo region number", "Got the expected error");

        create_atomic_file("test-pref-overloads",
                           "pref-overloads %d\n"
                           "country:XX-42x:0:0:0:0:0:0\n", PREF_OVERLOADS_VERSION);
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad region code");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-pref-overloads: 2: Field 1 invalid: Expected a geo region number", "Got the expected error");

        create_atomic_file("test-pref-overloads",
                           "pref-overloads %d\n"
                           "country:X:0:0:0:0:0:0\n", PREF_OVERLOADS_VERSION);
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad country code (too few characters)");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-pref-overloads: 2: Field 1 invalid: Expected 2 character country code", "Got the expected error");

        create_atomic_file("test-pref-overloads",
                           "pref-overloads %d\n"
                           "country:XX", PREF_OVERLOADS_VERSION);
        test_clear_sxel();
        ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad country code (truncated)");
        sxediag = test_all_sxel();
        is_strstr(sxediag, "test-pref-overloads: 2: Field 1 invalid: Expected 2 character country code", "Got the expected error");

        create_atomic_file("test-pref-overloads",
                           "pref-overloads %d\n"
                           "country:XX:0:0:0:0:0:0\n"
                           "country:UA-43:0:0:0:0:0:0\n", PREF_OVERLOADS_VERSION);
        ok(confset_load(NULL), "Loaded a pref-overloads file with a good country code and a good region");
    }

    create_atomic_file("test-pref-overloads",
                       "pref-overloads %d\n"
                       "country:XX:x:0:0:0:0:0\n", PREF_OVERLOADS_VERSION);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad orgflags field");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-pref-overloads: 2: Field 2 invalid: Expected hex orgflags", "Got the expected error");

    create_atomic_file("test-pref-overloads",
                       "pref-overloads %d\n"
                       "country:XX:0:x:0:0:0:0\n", PREF_OVERLOADS_VERSION);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad overridable_orgflags field");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-pref-overloads: 2: Field 3 invalid: Expected hex overridable_orgflags", "Got the expected error");

    create_atomic_file("test-pref-overloads",
                       "pref-overloads %d\n"
                       "country:XX:0:0:x:0:0:0\n", PREF_OVERLOADS_VERSION);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad bundleflags field");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-pref-overloads: 2: Field 4 invalid: Expected hex bundleflags", "Got the expected error");

    create_atomic_file("test-pref-overloads",
                       "pref-overloads %d\n"
                       "country:XX:0:0:0:x:0:0\n", PREF_OVERLOADS_VERSION);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad overridable_bundleflags field");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-pref-overloads: 2: Field 5 invalid: Expected hex overridable_bundleflags", "Got the expected error");

    create_atomic_file("test-pref-overloads",
                       "pref-overloads %d\n"
                       "country:XX:0:0:0:0:x:0\n", PREF_OVERLOADS_VERSION);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad categories field");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-pref-overloads: 2: Field 6 invalid: Expected hex categories", "Got the expected error");

    create_atomic_file("test-pref-overloads",
                       "pref-overloads %d\n"
                       "country:XX:0:0:0:0:0:x\n", PREF_OVERLOADS_VERSION);
    test_clear_sxel();
    ok(!confset_load(NULL), "Couldn't load a pref-overloads file with a bad overridable-categories field");
    sxediag = test_all_sxel();
    is_strstr(sxediag, "test-pref-overloads: 2: Field 7 invalid: Expected hex overridable-categories", "Got the expected error");

    diag("Actual lookups for v%d", PREF_OVERLOADS_VERSION);
    {
        create_atomic_file("test-pref-overloads",
                           "pref-overloads %d\n"
                           "listener:[1:2:3:4:5:6:7:8]:1:FFFFFFFFFFFFFFFE:2:BEEF:3:4\n"
                           "listener:1.2.3.4:4:FFFFFFFFFFFFFFFB:5:5:6:7\n"
                           "listener:[3:4:5:6:7:8::]:7:FFFFFFFFFFFFFFF8:8:10001000:9:10\n"
                           "listener:3.4.5.6:a:FFFFFFFFFFFFFFF5:b:f00f:c:d\n"
                           "country:IT:d:fffffffffffffff2:e:0:f:0\n"
                           "country:XX:10:ffffffffffffffef:11:ffffffee:12:ffffffed\n"
                           "country:UA-43:10:ffffffffffffbeef:11:ffffffee:12:ffffffed\n", PREF_OVERLOADS_VERSION);
        ok(confset_load(NULL), "Noted an update to the config set");
        ok(set = confset_acquire(&gen), "Acquired the new config set");
        ok(po = pref_overloads_conf_get(set, CONF_PREF_OVERLOADS), "Acquired a pref-overloads object from the config set");

        skip_if(!po, 23, "Cannot check content without pref-overloads data") {
            ok(pref = pref_overloads_default_listener(po), "Got a default pref from the pref-overloads object");
            skip_if(!pref, 6, "Cannot check the pref when getting the default fails") {
                is(pref->orgflags, 0, "Got orgflags=0x00 from pref");
                is(pref->overridable_orgflags, 0xFFFFFFFFFFFFFFFF, "Got overridable_orgflags=0xFFFFFFFFFFFFFFFF from pref");
                is(pref->bundleflags, 0, "Got bundleflags=0x00 from pref");
                is(pref->overridable_bundleflags, 0xFFFFFFFF, "Got overridable_bundleflags=0xFFFFFFFF from pref");
                ok(pref_categories_isnone(&pref->categories), "Got categories=00 from pref");
                ok(pref_categories_equal(&pref->overridable_categories, &all), "Got overridable-categories=<all-FFs> from pref");
            }

            netaddr_from_str(&addr, "1.2.3.5", AF_INET);
            ok(!pref_overloads_byip(po, &addr), "Cannot find listener 1.2.3.5");
            netaddr_from_str(&addr, "1.2.3.4", AF_INET);
            ok(pref = pref_overloads_byip(po, &addr), "Found listener 1.2.3.4");
            skip_if(!pref, 6, "Cannot check the pref when getting the pref fails") {
                is(pref->orgflags, 4, "Got orgflags=0x04 from pref");
                is(pref->overridable_orgflags, 0xFFFFFFFFFFFFFFFB, "Got overridable_orgflags=0xFFFFFFFFFFFFFFFB from pref");
                is(pref->bundleflags, 5, "Got bundleflags=0x05 from pref");
                is(pref->overridable_bundleflags, 5, "Got overridable_bundleflags=5 from pref");
                is_eq(pref_categories_idstr(&pref->categories), "6", "Got categories=06 from pref");
                is_eq(pref_categories_idstr(&pref->overridable_categories), "7", "Got overridable-categories=07 from pref");
            }

            netaddr_from_str(&addr, "3:4:5:6:7:8:9:a", AF_INET6);
            ok(!pref_overloads_byip(po, &addr), "Cannot find listener 3:4:5:6:7:8:9:a");
            netaddr_from_str(&addr, "3:4:5:6:7:8:0:0", AF_INET6);
            ok(pref = pref_overloads_byip(po, &addr), "Found listener 3:4:5:6:7:8:0:0");
            skip_if(!pref, 6, "Cannot check the pref when getting the pref fails") {
                is(pref->orgflags, 7, "Got orgflags=0x07 from pref");
                is(pref->overridable_orgflags, 0xFFFFFFFFFFFFFFF8, "Got overridable_orgflags=0xFFFFFFFFFFFFFFF8 from pref");
                is(pref->bundleflags, 8, "Got bundleflags=0x08 from pref");
                is(pref->overridable_bundleflags, 0x10001000, "Got overridable_bundleflags=0x10001000 from pref");
                is_eq(pref_categories_idstr(&pref->categories), "9", "Got categories=09 from pref");
                is_eq(pref_categories_idstr(&pref->overridable_categories), "10", "Got overridable-categories=10 from pref");
            }

            ok(!pref_overloads_bycc(po, "CA", 0), "Found no overrides for country CA");
            ok( pref_overloads_bycc(po, "IT", 0), "Found overrides for country IT");
            ok(!pref_overloads_bycc(po, "UA", 0), "Found no overrides for country UA");
            ok( pref_overloads_bycc(po, "UA", 43), "Found overrides for region UA-43");
        }
        confset_release(set);
    }

    diag("Test pref-overloads that include a default listener");
    {
        create_atomic_file("test-pref-overloads",
                           "pref-overloads %d\n"
                           "listener::1:FFFFFFFFFFFFFFFE:2:BEEF:3:4\n", PREF_OVERLOADS_VERSION);
        ok(confset_load(NULL), "Noted an update to the config set");
        ok(set = confset_acquire(&gen), "Acquired the new config set");
        ok(po = pref_overloads_conf_get(set, CONF_PREF_OVERLOADS), "Acquired a pref-overloads object from the config set");

        skip_if(!po, 7, "Cannot check content without pref-overloads data") {
            ok(pref = pref_overloads_default_listener(po), "Got a default pref from the pref-overloads object");

            skip_if(!pref, 6, "Cannot check the pref when getting the default fails") {
                is(pref->orgflags, 1, "Got orgflags=0x1 from pref");
                is(pref->overridable_orgflags, 0xFFFFFFFFFFFFFFFE, "Got overridable_orgflags=0xFFFFFFFFFFFFFFFE from pref");
                is(pref->bundleflags, 2, "Got bundleflags=0x2 from pref");
                is(pref->overridable_bundleflags, 0xBEEF, "Got overridable_bundleflags=0xBEEF from pref");
                is_eq(pref_categories_idstr(&pref->categories), "3", "Got categories=3 from pref");
                is_eq(pref_categories_idstr(&pref->overridable_categories), "4", "Got overridable-categories=4 from pref");
            }
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
