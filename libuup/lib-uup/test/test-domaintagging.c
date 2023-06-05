#include <kit-alloc.h>
#include <mockfail.h>
#include <tap.h>

#include "conf-loader.h"
#include "domaintagging-private.h"
#include "prefixtree.h"

#include "common-test.h"

int
main(void)
{
    uint64_t start_allocations;
    struct domaintagging *dt;
    struct conf_loader cl;
    const char *fn;

    plan_tests(113);

    kit_memory_initialize(false);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");
    conf_loader_init(&cl);

    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */

    diag("Test missing file load");
    {
        conf_loader_open(&cl, "/tmp/not-really-there", NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(!dt, "Failed to read non-existent file");
        OK_SXEL_ERROR("/tmp/not-really-there could not be opened: No such file or directory");
        OK_SXEL_ERROR("Unrecognized header line, expected 'domaintagging");
    }

    diag("Test first header");
    {
        fn = create_data("test-domaintagging", "This is not the correct format\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        unlink(fn);
        ok(!dt, "Failed to read garbage file");
        OK_SXEL_ERROR(": Unrecognized header line, expected 'domaintagging");
    }

    diag("Test V1 data load");
    {
        fn = create_data("test-domaintagging", "version 1\ncount 0\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        unlink(fn);
        ok(!dt, "Failed to read version 1 data");
        OK_SXEL_ERROR(": Unrecognized header line, expected 'domaintagging");
    }

    diag("Test V3 data load");
    {
        fn = create_data("test-domaintagging", "domaintagging 3\ncount 0\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        unlink(fn);
        ok(!dt, "Failed to read domaintagging 3 data");
        OK_SXEL_ERROR(": Unrecognized header line, expected 'domaintagging");
    }

    diag("Test V2 data with no count");
    {
        fn = create_data("test-domaintagging", "domaintagging 2\nsomething else\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        unlink(fn);
        ok(!dt, "Failed to read version 2 data with no count");
        OK_SXEL_ERROR(": 2: Unrecognized count line, expected 'count");
    }

    diag("Test V2 empty data load");
    {
        fn = create_data("test-domaintagging", "domaintagging 2\ncount 0\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(dt, "Constructed struct domaintagging from empty V2 data");
        skip_if(!dt, 1, "Cannot test without a domaintagging object") {
            is(dt->version, 2, "The version number is correct");
            CONF_REFCOUNT_DEC(dt);
        }

        unlink(fn);
        fn = create_data("test-domaintagging", "domaintagging 2\ncount 1\ndomain:ffffffff");

        MOCKFAIL_START_TESTS(2, DOMAINTAGGING_NEW);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(!dt, "Can't construct a struct domaintagging object when malloc fails");
        OK_SXEL_ERROR(": Couldn't allocate ");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(2, DOMAINTAGGING_NEW_POOL);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(!dt, "Can't construct a struct domaintagging object when pool malloc fails");
        OK_SXEL_ERROR(": Couldn't allocate ");
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(dt, "Constructed struct domaintagging from V2 data with a single record");
        skip_if(!dt, 1, "Cannot test without a domaintagging object") {
            is(dt->version, 2, "The version number is correct");
            CONF_REFCOUNT_DEC(dt);
        }

        unlink(fn);
    }

    diag("Test V2 data load with extra lines");
    {
        fn = create_data("test-domaintagging", "domaintagging 2\ncount 0\nextra data\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        unlink(fn);
        ok(!dt, "Failed to read version 2 data with extra lines");
        OK_SXEL_ERROR(": 3: unexpected line (exceeds count)");
    }

    diag("Test V2 data load with missing lines");
    {
        fn = create_data("test-domaintagging", "domaintagging 2\ncount 1\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        unlink(fn);
        ok(!dt, "Failed to read version 2 data with missing lines");
        OK_SXEL_ERROR(": 2: unexpected end of file at record 0 (less than count 1)");

    }

    diag("Test V2 data load with invalid lines");
    {
        fn = create_data("test-domaintagging", "domaintagging 2\n" "count 1\n" "missing.colon\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        unlink(fn);
        ok(!dt, "Failed to read version 2 data with a missing colon");
        OK_SXEL_ERROR(": 3: Missing colon separator");

        fn = create_data("test-domaintagging", "domaintagging 2\n" "count 1\n" "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.com:1\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        unlink(fn);
        ok(!dt, "Failed to read version 2 data with an invalid domain (64 characters in a label)");
        OK_SXEL_ERROR(": 3: Invalid domain name");

        fn = create_data("test-domaintagging", "domaintagging 2\n" "count 1\n" "bad.categories:abcdefg\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        unlink(fn);
        ok(!dt, "Failed to read version 2 data with invalid categories");
        OK_SXEL_ERROR(": 3: Invalid categories");

        fn = create_data("test-domaintagging", "domaintagging 2\n" "count 1\n" "bad.categories:abcdef:\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        unlink(fn);
        ok(!dt, "Failed to read version 2 data with invalid categories");
        OK_SXEL_ERROR(": 3: Invalid categories");
    }

    diag("Test V2 data load with the right number of lines");
    {
        fn = create_data("test-domaintagging", "domaintagging 2\n" "count 2\n" "my.domain:1\n" "her.domain:2");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(dt, "Constructed struct domaintagging from V2 data");
        skip_if(!dt, 1, "Cannot test without a domaintagging object") {
            is(dt->version, 2, "The version number is correct");
            CONF_REFCOUNT_DEC(dt);
        }

        /* All this mucking about with MOCKFAIL_SET_FREQ() covers all the prefixtree allocation failure cases */

        MOCKFAIL_START_TESTS(6, prefixtree_put);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(!dt, "Can't construct a struct domaintagging object when prefixtree_put() fails");
        OK_SXEL_ERROR("Failed to realloc space for 1 prefixtree child");

        MOCKFAIL_SET_FREQ(2);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(!dt, "Can't construct a struct domaintagging object when the second prefixtree_put() fails");
        OK_SXEL_ERROR("Failed to realloc space for 1 prefixtree child");

        MOCKFAIL_SET_FREQ(3);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(!dt, "Can't construct a struct domaintagging object when the second prefixtree_put() fails");
        OK_SXEL_ERROR("Failed to realloc space for 2 prefixtree children");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(8, prefixtree_new);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(!dt, "Can't construct a struct domaintagging object when prefixtree allocation fails");
        OK_SXEL_ERROR("Couldn't allocate a new prefixtree");

        MOCKFAIL_SET_FREQ(2);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(!dt, "Can't construct a struct domaintagging object when the second prefixtree allocation fails");
        OK_SXEL_ERROR("Couldn't allocate a new prefixtree");

        MOCKFAIL_SET_FREQ(3);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(!dt, "Can't construct a struct domaintagging object when the third prefixtree allocation fails");
        OK_SXEL_ERROR("Couldn't allocate a new prefixtree");

        MOCKFAIL_SET_FREQ(4);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(!dt, "Can't construct a struct domaintagging object when the fourth prefixtree allocation fails");
        OK_SXEL_ERROR("Couldn't allocate a new prefixtree");
        MOCKFAIL_END_TESTS();

        unlink(fn);
    }

    diag("Test V2 domain vs subdomain behaviour");
    {
        pref_categories_t cat;

        fn = create_data("test-domaintagging", "domaintagging 2\n" "count 2\n" "my.domain:1\n" "sub.my.domain:2");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(dt, "Constructed struct domaintagging from V2 data");
        skip_if(!dt, 1, "Cannot test without a domaintagging object") {
            is(dt->version, 2, "The version number is correct");

            pref_categories_setnone(&cat);
            ok(domaintagging_match(dt, &cat, (const uint8_t *)"\2my\6domain", NULL, "test"), "Found a match for my.domain");
            is_eq(pref_categories_idstr(&cat), "1", "The categorization was correct (parent)");

            pref_categories_setnone(&cat);
            ok(domaintagging_match(dt, &cat, (const uint8_t *)"\3sub\2my\6domain", NULL, "test"), "Found a match for sub.my.domain");
            is_eq(pref_categories_idstr(&cat), "2", "The categorization was correct (child)");

            ok(domaintagging_match(dt, &cat, (const uint8_t *)"\4sub2\2my\6domain", NULL, "test"), "Found a match for sub2.my.domain");
            is_eq(pref_categories_idstr(&cat), "3", "The categorization was merged correctly (with parent)");

            CONF_REFCOUNT_DEC(dt);
        }

        unlink(fn);
    }

    diag("Test V2 data with compressed category bits");
    {
        uint8_t name[DNS_MAXLEN_NAME];
        pref_categories_t cat;

        fn = create_data("test-domaintagging",
                         "domaintagging 2\n"
                         "count 5\n"
                         "my.domain:1\n"
                         "her.domain:2\n"
                         "his.domain:4\n"
                         "your.domain:6\n"
                         "# Note, we can only compress up to 3 bits on 32bit machines\n"
                         "their.domain:800000000000020000000000000000000000000000000001\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(dt, "Constructed struct domaintagging from V2 data");
        skip_if(!dt, 1, "Cannot test without a domaintagging object") {
            is(dt->version, 2, "The version number is correct");
            ok(dt->value_pool == NULL, "No value-pool was allocated");

            pref_categories_setnone(&cat);
            dns_name_sscan("my.domain", "", name);
            ok(domaintagging_match(dt, &cat, name, NULL, "dt"), "Matched categories for %s", dns_name_to_str1(name));
            ok(pref_categories_getbit(&cat, 0), "Matched category bit 0");
            ok(!pref_categories_getbit(&cat, 1), "Didn't match category bit 1");
            ok(!pref_categories_getbit(&cat, 2), "Didn't match category bit 2");
            ok(!pref_categories_getbit(&cat, 3), "Didn't match category bit 3");

            pref_categories_setnone(&cat);
            dns_name_sscan("her.domain", "", name);
            ok(domaintagging_match(dt, &cat, name, NULL, "dt"), "Matched categories for %s", dns_name_to_str1(name));
            ok(!pref_categories_getbit(&cat, 0), "Didn't match category bit 0");
            ok(pref_categories_getbit(&cat, 1), "Matched category bit 1");
            ok(!pref_categories_getbit(&cat, 2), "Didn't match category bit 2");
            ok(!pref_categories_getbit(&cat, 3), "Didn't match category bit 3");

            pref_categories_setnone(&cat);
            dns_name_sscan("his.domain", "", name);
            ok(domaintagging_match(dt, &cat, name, NULL, "dt"), "Matched categories for %s", dns_name_to_str1(name));
            ok(!pref_categories_getbit(&cat, 0), "Didn't match category bit 0");
            ok(!pref_categories_getbit(&cat, 1), "Didn't match category bit 1");
            ok(pref_categories_getbit(&cat, 2), "Matched category bit 2");
            ok(!pref_categories_getbit(&cat, 3), "Didn't match category bit 3");

            pref_categories_setnone(&cat);
            dns_name_sscan("your.domain", "", name);
            ok(domaintagging_match(dt, &cat, name, NULL, "dt"), "Matched categories for %s", dns_name_to_str1(name));
            ok(!pref_categories_getbit(&cat, 0), "Didn't match category bit 0");
            ok(pref_categories_getbit(&cat, 1), "Matched category bit 1");
            ok(pref_categories_getbit(&cat, 2), "Matched category bit 2");
            ok(!pref_categories_getbit(&cat, 3), "Didn't match category bit 3");

            pref_categories_setnone(&cat);
            dns_name_sscan("their.domain", "", name);
            ok(domaintagging_match(dt, &cat, name, NULL, "dt"), "Matched categories for %s", dns_name_to_str1(name));
            ok(pref_categories_getbit(&cat, 0), "Matched category bit 0");
            ok(!pref_categories_getbit(&cat, 1), "Didn't match category bit 1");
            ok(!pref_categories_getbit(&cat, 136), "Didn't match category bit 136");
            ok(pref_categories_getbit(&cat, 137), "Matched category bit 137");
            ok(!pref_categories_getbit(&cat, 138), "Didn't match category bit 138");
            ok(!pref_categories_getbit(&cat, 190), "Didn't match category bit 190");
            ok(pref_categories_getbit(&cat, 191), "Matched category bit 191");

            CONF_REFCOUNT_DEC(dt);
        }
        unlink(fn);
    }

    diag("Test V2 data with uncompressed category bits");
    {
        uint8_t name[DNS_MAXLEN_NAME];
        pref_categories_t cat;

        fn = create_data("test-domaintagging",
                         "domaintagging 2\n"
                         "count 5\n"
                         "my.domain:1\n"
                         "her.domain:2\n"
                         "his.domain:4\n"
                         "your.domain:6\n"
                         "# Note, we can only compress up to 7 bits on 64bit machines\n"
                         "their.domain:900000000000020020000010000000000000000000300001\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dt = domaintagging_new(&cl);
        ok(dt, "Constructed struct domaintagging from V2 data");
        skip_if(!dt, 1, "Cannot test without a domaintagging object") {
            is(dt->version, 2, "The version number is correct");
            ok(dt->value_pool, "A value-pool was allocated");

            pref_categories_setnone(&cat);
            dns_name_sscan("their.domain", "", name);
            ok(domaintagging_match(dt, &cat, name, NULL, "dt"), "Matched categories for %s", dns_name_to_str1(name));
            ok(pref_categories_getbit(&cat, 0), "Matched category bit 0");
            ok(!pref_categories_getbit(&cat, 1), "Didn't match category bit 1");
            ok(!pref_categories_getbit(&cat, 19), "Didn't match category bit 19");
            ok(pref_categories_getbit(&cat, 20), "Matched category bit 20");
            ok(pref_categories_getbit(&cat, 21), "Matched category bit 21");
            ok(!pref_categories_getbit(&cat, 22), "Didn't match category bit 22");
            ok(!pref_categories_getbit(&cat, 99), "Didn't match category bit 99");
            ok(pref_categories_getbit(&cat, 100), "Matched category bit 100");
            ok(!pref_categories_getbit(&cat, 101), "Didn't match category bit 101");
            ok(!pref_categories_getbit(&cat, 124), "Didn't match category bit 124");
            ok(pref_categories_getbit(&cat, 125), "Matched category bit 125");
            ok(!pref_categories_getbit(&cat, 126), "Didn't match category bit 126");
            ok(!pref_categories_getbit(&cat, 136), "Didn't match category bit 136");
            ok(pref_categories_getbit(&cat, 137), "Matched category bit 137");
            ok(!pref_categories_getbit(&cat, 138), "Didn't match category bit 138");
            ok(!pref_categories_getbit(&cat, 187), "Didn't match category bit 187");
            ok(pref_categories_getbit(&cat, 188), "Matched category bit 188");
            ok(!pref_categories_getbit(&cat, 189), "Didn't match category bit 189");
            ok(!pref_categories_getbit(&cat, 190), "Didn't match category bit 190");
            ok(pref_categories_getbit(&cat, 191), "Matched category bit 191");

            CONF_REFCOUNT_DEC(dt);
        }
        unlink(fn);
    }

    conf_loader_fini(&cl);

    OK_SXEL_ERROR(NULL);
    test_uncapture_sxel();

    is(memory_allocations(), start_allocations, "All memory allocations were freed");

    return exit_status();
}
