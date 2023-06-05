#include <kit-alloc.h>
#include <mockfail.h>
#include <tap.h>

#include "cidrlist.h"
#include "conf-loader.h"
#include "devprefs-private.h"
#include "dns-name.h"
#include "object-hash.h"

#include "common-test.h"

#define LOADFLAGS_DEVPREFS  (LOADFLAGS_FP_ALLOW_OTHER_TYPES | LOADFLAGS_FP_ELEMENTTYPE_DOMAIN | LOADFLAGS_FP_ELEMENTTYPE_APPLICATION)
#define LOADFLAGS_JUST_CIDR (LOADFLAGS_FP_ALLOW_OTHER_TYPES | LOADFLAGS_FP_ELEMENTTYPE_CIDR)

int
main(void)
{
    pref_categories_t expected_categories;
    uint8_t domain[DNS_MAXLEN_NAME];
    struct prefidentity *ident;
    uint64_t start_allocations;
    const struct preforg *corg;
    const struct preforg *org;
    struct prefbundle *bundle;
    struct kit_deviceid dev;
    struct conf_info *info;
    struct preflist *list;
    struct conf_loader cl;
    struct devprefs *dp;
    const char *fn;
    unsigned i, z;
    pref_t pr;

    plan_tests(293);

    conf_initialize(".", ".", false, NULL);
    kit_memory_initialize(false);
    KIT_ALLOC_SET_LOG(1);    // Uncomment to enable leak detection
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */

    conf_loader_init(&cl);

    diag("Test integration with the conf subsystem");
    {
        devprefs_register(&CONF_DEVPREFS, "devprefs", "devprefs", true);
        ok(!devprefs_conf_get(NULL, CONF_DEVPREFS), "Failed to get devprefs from a NULL confset");
        conf_unregister(CONF_DEVPREFS);
    }

    diag("Test missing file load");
    {
        info = conf_info_new(NULL, "noname", "nopath", NULL, LOADFLAGS_NONE, NULL, 0);
        info->updates++;
        memset(info->digest, 0xa5, sizeof(info->digest));

        conf_loader_open(&cl, "/tmp/not-really-there", NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        ok(!dp, "Failed to read non-existent file");
        OK_SXEL_ERROR("not-really-there could not be opened: No such file or directory");
        OK_SXEL_ERROR(NULL);

        conf_loader_done(&cl, info);
        is(info->updates, 1, "conf_loader_done() didn't bump 'updates'");
        is(info->st.dev, 0, "Loading a non-existent file gives a clear stat");
        for (z = 0; z < sizeof(info->digest); z++)
            if (info->digest[z])
                break;
        is(z, sizeof(info->digest), "The digest of an empty file has %zu zeros", sizeof(info->digest));
        conf_info_free(info);
    }

    diag("Test garbage file");
    {
        fn = create_data("test-devprefs", "This is not the correct format\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read garbage file");
        OK_SXEL_ERROR(": 1: Invalid header; must contain 'devprefs'");
        OK_SXEL_ERROR(NULL);
    }

    diag("Test V%u data load - old unsupported version", DEVPREFS_VERSION - 1);
    {
        fn = create_data("test-devprefs", "devprefs %u\ncount 0\n", DEVPREFS_VERSION - 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read V%u data", DEVPREFS_VERSION - 1);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [");
    }

    diag("Test V%u data load - future version not yet supported", DEVPREFS_VERSION + 1);
    {
        fn = create_data("test-devprefs", "devprefs %u\ncount 0\n", DEVPREFS_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data", DEVPREFS_VERSION + 1);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [");
    }

    diag("Test V%u & V%u data load - doesn't contain V%u", DEVPREFS_VERSION - 1, DEVPREFS_VERSION + 1, DEVPREFS_VERSION);
    {
        fn = create_data("test-devprefs", "devprefs %u %u\ncount 0\n", DEVPREFS_VERSION - 1, DEVPREFS_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u & version %u data", DEVPREFS_VERSION - 1, DEVPREFS_VERSION + 1);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [");
    }

    diag("Test V%u data load with missing count", DEVPREFS_VERSION);
    {
        fn = create_data("test-devprefs", "devprefs %u\nnocount 0\n", DEVPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with missing count", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 2: Invalid count; must begin with 'count '");
    }

    diag("Test V%u data load with truncated/short V%u section", DEVPREFS_VERSION, DEVPREFS_VERSION - 1);
    {
        fn = create_data("test-devprefs", "devprefs %u %u\ncount 1\n[lists:1:%u]\n", DEVPREFS_VERSION - 1, DEVPREFS_VERSION,
                         DEVPREFS_VERSION - 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read truncated version %u data in a version %u file", DEVPREFS_VERSION - 1, DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 3: Unexpected EOF in skipped section - read 0 items, not 1");

        fn = create_data("test-devprefs", "devprefs %u %u\ncount 1\n[lists:1:%u]\n[lists:0:%u]\n", DEVPREFS_VERSION - 1,
                         DEVPREFS_VERSION, DEVPREFS_VERSION - 1, DEVPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read short version %u data in a version %u file", DEVPREFS_VERSION - 1, DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 4: Unexpected [lists:0:%u] header in skipped section - read 0 items, not 1", DEVPREFS_VERSION);
    }

    diag("Test V%u load with dodgy counts", DEVPREFS_VERSION);
    {
        struct {
            unsigned result;
            unsigned count[6];
            const char *err;
        } data[] = {
            { 1, { 0, 0, 0, 0, 0, 0 }, "" },
            { 0, { 1, 0, 0, 0, 0, 0 }, ": 7: Incorrect total count 1 - read 0 data lines" },
            { 0, { 0, 1, 0, 0, 0, 0 }, ": 4: Unexpected [settinggroup] header - read 0 [list] items, not 1" },
            { 0, { 0, 0, 1, 0, 0, 0 }, ": 5: Unexpected [bundles] header - read 0 [settinggroup] items, not 1" },
            { 0, { 0, 0, 0, 1, 0, 0 }, ": 6: Unexpected [orgs] header - read 0 [bundle] items, not 1" },
            { 0, { 0, 0, 0, 0, 1, 0 }, ": 7: Unexpected [identities] header - read 0 [org] items, not 1" },
            { 0, { 0, 0, 0, 0, 0, 1 }, ": 7: Unexpected EOF - read 0 [identities] items, not 1" },
        };

        for (i = 0; i < sizeof(data) / sizeof(*data); i++) {
            fn = create_data("test-devprefs",
                             "devprefs %u\ncount %u\n[lists:%u]\n[settinggroup:%u]\n[bundles:%u]\n[orgs:%u]\n[identities:%u]\n",
                             DEVPREFS_VERSION, data[i].count[0], data[i].count[1], data[i].count[2], data[i].count[3],
                             data[i].count[4], data[i].count[5]);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
            ok(!!dp == data[i].result, "%s struct devprefs from V%u data set %u", data[i].result ? "Constructed" : "Didn't construct", DEVPREFS_VERSION, i);
            if (strcmp(data[i].err, ""))
                OK_SXEL_ERROR(data[i].err);
            else
                OK_SXEL_ERROR(NULL);
            devprefs_refcount_dec(dp);
            unlink(fn);
        }
        conf_loader_done(&cl, NULL);
    }

    diag("Test V%u load with allocation failures", DEVPREFS_VERSION);
    {
        fn = create_data("test-devprefs", "devprefs %u\ncount 2\n"
                         "[lists:0]\n"
                         "[settinggroup:2]\n"
                         "0:1:1f:1:0:4\n"
                         "1:1:1f:2:0:8\n"
                         "[bundles:0]\n"
                         "[orgs:0]\n"
                         "[identities:0]\n", DEVPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        ok(dp, "Constructed struct devprefs from V%u data with settinggroup", DEVPREFS_VERSION);
        devprefs_refcount_dec(dp);

        MOCKFAIL_START_TESTS(2, prefbuilder_allocsettinggroup);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        ok(!dp, "Didn't construct struct devprefs from V%u data with settinggroup when settinggroup allocation fails", DEVPREFS_VERSION);
        OK_SXEL_ERROR("Failed to realloc prefbuilder settinggroup block to 2 elements");
        MOCKFAIL_END_TESTS();

        unlink(fn);
        conf_loader_done(&cl, NULL);
    }

    diag("Test V%u load with bad section headers", DEVPREFS_VERSION);
    {
        char overflow[100];
        struct {
            unsigned result;
            const char *header[5];
            const char *err;
        } data[] = {
            { 1, { "[lists:0]",  "[settinggroup:0]",  "[bundles:0]",  "[orgs:0]",  "[identities:0]"  }, "" },
            { 0, { "[lists:x0]", "[settinggroup:0]",  "[bundles:0]",  "[orgs:0]",  "[identities:0]"  }, ": 3: Invalid section header count" },
            { 0, { "[lists:0]",  "[settinggroup:x0]", "[bundles:0]",  "[orgs:0]",  "[identities:0]"  }, ": 4: Invalid section header count" },
            { 0, { "[lists:0]",  "[settinggroup:0]",  "[bundles:0x]", "[orgs:0]",  "[identities:0]"  }, ": 5: Invalid section header count" },
            { 0, { "[lists:0]",  "[settinggroup:0]",  "[bundles:0]",  "[orgsx:0]", "[identities:0]"  }, ": 6: Invalid section header 'orgsx'" },
            { 0, { "[lists:0]",  "[settinggroup:0]",  "[bundles:0]",  "[orgs:0]",  "[identities:0]x" }, ": 7: Unexpected [orgs] line - wanted only 0 items" },
            { 0, { "[lists:0]",  "[settinggroup:0]",  "[bundles:0]",  "[orgs:0]",  overflow          }, ": 7: Section header count overflow" },
        };

        snprintf(overflow, sizeof(overflow), "[identities:%lu]", (unsigned long)-1);

        for (i = 0; i < sizeof(data) / sizeof(*data); i++) {
            fn = create_data("test-devprefs",
                             "devprefs %u\ncount 0\n%s\n%s\n%s\n%s\n%s\n", DEVPREFS_VERSION,
                             data[i].header[0], data[i].header[1], data[i].header[2],
                             data[i].header[3], data[i].header[4]);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
            ok(!!dp == data[i].result, "%s struct devprefs from V%u data set %u", data[i].result ? "Constructed" : "Didn't construct", DEVPREFS_VERSION, i);
            if (strcmp(data[i].err, ""))
                OK_SXEL_ERROR(data[i].err);
            else
                OK_SXEL_ERROR(NULL);
            devprefs_refcount_dec(dp);
            unlink(fn);
        }
        conf_loader_done(&cl, NULL);
    }

    diag("Test V%u empty data load", DEVPREFS_VERSION);
    {
        fn = create_data("test-devprefs", "devprefs %u\ncount 0\n", DEVPREFS_VERSION);

        MOCKFAIL_START_TESTS(2, fileprefs_new);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        ok(!dp, "devprefs_new() of empty V%u data fails when fileprefs_new() fails", DEVPREFS_VERSION);
        OK_SXEL_ERROR("Cannot allocate");
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        conf_loader_done(&cl, NULL);
        unlink(fn);
        ok(dp, "Constructed struct devprefs from empty V%u data", DEVPREFS_VERSION);
        skip_if(!dp, 9, "Cannot run these tests without prefs") {
            is(PREFS_COUNT(dp, identities), 0, "V%u data has a key count of zero", DEVPREFS_VERSION);
            is(PREFS_COUNT(dp, orgs), 0, "V%u data has an org count of zero", DEVPREFS_VERSION);
            is(PREFS_COUNT(dp, bundles), 0, "V%u data has a bundle count of zero", DEVPREFS_VERSION);
            is(PREFS_COUNT(dp, settinggroups), 0, "V%u data has a settinggroup count of zero", DEVPREFS_VERSION);
            is(PREFS_COUNT(dp, lists), 0, "V%u data has a list count of zero", DEVPREFS_VERSION);
            is(dp->conf.refcount, 1, "V%u data has a refcount of 1", DEVPREFS_VERSION);
            devprefs_refcount_inc(dp);
            is(dp->conf.refcount, 2, "V%u data can bump its refcount", DEVPREFS_VERSION);
            devprefs_refcount_dec(dp);
            is(dp->conf.refcount, 1, "V%u data can drop its refcount", DEVPREFS_VERSION);
            devprefs_refcount_dec(dp);
        }
    }

    diag("Test V%u data load with extra lines", DEVPREFS_VERSION);
    {
        fn = create_data("test-devprefs", "devprefs %u\ncount 0\n%sextra-garbage\n", DEVPREFS_VERSION, "[lists:0]\n[bundles:0]\n[orgs:0]\n[identities:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with extra garbage", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 7: Unexpected [identities] line - wanted only 0 items");
    }

    diag("Test V%u data load with missing lines", DEVPREFS_VERSION);
    {
        const char *data = "[lists:0]\n" "[bundles:1]\n" "0:1:0:32:1400000000007491CD:::::::::::\n"
                           "[orgs:1]\n" "2748:0:0:365:0:1002748:0\n" "[identities:1]\n";
        const char *identity = "000000001BADC0DE:0:24:2748:0:1\n";

        fn = create_data("test-devprefs", "devprefs %u\ncount 3\n%s%s", DEVPREFS_VERSION, data, identity);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(dp, "Read version %u data ok", DEVPREFS_VERSION);
        devprefs_refcount_dec(dp);

        fn = create_data("test-devprefs", "devprefs %u\ncount 3\n%s", DEVPREFS_VERSION, data);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with missing lines", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 8: Unexpected EOF - read 0 [identities] items, not 1");
    }

    diag("Test V%u data load with invalid identities", DEVPREFS_VERSION);
    {
        const char *start = "[lists:5]\n"
                            "0:1:domain:71:01:black1\n"
                            "0:4:domain:70:02:fireeye1\n"
                            "4:2:domain::03:typo1\n"
                            "8:3:domain:72:04:white1\n"
                            "C:5:domain::05:urlproxy1\n"
                            "[bundles:1]\n"
                            "0:1:0:32:1400000000007491CD::1 4:2:3:5::::::\n"
                            "[orgs:1]\n"
                            "2748:0:0:365:0:1002748:0\n"
                            "[identities:1]\n";
        struct {
            unsigned ok : 1;
            unsigned strict : 1;
            const char *data;
            const char *err;
        } expect[] = {
            { 0, 0, "121AABBF9x:1234:24:2748:0:1\n", ": 14: Unrecognised line (invalid key format)" },
            { 0, 0, "121AABBF9:1234x:24:2748:0:1\n", ": 14: Unrecognised identity line" },
            { 0, 0, "121AABBF9:1234:24x:2748:0:1\n", ": 14: Unrecognised identity line" },
            { 0, 0, "121AABBF9:1234:24:2748x:0:1\n", ": 14: Unrecognised identity line" },
            { 0, 0, "121AABBF9:1234:24:2748:0y:1\n", ": 14: Unrecognised identity line" },    /* sscanf() scans "0x" as "%X" */
            { 0, 0, "121AABBF9:1234:24:2748:0:1x\n", ": 14: Unrecognised identity line (trailing junk)" },
            { 1, 0, "121AABBF9:1234:24:2749:0:1\n",  "" },
            { 0, 1, "121AABBF9:1234:24:2749:0:1\n",  ": 14: Cannot add identity; invalid bundleid or orgid" },
            { 1, 0, "121AABBF9:1234:24:2748:0:2\n",  "" },
            { 0, 1, "121AABBF9:1234:24:2748:0:2\n",  ": 14: Cannot add identity; invalid bundleid or orgid" },
            { 1, 0, "121AABBF9:1234:24:2748:0:1\n",  "" },
        };

        for (i = 0; i < sizeof(expect) / sizeof(*expect); i++) {
            fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s", DEVPREFS_VERSION, start, expect[i].data);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            fileprefs_set_strict(expect[i].strict);
            dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
            unlink(fn);
            ok(!!dp == expect[i].ok, "%s struct devprefs from V%u data set %u", expect[i].ok ? "Constructed" : "Didn't construct", DEVPREFS_VERSION, i);
            if (strcmp(expect[i].err, ""))
                OK_SXEL_ERROR(expect[i].err);
            else
                OK_SXEL_ERROR(NULL);
            devprefs_refcount_dec(dp);
        }
    }

    diag("Test V%u data load with invalid key order", DEVPREFS_VERSION);
    {
        fn = create_data("test-devprefs", "devprefs %u\n"
                                          "count 5\n"
                                          "[lists:1]\n"
                                          "0:1:domain:71:01:black1\n"
                                          "[bundles:1]\n"
                                          "0:1:0:32:1400000000007491CD:::::::::::\n"
                                          "[orgs:1]\n"
                                          "2748:0:0:365:0:1002748:0\n"
                                          "[identities:2]\n"
                                          "121AABBF9:0:24:2748:0:1\n"
                                          "54B33863:1:24:2748:0:1\n", DEVPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with invalid key order", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 11: Invalid line (out of order)");
    }

    diag("Test V%u data load with duplicate key", DEVPREFS_VERSION);
    {
        fn = create_data("test-devprefs", "devprefs %u\n"
                                          "count 5\n"
                                          "[lists:1]\n"
                                          "0:1:domain:71:01:black1\n"
                                          "[bundles:1]\n"
                                          "0:1:0:32:1400000000007491CD:::::::::::\n"
                                          "[orgs:1]\n"
                                          "2748:0:0:365:0:1002748:0\n"
                                          "[identities:2]\n"
                                          "54B33863:1:24:2748:0:1\n"
                                          "54B33863:1:24:2748:0:1\n", DEVPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with invalid key order", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 11: Invalid line (duplicate)");
    }

    diag("Test V%u data load with invalid list data", DEVPREFS_VERSION);
    {
        fn = create_data("test-devprefs", "devprefs %u\n"
                                          "count 10\n"
                                          "[lists:5]\n"
                                          "0:1:cidr:99:01:5.6.7.0/24\n"
                                          "0:120:cidr:70:02:1.2.3.4/32\n"
                                          "0:120:domain:70:02:some.domain\n"
                                          "8:1:cidr:70:03:9.10.11.12/32\n"
                                          "8:1:domain:70:03:white.domain\n"
                                          "[bundles:2]\n"
                                          "0:1:0:32:1400000000007491CD::1:::::::::\n"
                                          "0:2:0:32:1400000000007491CD::1 120:::::::::\n"
                                          "[orgs:1]\n"
                                          "2748:0:0:365:0:1002748:0\n"
                                          "[identities:2]\n"
                                          "54B33863:1:24:2748:0:2\n"
                                          "121AABBF9:0:24:2748:0:1\n", DEVPREFS_VERSION);

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        ok(dp, "Loaded version %u data with mixed elementtypes and usual loadflags (APPLICATION|DOMAIN)", DEVPREFS_VERSION);

        if (dp) {    // Cannot run these tests without prefs
            kit_deviceid_from_str(&dev, "0000000121AABBF9");
            ok(devprefs_get(&pr, dp, "devprefs", &dev, NULL), "Got prefs for dev 121AABBF9");
            ok(bundle = PREF_BUNDLE(&pr), "Got a prefbundle pointer from the pref_t");
            ok(bundle && bundle->id == 1, "Got prefbundle id 1");
            is_eq(pref_sorted_list(&pr, AT_BUNDLE | AT_LIST_DESTBLOCK), "", "sorted block list output is correct (empty)");
            is(PREF_DESTLISTID(&pr, AT_BUNDLE | AT_LIST_DESTBLOCK, 0), PREF_NOLIST, "No application or domain block lists");

            kit_deviceid_from_str(&dev, "0000000054B33863");
            ok(devprefs_get(&pr, dp, "devprefs", &dev, NULL), "Got prefs for dev 54B33863");
            ok(bundle = PREF_BUNDLE(&pr), "Got a prefbundle pointer from the pref_t");
            ok(bundle && bundle->id == 2, "Got prefbundle id 2");
            is_eq(pref_sorted_list(&pr, AT_BUNDLE | AT_LIST_DESTBLOCK), "some.domain", "sorted block list output is correct");
            is(PREF_DESTLISTID(&pr, AT_BUNDLE | AT_LIST_DESTBLOCK, 0), 0,   "Got the expected pref list id");
            ok(list = PREF_DESTLIST(&pr, AT_BUNDLE | AT_LIST_DESTBLOCK, 0), "Got the block list from the pref_t");
            dns_name_sscan("1.2.3.4/32", "", domain);
            ok(!domainlist_match(list ? list->lp.domainlist : NULL, domain, DOMAINLIST_MATCH_EXACT, NULL, NULL), "List doesn't match '1.2.3.4/32'");
            dns_name_sscan("some.domain", "", domain);
            ok( domainlist_match(list ? list->lp.domainlist : NULL, domain, DOMAINLIST_MATCH_EXACT, NULL, NULL), "List matches 'some.domain'");
            dns_name_sscan("white.domain", "", domain);
            ok(!domainlist_match(list ? list->lp.domainlist : NULL, domain, DOMAINLIST_MATCH_EXACT, NULL, NULL), "List doesn't match 'white.domain'");

            devprefs_refcount_dec(dp);
        }

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_JUST_CIDR);
        ok(dp, "Reloaded version %u data with mixed elementtypes and CIDR loadflags", DEVPREFS_VERSION);

        if (dp) {    // Cannot run these tests without prefs
            struct netaddr ipaddr;

            kit_deviceid_from_str(&dev, "0000000121AABBF9");
            ok(devprefs_get(&pr, dp, "devprefs", &dev, NULL), "Got prefs for dev 121AABBF9");
            ok(bundle = PREF_BUNDLE(&pr), "Got a prefbundle pointer from the pref_t");
            ok(bundle && bundle->id == 1, "Got prefbundle id 1");
            is_eq(pref_sorted_list(&pr, AT_BUNDLE | AT_LIST_DESTBLOCK), "5.6.7.0/24", "sorted block list output is correct");
            is(PREF_DESTLISTID(&pr, AT_BUNDLE|AT_LIST_DESTBLOCK, 0), 0, "Got the expected pref list id");
            ok(list = PREF_DESTLIST(&pr, AT_BUNDLE|AT_LIST_DESTBLOCK, 0), "Got a block list from the pref_t");
            netaddr_from_str(&ipaddr, "5.6.7.0", AF_INET);
            ok(cidrlist_search(list ? list->lp.cidrlist : NULL, &ipaddr, NULL, NULL),  "List matches '5.6.7.0/24'");
            netaddr_from_str(&ipaddr, "1.2.3.4", AF_INET);
            ok(!cidrlist_search(list ? list->lp.cidrlist : NULL, &ipaddr, NULL, NULL), "List doesn't match 'some.domain'");

            kit_deviceid_from_str(&dev, "0000000054B33863");
            ok(devprefs_get(&pr, dp, "devprefs", &dev, NULL), "Got prefs for dev 54B33863");
            ok(bundle = PREF_BUNDLE(&pr), "Got a prefbundle pointer from the pref_t");
            ok(bundle && bundle->id == 2, "Got prefbundle id 2");
            is_eq(pref_sorted_list(&pr, AT_BUNDLE | AT_LIST_DESTBLOCK), "1.2.3.4 5.6.7.0/24", "sorted block list output is correct");
            is(PREF_DESTLISTID(&pr, AT_BUNDLE|AT_LIST_DESTBLOCK, 0), 0,     "Got the expected pref list id");
            ok(list = PREF_DESTLIST(&pr, AT_BUNDLE | AT_LIST_DESTBLOCK, 1), "Got the second block list from the pref_t");
            netaddr_from_str(&ipaddr, "5.6.7.0", AF_INET);
            ok(!cidrlist_search(list ? list->lp.cidrlist : NULL, &ipaddr, NULL, NULL), "List doesn't match 5.6.7.0");
            netaddr_from_str(&ipaddr, "1.2.3.4", AF_INET);
            ok(cidrlist_search(list ? list->lp.cidrlist : NULL, &ipaddr, NULL, NULL),  "List matches 1.2.3.4");
            netaddr_from_str(&ipaddr, "9.10.11.12", AF_INET);
            ok(!cidrlist_search(list ? list->lp.cidrlist : NULL, &ipaddr, NULL, NULL), "List doesn't match 9.10.11.12");

            devprefs_refcount_dec(dp);
        }

        unlink(fn);

        diag("Attempt an empty list");
        {
            const char *start = "[lists:1]\n0:1:domain:70:01:";
            const char *end = "\n[bundles:1]\n"
                              "0:1:0:32:1400000000007491CD::1:::::::::\n"
                              "[orgs:1]\n"
                              "2748:0:0:365:0:1002748:0\n"
                              "[identities:1]\n"
                              "121AABBF9:0:24:2748:0:1\n";
            fn = create_data("test-devprefs", "devprefs %u\ncount 4\n%s%s%s", DEVPREFS_VERSION, start, "", end);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            ok(!devprefs_new(&cl, LOADFLAGS_DEVPREFS), "Cannot load devprefs version %u with an empty list", DEVPREFS_VERSION);
            OK_SXEL_ERROR("Cannot load a domainlist with no names");
            OK_SXEL_ERROR(": 4: Unrecognised list line (parsing domainlist failed)");
            unlink(fn);

            fn = create_data("test-devprefs", "devprefs %u\ncount 4\n%s%s%s", DEVPREFS_VERSION, start, "valid-list", end);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            ok(dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS), "Loaded the same version %u data with a list", DEVPREFS_VERSION);
            OK_SXEL_ERROR(NULL);
            devprefs_refcount_dec(dp);
            unlink(fn);
        }

        pref_sorted_list(NULL, AT_BUNDLE);
    }

    diag("Test V%u data load with wrong sort order", DEVPREFS_VERSION);
    {
        fn = create_data("test-devprefs", "devprefs %u\n"
                                          "count 15\n"
                                          "[lists:10]\n"
                                          "0:1:domain:71:01:black1\n"
                                          "4:2:domain::02:typo1\n"
                                          "8:3:domain:72:03:white1\n"
                                          "0:4:domain:70:04:fireeye1\n"
                                          "C:5:domain::05:urlproxy1\n"
                                          "8:9:domain:72:06:white1 white2\n"
                                          "0:10:domain:71:07:black2\n"
                                          "4:12:domain::08:typo2\n"
                                          "0:1000:domain:71:09:fireeye2\n"
                                          "C:1000000:domain::10:urlproxy1 urlproxy2\n"
                                          "[bundles:2]\n"
                                          "0:1:0:32:1400000000007491CD::1 4:2:3:5::::::\n"
                                          "0:2:1:32:1400000000002241AC::1 4 10 1000:2 12:9:1000000::::::\n"
                                          "[orgs:1]\n"
                                          "2748:0:0:365:0:1002748:0\n"
                                          "[identities:2]\n"
                                          "121AABBF9:0:24:2748:0:1\n"
                                          "54B33863:1:24:2748:0:2\n", DEVPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with invalid sort order", DEVPREFS_VERSION);
        OK_SXEL_ERROR("Unsorted list insertions are not permitted");
        OK_SXEL_ERROR(": 7: Cannot create preflist 00:4:domain");
    }

    diag("Test V%u data load with an invalid org parts", DEVPREFS_VERSION);
    {
        const char *pre = "[lists:5]\n"
                          "0:1:domain:71:01:black1\n"
                          "0:4:domain:70:02:fireeye1\n"
                          "4:2:domain::03:typo1\n"
                          "8:3:domain:72:04:white1\n"
                          "C:5:domain::05:urlproxy1\n"
                          "[bundles:1]\n"
                          "0:1:0:32:0::1 4:2:3:5::::::\n"
                          "[orgs:1]\n";
        const char *mid = "\n"
                          "[identities:1]\n"
                          "121AABBF9:0:";
        const char *end = ":0:1\n";

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:365:0:1002748:0", mid, "24:2748", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(dp, "Read version %u data with correct org stuff", DEVPREFS_VERSION);
        devprefs_refcount_dec(dp);

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "wtf:0:0:365:0:1002748:0", mid, "24:2748", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with invalid orgid", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 12: Unrecognised org line (invalid orgid)");

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:365:0:1002748:0", mid, "24:4294967296", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with invalid ident orgid", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 14: Unrecognised identity line (overflow in originid:origintypeid:orgid:actype:bundleid)");

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:365:0:1002748:0", mid, "24:1234", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        fileprefs_set_strict(1);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with wrong ident orgid", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 14: Cannot add identity; invalid bundleid or orgid");

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:365:0:1002748:666", mid, "24:2748", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(dp, "Read version %u data with correct org stuff including a parentid", DEVPREFS_VERSION);
        devprefs_refcount_dec(dp);

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:365:0:1002748:", mid, "24:2748", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with a missing parentid", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 12: Unrecognised org line (invalid parentid)");

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:365x:0:1002748:666", mid, "24:2748", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with junk following the retention period", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 12: Unrecognised org line (invalid retention)");

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:365:10x:1002748:666", mid, "24:2748", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with junk following the warn period", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 12: Unrecognised org line (invalid warn period)");

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:365:0:1002748x:666", mid, "24:2748", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with junk following the originid", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 12: Unrecognised org line (invalid originid)");

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:365:0:1002748:666x", mid, "24:2748", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with junk following the parentid", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 12: Unrecognised org line (invalid parentid)");

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:365:0:1002748:666", mid, "24x:2748", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with junk following the origin-type-id", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 14: Unrecognised identity line");

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:40000000000:0:1002748:666", mid, "24:2748", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with an overflowing retention period", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 12: Unrecognised org line (invalid retention)");

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:365:40000000000:1002748:666", mid, "24:2748", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with an overflowing warn period", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 12: Unrecognised org line (invalid warn period)");

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:365:0:40000000000:666", mid, "24:2748", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with an overflowing originid", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 12: Unrecognised org line (invalid originid)");

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:365:0:1002748:40000000000", mid, "24:2748", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with an overflowing parentid", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 12: Unrecognised org line (invalid parentid)");

        fn = create_data("test-devprefs", "devprefs %u\n" "count 8\n" "%s%s%s%s%s", DEVPREFS_VERSION, pre, "2748:0:0:365:0:1002748:666", mid, "40000000000:2748", end);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with an overflowing origin-type-id", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 14: Unrecognised identity line (overflow in originid:origintypeid:orgid:actype:bundleid)");
    }

    diag("Test V%u data load with an invalid flags field", DEVPREFS_VERSION);
    {
        fn = create_data("test-devprefs", "devprefs %u\n"
                                          "count 8\n"
                                          "[lists:5]\n"
                                          "0:1:domain:71:01:black1\n"
                                          "0:4:domain:70:02:fireeye1\n"
                                          "4:2:domain::03:typo1\n"
                                          "8:3:domain:72:04:white1\n"
                                          "C:5:domain::05:urlproxy1\n"
                                          "[bundles:1]\n"
                                          "0:1:0:1ffffffff:0::1 4:2:3:5::::::\n"
                                          "[orgs:1]\n"
                                          "2748:0:0:365:0:1002748:0\n"
                                          "[identities:1]\n"
                                          "121AABBF9:0:24:2748:0:1\n", DEVPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with invalid flags", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 10: Unrecognised bundle line (overflow in actype:bundleid:priority:flags:)");

        fn = create_data("test-devprefs", "devprefs %u\n"
                                          "count 8\n"
                                          "[lists:5]\n"
                                          "0:1:domain:71:01:black1\n"
                                          "0:4:domain:70:02:fireeye1\n"
                                          "4:2:domain::03:typo1\n"
                                          "8:3:domain:72:04:white1\n"
                                          "C:5:domain::05:urlproxy1\n"
                                          "[bundles:1]\n"
                                          "0:1:0:32:0::1 4:2:3:5::::::\n"
                                          "[orgs:1]\n"
                                          "4294967296:ffffffffffffffff:0:365:0:1002748:0\n"
                                          "[identities:1]\n"
                                          "121AABBF9:0:24:4294967296:0:1\n", DEVPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with invalid orgid", DEVPREFS_VERSION);

        OK_SXEL_ERROR(": 14: Unrecognised identity line (overflow in originid:origintypeid:orgid:actype:bundleid)");

        fn = create_data("test-devprefs", "devprefs %u\n"
                                          "count 8\n"
                                          "[lists:5]\n"
                                          "0:1:domain:71:01:black1\n"
                                          "0:4:domain:70:02:fireeye1\n"
                                          "4:2:domain::03:typo1\n"
                                          "8:3:domain:72:04:white1\n"
                                          "C:5:domain::05:urlproxy1\n"
                                          "[bundles:1]\n"
                                          "0:1:0:32:0::1 4:2:3:5::::::\n"
                                          "[orgs:1]\n"
                                          "2748:1ffffffffffffffff:0:365:0:1002748:0\n"
                                          "[identities:1]\n"
                                          "121AABBF9:0:24:2748:0:1\n", DEVPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with invalid org flags", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 12: Unrecognised org line (invalid orgflags - overflow)");
    }

    diag("Test V%u data load with an invalid categories field", DEVPREFS_VERSION);
    {
        char max_categories[PREF_CATEGORIES_IDSTR_MAX_LEN + 1];

        for (i = 0; i < PREF_CATEGORIES_IDSTR_MAX_LEN; i++)
            max_categories[i] = 'f';

        max_categories[PREF_CATEGORIES_IDSTR_MAX_LEN] = '\0';

        fn = create_data("test-devprefs", "devprefs %u\n"
                                          "count 8\n"
                                          "[lists:5]\n"
                                          "0:1:domain:71:01:black1\n"
                                          "0:4:domain:70:02:fireeye1\n"
                                          "4:2:domain::03:typo1\n"
                                          "8:3:domain:72:04:white1\n"
                                          "C:5:domain::05:urlproxy1\n"
                                          "[bundles:1]\n"
                                          "0:1:0:32:%s::1 4:2:3:5::::::\n"
                                          "[orgs:1]\n"
                                          "2748:0:0:365:0:1002748:0\n"
                                          "[identities:1]\n"
                                          "121AABBF9:0:24:2748:0:1\n", DEVPREFS_VERSION, max_categories);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(dp, "Read version %u data with maximum category bit set", DEVPREFS_VERSION);
        devprefs_refcount_dec(dp);

        fn = create_data("test-devprefs", "devprefs %u\n"
                                          "count 8\n"
                                          "[lists:5]\n"
                                          "0:1:domain:71:01:black1\n"
                                          "0:4:domain:70:02:fireeye1\n"
                                          "4:2:domain::03:typo1\n"
                                          "8:3:domain:72:04:white1\n"
                                          "C:5:domain::05:urlproxy1\n"
                                          "[bundles:1]\n"
                                          "0:1:0:32:1%s::1 4:2:3:5::::::\n"    /* Note the leading 1, pushing the max categories over the edge */
                                          "[orgs:1]\n"
                                          "2748:0:0:365:0:1002748:0\n"
                                          "[identities:1]\n"
                                          "121AABBF9:0:24:2748:0:1\n", DEVPREFS_VERSION, max_categories);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with invalid categories", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 10: Unrecognised bundle line (invalid categories)");

        fn = create_data("test-devprefs", "devprefs %u\n"
                                          "count 8\n"
                                          "[lists:5]\n"
                                          "0:1:domain:71:01:black1\n"
                                          "0:4:domain:70:02:fireeye1\n"
                                          "4:2:domain::03:typo1\n"
                                          "8:3:domain:72:04:white1\n"
                                          "C:5:domain::05:urlproxy1\n"
                                          "[bundles:1]\n"
                                          "0:1:0:32:0::1 4:2:3:5::::::\n"
                                          "[orgs:1]\n"
                                          "2748:0:%s:365:0:1002748:0\n"
                                          "[identities:1]\n"
                                          "121AABBF9:0:24:2748:0:1\n", DEVPREFS_VERSION, max_categories);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(dp, "Read version %u data with maximum unmasked category bit set", DEVPREFS_VERSION);
        devprefs_refcount_dec(dp);

        fn = create_data("test-devprefs", "devprefs %u\n"
                                          "count 8\n"
                                          "[lists:5]\n"
                                          "0:1:domain:71:01:black1\n"
                                          "0:4:domain:70:02:fireeye1\n"
                                          "4:2:domain::03:typo1\n"
                                          "8:3:domain:72:04:white1\n"
                                          "C:5:domain::05:urlproxy1\n"
                                          "[bundles:1]\n"
                                          "0:1:0:32:0::1 4:2:3:5::::::\n"
                                          "[orgs:1]\n"
                                          "2748:0:1%s:365:0:1002748:0\n"    /* Note the leading 1, pushing the max categories over the edge */
                                          "[identities:1]\n"
                                          "121AABBF9:0:24:2748:0:1\n", DEVPREFS_VERSION, max_categories);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with invalid unmasked categories", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 12: Unrecognised org line (invalid unmasked categories)");
    }

    diag("Test V%u data load with invalid domainlist fields", DEVPREFS_VERSION);
    {
        const char *precontent = "[lists:9]\n"
                                 "0:1:domain:71:01:black1\n"
                                 "0:4:domain:70:02:fireeye1\n"
                                 "4:2:domain::03:typo1\n"
                                 "8:3:domain:72:04:white1\n"
                                 "C:5:domain::05:urlproxy1 urlproxy2\n"
                                 "10:6:domain::06:urlproxy2\n"
                                 "14:1:application:151:07:1\n"
                                 "18:3:application:152:07:1\n"
                                 "1c:6:application::08:2 3 4 5\n"
                                 "[bundles:1]\n"
                                 "0:1:0:32:140000000000000000::1 4:2:3:5:6:1:3:6:1:3";
        const char *postcontent = "\n"
                                  "[orgs:1]\n"
                                  "2748:0:0:365:0:1002748:0\n"
                                  "[identities:1]\n"
                                  "121AABBF9:2245036:24:2748:0:1\n";
        const char *withcolon = ":";
        const char *withoutcolon = "";

        fn = create_data("test-devprefs", "devprefs %u\ncount 12\n%s%s%s", DEVPREFS_VERSION, precontent, withoutcolon, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(dp, "Loaded version %u data with valid preflist data", DEVPREFS_VERSION);
        devprefs_refcount_dec(dp);

        fn = create_data("test-devprefs", "devprefs %u\ncount 12\n%s%s%s", DEVPREFS_VERSION, precontent, withcolon, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with invalid preflist", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 14: Unrecognised bundle line (invalid warn app list '3')");
    }

    diag("Test V%u data load with an invalid list reference", DEVPREFS_VERSION);
    {
        const char *precontent = "[lists:4]\n"
                                 "0:1:domain:71:01:black1\n"
                                 "0:4:domain:70:02:fireeye1\n"
                                 "4:2:domain::03:typo1\n"
                                 "8:3:domain:72:04:white1\n"
                                 "[bundles:1]\n"
                                 "0:1:0:32:140000000000000000::1 4:";
        const char *postcontent = ":3:::::::\n"
                                  "[orgs:1]\n"
                                  "2748:0:0:365:0:1002748:1234\n"
                                  "[identities:1]\n"
                                  "121AABBF9:2245036:24:2748:0:1\n";
        const char *goodlists = "2";
        const char *badlists = "2 42";

        fn = create_data("test-devprefs", "devprefs %u\ncount 7\n%s%s%s", DEVPREFS_VERSION, precontent, goodlists, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(dp, "Loaded version %u data with valid except list references", DEVPREFS_VERSION);
        devprefs_refcount_dec(dp);

        fn = create_data("test-devprefs", "devprefs %u\ncount 7\n%s%s%s", DEVPREFS_VERSION, precontent, badlists, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with invalid except list references", DEVPREFS_VERSION);
        OK_SXEL_ERROR("prefbuilder_attach: Except list 04:42:* doesn't exist");
        OK_SXEL_ERROR(": 9: Cannot attach bundle 0:1 to list 04:42 (list pos 1)");
    }

    diag("Test V%u data load with invalid categories/settinggroups", DEVPREFS_VERSION);
    {
        const char *precat = "[lists:4]\n"
                             "0:1:domain:71:01:black1\n"
                             "0:4:domain:70:02:fireeye1\n"
                             "4:2:domain::03:typo1\n"
                             "8:3:domain:72:04:white1\n";
        const char *midcat = "[bundles:1]\n"
                             "0:1:0:32:";
        const char *postcat = ":1 4:2:3:::::::\n"
                             "[orgs:1]\n"
                             "2748:0:0:365:0:1002748:1234\n"
                             "[identities:1]\n"
                             "121AABBF9:2245036:24:2748:0:1\n";

        fn = create_data("test-devprefs", "devprefs %u\ncount 8\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                 "[settinggroup:1]\n4:1:0:1:f:a\n", midcat, "140000000000000000:", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(dp, "Loaded V%u data with valid settinggroup", DEVPREFS_VERSION);
        devprefs_refcount_dec(dp);

        fn = create_data("test-devprefs", "devprefs %u\ncount 8\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                 "[settinggroup:1]\n5:1:0:1:f:a\n", midcat, "140000000000000000:", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Can't load V%u data with an out-of-range settinggroup idx (only 0-4 are valid)", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 9: Unrecognised settinggroup line (invalid idx)");

        fn = create_data("test-devprefs", "devprefs %u\ncount 8\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                 "[settinggroup:1]\n3:1:badx:1:f:a\n", midcat, "140000000000000000:", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Can't load V%u data with invalid settinggroup flags (must be 32 bit hex)", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 9: Unrecognised settinggroup line (invalid flags)");

        fn = create_data("test-devprefs", "devprefs %u\ncount 8\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                 "[settinggroup:1]\n0:1x:0:1:f:a\n", midcat, "140000000000000000:", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Can't load V%u data with an invalid settinggroup id", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 9: Unrecognised settinggroup line (invalid id)");

        fn = create_data("test-devprefs", "devprefs %u\ncount 8\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                 "[settinggroup:1]\n0:1:0:x1:f:a\n", midcat, "140000000000000000:", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Can't load V%u data with invalid blocked-category bits", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 9: Unrecognised settinggroup line (invalid blocked-categories)");

        fn = create_data("test-devprefs", "devprefs %u\ncount 8\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                 "[settinggroup:1]\n0:1:0:1:xf:a\n", midcat, "140000000000000000:", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Can't load V%u data with invalid nodecrypt-category bits", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 9: Unrecognised settinggroup line (invalid nodecrypt-categories)");

        fn = create_data("test-devprefs", "devprefs %u\ncount 8\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                         "[settinggroup:1]\n0:1:0:1:f:xa\n", midcat, "140000000000000000:", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Can't load V%u data with invalid nodecrypt-category bits", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 9: Unrecognised settinggroup line (invalid warn-categories)");

        fn = create_data("test-devprefs", "devprefs %u\ncount 9\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                 "[settinggroup:2]\n0:1:0:1:f:a\n0:1:0:1:f:a\n", midcat, "140000000000000000:", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Can't load V%u data with duplicate settinggroup lines", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 10: Cannot create settinggroup 0:1");

        fn = create_data("test-devprefs", "devprefs %u\ncount 9\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                 "[settinggroup:2]\n0:2:0:1:f:a\n0:1:0:1:f:a\n", midcat, "140000000000000000:", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Can't load V%u data with out-of-order settinggroup lines", DEVPREFS_VERSION);
        OK_SXEL_ERROR("Unsorted list insertions are not permitted");
        OK_SXEL_ERROR(": 10: Cannot create settinggroup 0:1");

        fn = create_data("test-devprefs", "devprefs %u\ncount 8\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                 "[settinggroup:1]\n0:1:0:1:f:a\n", midcat, "140000000000000000:1 2", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(dp, "Loaded V%u data with valid settinggroups and external refs", DEVPREFS_VERSION);
        devprefs_refcount_dec(dp);

        fn = create_data("test-devprefs", "devprefs %u\ncount 8\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                 "[settinggroup:1]\n0:1:0:1:f:a\n", midcat, "140000000000000000:x1 2", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Cannot load V%u data with an invalid external settinggroup ref", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 11: Unrecognised bundle line (invalid settinggroup-ids terminator)");

        fn = create_data("test-devprefs", "devprefs %u\ncount 8\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                 "[settinggroup:1]\n0:1:0:1:f:a\n", midcat, "140000000000000000:1x 2", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Cannot load V%u data with trailing garbage after the external settinggroup ref", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 11: Unrecognised bundle line (invalid settinggroup id)");

        fn = create_data("test-devprefs", "devprefs %u\ncount 8\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                 "[settinggroup:1]\n0:1:0:1:f:a\n", midcat, "140000000000000000:1 x2", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Cannot load V%u data with an invalid external settinggroup ref", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 11: Unrecognised bundle line (invalid settinggroup-ids terminator)");

        fn = create_data("test-devprefs", "devprefs %u\ncount 8\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                 "[settinggroup:1]\n0:1:0:1:f:a\n", midcat, "140000000000000000:1 2", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(dp, "Loaded V%u data with a valid external settinggroup ref", DEVPREFS_VERSION);
        devprefs_refcount_dec(dp);

        fn = create_data("test-devprefs", "devprefs %u\ncount 8\n%s%s%s%s%s", DEVPREFS_VERSION, precat,
                 "[settinggroup:1]\n0:1:0:1:f:a\n", midcat, "140000000000000000:1 2x", postcat);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Cannot load V%u data with trailing garbage after the external settinggroup ref", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 11: Unrecognised bundle line (invalid settinggroup id)");
    }

    diag("Test V%u data load with a domain list with an invalid checksum", DEVPREFS_VERSION);
    {
        const char *precontent = "[lists:2]\n"
                                 "0:1:domain:71:";
        const char *midcontent = ":mylookup1\n"
                                 "0:2:domain:71:";
        const char *postcontent = ":mylookup2\n"
                                  "[bundles:0]\n"
                                  "[orgs:0]\n"
                                  "[identities:0]\n";
        const char *longsum =    "A123456789012345678901234567890123456789";
        const char *half_assed = "A12345678901234567890123456789012345678";
        const char *shortsum =   "A1234567890123456789012345678901234567";
        const char *longsum_invalid3rdchar = "A1X3456789012345678901234567890123456789";
        const char *longsum_invalid4thchar = "A12X456789012345678901234567890123456789";

        fileprefs_freehashes();    // With strict elementtypes, hash sizes aren't allowed to change without this call

        fn = create_data("test-devprefs", "devprefs %u\ncount 2\n%s%s%s%s%s", DEVPREFS_VERSION, precontent, longsum, midcontent, longsum, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(dp, "Loaded version %u data with domainlists with the same length long fingerprint", DEVPREFS_VERSION);
        devprefs_refcount_dec(dp);

        fn = create_data("test-devprefs", "devprefs %u\ncount 2\n%s%s%s%s%s", DEVPREFS_VERSION, precontent, half_assed, midcontent, half_assed, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with a domain list with a fingerprint with an odd number of characters", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 4: List type 00 name domain must have a fingerprint (even number of hex digits)");

        fn = create_data("test-devprefs", "devprefs %u\ncount 2\n%s%s%s%s%s", DEVPREFS_VERSION, precontent, longsum, midcontent, shortsum, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with domain lists with different length fingerprint", DEVPREFS_VERSION);
        OK_SXEL_ERROR("Invalid domainlist fingerprint; hex length should be 40, not 38");
        OK_SXEL_ERROR(": 5: Unrecognised list line (parsing domainlist failed)");

        fn = create_data("test-devprefs", "devprefs %u\ncount 2\n%s%s%s%s%s", DEVPREFS_VERSION, precontent, longsum, midcontent, longsum_invalid3rdchar, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with a domain list with an invalid fingerprint (on an even boundary)", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 5: List type 00 name domain must have a fingerprint (even number of hex digits)");

        fn = create_data("test-devprefs", "devprefs %u\ncount 2\n%s%s%s%s%s", DEVPREFS_VERSION, precontent, longsum, midcontent, longsum_invalid4thchar, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with a domain list with an invalid fingerprint (on an odd boundary)", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 5: List type 00 name domain must have a fingerprint (even number of hex digits)");

        fileprefs_freehashes();    /* We can now allocate a hash for shortsums */

        MOCKFAIL_START_TESTS(3, object_hash_new);
        fn = create_data("test-devprefs", "devprefs %u\ncount 2\n%s%s%s%s%s", DEVPREFS_VERSION, precontent, longsum, midcontent, longsum, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(dp, "Loaded version %u data with domain lists with short fingerprints - despite hash allocation failures", DEVPREFS_VERSION);
        devprefs_refcount_dec(dp);
        OK_SXEL_ERROR("Cannot allocate object-hash with 262144 rows and 33 locks");
        OK_SXEL_ERROR("Cannot allocate object-hash with 262144 rows and 33 locks");    /* We try at the start, and at the end! */
        /* Not calling fileprefs_freehashes() here is ok - the next call will successfully create a hash with shortsums */
        MOCKFAIL_END_TESTS();

        fn = create_data("test-devprefs", "devprefs %u\ncount 2\n%s%s%s%s%s", DEVPREFS_VERSION, precontent, shortsum, midcontent, shortsum, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(dp, "Loaded version %u data with domain lists with short fingerprints", DEVPREFS_VERSION);
        devprefs_refcount_dec(dp);
        OK_SXEL_ERROR(NULL);
    }

    fileprefs_freehashes();    // With strict elementtypes, hash sizes aren't allowed to change without this call

    diag("Test V%u data load with a domain list with a checksum that is not followed by a colon", DEVPREFS_VERSION);
    {
        fn = create_data("test-devprefs", "devprefs %u\n"
                                          "count 1\n"
                                          "[lists:1]\n"
                                          "0:1:domain:71:A123456789012345678901234567890123456789 mylookup1\n"    /* Space instead of a colon */
                                          "[bundles:0]\n"
                                          "[orgs:0]\n"
                                          "[identities:0]\n", DEVPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with a checksum that is not followed by a colon", DEVPREFS_VERSION);
        OK_SXEL_ERROR(": 4: List type 00 name domain must have a fingerprint (even number of hex digits)");
    }

    diag("Test V%u data handling", DEVPREFS_VERSION);
    {
        fn = create_data("test-devprefs", "devprefs %u %u\n"
                                          "count 40\n"
                                          "[some-weird-section:5:%u]\n"
                                          "This is five lines of junk\n"
                                          "It's not actually parsed\n"
                                          "but is read, counted and dropped\n"
                                          "so the count contributes towards the total\n"
                                          "line count at the top of the file\n"
                                          "[lists:20]\n"
                                          "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                                          "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                                          "1:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                                          "1:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                                          "2:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                                          "2:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                                          "2:10:domain:71:f5e94651f0f19eaa63e46e9b8d3a74d44710f0c5:black2\n"
                                          "2:1000:domain:70:b4227d7d29dd9ff2650ac5effb7a72738ff66fc3:fireeye2\n"
                                          "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                                          "5:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                                          "6:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                                          "6:12:domain::6d50e1da8e24e4df3e789f1676cb3a4a1b7139c0:typo2\n"
                                          "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                                          "9:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                                          "A:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                                          "A:9:domain:72:f850d50ba38302a7e9d7972612dd85cdc38865af:white1 white2\n"
                                          "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                                          "D:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                                          "E:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                                          "E:1000000:domain::429941e556c42b9e62d9cd607eaa408be95f47e1:urlproxy1 urlproxy2\n"
                                          "[bundles:5:%u %u]\n"
                                          "0:123:256:32:140000000000000000::1 4:2:3:5::::::\n"
                                          "0:423:153:32:40000000000000000::1 4:2:3:5::::::\n"
                                          "0:1456:7:32:1400007E00400014C3::1 4:2:3:5::::::\n"
                                          "1:200:149:32:140000000000000000::1 4:2:3:5::::::\n"
                                          "2:400:148:32:140000780000000000::1 4 10 1000:2 12:9:1000000::::::\n"
                                          "[orgs:3]\n"
                                          "2:100:0:364:10:1002:0\n"
                                          "2748:0:0:365:20:1002748:0\n"
                                          "122307:0:140000780000000000:366:30:100122307:9999\n"
                                          "[identities:7]\n"
                                          "54B33863:2245036:24:2748:0:123\n"
                                          "6FFC5461:2600167:24:2748:0:423\n"
                                          "121AABBF9:7639501:24:2748:0:123\n"
                                          "1CD734A11:8319777:24:2748:0:1456\n"
                                          "1FF3D28A1:6801453:24:2748:0:1456\n"
                                          "214B3F6E8:2967253:24:2:1:200\n"
                                          "27CA91DC2:2931715:9:122307:2:400\n",
                                          DEVPREFS_VERSION - 1, DEVPREFS_VERSION,  /* line 1 */
                                          DEVPREFS_VERSION - 1,                    /* bogus section */
                                          DEVPREFS_VERSION, DEVPREFS_VERSION - 1); /* bundles section */
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        ok(dp, "Constructed struct devprefs from V%u data", DEVPREFS_VERSION);

        skip_if(!dp, 20, "Cannot run these tests without prefs") {
            is(PREFS_COUNT(dp, identities), 7, "V%u data has a count of 7", DEVPREFS_VERSION);
            is(dp->conf.refcount, 1, "V%u data has a refcount of 1", DEVPREFS_VERSION);

            diag("    V%u lookup failure", DEVPREFS_VERSION);
            {
                kit_deviceid_from_str(&dev, "000000000000dead");
                devprefs_get(&pr, dp, "devprefs", &dev, NULL);
                ok(!PREF_VALID(&pr), "Failed to get prefs for dev 0xdead");
            }

            diag("    V%u lookup ok", DEVPREFS_VERSION);
            {
                ok(devprefs_get_prefblock(dp, 666), "Got prefblock");    // Orgid is ignored
                kit_deviceid_from_str(&dev, "000000027CA91DC2");
                ok(devprefs_get(&pr, dp, "devprefs", &dev, NULL), "Got prefs for dev 27CA91DC2");
                skip_if(!PREF_VALID(&pr), 13, "Cannot run these tests without prefs") {
                    bundle = PREF_BUNDLE(&pr);
                    org = PREF_ORG(&pr);
                    ident = PREF_IDENT(&pr);
                    is(bundle->bundleflags, 0x32, "Got the correct flags for dev 27CA91DC2");
                    is(ident->originid, 0x2cbc03, "Got the correct origin_id for dev 27CA91DC2");
                    is(ident->origintypeid, 9, "Got the correct origin-type-id for dev 27CA91DC2");
                    is(bundle->priority, 148, "Got the correct priority for dev 27CA91DC2");
                    pref_categories_sscan(&expected_categories, "140000780000000000");
                    ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                       "Unexpected categories %s for dev 27CA91DC2 (expected 140000780000000000)",
                       pref_categories_idstr(&bundle->base_blocked_categories));
                    ok(pref_domainlist_match(&pr, NULL, AT_LIST_DESTALLOW, (const uint8_t *)"\6white2", DOMAINLIST_MATCH_EXACT, NULL), "Found white2 in the white list");
                    ok(!pref_domainlist_match(&pr, NULL, AT_LIST_DESTALLOW, (const uint8_t *)"\3not\5there", DOMAINLIST_MATCH_EXACT, NULL), "Didn't find not.there in the white list");
                    ok(pref_domainlist_match(&pr, NULL, AT_LIST_DESTBLOCK, (const uint8_t *)"\10fireeye2", DOMAINLIST_MATCH_EXACT, NULL), "Found fireeye2 in the block list");
                    ok(pref_domainlist_match(&pr, NULL, AT_LIST_URL_PROXY_HTTPS, (const uint8_t *)"\11urlproxy2", DOMAINLIST_MATCH_EXACT, NULL), "Found urlproxy2 in the url-proxy-https list");

                    is(org ? org->id : 0, 122307, "Got orgid 122307 for dev 27CA91DC2");
                    is(org ? org->retention : 0, 366, "Got retention period 366 for dev 27CA91DC2");
                    is(org ? org->warnperiod : 0, 30, "Got warn period 30 for dev 27CA91DC2");
                    is(org ? org->originid : 0, 100122307, "Got org originid 100122407 for dev 27CA91DC2");
                    is(bundle->id, 400, "Got the correct bundleid for dev 27CA91DC2");
                }
            }

            diag("    V%u lookup policy no longer fails without an index", DEVPREFS_VERSION);
            {
                ok(devprefs_get_policy(dp, &pr, AT_BUNDLE, 2748, 1456),  "Found bundle 1456 without an index");
                ok(devprefs_get_policy(dp, &pr, AT_POLICY, 122307, 400), "Found policy 400 without an index");
            }

            diag("    V%u key_to_str returns identity key with leading 0s", DEVPREFS_VERSION);
            {
                is_eq((*dp->fp.ops->key_to_str)(&dp->fp, 0), "0000000054b33863", "Got the correct first key");
            }

            devprefs_refcount_dec(dp);
        }

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devprefs_new(&cl, LOADFLAGS_DEVPREFS);
        unlink(fn);
        ok(dp, "Constructed struct devprefs from V%u data, this time with policy and org indices", DEVPREFS_VERSION);

        if (dp) {    // Cannot run these tests without prefs
            is(PREFS_COUNT(dp, identities), 7, "V%u data has a count of 7", DEVPREFS_VERSION);
            is(dp->conf.refcount, 1, "V%u data has a refcount of 1", DEVPREFS_VERSION);

            diag("    V%u lookup policy succeeds", DEVPREFS_VERSION);
            {
                ok(devprefs_get_policy(dp, &pr, AT_BUNDLE, 2748, 1456), "Found bundle 1456 with an index");

                ok(bundle = PREF_BUNDLE(&pr), "Got a prefbundle pointer from the policy_t");
                is(bundle->priority, 7, "bundle priority is 7");
                is(bundle->bundleflags, 0x32, "bundle flags are 0x32");
                is_eq(pref_categories_idstr(&bundle->base_blocked_categories), "1400007E00400014C3",
                      "bundle categories are '1400007E00400014C3'");

                for (i = 0; PREF_DESTLIST(&pr, AT_BUNDLE|AT_LIST_DESTBLOCK, i); i++)
                    ;
                is(i, 2, "Found 2 block lists for bundle 1456");
                skip_if(i != 2, 10, "Cannot verify list data - count is wrong") {
                    list = PREF_DESTLIST(&pr, AT_BUNDLE|AT_LIST_DESTBLOCK, 0);
                    is(list->id, 1, "First list is bundle block id 1");
                    is_eq(PREF_DESTLIST_NAME(&pr, AT_BUNDLE|AT_LIST_DESTBLOCK, 0), "domain", "First list is called 'domain'");
                    is(list->bit, 71, "First list is for category bit 71");
                    dns_name_sscan("black1", "", domain);
                    ok(domainlist_match(list->lp.domainlist, domain, DOMAINLIST_MATCH_EXACT, NULL, NULL), "First list blocks 'black1'");
                    dns_name_sscan("fireeye1", "", domain);
                    ok(!domainlist_match(list->lp.domainlist, domain, DOMAINLIST_MATCH_EXACT, NULL, NULL), "First list does not block 'fireeye1'");

                    list = PREF_DESTLIST(&pr, AT_BUNDLE|AT_LIST_DESTBLOCK, 1);
                    is(list->id, 4, "Second list is bundle block id 4");
                    is_eq(PREF_DESTLIST_NAME(&pr, AT_BUNDLE|AT_LIST_DESTBLOCK, 1), "domain", "Second list is called 'domain'");
                    is(list->bit, 70, "Second list is for category bit 70");
                    dns_name_sscan("black1", "", domain);
                    ok(!domainlist_match(list->lp.domainlist, domain, DOMAINLIST_MATCH_EXACT, NULL, NULL), "Second list does not block 'black1'");
                    dns_name_sscan("fireeye1", "", domain);
                    ok(domainlist_match(list->lp.domainlist, domain, DOMAINLIST_MATCH_EXACT, NULL, NULL), "Second list blocks 'fireeye1'");
                }

                ok(devprefs_get_policy(dp, &pr, AT_POLICY, 122307, 400), "Found policy 400 with an index");
                for (i = 0; PREF_DESTLIST(&pr, AT_POLICY|AT_LIST_DESTBLOCK, i); i++)
                    ;
                is(i, 4, "Found 4 block lists for policy 400");
                for (i = 0; PREF_DESTLIST(&pr, AT_POLICY|AT_LIST_EXCEPT, i); i++)
                    ;
                is(i, 2, "Found 2 except lists for policy 400");
                for (i = 0; PREF_DESTLIST(&pr, AT_POLICY|AT_LIST_DESTALLOW, i); i++)
                    ;
                is(i, 1, "Found 1 allow list for policy 400");

                skip_if(i != 1, 4, "Cannot verify list data - count is wrong") {
                    list = PREF_DESTLIST(&pr, AT_BUNDLE|AT_LIST_DESTALLOW, 0);
                    is(list->id, 9, "The list is bundle allow id 9");
                    is_eq(PREF_DESTLIST_NAME(&pr, AT_BUNDLE|AT_LIST_DESTALLOW, 0), "domain", "The allow list is called 'domain'");
                    is(list->bit, 72, "The list is for category bit 72");
                    dns_name_sscan("sub.white1", "", domain);
                    ok(domainlist_match(list->lp.domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, NULL), "The list contains 'sub.white1'");
                }
                for (i = 0; PREF_DESTLIST(&pr, AT_POLICY|AT_LIST_URL_PROXY_HTTPS, i); i++)
                    ;
                is(i, 1, "Found 1 url_proxy_https list for policy 400");
            }

            diag("    V%u lookup org succeeds", DEVPREFS_VERSION);
            {
                corg = devprefs_org(dp, 2);
                ok(corg, "Found org 2 with an index");
                skip_if(!corg, 3, "Cannot verify org data without an org") {
                    is(corg->orgflags, 0x100, "org 2 flags are correct");
                    ok(pref_categories_isnone(&corg->unmasked), "no org 2 unmasked bits are set");
                    is(corg->parentid, 0, "org 2 parentid is correct");
                }

                corg = devprefs_org(dp, 122307);
                ok(corg, "Found org 122307 with an index");
                skip_if(!corg, 3, "Cannot verify org data without an org") {
                    is(corg->orgflags, 0x0, "org 122307 flags are correct");
                    pref_categories_sscan(&expected_categories, "140000780000000000");
                    ok(pref_categories_equal(&corg->unmasked, &expected_categories),
                       "Unexpected categories %s for org 122307 (expected 140000780000000000)",
                       pref_categories_idstr(&corg->unmasked));
                    is(corg->parentid, 9999, "org 122307 parentid is correct");
                }
                ok(!devprefs_org(dp, 122308), "Didn't find org 122308");
            }
            devprefs_refcount_dec(dp);
        }
    }

    OK_SXEL_ERROR(NULL);
    test_uncapture_sxel();

    conf_loader_fini(&cl);
    fileprefs_freehashes();
    confset_unload();          // Finalize the conf subsystem
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
