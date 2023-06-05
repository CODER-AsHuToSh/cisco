#include <fcntl.h>
#include <kit-alloc.h>
#include <mockfail.h>

#include "cloudprefs-org.h"
#include "cloudprefs-private.h"
#include "kit-random.h"

#include "common-test.h"

int
main(void)
{
    char buf[4096], content[4096];
    const struct cloudprefs *cp;
    uint64_t start_allocations;
    uint32_t key, origin_id;
    struct oolist *oolist;
    struct netaddr addr;
    struct confset *set;
    struct fileprefs fp;
    struct prefblock pref_block;
    pref_t pref;
    int gen;

    static struct fileprefops cop = {
        .type               = "cloudprefs",
        .keysz              = sizeof(key),
        .key_to_str         = cloudprefs_org_key_to_str,
        .supported_versions = { CLOUDPREFS_VERSION, 0 }
    };

    /* Clean up after previous tests
     */
    unlink("test-cloudprefs-1");
    plan_tests(64);

#ifdef __FreeBSD__
    plan_skip_all("DPT-186 - Need to implement inotify as dtrace event");
    exit(0);
#endif

    kit_random_init(open("/dev/urandom", O_RDONLY));
    conf_initialize(".", ".", false, NULL);

    memset(&fp, '\0', sizeof(fp));
    fp.version                  = CLOUDPREFS_VERSION;
    fp.ops                      = &cop;
    fp.keys                     = &key;
    fp.values                   = &pref_block;
    pref_block.count.identities = 1;
    key                         = 2911559;
    oolist                      = NULL;
    is_eq(cloudprefs_org_key_to_str(&fp, 0), "2911559:", "Got the correct origin id");

    kit_memory_initialize(false);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    cloudprefs_register(&CONF_CLOUDPREFS, "cloudprefs", "test-cloudprefs-%u", true);

    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */

    diag("Test V%u data handling", CLOUDPREFS_VERSION);
    {
        snprintf(content, sizeof(content),
                 "cloudprefs %u\n"
                 "count 21\n"
                 "[lists:2:%u]\n"
                 "0:1175137:domain:71:59e259a74ffccfef01b1e6eeee30d1c8db34bf14:block.com\n"
                 "8:1175135:domain:72:296ecb3def058ee286310ebf3ec9087144a226b1:allow.com\n"
                 "[settinggroup:8:%u]\n"
                 "0:618867:0:80:0:0\n"
                 "1:550381:0:400000000030000000001FD000000000000000:0:0\n"
                 "2:507191:0:0:0:0\n"
                 "2:1060160:4000:0:0:0\n"
                 "2:1060210:4000:0:0:0\n"
                 "3:502311:0:0:0:0\n"
                 "3:1020280:180000:0:0:0\n"
                 "3:1020328:180000:0:0:0\n"
                 "[bundles:3:%u]\n"
                 "0:587671:4294967295:40:0:618867 550381 507191 502311:1175137::1175135:::::::\n"
                 "0:1104266:2:40:0:3 550381 1060160 1020280:1175137::1175135:::::::\n"
                 "0:1104312:0:40:0:7 550381 1060210 1020328:1175137::1175135:::::::\n"
                 "[orgs:1:%u]\n"
                 "2133813:67:FFFFFFFFFF000002000000000000000000000:730:0:61802099:0\n"
                 "[identities:7:%u]\n"
                 "2133813:61882711:61882711:48:2133813:0:1104312\n"
                 "2133813:63052149:63052149:48:2133813:0:1104266\n"
                 "2133813:125836178:125836178:48:2133813:0:587671\n"
                 "2133813:125836180:125836180:48:2133813:0:587671\n"
                 "2133813:125836184:125836184:48:2133813:0:1104312\n"
                 "2133813:125836186:125836186:48:2133813:0:587671\n"
                 "2133813:125836188:125836188:48:2133813:0:587671\n",
                 CLOUDPREFS_VERSION,
                 CLOUDPREFS_VERSION,
                 CLOUDPREFS_VERSION,
                 CLOUDPREFS_VERSION,
                 CLOUDPREFS_VERSION,
                 CLOUDPREFS_VERSION);

        create_atomic_file("test-cloudprefs-2133813", "%s", content);
        MOCKFAIL_START_TESTS(3, CLOUDPREFS_CLONE);
        ok(!confset_load(NULL), "Didn't see a change to test-cloudprefs-2133813 due to a malloc failure");
        OK_SXEL_ERROR("Couldn't allocate a cloudprefs structure");
        OK_SXEL_ERROR("Couldn't clone a cloudprefs conf object");
        MOCKFAIL_END_TESTS();

        ok(confset_load(NULL), "Noted an update to test-cloudprefs-2133813");
        create_atomic_file("test-cloudprefs-2133813", "we'll never even get to see this data");
        MOCKFAIL_START_TESTS(3, CLOUDPREFS_CLONE_ORGS);
        ok(!confset_load(NULL), "Didn't see a change to test-cloudprefs-2133813 due to a cloudprefs-origin slot allocation failure");

        OK_SXEL_ERROR("Couldn't allocate 10 new cloudprefs org slots");
        OK_SXEL_ERROR("Couldn't clone a cloudprefs conf object");
        MOCKFAIL_END_TESTS();
        unlink("test-cloudprefs-2133813");

        snprintf(content, sizeof(content), "cloudprefs %u\ncount 0\n%s", CLOUDPREFS_VERSION, "# Different\n");
        for (origin_id = 100; origin_id < 110; origin_id++) {
            snprintf(buf, sizeof(buf), "test-cloudprefs-%u", origin_id);
            create_atomic_file(buf, "%s", content);
        }
        ok(confset_load(NULL), "Loaded test-cloudprefs-100 - test-cloudprefs-109");

        MOCKFAIL_START_TESTS(11, CLOUDPREFS_MOREORGS);
        for (; origin_id < 120; origin_id++) {
            snprintf(buf, sizeof(buf), "test-cloudprefs-%u", origin_id);
            create_atomic_file(buf, "%s", content);
        }
        ok(!confset_load(NULL), "Didn't see a change to test-cloudprefs-110 - test-cloudprefs-119 due to a cloudprefs-origin slot re-allocation failure");
        for (int i = 0; i < 10; i++)
            OK_SXEL_ERROR("Couldn't reallocate 20 cloudprefs org slots");
        MOCKFAIL_END_TESTS();

        snprintf(content, sizeof(content), "cloudprefs %u\ncount 0\n", CLOUDPREFS_VERSION);
        for (origin_id = 100; origin_id < 120; origin_id++) {
            snprintf(buf, sizeof(buf), "test-cloudprefs-%u", origin_id);
            create_atomic_file(buf, "%s", content);
        }
        ok(confset_load(NULL), "Loaded test-cloudprefs-100 - test-cloudprefs-119");

        OK_SXEL_ERROR(NULL);

        /* cleanup */
        for (origin_id = 100; origin_id < 120; origin_id++) {
            snprintf(buf, sizeof(buf), "test-cloudprefs-%u", origin_id);
            unlink(buf);
            snprintf(buf, sizeof(buf), "test-cloudprefs-%u.last-good", origin_id);
            unlink(buf);
        }
    }

    diag("Test inserting cloudprefs org in existing conf, forcing rearrangements");
    {
        uint32_t orgid;

        for (orgid = 1000; orgid > 990; orgid--) {
            snprintf(buf, sizeof(buf), "test-cloudprefs-%u", orgid);
            snprintf(content, sizeof(content),
                     "cloudprefs %u\n"
                     "count 1\n"
                     "[orgs:1]\n"
                     "%u:0:0:365:0:1004:0\n",
                     CLOUDPREFS_VERSION, orgid);
            create_atomic_file(buf, "%s", content);

            /* Load the cloudprefs file individually so they'll be inserted in an existing array */
            ok(confset_load(NULL), "Loaded test-cloudprefs-%u", orgid);
        }
        OK_SXEL_ERROR(NULL);

        /* Cleanup prefs files */
        for (orgid = 1000; orgid > 990; orgid--) {
            snprintf(buf, sizeof(buf), "test-cloudprefs-%u", orgid);
            unlink(buf);
            snprintf(buf, sizeof(buf), "test-cloudprefs-%u.last-good", orgid);
            unlink(buf);
        }

        ok(confset_load(NULL), "Successfully loaded deletions");
    }

    diag("Error cases");
    {
        ok(!cloudprefs_get(&pref, NULL, "cloudprefs", 0, 0, &oolist, NULL), "Get on a NULL cloudprefs finds nothing");

        snprintf(content, sizeof(content),
                 "cloudprefs %u\n"
                 "count 5\n"
                 "[lists:1]\n"
                 "0:1175134:cidr:71:59e259a74ffccfef01b1e6eeee30d1c8db311111:5.6.7.0/24\n"
                 "[bundles:1]\n"
                 "0:587671:4294967295:40:0::1175134:::::::::\n"
                 "[orgs:1]\n"
                 "2133813:0:0:365:0:1004:0\n"
                 "[identities:2]\n"
                 "2133813:1234:1234:48:2133813:0:587671\n"
                 "2133813:1234:1234:48:2133813:0:587671\n",
                 CLOUDPREFS_VERSION);
        create_atomic_file("test-cloudprefs-2133813", "%s", content);
        ok(confset_load(NULL), "Failed to load test-cloudprefs");
        OK_SXEL_ERROR(": 11: Invalid line (duplicate)");

        snprintf(content, sizeof(content),
                 "cloudprefs %u\n"
                 "count 4\n"
                 "[lists:1]\n"
                 "0:1175134:cidr:71:59e259a74ffccfef01b1e6eeee30d1c8db311111:5.6.7.0/24\n"
                 "[bundles:1]\n"
                 "0:587671:4294967295:40:0::1175134:::::::::\n"
                 "[orgs:1]\n"
                 "2133813:0:0:365:0:1004:1\n"
                 "[identities:1]\n"
                 "bad:key:1234:48:2133813:0:587671\n",
                 CLOUDPREFS_VERSION);
        create_atomic_file("test-cloudprefs-2133813", "%s", content);
        ok(!confset_load(NULL), "Failed to load test-cloudprefs");
        OK_SXEL_ERROR(": 10: Unrecognised line (invalid key format)");

        snprintf(content, sizeof(content),
                 "cloudprefs %u\n"
                 "count 5\n"
                 "[lists:1]\n"
                 "0:1175134:cidr:71:59e259a74ffccfef01b1e6eeee30d1c8db311111:5.6.7.0/24\n"
                 "[bundles:1]\n"
                 "0:587671:4294967295:40:0::1175134:::::::::\n"
                 "[orgs:2]\n"
                 "2133813:0:0:365:0:1004:1\n"
                 "2133814:0:0:365:0:1004:1\n"
                 "[identities:1]\n"
                  "2133813:1234:1234:48:2133813:0:587671\n",
                 CLOUDPREFS_VERSION);
        create_atomic_file("test-cloudprefs-2133813", "%s", content);
        ok(!confset_load(NULL), "Failed to load test-cloudprefs");
        OK_SXEL_ERROR(": Expected exactly one org (2133813) entry in 'orgs' section");

        snprintf(content, sizeof(content),
                 "cloudprefs %u\n"
                 "count 4\n"
                 "[lists:1]\n"
                 "0:1175134:cidr:71:59e259a74ffccfef01b1e6eeee30d1c8db311111:5.6.7.0/24\n"
                 "[bundles:1]\n"
                 "0:587671:4294967295:40:0::1175134:::::::::\n"
                 "[orgs:1]\n"
                 "0:0:0:365:0:1004:1\n"
                 "[identities:1]\n"
                 "0:1234:1234:48:2133813:0:587671\n",
                 CLOUDPREFS_VERSION);
        create_atomic_file("test-cloudprefs-0", "%s", content);
        ok(confset_load(NULL), "Failed to load test-cloudprefs-0");
        OK_SXEL_ERROR(": Expected zero org entries in 'orgs' section for org 0 but found 1");
        unlink("test-cloudprefs-0");
    }

    diag("Test cloudprefs loading with CIDR lists");
    {
        snprintf(content, sizeof(content),    // Add a parent org
                 "cloudprefs %u\n"
                 "count 15\n"
                 "[lists:2]\n"
                 "0:1175137:domain:71:59e259a74ffccfef01b1e6eeee30d1c8db34bf14:block.com\n"
                 "8:1175135:domain:72:296ecb3def058ee286310ebf3ec9087144a226b1:allow.com\n"
                 "[settinggroup:8]\n"
                 "0:618867:0:80:0:0\n"
                 "1:550381:0:400000000030000000001FD000000000000000:0:0\n"
                 "2:507191:0:0:0:0\n"
                 "2:1060160:4000:0:0:0\n"
                 "2:1060210:4000:0:0:0\n"
                 "3:502311:0:0:0:0\n"
                 "3:1020280:180000:0:0:0\n"
                 "3:1020328:180000:0:0:0\n"
                 "[bundles:3]\n"
                 "0:587671:4294967295:40:0:618867 550381 507191 502311:1175137::1175135:::::::\n"
                 "0:1104266:2:40:0:3 550381 1060160 1020280:1175137::1175135:::::::\n"
                 "0:1104312:0:40:0:7 550381 1060210 1020328:1175137::1175135:::::::\n"
                 "[orgs:1]\n"
                 "1:67:FFFFFFFFFF000002000000000000000000000:730:0:61802099:0\n"
                 "[identities:1]\n"
                 "1:1:61882711:48:1:0:1104312\n",
                 CLOUDPREFS_VERSION);
        create_atomic_file("test-cloudprefs-1", "%s", content);

        snprintf(content, sizeof(content),
                 "cloudprefs %u\n"
                 "count 4\n"
                 "[lists:1]\n"
                 "0:1175134:cidr:71:59e259a74ffccfef01b1e6eeee30d1c8db311111:5.6.7.0/24\n"
                 "[bundles:1]\n"
                 "0:587671:4294967295:40:0::1175134:::::::::\n"
                 "[orgs:1]\n"
                 "2133813:0:0:365:0:1004:1\n"
                 "[identities:1]\n"
                 "2133813:1234:1234:48:2133813:0:587671\n",
                 CLOUDPREFS_VERSION);
        create_atomic_file("test-cloudprefs-2133813", "%s", content);

        ok(confset_load(NULL), "Loaded test-cloudprefs");
        OK_SXEL_ERROR(NULL);

        ok(set = confset_acquire(&gen), "Acquired the conf set");
        cp = cloudprefs_conf_get(set, CONF_CLOUDPREFS);
        ok(cloudprefs_get(&pref, cp, "cloudprefs", 2133813, 1234, &oolist, NULL), "Got a pref entry for org 2133813, originid 1234");
        netaddr_from_str(&addr, "5.6.7.100", AF_INET);
        ok(!pref_cidrlist_match(&pref, NULL, AT_LIST_DESTBLOCK, &addr), "Couldn't find a CIDR match for 5.6.7.100");
        confset_release(set);

        conf_unregister(CONF_CLOUDPREFS);
        ok(confset_load(NULL), "Unloaded test-cloudprefs");
        CONF_CLOUDPREFS = 0;
        cloudprefs_register_add_cidr(&CONF_CLOUDPREFS, "cloudprefs", "test-cloudprefs-%u", true);
        OK_SXEL_ERROR(NULL);

        create_atomic_file("test-cloudprefs-2133813", "%s", content);
        ok(confset_load(NULL), "Loaded test-cloudprefs");
        OK_SXEL_ERROR(NULL);

        ok(set = confset_acquire(&gen), "Acquired the conf set");
        cp = cloudprefs_conf_get(set, CONF_CLOUDPREFS);
        ok(cloudprefs_get(&pref, cp, "cloudprefs", 2133813, 1234, &oolist, NULL), "Got a pref entry for org 2133813, originid 1234");
        netaddr_from_str(&addr, "5.6.7.100", AF_INET);
        ok(pref_cidrlist_match(&pref, NULL, AT_LIST_DESTBLOCK, &addr), "Found a CIDR match for 5.6.7.100");

        ok(!cloudprefs_slotisempty(&cp->conf, prefs_org_slot(cp->org, 2133813, cp->count)), "Org 2133813 slot is not empty");
        ok( cloudprefs_slotisempty(&cp->conf, prefs_org_slot(cp->org, 2133814, cp->count)), "Org 2133814 slot is empty");
        ok(!cloudprefs_get_prefblock(cp, 2133812),                                          "No prefblock for org 2133812");
        ok( cloudprefs_get_prefblock(cp, 2133813),                                          "Got prefblock for org 2133813");
        ok(!cloudprefs_get(&pref, cp, "cloudprefs", 2133814, 1234, &oolist, NULL),                        "Can't get cloudprefs for 2133814");
        ok( cloudprefs_get(&pref, cp, "cloudprefs", 2133813, 1234, &oolist, NULL),                        "Got cloudprefs for 2133813/1234");
        ok(!cloudprefs_get(&pref, cp, "cloudprefs", 2133813, 1235, &oolist, NULL),                        "Can't get cloudprefs for 2133813/1235");

        confset_release(set);
    }

    oolist_clear(&oolist);
    confset_unload();
    fileprefs_freehashes();
    is(memory_allocations(), start_allocations, "All memory allocations were freed by end of tests");

    test_uncapture_sxel();

    return exit_status();
}
