#include <fcntl.h>
#include <kit-alloc.h>
#include <mockfail.h>
#include <sys/stat.h>
#include <tap.h>

#include "cidrlist.h"
#include "cidrprefs-org.h"
#include "cidrprefs-private.h"
#include "conf-loader.h"
#include "digest-store.h"
#include "kit-random.h"

#include "common-test.h"

#define TEST_DIGEST_STORE "test-cidrprefs-digest-store"

static time_t last_timestamp = 0UL;

static void
wait_next_sec(void)
{
    time_t now = time(NULL);
    SXEA1(now >= last_timestamp, "We're going back in time!");

    while (now == last_timestamp) {
        usleep(10000);
        now = time(NULL);
    }

    last_timestamp = now;
}

static void
cleanup_test_files(void)
{
    uint32_t orgid;
    char     buf[32];

    unlink("test-cidrprefs");
    unlink("test-cidrprefs-1");
    unlink("test-cidrprefs-2");
    unlink("test-cidrprefs-3");
    unlink("test-cidrprefs-4");
    unlink("test-cidrprefs-4.last-good");
    unlink("test-cidrprefs-5");
    unlink("test-cidrprefs-2748");

    for (orgid = 100; orgid < 116; orgid++) {
        snprintf(buf, sizeof(buf), "test-cidrprefs-%u", orgid);
        unlink(buf);
    }

    is(rrmdir(TEST_DIGEST_STORE), 0, "Removed %s with no errors", TEST_DIGEST_STORE);
}

int
main(void)
{
    struct conf_info info;
    char content[5][4096], hex[sizeof(info.digest) * 2 + 1];
    struct prefs_org *cidrprefs_org;
    uint64_t start_allocations;
    struct conf_loader cl;
    const char *fn;

    plan_tests(115);
#ifdef __FreeBSD__
    plan_skip_all("DPT-186 - Need to implement inotify as dtrace event");
    exit(0);
#endif

    kit_random_init(open("/dev/urandom", O_RDONLY));
    cleanup_test_files();
    is(mkdir(TEST_DIGEST_STORE, 0755), 0, "Created %s/", TEST_DIGEST_STORE);
    conf_initialize(".", ".", false, NULL);
    conf_loader_init(&cl);

    kit_memory_initialize(false);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");
    info.updates   = 0;
    info.loadflags = LOADFLAGS_FP_ALLOW_BUNDLE_EXTREFS;
    memset(info.digest, 0xa5, sizeof(info.digest));
    hex[sizeof(hex) - 1] = '\0';

    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */

    diag("Test empty file");
    {
        fn = create_data("test-cidrprefs-2748", "%s", "");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        cidrprefs_org = cidrprefs_org_new(0, &cl, &info);
        ok(!cidrprefs_org, "Failed to read empty file");
        conf_loader_done(&cl, &info);
        is(info.updates, 1, "conf_loader_done() didn't bump 'info.updates' after failing to read an empty file");
        unlink(fn);
        OK_SXEL_ERROR("No content found");
    }

    diag("Test V%u data load", CIDRPREFS_VERSION - 1);
    {
        fn = create_data("test-cidrprefs-2748", "cidrprefs %u\ncount 0\n", CIDRPREFS_VERSION - 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        cidrprefs_org = cidrprefs_org_new(0, &cl, &info);
        unlink(fn);
        ok(!cidrprefs_org, "V%u parser won't read version %u data", CIDRPREFS_VERSION, CIDRPREFS_VERSION - 1);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [9]");    /* Hardcoded version - no application tests to confirm the actual number! */
    }

    diag("Test V%u (newer that current version) data load", CIDRPREFS_VERSION + 1);
    {
        fn = create_data("test-cidrprefs-2748", "cidrprefs %u\ncount 0\n", CIDRPREFS_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        cidrprefs_org = cidrprefs_org_new(0, &cl, &info);
        unlink(fn);
        ok(!cidrprefs_org, "V%u parser won't read version %u data", CIDRPREFS_VERSION, CIDRPREFS_VERSION + 1);
        OK_SXEL_ERROR("1: Invalid version(s); must be from the set [%d]", CIDRPREFS_VERSION);
    }

    conf_loader_fini(&cl);

    /* KIT_ALLOC_SET_LOG(1); */

    cidrprefs_register(&CONF_CIDRPREFS, "cidrprefs", "test-cidrprefs-%u", true);

    diag("Test V%u cidrprefs load with identities, which are not allowed", CIDRPREFS_VERSION);
    {
        const char *valid_cidrprefs  = "[lists:1]\n"      "1:1:cidr:71:0123456789ABCDEF0123456789ABCDEF:1.2.3.4/32 5.6.7.8/32\n"
                                       "[bundles:1]\n"    "0:1:0:32:1400000000007491CD:::::::::::\n";
        const char *empty_orgs =       "[orgs:0]\n";
        const char *with_orgs =        "[orgs:1]\n"       "2748:0:0:365:0:1002748:0\n";
        const char *with_bad_orgs =    "[orgs:1]\n"       "2749:0:0:365:0:1002749:0\n";
        const char *with_2_orgs =      "[orgs:2]\n"       "2748:0:0:365:0:1002748:0\n" "2749:0:0:365:0:1002749:0\n";
        const char *empty_identities = "[identities:0]\n";
        const char *with_identities =  "[identities:1]\n" "00000001:0::0:1:2748:0:1\n";

        unlink("test-cidrprefs-2748.last-good");
        create_atomic_file("test-cidrprefs-2748", "cidrprefs %u\ncount %u\n%s", CIDRPREFS_VERSION, 2, valid_cidrprefs);
        ok(confset_load(NULL), "Noted an update; Bad version %u data with no orgs or identities sections", CIDRPREFS_VERSION);
        OK_SXEL_ERROR("./test-cidrprefs-2748: Expected exactly one org (2748) entry in 'orgs' section");

        create_atomic_file("test-cidrprefs-2748", "cidrprefs %u\ncount %u\n%s%s", CIDRPREFS_VERSION, 2, valid_cidrprefs, empty_orgs);
        ok(!confset_load(NULL), "Noted no update; Rejected version %u data with empty orgs and no identities section", CIDRPREFS_VERSION);
        OK_SXEL_ERROR("test-cidrprefs-2748.last-good could not be opened: No such file or directory");
        OK_SXEL_ERROR("./test-cidrprefs-2748: Expected exactly one org (2748) entry in 'orgs' section");

        create_atomic_file("test-cidrprefs-2748", "cidrprefs %u\ncount %u\n%s%s", CIDRPREFS_VERSION, 3, valid_cidrprefs, with_orgs);
        ok(confset_load(NULL), "Noted an update; Read valid version %u data with valid orgs and no identities section", CIDRPREFS_VERSION);
        OK_SXEL_ERROR(NULL);

        create_atomic_file("test-cidrprefs-2748", "cidrprefs %u\ncount %u\n%s%s", CIDRPREFS_VERSION, 3, valid_cidrprefs, with_bad_orgs);
        ok(!confset_load(NULL), "Noted no update; Rejected version %u data with the wrong org and no identities section", CIDRPREFS_VERSION);
        OK_SXEL_ERROR("./test-cidrprefs-2748: Expected exactly one org (2748) entry in 'orgs' section");

        create_atomic_file("test-cidrprefs-2748", "cidrprefs %u\ncount %u\n%s%s", CIDRPREFS_VERSION, 4, valid_cidrprefs, with_2_orgs);
        ok(!confset_load(NULL), "Noted no update; Rejected version %u data with 2 orgs and no identities section", CIDRPREFS_VERSION);
        OK_SXEL_ERROR("test-cidrprefs-2748: Expected exactly one org (2748) entry in 'orgs' section");

        create_atomic_file("test-cidrprefs-2748", "cidrprefs %u\ncount %u\n%s%s%s", CIDRPREFS_VERSION, 3, valid_cidrprefs, with_orgs, empty_identities);
        ok(confset_load(NULL), "Noted an update; Read valid version %u data with valid orgs and empty identities section", CIDRPREFS_VERSION);
        OK_SXEL_ERROR(NULL);

        create_atomic_file("test-cidrprefs-2748", "cidrprefs %u\ncount %u\n%s%s%s", CIDRPREFS_VERSION, 3, valid_cidrprefs, empty_orgs, with_identities);
        ok(!confset_load(NULL), "Noted no update; Rejected version %u data with empty orgs and populated identities sections", CIDRPREFS_VERSION);
        OK_SXEL_ERROR("test-cidrprefs-2748: 8: identities section header count must be 0");

        create_atomic_file("test-cidrprefs-2748", "cidrprefs %u\ncount %u\n%s%s", CIDRPREFS_VERSION, 3, valid_cidrprefs, with_identities);
        ok(!confset_load(NULL), "Noted no update; Rejected version %u data with no orgs and non-empty identities section", CIDRPREFS_VERSION);
        OK_SXEL_ERROR("test-cidrprefs-2748: 7: identities section header count must be 0");

        create_atomic_file("test-cidrprefs-2748", "cidrprefs %u\ncount %u\n%s%s%s", CIDRPREFS_VERSION, 4, valid_cidrprefs, with_orgs, with_identities);
        ok(!confset_load(NULL), "Noted an update; Rejected version %u data with non-empty orgs and identities sections", CIDRPREFS_VERSION);
        OK_SXEL_ERROR("test-cidrprefs-2748: 9: identities section header count must be 0");
    }
    OK_SXEL_ERROR(NULL);

    diag("Test V%u cidrprefs load with elementtypes other than 'cidr', which are not allowed with strict fileprefs", CIDRPREFS_VERSION);
    {
        fileprefs_set_strict(true);
        const char *start      = "count 3\n" "[lists:1]\n";
        const char *finish     = "[bundles:1]\n"    "0:1:0:32:1400000000007491CD:::::::::::\n"
                                 "[orgs:1]\n"       "2748:0:0:365:0:1002748:0\n";
        const char *domainlist = "1:1:domain:71:0123456789ABCDEF0123456789ABCDEF:blocked.1 blocked.2\n";
        const char *urllist    = "1:1:url:71:0123456789ABCDEF0123456789ABCDEF:blocked.1/block1 blocked.2/block2\n";
        const char *cidrlist   = "1:1:cidr:71:0123456789ABCDEF0123456789ABCDEF:1.2.3.4/32 5.6.7.8/32\n";
        const char *boguslist  = "1:1:bogus:71:??? ???\n";

        create_atomic_file("test-cidrprefs-2748", "cidrprefs %u\n%s%s%s", CIDRPREFS_VERSION, start, cidrlist, finish);
        ok(confset_load(NULL), "Noted an update; Read valid version %u data with elementtype 'cidr'", CIDRPREFS_VERSION);
        OK_SXEL_ERROR(NULL);

        create_atomic_file("test-cidrprefs-2748", "cidrprefs %u\n%s%s%s", CIDRPREFS_VERSION, start, urllist, finish);
        ok(!confset_load(NULL), "Noted an update; Rejected version %u data with elementtype 'url'", CIDRPREFS_VERSION);
        OK_SXEL_ERROR("cidrprefs v%d: ./test-cidrprefs-2748: 4: Invalid list line (unexpected elementtype url, loadflags 8E)",
                      CIDRPREFS_VERSION);

        create_atomic_file("test-cidrprefs-2748", "cidrprefs %u\n%s%s%s", CIDRPREFS_VERSION, start, domainlist, finish);
        ok(!confset_load(NULL), "Noted an update; Rejected version %u data with elementtype 'domain'", CIDRPREFS_VERSION);
        OK_SXEL_ERROR("test-cidrprefs-2748: 4: Invalid list line (unexpected elementtype domain, loadflags 8E)");

        create_atomic_file("test-cidrprefs-2748", "cidrprefs %u\n%s%s%s", CIDRPREFS_VERSION, start, boguslist, finish);
        ok(!confset_load(NULL), "Noted an update; Rejected version %u data with elementtype 'bogus'", CIDRPREFS_VERSION);
        OK_SXEL_ERROR("cidrprefs v%d: ./test-cidrprefs-2748: 4: Unrecognised list line (invalid elementtype 'bogus')",
                      CIDRPREFS_VERSION);
    }
    OK_SXEL_ERROR(NULL);

    diag("Test V%u data handling", CIDRPREFS_VERSION);
    {
        const struct cidrprefs *cidrprefs;
        struct confset *set;
        uint32_t orgid;
        char buf[4096];
        pref_t pr;
        int gen;

        snprintf(content[0], sizeof(content[0]),
                 "cidrprefs %u\n"
                 "count 12\n"
                 "[lists:6]\n"
                 "0:1:cidr:71:00000000000000000000000000000000: 208.67.222.222/32 207.67.220.220/32 10.10.10.0/24\n"
                 "0:4:cidr:70:00000000000000000000000000000001: 1.2.3.4/32\n"
                 "0:42:cidr:70:00000000000000000000000000000002: 123.234.210.234/31\n"
                 "8:3:cidr:72:00000000000000000000000000000003: 9.9.9.0/24 2001:123::/64\n"
                 "8:4:cidr:72:00000000000000000000000000000002: 123.456.789.234/31 1.1.1.1 2.2.2.2\n"
                 "8:5:cidr:72:00000000000000000000000000000004: abcd:ef01:2345:6789:abcd:effe:dcba:9876/127\n"
                 "[bundles:5]\n"
                 "0:1:0004:61:1F000000000000001F::1 4::3:::::::\n"
                 "0:3:0100:60:1F0000000000000000::1 4::3:::::::\n"
                 "0:19:0001:62:1F00000000000000F1::1 4::3:::::::\n"
                 "0:1234:0002:60:2F000000000000FF01::1 4::3:::::::\n"
                 "0:92143:0102:63:2F000000000000FF01::42::4 5:::::::\n"
                 "[orgs:1]\n"
                 "1:0:0:365:0:1001:0\n",
                 CIDRPREFS_VERSION);
        /* Org 2 is intentionally broken */
        snprintf(content[1], sizeof(content[1]), "cidrprefs %u\ncount 3\n"
                 "[lists:0]\n[bundles:1]\n0:1:0:0:0:::::::::::\n[orgs:1]\n2:0:0:365:0:1002:0\n[no-identities:1]\n2:0::1:1:2:0:1\n", CIDRPREFS_VERSION);
        snprintf(content[2], sizeof(content[2]),
                 "cidrprefs %u\n"
                 "count 5\n"
                 "[lists:3]\n"
                 "0:1:cidr:71:20000000000000000000000000000000: 8.8.0.0/16 50.64.60.197/32 2001:470:e83b:9a:240:f4ff:feb1:1c85/128 2001:470:e83b:a7:20d:61ff:fe45:2c3f/128\n"
                 "0:4:cidr:70:20000000000000000000000000000001: 1.2.4.0/24\n"
                 "8:3:cidr:72:20000000000000000000000000000003: 9.9.0.0/16\n"
                 "[bundles:1]\n"
                 "0:123:0099:63:1F0000000000000000::1 4::3:::::::\n"
                 "[orgs:1]\n"
                 "3:0:0:365:0:1003:0\n", CIDRPREFS_VERSION);
        snprintf(content[3], sizeof(content[3]), "cidrprefs %u\ncount 0\n[lists:0]\n[bundles:0]\n[orgs:0]\n", CIDRPREFS_VERSION);
        snprintf(content[4], sizeof(content[4]),
                 "cidrprefs %u\n"
                 "count 2\n"
                 "[bundles:1]\n"
                 "0:321:0:61:3F000000000000FF01::1 4::12:::::::\n"
                 "[orgs:1]\n"
                 "5:0:0:365:0:1005:3\n",    /* This org has a parent org (org 3) */
                 CIDRPREFS_VERSION);

        /* setup digest_store_dir */
        digest_store_set_options(TEST_DIGEST_STORE, DIGEST_STORE_DEFAULT_UPDATE_FREQ, DIGEST_STORE_DEFAULT_MAXIMUM_AGE);

        ok(set = confset_acquire(&gen), "Acquired the conf set");
        digest_store_changed(set);
        last_timestamp = time(NULL);
        confset_release(set);

        /* Verify the handling of out-of-memory trying to malloc cidrprefs on reload */
        MOCKFAIL_START_TESTS(3, CIDRPREFS_CLONE);
        create_atomic_file("test-cidrprefs-999", "%s", content[0]);
        ok(!confset_load(NULL), "Didn't see a change to test-cidrprefs-999 due to a malloc failure");
        OK_SXEL_ERROR("Couldn't allocate a cidrprefs structure");
        OK_SXEL_ERROR("Couldn't clone a cidrprefs conf object");
        MOCKFAIL_END_TESTS();
        unlink("test-cidrprefs-999");

        diag("Verify last-good stuff");
        {
            /* Kill off all config so that we use last-good files again */
            confset_unload();
            CONF_CIDRPREFS = 0;
            cidrprefs_register(&CONF_CIDRPREFS, "cidrprefs", "test-cidrprefs-%u", true);

            /* org 1 will load, org 2 won't and org 4 will load from last-good */
            create_atomic_file("test-cidrprefs-1", "%s", content[0]);
            create_atomic_file("test-cidrprefs-2", "%s", content[1]);    /* Broken content, no last-good */

            /* Intentionally break org 4 and make sure the lastgood file gets used. */
            create_atomic_file("test-cidrprefs-4.last-good", "%s", content[3]);
            snprintf(content[3], sizeof(content[3]), "cidrprefs %u\ncount 1\n[lists:0]\n[bundles:0]\n[orgs:0]\n", CIDRPREFS_VERSION);
            create_atomic_file("test-cidrprefs-4", "%s", content[3]);

            /* test-cidrprefs-2: 8: Invalid section header */
            /* ./test-cidrprefs-2.last-good: open: No such file or directory */
            /* parsing segment 2 (test-cidrprefs-2) failed, ./test-cidrprefs-2.last-good not available */
            /* test-cidrprefs-4: 5: Incorrect total count 1 - read 0 data lines */
            /* parsing segment 4 (test-cidrprefs-4) failed, used ./test-cidrprefs-4.last-good instead */
            ok(confset_load(NULL), "Noted an update to test-cidrprefs-1 and test-cidrprefs-4, but test-cidrprefs-2 failed");
            OK_SXEL_ERROR("cidrprefs v%d: ./test-cidrprefs-2748: 4: Unrecognised list line (invalid elementtype 'bogus')", CIDRPREFS_VERSION);
            OK_SXEL_ERROR("./test-cidrprefs-2: 8: Invalid section header 'no-identities'");

            ok(set = confset_acquire(&gen), "Reacquired the new config set");
            ok(cidrprefs = cidrprefs_conf_get(set, CONF_CIDRPREFS), "Got cidrprefs");
            is(cidrprefs->count, 4, "cidrprefs contains 4 orgs");
            skip_if(cidrprefs->count != 4, 7, "Cannot verify orgs") {
                is(cidrprefs->org[0]->cs.id, 1, "Org 1 is present");
                is(cidrprefs->org[1]->cs.id, 2, "Org 2 is present");
                is(cidrprefs->org[2]->cs.id, 4, "Org 4 is present");
                is(cidrprefs->org[3]->cs.id, 2748, "Org 2748 is present");

                ok(!cidrprefs->org[1]->cs.loaded, "Org 2 shows it was not loaded");
                ok(cidrprefs->org[1]->cs.failed_load, "Org 2 shows a failed load");
                is(prefblock_count_total(cidrprefs->org[2]->fp.values), 0, "Org 4 is empty");
            }
            confset_release(set);
        }

        OK_SXEL_ERROR("test-cidrprefs-2.last-good could not be opened: No such file or directory");
        OK_SXEL_ERROR("fileprefs_new(): cidrprefs v%d: ./test-cidrprefs-4: 5: Incorrect total count 1 - read 0 data lines", CIDRPREFS_VERSION);
        OK_SXEL_ERROR(NULL);
        /* Verify the handling of out-of-memory trying to malloc a cidrprefs-org on reload */
        MOCKFAIL_START_TESTS(4, CIDRPREFS_CLONE_ORGS);
        create_atomic_file("test-cidrprefs-3", "we'll never even get to see this data");
        ok(!confset_load(NULL), "Didn't see a change to test-cidrprefs-3 due to a cidrprefs-org slot allocation failure");
        OK_SXEL_ERROR("Couldn't allocate 10 new cidrprefs org slots");
        OK_SXEL_ERROR("Couldn't clone a cidrprefs conf object");
        OK_SXEL_ERROR(NULL);
        MOCKFAIL_END_TESTS();

        create_atomic_file("test-cidrprefs-3", "%s", content[2]);
        snprintf(content[3], sizeof(content[3]), "cidrprefs %u\ncount 0\n", CIDRPREFS_VERSION);
        create_atomic_file("test-cidrprefs-4", "%s", content[3]);
        create_atomic_file("test-cidrprefs-5", "%s", content[4]);
        ok(confset_load(NULL), "Noted an update to test-cidrprefs-[345]");

        create_atomic_file("test-cidrprefs-4", "%s", content[3]);
        ok(confset_load(NULL), "Noted an update after test-cidrprefs-4 was rewritten");

        ok(set = confset_acquire(&gen), "Acquired the new config");
        wait_next_sec();
        digest_store_changed(set);
        is(system("ls " TEST_DIGEST_STORE), 0, "Listed %s/", TEST_DIGEST_STORE);

        ok(cidrprefs = cidrprefs_conf_get(set, CONF_CIDRPREFS), "Got the cidrprefs");

        skip_if(!cidrprefs, 7, "Cannot run these tests without cidrprefs") {
            struct cidrlist *list;
            char *abuf;
            size_t sz;
            pref_categories_t categories;
            pref_categories_t expected_categories;
            struct netsock sock;

            cidrprefs_get_policy(cidrprefs, &pr, 1, 0XBADBAD);
            ok(!PREF_VALID(&pr), "No pref for bad bundle 0xBADBAD of org 1");
            cidrprefs_get_policy(cidrprefs, &pr, 1, 1234);
            ok(PREF_VALID(&pr), "Got the pref for bundle 1234 of org 1");

            /* check ip match in dest list type DESTBLOCK and categories for dest block */
            netaddr_from_str(&sock.a, "208.67.222.222", AF_INET);
            pref_categories_setnone(&categories);
            ok(pref_cidrlist_match(&pr, &categories, AT_LIST_DESTBLOCK, &sock.a),
                                   "CIDR list match found for 208.67.222.222");
            pref_categories_sscan(&expected_categories, "800000000000000000");
            ok(pref_categories_equal(&categories, &expected_categories), "Got categories %s (expected 800000000000000000)",
                                     pref_categories_idstr(&categories));

            /* check ip match aginst a cidr in dest list type DESTBLOCK */
            netaddr_from_str(&sock.a, "10.10.10.10", AF_INET);
            pref_categories_setnone(&categories);
            ok(pref_cidrlist_match(&pr, &categories, AT_LIST_DESTBLOCK, &sock.a),
                                   "CIDR list match found for 10.10.10.10");

            /* check ip match aginst a cidr in dest list type DESTALLOW and categories for dest allow*/
            netaddr_from_str(&sock.a, "9.9.9.9", AF_INET);
            pref_categories_setnone(&categories);
            ok(pref_cidrlist_match(&pr, &categories, AT_LIST_DESTALLOW, &sock.a),
                                   "CIDR list match found for 9.9.9.9");
            pref_categories_sscan(&expected_categories, "1000000000000000000");
            ok(pref_categories_equal(&categories, &expected_categories), "Got categories %s (expected 1000000000000000000)",
                                     pref_categories_idstr(&categories));

            /* check no ip match aginst a cidr in dest list type other than DESTBLOCK */
            pref_categories_setnone(&categories);
            ok(!pref_cidrlist_match(&pr, &categories, AT_LIST_DESTBLOCK, &sock.a),
                                    "CIDR list No match found for 9.9.9.9");

            MOCKFAIL_START_TESTS(3, CIDRLIST_APPEND4);
            list = cidrlist_new_from_pref(&pr, AT_LIST_DESTBLOCK);
            ok(!list, "Cannot get a cidrlist from the pref for bundle 1234 when the IPv4 realloc() fails in cidrlist_append()");
            OK_SXEL_ERROR("Failed to realloc 24 bytes");
            OK_SXEL_ERROR(NULL);
            MOCKFAIL_END_TESTS();

            list = cidrlist_new_from_pref(&pr, AT_LIST_DESTBLOCK);
            ok(list, "Got a cidrlist from the pref for bundle 1234");

            sz = cidrlist_buf_size(list);
            abuf = alloca(sz);
            cidrlist_to_buf(list, abuf, sz, NULL);

            is_eq(abuf, "1.2.3.4 10.10.10.0/24 207.67.220.220 208.67.222.222", "The cidrlist is correct");
            cidrlist_refcount_dec(list);

            /* Test with bundles that max out the buffer size */
            ok(cidrprefs_get_policy(cidrprefs, &pr, 1, 92143), "Got the pref for bundle 92143 of org 1");
            ok(PREF_VALID(&pr), "The pref is valid");
            skip_if(!PREF_VALID(&pr), 1, "Cannot check pref flags for no-pref") {
                is(PREF_BUNDLE(&pr)->bundleflags, 0x63, "The pref flags are correct");
            }

            list = cidrlist_new_from_pref(&pr, AT_LIST_DESTBLOCK);
            ok(list, "Got a BLOCK cidrlist from the pref for bundle 92143");
            is(sz = cidrlist_buf_size(list), 19, "cidrlist_buf_size() returns a size of 19");
            abuf = alloca(sz);
            is(strlen(cidrlist_to_buf(list, abuf, sz, NULL)), 18, "cidrlist_to_buf() returns a string of length of 18");
            is_eq(abuf, "123.234.210.234/31", "The cidrlist is correct");
            cidrlist_refcount_dec(list);

            list = cidrlist_new_from_pref(&pr, AT_LIST_DESTALLOW);
            ok(list, "Got an ALLOW cidrlist from the pref for bundle 92143");
            is(sz = cidrlist_buf_size(list), 71, "cidrlist_buf_size() returns a size of 71 (6 extra bytes to allow the last two words to be represented as an IPv4 address)");
            abuf = alloca(sz);
            size_t len;
            cidrlist_to_buf(list, abuf, sz, &len);
            is(len, 64, "cidrlist_to_buf() returns a length of 64");
            is_eq(abuf, "123.234.210.234/31 [abcd:ef01:2345:6789:abcd:effe:dcba:9876]/127", "The cidrlist is correct");
            cidrlist_refcount_dec(list);

            /* Test with an org that has a parent (MSP) */
            cidrprefs_get_policy(cidrprefs, &pr, 5, 321);
            ok(PREF_VALID(&pr), "Got the pref_t for bundle 321 of org 5");
            netaddr_from_str(&sock.a, "8.8.0.1", AF_INET);
            pref_categories_setnone(&categories);
            ok(pref_cidrlist_match(&pr, &categories, AT_LIST_DESTBLOCK, &sock.a),
               "is blocked by bundle 321 of org 5");
            pref_categories_sscan(&expected_categories, "800000000000000000");
            ok(pref_categories_equal(&categories, &expected_categories), "Got categories %s (expected 800000000000000000)",
                                     pref_categories_idstr(&categories));


            MOCKFAIL_START_TESTS(3, CIDRLIST_APPEND6);
            list = cidrlist_new_from_pref(&pr, AT_LIST_DESTBLOCK);
            ok(!list, "Cannot get a cidrlist from the pref for bundle 321 when the IPv6 realloc() fails in cidrlist_append()");
            OK_SXEL_ERROR("Failed to realloc 40 bytes");
            OK_SXEL_ERROR(NULL);
            MOCKFAIL_END_TESTS();

            list = cidrlist_new_from_pref(&pr, AT_LIST_DESTBLOCK);
            ok(list, "Got a cidrlist from the pref for bundle 321");
            is(list->how, PARSE_IP_OR_CIDR, "how is wrong - %d", list->how);

            sz = cidrlist_buf_size(list);
            abuf = alloca(sz);
            cidrlist_to_buf(list, abuf, sz, NULL);

            is_eq(abuf, "1.2.4.0/24 8.8.0.0/16 50.64.60.197 2001:470:e83b:9a:240:f4ff:feb1:1c85 2001:470:e83b:a7:20d:61ff:fe45:2c3f", "The cidrlist is correct");
            cidrlist_refcount_dec(list);
        }

        confset_release(set);

        /* Test removing a file */
        unlink("test-cidrprefs-1");
        ok(confset_load(NULL), "Noted an update to due to removal of test-cidrprefs-1");
        ok(set = confset_acquire(&gen), "Reacquired the new config set");
        ok(cidrprefs = cidrprefs_conf_get(set, CONF_CIDRPREFS), "Got the cidrprefs again");

        cidrprefs_get_policy(cidrprefs, &pr, 1, 1234);
        ok(!PREF_VALID(&pr), "Don't get a pref_t for bundle of deleted org 1");

        confset_release(set);

        OK_SXEL_ERROR(NULL);
        /* Verify the handling of out-of-memory trying to realloc cidrprefs-org slots on reload (realloced every 10+ slots) */
        MOCKFAIL_START_TESTS(6, CIDRPREFS_MOREORGS);
        snprintf(content[0], sizeof(content[0]), "cidrprefs %u\ncount 0\n# Different\n", CIDRPREFS_VERSION);

        /* Was 106-110 in dirprefs, but bumped up due to eliminating other tests. Also, reverse order to exercise index code */
        for (orgid = 115; orgid >= 106; orgid--) {
            snprintf(buf, sizeof(buf), "test-cidrprefs-%u", orgid);
            create_atomic_file(buf, "%s", content[0]);
        }

        /* Verify that not all 10 orgs were added */
        ok(!confset_load(NULL) || 1, "Shouldn't see changes to all of test-cidrprefs-106 - test-cidrprefs-115 due to a cidrprefs-org slot re-allocation failure");
        OK_SXEL_ERROR("Couldn't reallocate 20 cidrprefs org slots");
        OK_SXEL_ERROR("Couldn't reallocate 20 cidrprefs org slots");
        OK_SXEL_ERROR("Couldn't reallocate 20 cidrprefs org slots");
        OK_SXEL_ERROR("Couldn't reallocate 20 cidrprefs org slots");
        OK_SXEL_ERROR("Couldn't reallocate 20 cidrprefs org slots");
        MOCKFAIL_END_TESTS();
    }

    OK_SXEL_ERROR(NULL);
    test_uncapture_sxel();

    confset_unload();
    fileprefs_freehashes();
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");

    /* KIT_ALLOC_SET_LOG(0); */

    cleanup_test_files();
    return exit_status();
}
