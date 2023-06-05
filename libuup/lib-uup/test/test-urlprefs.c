#include <fcntl.h>
#include <kit-alloc.h>
#include <kit-random.h>
#include <mockfail.h>
#include <sys/stat.h>
#include <tap.h>

#include "conf-loader.h"
#include "conf-worker.h"
#include "digest-store.h"
#include "url-normalize.h"
#include "urlprefs-org.h"
#include "urlprefs-private.h"

#include "common-test.h"

#define TEST_DIGEST_STORE "test-urlprefs-digest-store"

static time_t last_timestamp;
static module_conf_t CONF_URLPREFS;

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

static char normalized_url[4096];

static unsigned
normalized_url_length(const char *url)
{
    unsigned length = sizeof(normalized_url);
    SXEA1(url_normalize(url, strlen(url), normalized_url, &length) == URL_NORM_SUCCESS, "Failed to normalize url %s", url);
    return(length);
}

static void
cleanup_test_files(void)
{
    uint32_t orgid;
    char     buf[32];

    unlink("test-urlprefs");
    unlink("test-urlprefs-1");
    unlink("test-urlprefs-2");
    unlink("test-urlprefs-2.last-good");
    unlink("test-urlprefs-3");
    unlink("test-urlprefs-4");
    unlink("test-urlprefs-4.last-good");
    unlink("test-urlprefs-5");
    unlink("test-urlprefs-2748");
    unlink("test-urlprefs-9876");
    unlink("test-urlprefs-9876.last-good");

    for (orgid = 100; orgid < 116; orgid++) {
        snprintf(buf, sizeof(buf), "test-urlprefs-%u", orgid);
        unlink(buf);
    }

    is(rrmdir(TEST_DIGEST_STORE), 0, "Removed %s with no errors", TEST_DIGEST_STORE);
}

static unsigned
confset_get_urlprefslistcount(uint32_t orgid)
{
    const struct prefblock *prefblock;
    const struct urlprefs *urlprefs;
    unsigned count = PREF_NOLIST;
    struct confset *set = NULL;

    if (confset_load(NULL) && (set = confset_acquire(NULL)) && (urlprefs = urlprefs_conf_get(set, CONF_URLPREFS))
     && (prefblock = urlprefs_get_prefblock(urlprefs, orgid)))
        count = prefblock->count.lists;

    confset_release(set);
    return count;
}

int
main(void)
{
    struct conf_info info;
    char hex[sizeof(info.digest) * 2 + 1];
    char buf[4096], content[5][4096];
    const struct urlprefs *urlprefs;
    struct prefs_org *urlprefs_org;
    uint64_t start_allocations;
    struct conf_loader cl;
    struct confset *set;
    uint32_t orgid;
    const char *fn;
    unsigned i;
    pref_t pr;
    int gen;

    plan_tests(79);

#ifdef __FreeBSD__
    plan_skip_all("DPT-186 - Need to implement inotify as dtrace event");
    exit(0);
#endif

    kit_random_init(open("/dev/urandom", O_RDONLY));
    cleanup_test_files();
    is(mkdir(TEST_DIGEST_STORE, 0755), 0, "Created %s/", TEST_DIGEST_STORE);
    conf_initialize(".", ".", false, NULL);
    conf_loader_init(&cl);

    /* KIT_ALLOC_SET_LOG(1); */

    kit_memory_initialize(false);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");
    info.updates = 0;
    memset(info.digest, 0xa5, sizeof(info.digest));
    hex[sizeof(hex) - 1] = '\0';

    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */

    diag("Test empty file");
    {
        fn = create_data("test-urlprefs", "%s", "");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        info.loadflags = LOADFLAGS_FP_ALLOW_BUNDLE_EXTREFS;
        urlprefs_org = urlprefs_org_new(0, &cl, &info);
        ok(!urlprefs_org, "Failed to read empty file");
        conf_loader_done(&cl, &info);
        is(info.updates, 1, "conf_loader_done() didn't bump 'info.updates' after failing to read an empty file");
        unlink(fn);
        OK_SXEL_ERROR("No content found");
    }

    diag("Test V%u data load", URLPREFS_VERSION - 1);
    {
        fn = create_data("test-urlprefs", "urlprefs %u\ncount 0\n", URLPREFS_VERSION - 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        urlprefs_org = urlprefs_org_new(0, &cl, &info);
        unlink(fn);
        ok(!urlprefs_org, "V%u parser won't read version %u data", URLPREFS_VERSION, URLPREFS_VERSION - 1);
        OK_SXEL_ERROR("1: Invalid version(s); must be from the set [9]");    /* Hardcoded version - no application tests to confirm the actual number! */
    }

    diag("Test V%u (newer that current version) data load", URLPREFS_VERSION + 1);
    {
        fn = create_data("test-urlprefs", "urlprefs %u\ncount 0\n", URLPREFS_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        urlprefs_org = urlprefs_org_new(0, &cl, &info);
        unlink(fn);
        ok(!urlprefs_org, "V%u parser won't read version %u data", URLPREFS_VERSION, URLPREFS_VERSION + 1);
        OK_SXEL_ERROR("1: Invalid version(s); must be from the set [%d]", URLPREFS_VERSION);
    }

    conf_loader_fini(&cl);
    urlprefs_register(&CONF_URLPREFS, "urlprefs", "test-urlprefs-%u", true);

    diag("Test V%u urlprefs load with identities, which are not allowed", URLPREFS_VERSION);
    {
        const char *valid_urlprefs   = "[lists:1]\n"      "1:1:url:71:0123456789ABCDEF0123456789ABCDEF:blocked.1 blocked.2\n"
                                       "[bundles:1]\n"    "0:1:0:32:1400000000007491CD:::::::::::\n"
                                       "[orgs:1]\n"       "2748:0:0:365:0:1002748:0\n";
        const char *empty_identities = "[identities:0]\n";
        const char *with_identities  = "[identities:1]\n" "00000001:0::0:0:2748:0:1\n";

        create_atomic_file("test-urlprefs-2748", "urlprefs %u\ncount %u\n%s", URLPREFS_VERSION, 3, valid_urlprefs);
        ok(confset_load(NULL), "Noted an update; Read valid version %u data with no identities section", URLPREFS_VERSION);

        create_atomic_file("test-urlprefs-2748", "urlprefs %u\ncount %u\n%s%s", URLPREFS_VERSION, 3, valid_urlprefs, empty_identities);
        ok(confset_load(NULL), "Noted an update; Read valid version %u data with empty identities section", URLPREFS_VERSION);

        create_atomic_file("test-urlprefs-2748", "urlprefs %u\ncount %u\n%s%s", URLPREFS_VERSION, 4, valid_urlprefs, with_identities);
        ok(!confset_load(NULL), "Noted no update; Rejected version %u data with non-empty identities section", URLPREFS_VERSION);
        OK_SXEL_ERROR("9: identities section header count must be 0");
    }

    diag("Test V%u urlprefs load with a wrong org count", URLPREFS_VERSION);
    {
        const char *preorg = "[lists:1]\n"      "1:1:url:71:0123456789ABCDEF0123456789ABCDEF:blocked.1 blocked.2\n"
                             "[bundles:1]\n"    "0:1:0:32:1400000000007491CD:::::::::::\n";
        const char *zeroorgs = "";
        const char *oneorg = "[orgs:1]\n"       "2748:0:0:365:0:1002748:0\n";
        const char *twoorgs = "[orgs:2]\n"      "2748:0:0:365:0:1002748:0\n2749:0:0:365:0:1002748:0\n";

        create_atomic_file("test-urlprefs-2748", "urlprefs %u\ncount 2\n%s%s", URLPREFS_VERSION, preorg, zeroorgs);
        ok(!confset_load(NULL), "Noted no update; Rejected version %u data with no orgs", URLPREFS_VERSION);
        OK_SXEL_ERROR("./test-urlprefs-2748: Expected exactly one org (2748) entry in 'orgs' section");

        create_atomic_file("test-urlprefs-2748", "urlprefs %u\ncount 3\n%s%s", URLPREFS_VERSION, preorg, oneorg);
        ok(confset_load(NULL), "Noted an update; Accepted version %u data with one org", URLPREFS_VERSION);

        create_atomic_file("test-urlprefs-2748", "urlprefs %u\ncount 4\n%s%s", URLPREFS_VERSION, preorg, twoorgs);
        ok(!confset_load(NULL), "Noted no update; Rejected version %u data with two orgs", URLPREFS_VERSION);
        OK_SXEL_ERROR("./test-urlprefs-2748: Expected exactly one org (2748) entry in 'orgs' section");
    }

    diag("Test V%u urlprefs load with elementtypes other than 'url', which are not allowed", URLPREFS_VERSION);
    {
        const char *before_list = "count 3\n"    "[lists:1]\n";
        const char *after_list = "[bundles:1]\n" "0:1:0:32:1400000000007491CD:::::::::::\n"
                                 "[orgs:1]\n"    "2748:0:0:365:0:1002748:0\n";
        const char *urllist = "1:1:url:71:0123456789ABCDEF0123456789ABCDE0:url.com/1 url.com/2\n";
        const char *applist = "15:1:application:148:0123456789ABCDEF0123456789ABCDE2:1 2\n";
        const char *domainlist = "1:1:domain:71:0123456789ABCDEF0123456789ABCDE1:blocked.1 blocked.2\n";
        const char *otherlist = "1:1:block:71:0123456789ABCDEF0123456789ABCDE1:some-data-format not-yet-invented\n";

        create_atomic_file("test-urlprefs-2748", "urlprefs %u\n%s%s%s", URLPREFS_VERSION, before_list, urllist, after_list);
        is(confset_get_urlprefslistcount(2748), 1, "Read valid version %u data with 1 list of elementtype 'url'", URLPREFS_VERSION);

        create_atomic_file("test-urlprefs-2748", "urlprefs %u\n%s%s%s", URLPREFS_VERSION, before_list, applist, after_list);
        is(confset_get_urlprefslistcount(2748), 1, "Read valid version %u data with 1 discarded list of elementtype 'application'", URLPREFS_VERSION);

        create_atomic_file("test-urlprefs-2748", "urlprefs %u\n%s%s%s", URLPREFS_VERSION, before_list, domainlist, after_list);
        is(confset_get_urlprefslistcount(2748), 0, "Read valid version %u data with 1 discarded list of elementtype 'domain'", URLPREFS_VERSION);

        create_atomic_file("test-urlprefs-2748", "urlprefs %u\n%s%s%s", URLPREFS_VERSION, before_list, otherlist, after_list);
        is(confset_get_urlprefslistcount(2748), 0, "Rejected version %u data with 1 discarded list of elementtype 'block' (i.e. unknown elementtype)", URLPREFS_VERSION);
    }

    diag("Test V%u data handling", URLPREFS_VERSION);
    {
        snprintf(content[0], sizeof(content[0]),
                 "urlprefs %u\n"
                 "count 11\n"
                 "[lists:5]\n"
                 "0:1:url:71:00000000000000000000000000000000: my-mixed-list-proxydomain.com/somePath/\n"
                 "0:4:url:70:00000000000000000000000000000001: fireeye1\n"
                 "4:2:url::00000000000000000000000000000002: typo1\n"
                 "8:3:url:72:00000000000000000000000000000003: white1\n"
                 "C:5:url::00000000000000000000000000000004: urlproxy1\n"
                 "[bundles:5]\n"
                 "0:1:0004:61:1F000000000000001F::1 4:2:3:5::::::\n"
                 "0:3:0100:60:1F0000000000000000::1 4:2:3:5::::::\n"
                 "0:19:0001:62:1F00000000000000F1::1 4:2:3:5::::::\n"
                 "0:1234:0002:60:2F000000000000FF01::1 4:2:3:5::::::\n"
                 "0:92143:0102:63:2F000000000000FF01::1 4:2:3:5::::::\n"
                 "[orgs:1]\n"
                 "1:0:0:365:0:1001:0\n",
                 URLPREFS_VERSION);
        /* Org 2 is intentionally broken */
        snprintf(content[1], sizeof(content[1]), "urlprefs %u\ncount 3\n"
                 "[lists:0]\n[bundles:1]\n0:1:0:0:0:::::::::::\n[orgs:1]\n2:0:0:365:0:1002:0\n[no-identities:1]\n2:0::1:2:0:1\n", URLPREFS_VERSION);
        snprintf(content[2], sizeof(content[2]),
                 "urlprefs %u\n"
                 "count 7\n"
                 "[lists:5]\n"
                 "0:1:url:71:20000000000000000000000000000000: my-mixed-list-proxydomain.com/somePath/\n"
                 "0:4:url:70:20000000000000000000000000000001: fireeye1\n"
                 "4:2:url::20000000000000000000000000000002: typo1\n"
                 "8:3:url:72:20000000000000000000000000000003: white1\n"
                 "C:5:url::20000000000000000000000000000004: urlproxy1\n"
                 "[bundles:1]\n"
                 "0:123:0099:63:1F0000000000000000::1 4:2:3:5::::::\n"
                 "[orgs:1]\n"
                 "3:0:0:365:0:1003:0\n", URLPREFS_VERSION);
        snprintf(content[3], sizeof(content[3]), "urlprefs %u\ncount 0\n[lists:0]\n[bundles:0]\n[orgs:0]\n", URLPREFS_VERSION);
        snprintf(content[4], sizeof(content[4]),
                 "urlprefs %u\n"
                 "count 3\n"
                 "[lists:1]\n"
                 "4:100:url::40000000000000000000000000000002: typo2\n"
                 "[bundles:1]\n"
                 "0:321:0:61:3F000000000000FF01::1 4:100:12:923::::::\n"
                 "[orgs:1]\n"
                 "5:0:0:365:0:1005:3\n",    /* This org has a parent org (org 3) */
                 URLPREFS_VERSION);

        // Set default options for digest store. The options_update will set the test digest directory
        digest_store_set_options(TEST_DIGEST_STORE, DIGEST_STORE_DEFAULT_UPDATE_FREQ, DIGEST_STORE_DEFAULT_MAXIMUM_AGE);
        ok(set = confset_acquire(&gen), "Acquired the conf set");
        digest_store_changed(set);

        last_timestamp = time(NULL);
        confset_release(set);
        is(system("ls " TEST_DIGEST_STORE), 0, "Listed %s/", TEST_DIGEST_STORE);

        /* Verify the handling of out-of-memory trying to malloc urlprefs on reload */
        MOCKFAIL_START_TESTS(3, URLPREFS_CLONE);
        create_atomic_file("test-urlprefs-999", "%s", content[0]);
        ok(!confset_load(NULL), "Didn't see a change to test-urlprefs-999 due to a malloc failure");
        OK_SXEL_ERROR("Couldn't allocate a urlprefs structure");
        OK_SXEL_ERROR("Couldn't clone a urlprefs conf object");
        MOCKFAIL_END_TESTS();
        unlink("test-urlprefs-999");
        is(system("ls " TEST_DIGEST_STORE), 0, "Listed %s/", TEST_DIGEST_STORE);

        diag("Verify last-good alloc failures");
        {
            /*
             * Kill off all config so that we use last-good files again
             *
             * This will verify what happens when there is an invalid prefs file,
             * but there's an allocation error reading its otherwise valid
             * last-good file.
             */
            confset_unload();
            gen           = 1;
            CONF_URLPREFS = 0;
            urlprefs_register(&CONF_URLPREFS, "urlprefs", "test-urlprefs-%u", true);

            create_atomic_file("test-urlprefs-9876", "invalid prefs file");
            create_atomic_file("test-urlprefs-9876.last-good", "%s", content[1]);

            MOCKFAIL_START_TESTS(9, conf_worker_load);
            ok(confset_load(NULL), "Didn't load test-urlprefs-9876.last-good due to newsegment failure");

            OK_SXEL_ERROR("./test-urlprefs-9876: 1: Invalid header; must contain 'urlprefs'");

            ok(set = confset_acquire(&gen), "Acquired the new config set");
            ok(urlprefs = urlprefs_conf_get(set, CONF_URLPREFS), "Got urlprefs");
            skip_if(!urlprefs, 5, "Cannot test urlprefs NULL value") {
                is(urlprefs->count, 2, "urlprefs contains 2 org");

                skip_if(urlprefs->count != 2, 4, "Not looking at urlprefs content due to incorrect count") {
                    is(urlprefs->org[0]->cs.id, 2748, "Org 2748 is present");
                    is(urlprefs->org[1]->cs.id, 9876, "Org 9876 is present");

                    ok(!urlprefs->org[1]->cs.loaded, "Org 9876 shows it was not loaded");
                    ok(urlprefs->org[1]->cs.failed_load, "Org 9876 shows a failed load");
                }
            }
            confset_release(set);
            MOCKFAIL_END_TESTS();

            unlink("test-urlprefs-9876");
            unlink("test-urlprefs-9876.last-good");
        }

        diag("Verify last-good stuff");
        {
            /* Kill off all config so that we use last-good files again */
            confset_unload();
            gen           = 1;
            CONF_URLPREFS = 0;
            urlprefs_register(&CONF_URLPREFS, "urlprefs", "test-urlprefs-%u", true);

            /* org 1 will load, org 2 won't - neither the org 2 file nor the last-good, and org 4 will load from last-good */
            create_atomic_file("test-urlprefs-1", "%s", content[0]);
            create_atomic_file("test-urlprefs-2", "%s", content[1]);    /* Broken content */
            snprintf(content[1], sizeof(content[1]), "urlprefs %u\n" "count 3\n"
                     "[lists:1]\n"   "0:1:url:71:10000000000000000000000000000000: lastgood.com/lastPath/\n"
                     "[bundles:1]\n" "0:123:0099:63:1F0000000000000000::1:::::::::\n"
                     "[orgs:1]\n"    "x2:0:0:365:0:1002:0\n", URLPREFS_VERSION);

            create_atomic_file("test-urlprefs-2.last-good", "%s", content[1]);

            /* Intentionally break org 4 and make sure the lastgood file gets used. */
            create_atomic_file("test-urlprefs-4.last-good", "%s", content[3]);
            snprintf(content[3], sizeof(content[3]), "urlprefs %u\ncount 1\n[lists:0]\n[bundles:0]\n[orgs:0]\n", URLPREFS_VERSION);
            create_atomic_file("test-urlprefs-4", "%s", content[3]);

            ok(confset_load(NULL), "Noted an update to test-urlprefs-1 and test-urlprefs-4, but test-urlprefs-2 failed");
            OK_SXEL_ERROR("./test-urlprefs-2: 8: Invalid section header 'no-identities'");
            OK_SXEL_ERROR("urlprefs v%d: ./test-urlprefs-2.last-good: 8: Unrecognised org line (invalid orgid)", URLPREFS_VERSION);
            /* parsing segment 2 (test-urlprefs-2) failed, ./test-urlprefs-2.last-good also failed */

            OK_SXEL_ERROR("urlprefs v%d: ./test-urlprefs-4: 5: Incorrect total count 1 - read 0 data lines", URLPREFS_VERSION);
            /* parsing segment 4 (test-urlprefs-4) failed, used ./test-urlprefs-4.last-good instead */

            ok(set = confset_acquire(&gen), "Reacquired the new config set");
            ok(urlprefs = urlprefs_conf_get(set, CONF_URLPREFS), "Got urlprefs");
            skip_if(!urlprefs, 8, "Cannot test urlprefs NULL value") {
                is(urlprefs->count, 4, "urlprefs contains 4 orgs");

                skip_if(urlprefs->count != 4, 7, "Not looking at urlprefs content due to incorrect count") {
                    is(urlprefs->org[0]->cs.id, 1, "Org 1 is present");
                    is(urlprefs->org[1]->cs.id, 2, "Org 2 is present");
                    is(urlprefs->org[2]->cs.id, 4, "Org 4 is present");
                    is(urlprefs->org[3]->cs.id, 2748, "Org 2748 is present");

                    ok(!urlprefs->org[1]->cs.loaded, "Org 2 shows it was not loaded");
                    ok(urlprefs->org[1]->cs.failed_load, "Org 2 shows a failed load");
                    is(prefblock_count_total(urlprefs->org[2]->fp.values), 0, "Org 4 is empty");
                }
                if (urlprefs->count != 4)
                    for (i = 0; i < urlprefs->count; i++)
                        diag("Org %u has id %u", i, urlprefs->org[i]->cs.id);
            }

            confset_release(set);
        }

        /* Verify the handling of out-of-memory trying to malloc a urlprefs-org on reload */
        MOCKFAIL_START_TESTS(4, URLPREFS_CLONE_ORGS);
        create_atomic_file("test-urlprefs-3", "we'll never even get to see this data");
        ok(!confset_load(NULL), "Didn't see a change to test-urlprefs-3 due to a urlprefs-org slot allocation failure");
        OK_SXEL_ERROR("Couldn't allocate 10 new urlprefs org slots");
        OK_SXEL_ERROR("Couldn't clone a urlprefs conf object");
        OK_SXEL_ERROR(NULL);
        MOCKFAIL_END_TESTS();

        create_atomic_file("test-urlprefs-3", "%s", content[2]);
        snprintf(content[3], sizeof(content[3]), "urlprefs %u\ncount 0\n", URLPREFS_VERSION);
        create_atomic_file("test-urlprefs-4", "%s", content[3]);
        create_atomic_file("test-urlprefs-5", "%s", content[4]);
        ok(confset_load(NULL), "Noted an update to test-urlprefs-[345]");

        create_atomic_file("test-urlprefs-4", "%s", content[3]);
        ok(confset_load(NULL), "Noted an update after test-urlprefs-4 was rewritten");

        ok(set = confset_acquire(&gen), "Acquired the new config");
        wait_next_sec();
        digest_store_changed(set);
        is(system("ls " TEST_DIGEST_STORE), 0, "Listed %s/", TEST_DIGEST_STORE);

        ok(urlprefs = urlprefs_conf_get(set, CONF_URLPREFS), "Got the URL prefs");

        if (urlprefs != NULL) {    /* Don't dump core, but if the last test failed, skip those that depend on it */
            pref_categories_t categories;
            pref_categories_t expected_categories;

            urlprefs_get_policy(urlprefs, &pr, 1, 0XBADBAD);
            ok(!PREF_VALID(&pr), "No pref for bad bundle 0xBADBAD of org 1");
            urlprefs_get_policy(urlprefs, &pr, 1, 1234);
            ok( PREF_VALID(&pr), "Got the pref for bundle 1234 of org 1");
            pref_categories_setnone(&categories);
            ok(pref_urllist_match(&pr, &categories, AT_LIST_DESTBLOCK, normalized_url,
                               normalized_url_length("my-mixed-list-proxydomain.com/somePath/"), NULL),
               "my-mixed-list-proxydomain.com/somePath/ is blocked by bundle 1234 of org 1");

            pref_categories_sscan(&expected_categories, "800000000000000000");
            ok(pref_categories_equal(&categories, &expected_categories), "Unexpected categories %s (expected 800000000000000000)",
               pref_categories_idstr(&categories));
            ok(!pref_urllist_match(&pr, &categories, AT_LIST_DESTBLOCK, normalized_url,
                                normalized_url_length("my-mixed-list-proxydomain.com/unblockedPath/"), NULL),
               "my-mixed-list-proxydomain.com/unblockedPath/ isn't blocked by bundle 1234 of org 1");

            /* Test with an org that has a parent (MSP) */
            urlprefs_get_policy(urlprefs, &pr, 5, 321);
            ok(PREF_VALID(&pr), "Got the pref_t for bundle 321 of org 5");
            ok(pref_urllist_match(&pr, &categories, AT_LIST_DESTBLOCK, normalized_url,
                               normalized_url_length("my-mixed-list-proxydomain.com/somePath/"), NULL),
               "my-mixed-list-proxydomain.com/somePath/ is blocked by bundle 321 of org 5");
        }

        confset_release(set);

        /* Test removing a file */
        unlink("test-urlprefs-1");
        ok(confset_load(NULL), "Noted an update to due to removal of test-urlprefs-1");
        ok(set = confset_acquire(&gen), "Reacquired the new config set");
        ok(urlprefs = urlprefs_conf_get(set, CONF_URLPREFS), "Got the URL prefs again");

        urlprefs_get_policy(urlprefs, &pr, 1, 1234);
        ok(!PREF_VALID(&pr), "Don't get a pref_t for bundle of deleted org 1");

        confset_release(set);

        /* Verify the handling of out-of-memory trying to realloc urlprefs-org slots on reload (realloced every 10+ slots) */
        MOCKFAIL_START_TESTS(3, URLPREFS_MOREORGS);
        snprintf(content[0], sizeof(content[0]), "urlprefs %u\ncount 0\n# Different\n", URLPREFS_VERSION);

        /* Was 106-110 in dirprefs, but bumped up due to eliminating other tests. Also, reverse order to exercise index code */
        for (orgid = 115; orgid >= 109; orgid--) {
            snprintf(buf, sizeof(buf), "test-urlprefs-%u", orgid);
            create_atomic_file(buf, "%s", content[0]);
        }

        /* Doesn't always fail. TODO: Verify that not all 10 orgs were added (using info.updates?) */
        ok(!confset_load(NULL) || 1, "Shouldn't see changes to all of test-urlprefs-106 - test-urlprefs-115 due to a urlprefs-org slot re-allocation failure");
        OK_SXEL_ERROR("Couldn't reallocate 20 urlprefs org slots");
        OK_SXEL_ERROR("Couldn't reallocate 20 urlprefs org slots");
        MOCKFAIL_END_TESTS();
        OK_SXEL_ERROR(NULL);
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
