#include <dirent.h>
#include <fcntl.h>
#include <kit-alloc.h>
#include <kit-random.h>
#include <mockfail.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tap.h>

#include "cidrlist.h"
#include "conf-loader.h"
#include "digest-store.h"
#include "dns-name.h"
#include "lists-private.h"
#include "urllist-private.h"
#include "urlprefs-org.h"
#include "urlprefs.h"

#include "common-test.h"

static void
unlink_test_files(void)
{
    unsigned i;
    char     rmfn[32];

    for (i = 0; i <= 10; i++) {
        snprintf(rmfn, sizeof(rmfn), "test-lists-%u", i);
        unlink(rmfn);
        snprintf(rmfn, sizeof(rmfn), "test-lists-%u.last-good", i);
        unlink(rmfn);
    }

    unlink("test-lists-2748");
}

int
main(void)
{
    struct conf_loader  cl;
    module_conf_t       reg;
    struct conf_info   *info;
    const struct lists *lists;
    struct lists_org   *org;
    struct confset     *set;
    const char         *fn;
    uint64_t            start_allocations;
    unsigned            i;
    int                 gen, lines;
    char                content[4][4096];

    plan_tests(168);

    #ifdef __FreeBSD__
        plan_skip_all("DPT-186 - Need to implement inotify as dtrace event");
        exit(0);
    #endif

    kit_random_init(open("/dev/urandom", O_RDONLY));
    conf_initialize(".", ".", false, NULL);
    conf_loader_init(&cl);
    gen = 0;

    kit_memory_initialize(false);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");
    KIT_ALLOC_SET_LOG(0);    // Turn off when done

    unlink_test_files();

    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */

    diag("Test missing file load");
    {
        info = conf_info_new(NULL, "noname", "nopath", NULL, LOADFLAGS_NONE, NULL, 0);
        info->updates++;

        conf_loader_open(&cl, "/tmp/not-really-there", NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(1, &cl, info);
        ok(!org, "Failed to read non-existent file");
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

        is(memory_allocations(), start_allocations, "All memory allocations were freed");
    }

    info = conf_info_new(NULL, "lists", "test-lists", NULL, LOADFLAGS_LISTS, NULL, 0);

    diag("Test empty files");
    {
        fn   = create_data("test-lists", "%s", "");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(!org, "Failed to read empty file");
        OK_SXEL_ERROR(": No content found");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-lists", "lists 1\ncount 0\n[lists:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(org, "Read file with empty [lists] section");
        lists_org_refcount_dec(org);
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-lists", "lists 1\ncount 0\n# No lists section header\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(org, "Read file with valid file header, missing [lists] section");
        lists_org_refcount_dec(org);
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-lists", "lists 1\ncount 0\n[lists:0]\n[identities:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(!org, "Failed to read file empty [lists] section followed by empty [identities]");
        OK_SXEL_ERROR(": 4: Invalid section header 'identities'");
        OK_SXEL_ERROR(NULL);
    }

    diag("Test garbage files");
    {
        fn = create_data("test-lists", "This is not the correct format\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(!org, "Failed to read garbage file");
        OK_SXEL_ERROR(": Invalid header; must contain 'lists'");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-lists", "lists 1\ncount 1\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(!org, "Failed to read file with EOF before lists are done");
        OK_SXEL_ERROR(": 2: EOF with 1 of 1 lists remaining");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-lists", "lists 1\ncount 1\n[lists:1]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(!org, "Failed to read file with EOF before lists are done");
        OK_SXEL_ERROR(": 3: Unexpected EOF - read 0 [lists] items, not 1");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-lists", "lists 1\ncount 1\n[lists:1]\n[garbage:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(!org, "Failed to read file with [garbage] header before lists are done");
        OK_SXEL_ERROR(": 4: Unexpected [garbage] header - read 0 [list] items, not 1");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-lists", "lists 1\ncount 0\n[lists:1]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(!org, "Failed to read file with count 0 and EOF before lines are done");
        OK_SXEL_ERROR(": 3: Unexpected EOF - read 0 [lists] items, not 1");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-lists", "lists 1\ncount 1\n[lists:1]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(!org, "Failed to read file with count 1 and EOF before lists are done");
        OK_SXEL_ERROR(": 3: Unexpected EOF - read 0 [lists] items, not 1");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-lists", "lists 1\ncount 1\n[identities:1]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(!org, "Failed to read file with count 1 and identities before lists");
        OK_SXEL_ERROR(": 3: Invalid section header 'identities'");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-lists", "lists 1\ncount 1\n[lists:1x]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(!org, "Failed to read file with bad list header count");
        OK_SXEL_ERROR(": 3: Invalid section header count");
        OK_SXEL_ERROR(NULL);

        // The following test used to verify that lists couldn't be skipped. Now, lists can only contain list sections
        fn = create_data("test-lists", "lists 1\ncount 1\n[lists:0]\n[settinggroup:1]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(!org, "Failed to read file with bad list header count");
        OK_SXEL_ERROR(": 4: Invalid section header 'settinggroup'");
        OK_SXEL_ERROR(NULL);

        conf_loader_fini(&cl);
    }

    diag("Test V%u data load", LISTS_VERSION - 1);
    {
        fn = create_data("test-lists", "lists %u\ncount 0\n", LISTS_VERSION - 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(!org, "Failed to read version %u data", LISTS_VERSION - 1);
        OK_SXEL_ERROR(": 1: Invalid header version(s); must be numeric");    // Only because 0 is not a valid version
        OK_SXEL_ERROR(NULL);
    }

    diag("Test V%u data load", LISTS_VERSION + 1);
    {
        fn = create_data("test-lists", "lists %u\ncount 0\n", LISTS_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(!org, "Failed to read version %u data", LISTS_VERSION + 1);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [1]");
        OK_SXEL_ERROR(NULL);
    }

    diag("Test V%u data loadS with future V%u", LISTS_VERSION, LISTS_VERSION + 1);
    {
        fn = create_data("test-lists", "lists %u %u\ncount 1\n[lists:0:%u]\n[lists:1:%u]\nnew weird format\n[zork:0:%u]\n",
                         LISTS_VERSION, LISTS_VERSION + 1, LISTS_VERSION, LISTS_VERSION + 1, LISTS_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(org, "Read version %u data despite wonky version %u data", LISTS_VERSION, LISTS_VERSION + 1);
        lists_org_refcount_dec(org);
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-lists", "lists %u %u\ncount 0\n[lists:0]\n[zork:0:%u]\n", LISTS_VERSION, LISTS_VERSION + 1,
                         LISTS_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = lists_org_new(0, &cl, info);
        unlink(fn);
        ok(org, "Read version %u data with unversioned list data despite wonky version %u data", LISTS_VERSION,
           LISTS_VERSION + 1);
        lists_org_refcount_dec(org);
        OK_SXEL_ERROR(NULL);
    }

    conf_info_free(info);
    conf_loader_fini(&cl);
    is(memory_allocations(), start_allocations, "All memory allocations were freed after out-of-version-range tests");
    digest_store_set_options("lists-digest-dir", 1, DIGEST_STORE_DEFAULT_MAXIMUM_AGE);

    lists_register(&CONF_LISTS, "lists", "test-lists-%u", true);
    reg = 0;
    lists_register(&reg, "lists", "test-more-lists-%u", true);
    is(reg, 0, "Cannot register lists twice by name");
    OK_SXEL_ERROR("lists: Config name already registered as ./test-lists-%%u");
    OK_SXEL_ERROR(NULL);

    diag("Test V%u empty data load", LISTS_VERSION);
    {
        snprintf(content[0], sizeof(content[0]), "lists %u\ncount 0\n%s", LISTS_VERSION, "[lists:0]\n");
        create_atomic_file("test-lists-1", "%s", content[0]);

        ok(confset_load(NULL), "Noted an update to test-lists-1 item %u", i);
        ok(!confset_load(NULL), "A second confset_load() call results in nothing");
        ok(set = confset_acquire(&gen), "Acquired the new config");

        skip_if(set == NULL, 8, "Cannot check content without acquiring config") {
            lists = lists_conf_get(set, CONF_LISTS);
            ok(lists, "Constructed lists from empty V%u data", LISTS_VERSION);

            skip_if(lists == NULL, 7, "Cannot check content of NULL lists") {
                is(lists->count, 1, "V%u data has a count of 1 list", LISTS_VERSION);
                is(lists->conf.refcount, 2, "V%u data has a refcount of 2", LISTS_VERSION);

                skip_if(!lists->count, 1, "Cannot verify org count")
                    ok(lists->orgs[0]->lists == NULL, "V%u data has a NULL lists", LISTS_VERSION);

                ok(org = lists_find_org(lists, 1), "Found org 1 in the list");

                skip_if (!org, 3, "Skipping tests that need an org") {
                    diag("Test lookups in an org that has no lists");

                    struct netaddr ipaddr;
                    const uint8_t *name   = (const uint8_t *)"\6amazon\3com";
                    const uint8_t *match  = (const uint8_t *)"\2no\5match";
                    const char    *url    = "amazon.com/shopping/books";
                    unsigned       length = 0;
                    uint32_t       listid;

                    netaddr_from_str(&ipaddr, "5.6.7.8", AF_INET);
                    is(lists_org_lookup_domainlist(org, NULL, 0, 0, name, &listid, &match, NULL), 0, "Can't lookup domain name");
                    is(lists_org_lookup_urllist(org, NULL, 0, 0, url, strlen(url), &listid, &length, NULL), 0, "Can't lookup URL");
                    is(lists_org_lookup_cidrlist(org, NULL, 0, 0, &ipaddr, &listid, &length, NULL), 0, "Can't lookup CIDR");
                }
            }

            confset_release(set);
            is(lists ? lists->conf.refcount : 0, 1, "confset_release() dropped the refcount back to 1");
        }
    }

    diag("Test V%u data load with extra lines after lists section", LISTS_VERSION);
    {
        create_atomic_file("test-lists-1", "lists %u\nextra garbage\ncount 0\n[lists:0]\n", LISTS_VERSION);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with extra garbage", LISTS_VERSION);
        OK_SXEL_ERROR(": Invalid count; must begin with 'count '");

        create_atomic_file("test-lists-1", "lists %u\ncount 0\nextra garbage\n[lists:0]\n", LISTS_VERSION);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with extra garbage", LISTS_VERSION);
        OK_SXEL_ERROR(": Unrecognized line, expected section header");

        create_atomic_file("test-lists-1", "lists %u\ncount 0\n[lists:0]\nextra garbage\n", LISTS_VERSION);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with extra garbage", LISTS_VERSION);
        OK_SXEL_ERROR(": Unrecognized line, expected section header");

        OK_SXEL_ERROR(NULL);
    }

    diag("Test V%u data load with an invalid count line", LISTS_VERSION);
    {
        create_atomic_file("test-lists-2748", "lists %u\nwrong\n", LISTS_VERSION);
        ok(!confset_load(NULL), "Noted no update; Missing version %u count line", LISTS_VERSION);
        OK_SXEL_ERROR("test-lists-2748: 2: Invalid count; must begin with 'count '");
    }

    diag("Test V%u data load with bad list lines", LISTS_VERSION);
    {
        create_atomic_file("test-lists-2748", "lists %u\ncount 1\n[lists:1]\nnot a valid list\n", LISTS_VERSION);
        ok(!confset_load(NULL), "Noted no update; Failed to read bad list line");
        OK_SXEL_ERROR("test-lists-2748: 4: Unrecognised list line (invalid id:)");
    }

    diag("Test V%u data load with bad list lines", LISTS_VERSION);
    {
        create_atomic_file("test-lists-2748", "lists %u\ncount 1\n[lists:1]\nnot a valid list\n", LISTS_VERSION);
        ok(!confset_load(NULL), "Noted no update; Failed to read bad list line");
        OK_SXEL_ERROR("test-lists-2748: 4: Unrecognised list line (invalid id:)");
    }

    diag("Test V%u data load with various memory allocation failures", LISTS_VERSION);
    {
        snprintf(content[0], sizeof(content[0]), "lists %u\ncount 0\n%s", LISTS_VERSION, "[lists:0]\n");

        MOCKFAIL_START_TESTS(3, LISTS_CLONE);
        create_atomic_file("test-lists-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR("Couldn't allocate a lists structure");
        OK_SXEL_ERROR("Couldn't clone a lists conf object");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(3, LISTS_CLONE_LISTS_ORGS);
        create_atomic_file("test-lists-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR("Couldn't allocate 10 new lists org slots");
        OK_SXEL_ERROR("Couldn't clone a lists conf object");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(2, lists_org_new);
        create_atomic_file("test-lists-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR("Cannot allocate 80 bytes for a lists_org object");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(4, LISTS_MORE_LISTS_ORGS);
        char filename[32];

        for (i = 1; i <= 10; i++) {
            snprintf(filename, sizeof(filename), "test-lists-%u", i);
            create_atomic_file(filename, "%s", content[0]);
        }

        ok(confset_load(NULL), "Noted an update");
        OK_SXEL_ERROR(NULL);
        create_atomic_file("test-lists-0", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR("Couldn't reallocate 20 lists org slots");
        MOCKFAIL_END_TESTS();

        create_atomic_file("test-lists-0", "%s", content[0]);    // Actually insert out of order to cover this case
        ok(confset_load(NULL), "Noted an update");

        snprintf(content[0], sizeof(content[0]), "lists %u\ncount 1\n%s", LISTS_VERSION,
                 "[lists:1]\n11111:domain:70:0000000000000000000000000000000000000001:amazon.com google.com\n");

        MOCKFAIL_START_TESTS(2, prefbuilder_alloclist);
        create_atomic_file("test-lists-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR("Failed to realloc prefbuilder list block to 1 elements");
        MOCKFAIL_END_TESTS();

        unlink_test_files();
        ok(confset_load(NULL), "Noted an update");
    }

    OK_SXEL_ERROR(NULL);
    test_uncapture_sxel();    // Stop capturing errors

    diag("Test V%u data handling", LISTS_VERSION);
    {
        create_atomic_file("test-lists-1",
            "lists %u\n"
            "count 8\n"
            "[lists:8]\n"
            "11111:domain:70:0000000000000000000000000000000000000001:amazon.com google.com\n"
            "11112:application:42:151:07:1\n"    // Just to make sure this is skipped
            "22222:url:71:0000000000000000000000000000000000000002:amazon.com/shopping/books google.com/news/us\n"
            "33333:url:72:0000000000000000000000000000000000000003:amazon.com/shopping google.com/news\n"
            "44444:domain::0000000000000000000000000000000000000004:shopping.amazon.com\n"    // Verify that no bits is OK
            "55555:url:152:0000000000000000000000000000000000000005:amazon.com/shopping/books\n"
            "66666:cidr:99:0000000000000000000000000000000000000006:5.6.7.0/24\n"
            "77777:cidr:100:0000000000000000000000000000000000000007:0.0.0.0/0\n",
            LISTS_VERSION);
        ok(confset_load(NULL), "Noted an update to test-lists-1");
        ok(set = confset_acquire(&gen), "Acquired the config set that includes urlprefs");

        skip_if (!set, 59, "Tests that need the config set") {
            ok(lists = lists_conf_get(set, CONF_LISTS), "Extracted the lists from the confset");

            skip_if (!lists, 58, "Tests that need the lists") {
                is(lists_find_org(lists, 2), NULL, "Didn't find org 2; there can only be 1");
                ok(org = lists_find_org(lists, 1), "Found org 1 in the list");

                skip_if (!org, 56, "Tests that need the org") {
                    diag("Test unfiltered domainlist lookups");

                    const uint8_t *name  = (const uint8_t *)"\6amazon\3com";
                    const uint8_t *match = (const uint8_t *)"\2no\5match";
                    unsigned       next;
                    uint32_t       listid;
                    uint8_t        bit;

                    next = lists_org_lookup_domainlist(org, NULL, 0, 0, name, &listid, &match, &bit);
                    is(next,                      1,     "amazon.com matched in list slot 0");
                    is(listid,                    11111, "listid is 11111");
                    is(bit,                       70,    "bit is 70");
                    is(dns_name_cmp(name, match), 0,     "matched name is amazon.com");

                    next = lists_org_lookup_domainlist(org, NULL, 0, next, name, &listid, &match, NULL);
                    is(next, 0, "amazon.com found in no other domainlist");

                    diag("Test unfiltered domainlist lookups with subdomain matching");

                    name  = (const uint8_t *)"\x8shopping\6amazon\3com";
                    match = (const uint8_t *)"\2no\5match";

                    next = lists_org_lookup_domainlist(org, NULL, 0, 0, name, &listid, &match, &bit);
                    is(next,                                                  1,     "shopping.amazon.com matched in list slot 0");
                    is(listid,                                                11111, "listid is 11111");
                    is(bit,                                                   70,    "bit is 70");
                    is(dns_name_cmp((const uint8_t *)"\6amazon\3com", match), 0,     "matched name is amazon.com");

                    next = lists_org_lookup_domainlist(org, NULL, 0, next, name, &listid, &match, &bit);
                    is(next,                      4,     "shopping.amazon.com matched in list slot 3");
                    is(listid,                    44444, "listid is 44444");
                    is(bit,                       0,     "bit is 0 (empty)");
                    is(dns_name_cmp(name, match), 0,     "matched name is shopping.amazon.com");

                    next = lists_org_lookup_domainlist(org, NULL, 0, next, name, &listid, &match, NULL);
                    is(next, 0, "shopping.amazon.com matched in no other domainlist");

                    diag("Test filtered domainlist lookups with subdomain matching");

                    name              = (const uint8_t *)"\x8shopping\6amazon\3com";
                    match             = (const uint8_t *)"\2no\5match";
                    unsigned subset[] = {11111, 55555, 66666};
                    unsigned count    = sizeof(subset) / sizeof(subset[0]);

                    next = lists_org_lookup_domainlist(org, subset, count,  0, name, &listid, &match, &bit);
                    is(next,                                                  4,     "shopping.amazon.com matched in subset 0 in list slot 0");
                    is(listid,                                                11111, "listid is 11111");
                    is(bit,                                                   70,    "bit is 70");
                    is(dns_name_cmp((const uint8_t *)"\6amazon\3com", match), 0,     "matched name is amazon.com");

                    next = lists_org_lookup_domainlist(org, subset, count, next, name, &listid, &match, NULL);
                    is(next, 0, "shopping.amazon.com matched in no other domainlist in {11111, 55555, 66666}");

                    diag("Test unfiltered urllist lookups");

                    const char *url    = "amazon.com/shopping/books";
                    unsigned    length = 0;

                    next = lists_org_lookup_urllist(org, NULL, 0, 0, url, strlen(url), &listid, &length, &bit);
                    is(next,   2,           "amazon.com/shopping/books matched in list slot 1");
                    is(listid, 22222,       "listid is 22222");
                    is(bit,    71,          "bit is 71");
                    is(length, strlen(url), "matched url is amazon.com/shopping/books");

                    next = lists_org_lookup_urllist(org, NULL, 0, next, url, strlen(url), &listid, &length, &bit);
                    is(next,   3,                             "amazon.com/shopping/books matched in list slot 2");
                    is(listid, 33333,                         "listid is 33333");
                    is(bit,    72,                            "bit is 72");
                    is(length, strlen("amazon.com/shopping"), "matched url is amazon.com/shopping");

                    next = lists_org_lookup_urllist(org, NULL, 0, next, url, strlen(url), &listid, &length, &bit);
                    is(next,   5,           "amazon.com/shopping/books matched in list slot 4");
                    is(listid, 55555,       "listid is 55555");
                    is(bit,    152,         "bit is 152");
                    is(length, strlen(url), "matched url is amazon.com/shopping/books");

                    next = lists_org_lookup_urllist(org, NULL, 0, next, url, strlen(url), &listid, &length, NULL);
                    is(next, 0, "amazon.com/shopping/books matched in no other urllist");

                    diag("Test filtered urllist lookups");

                    length    = 0;
                    subset[0] = 33333;    // Making subset {33333. 55555, 66666}

                    next = lists_org_lookup_urllist(org, subset, count, 0, url, strlen(url), &listid, &length, &bit);
                    is(next,   3 * count + 1,                 "amazon.com/shopping/books matched subset 0 in list slot 2");
                    is(listid, 33333,                         "listid is 33333");
                    is(bit,    72,                            "bit is 72");
                    is(length, strlen("amazon.com/shopping"), "matched url is amazon.com/shopping");

                    next = lists_org_lookup_urllist(org, subset, count, next, url, strlen(url), &listid, &length, &bit);
                    is(next,   5 * count + 2, "amazon.com/shopping/books matched subset 1 in list slot 4");
                    is(listid, 55555,         "listid is 55555");
                    is(bit,    152,           "bit is 152");
                    is(length, strlen(url),   "matched url is amazon.com/shopping/books");

                    next = lists_org_lookup_urllist(org, subset, count, next, url, strlen(url), &listid, &length, NULL);
                    is(next, 0, "amazon.com/shopping/books matched in no other urllist in {33333, 55555, 66666}");

                    diag("Test unfiltered cidrlist lookups");

                    struct netaddr ipaddr;

                    netaddr_from_str(&ipaddr, "5.6.7.8", AF_INET);
                    length = 0;

                    next = lists_org_lookup_cidrlist(org, NULL, 0, 0, &ipaddr, &listid, &length, &bit);
                    is(next,   6,     "5.6.7.8 matched in list slot 5");
                    is(listid, 66666, "listid is 66666");
                    is(bit,    99,    "bit is 99");
                    is(length, 24,    "matched cidr is 5.6.7.0/24");

                    next = lists_org_lookup_cidrlist(org, NULL, 0, next, &ipaddr, &listid, &length, &bit);
                    is(next,   7,              "5.6.7.8 matched in list slot 6");
                    is(listid, 77777,          "listid is 77777");
                    is(bit,    100,            "bit is 100");
                    is(length, CIDR_MATCH_ALL, "matched cidr is 0.0.0.0/0 (match all)");

                    next = lists_org_lookup_cidrlist(org, NULL, 0, next, &ipaddr, &listid, &length, NULL);
                    is(next, 0, "5.6.7.8 found in no other cidrlist");

                    diag("Test filtered cidrlist lookups");

                    length = 0;

                    next = lists_org_lookup_cidrlist(org, subset, count, 0, &ipaddr, &listid, &length, &bit);
                    is(next,   6 * 3 + 3, "5.6.7.8 matched element 2 list slot 5");
                    is(listid, 66666,     "listid is 66666");
                    is(bit,    99,        "bit is 99");
                    is(length, 24,        "matched cidr is 5.6.7.0/24");

                    next = lists_org_lookup_cidrlist(org, subset, count, next, &ipaddr, &listid, &length, NULL);
                    is(next, 0, "5.6.7.8 found in no other cidrlist in {33333, 55555, 66666}");

                    diag("Test with a listid in the subset that is greater than any in the lists org");
                    subset[2] = 88888;
                    next      = lists_org_lookup_cidrlist(org, subset, count, 0, &ipaddr, &listid, &length, &bit);
                    is(next, 0, "5.6.7.8 found in cidrlist in {33333, 55555, 88888}");
                }

                diag("Test the digest store directory");
                is(rrmdir("lists-digest-dir"), 0, "Removed lists-digest-dir with no errors");
                is(mkdir("lists-digest-dir", 0755), 0, "Created lists-digest-dir");
                digest_store_changed(set);
                diag("Looking at the lists-digest-dir directory");
                lines = showdir("lists-digest-dir", stdout);
                is(lines, 1, "Found 1 line of data (for 1 list file)");

                confset_release(set);
            }
        }

        unlink("test-lists-1");
        ok(confset_load(NULL), "Noted an update for the test-lists-1 removal");
    }

    OK_SXEL_ERROR(NULL);
    confset_unload();
    fileprefs_freehashes();
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    /* KIT_ALLOC_SET_LOG(0); */

    unlink_test_files();

    return exit_status();
}
