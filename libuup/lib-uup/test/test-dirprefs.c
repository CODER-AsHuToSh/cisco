#include <fcntl.h>
#include <kit-alloc.h>
#include <kit-random.h>
#include <mockfail.h>
#include <sys/stat.h>

#include "digest-store.h"
#include "dirprefs-private.h"
#include "odns.h"

#include "common-test.h"

#ifdef __FreeBSD__
#define FreeBSD __FreeBSD__
#else
#define FreeBSD 0
#endif

int
main(void)
{
    pref_categories_t expected_categories;
    char buf[4096], content[5][4096];
    uint64_t start_allocations;
    struct prefidentity *ident;
    struct prefbundle *bundle;
    const struct preforg *org;
    const struct dirprefs *dp;
    struct conf_info *info;
    enum dirprefs_type dt;
    struct conf_loader cl;
    struct prefs_org *dpo;
    struct confset *set;
    struct oolist *ids;
    unsigned org_slot;
    module_conf_t reg;
    struct odns odns;
    uint32_t orgid;
    const char *fn;
    int gen, lines;
    unsigned z;
    pref_t pr;

    plan_tests(321);
#ifdef __FreeBSD__
    plan_skip_all("DPT-186 - Need to implement inotify as dtrace event");
    exit(0);
#endif

    kit_random_init(open("/dev/urandom", O_RDONLY));
    conf_initialize(".", ".", false, NULL);
    conf_loader_init(&cl);
    ids = oolist_new();
    gen = 0;

    kit_memory_initialize(false);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */

    diag("Test missing file load");
    {
        info = conf_info_new(NULL, "noname", "nopath", NULL, LOADFLAGS_FP_ALLOW_BUNDLE_EXTREFS, NULL, 0);
        info->updates++;

        skip_if(FreeBSD, 3, "read(2) on FreeBSD can read directories") {
            conf_loader_open(&cl, "/tmp", NULL, NULL, 0, CONF_LOADER_DEFAULT);
            dpo = dirprefs_org_new(0, &cl, info);
            ok(!dpo, "Failed to read a directory as a file");
            OK_SXEL_ERROR("Is a directory");
            OK_SXEL_ERROR("/tmp: No content found");
        }

        conf_loader_open(&cl, "/tmp/not-really-there", NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dpo = dirprefs_org_new(0, &cl, info);
        ok(!dpo, "Failed to read non-existent file");
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
        is(memory_allocations(), start_allocations, "All memory allocations were freed");
    }

    info = conf_info_new(NULL, "dirprefs", "test0-dirprefs", NULL, LOADFLAGS_FP_ALLOW_BUNDLE_EXTREFS, NULL, 0);

    diag("Test empty file");
    {
        fn = create_data("test-dirprefs", "%s", "");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dpo = dirprefs_org_new(0, &cl, info);
        unlink(fn);
        ok(!dpo, "Failed to read empty file");
        OK_SXEL_ERROR("No content found");
        OK_SXEL_ERROR(NULL);
    }

    diag("Test garbage file");
    {
        fn = create_data("test-dirprefs", "This is not the correct format\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dpo = dirprefs_org_new(0, &cl, info);
        unlink(fn);
        ok(!dpo, "Failed to read garbage file");
        OK_SXEL_ERROR(": 1: Invalid header; must contain 'dirprefs'");
    }

    diag("Test V%u data load", DIRPREFS_VERSION - 1);
    {
        fn = create_data("test-dirprefs", "dirprefs %u\ncount 0\n", DIRPREFS_VERSION - 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dpo = dirprefs_org_new(0, &cl, info);
        unlink(fn);
        ok(!dpo, "Failed to read version %u data", DIRPREFS_VERSION - 1);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [");
    }

    diag("Test V%u data load", DIRPREFS_VERSION + 1);
    {
        fn = create_data("test-dirprefs", "dirprefs %u\ncount 0\n", DIRPREFS_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dpo = dirprefs_org_new(0, &cl, info);
        unlink(fn);
        ok(!dpo, "Failed to read version %u data", DIRPREFS_VERSION + 1);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [");
    }

    conf_info_free(info);
    conf_loader_fini(&cl);

    /* KIT_ALLOC_SET_LOG(1); */
    is(memory_allocations(), start_allocations, "All memory allocations were freed after out-of-version-range tests");

    diag("Create some unreadable V%u files", DIRPREFS_VERSION);
    {
        snprintf(content[0], sizeof(content[0]), "dirprefs %u\ncount 0\n", DIRPREFS_VERSION);
        create_atomic_file("test-dirprefs-666", "%s", content[0]);
        create_atomic_file("test-dirprefs-666.last-good", "%s", content[0]);
        ok(chmod("test-dirprefs-666", 0220) == 0, "Changed permissions of test-dirprefs-666 to 0220");
        ok(chmod("test-dirprefs-666.last-good", 0220) == 0, "Changed permissions of test-dirprefs-666.last-good to 0220");
    }

    dirprefs_register(&CONF_DIRPREFS, "dirprefs", "test-dirprefs-%u", true);
    reg = 0;
    dirprefs_register(&reg, "dirprefs", "test-more-dirprefs-%u", true);
    is(reg, 0, "Cannot register dirprefs twice by name");
    OK_SXEL_ERROR("dirprefs: Config name already registered as ./test-dirprefs-%%u");

    diag("Test V%u data load with unreadable files", DIRPREFS_VERSION);
    {
        /* parsing segment 666 (./test-dirprefs-666) failed, ./test-dirprefs-666.last-good cannot be opened */
        ok(confset_load(NULL), "Noted an update to test-dirprefs-666 - failed to read, last-good not readable");
        OK_SXEL_ERROR("test-dirprefs-666 could not be opened: Permission denied");
        OK_SXEL_ERROR("test-dirprefs-666.last-good could not be opened: Permission denied");
        OK_SXEL_ERROR(NULL);

        ok(set = confset_acquire(&gen), "Acquired the failed confset");
        ok(dp = dirprefs_conf_get(set, CONF_DIRPREFS), "Got dirprefs");
        skip_if(!dp, 4, "Skipping dirprefs tests due to NULL dirprefs") {
            is(dp->count, 1, "dirprefs has a single entry");
            skip_if(dp->count != 1, 3, "Not looking at dirprefs content due to incorrect count") {
                is(dp->org[0]->cs.id, 666, "Org 666 is present in dirprefs");
                ok(!dp->org[0]->cs.loaded, "Org 2 shows it was not loaded");
                ok(dp->org[0]->cs.failed_load, "Org 2 shows a failed load");
            }
        }
        confset_release(set);

        // Set default options for digest store.
        digest_store_set_options("dirprefs-digest-dir", DIGEST_STORE_DEFAULT_UPDATE_FREQ, DIGEST_STORE_DEFAULT_MAXIMUM_AGE);

        unlink("test-dirprefs-666");
        unlink("test-dirprefs-666.last-good");
        ok(confset_load(NULL), "Cleared test-dirprefs-666");
    }

    /* setup digest_store_dir */
    is(rrmdir("dirprefs-digest-dir"), 0, "Removed dirprefs-digest-dir with no errors");
    is(mkdir("dirprefs-digest-dir", 0755), 0, "Created dirprefs-digest-dir");
    ok(set = confset_acquire(&gen), "Acquired the conf set");

    skip_if(!set, 1, "Cannot call digest_store_changed() with no set") {
        digest_store_changed(set);
        diag("Looking at the dirprefs-digest-dir directory");
        lines = showdir("dirprefs-digest-dir", stdout);
        is(lines, 0, "Found 0 lines of data (there are no files yet)");
        confset_release(set);
    }

    is(rrmdir("dirprefs-digest-dir"), 0, "Removed dirprefs-digest-dir with no errors");

    diag("Test V%u empty data load", DIRPREFS_VERSION);
    {
        snprintf(content[0], sizeof(content[0]), "dirprefs %u\ncount 0\n%s", DIRPREFS_VERSION, "");
        snprintf(content[1], sizeof(content[1]), "dirprefs %u\ncount 0\n%s", DIRPREFS_VERSION,
                 "[lists:0]\n[bundles:0]\n[orgs:0]\n[identities:0]\n");
        snprintf(content[2], sizeof(content[2]), "dirprefs %u\ncount 0\n%s", DIRPREFS_VERSION,
                 "[lists:0]\n[settinggroup:0]\n[bundles:0]\n[orgs:0]\n[identities:0]\n");

        for (z = 0; z < 3; z++) {
            create_atomic_file("test-dirprefs-1", "%s", content[z]);

            ok(confset_load(NULL), "Noted an update to test-dirprefs-1 item %u", z);
            ok(!confset_load(NULL), "A second confset_load() call results in nothing");
            ok(set = confset_acquire(&gen), "Acquired the new config");
            skip_if(set == NULL, 5, "Cannot check content without acquiring config") {
                dp = dirprefs_conf_get(set, CONF_DIRPREFS);
                ok(dp, "Constructed struct dirprefs from empty V%u data", DIRPREFS_VERSION);
                skip_if(dp == NULL, 3, "Cannot check content of NULL struct dirprefs") {
                    is(dp->count, 1, "V%u data has a count of 1 org", DIRPREFS_VERSION);
                    is(dp->conf.refcount, 2, "V%u data has a refcount of 2", DIRPREFS_VERSION);
                    skip_if(!dp->count, 1, "Cannot verify org count")
                        is(dp->org[0]->fp.total, 0, "V%u data has a record count of 0", DIRPREFS_VERSION);
                }
                confset_release(set);
                is(dp ? dp->conf.refcount : 0, 1, "confset_release() dropped the refcount back to 1");
            }
        }
    }

    diag("Test V%u data load with extra lines after each section", DIRPREFS_VERSION);
    {
        const char *data[] = { "[lists:0]\n", "[settinggroup:0]\n", "[bundles:0]\n", "[orgs:0]\n", "[identities:0]\n" };
        const char *extra = "extra-garbage\n";
        const char *l[6];
        char err[256];
        unsigned i;

        create_atomic_file("test-dirprefs-1", "dirprefs %u\ncount 0\n%s%s%s%s%s", DIRPREFS_VERSION, data[0], data[1], data[2], data[3], data[4]);
        ok(confset_load(NULL), "Noted an update for koshir v%u data", DIRPREFS_VERSION);

        for (z = 0; z < 5; z++) {
            for (i = 0; i <= z; i++)
                l[i] = data[i];
            l[i] = extra;
            snprintf(err, sizeof(err), "test-dirprefs-1: %u: Invalid section header", i + 3);
            for (; i < 6; i++)
                l[i] = data[i - 1];
            create_atomic_file("test-dirprefs-1", "dirprefs %u\ncount 0\n%s%s%s%s%s%s", DIRPREFS_VERSION, l[0], l[1], l[2], l[3], l[4], l[5]);
            ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with extra garbage", DIRPREFS_VERSION);
            OK_SXEL_ERROR(err);
        }
    }

    diag("Test V%u data load with missing lines", DIRPREFS_VERSION);
    {
        const char *data = "[bundles:1]\n" "0:1:0:32:1400000000007491CD:::::::::::\n" "[orgs:1]\n" "2748:0:0:365:0:1002748:0\n" "[identities:1]\n";
        const char *identity = "00000001:0::0:22:2748:0:1\n";
        const char *trunc = "00000001:0:\n";

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 3\n%s%s", DIRPREFS_VERSION, data, identity);
        ok(confset_load(NULL), "Noted an update; Read valid version %u data", DIRPREFS_VERSION);

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 3\n%s%s", DIRPREFS_VERSION, data, trunc);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with truncated ident", DIRPREFS_VERSION);
        OK_SXEL_ERROR(": 8: Unrecognised line (invalid key format)");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 3\n%s", DIRPREFS_VERSION, data);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with missing ident", DIRPREFS_VERSION);
        OK_SXEL_ERROR(": 7: Unexpected EOF - read 0 [identities] items, not 1");
    }

    diag("Test V%u data load with invalid key format", DIRPREFS_VERSION);
    {
        const char *data = "[bundles:1]\n" "0:1:0:32:1400000000007491CD:::::::::::\n" "[orgs:1]\n" "2748:0:0:365:0:1002748:0\n" "[identities:1]\n";
        const char *valid_identity = "00000001:0::0:22:2748:0:1\n";
        const char *invalid_identity = "00000001:4::0:7:2748:0:1\n";

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 3\n%s%s", DIRPREFS_VERSION, data, valid_identity);
        ok(confset_load(NULL), "Noted an update; Read valid version %u data", DIRPREFS_VERSION);

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 3\n%s%s", DIRPREFS_VERSION, data, invalid_identity);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with invalid key format", DIRPREFS_VERSION);
        OK_SXEL_ERROR(": 8: Unrecognised line (invalid key format)");
    }

    diag("Test V%u data load with invalid alt-uid format", DIRPREFS_VERSION);
    {
        const char *data = "[bundles:1]\n" "0:1:0:32:1400000000007491CD:::::::::::\n" "[orgs:1]\n" "2748:0:0:365:0:1002748:0\n";
        const char *identity = "[identities:1]\n";
        const char *valid_alt_uid = "00000001:3:H0123456789abcdef0123456789abcdef:0:22:2748:0:1\n";
        const char *invalid_alt_uid = "00000001:3:invalid:0:22:2748:0:1\n";
        const char *invalid_alt_uid_type = "00000001:3:G0123456789abcdef0123456789abcdef:0:22:2748:0:1\n";
        const char *not_sorted_alt_uid = "[identities:2]\n"
                                         "00000001:3:H0123456789abcdef0123456789abcdef:0:22:2748:0:1\n"
                                         "00000001:3:H0000456789abcdef0123456789abcdef:0:22:2748:0:1\n";
        const char *duplicate_alt_uid = "[identities:2]\n"
                                         "00000001:3:H0123456789abcdef0123456789abcdef:0:22:2748:0:1\n"
                                         "00000001:3:H0123456789abcdef0123456789abcdef:0:22:2748:0:1\n";

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 3\n%s%s%s", DIRPREFS_VERSION, data, identity, valid_alt_uid);
        ok(confset_load(NULL), "Noted an update; Read valid version %u data with valid alt-uid", DIRPREFS_VERSION);

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 3\n%s%s%s", DIRPREFS_VERSION, data, identity, invalid_alt_uid);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with invalid alt-uid format", DIRPREFS_VERSION);
        OK_SXEL_ERROR(": 8: Unrecognised line (invalid key format)");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 3\n%s%s%s", DIRPREFS_VERSION, data, identity, invalid_alt_uid_type);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with invalid alt-uid type", DIRPREFS_VERSION);
        OK_SXEL_ERROR(": 8: Unrecognised line (invalid key format)");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 4\n%s%s", DIRPREFS_VERSION, data, not_sorted_alt_uid);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with out of order alt-uids", DIRPREFS_VERSION);
        OK_SXEL_ERROR(": 9: Invalid line (out of order)");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 4\n%s%s", DIRPREFS_VERSION, data, duplicate_alt_uid);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with duplicate alt-uids", DIRPREFS_VERSION);
        OK_SXEL_ERROR(": 9: Invalid line (duplicate)");

        MOCKFAIL_START_TESTS(3, prefbuilder_consume);
        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 3\n%s%s%s", DIRPREFS_VERSION, data, identity, valid_alt_uid);
        ok(!confset_load(NULL), "Noted an update; Read valid version %u failed due to allocation", DIRPREFS_VERSION);
        OK_SXEL_ERROR("Couldn't allocate a prefblock");
        OK_SXEL_ERROR(": prefbuilder failure");
        MOCKFAIL_END_TESTS();
    }

    diag("Test V%u data load with invalid list format", DIRPREFS_VERSION);
    {
        const char *prelist_data = "[lists:1]\n";
        const char *postlist_data = "[bundles:1]\n"
                                    "0:1:0:32:1400000000007491CD:::::::::::\n"
                                    "[orgs:1]\n"
                                    "2748:0:0:365:0:1002748:0\n"
                                    "[identities:2]\n"
                                    "00000001:0::0:22:2748:0:1\n"
                                    "00000001:2:01836e63941c1f33a38e0f6e78715d2e:1:5:2748:0:1\n";
        const char *valid_list = "0:1:domain:71:b0938471d544cc036823fe16119930a320b55a8c:black\n";
        const char *invalid_list = "x:1:domain:71:b0938471d544cc036823fe16119930a320b55a8c:black\n";

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 5\n%s%s%s", DIRPREFS_VERSION, prelist_data, valid_list, postlist_data);
        ok(confset_load(NULL), "Noted an update; Read valid version %u data", DIRPREFS_VERSION);

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 5\n%s%s%s", DIRPREFS_VERSION, prelist_data, invalid_list, postlist_data);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with invalid list format", DIRPREFS_VERSION);
        OK_SXEL_ERROR(": 4: Unrecognised list line (invalid ltype:id:)");
    }

    diag("Test V%u data load with wrong sort order", DIRPREFS_VERSION);
    {
        {
            const char *list_lo = "1:1:domain:71:2d6fff2424c0dc1599f3dc01f5491666d98fe9dc:blocked.1 blocked.2\n";
            const char *list_hi = "1:2:domain:70:c52bdbfdc1ea81f6bd66dd5dea67e6010c0f5751:viral.com dropbox.com\n";
            const char *prelist_data = "[lists:10]\n";
            const char *postlist_data = "1:6:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                                        "1:7:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                                        "5:3:domain::48a73ac65f67a7e2eb82197ea6e57ac562bbb7f4:exception.1 exception.2 exception.3\n"
                                        "5:8:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                                        "9:4:domain:72:f819f78d349199f03962dee4d6fc5bd4b7ce64c1:white.list.domain\n"
                                        "9:9:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                                        "D:5:domain::1a3f4ee6082f803d25f38ac87f3e88a7a4c3a658:proxy.com\n"
                                        "D:10:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                                        "[bundles:2]\n"
                                        "1:1:1:61:1F0000000000000001::1 2:3:4:5::::::\n"
                                        "1:2:0:60:1F0000000000000000::6 7:8:9:10::::::\n"
                                        "[orgs:1]\n"
                                        "2748:0:0:365:0:1002748:0\n"
                                        "[identities:2]\n"
                                        "1:0::6789972:22:0:1:1\n"
                                        "2:0::6789971:22:0:1:2\n";

            create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 15\n%s%s%s%s", DIRPREFS_VERSION, prelist_data, list_lo, list_hi, postlist_data);
            ok(confset_load(NULL), "Noted an update; Read valid version %u data with valid list sort order", DIRPREFS_VERSION);

            create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 15\n%s%s%s%s", DIRPREFS_VERSION, prelist_data, list_hi, list_lo, postlist_data);
            ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with invalid list sort order", DIRPREFS_VERSION);
            OK_SXEL_ERROR("Unsorted list insertions are not permitted");
            OK_SXEL_ERROR("test-dirprefs-2748: 5: Cannot create preflist 01:1:domain");
        }

        {
            const char *bundle_lo = "1:1:1:61:1F0000000000000001::1 2:3:4:5::::::\n";
            const char *bundle_hi = "1:2:0:60:1F0000000000000000::6 7:8:9:10:11:::::\n";
            const char *prebundle_data = "[lists:11]\n"
                                         "1:1:domain:71:4fbdc8712b77214e1ceb91883b8c62cb79fe4f2f:blocked.1 blocked.2\n"
                                         "1:2:domain:70:37a3ec7b8ae861a3fb8eb743ba5f0657746eb5ac:viral.com dropbox.com\n"
                                         "1:6:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                                         "1:7:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                                         "5:3:domain::48a73ac65f67a7e2eb82197ea6e57ac562bbb7f4:exception.1 exception.2 exception.3\n"
                                         "5:8:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                                         "9:4:domain:72:f819f78d349199f03962dee4d6fc5bd4b7ce64c1:white.list.domain\n"
                                         "9:9:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                                         "D:5:domain::88dc59e021b6e0ff657d4dd26f9e7bd0641b0021:proxy.com\n"
                                         "D:10:domain::97de4f1e791cf79d7bb9eebc1ae1e8698c1ba941:urlproxy1 urlproxy2\n"
                                         "11:11:domain::d2288b690c7fb1651fdf6745e81efe51a7b82328:urlproxy2\n"
                                         "[bundles:2]\n";
            const char *postbundle_data = "[orgs:1]\n"
                                          "2748:0:0:365:0:1002748:0\n"
                                          "[identities:2]\n"
                                          "1:0::6789972:22:0:1:1\n"
                                          "2:0::6789971:22:0:1:2\n";

            create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 16\n%s%s%s%s", DIRPREFS_VERSION, prebundle_data, bundle_lo, bundle_hi, postbundle_data);
            ok(confset_load(NULL), "Noted an update; Read valid version %u data with valid bundle sort order", DIRPREFS_VERSION);

            create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 16\n%s%s%s%s", DIRPREFS_VERSION, prebundle_data, bundle_hi, bundle_lo, postbundle_data);
            ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with invalid bundle sort order", DIRPREFS_VERSION);
            OK_SXEL_ERROR("Unsorted list insertions are not permitted");
            OK_SXEL_ERROR("test-dirprefs-2748: 17: Cannot create bundle 1:1");
        }

        {
            const char *data = "[lists:11]\n"
                               "1:1:domain:71:4fbdc8712b77214e1ceb91883b8c62cb79fe4f2f:blocked.1 blocked.2\n"
                               "1:2:domain:70:37a3ec7b8ae861a3fb8eb743ba5f0657746eb5ac:viral.com dropbox.com\n"
                               "1:6:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                               "1:7:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                               "5:3:domain::48a73ac65f67a7e2eb82197ea6e57ac562bbb7f4:exception.1 exception.2 exception.3\n"
                               "5:8:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                               "9:4:domain:72:f819f78d349199f03962dee4d6fc5bd4b7ce64c1:white.list.domain\n"
                               "9:9:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                               "D:5:domain::88dc59e021b6e0ff657d4dd26f9e7bd0641b0021:proxy.com\n"
                               "D:10:domain::97de4f1e791cf79d7bb9eebc1ae1e8698c1ba941:urlproxy1 urlproxy2\n"
                               "11:11:domain::d2288b690c7fb1651fdf6745e81efe51a7b82328:urlproxy2\n"
                               "[bundles:2]\n"
                               "1:1:1:61:1F0000000000000001::1 2:3:4:5::::::\n"
                               "1:2:0:60:1F0000000000000000::6 7:8:9:10:11:::::\n"
                               "[orgs:1]\n"
                               "1:0:0:365:0:1001:0\n"
                               "[identities:2]\n";
            const char *ident_lo = "1:0::6789972:22:0:1:1\n";
            const char *ident_hi = "2:0::6789971:22:0:1:2\n";

            create_atomic_file("test-dirprefs-1", "dirprefs %u\ncount 16\n%s%s%s", DIRPREFS_VERSION, data, ident_lo, ident_hi);
            ok(confset_load(NULL), "Noted an update; Read valid version %u data", DIRPREFS_VERSION);

            create_atomic_file("test-dirprefs-1", "dirprefs %u\ncount 16\n%s%s%s", DIRPREFS_VERSION, data, ident_lo, ident_lo);
            ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with duplicate identities", DIRPREFS_VERSION);
            OK_SXEL_ERROR("test-dirprefs-1: 22: Invalid line (duplicate)");

            create_atomic_file("test-dirprefs-1", "dirprefs %u\ncount 16\n%s%s%s", DIRPREFS_VERSION, data, ident_hi, ident_lo);
            ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with invalid identity sort order", DIRPREFS_VERSION);
            OK_SXEL_ERROR("test-dirprefs-1: 22: Invalid line (out of order)");
        }
    }

    diag("Test V%u dirprefs load with a wrong org count", DIRPREFS_VERSION);
    {
        const char *preorg = "[lists:5]\n"
                             "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                             "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                             "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                             "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                             "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                             "[bundles:1]\n"
                             "0:1:0:60:1F0000000000000000::1 4:2:3:5::::::\n";
        const char *zeroorgs = "";
        const char *oneorg = "[orgs:1]\n"
                             "2748:0:0:365:0:1002748:0\n";
        const char *twoorgs = "[orgs:2]\n"
                             "2748:0:0:365:0:1002748:0\n"
                             "2749:0:0:365:0:1002748:0\n";
        const char *postorg = "[identities:1]\n"
                              "00000001:0::6789971:22:2748:0:1\n";

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 7\n%s%s%s", DIRPREFS_VERSION, preorg, zeroorgs, postorg);
        ok(!confset_load(NULL), "Noted no update; Rejected version %u data with no orgs", DIRPREFS_VERSION);
        OK_SXEL_ERROR("test-dirprefs-2748: Expected exactly one org (2748) entry in 'orgs' section");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s", DIRPREFS_VERSION, preorg, oneorg, postorg);
        ok(confset_load(NULL), "Noted an update; Accepted version %u data with one org", DIRPREFS_VERSION);

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 9\n%s%s%s", DIRPREFS_VERSION, preorg, twoorgs, postorg);
        ok(!confset_load(NULL), "Noted no update; Rejected version %u data with two orgs", DIRPREFS_VERSION);
        OK_SXEL_ERROR("test-dirprefs-2748: Expected exactly one org (2748) entry in 'orgs' section");
    }

    diag("Test V%u data load with invalid domainlist fields", DIRPREFS_VERSION);
    {
        const char *bundle_good = "0:1:0:60:1F0000000000000000::1 4:2:3:5::::::\n";
        const char *bundle_bad1 = "0:1:0:60:1F0000000000000000::1 4:2:3::::5\n";
        const char *bundle_bad2 = "0:1:0:60:1F0000000000000000::1 4:2:3:5:::::::::\n";
        const char *prebundle_data = "[lists:5]\n"
                                     "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                                     "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                                     "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                                     "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                                     "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                                     "[bundles:1]\n";
        const char *postbundle_data = "[orgs:1]\n"
                                      "2748:0:0:365:0:1002748:0\n"
                                      "[identities:1]\n"
                                      "00000001:0::6789971:22:2748:0:1\n";

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s", DIRPREFS_VERSION, prebundle_data, bundle_good, postbundle_data);
        ok(confset_load(NULL), "Noted an update; Read valid version %u data", DIRPREFS_VERSION);

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s", DIRPREFS_VERSION, prebundle_data, bundle_bad1, postbundle_data);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with missing domainlist", DIRPREFS_VERSION);
        OK_SXEL_ERROR("test-dirprefs-2748: 10: Unrecognised bundle line (invalid allow app list '5')");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s", DIRPREFS_VERSION, prebundle_data, bundle_bad2, postbundle_data);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with extra domainlist", DIRPREFS_VERSION);
        OK_SXEL_ERROR("test-dirprefs-2748: 10: Unrecognised bundle line (invalid warn app list ':')");
    }

    diag("Test V%u data load with invalid settinggroups", DIRPREFS_VERSION);
    {
        const char *presg  = "[lists:4]\n"
                             "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                             "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                             "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                             "8:3:domain:72:6339e5f67660af196a583f9164cfb72b5acef138:white1\n";
        const char *midsg  = "[bundles:1]\n"
                             "0:1:0:32:140000000000000000:";
        const char *postsg = ":1 4:2:3:::::::\n"
                             "[orgs:1]\n"
                             "2748:0:0:365:0:1002748:1234\n"
                             "[identities:1]\n"
                             "00000001:0::2245036:22:2748:0:1\n";

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s%s%s", DIRPREFS_VERSION, presg,
                 "[settinggroup:1]\n0:1:0:1:f:a\n", midsg,  "", postsg);
        ok(confset_load(NULL), "Loaded V%u data with valid settinggroup", DIRPREFS_VERSION);

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s%s%s", DIRPREFS_VERSION, presg,
                 "[settinggroup:1]\n0:1x:0:1:f:a\n", midsg, "", postsg);
        ok(!confset_load(NULL), "Can't load V%u data with an invalid settinggroup id", DIRPREFS_VERSION);
        OK_SXEL_ERROR("test-dirprefs-2748: 9: Unrecognised settinggroup line (invalid id)");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s%s%s", DIRPREFS_VERSION, presg,
                 "[settinggroup:1]\n0:1:0:x1:f:a\n", midsg, "", postsg);
        ok(!confset_load(NULL), "Can't load V%u data with invalid settinggroup bits", DIRPREFS_VERSION);
        OK_SXEL_ERROR("test-dirprefs-2748: 9: Unrecognised settinggroup line (invalid blocked-categories)");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s%s%s", DIRPREFS_VERSION, presg,
                 "[settinggroup:1]\n0:1:0:1:xf:a\n", midsg, "", postsg);
        ok(!confset_load(NULL), "Can't load V%u data with invalid settinggroup bits", DIRPREFS_VERSION);
        OK_SXEL_ERROR("test-dirprefs-2748: 9: Unrecognised settinggroup line (invalid nodecrypt-categories)");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s%s%s", DIRPREFS_VERSION, presg,
                           "[settinggroup:1]\n0:1:0:1:f:xa\n", midsg, "", postsg);
        ok(!confset_load(NULL), "Can't load V%u data with invalid settinggroup bits", DIRPREFS_VERSION);
        OK_SXEL_ERROR("test-dirprefs-2748: 9: Unrecognised settinggroup line (invalid warn-categories)");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 9\n%s%s%s%s%s", DIRPREFS_VERSION, presg,
                 "[settinggroup:2]\n0:1:0:1:f:a\n0:1:1:0:f:a\n", midsg, "", postsg);
        ok(!confset_load(NULL), "Can't load V%u data with duplicate settinggroup lines", DIRPREFS_VERSION);
        OK_SXEL_ERROR("test-dirprefs-2748: 10: Cannot create settinggroup 0:1");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 9\n%s%s%s%s%s", DIRPREFS_VERSION, presg,
                 "[settinggroup:2]\n0:2:0:1:f:a\n0:1:0:1:f:a\n", midsg, "", postsg);
        ok(!confset_load(NULL), "Can't load V%u data with out-of-order settinggroup lines", DIRPREFS_VERSION);
        OK_SXEL_ERROR("Unsorted list insertions are not permitted");
        OK_SXEL_ERROR("test-dirprefs-2748: 10: Cannot create settinggroup 0:1");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s%s%s", DIRPREFS_VERSION, presg,
                 "[settinggroup:1]\n0:1:0:1:f:a\n", midsg, "1 2", postsg);
        ok(confset_load(NULL), "Loaded V%u data with valid settinggroup and external refs", DIRPREFS_VERSION);

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s%s%s", DIRPREFS_VERSION, presg,
                 "[settinggroup:1]\n0:1:0:1:f:a\n", midsg, "x1 2", postsg);
        ok(!confset_load(NULL), "Cannot load V%u data with an invalid external settinggroup ref", DIRPREFS_VERSION);
        OK_SXEL_ERROR("test-dirprefs-2748: 11: Unrecognised bundle line (invalid settinggroup-ids terminator)");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s%s%s", DIRPREFS_VERSION, presg,
                 "[settinggroup:1]\n0:1:0:1:f:a\n", midsg, "1x 2", postsg);
        ok(!confset_load(NULL), "Cannot load V%u data with trailing garbage after the external settinggroup ref", DIRPREFS_VERSION);
        OK_SXEL_ERROR("test-dirprefs-2748: 11: Unrecognised bundle line (invalid settinggroup id)");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s%s%s", DIRPREFS_VERSION, presg,
                 "[settinggroup:1]\n0:1:0:1:f:a\n", midsg, "1 x2", postsg);
        ok(!confset_load(NULL), "Cannot load V%u data with an invalid external settinggroup-security ref", DIRPREFS_VERSION);
        OK_SXEL_ERROR("test-dirprefs-2748: 11: Unrecognised bundle line (invalid settinggroup-ids terminator)");

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s%s%s", DIRPREFS_VERSION, presg,
                 "[settinggroup:1]\n0:1:0:1:f:a\n", midsg, "1 2", postsg);
        ok(confset_load(NULL), "Loaded V%u data with a valid external settinggroup-security ref", DIRPREFS_VERSION);

        create_atomic_file("test-dirprefs-2748", "dirprefs %u\ncount 8\n%s%s%s%s%s", DIRPREFS_VERSION, presg,
                 "[settinggroup:1]\n0:1:0:1:f:a\n", midsg, "1 2x", postsg);
        ok(!confset_load(NULL), "Cannot load V%u data with trailing garbage after the external settinggroup-security ref", DIRPREFS_VERSION);
        OK_SXEL_ERROR("test-dirprefs-2748: 11: Unrecognised bundle line (invalid settinggroup id)");
    }

    diag("Test V%u data handling", DIRPREFS_VERSION);
    {
        struct pref_segments *ps;

        snprintf(content[0], sizeof(content[0]),
                 "dirprefs %u\n"
                 "count 19\n"
                 "[lists:5]\n"
                 "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                 "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                 "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                 "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                 "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                 "[bundles:5]\n"
                 "0:1:0004:61:1F000000000000001F::1 4:2:3:5::::::\n"
                 "0:3:0100:60:1F0000000000000000::1 4:2:3:5::::::\n"
                 "0:19:0001:62:1F00000000000000F1::1 4:2:3:5::::::\n"
                 "0:1234:0002:60:2F000000000000FF01::1 4:2:3:5::::::\n"
                 "0:92143:0102:63:2F000000000000FF01::1 4:2:3:5::::::\n"
                 "[orgs:1]\n"
                 "1:0:0:365:0:1001:0\n"
                 "[identities:8]\n"
                 "00000001:0::6789971:22:1:0:3\n"
                 "00000001:2:01836e63941c1f33a38e0f6e78715d2e:6789972:7:1:0:1\n"
                 "00000001:2:032e0f6e78715d2e1836e63941c1f33a:4584097:7:1:0:19\n"
                 "00000001:2:03683af90ce38893ff3a212f57ebca81:8712753:7:1:0:1234\n"
                 "00000001:2:04444444444444444444444444444444:8712752:5:1:0:92143\n"
                 "00000001:3:H0bb6a813bb4426cc7e22b0caba38f1e9:8712754:7:1:0:1234\n"
                 "00000001:3:H1483e2e5529ea0c5f75c3f3613860548:4584098:7:1:0:19\n"
                 "00000001:3:Ha79555d840d671093db8ea4a4fd82c71:6789973:7:1:0:1\n",
                 DIRPREFS_VERSION);
        snprintf(content[1], sizeof(content[1]), "dirprefs %u\ncount 3\n"
                 "[bundles:1]\n0:1:0:0:0::::::::::::\n[orgs:1]\n2:0:0:365:0:1002:0\n[no-identities:1]\n2:0::1:22:2:0:1\n", DIRPREFS_VERSION);
        snprintf(content[2], sizeof(content[2]), "dirprefs %u\ncount 8\n"
                 "[lists:5]\n"
                 "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                 "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                 "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                 "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                 "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                 "[bundles:1]\n"
                 "0:123:0099:63:1F0000000000000000::1 4:2:3:5::::::\n"
                 "[orgs:1]\n"
                 "3:0:0:365:0:1003:0\n"
                 "[identities:1]\n"
                 "3:1:2911558:2911558:13:3:0:123\n", DIRPREFS_VERSION);
        snprintf(content[3], sizeof(content[3]), "dirprefs %u\ncount 0\n", DIRPREFS_VERSION);
        snprintf(content[4], sizeof(content[4]), "dirprefs %u\ncount 8\n"
                 "[lists:5]\n"
                 "0:1:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                 "0:4:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                 "4:100:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                 "8:12:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                 "C:923:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                 "[bundles:1]\n"
                 "0:321:0:61:3F000000000000FF01::1 4:100:12:923::::::\n"
                 "[orgs:1]\n"
                 "5:0:0:365:0:1005:0\n"
                 "[identities:1]\n"
                 "5:2:06666666666666666666666666666666:8712753:7:5:0:321\n",
                 DIRPREFS_VERSION);

        MOCKFAIL_START_TESTS(3, DIRPREFS_CLONE);
        create_atomic_file("test-dirprefs-1", "%s", content[0]);
        ok(!confset_load(NULL), "Didn't see a change to test-dirprefs-1 due to a malloc failure");
        OK_SXEL_ERROR("Couldn't allocate a dirprefs structure");
        OK_SXEL_ERROR("Couldn't clone a dirprefs conf object");
        MOCKFAIL_END_TESTS();
        unlink("test-dirprefs-1");

        unlink("test-dirprefs-2");
        unlink("test-dirprefs-2.last-good");
        unlink("test-dirprefs-3");
        unlink("test-dirprefs-4");
        unlink("test-dirprefs-4.last-good");
        unlink("test-dirprefs-5");
        unlink("test-dirprefs-6");
        unlink("test-dirprefs-2748");
        for (orgid = 100; orgid < 110; orgid++) {
            snprintf(buf, sizeof(buf), "test-dirprefs-%u", orgid);
            unlink(buf);
        }

        /* pref_segments_new() results are assert()ed in the code (only called at start), but can fail */
        ok(ps = pref_segments_new("something-%u"), "Calling pref_segments_new() directly works");
        pref_segments_free(ps);

        MOCKFAIL_START_TESTS(2, PREF_SEGMENTS_PREFDIR_NEW_BRANCH);
        ps = pref_segments_new("something-%u");
        ok(!ps, "pref_segments_new() fails when allocation of a new branch fails");
        OK_SXEL_ERROR("Couldn't allocate a struct prefdir");
        MOCKFAIL_END_TESTS();

        /* Now do some content testing */
        create_atomic_file("test-dirprefs-1", "%s", content[0]);
        create_atomic_file("test-dirprefs-2", "%s", content[1]);
        snprintf(content[1], sizeof(content[1]), "dirprefs %u\n" "count 1\n"
                 "[lists:0]\n" "[bundles:1]\n" "0:1:0:0:0::::::::::::\n" "[orgs:1]\n" "2:0:0:365:0:1002:0\n" "[identities:1]\n" "2:0::22:1:2:0:\n", DIRPREFS_VERSION);
        create_atomic_file("test-dirprefs-2.last-good", "%s", content[1]);
        ok(confset_load(NULL), "Noted an update to test-dirprefs-1");
        /* ./test-dirprefs-2.last-good: 7: Unrecognised identity line */
        OK_SXEL_ERROR("test-dirprefs-2: 4: Unrecognised bundle line (invalid warn app list ':')");

        MOCKFAIL_START_TESTS(2, PREF_SEGMENTS_PREFFILE_NEW);
        create_atomic_file("test-dirprefs-3", "%s", content[3]);
        ok(!confset_load(NULL), "Didn't see test-dirprefs-3 turn up when preffile_new() fails");
        OK_SXEL_ERROR("Couldn't allocate preffile struct with 17 extra bytes");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(3, DIRPREFS_CLONE_ORGS);
        create_atomic_file("test-dirprefs-3", "we'll never even get to see this data");
        ok(!confset_load(NULL), "Didn't see a change to test-dirprefs-3 due to a dirprefs-org slot allocation failure");
        OK_SXEL_ERROR("Couldn't allocate 10 new dirprefs org slots");
        OK_SXEL_ERROR("Couldn't clone a dirprefs conf object");
        MOCKFAIL_END_TESTS();

        create_atomic_file("test-dirprefs-3", "%s", content[2]);
        create_atomic_file("test-dirprefs-4", "%s", content[3]);
        create_atomic_file("test-dirprefs-5", "%s", content[4]);
        ok(confset_load(NULL), "Noted an update to test-dirprefs-[345]");

        ok(!confset_load(NULL), "A second confset_load() call results in nothing");
        ok(set = confset_acquire(&gen), "Acquired the new config");

        skip_if(set == NULL, 109, "Cannot check content without acquiring config") {
            snprintf(content[3], sizeof(content[3]), "dirprefs %u\ncount 1\n"
                     "This is garbage - it won't load\n", DIRPREFS_VERSION);
            create_atomic_file("test-dirprefs-4", "%s", content[3]);
            ok(!confset_load(NULL), "Noted no update; test-dirprefs-4 modification was garbage");
            OK_SXEL_ERROR("test-dirprefs-4: 3: Expected section header");

            snprintf(content[1], sizeof(content[1]), "dirprefs %u\ncount 10\n"
                     "[lists:7]\n"
                     "1:9:domain:70:37a3ec7b8ae861a3fb8eb743ba5f0657746eb5ac:viral.com dropbox.com\n"
                     "1:84:domain:71:133631e236f708b7148837c5c2f959997c9f7724:blocked.2\n"
                     "1:120:domain:71:65aaff8b90a25b44c0465b5eaa48e78bf8ad5193:blocked.1\n"
                     "5:100:domain::48a73ac65f67a7e2eb82197ea6e57ac562bbb7f4:exception.1 exception.2 exception.3\n"
                     "9:12:domain:72:f819f78d349199f03962dee4d6fc5bd4b7ce64c1:white.list.domain\n"
                     "D:923:domain::1a3f4ee6082f803d25f38ac87f3e88a7a4c3a658:proxy.com\n"
                     "21:123:domain:158:da4017e8921dcb4e2f98bbb408007ee0985a14be:warn.com\n"
                     "[bundles:1]\n"
                     "1:975:0:62:1F0000000000000666::9 84 120:100:12:923:::::123:\n"
                     "[orgs:1]\n"
                     "2:0:0:365:0:1002:3\n"    // Parent org is 3 to allow testing
                     "[identities:1]\n"
                     "2:2:05222832ed6f81efca73beb2abc1979f:2911557:5:2:1:975\n", DIRPREFS_VERSION);
            snprintf(content[3], sizeof(content[3]), "dirprefs %u\ncount 11\n"
                     "[lists:5]\n"
                     "2:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                     "2:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                     "6:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                     "A:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                     "E:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                     "[bundles:2]\n"
                     "2:123:0098:62:2F0000000000000000::1 4:2:3:5::::::\n"
                     "2:456:0099:60:3F000000000000FF01::1 4:2:3:5::::::\n"
                     "[orgs:1]\n"
                     "4:0:0:365:0:1004:0\n"
                     "[identities:3]\n"
                     "4:1:2911559:2911559:13:4:2:123\n"
                     "4:2:05555555555555555555555555555555:8712752:5:4:2:456\n"
                     "4:3:H0bb6a813bb4426cc7e22b0caba38f1e9:8712753:5:4:2:456\n",
                     DIRPREFS_VERSION);
            create_atomic_file("test-dirprefs-2", "%s", content[1]);
            create_atomic_file("test-dirprefs-4", "%s", content[3]);
            create_atomic_file("test-dirprefs-6", "invalid data");

            ok(confset_load(NULL), "Noted an update to test-dirprefs-[246]");
            confset_release(set);
            ok(set = confset_acquire(&gen), "Acquired the new config");

            skip_if(set == NULL, 105, "Cannot check content without acquiring config") {
                dp = dirprefs_conf_get(set, CONF_DIRPREFS);
                ok(dp, "Constructed struct dirprefs from segmented V%u data", DIRPREFS_VERSION);
                is(dp->count, 6, "V%u data has a count of 6 orgs", DIRPREFS_VERSION);
                is(dp->conf.refcount, 2, "V%u data has a refcount of 2", DIRPREFS_VERSION);

                skip_if(dp->count != 5, 6, "Cannot verify org count") {
                    is(PREFS_COUNT(dp->org[0], identities), 5, "V%u data in slot 0 has an identity count of 5", DIRPREFS_VERSION);
                    is(PREFS_COUNT(dp->org[1], identities), 1, "V%u data in slot 1 has an identity count of 1", DIRPREFS_VERSION);
                    is(PREFS_COUNT(dp->org[2], identities), 1, "V%u data in slot 2 has an identity count of 1", DIRPREFS_VERSION);
                    is(PREFS_COUNT(dp->org[3], identities), 2, "V%u data in slot 3 has an identity count of 2", DIRPREFS_VERSION);
                    is(PREFS_COUNT(dp->org[4], identities), 1, "V%u data in slot 4 has an identity count of 1", DIRPREFS_VERSION);
                    is(PREFS_COUNT(dp->org[5], identities), 0, "V%u data in slot 5 has an identity count of 0", DIRPREFS_VERSION);
                }

                ok(!dirprefs_slotisempty(&dp->conf, prefs_org_slot(dp->org, 5, dp->count)), "Org 5 slot is not empty");
                ok( dirprefs_slotisempty(&dp->conf, prefs_org_slot(dp->org, 6, dp->count)), "Org 6 slot is empty");
                ok( dirprefs_get_prefblock(dp, 5),                                          "Got prefblock for org 5");
                ok(!dirprefs_get_prefblock(dp, 6),                                          "No prefblock for org 6");
                ok(prefs_org_slot(dp->org, 6, dp->count) < dp->count,                       "Org 6 does have a slot");
                ok(!dirprefs_get_prefblock(dp, 666),                                        "No prefblock for org 666");

                diag("    V%u orgid lookup", DIRPREFS_VERSION);
                {
                    memset(&odns, '\0', sizeof odns);
                    odns.fields |= ODNS_FIELD_ORG;
                    oolist_clear(&ids);
                    odns.org_id = 666;
                    ok(!dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL), "Failed to get dirprefs for org 666");

                    odns.org_id = 1;
                    ok(dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL), "Successfully got the dirprefs for org 1");
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "6789971:22:1:365:0", "Collected other origin IDs: org");
                    ok(PREF_VALID(&pr), "Got prefs for orgid 1");
                    is(dt, DIRPREFS_TYPE_ORG, "Got dirprefs type ORG");

                    skip_if(!PREF_VALID(&pr), 5, "Cannot run these tests without prefs") {
                        ident = PREF_IDENT(&pr);
                        org = PREF_ORG(&pr);
                        bundle = PREF_BUNDLE(&pr);
                        is(bundle->bundleflags, 0x60, "Got the correct flags for orgid 1");
                        is(ident->originid, 0x679b53, "Got the correct origin_id for orgid 1");
                        pref_categories_sscan(&expected_categories, "1F0000000000000000");
                        ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                           "Unexpected categories %s for orgid 1 (expected 1F0000000000000000)",
                           pref_categories_idstr(&bundle->base_blocked_categories));
                        is(org ? org->id : 0, 1, "Got the correct orgid for orgid 1");
                        is(bundle->id, 3, "Got the correct bundleid for orgid 1");
                    }

                    org_slot = prefs_org_slot(dp->org, 4, dp->count);    /* Get the index of org 4 */
                    dpo = dp->org[org_slot];                             /* Get a pointer to the dirprefs for the org */
                    is_eq(dpo->fp.ops->key_to_str(&dpo->fp, 0), "4:1:2911559", "Got the correct first key for org 4");
                    is_eq(dpo->fp.ops->key_to_str(&dpo->fp, 1), "4:2:05555555555555555555555555555555",
                                                                               "Got the correct second key for org 4");
                    is_eq(dpo->fp.ops->key_to_str(&dpo->fp, 2), "4:3:H0bb6a813bb4426cc7e22b0caba38f1e9",
                                                                               "Got the correct third key for org 4");

                    /* Lookup against an org that failed to load */
                    memset(&odns, '\0', sizeof odns);
                    odns.org_id = 6;
                    odns.fields |= ODNS_FIELD_ORG;
                    oolist_clear(&ids);
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "-", "No origin from failed load of orgid 6");
                    ok(!PREF_VALID(&pr), "Prefs for orgid 6 is invalid");
                    is(dt, DIRPREFS_TYPE_NONE, "Got dirprefs type NONE");
                    unlink("test-dirprefs-6");
                }

                diag("    V%u GUID lookup", DIRPREFS_VERSION);
                {
                    const char guid[] = { 0x01, 0x83, 0x6e, 0x63, 0x94, 0x1c, 0x1f, 0x33, 0xa3, 0x8e, 0x0f, 0x6e, 0x78, 0x71, 0x5d, 0x2e };
                    memset(&odns, '\0', sizeof odns);
                    odns.org_id = 1;
                    memcpy(&odns.user_id, guid, sizeof odns.user_id);
                    odns.fields |= ODNS_FIELD_ORG | ODNS_FIELD_USER;
                    oolist_clear(&ids);
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "6789972:7:1:365:0,6789971:22:1:365:0", "Collected other origin IDs: user, org");
                    ok(PREF_VALID(&pr), "Got prefs for orgid 1 for a specific GUID");
                    is(dt, DIRPREFS_TYPE_GUID, "Got dirprefs type GUID");
                    skip_if(!PREF_VALID(&pr), 5, "Cannot run these tests without prefs") {
                        ident = PREF_IDENT(&pr);
                        org = PREF_ORG(&pr);
                        bundle = PREF_BUNDLE(&pr);
                        is(bundle->bundleflags, 0x61, "Got the correct flags for specific GUID");
                        is(ident->originid, 0x679b54, "Got the correct origin_id for specific GUID");
                        pref_categories_sscan(&expected_categories, "1f000000000000001f");
                        ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                            "Unexpected categories %s for specific GUID (expected 1F000000000000001F)",
                            pref_categories_idstr(&bundle->base_blocked_categories));
                        is(org ? org->id : 0, 1, "Got the correct orgid for specific GUID");
                        is(bundle->id, 1, "Got the correct bundleid for specific GUID");
                    }

                    odns.user_id.bytes[ODNS_LEN_USER - 1]++; /* A different GUID */
                    oolist_clear(&ids);
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "6789971:22:1:365:0", "Collected other origin IDs: org");
                    ok(PREF_VALID(&pr), "Got prefs for orgid 1 with a GUID mismatch");
                    is(dt, DIRPREFS_TYPE_ORG, "Got dirprefs type ORG");
                    skip_if(!PREF_VALID(&pr), 5, "Cannot run these tests without prefs") {
                        ident = PREF_IDENT(&pr);
                        org = PREF_ORG(&pr);
                        bundle = PREF_BUNDLE(&pr);
                        is(bundle->bundleflags, 0x60, "Got the correct flags for orgid 1");
                        is(ident->originid, 0x679b53, "Got the correct origin_id for orgid 1");
                        pref_categories_sscan(&expected_categories, "1F0000000000000000");
                        ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                           "Unexpected categories %s for orgid 1 (expected 1F0000000000000000)",
                           pref_categories_idstr(&bundle->base_blocked_categories));
                        is(org ? org->id : 0, 1, "Got the correct org_id for orgid 1");
                        is(bundle->id, 3, "Got the correct bundle_id for orgid 1");
                    }

                    odns.org_id++; /* A different orgid */
                    oolist_clear(&ids);
                    ok(!dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL), "Didn't get prefs for orgid 2");
                    is(dt, DIRPREFS_TYPE_NONE, "Got dirprefs type NONE");
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "-", "Collected other origin IDs: none");
                }

                diag("    V%u ALT-UID lookup", DIRPREFS_VERSION);
                {
                    const char alt_uid[] = { 0xa7, 0x95, 0x55, 0xd8, 0x40, 0xd6, 0x71, 0x09, 0x3d, 0xb8, 0xea, 0x4a, 0x4f, 0xd8, 0x2c, 0x71 };
                    memset(&odns, '\0', sizeof odns);
                    odns.org_id = 1;
                    memcpy(&odns.alt_user_id, alt_uid, sizeof odns.alt_user_id);
                    odns.fields |= ODNS_FIELD_ORG | ODNS_FIELD_ALT_UID;
                    oolist_clear(&ids);
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "6789973:7:1:365:0,6789971:22:1:365:0", "Collected other origin IDs: user, org");
                    ok(PREF_VALID(&pr), "Got prefs for orgid 1 for a specific ALT-UID");
                    is(dt, DIRPREFS_TYPE_ALT_UID, "Got dirprefs type ALT-UID");
                    skip_if(!PREF_VALID(&pr), 5, "Cannot run these tests without prefs") {
                        ident = PREF_IDENT(&pr);
                        org = PREF_ORG(&pr);
                        bundle = PREF_BUNDLE(&pr);
                        is(bundle->bundleflags, 0x61, "Got the correct flags for specific ALT-UID");
                        is(ident->originid, 0x679b55, "Got the correct origin_id for specific ALT-UID");
                        pref_categories_sscan(&expected_categories, "1f000000000000001f");
                        ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                           "Unexpected categories %s for specific ALT-UID (expected 1F000000000000001F)",
                           pref_categories_idstr(&bundle->base_blocked_categories));
                        is(org ? org->id : 0, 1, "Got the correct orgid for specific ALT-UID");
                        is(bundle->id, 1, "Got the correct bundleid for specific ALT-UID");
                    }

                    odns.alt_user_id.bytes[ODNS_LEN_ALT_UID - 1]++; /* A different ALT-UID */
                    oolist_clear(&ids);
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "6789971:22:1:365:0", "Collected other origin IDs: org");
                    ok(PREF_VALID(&pr), "Got prefs for orgid 1 with a ALT-UID mismatch");
                    is(dt, DIRPREFS_TYPE_ORG, "Got dirprefs type ORG");
                    skip_if(!PREF_VALID(&pr), 5, "Cannot run these tests without prefs") {
                        ident = PREF_IDENT(&pr);
                        org = PREF_ORG(&pr);
                        bundle = PREF_BUNDLE(&pr);
                        is(bundle->bundleflags, 0x60, "Got the correct flags for orgid 1");
                        is(ident->originid, 0x679b53, "Got the correct origin_id for orgid 1");
                        pref_categories_sscan(&expected_categories, "1F0000000000000000");
                        ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                           "Unexpected categories %s for orgid 1 (expected 1F0000000000000000)",
                           pref_categories_idstr(&bundle->base_blocked_categories));
                        is(org ? org->id : 0, 1, "Got the correct org_id for orgid 1");
                        is(bundle->id, 3, "Got the correct bundle_id for orgid 1");
                    }

                    odns.org_id++; /* A different orgid with original alt-uid */
                    memcpy(&odns.alt_user_id, alt_uid, sizeof odns.alt_user_id);
                    oolist_clear(&ids);
                    ok(!dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL), "Didn't get prefs for orgid 2");
                    is(dt, DIRPREFS_TYPE_NONE, "Got dirprefs type NONE");
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "-", "Collected other origin IDs: none");
                }

                diag("    V%u host GUID override", DIRPREFS_VERSION);
                {
                    const char userguid1[] = { 0x01, 0x83, 0x6e, 0x63, 0x94, 0x1c, 0x1f, 0x33, 0xa3, 0x8e, 0x0f, 0x6e, 0x78, 0x71, 0x5d, 0x2e };
                    const char userguid2[] = { 0x03, 0x2e, 0x0f, 0x6e, 0x78, 0x71, 0x5d, 0x2e, 0x18, 0x36, 0xe6, 0x39, 0x41, 0xc1, 0xf3, 0x3a };
                    const char hostguid[] = { 0x03, 0x68, 0x3a, 0xf9, 0x0c, 0xe3, 0x88, 0x93, 0xff, 0x3a, 0x21, 0x2f, 0x57, 0xeb, 0xca, 0x81 };

                    memset(&odns, '\0', sizeof odns);

                    /* Host over-rides user */
                    odns.org_id = 1;
                    memcpy(&odns.user_id, userguid1, sizeof odns.user_id);
                    memcpy(&odns.host_id, hostguid, sizeof odns.user_id);
                    odns.fields = ODNS_FIELD_ORG | ODNS_FIELD_USER | ODNS_FIELD_HOST;
                    oolist_clear(&ids);
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "6789972:7:1:365:0,8712753:7:1:365:0,6789971:22:1:365:0", "Collected other origin IDs: user, host, org");
                    ok(PREF_VALID(&pr), "Got prefs for orgid 1 for a specific GUID");
                    is(dt, DIRPREFS_TYPE_GUID, "Got dirprefs type GUID");
                    skip_if(!PREF_VALID(&pr), 5, "Cannot run these tests without prefs") {
                        ident = PREF_IDENT(&pr);
                        org = PREF_ORG(&pr);
                        bundle = PREF_BUNDLE(&pr);
                        is(bundle->bundleflags, 0x60, "Got the correct flags for host GUID");
                        is(ident->originid, 0x84F231, "Got the correct origin_id for host GUID");
                        pref_categories_sscan(&expected_categories, "2f000000000000ff01");
                        ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                           "Unexpected categories %s for host GUID (expected 2F000000000000FF01)",
                           pref_categories_idstr(&bundle->base_blocked_categories));
                        is(org ? org->id : 0, 1, "Got the correct orgid for host GUID");
                        is(bundle->id, 1234, "Got the correct bundleid for host GUID");
                    }

                    /* User over-rides host */
                    memcpy(&odns.user_id, userguid2, sizeof odns.user_id);
                    oolist_clear(&ids);
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "4584097:7:1:365:0,8712753:7:1:365:0,6789971:22:1:365:0", "Collected other origin IDs: user, host, org");
                    ok(PREF_VALID(&pr), "Got prefs for orgid 1 for a specific GUID");
                    is(dt, DIRPREFS_TYPE_GUID, "Got dirprefs type GUID");
                    skip_if(!PREF_VALID(&pr), 5, "Cannot run these tests without prefs") {
                        ident = PREF_IDENT(&pr);
                        org = PREF_ORG(&pr);
                        bundle = PREF_BUNDLE(&pr);
                        is(bundle->bundleflags, 0x62, "Got the correct flags for user GUID");
                        is(ident->originid, 0x45F2A1, "Got the correct origin_id for user GUID");
                        pref_categories_sscan(&expected_categories, "1f00000000000000f1");
                        ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                           "Unexpected categories %s for user GUID (expected 1F00000000000000F1)",
                           pref_categories_idstr(&bundle->base_blocked_categories));
                        is(org ? org->id : 0, 1, "Got the correct orgid for user GUID");
                        is(bundle->id, 19, "Got the correct bundleid for user GUID");
                    }

                    odns.user_id.bytes[ODNS_LEN_USER - 1]++; /* A different user GUID */
                    oolist_clear(&ids);
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "8712753:7:1:365:0,6789971:22:1:365:0", "Collected other origin IDs: host, org");
                    ok(PREF_VALID(&pr), "Got prefs for orgid 1 with a user GUID mismatch");
                    is(dt, DIRPREFS_TYPE_GUID, "Got dirprefs type GUID");
                    skip_if(!PREF_VALID(&pr), 5, "Cannot run these tests without prefs") {
                        ident = PREF_IDENT(&pr);
                        org = PREF_ORG(&pr);
                        bundle = PREF_BUNDLE(&pr);
                        is(bundle->bundleflags, 0x60, "Got the correct flags for host GUID");
                        is(ident->originid, 0x84F231, "Got the correct origin_id for host GUID");
                        pref_categories_sscan(&expected_categories, "2f000000000000ff01");
                        ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                           "Unexpected categories %s for specific GUID (expected 2F000000000000FF01)",
                           pref_categories_idstr(&bundle->base_blocked_categories));
                        is(org ? org->id : 0, 1, "Got the correct orgid for host GUID");
                        is(bundle->id, 1234, "Got the correct bundleid for host GUID");
                    }

                    odns.org_id++; /* A different orgid - can't find host for this org either! */
                    oolist_clear(&ids);
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    is(dt, DIRPREFS_TYPE_NONE, "Got dirprefs type NONE");
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "-", "Collected other origin IDs: none");
                    ok(!PREF_VALID(&pr), "Didn't get prefs for orgid 2");
                }

                diag("    V%u GUID lookup with domains", DIRPREFS_VERSION);
                {
                    const char guid[] = { 0x05, 0x22, 0x28, 0x32, 0xed, 0x6f, 0x81, 0xef, 0xca, 0x73, 0xbe, 0xb2, 0xab, 0xc1, 0x97, 0x9f };
                    const uint8_t blocked1[] = { 0x7, 'b', 'l', 'o', 'c', 'k', 'e', 'd', 0x1, '1', 0x0 };
                    const uint8_t blocked2[] = { 0x7, 'b', 'l', 'o', 'c', 'k', 'e', 'd', 0x1, '2', 0x0 };
                    const uint8_t blocked3[] = { 0x7, 'b', 'l', 'o', 'c', 'k', 'e', 'd', 0x1, '3', 0x0 };
                    const uint8_t exception1[] = { 0x9, 'e', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', 0x1, '1', 0x0 };
                    const uint8_t exception2[] = { 0x9, 'e', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', 0x1, '2', 0x0 };
                    const uint8_t exception3[] = { 0x9, 'e', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', 0x1, '3', 0x0 };
                    const uint8_t white[] = { 0x5, 'w', 'h', 'i', 't', 'e', 0x4, 'l', 'i', 's', 't', 0x6, 'd', 'o', 'm', 'a', 'i', 'n', 0x0 };
                    const uint8_t dropbox[] = { 0x7, 'd', 'r', 'o', 'p', 'b', 'o', 'x', 0x3, 'c', 'o', 'm', 0x0 };
                    const uint8_t proxy[] = { 0x5, 'p', 'r', 'o', 'x', 'y', 0x3, 'c', 'o', 'm', 0x0 };
                    const uint8_t warn[] = { 0x4, 'w', 'a', 'r', 'n', 0x3, 'c', 'o', 'm', 0x0 };

                    memset(&odns, '\0', sizeof odns);
                    odns.org_id = 2;
                    memcpy(&odns.user_id, guid, sizeof odns.user_id);
                    odns.fields |= ODNS_FIELD_ORG | ODNS_FIELD_USER;
                    oolist_clear(&ids);
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "2911557:5:2:365:3", "Collected other origin IDs: user");
                    ok(PREF_VALID(&pr), "Got prefs for orgid 2 for the GUID with domainlists");
                    is(dt, DIRPREFS_TYPE_GUID, "Got dirprefs type GUID");
                    skip_if(!PREF_VALID(&pr), 15, "Cannot run these tests without prefs") {
                        ident = PREF_IDENT(&pr);
                        org = PREF_ORG(&pr);
                        bundle = PREF_BUNDLE(&pr);
                        is(bundle->bundleflags, 0x62, "Got the correct flags for the given GUID");
                        is(ident->originid, 0x2C6D45, "Got the correct origin_id for the given GUID");
                        pref_categories_sscan(&expected_categories, "1f0000000000000666");
                        ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                           "Unexpected categories %s for given GUID (expected 1f0000000000000666)",
                           pref_categories_idstr(&bundle->base_blocked_categories));
                        is(org ? org->id : 0, 2, "Got the correct orgid for given GUID");
                        is(bundle->id, 975, "Got the correct bundleid for given GUID");
                        ok(pref_domainlist_match(&pr, NULL, AT_LIST_DESTBLOCK, blocked1, DOMAINLIST_MATCH_EXACT, NULL), "Found blocked.1 in the blocked list");
                        ok(pref_domainlist_match(&pr, NULL, AT_LIST_DESTBLOCK, blocked2, DOMAINLIST_MATCH_EXACT, NULL), "Found blocked.2 in the blocked list");
                        ok(!pref_domainlist_match(&pr, NULL, AT_LIST_DESTBLOCK, blocked3, DOMAINLIST_MATCH_EXACT, NULL), "Didn't find blocked.3 in the blocked list");
                        ok(pref_domainlist_match(&pr, NULL, AT_LIST_EXCEPT, exception1, DOMAINLIST_MATCH_EXACT, NULL), "Found exception.1 in the typo exception list");
                        ok(pref_domainlist_match(&pr, NULL, AT_LIST_EXCEPT, exception2, DOMAINLIST_MATCH_EXACT, NULL), "Found exception.2 in the typo exception list");
                        ok(pref_domainlist_match(&pr, NULL, AT_LIST_EXCEPT, exception3, DOMAINLIST_MATCH_EXACT, NULL), "Found exception.3 in the typo exception list");
                        ok(pref_domainlist_match(&pr, NULL, AT_LIST_DESTALLOW, white, DOMAINLIST_MATCH_EXACT, NULL), "Found white.list.domain in the white list");
                        ok(pref_domainlist_match(&pr, NULL, AT_LIST_DESTBLOCK, dropbox, DOMAINLIST_MATCH_EXACT, NULL), "Found dropbox.com in the fireeye list");
                        ok(pref_domainlist_match(&pr, NULL, AT_LIST_URL_PROXY_HTTPS, proxy, DOMAINLIST_MATCH_EXACT, NULL), "Found proxy.com in the url-proxy list");
                        ok(pref_domainlist_match(&pr, NULL, AT_LIST_DESTWARN, warn, DOMAINLIST_MATCH_EXACT, NULL), "Found warn.com in the warn list");
                    }
                }

                diag("    V%u orgid trumps GUID", DIRPREFS_VERSION);
                {
                    const char guid4[] = { 0x04, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 };

                    memset(&odns, '\0', sizeof odns);

                    odns.org_id = 1;
                    memcpy(&odns.user_id, guid4, sizeof odns.user_id);
                    odns.fields = ODNS_FIELD_ORG | ODNS_FIELD_USER;
                    oolist_clear(&ids);
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "8712752:5:1:365:0,6789971:22:1:365:0", "Collected other origin IDs: user, org");
                    ok(PREF_VALID(&pr), "Got prefs for orgid 1 for GUID 0x04444...");
                    is(dt, DIRPREFS_TYPE_ORG, "Got dirprefs type GUID");
                    skip_if(!PREF_VALID(&pr), 1, "Cannot run these tests without prefs")
                        is(PREF_BUNDLE(&pr)->bundleflags, 0x60, "The selected prefs were the org prefs");
                }

                diag("    V%u asset trumps GUID", DIRPREFS_VERSION);
                {
                    const char guid5[] = { 0x05, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

                    memset(&odns, '\0', sizeof odns);

                    odns.org_id = 4;
                    memcpy(&odns.user_id, guid5, sizeof odns.user_id);
                    odns.va_id = 2911559;

                    odns.fields = ODNS_FIELD_ORG | ODNS_FIELD_USER;
                    oolist_clear(&ids);
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "8712752:5:4:365:0", "Collected other origin IDs: user");
                    ok(PREF_VALID(&pr), "Got prefs for orgid 4 for GUID 0x05555...");
                    is(dt, DIRPREFS_TYPE_GUID, "Got dirprefs type GUID");
                    skip_if(!PREF_VALID(&pr), 1, "Cannot run these tests without prefs")
                        is(PREF_BUNDLE(&pr)->bundleflags, 0x60, "The selected prefs were the user prefs");

                    odns.fields = ODNS_FIELD_ORG | ODNS_FIELD_USER | ODNS_FIELD_VA;
                    oolist_clear(&ids);
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "8712752:5:4:365:0,2911559:13:4:365:0", "Collected other origin IDs: user, VA");
                    ok(PREF_VALID(&pr), "Got prefs for orgid 4 for GUID 0x05555... VA 2911559");
                    is(dt, DIRPREFS_TYPE_ASSET, "Got dirprefs type GUID");
                    skip_if(!PREF_VALID(&pr), 1, "Cannot run these tests without prefs")
                        is(PREF_BUNDLE(&pr)->bundleflags, 0x62, "The selected prefs were the VA prefs");
                }

                diag("    V%u lookup gets GUID priority 0 and assumes VA entry", DIRPREFS_VERSION);
                {
                    const char guid6[] = { 0x06, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 };

                    memset(&odns, '\0', sizeof odns);

                    odns.org_id = 5;
                    memcpy(&odns.user_id, guid6, sizeof odns.user_id);
                    odns.va_id = 4275878552;

                    odns.fields = ODNS_FIELD_USER | ODNS_FIELD_VA;
                    oolist_clear(&ids);
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    ok(!PREF_VALID(&pr), "dirprefs_get fails when ODNS_FIELD_ORG isn't set");
                    is(dt, DIRPREFS_TYPE_NONE, "Got dirprefs type NONE");
                    odns.fields |= ODNS_FIELD_ORG;
                    dirprefs_get(&pr, dp, &odns, &ids, &dt, NULL);
                    is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "8712753:7:5:365:0", "Collected other origin IDs: user");
                    ok(PREF_VALID(&pr), "Got prefs for orgid 4 for GUID 0x06666... VA 002c6d47");
                    is(dt, DIRPREFS_TYPE_GUID, "Got dirprefs type GUID");
                    skip_if(!PREF_VALID(&pr), 1, "Cannot run these tests without prefs")
                        is(PREF_BUNDLE(&pr)->bundleflags, 0x61, "The selected prefs were the user prefs");
                }

                ok(access("test-dirprefs-4.last-good", 0) == 0, "The test-dirprefs-4 update created test-dirprefs-4.last-good");
                unlink("test-dirprefs-4");
                ok(confset_load(NULL), "Noted an update for the test-dirprefs-4 removal");
                confset_release(set);

                ok(set = confset_acquire(&gen), "Acquired the new config");
                skip_if(set == NULL, 3, "Cannot check content without acquiring config") {
                    dp = dirprefs_conf_get(set, CONF_DIRPREFS);
                    ok(dp, "Obtained the revised struct dirprefs from segmented V%u data", DIRPREFS_VERSION);

                    ok(prefs_org_slot(dp->org, 4, dp->count) == 3 && dp->org[3]->cs.id != 4, "orgid 4 doesn't exist in struct dirprefs");
                    ok(access("test-dirprefs-4.last-good", 0) != 0, "The test-dirprefs-4 removal removed test-dirprefs-4.last-good");
                    confset_release(set);
                }
            }
        }
        OK_SXEL_ERROR(": 1: Invalid header; must contain 'dirprefs'");

        snprintf(content[0], sizeof(content[0]), "dirprefs %u\ncount 0\n%s", DIRPREFS_VERSION, "# Different\n");
        for (orgid = 100; orgid < 106; orgid++) {
            snprintf(buf, sizeof(buf), "test-dirprefs-%u", orgid);
            create_atomic_file(buf, "%s", content[0]);
        }
        ok(confset_load(NULL), "Loaded test-dirprefs-100 - test-dirprefs-105");

        MOCKFAIL_START_TESTS(5, DIRPREFS_MOREORGS);
        for (; orgid < 110; orgid++) {
            snprintf(buf, sizeof(buf), "test-dirprefs-%u", orgid);
            create_atomic_file(buf, "%s", content[0]);
        }
        ok(!confset_load(NULL), "Didn't see a change to test-dirprefs-106 - test-dirprefs-109  due to a dirprefs-org slot re-allocation failure");
        for (orgid = 106; orgid < 110; orgid++)
            OK_SXEL_ERROR("Couldn't reallocate 20 dirprefs org slots");
        MOCKFAIL_END_TESTS();

        snprintf(content[0], sizeof(content[0]), "dirprefs %u\ncount 0\n", DIRPREFS_VERSION);
        for (orgid = 100; orgid < 110; orgid++) {
            snprintf(buf, sizeof(buf), "test-dirprefs-%u", orgid);
            create_atomic_file(buf, "%s", content[0]);
        }
        ok(confset_load(NULL), "Loaded test-dirprefs-???");
    }

    oolist_clear(&ids);

    confset_unload();
    fileprefs_freehashes();
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    /* KIT_ALLOC_SET_LOG(0); */

    unlink("test-dirprefs");
    unlink("test-dirprefs-1");
    unlink("test-dirprefs-2");
    unlink("test-dirprefs-2.last-good");
    unlink("test-dirprefs-3");
    unlink("test-dirprefs-4");
    unlink("test-dirprefs-4.last-good");
    unlink("test-dirprefs-5");
    unlink("test-dirprefs-6");
    unlink("test-dirprefs-2748");
    for (orgid = 100; orgid < 110; orgid++) {
        snprintf(buf, sizeof(buf), "test-dirprefs-%u", orgid);
        unlink(buf);
    }

    OK_SXEL_ERROR(NULL);

    diag("Test prefs_org_slot()");
    {
        /* This test creates/manages its own dirprefs structure to exercise prefs_org_slot() */
#define ITERATIONS 100
        struct prefs_org dorg[ITERATIONS], *dorgp[ITERATIONS];
        int ahead, behind, hit, miss, overflow;
        uint32_t nextid;
        struct dirprefs d;
        unsigned i;

        memset(&d, '\0', sizeof d);
        d.org = dorgp;
        ahead = behind = hit = miss = overflow = 0;

        for (i = 0; i < ITERATIONS; i++)
            dorgp[i] = dorg + i;

        for (d.count = 0; d.count < ITERATIONS; d.count++) {
            nextid = (d.count << 1) + 1;
            for (orgid = 0; orgid < nextid; orgid++) {
                i = prefs_org_slot(d.org, orgid, d.count);
                if (i > d.count) {
                    diag("ERROR: Looking for %u, got pos %u (count %u) - expected pos <=%u", orgid, i, d.count, d.count);
                    overflow++;
                } else if (orgid & 1) {
                    if (i == d.count) {
                        diag("ERROR: Looking for %u, found <end> (count %u) - expected to find %u", orgid, d.count, orgid);
                        miss++;
                    } else if (d.org[i]->cs.id != orgid) {
                        diag("ERROR: Looking for %u, found %u at pos %u (count %u) - expected to find %u", orgid,
                             d.org[i]->cs.id, i, d.count, orgid);
                        miss++;
                    }
                } else if (i < d.count && d.org[i]->cs.id == orgid) {
                    diag("ERROR: Looking for %u, but found it pos %u (count %u) - expected >%u", orgid, i, d.count, orgid);
                    hit++;
                } else if (i && d.org[i - 1]->cs.id >= orgid) {
                    diag("ERROR: Looking for %u, found %u at pos %u, but the previous element is %u (count %u) - expected <%u",
                          orgid, d.org[i]->cs.id, i, d.org[i - 1]->cs.id, d.count, orgid);
                    ahead++;
                } else if (i < d.count && d.org[i]->cs.id < orgid) {
                    diag("ERROR: Looking for %u, but found %u at pos %u (count %u) - expected >%u",
                         orgid, d.org[i]->cs.id, i, d.count, orgid);
                    behind++;
                }
            }
            d.org[d.count]->cs.id = nextid;
        }
        is(overflow, 0, "No overflows were received from prefs_org_slot()");
        is(ahead, 0, "No results from prefs_org_slot() were too large");
        is(behind, 0, "No results from prefs_org_slot() were too small");
        is(miss, 0, "All odd values were found as dirprefs was built");
        is(hit, 0, "All even values were not found as dirprefs was built");
    }

    OK_SXEL_ERROR(NULL);
    test_uncapture_sxel();

    fileprefs_freehashes();
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");

    return exit_status();
}
