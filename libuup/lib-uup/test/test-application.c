#include <fcntl.h>
#include <kit-alloc.h>
#include <kit-random.h>
#include <mockfail.h>
#include <sys/stat.h>

#include "application-private.h"
#include "categorization.h"
#include "conf-meta.h"
#include "digest-store.h"
#include "dns-name.h"
#include "urllist-private.h"
#include "urlprefs-org.h"
#include "urlprefs.h"

#include "common-test.h"

static void
unlink_test_al_files(void)
{
    unsigned z;

    unlink("test-al");
    for (z = 1; z < 11; z++) {
        char rmfn[22];

        snprintf(rmfn, sizeof(rmfn), "test-al-%u", z);
        unlink(rmfn);
        snprintf(rmfn, sizeof(rmfn), "test-al-%u.last-good", z);
        unlink(rmfn);
    }
    unlink("test-al-2748");
}

static void
unlink_test_files(void)
{
    unlink("test-categorization");
    unlink_test_al_files();
}

int
main(void)
{
    module_conf_t CONF_APPLICATION, CONF_CATEGORIZATION, CONF_URLPREFS, reg;
    const struct application *app;
    struct application_lists *al;
    const char *expectstr, *fn;
    uint64_t start_allocations;
    struct confset *set, *nset;
    struct conf_info *info;
    struct conf_loader cl;
    char content[4][4096];
    unsigned expect, r, z;
    int gen, lines;
    bool ret;

    struct {
        const char *name;
        void (*reg)(module_conf_t *, const char *, const char *, bool loadable);
        bool proxy;
    } app_reg[] = {
        { "application_register_proxy", application_register_proxy, true },
        { "application_register", application_register, false },
    };

    plan_tests(426);

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
    /* KIT_ALLOC_SET_LOG(1); */    /* for kit-alloc-analyze data */

    unlink_test_files();

    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */

    diag("Test missing file load");
    {
        info = conf_info_new(NULL, "noname", "nopath", NULL, LOADFLAGS_NONE, NULL, 0);
        info->updates++;

        conf_loader_open(&cl, "/tmp/not-really-there", NULL, NULL, 0, CONF_LOADER_DEFAULT);
        al = application_lists_new(1, &cl, info);
        ok(!al, "Failed to read non-existent file");
        OK_SXEL_ERROR("not-really-there could not be opened: No such file or directory");
        OK_SXEL_ERROR("not-really-there: Missing header line");

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

    info = conf_info_new(NULL, "application", "test-al", NULL, LOADFLAGS_NONE, NULL, 0);

    diag("Test empty file");
    {
        fn = create_data("test-al", "%s", "");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(!al, "Failed to read empty file");
        OK_SXEL_ERROR(": Missing header line");
        OK_SXEL_ERROR(NULL);
    }

    diag("Test garbage file");
    {
        fn = create_data("test-al", "This is not the correct format\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(!al, "Failed to read garbage file");
        OK_SXEL_ERROR(": Unrecognized header line, expected 'lists 1' or 'domainlist 1");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-al", "lists 1\ncount 1\n[domains:1]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        info->loadflags = LOADFLAGS_APPLICATION_IGNORE_DOMAINS;
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(!al, "Failed to read file with EOF before ignored domains are done");
        OK_SXEL_ERROR(": 3: Got EOF after ignoring 0 of 1 domain");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-al", "lists 1\ncount 1\n[domains:1]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        info->loadflags = LOADFLAGS_NONE;
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(!al, "Failed to read file with EOF before domains are done");
        OK_SXEL_ERROR(": 3: Cannot load 1 line, got 0");
        OK_SXEL_ERROR(": 3: Failed to load domainlist");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-al", "lists 1\ncount 1\n[domains:1]\n[urls:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        info->loadflags = LOADFLAGS_APPLICATION_IGNORE_DOMAINS;
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(!al, "Failed to read file with [urls] section before ignored domains are done");
        OK_SXEL_ERROR(": 4: Got section header after ignoring 0 of 1 domain");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-al", "lists 1\ncount 1\n[domains:1]\n[urls:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        info->loadflags = LOADFLAGS_NONE;
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(!al, "Failed to read file with [urls] section before domains are done");
        OK_SXEL_ERROR("Invalid domain character (0x5b) found (offset 0)");
        OK_SXEL_ERROR(": 3: Failed to load domainlist");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-al", "lists 1\ncount 0\n[domains:0]\n[urls:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(al, "Read file with empty [domains] and [urls] sections");
        application_lists_refcount_dec(al);

        fn = create_data("test-al", "lists 1\ncount 0\n[urls:0]\n[domains:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(al, "Read file with empty [urls] and [domains] sections");
        application_lists_refcount_dec(al);

        fn = create_data("test-al", "lists 1\ncount 0\n[urls:1]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(!al, "Failed to read file with count 0 and EOF before urls are done");
        OK_SXEL_ERROR(": 3: Cannot load 1 line, got 0");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-al", "lists 1\ncount 1\n[urls:1]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(!al, "Failed to read file with count 1 and EOF before urls are done");
        OK_SXEL_ERROR(": 3: Cannot load 1 line, got 0");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-al", "lists 1\ncount 0\n[urls:1]\n[domains:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(!al, "Failed to read file with count 0 and [domains] before urls are done");
        OK_SXEL_ERROR("Offset 0: URL failed to normalize: '[domains:0]");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-al", "lists 1\ncount 0\n[urls:1]\n[domains:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        info->loadflags = LOADFLAGS_APPLICATION_URLS_AS_PROXY;
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(!al, "Failed to read file with count 0 and [domains] before urls are done when reading URLS as domains");
        OK_SXEL_ERROR("Invalid domain character (0x5b) found (offset 0)");
        OK_SXEL_ERROR(": 3: Failed to load domains from URL list");
        OK_SXEL_ERROR(NULL);

        fn = create_data("test-al", "lists 1\ncount 1\n[urls:1]\n[domains:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        info->loadflags = LOADFLAGS_NONE;
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(!al, "Failed to read file with count 1 and [domains] before urls are done");
        OK_SXEL_ERROR("Offset 0: URL failed to normalize: '[domains:0]");
        OK_SXEL_ERROR(NULL);

        conf_loader_fini(&cl);
    }

    diag("Test V%u data load", APPLICATION_VERSION - 1);
    {
        fn = create_data("test-al", "domainlist %u\ncount 0\n", APPLICATION_VERSION - 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(!al, "Failed to read version %u data", APPLICATION_VERSION - 1);
        OK_SXEL_ERROR(": 1: Unrecognized header version, expected 1, not 0");
        OK_SXEL_ERROR(NULL);
    }

    diag("Test V%u data load", APPLICATION_VERSION + 1);
    {
        fn = create_data("test-al", "domainlist %u\ncount 0\n", APPLICATION_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        al = application_lists_new(0, &cl, info);
        unlink(fn);
        ok(!al, "Failed to read version %u data", APPLICATION_VERSION + 1);
        OK_SXEL_ERROR(": 1: Unrecognized header version, expected 1, not 2");
        OK_SXEL_ERROR(NULL);
    }

    conf_info_free(info);
    conf_loader_fini(&cl);

    /* KIT_ALLOC_SET_LOG(1); */
    is(memory_allocations(), start_allocations, "All memory allocations were freed after out-of-version-range tests");

    categorization_register(&CONF_CATEGORIZATION, "categorization", "test-categorization", true);
    digest_store_set_options("al-digest-dir", 1, DIGEST_STORE_DEFAULT_MAXIMUM_AGE);

    for (CONF_APPLICATION = 0, r = 0; r < sizeof(app_reg) / sizeof(*app_reg); r++) {
        if (r)
            sleep(2);    /* For the digest */

        app_reg[r].reg(&CONF_APPLICATION, "application", "test-al-%u", true);
        OK_SXEL_ERROR(NULL);
        reg = 0;
        application_register_resolver(&reg, "application", "test-more-al-%u", true);
        is(reg, 0, "Cannot register application twice by name");
        OK_SXEL_ERROR("application: Config name already registered as ./test-al-%%u");
        OK_SXEL_ERROR(NULL);

        diag("Test V%u empty data load", APPLICATION_VERSION);
        {
            snprintf(content[0], sizeof(content[0]), "domainlist %u\ncount 0\n%s", APPLICATION_VERSION, "");
            snprintf(content[1], sizeof(content[1]), "domainlist %u\ncount 0\n%s", APPLICATION_VERSION, "[meta:0]\n[data:0]\n");
            snprintf(content[2], sizeof(content[2]), "domainlist %u\ncount 0\n%s", APPLICATION_VERSION, "[meta:0]\n");
            snprintf(content[3], sizeof(content[3]), "domainlist %u\ncount 0\n%s", APPLICATION_VERSION, "[data:0]\n");

            for (z = 0; z < 4; z++) {
                create_atomic_file("test-al-1", "%s", content[z]);

                ok(confset_load(NULL), "Noted an update to test-al-1 item %u", z);
                ok(!confset_load(NULL), "A second confset_load() call results in nothing");
                ok(set = confset_acquire(&gen), "Acquired the new config");
                skip_if(set == NULL, 5, "Cannot check content without acquiring config") {
                    app = application_conf_get(set, CONF_APPLICATION);
                    ok(app, "Constructed application from empty V%u data", APPLICATION_VERSION);
                    skip_if(app == NULL, 3, "Cannot check content of NULL application") {
                        is(app->count, 1, "V%u data has a count of 1 list", APPLICATION_VERSION);
                        is(app->conf.refcount, 2, "V%u data has a refcount of 2", APPLICATION_VERSION);
                        skip_if(!app->count, 1, "Cannot verify org count")
                            ok(app->al[0]->dl == NULL, "V%u data has a NULL domainlist", APPLICATION_VERSION);
                    }
                    confset_release(set);
                    is(app ? app->conf.refcount : 0, 1, "confset_release() dropped the refcount back to 1");
                }
            }
        }

        diag("Test V%u data load with extra lines after each section", APPLICATION_VERSION);
        {
            const char *data[] = { "[meta:0]\n", "[data:0]\n" };
            const char *extra = "extra-garbage\n";
            const char *l[3];
            unsigned i;

            create_atomic_file("test-al-1", "domainlist %u\ncount 0\n%s%s", APPLICATION_VERSION, data[0], data[1]);
            ok(confset_load(NULL), "Noted an update for koshir v%u data", APPLICATION_VERSION);
            OK_SXEL_ERROR(NULL);

            for (z = 0; z < 2; z++) {
                for (i = 0; i <= z; i++)
                    l[i] = data[i];
                l[i] = extra;
                for (; i < 3; i++)
                    l[i] = data[i - 1];
                create_atomic_file("test-al-1", "domainlist %u\ncount 0\n%s%s%s", APPLICATION_VERSION, l[0], l[1], l[2]);
                ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with extra garbage", APPLICATION_VERSION);
                OK_SXEL_ERROR(": Unexpected line");
            }

            OK_SXEL_ERROR(NULL);
        }

        diag("Test V%u data load with an invalid count line", APPLICATION_VERSION);
        {
            create_atomic_file("test-al-2748", "domainlist %u\nwrong\n", APPLICATION_VERSION);
            ok(!confset_load(NULL), "Noted no update; Missing version %u count line", APPLICATION_VERSION);
            OK_SXEL_ERROR("test-al-2748: 2: Unrecognized count line, expected 'count <N>'");

            create_atomic_file("test-al-2748", "domainlist %u\ncount 1\n", APPLICATION_VERSION);
            ok(!confset_load(NULL), "Noted no update; Wrong version %u count line", APPLICATION_VERSION);
            OK_SXEL_ERROR("test-al-2748: 2: Headers don't add up; count 1 != meta 0 + domainlist 0 + urllist 0");
            OK_SXEL_ERROR(NULL);
        }

        diag("Test V%u data load with missing lines", APPLICATION_VERSION);
        {
            const char *goodmeta = "[meta:2]\nname bob\nage 12\n";
            const char *badmeta = "[meta:2]\nname bob\n";
            const char *gooddata = "[data:2]\nbob.com\nbob2.com\n";
            const char *baddata = "[data:2]\nbob.com\n";

            create_atomic_file("test-al-2748", "domainlist %u\ncount 2\n%s", APPLICATION_VERSION, goodmeta);
            ok(confset_load(NULL), "Noted an update; Read valid version %u meta", APPLICATION_VERSION);

            create_atomic_file("test-al-2748", "domainlist %u\ncount 2\n%s", APPLICATION_VERSION, badmeta);
            ok(!confset_load(NULL), "Noted no update; Failed to read bad version %u meta", APPLICATION_VERSION);
            OK_SXEL_ERROR("test-al-2748: 4: Found 1 meta lines, expected 2");

            create_atomic_file("test-al-2748", "domainlist %u\ncount 2\n%s", APPLICATION_VERSION, gooddata);
            ok(confset_load(NULL), "Noted an update; Read valid version %u data", APPLICATION_VERSION);

            create_atomic_file("test-al-2748", "domainlist %u\ncount 2\n%s", APPLICATION_VERSION, baddata);
            ok(!confset_load(NULL), "Noted no update; Failed to read bad version %u data", APPLICATION_VERSION);
            if (app_reg[r].proxy)
                OK_SXEL_ERROR("test-al-2748: 4: Got EOF after ignoring 1 of 2 domains");
            else {
                OK_SXEL_ERROR("test-al-2748: 4: Cannot load 2 lines, got 1");
                OK_SXEL_ERROR("test-al-2748: 3: Failed to load domainlist");
            }

            create_atomic_file("test-al-2748", "domainlist %u\ncount 4\n%s%s", APPLICATION_VERSION, goodmeta, gooddata);
            ok(confset_load(NULL), "Noted an update; Read valid version %u meta & data", APPLICATION_VERSION);

            create_atomic_file("test-al-2748", "domainlist %u\ncount 4\n%s%s", APPLICATION_VERSION, goodmeta, baddata);
            ok(!confset_load(NULL), "Noted no update; Failed to read version %u meta with bad data", APPLICATION_VERSION);
            if (app_reg[r].proxy)
                OK_SXEL_ERROR("test-al-2748: 7: Got EOF after ignoring 1 of 2 domains");
            else {
                OK_SXEL_ERROR("test-al-2748: 7: Cannot load 2 lines, got 1");
                OK_SXEL_ERROR("test-al-2748: 6: Failed to load domainlist");
            }

            create_atomic_file("test-al-2748", "domainlist %u\ncount 4\n%s%s", APPLICATION_VERSION, badmeta, gooddata);
            ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with bad meta", APPLICATION_VERSION);
            OK_SXEL_ERROR("test-al-2748: 6: Unexpected line");

            create_atomic_file("test-al-2748", "domainlist %u\ncount 4\n%s%s", APPLICATION_VERSION, badmeta, baddata);
            ok(!confset_load(NULL), "Noted no update; Failed to read bad version %u meta & data", APPLICATION_VERSION);
            OK_SXEL_ERROR("test-al-2748: 6: Unexpected line");

            create_atomic_file("test-al-2748", "domainlist %u\ncount 4\n%s%s", APPLICATION_VERSION, gooddata, goodmeta);
            ok(!confset_load(NULL), "Noted no update; Failed to read version %u data & meta (wrong order)", APPLICATION_VERSION);
            OK_SXEL_ERROR(app_reg[r].proxy ? "test-al-2748: 6: Unexpected line" : "test-al-2748: 6: Unexpected line");

            create_atomic_file("test-al-2748", "domainlist %u\ncount 4\n%s%s", APPLICATION_VERSION, goodmeta, gooddata);
            ok(confset_load(NULL), "Noted an update; Read valid version %u meta & data", APPLICATION_VERSION);
        }
        OK_SXEL_ERROR(NULL);

        diag("Test V%u data handling", APPLICATION_VERSION);
        {
            const uint8_t *match;
            const char *err;

            snprintf(content[0], sizeof(content[0]),
                     "domainlist %u\n"
                     "count 5\n"
                     "[data:5]\n"
                     "a.net\n"
                     "x.com\n"
                     "b.x.com\n"
                     "z.x.com\n"
                     "a.com\n",
                     APPLICATION_VERSION);
            snprintf(content[1], sizeof(content[1]),
                     "lists %u\n"
                     "count 6\n"
                     "[domains:3]\n"
                     "a.x.com\n"
                     "a.net\n"
                     "a.com\n"
                     "[urls:3]\n"
                     "c.net/some/url/path\n"
                     "c.com/cgi-bin/post-prog\n"
                     "c.com/cgi-bin/other-prog\n",
                     APPLICATION_VERSION);
            snprintf(content[2], sizeof(content[2]),
                     "domainlist %u\n"
                     "count 0\n",
                     APPLICATION_VERSION);
            snprintf(content[3], sizeof(content[3]),
                     "lists %u\n"
                     "count 4\n"
                     "[meta:1]\n"
                     "name bob\n"
                     "[domains:2]\n"
                     "bob.com\n"
                     "bob.net\n"
                     "[urls:1]\n"
                     "api.bobdata.com/bobpost\n",
                     APPLICATION_VERSION);

            /* Now do some content testing */
            create_atomic_file("test-al-1", "%s", content[0]);
            create_atomic_file("test-al-2", "%s", content[1]);
            create_atomic_file("test-al-3", "%s", content[2]);
            ok(confset_load(NULL), "Noted an update to test-al-1, test-al-2 and test-al-3");

            MOCKFAIL_START_TESTS(3, CONF_META_ALLOC);
            strcat(content[3], "# kick\n");
            create_atomic_file("test-al-4", "%s", content[3]);
            ok(!confset_load(NULL), "Didn't see test-al-4 turn up when conf-meta struct allocation fails");
            err = test_shift_sxel();
            is_strstr(err, "Cannot allocate ", "Found the correct error start: 'Cannot allocate ...'");
            is_strstr(err, " conf-meta bytes", "Found the correct error end: '... conf-meta bytes'");
            MOCKFAIL_END_TESTS();

            MOCKFAIL_START_TESTS(2, CONF_META_NAMEALLOC);
            strcat(content[3], "# kick\n");
            create_atomic_file("test-al-4", "%s", content[3]);
            ok(!confset_load(NULL), "Didn't see test-al-4 turn up when conf-meta name allocation fails");
            OK_SXEL_ERROR("test-al-4: 4: Cannot allocate 4 name bytes");
            MOCKFAIL_END_TESTS();

            MOCKFAIL_START_TESTS(3, APPLICATION_CLONE_DOMAINLISTS);
            strcat(content[3], "# kick\n");
            create_atomic_file("test-al-4", "%s", content[3]);
            ok(!confset_load(NULL), "Didn't see test-al-4 turn up when application-lists clone fails");
            OK_SXEL_ERROR("Couldn't allocate 10 new application domainlist slots");
            OK_SXEL_ERROR("Couldn't clone a application conf object");
            MOCKFAIL_END_TESTS();

            MOCKFAIL_START_TESTS(3, application_lists_new);
            strcat(content[3], "# kick\n");
            create_atomic_file("test-al-4", "%s", content[3]);
            ok(!confset_load(NULL), "Didn't see test-al-4 turn up when application-lists allocation fails");
            err = test_shift_sxel();
            is_strstr(err, "Cannot allocate ", "Found the correct error start: 'Cannot allocate ...'");
            is_strstr(err, " bytes for an application-lists object", "Found the correct error end: '... bytes for an application-lists object'");
            MOCKFAIL_END_TESTS();

            strcat(content[3], "# kick\n");
            create_atomic_file("test-al-4", "%s", content[3]);
            ok(confset_load(NULL), "Noted an update to test-al-4");

            ok(set = confset_acquire(&gen), "Acquired the new config");
            skip_if(set == NULL, 58, "Cannot check content without acquiring config") {
                app = application_conf_get(set, CONF_APPLICATION);
                ok(app, "Constructed an application from segmented V%u data", APPLICATION_VERSION);
                skip_if(app == NULL, 53, "Cannot check app") {
                    is(app->count, 5, "V%u data has a count of 5 lists", APPLICATION_VERSION);
                    is(app->conf.refcount, 2, "V%u data has a refcount of 2", APPLICATION_VERSION);

                    expect = app_reg[r].reg == application_register ? 6 : 0;
                    is(app->dindex.count, expect, "application domain super-index has %u entries (registered with %s())", expect, app_reg[r].name);

                    is(app->pindex.count, 0, "application proxy super-index has 0 entries (not 2)");
                    skip_if(app->count != 5, 48, "Cannot verify list counts") {
                        is(app->al[0]->cs.id, 1, "V%u domainlist in slot 0 is id 1", APPLICATION_VERSION);
                        expect = app_reg[r].reg == application_register ? app->al[0]->dl != 0 : app->al[0]->dl == 0;
                        ok(expect, "V%u domainlist in slot 0 is %sset", APPLICATION_VERSION, expect ? "" : "not ");
                        ok(!app->al[0]->ul, "V%u urllist in slot 0 is unallocated", APPLICATION_VERSION);
                        is(app->al[1]->cs.id, 2, "V%u domainlist in slot 1 is id 2", APPLICATION_VERSION);
                        expect = app_reg[r].reg == application_register ? app->al[1]->dl != 0 : app->al[1]->dl == 0;
                        ok(expect, "V%u domainlist in slot 1 is %sset", APPLICATION_VERSION, expect ? "" : "not ");
                        is(app->al[1]->ul->hash_size, 1, "V%u urllist in slot 1 has a hash size of 1", APPLICATION_VERSION);
                        is(app->al[2]->cs.id, 3, "V%u domainlist in slot 2 is id 3", APPLICATION_VERSION);
                        ok(app->al[2]->dl == NULL, "V%u domainlist in slot 2 has no domainlist", APPLICATION_VERSION);
                        ok(!app->al[2]->ul, "V%u urllist in slot 2 is unallocated", APPLICATION_VERSION);
                        is(app->al[3]->cs.id, 4, "V%u domainlist in slot 3 is id 4", APPLICATION_VERSION);
                        expect = app_reg[r].reg == application_register ? app->al[3]->dl != 0 : app->al[3]->dl == 0;
                        ok(expect, "V%u domainlist in slot 3 is %sset", APPLICATION_VERSION, expect ? "" : "not ");
                        is(app->al[3]->ul->hash_size, 1, "V%u urllist in slot 3 has a hash size of 1", APPLICATION_VERSION);
                        is(app->al[4]->cs.id, 2748, "V%u domainlist in slot 4 is id 2748", APPLICATION_VERSION);
                        expect = app_reg[r].reg == application_register ? app->al[4]->dl != 0 : app->al[4]->dl == 0;
                        ok(expect, "V%u domainlist in slot 4 is %sset", APPLICATION_VERSION, expect ? "" : "not ");
                        ok(!app->al[4]->ul, "V%u urllist in slot 4 is unallocated", APPLICATION_VERSION);

                        match = application_match_domain_byid(app, 1, (const uint8_t *)"\1x\3com", NULL);
                        expectstr = app_reg[r].reg == application_register ? "x.com" : "<NULL>";
                        is_eq(match ? dns_name_to_str1(match) : "<NULL>", expectstr, "appid 1 matches %s", expectstr);
                        ok(!application_match_domain_byid(app, 1, (const uint8_t *)"\1bob\3com", NULL), "appid 1 doesn't contain bob.com");
                        ok(!application_match_url_byid(app, 1, "c.com/cgi-bin", 13), "appid 1 doesn't contain c.com/cgi-bin");
                        ok(!application_match_url_byid(app, 2, "c.com/cgi-bin", 13), "appid 2 doesn't contain c.com/cgi-bin");
                        ok(application_match_url_byid(app, 2, "c.com/cgi-bin/post-prog", 23), "appid 2 contains c.com/cgi-bin/post-prog");
                        ok(!application_proxy_byid(app, 2, (const uint8_t *)"\1c\3com", NULL), "appid 2 doesn't proxy c.com");
                        ok(!application_match_url_byid(app, 2, "c.com/cgi-bin/post", 18), "appid 2 doesn't contain c.com/cgi-bin/post");
                        ok(!application_match_url_byid(app, 2, "c.com/cgi-bin/get-prog", 22), "appid 2 doesn't contain c.com/cgi-bin/get-prog");
                        match = application_match_domain_byid(app, 4, (const uint8_t *)"\4mail\3bOb\3com", NULL);
                        expectstr = app_reg[r].reg == application_register ? "bOb.com" : "<NULL>";
                        is_eq(match ? dns_name_to_str1(match) : "<NULL>", expectstr, "appid 4 matches %s", expectstr);

                        ret = application_match_domain(app, (const uint8_t *)"\1x\3com", NULL, "app");
                        expect = app_reg[r].reg == application_register ? 1 : 0;
                        is(ret, expect, "application %s x.com", expect ? "contains" : "doesn't contain");
                        ret = application_match_domain(app, (const uint8_t *)"\3bob\3com", NULL, "app");
                        expect = app_reg[r].reg == application_register ? 1 : 0;
                        is(ret, expect, "application %s bob.com", expect ? "contains" : "doesn't contain");
                        ret = application_match_domain(app, (const uint8_t *)"\3ten\3bob\3net", NULL, "app");
                        expect = app_reg[r].reg == application_register ? 1 : 0;
                        is(ret, expect, "application %s subdomain ten.bob.com", expect ? "contains" : "doesn't contain");
                        diag("The proxy needs to search a pref_t for application matches");
                        {
                            pref_categories_t cat;
                            pref_t pr;
                            char app_list_str[100];

                            create_atomic_file("test-urlprefs-1",
                                               "urlprefs %d\n"
                                               "count 3\n"
                                               "[lists:2]\n"
                                               "18:4242:application:152:00000000000000000000000000000003:2\n"
                                               "1C:200:application::00000000000000000000000000011119:400 500\n"
                                               "[orgs:1]\n"
                                               "1:0:0:365:0:1001:0\n", URLPREFS_VERSION);
                            create_atomic_file("test-urlprefs-666",
                                               "urlprefs %d\n"
                                               "count 6\n"
                                               "[lists:5]\n"
                                               "0:1:url:71:00000000000000000000000000000000:my-mixed-list-proxydomain.com/somePath/\n"
                                               "0:4:url:70:00000000000000000000000000000001:fireeye1\n"
                                               "14:4:application:148:00000000000000000000000000000002:1 4\n"
                                               "18:42:application:148:00000000000000000000000000000003:2 3 42\n"
                                               "24:66:application:159:00000000000000000000000000000004:6 9 19\n"
                                               "[orgs:1]\n"
                                               "666:0:0:365:0:1001:0\n", URLPREFS_VERSION);
                            create_atomic_file("test-urlprefs-1234",
                                               "urlprefs %d\n"
                                               "count 10\n"
                                               "[lists:3]\n"
                                               "14:14:application:151:00000000000000000000000000000002:1 4\n"
                                               "18:142:application:148:00000000000000000000000000000003:2 3 42\n"
                                               "1C:199:application::00000000000000000000000000000019:100 200 300\n"
                                               "[bundles:6]\n"
                                               "0:1:0004:61:1F000000000000001F:::::::14::::\n"
                                               "0:3:0100:60:1F0000000000000000::4:::::4::::\n"
                                               "0:19:0001:62:1F00000000000000F1::::42::::42:::\n"
                                               "0:99:0001:62:1F00000000000000F1::::::::4242:::\n"
                                               "0:1234:0002:60:2F000000000000FF01::::::::142:::66\n"
                                               "0:1235:0002:60:2F000000000000FF01::::::::142:199 200::66\n"
                                               "[orgs:1]\n"
                                               "1234:0:0:365:0:1001:666\n", URLPREFS_VERSION);
                            CONF_URLPREFS = 0;
                            urlprefs_register(&CONF_URLPREFS, "urlprefs", "test-urlprefs-%u", true);
                            ok(confset_load(NULL), "Noted new urlprefs files");
                            ok(nset = confset_acquire(&gen), "Acquired the config set that includes urlprefs");
                            skip_if(!nset, 19, "Cannot test without a urlprefs object") {
                                ok(urlprefs_get_policy(urlprefs_conf_get(nset, CONF_URLPREFS), &pr, 1234, 1), "Found prefs for org 1234, bundle 1");

                                pref_categories_setnone(&cat);
                                is(pref_applicationlist_url_match(&pr, app, AT_LIST_APPBLOCK, "api.bobdata.com/bobpost", 23, &cat), 4, "Found bobpost block in app 4");
                                is_eq(pref_categories_idstr(&cat), "80000000000000000000000000000000000000", "The correct category bit (151) is set");
                                is(pref_applicationlist_url_match(&pr, app, AT_LIST_APPBLOCK, "api.bobdata.com/nothing", 23, &cat), 0, "Didn't find nothing block");
                                is_eq(pref_categories_idstr(&cat), "80000000000000000000000000000000000000", "The previous category bit is still set");

                                ok(urlprefs_get_policy(urlprefs_conf_get(nset, CONF_URLPREFS), &pr, 1234, 3), "Found prefs for org 1234, bundle 3");
                                is(pref_applicationlist_url_match(&pr, app, AT_LIST_APPBLOCK, "api.bobdata.com/bobpost", 23, &cat), 4, "Found bobpost block in app 4");
                                is_eq(pref_categories_idstr(&cat), "90000000000000000000000000000000000000", "Added the new category bit (148) correctly");

                                ok(urlprefs_get_policy(urlprefs_conf_get(nset, CONF_URLPREFS), &pr, 1234, 19), "Found prefs for org 1234, bundle 19");
                                pref_categories_setnone(&cat);
                                is(pref_applicationlist_url_match(&pr, app, AT_LIST_APPALLOW, "c.com/cgi-bin/other-prog", 24, &cat), 2, "Found other-prog allow in app 2");

                                ok(urlprefs_get_policy(urlprefs_conf_get(nset, CONF_URLPREFS), &pr, 1234, 99), "Found prefs for org 1234, bundle 99");
                                pref_categories_setnone(&cat);
                                is(pref_applicationlist_url_match(&pr, app, AT_LIST_APPALLOW, "c.com/cgi-bin/other-prog", 24, &cat), 2, "Found other-prog allow in app 2");
                                is_eq(pref_categories_idstr(&cat), "100000000000000000000000000000000000000", "The correct category bit (152) is set");

                                ok(urlprefs_get_policy(urlprefs_conf_get(nset, CONF_URLPREFS), &pr, 1234, 1234), "Found prefs for org 1234, bundle 1234");
                                pref_categories_setnone(&cat);
                                is(pref_applicationlist_url_match(&pr, app, AT_LIST_APPALLOW, "c.com/cgi-bin/post-prog", 23, &cat), 2, "Found post-prog allow in app 2");
                                is(pref_applicationlist_url_match(&pr, app, AT_LIST_APPALLOW, "c.com/cgi-bin/post-prog", 23, &cat), 2, "Found again with a repeated match");
                                is_eq(pref_categories_idstr(&cat), "10000000000000000000000000000000000000", "The correct category bit (148) is set");
                                pref_categories_setnone(&cat);
                                is(pref_applicationlist_url_match(&pr, app, AT_LIST_APPALLOW, "c.com/cgi-bin/get-prog", 22, &cat), 0, "Didn't find get-prog allow");
                                ok(pref_categories_isnone(&cat), "No categories were set");

                                // Tests for pref_applicationlist_appid_match
                                ok(urlprefs_get_policy(urlprefs_conf_get(nset, CONF_URLPREFS), &pr, 1234, 1), "Found prefs for org 1234, bundle 1");
                                pref_categories_setnone(&cat);
                                is(pref_applicationlist_appid_match(&pr, AT_LIST_APPBLOCK, 4, &cat), true, "Found block for app 4");
                                is_eq(pref_categories_idstr(&cat), "80000000000000000000000000000000000000", "The correct category bit (151) is set");

                                pref_categories_setnone(&cat);
                                is(pref_applicationlist_appid_match(&pr, AT_LIST_APPALLOW, 4, &cat), false, "Didn't find allow for app 4");
                                ok(pref_categories_isnone(&cat), "No categories were set");

                                pref_categories_setnone(&cat);
                                is(pref_applicationlist_appid_match(&pr, AT_LIST_APPBLOCK, 9797, &cat), false, "Didn't find allow for app 9797 (not in pref)");
                                ok(pref_categories_isnone(&cat), "No categories were set");
                                is(pref_applicationlist_appid_match(&pr, AT_LIST_APPALLOW, 9797, &cat), false, "Didn't find block for app 9797 (not in pref)");
                                ok(pref_categories_isnone(&cat), "No categories were set");

                                ok(urlprefs_get_policy(urlprefs_conf_get(nset, CONF_URLPREFS), &pr, 1234, 99), "Found prefs for org 1234, bundle 99");
                                pref_categories_setnone(&cat);
                                is(pref_applicationlist_appid_match(&pr, AT_LIST_APPALLOW, 2, &cat), true, "Found allow for app 2");
                                is_eq(pref_categories_idstr(&cat), "100000000000000000000000000000000000000", "The correct category bit (152) is set");

                                // Tests for no-decrypt application list
                                ok(urlprefs_get_policy(urlprefs_conf_get(nset, CONF_URLPREFS), &pr, 1234, 1235), "Found prefs for org 1234, bundle 1235");
                                ok(pref_get_app_list_str(&pr, AT_LIST_APPNODECRYPT, app_list_str, 100), "App list fetched");
                                ok(!strcmp(app_list_str, "100,200,300,400,500"), "Expected apps found");
                                ok(!pref_get_app_list_str(&pr, AT_LIST_APPNODECRYPT, app_list_str, 0), "Smaller sized array sent");
                                ok(!pref_get_app_list_str(&pr, AT_LIST_APPNODECRYPT, app_list_str, 1), "Smaller sized array sent");
                                ok(!pref_get_app_list_str(&pr, AT_LIST_APPNODECRYPT, app_list_str, 4), "Smaller sized array sent");
                                ok(!pref_get_app_list_str(&pr, AT_LIST_APPNODECRYPT, app_list_str, 13), "Smaller sized array sent");
                                ok(!pref_get_app_list_str(&pr, AT_LIST_APPNODECRYPT, app_list_str, 16), "Smaller sized array sent");
                                ok(!strcmp(app_list_str, ""), "Return empty string for smaller sized array");

                                // Tests for APP_WARN matches
                                ok(urlprefs_get_policy(urlprefs_conf_get(nset, CONF_URLPREFS), &pr, 1234, 1234), "Found prefs for org 1234, bundle 1234");
                                pref_categories_setnone(&cat);
                                is(pref_applicationlist_appid_match(&pr, AT_LIST_APPWARN, 6, &cat), true, "Found warn for app 6");
                                is_eq(pref_categories_idstr(&cat), "8000000000000000000000000000000000000000", "The correct category bit (159) is set");
                                pref_categories_setnone(&cat);
                                is(pref_applicationlist_appid_match(&pr, AT_LIST_APPWARN, 4, &cat), false, "Did not find warn for app 4");
                                ok(pref_categories_isnone(&cat), "No categories were set");

                                confset_release(nset);
                            }
                            conf_unregister(CONF_URLPREFS);
                            CONF_URLPREFS = 0;
                            unlink("test-urlprefs-1234");
                            unlink("test-urlprefs-666");
                            unlink("test-urlprefs-1");
                        }
                    }
                    is(app->conf.refcount, 2, "Before confset_release(), refcount is 2 (me and dispatch queue)");
                }

                /* setup digest_store_dir */
                is(rrmdir("al-digest-dir"), 0, "Removed al-digest-dir with no errors");
                is(mkdir("al-digest-dir", 0755), 0, "Created al-digest-dir");
                digest_store_changed(set);
                diag("Looking at the al-digest-dir directory");
                lines = showdir("al-digest-dir", stdout);
                is(lines, 6, "Found 6 lines of data (categorization and 5 application files)");

                confset_release(set);

                is(rrmdir("al-digest-dir"), 0, "Removed al-digest-dir with no errors");
            }

            OK_SXEL_ERROR(NULL);

            conf_unregister(CONF_APPLICATION);
            CONF_APPLICATION = 0;

            /* By default we have a categorization controlled application */
            ok(confset_load(NULL), "Noted the removal of test-al-%%u");
            create_atomic_file("test-categorization", "categorization 1\n" "application:application:test-al-%%u:148::");

            MOCKFAIL_START_TESTS(3, APPLICATION_CLONE);
            ok(confset_load(NULL), "Loaded the categorization file... but not the application file (clone failure)");
            OK_SXEL_ERROR("Couldn't allocate an application structure");
            OK_SXEL_ERROR("Couldn't clone a application conf object");
            MOCKFAIL_END_TESTS();

            ok(confset_load(NULL), "Noted an update to categorized application lists");

            for (z = 5; z < 10; z++) {
                char emptyfn[12];

                snprintf(emptyfn, sizeof(emptyfn), "test-al-%u", z);
                create_atomic_file(emptyfn, "domainlist 1\ncount 0");
            }
            ok(confset_load(NULL), "Loaded 5 empty domainlists");

            create_atomic_file("test-al-10", "domainlist 1\ncount 0");

            MOCKFAIL_START_TESTS(2, APPLICATION_MOREDOMAINLISTS);
            ok(!confset_load(NULL), "Cannot load confset when allocating more application domainlists fails");
            OK_SXEL_ERROR("Couldn't reallocate 20 application domainlist slots");
            MOCKFAIL_END_TESTS();

            create_atomic_file("test-al-10", "domainlist 1\ncount 0\n#changed\n");
            ok(confset_load(NULL), "Loaded a 6th empty application domainlist");

            ok(set = confset_acquire(&gen), "Acquired the new config");
            skip_if(set == NULL, 8, "Cannot check content without acquiring config") {
                const struct categorization *categorization = categorization_conf_get(set, CONF_CATEGORIZATION);
                pref_categories_t            got, find;

                pref_categories_setnone(&find);
                pref_categories_setnone(&got);

                ok(!categorization_match_appid(categorization, set, &got, 2, (const uint8_t *)"\1a\1x\3com", 0, 0, &find, NULL),
                   "categorization doesn't match if not asked");
                pref_categories_setbit(&find, CATEGORY_BIT_APPLICATION);
                ok(categorization_match_appid(categorization, set, &got, 2, (const uint8_t *)"\1a\1x\3com", 0, 0, &find, NULL),
                   "categorization matches appid 2 for a.x.com");
                ok(pref_categories_getbit(&got, CATEGORY_BIT_APPLICATION), "categorization match sets the APPLICATION bit");
                ok(!categorization_match_appid(categorization, set, &got, 2, (const uint8_t *)"\1x\3com", 0, 0, &find, NULL),
                   "categorization doesn't match appid 2 for x.com");
                ok(categorization_might_proxy(categorization, set, (const uint8_t *)"\1c\3com", 0, 0, NULL),
                   "We might proxy c.com...");
                ok(categorization_proxy_appid(categorization, set, 2, (const uint8_t *)"\1c\3com", 0, 0, NULL),
                   "appid 2 proxies c.com");
                ok(!categorization_might_proxy(categorization, set, (const uint8_t *)"\3sub\1c\3com", 0, 0, NULL),
                   "We have no chance of proxying sub.c.com");
                ok(!categorization_proxy_appid(categorization, set, 2, (const uint8_t *)"\3sub\1c\3com", 0, 0, NULL),
                   "appid 2 doesn't proxy sub.c.com");

                confset_release(set);
            }
            unlink_test_al_files();
            ok(confset_load(NULL), "Noted an update for the test-al* removal");
        }
        create_atomic_file("test-categorization", "categorization 1\n");
        ok(confset_load(NULL), "Noted an update for the truncation of test-categorization");
        OK_SXEL_ERROR(NULL);
    }

    confset_unload();
    fileprefs_freehashes();
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    /* KIT_ALLOC_SET_LOG(0); */

    unlink_test_files();

    return exit_status();
}
