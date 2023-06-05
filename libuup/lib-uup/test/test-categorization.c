#include <fcntl.h>
#include <kit-alloc.h>
#include <kit-random.h>
#include <mockfail.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "categorization-private.h"
#include "conf-loader.h"
#include "dns-name.h"
#include "domaintagging.h"

#include "common-test.h"

static int
tidyfiles(int ret)
{
    if (ret == 0) {
        unlink("bobfile");
        unlink("bobfile.last-good");
        unlink("catfile");
        unlink("catfile.last-good");
        unlink("do-not-proxy");
        unlink("ifile");
        unlink("race-file");
    }

    return ret;
}

static void *
use_dynamic_counter_slot(void *arg)
{
    SXE_UNUSED_PARAMETER(arg);
    kit_counters_fini_dynamic_thread(kit_counters_init_dynamic_thread());
    fflush(stderr);
    return NULL;
}

extern void *(*test_register_race_alloc)(void *nset, size_t sz);
static module_conf_t racey;
static void *
register_race_alloc(void *nset, size_t sz)
{
    if (racey == 0) {
        SXEL6("Caught the registration realloc to %zu bytes... registering the race-file", sz);
        domainlist_register(&racey, "race-file", "race-file", true);
    }
    return kit_realloc(nset, sz);
}

static bool
wait_for_conf_load(void)
{
    int i;

    for (i = 0; i < 10; i++) {
        SXEL6("wait_for_conf_load(): iteration %d", i);
        if (confset_load(NULL))
            return true;
        usleep(2000);
    }

    return confset_load(NULL);
}

/* Emulate updating half_domaintagging from the options. The 1 bit will be removed for orgs that specify half tagging.
 */
static void
test_update_options(void)
{
    pref_categories_t half_domaintagging;

    pref_categories_setnone(&half_domaintagging);
    pref_categories_setbit(&half_domaintagging, 1);
    categorization_set_thread_options(&half_domaintagging);
}

int
main(void)
{
    const struct domainlist *bob;
    uint64_t start_allocations;
    struct categorization *cat;
    struct conf_loader cl;
    struct confset *set;
    module_conf_t m;
    const char *fn;
    pthread_t thr;
    int gen;

    plan_tests(97);

    kit_random_init(open("/dev/urandom", O_RDONLY));
    conf_initialize(NULL, ".", false, test_update_options);
    kit_memory_initialize(false);
    kit_counters_initialize(MAXCOUNTERS, 1, false);    // 1 slot

    /*
     * Pre-alloc/warm-up counter space for dynamic threads.
     * Necessary as we won't be able to clean up counter structural
     * realloc()s and still be able to count allocations....
     */
    kit_counters_prepare_dynamic_threads(2);
    pthread_create(&thr, NULL, use_dynamic_counter_slot, NULL);
    pthread_join(thr, NULL);
    pthread_create(&thr, NULL, use_dynamic_counter_slot, NULL);
    pthread_join(thr, NULL);

    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");
    /* KIT_ALLOC_SET_LOG(1); */

    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */

    diag("Verify that a config load that is then unregistered is also unloaded");
    {
        m = 0;
        categorization_register(&m, "cat", "catfile", true);
        is(m, 1, "Registered 'cat' as module 1");

        create_atomic_file("bobfile", "bob.com");
        create_atomic_file("catfile", "categorization 1\ndomainlist:bob:bobfile:100::");
        ok(confset_load(NULL), "Loaded bob and cat");

        gen = 0;
        ok(set = confset_acquire(&gen), "Acquired a confset");
        ok(bob = domainlist_conf_get(set, 2), "found bob in the confset");
        confset_release(set);

        create_atomic_file("bobfile", "bob.com\nbobby.com");
        create_atomic_file("catfile", "categorization 1");
        ok(confset_load(NULL), "Loaded bob, then cat, then threw away bob");

        ok(set = confset_acquire(&gen), "Acquired a confset");
        ok((bob = domainlist_conf_get(set, 2)) == NULL, "bob is not in the confset");
        confset_release(set);

        conf_unregister(m);
        confset_unload();
    }

    OK_SXEL_ERROR(NULL);
    is(memory_allocations(), start_allocations, "All memory allocations were freed after unregister unload tests");
    /* KIT_ALLOC_SET_LOG(0); */

    diag("Create a config load race, where the categorization file registrations make current.set realloc() itself");
    {
        unlink("do-not-proxy");

        domainlist_register(&CONF_DNAT_NS, "dnat-ns", "dnat-ns", true);
        domainlist_register(&CONF_DNSCRYPT_BLOCKLIST, "dnscrypt-blocklist", "dnscrypt-blocklist", true);
        domainlist_register(&CONF_DOMAIN_DROPLIST, "domain-droplist", "domain-droplist", true);
        domainlist_register(&CONF_DOMAIN_FREEZELIST, "domain-freezelist", "domain-freezelist", true);
        domainlist_register(&CONF_DOMAIN_ALLOWLIST, "domain-allowlist", "domain-allowlist", true);
        domainlist_register(&CONF_DO_NOT_PROXY, "do-not-proxy", "do-not-proxy", true);

        m = 0;
        categorization_register(&m, "cat", "catfile", true);
        is(m, 7, "Registered 'cat' as module 7");

        create_atomic_file("bobfile", "bob.com");
        create_atomic_file("do-not-proxy", "do-not-proxy.com");
        create_atomic_file("catfile", "categorization 1\ndomainlist:a:afile:98::\ndomainlist:b:bfile:99::\ndomainlist:bob:bobfile:100::");
        ok(confset_load(NULL), "Loaded bob, do-not-proxy and cat");

        // Simulate the application setting "conf_workers 2" in its options file before creating "bobfile".
        conf_set_global_options(2);

        gen = 0;
        ok(set = confset_acquire(&gen), "Acquired a confset");
        ok(bob = domainlist_conf_get(set, 10), "found bob in the confset");
        confset_release(set);

        MOCKFAIL_START_TESTS(5, confset_load);
        diag("Create 10 more files.");
        diag("We'll see a realloc at 18 (we allocate in ALLOC_BLOCKs of 10");
        diag("but add 2 to mostly avoid malloc/lock/too-late issues!");
        {
            uint8_t domain[DNS_MAXLEN_NAME];
            const struct domainlist *dl;

            /* The MOCKFAIL here doesn't actually fail... it just runs register_race_alloc() instead of kit_realloc() */
            test_register_race_alloc = register_race_alloc;
            unlink("race-file");
            racey = 0;

            create_atomic_file("do-not-proxy", "do-not-proxy.com\n" "dontproxy.com\n");
            ok(wait_for_conf_load(), "Loaded do-not-proxy with one more registration; race-file (added by register_race_alloc())");

            create_atomic_file("race-file", "r.com\nrace.com");
            ok(wait_for_conf_load(), "Loaded do-not-proxy and race-file");

            ok(set = confset_acquire(&gen), "Acquired a confset");
            ok((dl = domainlist_conf_get(set, racey)) != NULL, "race-file is in the confset");
            dns_name_sscan("www.race.com", "", domain);
            ok(domainlist_match(dl, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test no newline"), "Found a race-file match");
            confset_release(set);
        }
        MOCKFAIL_END_TESTS();

//      create_atomic_file("options", "%s", "");                 // Simulate what this would do in opendnscache
//      ok(wait_for_conf_load(), "Emptied the options file");    // Simulate what this would do in opendnscache
        conf_set_global_options(0);

        ok(!confset_load(NULL), "Ran a confset_load() to process zero files, but harvest the threads");

        create_atomic_file("bobfile", "bob.com\nbobby.com");
        create_atomic_file("catfile", "categorization 1");
        ok(confset_load(NULL), "Loaded bob, then cat, then threw away bob");

        ok(set = confset_acquire(&gen), "Acquired a confset");
        ok((bob = domainlist_conf_get(set, 10)) == NULL, "bob is not in the confset");
        confset_release(set);

        confset_unload();
    }

    OK_SXEL_ERROR(NULL);
    is(memory_allocations(), start_allocations, "All memory allocations were freed after load realloc tests");
    /* KIT_ALLOC_SET_LOG(0); */

    diag("Verify categorization V%u reference counting", CATEGORIZATION_VERSION);
    {
        conf_loader_init(&cl);
        fn = create_data("test-categorization", "categorization %u\n", CATEGORIZATION_VERSION);

        MOCKFAIL_START_TESTS(3, CATEGORIZATION_NEW);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Cannot create a categorization file when allocations fail");
        OK_SXEL_ERROR("Couldn't allocate 64 bytes");
        OK_SXEL_ERROR(NULL);
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(cat = categorization_new(&cl), "Created a categorization file (with no entries)");
        skip_if(!cat, 3, "Cannot test stuff when the categorization file wasn't loaded") {
            is(cat->conf.refcount, 1, "A new categorization file has a refcount of 1");
            categorization_refcount_inc(cat);
            is(cat->conf.refcount, 2, "Incrementing the refcount makes 2");
            categorization_refcount_dec(cat);
            is(cat->conf.refcount, 1, "Decrementing the refcount makes 1");
            categorization_refcount_dec(cat);
        }

        conf_loader_fini(&cl);
        unlink(fn);
    }

    OK_SXEL_ERROR(NULL);
    is(memory_allocations(), start_allocations, "All memory allocations were freed after reference counting tests");
    /* KIT_ALLOC_SET_LOG(0); */

    diag("Verify categorization load failures");
    {
        conf_loader_init(&cl);

        fn = create_data("test-categorization", "categorization %u\n", CATEGORIZATION_VERSION - 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Cannot load categorization V%u", CATEGORIZATION_VERSION - 1);
        OK_SXEL_ERROR("Unrecognized header line, expected 'categorization %u", CATEGORIZATION_VERSION);
        OK_SXEL_ERROR(NULL);
        unlink(fn);

        fn = create_data("test-categorization", "categorization %u\n", CATEGORIZATION_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Cannot load categorization V%u", CATEGORIZATION_VERSION + 1);
        OK_SXEL_ERROR("Unrecognized header line, expected 'categorization %u", CATEGORIZATION_VERSION);
        OK_SXEL_ERROR(NULL);
        unlink(fn);

        fn = create_data("test-categorization", "categorization %u\n" "domainlist:bob:bobfile:100::", CATEGORIZATION_VERSION);

        MOCKFAIL_START_TESTS(3, CATEGORIZATION_ALLOC_ITEM);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Cannot create a categorization file when item allocations fail");
        OK_SXEL_ERROR("Couldn't allocate 10 categorization items");
        OK_SXEL_ERROR(NULL);
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(3, CATEGORIZATION_ALLOC_MOD);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Cannot create a categorization file when module allocations fail");
        OK_SXEL_ERROR("Couldn't allocate 10 categorization items");
        OK_SXEL_ERROR(NULL);
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(3, CATEGORIZATION_ALLOC_NAMES);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Cannot create a categorization file when name index allocations fail");
        OK_SXEL_ERROR("Couldn't allocate 10 categorization items");
        OK_SXEL_ERROR(NULL);
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(3, conf_register);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Cannot create a categorization file when conf_register() allocations fail");
        OK_SXEL_ERROR("Couldn't allocate conf data for 10 entries");
        OK_SXEL_ERROR(NULL);
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(3, conf_registrar_add);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Cannot create a categorization file when conf_registrar_add() allocations fail");
        OK_SXEL_ERROR("Failed to reallocate conf-registrar modules to 40 bytes");
        OK_SXEL_ERROR(NULL);
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(cat = categorization_new(&cl), "Loaded categorization V%u", CATEGORIZATION_VERSION);
        categorization_refcount_dec(cat);
        unlink(fn);

        fn = create_data("test-categorization", "categorization %u\n" "zorkon15:bob:bobfile:100::", CATEGORIZATION_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Failed to load categorization V%u due to an invalid type", CATEGORIZATION_VERSION);
        OK_SXEL_ERROR(": 2: Invalid categorization type (field 1)");
        OK_SXEL_ERROR(NULL);
        unlink(fn);

        fn = create_data("test-categorization", "categorization %u\n" "domainlist::bobfile:100::", CATEGORIZATION_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Failed to load categorization V%u due to a missing name", CATEGORIZATION_VERSION);
        OK_SXEL_ERROR(": 2: Invalid categorization name (field 2)");
        OK_SXEL_ERROR(NULL);
        unlink(fn);

        fn = create_data("test-categorization", "categorization %u\n" "domainlist:bob::100::", CATEGORIZATION_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Failed to load categorization V%u due to a missing path", CATEGORIZATION_VERSION);
        OK_SXEL_ERROR(": 2: Invalid categorization path (field 3)");
        OK_SXEL_ERROR(NULL);
        unlink(fn);

        fn = create_data("test-categorization", "categorization %u\n" "domaintagging:bob:bobfile:100::", CATEGORIZATION_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Failed to load categorization V%u due to a specified catbit", CATEGORIZATION_VERSION);
        OK_SXEL_ERROR(": 2: Invalid category bit (field 4) - should be empty");
        OK_SXEL_ERROR(NULL);
        unlink(fn);

        fn = create_data("test-categorization", "categorization %u\n" "domaintagging:bob:bobfile:::15,%zu", CATEGORIZATION_VERSION, PREF_ORG_MAX_BITS);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Failed to load categorization V%u due to an invalid orgflag bit", CATEGORIZATION_VERSION);
        OK_SXEL_ERROR(": 2: Invalid org bit (field 6) - must be less than 64");
        OK_SXEL_ERROR(NULL);
        unlink(fn);

        fn = create_data("test-categorization", "categorization %u\n" "domaintagging:bob:bobfile:::15,", CATEGORIZATION_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Failed to load categorization V%u due bad orgbit format", CATEGORIZATION_VERSION);
        OK_SXEL_ERROR(": 2: Invalid org bit (field 6) - must be less than 64");
        OK_SXEL_ERROR(NULL);
        unlink(fn);

        fn = create_data("test-categorization", "categorization %u\n" "domainlist:bob:bobfile:512::", CATEGORIZATION_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Failed to load categorization V%u due to an invalid category bit", CATEGORIZATION_VERSION);
        OK_SXEL_ERROR(": 2: Invalid category bit (field 4) - must be less than 256");
        OK_SXEL_ERROR(NULL);
        unlink(fn);

        fn = create_data("test-categorization", "categorization %u\n" "domainlist:bob:bobfile:100:32:", CATEGORIZATION_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Failed to load categorization V%u due to an invalid policy flag bit", CATEGORIZATION_VERSION);
        OK_SXEL_ERROR(": 2: Invalid policy bit (field 5) - must be less than 32");
        OK_SXEL_ERROR(NULL);
        unlink(fn);

        fn = create_data("test-categorization", "categorization %u\n" "domainlist:bob:bobfile:100::%zu", CATEGORIZATION_VERSION, PREF_ORG_MAX_BITS);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Failed to load categorization V%u due to an invalid org flag bit", CATEGORIZATION_VERSION);
        OK_SXEL_ERROR(": 2: Invalid org bit (field 6) - must be less than 64");
        OK_SXEL_ERROR(NULL);
        unlink(fn);

        fn = create_data("test-categorization", "categorization %u\n"
                                                "domainlist:bob:bobfile1:100::31\n"
                                                "domainlist:bob:bobfile2:100:31:", CATEGORIZATION_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(categorization_new(&cl) == NULL, "Failed to load categorization V%u due to duplicate names", CATEGORIZATION_VERSION);
        OK_SXEL_ERROR(": 3: Invalid name (field 2) - must be unique");
        OK_SXEL_ERROR(NULL);
        unlink(fn);

        conf_loader_fini(&cl);
        confset_unload();
    }

    OK_SXEL_ERROR(NULL);

    diag("Test categorization_by_domain and categorization_by_address");
    {
        struct netaddr               addr;
        const struct categorization *catp;
        pref_categories_t            match;

        m = 0;
        categorization_register(&m, "cat", "catfile", true);
        ok(m != 0, "Registered cat/catfile as configuration");
        create_atomic_file("catfile",
                           "categorization 1\n"
                           "domaintagging:domaintagging:domaintagging:::25,26\n"
                           "domainlist:botnet:botnet:64::\n"
                           "application:application:application/application.%%u:148::\n"
                           "iplist:botnet2ips:botnet2ips:65::\n");
        create_atomic_file("domaintagging",
                           "domaintagging 2\n"
                           "count 1\n"
                           "name.com:3\n");    // Note that both bits 0 and 1 are set; 1 will be cleared by half domain tagging
        create_atomic_file("botnet",
                           "name.com");
        mkdir("application", 0777);
        create_atomic_file("application/application.1",
                           "lists 1\n"
                           "count 2\n"
                           "[meta:1]\n"
                           "name appy\n"
                           "[domains:1]\n"
                           "name.com\n"
                           "[urls:0]\n");
        create_atomic_file("botnet2ips",
                           "1.116.30.69");

        ok(confset_load(NULL),                     "Loaded cat/catfile");
        ok(set  = confset_acquire(&gen),           "Acquired a confset");
        ok(catp = categorization_conf_get(set, m), "Got categorization from confset");
        pref_categories_setnone(&match);

        categorization_by_domain(NULL, set, &match, (const uint8_t *)"\4name\3com", 0, PREF_ORGFLAGS_HALF_DOMAINTAGGING, NULL);
        is_eq(pref_categories_idstr(&match), "0", "Categories were untouched when no categorization passed (domain)");
        categorization_by_address(NULL, set, &match, &addr, 0, PREF_ORGFLAGS_HALF_DOMAINTAGGING, NULL);
        is_eq(pref_categories_idstr(&match), "0", "Categories were untouched when no categorization passed (address)");

        categorization_by_domain(catp, set, &match, (const uint8_t *)"\4name\3com", 0, PREF_ORGFLAGS_HALF_DOMAINTAGGING, NULL);
        is_eq(pref_categories_idstr(&match), "10000000000000000000010000000000000001",
              "Expected categories were matched (bits 0, 64, and 148)");
        netaddr_from_str(&addr, "1.116.30.69", AF_INET);
        categorization_by_address(catp, set, &match, &addr, 0, PREF_ORGFLAGS_HALF_DOMAINTAGGING, NULL);
        is_eq(pref_categories_idstr(&match), "10000000000000000000030000000000000001",
              "Expected categories were matched (bits 0, 64, 65, and 148)");    // Note that match is added to

        confset_release(set);
        confset_unload();    // Finalize conf subsytem
    }

    OK_SXEL_ERROR(NULL);
    test_uncapture_sxel();

    is(memory_allocations(), start_allocations, "All memory allocations were freed after load failure tests");
    /* KIT_ALLOC_SET_LOG(0); */

    return tidyfiles(exit_status());
}
