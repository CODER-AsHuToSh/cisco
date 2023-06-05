#include <cjson/cJSON.h>
#include <kit-alloc.h>
#include <mockfail.h>
#include <sys/types.h>
#include <tap.h>

#include "common-test.h"
#include "conf-loader.h"
#include "digest-store.h"
#include "osversion-current.h"

#define TEST_VERSION 1.0    // Current version of the file format we're testing

static void
error_capture(void)
{
    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */
}

static void
error_test(const char *error1, const char *error2)
{
    OK_SXEL_ERROR(error1);
    OK_SXEL_ERROR(error2);
    test_uncapture_sxel();
}

int
main(void)
{
    struct conf_loader             cl;
    module_conf_t                  reg;
    const struct osversion_current *osversion_const;
    struct osversion_current       *osversion_current;
    struct confset                *set;
    const char                    *fn;
    uint64_t                       start_allocations;
    unsigned                       i;
    int                            gen;
    char                           content[4096];

    plan_tests(47);

    kit_memory_initialize(false);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");
    // KIT_ALLOC_SET_LOG(1);    // Turn off when done

    conf_initialize(".", ".", false, NULL);
    conf_loader_init(&cl);

    diag("Test missing file load");
    {
        struct conf_info *info = conf_info_new(NULL, "noname", "nopath", NULL, LOADFLAGS_NONE, NULL, 0);
        info->updates++;

        error_capture();
        conf_loader_open(&cl, "/tmp/not-really-there", NULL, NULL, 0, CONF_LOADER_DEFAULT);
        osversion_current = osversion_current_new(&cl);
        ok(!osversion_current, "Failed to read non-existent osversion_current file");
        error_test("not-really-there could not be opened: No such file or directory", NULL);

        conf_loader_done(&cl, info);
        is(info->updates, 1, "conf_loader_done() didn't bump 'updates'");
        is(info->st.dev,  0, "Loading a non-existent file gives a clear stat");

        for (i = 0; i < sizeof(info->digest); i++)
            if (info->digest[i])
                break;

        is(i, sizeof(info->digest), "The digest of an empty file has %zu zeros", sizeof(info->digest));
        conf_info_free(info);
    }

    diag("Test empty/error files");
    {
        fn = create_data("test-osversion-current", "%s", "");

        MOCKFAIL_START_TESTS(3, CONF_LOADER_READFILE);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        osversion_current = osversion_current_new(&cl);
        ok(!osversion_current, "Failed to read empty file on allocation failure");
        error_test("Couldn't allocate 1 bytes for file data", ": Unable to load file (errno = 0)");
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        osversion_current = osversion_current_new(&cl);
        ok(!osversion_current, "Failed to read empty file");
        error_test(": No content found", NULL);

        unlink(fn);

        fn = create_data("test-osversion-current", "%s", "{\"no.catalog\":{}");

        MOCKFAIL_START_TESTS(3, OSVERSION_CURRENT_NEW);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        osversion_current = osversion_current_new(&cl);
        ok(!osversion_current, "Failed to read a file when an osversion_current object could not be allocated");
        error_test(": Couldn't allocate 40 bytes", NULL);
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        osversion_current = osversion_current_new(&cl);
        ok(!osversion_current, "Failed to read a file that does not contain a JSON object");
        error_test(": Member name \"catalog\" not found in 16 bytes", NULL);

        unlink(fn);

        fn = create_data("test-osversion-current", "%s", "{\"catalog\":not json");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        osversion_current = osversion_current_new(&cl);
        ok(!osversion_current, "Failed to read a file whose catalog is not JSON");
        error_test(": Error parsing JSON at byte 12 of 19", NULL);

        fn = create_data("test-osversion-current", "%s", "{\"catalog\" : 0}");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        osversion_current = osversion_current_new(&cl);
        unlink(fn);
        ok(!osversion_current, "Failed to read a file whose catalog is not a JSON object");
        error_test(": Content is not a JSON object", NULL);

        fn = create_data("test-osversion-current", "%s", "{\"catalog\":{}}");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        osversion_current = osversion_current_new(&cl);
        unlink(fn);
        ok(!osversion_current, "Failed to read a file that does not contain a JSON object with a 'osversion-current' member");
        error_test(": JSON object does not include a 'osversion-current' member", NULL);

        fn = create_data("test-osversion-current", "%s", "\"catalog\"\t:{\"osversion-current\":{}}");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        osversion_current = osversion_current_new(&cl);
        unlink(fn);
        ok(!osversion_current, "Failed to read a file that does not contain a JSON object with a 'version' member");
        error_test(": JSON object does not include a 'version' member", NULL);

        fn = create_data("test-osversion-current", "%s", "\"catalog\"  :  {\"osversion-current\":{}, \"version\": 1} }");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        osversion_current = osversion_current_new(&cl);
        unlink(fn);
        ok(!osversion_current, "Failed to read a file that does not contain a JSON object with a 'version' member");
        error_test(": JSON object version is not an array or is empty, or its first element is non-numeric", NULL);

        fn = create_data("test-osversion-current", "%s", "\"catalog\"\t:{\"osversion-current\":{}, \"version\": [3.14159]}");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        osversion_current = osversion_current_new(&cl);
        unlink(fn);
        ok(!osversion_current, "Failed to read a file that does not contain a JSON object with a 'version' member");
        error_test(": JSON object version is 3.141590, expected 1.000000", NULL);
    }

    conf_loader_fini(&cl);

    digest_store_set_options("policy-digest-dir", 1, DIGEST_STORE_DEFAULT_MAXIMUM_AGE);    // Set the test digest directory
    osversion_current_register(&CONF_OSVERSION_CURRENT, "osversion-current", "osversion-current", NULL);
    error_capture();

    reg = 0;
    osversion_current_register(&reg, "osversion-current", "osversion-current", NULL);
    is(reg, 0, "Cannot register osversion-current twice by name");
    error_test("osversion-current: Config name already registered as ./osversion-current", NULL);

    diag("Test V%f empty data load", TEST_VERSION);
    {
        snprintf(content, sizeof(content), "%s", "[{\"catalog\":{\"osversion-current\":{}, \"version\": [1]},"
                                                   "\"organizationId\": 0}]");
        create_atomic_file("osversion-current", "%s", content);

        ok(confset_load(NULL), "Noted an update to osversion-current");
        ok(!confset_load(NULL), "A second confset_load() call results in nothing");
        ok(set = confset_acquire(&gen), "Acquired the new config");

        skip_if(set == NULL, 6, "Cannot check content without acquiring config") {
            osversion_const = osversion_current_conf_get(set, CONF_OSVERSION_CURRENT);
            ok(osversion_const, "Constructed osversion_current from empty V%f data", TEST_VERSION);

            skip_if(osversion_const == NULL, 1, "Cannot check content of NULL policy") {
                is(cJSON_GetArraySize(osversion_current_get_data(osversion_const)), 0, "There are no OSs in the file");
            }

            confset_release(set);
            is(osversion_const ? ((const struct conf *)osversion_const)->refcount : 0, 1, "confset_release() dropped the refcount back to 1");
        }
    }

    confset_unload();
    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    return exit_status();
}

