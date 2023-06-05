#include <errno.h>
#include <kit-alloc.h>
#include <mockfail.h>
#include <tap.h>

#include "common-test.h"
#include "groupsprefs.h"

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
    struct conf_loader     cl;
    groups_per_user_map_t *gpum;
    const char            *fn;
    uint64_t               start_allocations;
    unsigned               i;

    plan_tests(58);

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
        gpum = groups_per_user_map_new_from_file(&cl, CONF_LOADER_DEFAULT);
        ok(!gpum, "Failed to read non-existent group from user map file");
        error_test("not-really-there could not be opened: No such file or directory", "Failed to read groupsprefs 'version'");

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
        fn = create_data("test-groupusers", "%s", "");

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        gpum = groups_per_user_map_new_from_file(&cl, 0);
        ok(!gpum, "Failed to read empty file when empty lists are allowed");
        is(errno, EINVAL, "Errno is correctly set to invalid");
        error_test(NULL, NULL);    // No error

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);    // The way its called by groups_per_user_map_new
        error_capture();
        gpum = groups_per_user_map_new_from_file(&cl, LOADFLAGS_UTG_ALLOW_EMPTY_LISTS);
        ok(!gpum, "Failed to read empty file");
        error_test("Failed to read groupsprefs 'version'", NULL);

        unlink(fn);

        fn = create_data("test-groupusers", "%s", "version 1\nbad header\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        gpum = groups_per_user_map_new(&cl);
        ok(!gpum, "Failed to read a file that does not contain a valid header");
        error_test("Failed to read groupsprefs version 1 headers", NULL);
        unlink(fn);

        fn = create_data("test-groupusers", "%s", "version 2\ncount 0\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        gpum = groups_per_user_map_new(&cl);
        ok(!gpum, "Failed to read a file that does not contain version 1");
        error_test("Unkown groupsprefs version '2'", NULL);
        unlink(fn);

        fn = create_data("test-groupusers", "%s", "version 1\ncount 0\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        gpum = groups_per_user_map_new(&cl);
        ok(!gpum, "Failed to read a file that has a count of 0");
        error_test(NULL, NULL);
        unlink(fn);

        fn = create_data("test-groupusers", "%s", "version 1\ncount 1\nNAN");

        MOCKFAIL_START_TESTS(3, GPUM_ALLOC_USERCOUNT);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        gpum = groups_per_user_map_new(&cl);
        ok(!gpum, "Failed to read a file when user count array could not be allocated");
        error_test("Failed to allocate 4000000 bytes for user counting", NULL);
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        gpum = groups_per_user_map_new(&cl);
        ok(!gpum, "Failed to read a file that has a group number that's not a number");
        error_test("Failed parsing group_id: 'NAN'", "parse_users_for_counting failed for line 0 in groupspref");

        unlink(fn);

        fn = create_data("test-groupusers", "%s", "version 1\ncount 1\n0");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        gpum = groups_per_user_map_new(&cl);
        ok(!gpum, "Group id 0 is invalid");
        error_test("Invalid group_id '0': '0'", "parse_users_for_counting failed for line 0 in groupspref");
        unlink(fn);

        fn = create_data("test-groupusers", "%s", "version 1\ncount 1\n1:NAN");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        gpum = groups_per_user_map_new(&cl);
        ok(!gpum, "Group id 0 has an invalid user");
        error_test("Invalid user_id '0' is present in this line: '1:NAN' so not loading the new map",
                   "parse_users_for_counting failed for line 0 in groupspref");
        unlink(fn);

        fn = create_data("test-groupusers", "%s", "version 1\ncount 1\n1:11 12\n2:11 13\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        gpum = groups_per_user_map_new(&cl);
        ok(!gpum, "Too many lines");
        error_test("group lines exceeds 'count' header in groupspref", NULL);
        unlink(fn);

        fn = create_data("test-groupusers", "%s", "version 1\ncount 3\n1:11 12\n2:11 13\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        gpum = groups_per_user_map_new(&cl);
        ok(!gpum, "Too few lines");
        error_test("Mismatched number of lines vs 'count' in groupsprefs file (count=3, read=2)", NULL);
        unlink(fn);

        fn = create_data("test-groupusers", "%s", "version 1\ncount 2\n1:11 12\n2:11 13\n");

        MOCKFAIL_START_TESTS(3, GPUM_ALLOC_GPUMS);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        gpum = groups_per_user_map_new(&cl);
        ok(!gpum, "Failed to read a file when groups per user maps could not be allocated");
        error_test("Failed to allocate 72 bytes for groups_per_user_map", NULL);
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(3, GPUM_ALLOC_GPU);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        gpum = groups_per_user_map_new(&cl);
        ok(!gpum, "Failed to read a file when groups per user maps could not be allocated");
        error_test("Failed to allocate 40 bytes for groups_per_user", NULL);
        MOCKFAIL_END_TESTS();

        unlink(fn);

        fn = create_data("test-groupusers", "%s", "version 1\ncount 2\n1\n2\n");    // Groups with no users (why?)
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        gpum = groups_per_user_map_new(&cl);
        ok(!gpum, "Too few lines");
        ok(!groups_per_user_map_get_groups(gpum, 11), "Can't find a user in a NULL gpm");
        error_test("Zero user count for org", "get_groups_for_user, gpum is NULL");
        unlink(fn);
    }

    diag("Test a valid group per user map parsed from a string");
    {
        gpum = groups_per_user_map_new_from_buffer("version 1\ncount 2\n1:11 12\n2:11 13\n", sizeof("version 1\ncount 2\n1:11 12\n2:11 13\n") - 1, NULL, 0);
        ok(gpum, "Parsed a test groupusers file");

        skip_if(gpum == NULL, 4, "Cannot check content without acquiring the group per user map") {
            is(groups_per_user_map_count_users(gpum), 3, "There are 3 users");
            groups_per_user_t *gpu = groups_per_user_map_get_groups(gpum, 11);
            is(gpu->count, 2,     "User 11 is in 2 groups");
            is(gpu->groups[0], 1, "User 11 is in group 1");
            is(gpu->groups[1], 2, "User 11 is in group 2");
            ok(!groups_per_user_map_get_groups(gpum, 666), "Can't get the groups for a non-existant user");
            groups_per_user_map_free(gpum);
        }
    }

    conf_loader_fini(&cl);
    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    return exit_status();
}
