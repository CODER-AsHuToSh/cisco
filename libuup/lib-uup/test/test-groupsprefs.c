#include <kit-alloc.h>
#include <mockfail.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tap.h>

#include "common-test.h"
#include "conf.h"
#include "digest-store.h"
#include "groupsprefs.h"

static void
error_capture(void)
{
    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */
}

static void
error_test1(const char *error)
{
    OK_SXEL_ERROR(error);
    test_uncapture_sxel();
}

static void
error_test2(const char *error1, const char *error2)
{
    OK_SXEL_ERROR(error1);
    error_test1(error2);
}

int
main(void)
{
    struct confset        *set;
    groups_per_user_map_t *gpum;
    uint64_t               start_allocations;
    unsigned               i, expected_digests = 0;
    int                    gen;
    char                   filename[256];

    plan_tests(32);

    kit_memory_initialize(false);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");
    // KIT_ALLOC_SET_LOG(1);    // Turn off when done

    conf_initialize(".", ".", false, NULL);
    digest_store_set_options("groupsprefs-digest-dir", 1, DIGEST_STORE_DEFAULT_MAXIMUM_AGE);    // Set the test digest directory

    ok(!groupsprefs_get_groups_per_user_map(NULL, CONF_GROUPSPREFS, 1), "Didn't find groups per user in a NULL set");

    for (i = 0; i <= 10; i++) {
        snprintf(filename, sizeof(filename), "test-groupsprefs-%u", i);
        unlink(filename);
        snprintf(filename, sizeof(filename), "test-groupsprefs-%u.last-good", i);
        unlink(filename);
    }

    groupsprefs_register(&CONF_GROUPSPREFS, "groupsprefs", NULL);    // Should this be a SXEA1 failure?

    groupsprefs_register(&CONF_GROUPSPREFS, "groupsprefs", "test-groupsprefs-%u");

    MOCKFAIL_START_TESTS(3, GROUPSPREFS_CLONE);
    error_capture();
    create_atomic_file("test-groupsprefs-1", "version 1\ncount 2\n1:11 12\n2:11 13\n");
    ok(!confset_load(NULL), "Noted no update");
    error_test2("Couldn't allocate an groupsprefs structure", "Couldn't clone a groupsprefs conf object");
    MOCKFAIL_END_TESTS();

    create_atomic_file("test-groupsprefs-1", "version 1\ncount 2\n1:11 12\n2:11 13\n");
    expected_digests++;
    ok(confset_load(NULL),                                                   "Noted an update to test-groupsprefs-1");
    ok(set = confset_acquire(&gen),                                          "Acquired the config set that includes policy");
    ok(gpum = groupsprefs_get_groups_per_user_map(set, CONF_GROUPSPREFS, 1), "Found groups per user for org 1");
    ok(!groupsprefs_get_groups_per_user_map(set, CONF_GROUPSPREFS, 2),       "Didn't found groups per user for org 2");
    confset_release(set);

    create_atomic_file("test-groupsprefs-1", "version 1\ncount 3\n1:11 12\n2:11 13\n3: 14\n");
    ok(confset_load(NULL),                                                   "Noted an update to test-groupsprefs-1");
    ok(set = confset_acquire(&gen),                                          "Acquired the config set that includes policy");
    ok(gpum = groupsprefs_get_groups_per_user_map(set, CONF_GROUPSPREFS, 1), "Found groups per user for org 1");
    confset_release(set);

    MOCKFAIL_START_TESTS(3, GROUPSPREFS_CLONE_GPUMS);
    error_capture();
    create_atomic_file("test-groupsprefs-2", "version 1\ncount 2\n1:11 12\n2:11 13\n");
    ok(!confset_load(NULL), "Noted no update");
    error_test2("Couldn't allocate 10 new groups_per_user_map_t slots", "Couldn't clone a groupsprefs conf object");
    MOCKFAIL_END_TESTS();

    create_atomic_file("test-groupsprefs-2", "version 1\ncount 2\n1:11 12\n2:11 13\n");
    expected_digests++;
    ok(confset_load(NULL),          "Noted an update");
    ok(set = confset_acquire(&gen), "Acquired the config set that includes policy");
    ok(groupsprefs_get_groups_per_user_map(set, CONF_GROUPSPREFS, 1), "Found groups per user for org 1");
    ok(groupsprefs_get_groups_per_user_map(set, CONF_GROUPSPREFS, 2), "Found groups per user for org 2");
    confset_release(set);

    MOCKFAIL_START_TESTS(4, GROUPSPREFS_MORE_ORGS);
    error_capture();

    for (i = 3; i <= 10; i++) {
        snprintf(filename, sizeof(filename), "test-groupsprefs-%u", i);
        create_atomic_file(filename, "%s", "version 1\ncount 2\n1:11 12\n2:11 13\n");
        expected_digests++;
    }

    ok(confset_load(NULL), "Noted an update");
    OK_SXEL_ERROR(NULL);
    create_atomic_file("test-groupsprefs-0", "%s", "version 1\ncount 2\n1:11 12\n2:11 13\n");
    ok(!confset_load(NULL), "Noted no update");
    error_test1("Couldn't reallocate 20 groups_per_user_map_t slots");
    MOCKFAIL_END_TESTS();

    // Actually insert out of order to cover this case
    create_atomic_file("test-groupsprefs-0", "%s", "version 1\ncount 2\n1:11 12\n2:11 13\n");
    ok(confset_load(NULL), "Noted an update");

    unlink("test-groupsprefs-11");
    unlink("test-groupsprefs-2");
    ok(confset_load(NULL),                                             "Noted an update");
    ok(set = confset_acquire(&gen),                                    "Acquired the config set that includes policy");
    ok(groupsprefs_get_groups_per_user_map(set, CONF_GROUPSPREFS,  1), "Found groups per user for org 1");
    ok(!groupsprefs_get_groups_per_user_map(set, CONF_GROUPSPREFS, 2), "Didn't found groups per user for org 2");

    // This test covers policy_slotisempty
    is(rrmdir("groupsprefs-digest-dir"),      0, "Removed groupsprefs-digest-dir with no errors");
    is(mkdir("groupsprefs-digest-dir", 0755), 0, "Created groupsprefs-digest-dir");
    digest_store_changed(set);
    int lines = showdir("groupsprefs-digest-dir", stdout);
    is(lines, expected_digests, "Found %u lines of data in groupsprefs-digest-dir directory, expected %u", lines,
       expected_digests);
    confset_release(set);

    confset_unload();
    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    return exit_status();
}
