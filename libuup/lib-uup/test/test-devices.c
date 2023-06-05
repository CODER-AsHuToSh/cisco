#include <fcntl.h>
#include <kit-alloc.h>
#include <mockfail.h>
#include <tap.h>

#include "conf-loader.h"
#include "devices-private.h"
#include "kit-random.h"

#include "common-test.h"

#define LOADFLAGS_DEVICES   (LOADFLAGS_FP_ALLOW_OTHER_TYPES | LOADFLAGS_FP_ELEMENTTYPE_DOMAIN | LOADFLAGS_FP_ELEMENTTYPE_APPLICATION)
#define LOADFLAGS_JUST_CIDR (LOADFLAGS_FP_ALLOW_OTHER_TYPES | LOADFLAGS_FP_ELEMENTTYPE_CIDR)

int
main(void)
{
    struct conf_loader cl;
    uint64_t           start_allocations;
    struct conf_info  *info;
    struct devices    *dp;
    const char        *fn;
    unsigned           i;

    plan_tests(67);

    // Clean up any files left if the test crashes
    unlink("test-devices");

    kit_random_init(open("/dev/urandom", O_RDONLY));
    conf_initialize(".", ".", false, NULL);
    kit_memory_initialize(false);
    // KIT_ALLOC_SET_LOG(1);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */

    conf_loader_init(&cl);

    diag("Test missing file load");
    {
        info = conf_info_new(NULL, "noname", "nopath", NULL, LOADFLAGS_NONE, NULL, 0);
        info->updates++;
        memset(info->digest, 0xa5, sizeof(info->digest));

        conf_loader_open(&cl, "/tmp/not-really-there", NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        ok(!dp, "Failed to read non-existent file");
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
    }

    diag("Test garbage file");
    {
        fn = create_data("test-devices", "This is not the correct format\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read garbage file");
        OK_SXEL_ERROR(": 1: Invalid header; must contain 'devices'");
    }

    diag("Test V%u data load - old unsupported version", DEVICES_VERSION - 1);
    {
        fn = create_data("test-devices", "devices %u\ncount 0\n", DEVICES_VERSION - 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data", DEVICES_VERSION - 1);
        OK_SXEL_ERROR(": 1: Invalid header version(s); must be numeric");    // This message will change when version > 1
    }

    diag("Test V%u data load - future version not yet supported", DEVICES_VERSION + 1);
    {
        fn = create_data("test-devices", "devices %u\ncount 0\n", DEVICES_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data", DEVICES_VERSION + 1);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [%u]", DEVICES_VERSION);
    }

    diag("Test V%u & V%u data load - doesn't contain V%u", DEVICES_VERSION + 1, DEVICES_VERSION + 2, DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u %u\ncount 0\n", DEVICES_VERSION + 1, DEVICES_VERSION + 2);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u & version %u data", DEVICES_VERSION + 1, DEVICES_VERSION + 2);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [%u]", DEVICES_VERSION);
    }

    diag("Test V%u data load with missing count", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\nnocount 0\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with missing count", DEVICES_VERSION);
        OK_SXEL_ERROR(": 2: Invalid count; must begin with 'count '");
    }

    diag("Test V%u data load with count 0 empty file", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 0\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(dp, "Read version %u data with count 0 and no data", DEVICES_VERSION);
        OK_SXEL_ERROR(NULL);    // No error expected
        CONF_REFCOUNT_DEC(dp);
    }

    diag("Test V%u data load with count 1 and no section heading before EOF", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 1\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with count 1 and no section heading (EOF)", DEVICES_VERSION);
        OK_SXEL_ERROR(": 2: Incorrect total count 1 - read 0 data lines");
    }

    diag("Test V%u data load with count 1 and missing section heading before data", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 1\nwhere's my header?\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with count 1 and no section heading", DEVICES_VERSION);
        OK_SXEL_ERROR(": 3: Expected section header");
    }

    diag("Test V%u data load with count 1 and no data", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 1\n[devices:1:1]\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with count 1 and no data", DEVICES_VERSION);
        OK_SXEL_ERROR(": 3: Unexpected EOF - read 0 [devices] items, not 1");
    }

    diag("Test V%u data load with count 1 and 2 device:origin_id mappings", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 1\n[devices:1:1]\n0123456789abcdef:1234567890:0:1\n"
                         "1123456789abcdef:1123456789:0:0\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with count 1 and 2 device:origin_id mappings", DEVICES_VERSION);
        OK_SXEL_ERROR(": 5: Unexpected [devices] line - wanted only 1 item");
    }

    diag("Test V%u data load with a garbled device:origin_id mapping", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 1\n[devices:1:1]\ngarbled\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with a garbled device:origin_id mapping", DEVICES_VERSION);
        OK_SXEL_ERROR(": 4: Unrecognised device line (invalid deviceid:originid:origintypeid:orgid)");
    }

    diag("Test V%u data load with an invalid device id", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 1\n[devices:1:1]\nx123456789abcdef:1234567890:0:1\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with an invalid device", DEVICES_VERSION);
        OK_SXEL_ERROR(": 4: Unrecognised device line (invalid deviceid:originid:origintypeid:orgid)");
    }

    diag("Test V%u data load with a device id that overflows", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 1\n[devices:1:1]\n0123456789abcdef0123:1234567890:0:1\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with a device id that overflows", DEVICES_VERSION);
        OK_SXEL_ERROR(": 4: Unrecognised device line (invalid deviceid:originid:origintypeid:orgid)");
    }

    diag("Test V%u data load with a bad origin id", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 1\n[devices:1:1]\n0:baddef:0:0\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with a bad origin id", DEVICES_VERSION);
        OK_SXEL_ERROR(": 4: Unrecognised device line (invalid deviceid:originid:origintypeid:orgid)");
    }

    diag("Test V%u data load with an origin id >= 2^32", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 1\n[devices:1:1]\n0123456789abcdef:9999999999:0:9999999999\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with a bad origin id", DEVICES_VERSION);
        OK_SXEL_ERROR(": 4: Origin id 9999999999 overflows 32 bits");
    }

    diag("Test V%u data load with an invalid org id", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 1\n[devices:1:1]\n0123456789abcdef:1234567890:0:1x\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with a bad org id", DEVICES_VERSION);
        OK_SXEL_ERROR(": 4: Org id is followed by 'x', not end of line");
    }

    diag("Test V%u data load with an org id >= 2^32", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 1\n[devices:1:1]\n0123456789abcdef:1234567890:0:9999999999\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with a bad org id", DEVICES_VERSION);
        OK_SXEL_ERROR(": 4: Org id 9999999999 overflows 32 bits");
    }

    diag("Test V%u data load with garbage after the origin id", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 1\n[devices:1:1]\n0:0:0:0:garbage\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with garbage after the origin id", DEVICES_VERSION);
        OK_SXEL_ERROR(": 4: Org id is followed by ':', not end of line");
    }

    diag("Test V%u load with invalid sort order", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 2\n[devices:2:1]\n1123456789abcdef:1234567890:0:1\n"
                         "0123456789abcdef:1123456789:0:0\n", DEVICES_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data with invalid sort order", DEVICES_VERSION);
        OK_SXEL_ERROR(": 5: Device id 123456789abcdef is not greater than previous device id 1123456789abcdef");
    }

    diag("Test V%u + V%u load with truncated V%u data (EOF)", DEVICES_VERSION, DEVICES_VERSION + 1, DEVICES_VERSION + 1);
    {
        fn = create_data("test-devices", "devices 1 2\ncount 2\n[devices:1:1]\n1123456789abcdef:1234567890:0:1\n"
                         "[devices:1:2]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data when truncated by EOF", DEVICES_VERSION + 1);
        OK_SXEL_ERROR(": 5: Unexpected EOF in skipped section - read 0 items, not 1");
    }

    diag("Test V%u + V%u load with truncated V%u data (by header)", DEVICES_VERSION, DEVICES_VERSION + 1, DEVICES_VERSION + 1);
    {
        fn = create_data("test-devices", "devices 1 2\ncount 2\n[devices:1:1]\n1123456789abcdef:1234567890:0:1\n"
                         "[devices:1:2]\n[devices:0:3]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        dp = devices_new(&cl);
        unlink(fn);
        ok(!dp, "Failed to read version %u data when truncated by a header", DEVICES_VERSION + 1);
        OK_SXEL_ERROR(": 6: Unexpected [devices:0:3] header in skipped section - read 0 items, not 1");
    }

    diag("Test V%u load with allocation failures", DEVICES_VERSION);
    {
        fn = create_data("test-devices", "devices %u\ncount 1\n[devices:1:1]\n0123456789abcdef:1234567890:0:1\n", DEVICES_VERSION);

        MOCKFAIL_START_TESTS(2, DEVICES_NEW);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!devices_new(&cl), "Didn't construct struct devices: failed to allocate devices structure");
        OK_SXEL_ERROR("Failed to malloc a devices structure");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(2, DEVICE_ARRAY_NEW);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!devices_new(&cl), "Didn't construct struct devices: failed to allocate device array");
        OK_SXEL_ERROR(": 3: Failed to malloc a device array");
        MOCKFAIL_END_TESTS();

        unlink(fn);
        conf_loader_done(&cl, NULL);
    }

    // Turn error log capture back off for non-error cases
    //
    OK_SXEL_ERROR(NULL);
    test_uncapture_sxel();

    diag("Test success cases of devices");
    {
        struct confset       *conf_set;
        struct kit_deviceid   device_id;
        const struct device  *device;
        const struct devices *devices;
        int                   gen;

        devices_register(&CONF_DEVICES, "devices", "test-devices", true);
        create_atomic_file("test-devices", "devices %u\ncount 1\n[devices:1:1]\n0123456789abcdef:1234567890:0:1\n",
                           DEVICES_VERSION);

        ok(confset_load(NULL), "Loaded devices");
        ok(conf_set = confset_acquire(&gen), "Acquired the new conf set");

        if (conf_set) {
            ok(devices = devices_conf_get(conf_set, CONF_DEVICES), "Got devices conf");

            if (devices) {
                kit_deviceid_from_str(&device_id, "1123456789abcdef");
                ok(!devices_get(devices, &device_id, NULL), "Failed to get non-existant device");
                kit_deviceid_from_str(&device_id, "0123456789abcdef");
                ok(device = devices_get(devices, &device_id, NULL), "Got device 0123456789abcdef");

                if (device) {
                    ok(memcmp(&device->device_id, &device_id, sizeof(device_id)) == 0, "Got expected device id");
                    is(device->org_id,    1,          "Got expected org id");
                    is(device->origin_id, 1234567890, "Got expected origin id");
                }
            }

            confset_release(conf_set);
        }

        unlink("test-devices");

        create_atomic_file("test-devices", "devices %u %u\ncount 3\n[devices:1:%u]\n0123456789abcdef:1234567890:0:1\n"
                           "[devices:2:%u]\nsome whacky new format\ntwo lines of it\n",
                           DEVICES_VERSION, DEVICES_VERSION + 1, DEVICES_VERSION, DEVICES_VERSION + 1);

        ok(confset_load(NULL), "Loaded devices");
        ok(conf_set = confset_acquire(&gen), "Acquired the new conf set");

        if (conf_set) {
            ok(devices = devices_conf_get(conf_set, CONF_DEVICES), "Got devices conf");
            is(devices->count, 1, "Only one device read");
            confset_release(conf_set);
        }

        confset_unload();
        unlink("test-devices");
    }

    conf_loader_fini(&cl);
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    // KIT_ALLOC_SET_LOG(0);

    return exit_status();
}
