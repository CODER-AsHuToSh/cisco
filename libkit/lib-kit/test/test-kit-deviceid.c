#include <string.h>
#include <tap.h>

#include "kit.h"

int
main(void)
{
    plan_tests(12);

    struct kit_deviceid deviceid = {
        .bytes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
    };
    char deviceidstr[] = "0001020304050607";
    const char *str;

    ok(str = kit_deviceid_to_str(&deviceid), "Called kit_deviceid_to_str");
    is_eq(str, deviceidstr, "Printed string matches expected");

    ok(str = kit_deviceid_to_str(NULL), "Called kit_deviceid_to_str with NULL");
    is_eq(str, "0000000000000000", "Printed string for NULL matches expected");

    /* Test creating deviceid from string */
    struct kit_deviceid deviceid2;
    kit_deviceid_from_str(&deviceid2, deviceidstr);
    ok(kit_deviceid_cmp(&deviceid, &deviceid2) == 0, "deviceid from string as expected");
    is_eq(kit_deviceid_to_str(&deviceid2), deviceidstr, "Print of build deviceid as expected");

    char deviceidstrbad[] = "bad string";
    kit_deviceid_from_str(&deviceid2, deviceidstrbad);
    ok(str = kit_deviceid_to_str(&deviceid2), "Called kit_deviceid_to_str");
    is_eq(str, "0000000000000000", "Printed string matches expected");
    ok(kit_deviceid_cmp(&deviceid2, &kit_deviceid_nil) == 0, "Deviceid from bad string as expected");
    ok(kit_deviceid_cmp(&deviceid,  &deviceid2)        != 0, "Deviceids should not match");
    ok(kit_deviceid_cmp(&deviceid,  &deviceid)         == 0, "Deviceid compare for same pointer");
    ok(kit_deviceid_cmp(&deviceid,  NULL)          != 0, "Deviceid compare for NULL pointer");

    return exit_status();
}
