#include <string.h>

#include "kit.h"
#include "sxe-log.h"
#include "sxe-util.h"

const struct kit_deviceid kit_deviceid_nil = {
    {0, 0, 0, 0, 0, 0, 0, 0}
};

/**
 * Convert a guid into a string of KIT_DEVICEID_STR_LEN bytes
 */
char *
kit_deviceid_to_buf(const struct kit_deviceid *deviceid, char *buf, size_t size)
{
    SXE_UNUSED_PARAMETER(size);
    SXEA6(size >= KIT_DEVICEID_STR_LEN + 1, "DeviceID buffer must have room for %u hex digits plus 1 for the NUL", KIT_DEVICEID_STR_LEN);
    kit_bin2hex(buf, (const char *)deviceid ? deviceid->bytes : kit_deviceid_nil.bytes, KIT_DEVICEID_SIZE, KIT_BIN2HEX_LOWER);
    return buf;
}

/* Return printable string of a deviceid */
const char *
kit_deviceid_to_str(const struct kit_deviceid *deviceid)
{
    static __thread char str[KIT_DEVICEID_STR_LEN + 1];

    return kit_deviceid_to_buf(deviceid, str, sizeof(str));
}

/* Build a deviceid from a string */
struct kit_deviceid *
kit_deviceid_from_str(struct kit_deviceid *deviceid, const char *str_hex)
{
    SXEE7("(deviceid=%p str_hex=%s)", deviceid, str_hex);

    if (strlen(str_hex) != KIT_DEVICEID_STR_LEN) {
        SXEL3("kit_deviceid_from_str: invalid guid str '%s'", str_hex);
        *deviceid = kit_deviceid_nil;
    }
    else
        kit_hex2bin(deviceid->bytes, str_hex, KIT_DEVICEID_STR_LEN);

    SXER7("return deviceid=%s", kit_deviceid_to_str(deviceid));
    return deviceid;
}

/* Compare two deviceids */
int
kit_deviceid_cmp(const struct kit_deviceid *deviceid1, const struct kit_deviceid *deviceid2)
{
    return deviceid1 == NULL ? (deviceid2 == NULL ? 0 : -1) : deviceid2 == NULL ? 1 : memcmp(deviceid1, deviceid2, sizeof(struct kit_deviceid));
}
