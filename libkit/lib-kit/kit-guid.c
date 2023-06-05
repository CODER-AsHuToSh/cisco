#include <string.h>
#include <sxe-log.h>
#include <sxe-util.h>

#include "kit.h"

const struct kit_guid kit_guid_nil = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
};

/**
 * Convert a guid into a string of KIT_GUID_STR_LEN bytes
 */
char *
kit_guid_to_buf(const struct kit_guid *guid, char *buf, size_t size)
{
    SXE_UNUSED_PARAMETER(size);
    SXEA6(size >= KIT_GUID_STR_LEN + 1, "GUID buffer must have room for %u hex digits plus 1 for the NUL", KIT_GUID_STR_LEN);
    sxe_hex_from_bytes(buf, guid ? guid->bytes : kit_guid_nil.bytes, KIT_GUID_SIZE);
    return buf;
}

/* Return printable string of a guid */
const char *
kit_guid_to_str(const struct kit_guid *guid)
{
    static __thread char str[KIT_GUID_STR_LEN + 1];

    return kit_guid_to_buf(guid, str, sizeof(str));
}

/* Return printable string of a md5 */
const char *
kit_md5_to_str(const struct kit_md5 *md5)
{
    static __thread char str[KIT_GUID_STR_LEN + 1];

    return kit_guid_to_buf((const struct kit_guid *)md5, str, sizeof(str));
}

/* Build a guid from a string */
struct kit_guid *
kit_guid_from_str(struct kit_guid *guid, const char *str_hex)
{
    SXEE7("(guid=%p str_hex=%s)", guid, str_hex);

    if (strlen(str_hex) != KIT_GUID_STR_LEN) {
        SXEL3("kit_guid_from_str: invalid guid str '%s'", str_hex);
        *guid = kit_guid_nil;
    }
    else
        sxe_hex_to_bytes(guid->bytes, str_hex, KIT_GUID_STR_LEN);

    SXER7("return guid=%s", kit_guid_to_str(guid));
    return guid;
}

/* Compare two guids */
int
kit_guid_cmp(const struct kit_guid *guid1, const struct kit_guid *guid2)
{
    return guid1 == NULL ? (guid2 == NULL ? 0 : -1) : guid2 == NULL ? 1 : memcmp(guid1, guid2, sizeof(struct kit_guid));
}

