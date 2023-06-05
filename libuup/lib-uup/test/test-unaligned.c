#include <limits.h>
#include <string.h>
#include <tap.h>

#include "unaligned.h"

int
main(void)
{
    uint8_t buffer[8];
    uint64_t uval64;
    uint32_t uval32;
    uint16_t uval16;
    int64_t val64;
    int32_t val32;
    int16_t val16;

    plan_tests(45);

    unaligned_htonll(buffer, 1);
    is(buffer[7], 1, "unaligned_htonll() wrote the LSB to last");
    is(unaligned_ntohll(buffer), 1, "unaligned_ntohll() got the right value back");

    is(unaligned_set_uint64(buffer, UINT64_MAX), buffer + 8, "unaligned_set_uint64 returns the correct buffer offset");
    is(unaligned_get_uint64(buffer), UINT64_MAX, "unaligned_get_uint64 is correct for UINT64_MAX");
    is(unaligned_set_uint64(buffer, 1), buffer + 8, "unaligned_set_uint64 returns the correct buffer offset");
    is(unaligned_get_uint64(buffer), 1, "unaligned_get_uint64 is correct for 1");
    memcpy(&uval64, buffer, sizeof(uval64));
    is(uval64, 1, "unaligned_set_uint64 stored the data in host order");

    unaligned_htonl(buffer, 1);
    is(buffer[3], 1, "unaligned_htonl() wrote the LSB to last");
    is(unaligned_ntohl(buffer), 1, "unaligned_ntohl() got the right value back");

    is(unaligned_set_uint32(buffer, UINT32_MAX), buffer + 4, "unaligned_set_uint32 returns the correct buffer offset");
    is(unaligned_get_uint32(buffer), UINT32_MAX, "unaligned_get_uint32 is correct for UINT32_MAX");
    is(unaligned_set_uint32(buffer, 1), buffer + 4, "unaligned_set_uint32 returns the correct buffer offset");
    is(unaligned_get_uint32(buffer), 1, "unaligned_get_uint32 is correct for 1");
    memcpy(&uval32, buffer, sizeof(uval32));
    is(uval32, 1, "unaligned_set_uint32 stored the data in host order");

    unaligned_htons(buffer, 1);
    is(buffer[1], 1, "unaligned_htons() wrote the LSB to last");
    is(unaligned_ntohs(buffer), 1, "unaligned_ntohs() got the right value back");

    is(unaligned_set_uint16(buffer, UINT16_MAX), buffer + 2, "unaligned_set_uint16 returns the correct buffer offset");
    is(unaligned_get_uint16(buffer), UINT16_MAX, "unaligned_get_uint16 is correct for UINT16_MAX");
    is(unaligned_set_uint16(buffer, 1), buffer + 2, "unaligned_set_uint16 returns the correct buffer offset");
    is(unaligned_get_uint16(buffer), 1, "unaligned_get_uint16 is correct for 1");
    memcpy(&uval16, buffer, sizeof(uval16));
    is(uval16, 1, "unaligned_set_uint16 stored the data in host order");

    is(unaligned_set_int64(buffer, INT64_MAX), buffer + 8, "unaligned_set_int64 returns the correct buffer offset");
    is(unaligned_get_int64(buffer), INT64_MAX, "unaligned_get_int64 is correct for INT64_MAX");
    is(unaligned_set_int64(buffer, 1), buffer + 8, "unaligned_set_int64 returns the correct buffer offset");
    is(unaligned_get_int64(buffer), 1, "unaligned_get_int64 is correct for 1");
    memcpy(&val64, buffer, sizeof(val64));
    is(val64, 1, "unaligned_set_int64 stored the data in host order");
    is(unaligned_set_int64(buffer, -1), buffer + 8, "unaligned_set_int64 returns the correct buffer offset");
    is(unaligned_get_int64(buffer), -1, "unaligned_get_int64 is correct for 1");
    memcpy(&val64, buffer, sizeof(val64));
    is(val64, -1, "unaligned_set_int64 stored the data in host order");

    is(unaligned_set_int32(buffer, INT32_MAX), buffer + 4, "unaligned_set_int32 returns the correct buffer offset");
    is(unaligned_get_int32(buffer), INT32_MAX, "unaligned_get_int32 is correct for INT32_MAX");
    is(unaligned_set_int32(buffer, 1), buffer + 4, "unaligned_set_int32 returns the correct buffer offset");
    is(unaligned_get_int32(buffer), 1, "unaligned_get_int32 is correct for 1");
    memcpy(&val32, buffer, sizeof(val32));
    is(val32, 1, "unaligned_set_int32 stored the data in host order");
    is(unaligned_set_int32(buffer, -1), buffer + 4, "unaligned_set_int32 returns the correct buffer offset");
    is(unaligned_get_int32(buffer), -1, "unaligned_get_int32 is correct for 1");
    memcpy(&val32, buffer, sizeof(val32));
    is(val32, -1, "unaligned_set_int32 stored the data in host order");

    is(unaligned_set_int16(buffer, INT16_MAX), buffer + 2, "unaligned_set_int16 returns the correct buffer offset");
    is(unaligned_get_int16(buffer), INT16_MAX, "unaligned_get_int16 is correct for INT16_MAX");
    is(unaligned_set_int16(buffer, 1), buffer + 2, "unaligned_set_int16 returns the correct buffer offset");
    is(unaligned_get_int16(buffer), 1, "unaligned_get_int16 is correct for 1");
    memcpy(&val16, buffer, sizeof(val16));
    is(val16, 1, "unaligned_set_int16 stored the data in host order");
    is(unaligned_set_int16(buffer, -1), buffer + 2, "unaligned_set_int16 returns the correct buffer offset");
    is(unaligned_get_int16(buffer), -1, "unaligned_get_int16 is correct for 1");
    memcpy(&val16, buffer, sizeof(val16));
    is(val16, -1, "unaligned_set_int16 stored the data in host order");

    return exit_status();
}
