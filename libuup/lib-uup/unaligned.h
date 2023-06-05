#ifndef UNALIGNED_H
#define UNALIGNED_H

#include <string.h>

/*-
 * Convert hostlonglong to a network byte ordered uint64_t at an arbitrary address (may be unaligned)
 *
 * @return A pointer to the address after the network byte ordered uint64_t
 */
static inline void *
unaligned_htonll(void *netlonglong, uint64_t hostlonglong)
{
    uint8_t *p = netlonglong;

    p[0] = hostlonglong >> 56;
    p[1] = hostlonglong >> 48;
    p[2] = hostlonglong >> 40;
    p[3] = hostlonglong >> 32;
    p[4] = hostlonglong >> 24;
    p[5] = hostlonglong >> 16;
    p[6] = hostlonglong >> 8;
    p[7] = hostlonglong;
    return p + 8;
}

/*-
 * Convert hostlong to a network byte ordered uint32_t at an arbitrary address (may be unaligned)
 *
 * @return A pointer to the address after the network byte ordered uint32_t
 */
static inline void *
unaligned_htonl(void *netlong, uint32_t hostlong)
{
    uint8_t *p = netlong;

    p[0] = hostlong >> 24;
    p[1] = hostlong >> 16;
    p[2] = hostlong >> 8;
    p[3] = hostlong;
    return p + 4;
}

/*-
 * Convert hostshort to a network byte ordered uint16_t at an arbitrary address (may be unaligned)
 *
 * @return A pointer to the address after the network byte ordered uint16_t
 */
static inline void *
unaligned_htons(void *netshort, uint16_t hostshort)
{
    uint8_t *p = netshort;

    p[0] = hostshort >> 8;
    p[1] = hostshort;
    return p + 2;
}

/*-
 * Just like memcpy()
 *
 * @return A pointer to the address *after* the copy of the data
 */
static inline void *
unaligned_memcpy(void *netpacket, const void *hostdata, size_t size)
{
    memcpy(netpacket, hostdata, size);
    return (uint8_t *)netpacket + size;
}

static inline uint64_t
unaligned_ntohll(const void *netlonglong)
{
    const uint8_t *p = netlonglong;

    return (uint64_t)p[0] << 56 | (uint64_t)p[1] << 48 |
           (uint64_t)p[2] << 40 | (uint64_t)p[3] << 32 |
           (uint64_t)p[4] << 24 | (uint64_t)p[5] << 16 |
           (uint64_t)p[6] << 8  | (uint64_t)p[7];
}

static inline uint32_t
unaligned_ntohl(const void *netlong)
{
    const uint8_t *p = netlong;

    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static inline uint16_t
unaligned_ntohs(const void *netshort)
{
    const uint8_t *p = netshort;

    return (uint16_t)p[0] << 8 | (uint16_t)p[1];
}

static inline uint64_t
unaligned_get_uint64(const void *v)
{
    uint64_t ret;

    memcpy(&ret, v, sizeof(ret));
    return ret;
}

static inline const void *
unaligned_set_uint64(void *v, uint64_t val)
{
    return unaligned_memcpy(v, &val, sizeof(val));
}

/* Get a uint32 from a (possibly unaligned) host-order memory location */
static inline uint32_t
unaligned_get_uint32(const void *v)
{
    uint32_t ret;

    memcpy(&ret, v, sizeof(ret));
    return ret;
}

/* Set the (possibly unaligned) host-order memory location with the given value, returns the address after the copy of the data */
static inline const void *
unaligned_set_uint32(void *v, uint32_t val)
{
    return unaligned_memcpy(v, &val, sizeof(val));
}

/* Get a uint16 from a (possibly unaligned) host-order memory location */
static inline uint16_t
unaligned_get_uint16(const void *v)
{
    uint16_t ret;

    memcpy(&ret, v, sizeof(ret));
    return ret;
}

/* Set the (possibly unaligned) host-order memory location with the given value, returns the address after the copy of the data */
static inline const void *
unaligned_set_uint16(void *v, uint16_t val)
{
    return unaligned_memcpy(v, &val, sizeof(val));
}

/* Get an int64 from a (possibly unaligned) host-order memory location */
static inline int64_t
unaligned_get_int64(const void *v)
{
    int64_t ret;

    memcpy(&ret, v, sizeof(ret));
    return ret;
}

/* Set the (possibly unaligned) host-order memory location with the given value, returns the address after the copy of the data */
static inline const void *
unaligned_set_int64(void *v, int64_t val)
{
    return unaligned_memcpy(v, &val, sizeof(val));
}

/* Get an int32 from a (possibly unaligned) host-order memory location */
static inline int32_t
unaligned_get_int32(const void *v)
{
    int32_t ret;

    memcpy(&ret, v, sizeof(ret));
    return ret;
}

/* Set the (possibly unaligned) host-order memory location with the given value, returns the address after the copy of the data */
static inline const void *
unaligned_set_int32(void *v, int32_t val)
{
    return unaligned_memcpy(v, &val, sizeof(val));
}

/* Get an int16 from a (possibly unaligned) host-order memory location */
static inline int16_t
unaligned_get_int16(const void *v)
{
    int16_t ret;

    memcpy(&ret, v, sizeof(ret));
    return ret;
}

/* Set the (possibly unaligned) host-order memory location with the given value, returns the address after the copy of the data */
static inline const void *
unaligned_set_int16(void *v, int16_t val)
{
    return unaligned_memcpy(v, &val, sizeof(val));
}

#endif
