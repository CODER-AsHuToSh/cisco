#ifndef DNS_NAME_H
#define DNS_NAME_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/*
 * |  domain name  |   string length   |  binary length  |
 * |               |   (excludes NUL)  |                 |
 * | .             | 1                 | 1               |
 * | x.            | 2                 | 3               |
 * | xx.           | 3                 | 4               |
 * | x{n}.         | n + 1             | n + 2           |
 * | (x{22}.){11}. | 254               | 255             |
 */
#define DNS_MAXLEN_LABEL         63                         /* RFC 1034 section 3.1 */
#define DNS_MAXLEN_NAME          255                        /* RFC 1034 section 3.1 */
#define DNS_MAXLEN_STRING        253                        /* No trailing '.', NOT including a terminating NUL */
#define DNS_MAX_LABEL_CNT        (DNS_MAXLEN_NAME / 2)      /* The practical limit of the number of labels in a name */

#define DNS_NAME_ROOT            ((const uint8_t *)"")

#define DNS_NAME_DEFAULT      0x00    // Allow mixed case and don't fully qualify
#define DNS_NAME_TOLOWER      0x01

#define DNS_CLASS_IN   1
#define DNS_CLASS_CS   2
#define DNS_CLASS_CH   3
#define DNS_CLASS_HS   4
#define DNS_CLASS_NONE 254
#define DNS_CLASS_ANY  255

extern const uint8_t dns_tolower[256];
extern const uint8_t dns_tohost[256];

#include "dns-name-proto.h"

static inline uint8_t *
dns_name_copy(uint8_t name_to[DNS_MAXLEN_NAME], const uint8_t *name_from)
{
    return memcpy(name_to, name_from, dns_name_len(name_from));
}

static inline const char *
dns_name_sscan(const char *str, const char *delim, uint8_t name[DNS_MAXLEN_NAME])
{
    unsigned name_len;

    name_len = DNS_MAXLEN_NAME;
    return dns_name_sscan_len(str, delim, name, &name_len);
}

#endif
