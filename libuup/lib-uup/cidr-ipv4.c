#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <sxe-log.h>

#if __FreeBSD__
#include <string.h>
#else
#include <bsd/string.h>
#endif

#include "cidr-ipv4.h"

static const char *
cidr_ipv4_parse(struct cidr_ipv4 *cidr, const char *str, enum cidr_parse how)
{
    unsigned  mask_len = 32;
    int       consumed = 0;     // Must be initialized to 0 (undocumented sscanf requirement)
    in_addr_t addr;
    unsigned  u0, u1, u2, u3;

    if (!isdigit(*str) || sscanf(str, "%u.%u.%u.%u%n", &u0, &u1, &u2, &u3, &consumed) != 4
     || u0 > 255 || u1 > 255 || u2 > 255 || u3 > 255)
        return NULL;

    addr     = u0 << 24 | u1 << 16 | u2 << 8 | u3;
    str     += consumed;
    consumed = 0;

    if (how != PARSE_IP_ONLY && sscanf(str, "/%u%n", &mask_len, &consumed) != 1) {
        if (how == PARSE_CIDR_ONLY)
            return NULL;

        consumed = 0;
        mask_len = 32;
    }

    if (mask_len > 32)
        return NULL;

    cidr->addr = addr;
    /* An N-bit shift of an N-bit type is undefined */
    cidr->mask = mask_len == 0 ? 0 : (in_addr_t)-1 << (32 - mask_len);

    return str + consumed;
}

const char *
cidr_ipv4_sscan(struct cidr_ipv4 *cidr, const char *str, enum cidr_parse how)
{
    const char *end = cidr_ipv4_parse(cidr, str, how);
    if (end)
        cidr->addr &= cidr->mask;
    return end;
}

const char *
cidr_ipv4_sscan_verbose(struct cidr_ipv4 *cidr, const char *fn, int line, const char *str, enum cidr_parse how)
{
    const char *end = cidr_ipv4_parse(cidr, str, how);

    if (end && (cidr->addr & cidr->mask) != cidr->addr) {
        cidr->addr &= cidr->mask;
        SXEL3("%s: %d: %.*s: Invalid CIDR - should be %s", fn, line, (int)(end - str), str, cidr_ipv4_to_str(cidr, false));
    }

    return end;
}

unsigned
cidr_ipv4_maskbits(const struct cidr_ipv4 *cidr)
{
    uint32_t check;
    unsigned bits;

    for (bits = 0, check = 0x80000000; bits < 32 && cidr->mask & check; bits++, check >>= 1)
        ;

    return bits;
}

const char *
cidr_ipv4_to_buf(const struct cidr_ipv4 *cidr, bool elide_32bit_masks, char *buf, unsigned size)
{
    const char    *addrtxt;
    struct in_addr a;

    a.s_addr = htonl(cidr->addr);
    addrtxt  = inet_ntoa(a);

    if (elide_32bit_masks && cidr->mask == 0xffffffff) {
        if (strlcpy(buf, addrtxt, size) >= size)
            return NULL;

        return buf;
    }

    if ((size_t)snprintf(buf, size, "%s/%u%s", addrtxt, cidr_ipv4_maskbits(cidr),
                         (cidr->addr & cidr->mask) != cidr->addr ? " (WARNING: invalid CIDR)" : "") >= size)
        return NULL;

    return buf;
}

const char *
cidr_ipv4_to_str(const struct cidr_ipv4 *cidr, bool elide_32bit_masks)
{
    static __thread char buf[CIDR_IPV4_MAX_BUF_SIZE];

    SXEA1(cidr_ipv4_to_buf(cidr, elide_32bit_masks, buf, sizeof(buf)), "%zu byte buffer is too small", sizeof(buf));
    return buf;
}

int
#ifdef __linux__
cidr_ipv4_sort_compar_r(const void *a, const void *b, void *collision)
#else
cidr_ipv4_sort_compar_r(void *collision, const void *a, const void *b)
#endif
{
    const struct cidr_ipv4 *ca = (const struct cidr_ipv4 *)a;
    const struct cidr_ipv4 *cb = (const struct cidr_ipv4 *)b;

    if (CIDR_IPV4_COLLIDES(ca, cb)) {
        if (collision)
            *(int *)collision = 1;
        return ca->mask < cb->mask ? -1 : ca->mask > cb->mask;
    }
    return ca->addr < cb->addr ? -1 : ca->addr > cb->addr;
}

int
cidr_ipv4_find_compare(const void *a, const void *b)
{
    const struct cidr_ipv4 *ca = (const struct cidr_ipv4 *)a;
    const struct cidr_ipv4 *cb = (const struct cidr_ipv4 *)b;

    if (CIDR_IPV4_COLLIDES(ca, cb))
        return 0;
    return ca->addr < cb->addr ? -1 : ca->addr > cb->addr;
}
