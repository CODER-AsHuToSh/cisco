#include <arpa/inet.h>
#include <errno.h>
#include <kit.h>
#include <stdio.h>
#include <string.h>
#include <sxe-log.h>

#if __FreeBSD__
#include <sys/socket.h>
#endif

#include "cidr-ipv6.h"

/*-
 * A few notes regarding the choice of data structures:
 *
 * - Although there are native 128bit data types in current versions of
 *   gcc, we don't use them because the resulting code would not fit
 *   well with the defined struct in6_addr (as of Dec 2012).  Instead,
 *   we work with the s6_addr32 part of the structure.  As a result,
 *   N32BITPARTS iterations will show up frequently as we iterate through
 *   the 32bit parts of the IPv6 address.
 *
 * - We keep data in correct struct in6_addr format (network byte order)
 *   rather than taking the cidr_ipv4 approach of storing in host byte
 *   order so that native bitwise operations are more convenient.
 *
 * - We store the netmask bits rather than the netmask itself as it is
 *   easier to compare than a network byte order, segmented, IPv6 mask.
 */

#define N32BITPARTS 4
#define NIPV6BITS   128

in_addr_t
bits2mask(int bits)
{
    uint32_t mask = 0xffffffff;

    /*
     * Find the mask for the first 32bits of the given mask bits.
     * The passed bits may be greater than 32 and may be less than
     * zero, so we must handle out-of-range values gracefully.
     */
    if (bits < 32)
        mask = bits <= 0 ? 0 : mask << (32 - bits);

    return htonl(mask);
}

static int
cidr6_cmp(const struct cidr_ipv6 *a1, const struct cidr_ipv6 *a2)
{
    uint64_t cmp;
    unsigned q;

    for (q = 0; q < N32BITPARTS; q++)
        if ((cmp = (uint64_t)ntohl(CIDRV6_DWORD(*a1, q)) - (uint64_t)ntohl(CIDRV6_DWORD(*a2, q))))
            return cmp;

    return 0;    /* COVERAGE EXCLUSION: unreachable - cidr_ipv6_collides() is always checked before calling cidr6_cmp() */
}

bool
cidr_ipv6_apply_mask(struct cidr_ipv6 *cidr)
{
    in_addr_t mask;
    unsigned q;
    int bits;
    bool ret;

    ret = false;
    for (q = 0, bits = cidr->maskbits; q < N32BITPARTS; q++, bits -= 32) {
        mask = bits2mask(bits);
        if ((CIDRV6_DWORD(*cidr, q) & mask) != CIDRV6_DWORD(*cidr, q)) {
            CIDRV6_DWORD(*cidr, q) &= mask;
            ret = true;
        }
    }

    return ret;
}

static const char *
cidr_ipv6_parse(struct cidr_ipv6 *cidr, const char *str, enum cidr_parse how)
{
    char buf[INET6_ADDRSTRLEN + sizeof("[]/128") - 1], *end, *slash;
    unsigned long val;
    int square;

    /*-
     * We read "[addr]/bits", where "[" and "]" are optional and "/bits"
     * is optional/mandatory depending on the value of 'how'.
     *
     * The optional [] is necessary for file formats such as *prefs
     * where we use ':' as a separator.
     *
     * inet_pton() parses the address, but doesn't tolerate trailing
     * garbage, so we need to copy the address and nul-teriminate it.
     */
    square = *str == '[';
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    slash = NULL;
    for (end = buf; *end; end++) {
        if ((*end >= 'a' && *end <= 'f')
         || (*end >= 'A' && *end <= 'F')
         || (*end >= '0' && *end <= '9')
         || (square && end == buf)
         || *end == ':' || *end == '.')
            continue;    /* valid char */

        if (square && *end == ']')
            end++;
        if (*end == '/')
            slash = end;
        *end = '\0';
        break;
    }

    if (how == PARSE_CIDR_ONLY && !slash) {
        SXEL7("Missing /NNN part");
        return NULL;
    }

    if (square) {
        if (end == buf || end[-1] != ']') {
            if (slash)
                *slash = '/';
            SXEL7("No balancing ']'");
            return NULL;
        }
        end[-1] = '\0';
    }

    if (!inet_pton(AF_INET6, buf + square, &cidr->addr)) {
        SXEL7("Invalid address (inet_pton() fails)");
        return NULL;
    }

    if (!slash || how == PARSE_IP_ONLY)
        val = NIPV6BITS;
    else if ((val = kit_strtoul(slash + 1, &end, 10)) > NIPV6BITS || errno != 0 || end == slash + 1) {
        SXEL7("Invalid bits value");
        return NULL;
    }
    cidr->maskbits = val;

    return end ? str + (end - buf) : NULL;
}

const char *
cidr_ipv6_sscan(struct cidr_ipv6 *cidr, const char *str, enum cidr_parse how)
{
    const char *end = cidr_ipv6_parse(cidr, str, how);
    if (end)
        cidr_ipv6_apply_mask(cidr);
    return end;
}

const char *
cidr_ipv6_sscan_verbose(struct cidr_ipv6 *cidr, const char *fn, int line, const char *str, enum cidr_parse how)
{
    const char *end = cidr_ipv6_parse(cidr, str, how);

    if (end && cidr_ipv6_apply_mask(cidr))
        SXEL3("%s: %d: %.*s: Invalid CIDR - should be %s", fn, line, (int)(end - str), str, cidr_ipv6_to_str(cidr, false));

    return end;
}

const char *
cidr_ipv6_to_str(const struct cidr_ipv6 *cidr, bool elide_128bit_mask)
{
    static __thread char buf[INET6_ADDRSTRLEN + sizeof("[]/128") - 1];
    int pos;

    if (elide_128bit_mask && cidr->maskbits != 128)
        elide_128bit_mask = false;
    pos = 0;
    if (!elide_128bit_mask)
        buf[pos++] = '[';
    inet_ntop(AF_INET6, &cidr->addr, buf + pos, INET6_ADDRSTRLEN);
    if (!elide_128bit_mask) {
        pos = strlen(buf);
        snprintf(buf + pos, sizeof(buf) - pos, "]/%u", cidr->maskbits);
    }

    return buf;
}

bool
cidr_ipv6_collides(const struct cidr_ipv6 *a, const struct cidr_ipv6 *b)
{
    int bits;
    unsigned q;

    bits = a->maskbits < b->maskbits ? a->maskbits : b->maskbits;
    for (q = 0; q < N32BITPARTS && bits > 0; q++, bits -= 32)
        if ((CIDRV6_DWORD(*a, q) ^ CIDRV6_DWORD(*b, q)) & bits2mask(bits))
            return false;    /* no collision */

    return true;    /* all masked parts are the same! */
}

bool
cidr_ipv6_contains_net(const struct cidr_ipv6 *cidr, const struct cidr_ipv6 *net)
{
    return cidr->maskbits <= net->maskbits && cidr_ipv6_collides(cidr, net);
}

bool
cidr_ipv6_contains_addr(const struct cidr_ipv6 *cidr, const struct in6_addr *ip6addr)
{
    struct cidr_ipv6 addr = { *ip6addr, 128 };
    return cidr_ipv6_collides(cidr, &addr);
}

int
#ifdef __linux__
cidr_ipv6_sort_compar_r(const void *a, const void *b, void *collision)
#else
cidr_ipv6_sort_compar_r(void *collision, const void *a, const void *b)
#endif
{
    const struct cidr_ipv6 *ca = (const struct cidr_ipv6 *)a;
    const struct cidr_ipv6 *cb = (const struct cidr_ipv6 *)b;

    if (cidr_ipv6_collides(ca, cb)) {
        if (collision)
            *(int *)collision = 1;
        return ca->maskbits - cb->maskbits;
    }

    return cidr6_cmp(ca, cb);
}

int
cidr_ipv6_find_compare(const void *a, const void *b)
{
    const struct cidr_ipv6 *ca = (const struct cidr_ipv6 *)a;
    const struct cidr_ipv6 *cb = (const struct cidr_ipv6 *)b;

    if (cidr_ipv6_collides(ca, cb))
        return 0;

    return cidr6_cmp(ca, cb);
}
