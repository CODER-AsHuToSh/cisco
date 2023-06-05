#ifndef CIDR_IPV6_H
#define CIDR_IPV6_H

#include <netinet/in.h>
#include <stdbool.h>

#include "cidr-parse.h"

#ifdef __linux__
#define CIDRV6_DWORD(cidr, n) (cidr).addr.s6_addr32[n]
#else
#define CIDRV6_DWORD(cidr, n) (cidr).addr.__u6_addr.__u6_addr32[n]
#endif

struct cidr_ipv6 {
    struct in6_addr addr;        /* Base address */
    uint8_t         maskbits;    /* Bits in mask */
};

in_addr_t bits2mask(int bits);
bool cidr_ipv6_collides(const struct cidr_ipv6 *a, const struct cidr_ipv6 *b);
bool cidr_ipv6_contains_net(const struct cidr_ipv6 *cidr, const struct cidr_ipv6 *net);
bool cidr_ipv6_contains_addr(const struct cidr_ipv6 *cidr, const struct in6_addr *addr);
/* The comparison functions differ as described in cidr-ipv4.h */
int cidr_ipv6_find_compare(const void *a, const void *b);
#ifdef __linux__
int cidr_ipv6_sort_compar_r(const void *a, const void *b, void *collision);
#else
int cidr_ipv6_sort_compar_r(void *collision, const void *a, const void *b);
#endif
bool cidr_ipv6_apply_mask(struct cidr_ipv6 *cidr);
const char *cidr_ipv6_sscan(struct cidr_ipv6 *cidr, const char *str, enum cidr_parse how);
const char *cidr_ipv6_sscan_verbose(struct cidr_ipv6 *cidr, const char *fn, int line, const char *str, enum cidr_parse how);
const char *cidr_ipv6_to_str(const struct cidr_ipv6 *cidr, bool elide_128bit_mask);

#endif
