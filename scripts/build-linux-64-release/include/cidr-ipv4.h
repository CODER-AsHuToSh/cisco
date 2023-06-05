#ifndef CIDR_IPV4_H
#define CIDR_IPV4_H

#include <netinet/in.h>
#include <stdbool.h>

#include "cidr-parse.h"

#define CIDR_IPV4_MAX_BUF_SIZE sizeof("###.###.###.###/##")

struct cidr_ipv4 {
    in_addr_t addr;    /* In host byte order */
    in_addr_t mask;    /* In host byte order */
};

/*-
 * The comparison functions differ:
 *
 * - cidr_ipv4_find_compare()
 *   Compares cidrs as equal if they collide.  This is usually used with bsearch().
 *
 * - cidr_ipv4_sort_compar_r()
 *   Compares cidrs as equal only if they're exactly equal.  This is used with qsort_r().
 *
 *   A collisions 'int' should be set to zero and its address passed to qsort_r().  If
 *   the value is updated to non-zero, then the caller should iterate through the list
 *   and delete the (already sorted) colliding values.
 */
int cidr_ipv4_find_compare(const void *a, const void *b);
#ifdef __linux__
int cidr_ipv4_sort_compar_r(const void *a, const void *b, void *collision);
#else
int cidr_ipv4_sort_compar_r(void *collision, const void *a, const void *b);
#endif
const char *cidr_ipv4_sscan(struct cidr_ipv4 *cidr, const char *str, enum cidr_parse how);
const char *cidr_ipv4_sscan_verbose(struct cidr_ipv4 *cidr, const char *fn, int line, const char *str, enum cidr_parse how);
unsigned cidr_ipv4_maskbits(const struct cidr_ipv4 *cidr);
const char *cidr_ipv4_to_buf(const struct cidr_ipv4 *cidr, bool elide_32bit_masks, char *buf, unsigned size);
const char *cidr_ipv4_to_str(const struct cidr_ipv4 *cidr, bool elide_32bit_masks);

/* Note, struct cidr_ipv4 (cidr & net) is in host byte order, inaddr is (of course) in network byte order */
#define CIDR_IPV4_CONTAINS_ADDR(cidr, inaddr) (((ntohl((inaddr).s_addr) ^ (cidr)->addr) & (cidr)->mask) == 0)
#define CIDR_IPV4_CONTAINS_NET(cidr, net)     ((cidr)->mask <= (net)->mask && (((net)->addr ^ (cidr)->addr) & (cidr)->mask) == 0)
#define CIDR_IPV4_COLLIDES(cidr1, cidr2)      (!(((cidr1)->addr ^ (cidr2)->addr) & (cidr1)->mask & (cidr2)->mask))
#define CIDR_IPV4_EXCEEDS_ADDR(cidr, inaddr)  (((cidr)->addr & (cidr)->mask) > (ntohl((inaddr).s_addr) & (cidr)->mask))

#endif
