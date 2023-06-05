#ifndef NETSOCK_H
#define NETSOCK_H

#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>

#if __FreeBSD__
#include <sys/socket.h>
#endif

#ifdef __linux__
#define NETADDRV6_DWORD(netaddr, n) (netaddr).in6_addr.s6_addr32[n]
#else
#define NETADDRV6_DWORD(netaddr, n) (netaddr).in6_addr.__u6_addr.__u6_addr32[n]
#endif

#define NETADDRV4_DWORD(netaddr)    (netaddr).in_addr.s_addr
#define NETADDR_SIZE(a) ((a)->family == AF_INET6 ? sizeof(struct in6_addr) : (a)->family == AF_INET ? sizeof(struct in_addr) : 0)

struct netaddr {
    union {
        struct in_addr in_addr;
        struct in6_addr in6_addr;
        uint8_t addr;
    };
    sa_family_t family;
};

struct netsock {
    struct netaddr a;
    in_port_t port;
};

#include "netsock-proto.h"

static inline bool
netaddr_is_loopback(const struct netaddr *addr)
{
    return (addr->family == AF_INET && (ntohl(addr->in_addr.s_addr) & 0xff000000) == 0x7f000000)    /* 127.0.0.0/8 */
        || (addr->family == AF_INET6 && IN6_IS_ADDR_LOOPBACK(&addr->in6_addr));                     /* ::1 */
}

static inline void
netaddr_init(struct netaddr *addr, uint8_t value, sa_family_t family)
{
    size_t sz = NETADDR_SIZE(addr);

    addr->family = family;
    if (sz)    /* To silence a mis-warning about memset() using a const size of 0 from debian-8's gcc! */
        /* We would ideally like to pass &addr->addr instead of &addr->in6_addr to memset
         * but, GCC version 9 introduces stricter array-bounds checks and complains about
         * the offset being out of bounds.
         */
        memset(&addr->in6_addr, value, sz);
}

#endif
