#include <arpa/inet.h>
#include <murmurhash3.h>
#include <stdio.h>
#include <sxe-log.h>

#if __FreeBSD__
#include <sys/socket.h>
#endif

#include "netsock.h"
#include "sockaddrutil.h"

bool
netaddr_equal(const struct netaddr *a1, const struct netaddr *a2)
{
    return a1->family == a2->family && memcmp(&a1->in6_addr, &a2->in6_addr, NETADDR_SIZE(a1)) == 0;
}

bool
netsock_fromsockaddr(struct netsock *n, const struct sockaddr *sa, socklen_t sa_len)
{
    switch (n->a.family = sa->sa_family) {
    case AF_INET:
        if ((size_t)sa_len < sizeof(const struct sockaddr_in))
            break;
        n->port = ((const struct sockaddr_in *)sa)->sin_port;
        n->a.in_addr = ((const struct sockaddr_in *)sa)->sin_addr;
        return true;
    case AF_INET6:
        if ((size_t)sa_len < sizeof(const struct sockaddr_in6))
            break;
        n->port = ((const struct sockaddr_in6 *)sa)->sin6_port;
        n->a.in6_addr = ((const struct sockaddr_in6 *)sa)->sin6_addr;
        return true;
    }
    return false;
}

uint32_t
netaddr_hash32(const struct netaddr *a)
{
    const uint32_t seed = 91099104;

    /*
     * These values were chosen based on the assumption that the
     * low-order bits of network addresses have the greatest entropy.
     */
    switch (a->family) {
    case AF_INET:
        return murmur3_32(&a->in_addr, sizeof(a->in_addr), seed);
    case AF_INET6:
        return murmur3_32(&a->in6_addr, sizeof(a->in6_addr), seed);
    }
    return 0;
}

uint32_t
netaddr_fingerprint_bit(const struct netaddr *a)
{
    return (uint32_t)1 << (netaddr_hash32(a) % 32);
}

struct netaddr *
netaddr_from_str(struct netaddr *a, const char *str, sa_family_t family)
{
    a->family = family;
    return inet_pton(family, str, a) == 1 ? a : NULL;
}

const char *
netaddr_to_buf(const struct netaddr *a, char *buf, size_t sz)
{
    if (a == NULL || inet_ntop(a->family, &a->addr, buf, sz) == NULL)
        snprintf(buf, sz, "unknown");

    return buf;
}

const char *
netaddr_to_str(const struct netaddr *a)
{
    static __thread char str[INET6_ADDRSTRLEN];

    return netaddr_to_buf(a, str, sizeof(str));
}

bool
netaddr_within_mask(const struct netaddr *n1, const struct netaddr *n2, unsigned bits)
{
    uint32_t mask;
    unsigned i;

    if (n1->family == n2->family)
        switch (n1->family) {
        case AF_INET:
            if (bits > 32)
                bits = 32;
            mask = htonl(~(uint32_t)((1UL << (32 - bits)) - 1));
            return (n1->in_addr.s_addr & mask) == (n2->in_addr.s_addr & mask);
        case AF_INET6:
            if (bits > 128)
                bits = 128;
            for (i = 0; bits && i < 4; i++, bits -= 32)
                if (bits <= 32) {
                    mask = htonl(~(uint32_t)((1UL << (32 - bits)) - 1));
                    return (NETADDRV6_DWORD(*n1, i) & mask) == (NETADDRV6_DWORD(*n2, i) & mask);
                } else if (NETADDRV6_DWORD(*n1, i) != NETADDRV6_DWORD(*n2, i))
                    break;
        default:
            break;
        }

    return false;
}

void
netsock_init(struct netsock *me, sa_family_t family, const void *addr, in_port_t port)
{
    if (addr == NULL)
        addr = (const void *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"; /* in6addr_any / INADDR_ANY */

    me->a.family = family == AF_INET || family == AF_INET6 ? family : AF_UNSPEC;
    me->port = port;
    memcpy(&me->a.in_addr, addr, NETADDR_SIZE(&me->a));
}

socklen_t
netsock_to_sockaddr(const struct netsock *n, void *sockaddr, socklen_t sockaddr_len)
{
    switch (((struct sockaddr *)sockaddr)->sa_family = n->a.family) {
    case AF_INET:
        if ((size_t) sockaddr_len < sizeof(struct sockaddr_in))
            break;
        ((struct sockaddr_in *)sockaddr)->sin_port = n->port;
        ((struct sockaddr_in *)sockaddr)->sin_addr = n->a.in_addr;
#if defined(__FreeBSD__) || defined(__APPLE__)
        ((struct sockaddr_in *)sockaddr)->sin_len = sizeof(struct sockaddr_in);
#endif
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        if ((size_t) sockaddr_len < sizeof(struct sockaddr_in6))
            break;
        ((struct sockaddr_in6 *)sockaddr)->sin6_port = n->port;
        ((struct sockaddr_in6 *)sockaddr)->sin6_flowinfo = 0;
        ((struct sockaddr_in6 *)sockaddr)->sin6_addr = n->a.in6_addr;
        ((struct sockaddr_in6 *)sockaddr)->sin6_scope_id = 0;
#if defined(__FreeBSD__) || defined(__APPLE__)
        ((struct sockaddr_in6 *)sockaddr)->sin6_len = sizeof(struct sockaddr_in6);
#endif
        return sizeof(struct sockaddr_in6);
    }
    return 0;
}

const char *
netsock_to_str(const struct netsock *netsock)
{
    static __thread char buf[INET6_ADDRSTRLEN + sizeof("[]:65535") - 1];
    int i, used;

    if (inet_ntop(netsock->a.family, &netsock->a.addr, buf + 1, sizeof(buf) - 1) == NULL)
        return "unknown";    /* COVERAGE EXCLUSION: buf will always be big enough... right? */
    used = 1 + strlen(buf + 1);
    SXEA6(used < (int)sizeof(buf) - 7, "inet_ntop() is too greedy - used %d of %zu bytes", used - 1, sizeof(buf));

    if (netsock->a.family == AF_INET6) {
        buf[0] = '[';
        buf[used++] = ']';
    }

    if ((i = snprintf(buf + used, sizeof(buf) - used, ":%u", ntohs(netsock->port))) < 0 || (size_t)i >= sizeof(buf) - used)
        return "unknown";    /* COVERAGE EXCLUSION: buf will always be big enough... right? */

    return netsock->a.family == AF_INET6 ? buf : buf + 1;
}

struct netsock *
netsock_from_str(struct netsock *ns, const char *str, unsigned default_port)
{
    socklen_t slen;
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } sock;

    slen = sizeof(sock);
    return sockaddr_sscan(str, default_port, &sock.sa, &slen) && netsock_fromsockaddr(ns, &sock.sa, slen) ? ns : NULL;
}
