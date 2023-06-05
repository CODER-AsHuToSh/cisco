#include <arpa/inet.h>
#include <sxe-log.h>
#include <tap.h>

#include "netsock.h"


int
main(void)
{
    struct netsock addr1, addr2;
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } sock;

    plan_tests(62);

    is_strncmp(netaddr_to_str(NULL), "unknown", INET6_ADDRSTRLEN, "netaddr_to_str() handled NULL address");

    addr1.a.family = 0;
    is_strncmp(netaddr_to_str(&addr1.a), "unknown", INET6_ADDRSTRLEN, "netaddr_to_str() handled bad address");

    netsock_init(&addr1, AF_INET, NULL, 0);
    is_strncmp(netaddr_to_str(&addr1.a), "0.0.0.0", INET6_ADDRSTRLEN, "netsock_init() handled a NULL IPv4 address");

    netsock_init(&addr1, AF_INET6, NULL, 0);
    is_strncmp(netaddr_to_str(&addr1.a), "::", INET6_ADDRSTRLEN, "netsock_init() handled a NULL IPv6 address");

    netsock_init(&addr1, AF_INET + AF_INET6 + 1, (const char *)1, 0);
    is_strncmp(netaddr_to_str(&addr1.a), "unknown", INET6_ADDRSTRLEN, "netsock_init() handled a bad family and didn't reference the pointer");

    ok(netaddr_from_str(&addr1.a, "192.168.1.1", AF_INET), "Create IPv4 netsock from string");
    is_strncmp(netaddr_to_str(&addr1.a), "192.168.1.1", INET6_ADDRSTRLEN, "netaddr_to_str() handled good IPv4 address");
    sock.sin.sin_family = AF_INET;
    sock.sin.sin_port = 0;
    inet_pton(AF_INET, "192.168.1.1", &sock.sin.sin_addr);
    ok(!netsock_fromsockaddr(&addr2, &sock.sa, sizeof(sock.sin) - 1), "Cannot convert from a sockaddr that's too small");
    ok(netsock_fromsockaddr(&addr2, &sock.sa, sizeof(sock.sin)), "Converted 192.168.1.1 sockaddr to a netsock");
    ok(netaddr_equal(&addr1.a, &addr2.a), "IPv4 netsocks are equal");
    ok(netsock_to_sockaddr(&addr1, &sock.sa, sizeof(sock.sin) - 1) == 0, "Cannot convert IPv4 to a sockaddr without enough space");

    ok(netaddr_from_str(&addr1.a, "2001:1938:27d:0:240:f4ff:feb1:1c85", AF_INET6), "Create IPv6 netsock from string");
    is_strncmp(netaddr_to_str(&addr1.a), "2001:1938:27d:0:240:f4ff:feb1:1c85", INET6_ADDRSTRLEN, "netaddr_to_str() handled good IPv6 address");
    sock.sin6.sin6_family = AF_INET6;
    sock.sin6.sin6_port = 0;
    inet_pton(AF_INET6, "2001:1938:27d:0:240:f4ff:feb1:1c85", &sock.sin6.sin6_addr);
    ok(!netsock_fromsockaddr(&addr2, &sock.sa, sizeof(sock.sin6) - 1), "Cannot convert from a sockaddr that's too small");
    ok(netsock_fromsockaddr(&addr2, &sock.sa, sizeof(sock.sin6)), "Converted 2001:1938:27d:0:240:f4ff:feb1:1c85 sockaddr to a netsock");
    ok(netaddr_equal(&addr1.a, &addr2.a), "IPv6 netsocks are equal");
    ok(netsock_to_sockaddr(&addr1, &sock.sa, sizeof(sock.sin6) - 1) == 0, "Cannot convert IPv6 to a sockaddr without enough space");

    sock.sa.sa_family = AF_INET + AF_INET6 + 1;
    ok(!netsock_fromsockaddr(&addr2, &sock.sa, sizeof(sock)), "Cannot convert from a sockaddr with an invalid family");

    addr1.a.family = AF_INET + AF_INET6 + 1;
    ok(netaddr_hash32(&addr1.a) == 0, "Cannot hash a netsock with an invalid family");
    ok(netsock_to_sockaddr(&addr1, &sock.sa, sizeof(sock)) == 0, "Cannot convert a netsock with an invalid family to a sockaddr");

    ok(netaddr_from_str(&addr1.a, "1.2.3.0", AF_INET), "Create IPv4 netaddr from string");
    ok(netaddr_from_str(&addr2.a, "1.2.3.255", AF_INET), "Create another IPv4 netaddr from string");
    ok(netaddr_within_mask(&addr1.a, &addr2.a, 24), "Addresses are within the same /24");
    ok(!netaddr_within_mask(&addr1.a, &addr2.a, 25), "Addresses are not within the same /25");
    ok(!netaddr_within_mask(&addr1.a, &addr2.a, 33), "Addresses are not within the same /33!");

    ok(netaddr_from_str(&addr1.a, "1:2:3:4:5:6:7:8", AF_INET6), "Create IPv6 netaddr from string");
    ok(netaddr_from_str(&addr2.a, "1:2:3::5:6:7:8", AF_INET6), "Create another IPv6 netaddr from string");
    ok(netaddr_within_mask(&addr1.a, &addr2.a, 56), "Addresses are within the same /56");
    ok(netaddr_within_mask(&addr1.a, &addr2.a, 61), "Addresses are within the same /61");
    ok(!netaddr_within_mask(&addr1.a, &addr2.a, 62), "Addresses are not within the same /62");
    ok(netaddr_from_str(&addr2.a, "1:2:3:100:5:6:7:8", AF_INET6), "Create yet another IPv6 netaddr from string");
    ok(!netaddr_within_mask(&addr1.a, &addr2.a, 56), "Addresses are not within the same /56");
    ok(!netaddr_within_mask(&addr1.a, &addr2.a, 128), "Addresses are not within the same /128");
    ok(netaddr_from_str(&addr2.a, "1:2:3:4:5:6:7:0", AF_INET6), "Create still another IPv6 netaddr from string");
    ok(netaddr_within_mask(&addr1.a, &addr2.a, 124), "Addresses are within the same /124");
    ok(!netaddr_within_mask(&addr1.a, &addr2.a, 125), "Addresses are not within the same /125");
    ok(!netaddr_within_mask(&addr1.a, &addr2.a, 129), "Addresses are not within the same /129");
    ok(netaddr_within_mask(&addr1.a, &addr1.a, 129), "Address is within the same /129 as itself");
    addr1.a.family = AF_INET + AF_INET6 + 1;
    ok(!netaddr_within_mask(&addr1.a, &addr1.a, 128), "Unrecognised address is not within the same /128 as itself");

    netaddr_from_str(&addr1.a, "1.2.3.4", AF_INET);
    is(netaddr_fingerprint_bit(&addr1.a), 4194304, "random bit within 32 bits set from murmurhash ipv4");
    is(__builtin_popcount(netaddr_fingerprint_bit(&addr1.a)), 1, "generated random hash with 1 bit set");

    netaddr_from_str(&addr1.a, "2.0.1.0", AF_INET);
    is(netaddr_fingerprint_bit(&addr1.a), 16384, "random bit within 32 bits set from murmurhash ipv4");
    is(__builtin_popcount(netaddr_fingerprint_bit(&addr1.a)), 1, "generated random hash with 1 bit set");

    netaddr_from_str(&addr1.a, "1.0.2.0", AF_INET);
    is(netaddr_fingerprint_bit(&addr1.a), 16384, "random bit within 32 bits set from murmurhash ipv4");
    is(__builtin_popcount(netaddr_fingerprint_bit(&addr1.a)), 1, "generated random hash with 1 bit set");

    netaddr_from_str(&addr1.a, "1.2.0.1", AF_INET);
    is(netaddr_fingerprint_bit(&addr1.a), 524288, "random bit within 32 bits set from murmurhash ipv4");
    is(__builtin_popcount(netaddr_fingerprint_bit(&addr1.a)), 1, "generated random hash with 1 bit set");

    netaddr_from_str(&addr1.a, "1.1.0.4", AF_INET);
    is(netaddr_fingerprint_bit(&addr1.a), 67108864, "random bit within 32 bits set from murmurhash ipv4");
    is(__builtin_popcount(netaddr_fingerprint_bit(&addr1.a)), 1, "generated random hash with 1 bit set");

    netaddr_from_str(&addr1.a, "A:0:0:0:2:0:0:1", AF_INET6);
    is(netaddr_fingerprint_bit(&addr1.a), 134217728, "random bit within 32 bits set from murmurhash ipv6");
    is(__builtin_popcount(netaddr_fingerprint_bit(&addr1.a)), 1, "generated random hash with 1 bit set");

    netaddr_from_str(&addr1.a, "0:0:0:0:0:0:0:0", AF_INET6);
    is(netaddr_fingerprint_bit(&addr1.a), 32, "random bit within 32 bits set from murmurhash ipv6");
    is(__builtin_popcount(netaddr_fingerprint_bit(&addr1.a)), 1, "generated random hash with 1 bit set");

    netaddr_from_str(&addr1.a, "F:2:F:F:F:F:4.3.2.1", AF_INET6);
    is(netaddr_fingerprint_bit(&addr1.a), 2097152, "random bit within 32 bits set from murmurhash ipv6");
    is(__builtin_popcount(netaddr_fingerprint_bit(&addr1.a)), 1, "generated random hash with 1 bit set");

    netaddr_from_str(&addr1.a, "::FFFF:204.152.189.116", AF_INET6);
    is(netaddr_fingerprint_bit(&addr1.a), 32768,                 "random bit within 32 bits set from murmurhash ipv6");
    is(__builtin_popcount(netaddr_fingerprint_bit(&addr1.a)), 1, "generated random hash with 1 bit set");
    is_eq(netsock_to_str(&addr1), "[::ffff:204.152.189.116]:0",  "Got the expected string representation of a IPv6/port pair");

    diag("Add coverage");
    {
        ok(netsock_from_str(&addr1, "127.0.0.1:52", 0),                         "Successfully converted an IPv4/port to netsock");
        is(netsock_to_sockaddr(&addr1, &sock, sizeof(sock)), sizeof(sock.sin),  "Netaddr of family AF_INET produces a sockaddr_in");
        ok(netsock_from_str(&addr1, "[A:0:0:0:2:0:0:1]:0", 52),                 "Successfully converted an IPv6/port to netsock");
        is(netsock_to_sockaddr(&addr1, &sock, sizeof(sock)), sizeof(sock.sin6), "Netaddr of family AF_INET produces a sockaddr_in6");
    }

    return exit_status();
}
