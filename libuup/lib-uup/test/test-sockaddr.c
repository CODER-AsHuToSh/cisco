#include <arpa/inet.h>
#include <tap.h>

#if __FreeBSD__
#include <sys/socket.h>
#endif

#include "sockaddrutil.h"

int
main(void)
{
    char      buf[INET6_ADDRSTRLEN];
    socklen_t socklen;
    size_t    len;
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } s;

    plan_tests(26);

    s.sa.sa_family = AF_INET + AF_INET6 + 1;
    ok(!sockaddr_to_buf(&s.sa, buf, sizeof(buf), NULL), "Printing an unrecognised address says it fails");

    s.sin.sin_family = AF_INET;
    inet_aton("1.2.3.4", &s.sin.sin_addr);
    s.sin.sin_port = htons(1234);

    is_eq(sockaddr_to_buf(&s.sa, buf, sizeof(buf), &len), "1.2.3.4", "sockaddr_to_buf() of an IPv4 address returns the right value");
    ok(len == 7, "sockaddr_to_buf() of an IPv4 address outputs the correct length");

    ok(!sockaddr_to_buf(&s.sa, buf, 6, &len), "sockaddr_to_buf() of an IPv4 address into a short buffer fails");

    s.sin6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::1:2:3:4", &s.sin6.sin6_addr);
    s.sin6.sin6_port = htons(1234);

    ok(sockaddr_to_buf(&s.sa, buf, sizeof(buf), NULL), "sockaddr_to_buf() of an IPv6 address says it works");
    is_eq(buf, "::1:2:3:4", "sockaddr_to_buf() of an IPv6 address shows the right value");
    ok(!sockaddr_to_buf(&s.sa, buf, 8, NULL), "sockaddr_to_buf() of an IPv6 address into a short buffer fails");

    socklen = sizeof(s);
    ok(sockaddr_sscan("1.2.3.4:1234", 5678, &s.sa, &socklen), "sockaddr_sscan() parses an IPv4 addr/port pair");
    is(s.sa.sa_family, AF_INET, "sockaddr_sscan() interpreted it as an IPv4 address");
    is_eq(inet_ntoa(s.sin.sin_addr), "1.2.3.4", "sockaddr_sscan() got the IPv4 address right");
    is(ntohs(s.sin.sin_port), 1234, "sockaddr_sscan() got the IPv4 port right");

    /*
    socklen = sizeof(s);
    ok(sockaddr_sscan("::1.2.3.4:1234", 5678, &s.sa, &socklen), "sockaddr_sscan() parses an IPv4 mapped IPv6 addr/port pair");
    is(s.sa.sa_family, AF_INET6, "sockaddr_sscan() interpreted it as an IPv6 address");
    is_eq(inet_ntop(AF_INET6, &s.sin6.sin6_addr, buf, sizeof(buf)), "::1.2.3.4", "sockaddr_sscan() got the mapped address right");
    is(ntohs(s.sin6.sin6_port), 1234, "sockaddr_sscan() got the IPv6 port right");
    */

    socklen = sizeof(s);
    ok(sockaddr_sscan("[2001:4700:e83b:9a00:2400:f4ff:feb1:1c85]:1234", 5678, &s.sa, &socklen), "sockaddr_sscan() parses an IPv6 addr/port pair");
    is(s.sa.sa_family, AF_INET6, "sockaddr_sscan() interpreted it as an IPv6 address");
    is_eq(inet_ntop(AF_INET6, &s.sin6.sin6_addr, buf, sizeof(buf)), "2001:4700:e83b:9a00:2400:f4ff:feb1:1c85", "sockaddr_sscan() got the IPv6 address right");
    is(ntohs(s.sin6.sin6_port), 1234, "sockaddr_sscan() got the IPv6 port right");

    socklen = sizeof(s);
    ok(sockaddr_sscan("2001:4700:e83b:9a00:2400:f4ff:feb1:1c85", 5678, &s.sa, &socklen), "sockaddr_sscan() parses an IPv6 addr");
    is(s.sa.sa_family, AF_INET6, "sockaddr_sscan() interpreted it as an IPv6 address");
    is_eq(inet_ntop(AF_INET6, &s.sin6.sin6_addr, buf, sizeof(buf)), "2001:4700:e83b:9a00:2400:f4ff:feb1:1c85", "sockaddr_sscan() got the IPv6 address right");
    is(ntohs(s.sin6.sin6_port), 5678, "sockaddr_sscan() defaulted the IPv6 port correctly");

    socklen = sizeof(s);
    ok(!sockaddr_sscan("[2001:4700:e83b:9a00:2400:f4ff:feb1:1c85]:0000000012345", 5678, &s.sa, &socklen), "sockaddr_sscan() checks the string length - but using INET6_ADDRSTRLEN is probably overkill");

    socklen = sizeof(s);
    ok(!sockaddr_sscan("[2001:4700:e83b:9a00:2400:f4ff:feb1:1c85]:xxx", 5678, &s.sa, &socklen), "sockaddr_sscan() fails when the port is invalid");

    socklen = sizeof(s);
    ok(!sockaddr_sscan("[2001:4700:e83b:9a00:2400:f4ff:feb1:1c85]:1234xx", 5678, &s.sa, &socklen), "sockaddr_sscan() fails because of trailing junk");

    socklen = sizeof(s);
    ok(!sockaddr_sscan("[2001:4700:e83b:9a00:2400:f4ff:feb1:1c85]:65536", 5678, &s.sa, &socklen), "sockaddr_sscan() fails when the ports out-of-range");

    socklen = sizeof(s.sin) - 1;
    ok(!sockaddr_sscan("1.2.3.4:1234", 5678, &s.sa, &socklen), "sockaddr_sscan() fails when the IPv4 addr is too small");

    socklen = sizeof(s.sin6) - 1;
    ok(!sockaddr_sscan("[2001:4700:e83b:9a00:2400:f4ff:feb1:1c85]:1234", 5678, &s.sa, &socklen), "sockaddr_sscan() fails when the IPv6 addr is too small");

    socklen = sizeof(s);
    ok(!sockaddr_sscan("no-addr:1234", 5678, &s.sa, &socklen), "sockaddr_sscan() fails when the addr is garbage");

    return exit_status();
}
