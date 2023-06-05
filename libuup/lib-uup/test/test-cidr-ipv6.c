#include <tap.h>

#include "cidr-ipv6.h"
#include "conf.h"

int
main(void)
{
    struct cidr_ipv6 cidr;
    const char *ret;
    unsigned i;

    plan_tests(38);
    conf_initialize(".", ".", false, NULL);

    diag("Valid (or nearly valid) IPv6 cidr scans");
    {
        struct {
            const char *scan;
            enum cidr_parse how;
            unsigned consume;
            const char *ascii;
        } valid[] = {
            { "::1/128",                                            PARSE_CIDR_ONLY,  7,  "::1" },
            { "[::1]/128",                                          PARSE_CIDR_ONLY,  9,  "::1" },
            { "[::1]/128:other data",                               PARSE_CIDR_ONLY,  9,  "::1" },
            { "[2001:1938:27d::]/48:more data",                     PARSE_CIDR_ONLY,  20, "[2001:1938:27d::]/48" },
            { "::/10",                                              PARSE_CIDR_ONLY,  5,  "[::]/10" },
            { "::1/127",                                            PARSE_IP_OR_CIDR, 7,  "[::]/127" },
            { "2001:1938:27d:1:20d:61ff:fe45:2c3f/48:next field",   PARSE_IP_OR_CIDR, 37, "[2001:1938:27d::]/48" },
            { "[2001:1938:27d:0:240:f4ff:feb1:1c85]/48:more data",  PARSE_IP_OR_CIDR, 39, "[2001:1938:27d::]/48" },
            { "2001:1938:27d:0:240:f4ff:feb1:1c85/0:yada yada",     PARSE_IP_OR_CIDR, 36, "[::]/0" },
            { "[2001:1938:27d:0:240:f4ff:feb1:1c85]/0:yada yada",   PARSE_IP_ONLY,    36, "2001:1938:27d:0:240:f4ff:feb1:1c85" },
        };

        for (i = 0; i < sizeof valid / sizeof *valid; i++) {
            ret = cidr_ipv6_sscan_verbose(&cidr, __FILE__, i, valid[i].scan, valid[i].how);
            is_eq(ret ? ret : "<NULL>", valid[i].scan + valid[i].consume, "cidr_ipv6_sscan() consumed %u bytes from '%s' as %s", valid[i].consume, valid[i].scan, CIDR_PARSE_TXT(valid[i].how));
            ret = cidr_ipv6_to_str(&cidr, 1);
            is_eq(ret, valid[i].ascii, "'%s' reads back as '%s'", valid[i].scan, valid[i].ascii);
        }
    }

    diag("Invalid IPv6 cidr scans");
    {
        struct {
            const char *scan;
            enum cidr_parse how;
        } invalid[] = {
            { "::1/129", PARSE_CIDR_ONLY },
            { "::", PARSE_CIDR_ONLY },
            { ":::/0", PARSE_CIDR_ONLY },
            { "0:0/0", PARSE_CIDR_ONLY },
            { "1.2.3.4/32", PARSE_CIDR_ONLY },
            { "[::/0", PARSE_CIDR_ONLY },
            { "::]/0", PARSE_CIDR_ONLY },
            { "[::/0]", PARSE_CIDR_ONLY },
            { "::", PARSE_CIDR_ONLY },
            { "[::]", PARSE_CIDR_ONLY },
            { ":::", PARSE_IP_ONLY },
            { "0:0", PARSE_IP_ONLY },
            { "1.2.3.4", PARSE_IP_ONLY },
            { "[::", PARSE_IP_ONLY },
        };

        for (i = 0; i < sizeof invalid / sizeof *invalid; i++)
            ok(!cidr_ipv6_sscan(&cidr, invalid[i].scan, invalid[i].how), "'%s' doesn't scan as %s", invalid[i].scan, CIDR_PARSE_TXT(invalid[i].how));
    }

    diag("IPv6 CIDR contains");
    {
        struct cidr_ipv6 cidr2;
        struct netsock addr;

        ok(cidr_ipv6_sscan(&cidr, "2001:470:e83b::/48", PARSE_CIDR_ONLY), "2001:470:e83b::/48 scans as a network");
        ok(cidr_ipv6_sscan(&cidr2, "2001:470:e83b:9a::/64", PARSE_CIDR_ONLY), "2001:470:e83b:9a::/64 scans as a network");
        ok(cidr_ipv6_contains_net(&cidr, &cidr2), "2001:470:e83b::/48 contains 2001:470:e83b:9a::/64");
        netaddr_from_str(&addr.a, "2001:470:e83b:9a:240:f4ff:feb1:1c85", AF_INET6);
        ok(cidr_ipv6_contains_addr(&cidr, &addr.a.in6_addr), "2001:470:e83b::/48 contains 2001:470:e83b:9a:240:f4ff:feb1:1c85");
    }

    return exit_status();
}
