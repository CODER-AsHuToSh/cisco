#include <stdlib.h>
#include <tap.h>

#include "cidr-ipv4.h"
#include "conf.h"

int
main(void)
{
    struct cidr_ipv4 cidr;
    const char      *ret;
    unsigned         i;
    char             cidr_str[CIDR_IPV4_MAX_BUF_SIZE];

    plan_tests(45);
    conf_initialize(".", ".", false, NULL);

    diag("Valid (or nearly valid) IPv4 cidr scans");
    {
        struct {
            const char *scan;
            enum cidr_parse how;
            unsigned consume;
            const char *ascii;
        } valid[] = {
            { "127.0.0.1/32",             PARSE_CIDR_ONLY,  12, "127.0.0.1" },
            { "127.0.0.1/32:other data",  PARSE_CIDR_ONLY,  12, "127.0.0.1" },
            { "172.16.0.0/24:more data",  PARSE_IP_OR_CIDR, 13, "172.16.0.0/24" },
            { "172.16.0.0/24:more data",  PARSE_IP_ONLY,    10, "172.16.0.0" },
            { "172.16.2.2/25:extra data", PARSE_IP_OR_CIDR, 13, "172.16.2.0/25" },
        };

        for (i = 0; i < sizeof valid / sizeof *valid; i++) {
            ret = cidr_ipv4_sscan_verbose(&cidr, __FILE__, i, valid[i].scan, valid[i].how);
            is_eq(ret ? ret : "<NULL>", valid[i].scan + valid[i].consume, "cidr_ipv4_sscan() consumed %u bytes from '%s' as %s",
                  valid[i].consume, valid[i].scan, CIDR_PARSE_TXT(valid[i].how));
            ret = cidr_ipv4_to_str(&cidr, true);
            is_eq(ret, valid[i].ascii, "'%s' reads back as '%s'", valid[i].scan, valid[i].ascii);

            if (i == 0) {
                ok(!cidr_ipv4_to_buf(&cidr, true, cidr_str, sizeof("127.0.0.")),     "Failed due to truncation");
                is_eq(cidr_str, "127.0.0.",                                          "Buffer too short even without elided /32");
                ok(!cidr_ipv4_to_buf(&cidr, false, cidr_str, sizeof("127.0.0.1/3")), "Also failed due to truncation");
                is_eq(cidr_str, "127.0.0.1/3",                                       "Longer buffer still too short with /32");
            }
        }
    }

    diag("Invalid IPv4 cidr scans");
    {
        struct {
            const char *scan;
            enum cidr_parse how;
        } invalid[] = {
            { "192.168.0.1/33", PARSE_CIDR_ONLY },
            { "192.168.0/16", PARSE_CIDR_ONLY },
            { "192.168/16", PARSE_CIDR_ONLY },
            { "192/16", PARSE_CIDR_ONLY },
            { "192.168.0.256/10", PARSE_CIDR_ONLY },
            { "192.168.0.0", PARSE_CIDR_ONLY },
            { "192.168.0", PARSE_IP_ONLY },
            { "192.168", PARSE_IP_ONLY },
            { "192", PARSE_IP_ONLY },
        };

        for (i = 0; i < sizeof invalid / sizeof *invalid; i++)
            ok(!cidr_ipv4_sscan(&cidr, invalid[i].scan, invalid[i].how), "'%s' doesn't scan as %s", invalid[i].scan,
                                CIDR_PARSE_TXT(invalid[i].how));
    }

    diag("Test sorting");
    {
        const char *cidr_strs[] = {"192.168.255.0/24", "192.168.192.0/20",   "192.168.0.0/16",   "192.168.0.0/20",
                                   "192.168.0.0/28",   "192.168.255.192/28", "192.168.0.0/24"};
        const char *sort_exps[] = {"192.168.0.0/16",   "192.168.0.0/20",     "192.168.0.0/24",   "192.168.0.0/28",
                                   "192.168.192.0/20", "192.168.255.0/24",   "192.168.255.192/28"};
        struct cidr_ipv4 cidrs[sizeof(cidr_strs) / sizeof(cidr_strs[0])];
        int              collisions = 0;

        for (i = 0; i < sizeof(cidr_strs) / sizeof(cidr_strs[0]); i++)
            ok(cidr_ipv4_sscan(&cidrs[i], cidr_strs[i], PARSE_CIDR_ONLY), "Parsed CIDR '%s'", cidr_strs[i]);

        qsort_r(cidrs, sizeof(cidr_strs) / sizeof(cidr_strs[0]), sizeof(cidrs[0]), cidr_ipv4_sort_compar_r, &collisions);
        ok(collisions, "Collisions found while sorting");

        for (i = 0; i < sizeof(cidr_strs) / sizeof(cidr_strs[0]); i++) {
            ok(cidr_ipv4_to_buf(&cidrs[i], false, cidr_str, sizeof(cidr_str)), "Converted CIDR %u back to a string", i);
            is_eq(cidr_str, sort_exps[i], "Got the expected string");
        }
    }

    return exit_status();
}
