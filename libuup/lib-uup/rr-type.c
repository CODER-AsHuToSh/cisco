#include <errno.h>
#include <kit.h>
#include <stdio.h>
#include <string.h>

#if __linux__
#include <bsd/string.h>
#endif

#include "rr-type.h"

struct dns_type {
    rr_type_t type;
    const char *txt; // RR_TYPE_MAX_STR_SZ
} known_dns_types[] = {
    { RR_TYPE_A,                 "A" },
    { RR_TYPE_NS,                "NS" },
    { RR_TYPE_MD,                "MD" },
    { RR_TYPE_MF,                "MF" },
    { RR_TYPE_CNAME,             "CNAME" },
    { RR_TYPE_SOA,               "SOA" },
    { RR_TYPE_MB,                "MB" },
    { RR_TYPE_MG,                "MG" },
    { RR_TYPE_MR,                "MR" },
    { RR_TYPE_NULL,              "NULL" },
    { RR_TYPE_WKS,               "WKS" },
    { RR_TYPE_PTR,               "PTR" },
    { RR_TYPE_HINFO,             "HINFO" },
    { RR_TYPE_MINFO,             "MINFO" },
    { RR_TYPE_MX,                "MX" },
    { RR_TYPE_TXT,               "TXT" },
    { RR_TYPE_RP,                "RP" },
    { RR_TYPE_AFSDB,             "AFSDB" },
    { RR_TYPE_X25,               "X25" },
    { RR_TYPE_ISDN,              "ISDN" },
    { RR_TYPE_RT,                "RT" },
    { RR_TYPE_NSAP,              "NSAP" },
    { RR_TYPE_NSAP_PTR,          "NSAP_PTR" },
    { RR_TYPE_SIG,               "SIG" },
    { RR_TYPE_KEY,               "KEY" },
    { RR_TYPE_PX,                "PX" },
    { RR_TYPE_GPOS,              "GPOS" },
    { RR_TYPE_AAAA,              "AAAA" },
    { RR_TYPE_LOC,               "LOC" },
    { RR_TYPE_NXT,               "NXT" },
    { RR_TYPE_EID,               "EID" },
    { RR_TYPE_NIMLOC,            "NIMLOC" },
    { RR_TYPE_SRV,               "SRV" },
    { RR_TYPE_ATMA,              "ATMA" },
    { RR_TYPE_NAPTR,             "NAPTR" },
    { RR_TYPE_KX,                "KX" },
    { RR_TYPE_CERT,              "CERT" },
    { RR_TYPE_A6,                "A6" },
    { RR_TYPE_DNAME,             "DNAME" },
    { RR_TYPE_SINK,              "SINK" },
    { RR_TYPE_OPT,               "OPT" },
    { RR_TYPE_APL,               "APL" },
    { RR_TYPE_DS,                "DS" },
    { RR_TYPE_SSHFP,             "SSHFP" },
    { RR_TYPE_IPSECKEY,          "IPSECKEY" },
    { RR_TYPE_RRSIG,             "RRSIG" },
    { RR_TYPE_NSEC,              "NSEC" },
    { RR_TYPE_DNSKEY,            "DNSKEY" },
    { RR_TYPE_DHCID,             "DHCID" },
    { RR_TYPE_NSEC3,             "NSEC3" },
    { RR_TYPE_NSEC3PARAM,        "NSEC3PARAM" },
    { RR_TYPE_NSEC3PARAMS,       "NSEC3PARAMS" },
    { RR_TYPE_TLSA,              "TLSA" },
    { RR_TYPE_SMIMEA,            "SMIMEA" },
    { RR_TYPE_HIP,               "HIP" },
    { RR_TYPE_RNINFO,            "RNINFO" },
    { RR_TYPE_RKEY,              "RKEY" },
    { RR_TYPE_TALINK,            "TALINK" },
    { RR_TYPE_CDS,               "CDS" },
    { RR_TYPE_CDNSKEY,           "CDNSKEY" },
    { RR_TYPE_OPENPGPKEY,        "OPENPGPKEY" },
    { RR_TYPE_CSYNC,             "CSYNC" },
    { RR_TYPE_ZONEMD,            "ZONEMD" },
    { RR_TYPE_SVCB,              "SVCB" },
    { RR_TYPE_HTTPS,             "HTTPS" },
    { RR_TYPE_SPF,               "SPF" },
    { RR_TYPE_UINFO,             "UINFO" },
    { RR_TYPE_UID,               "UID" },
    { RR_TYPE_GID,               "GID" },
    { RR_TYPE_UNSPEC,            "UNSPEC" },
    { RR_TYPE_NID,               "NID" },
    { RR_TYPE_L32,               "L32" },
    { RR_TYPE_L64,               "L64" },
    { RR_TYPE_LP,                "LP" },
    { RR_TYPE_EUI48,             "EUI48" },
    { RR_TYPE_EUI64,             "EUI64" },
    { RR_TYPE_TKEY,              "TKEY" },
    { RR_TYPE_TSIG,              "TSIG" },
    { RR_TYPE_IXFR,              "IXFR" },
    { RR_TYPE_AXFR,              "AXFR" },
    { RR_TYPE_MAILB,             "MAILB" },
    { RR_TYPE_MAILA,             "MAILA" },
    { RR_TYPE_ANY,               "ANY" },
    { RR_TYPE_URRL,              "URRL" },
    { RR_TYPE_CAA,               "CAA" },
    { RR_TYPE_AVC,               "AVC" },
    { RR_TYPE_DOA,               "DOA" },
    { RR_TYPE_AMTRELAY,          "AMTRELAY" },
    { RR_TYPE_TA,                "TA" },
    { RR_TYPE_DLV,               "DLV" },
    { RR_TYPE_EXPERIMENTAL_ADDR, "ADDR" }
};

const char *
rr_type_to_str(rr_type_t type)
{
    static __thread char unknown[RR_TYPE_MAX_STR_SZ];
    unsigned i;

    for (i = 0; i < sizeof(known_dns_types) / sizeof(*known_dns_types); i++)
        if (type == known_dns_types[i].type)
            return known_dns_types[i].txt;

    snprintf(unknown, sizeof(unknown), "TYPE%u", (unsigned)ntohs(type));    /* RFC 3597 */
    return unknown;
}

char *
rr_type_to_buf(rr_type_t type, char *buf, size_t bufsz)
{
    strlcpy(buf, rr_type_to_str(type), bufsz);
    return buf;
}

rr_type_t
rr_type_from_str(const char *txt)
{
    unsigned long i;

    if (strncasecmp(txt, "type", 4) == 0) {   /* RFC 3597 */
        i = kit_strtoul(txt + 4, NULL, 10);
        if (errno != 0)
            return RR_TYPE_INVALID;
        return htons(i);
    }

    for (i = 0; i < sizeof(known_dns_types) / sizeof(*known_dns_types); i++)
        if (strcasecmp(txt, known_dns_types[i].txt) == 0)
            return known_dns_types[i].type;

    return RR_TYPE_INVALID;
}
