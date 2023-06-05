#ifndef RR_TYPE_H
#define RR_TYPE_H

#include <arpa/inet.h>

#if BYTE_ORDER == LITTLE_ENDIAN
#define __constant_htons(x)    ((uint16_t)(((uint16_t)(x)) << 8 | ((uint16_t)(x)) >> 8))
#define __constant_ntohs(x)    (ntohs(x))
#elif BYTE_ORDER == BIG_ENDIAN
#define __constant_htons(x)    (x)
#define __constant_ntohs(x)    (x)
#else
#error  "Update structure for unknown BYTE_ORDER"
#endif

/* The rr_type_t value lies between 0xFF00 and 0xFFFE as per RFC 6895 section 3.1 */

#define RR_TYPE_MAX_STR_SZ        sizeof("NSEC3PARAMS") // longest string in known_dns_types (struct dns_type)
#define CONST_HTONS(x)            __constant_htons(x)

enum rr_type {
    RR_TYPE_A                 = CONST_HTONS(1),        // a host address
    RR_TYPE_NS                = CONST_HTONS(2),        // an authoritative name server
    RR_TYPE_MD                = CONST_HTONS(3),        // a mail destination (Obsolete - use MX)
    RR_TYPE_MF                = CONST_HTONS(4),        // a mail forwarder (Obsolete - use MX)
    RR_TYPE_CNAME             = CONST_HTONS(5),        // the canonical name for an alias
    RR_TYPE_SOA               = CONST_HTONS(6),        // marks the start of a zone of authority
    RR_TYPE_MB                = CONST_HTONS(7),        // a mailbox domain name (EXPERIMENTAL)
    RR_TYPE_MG                = CONST_HTONS(8),        // a mail group member (EXPERIMENTAL)
    RR_TYPE_MR                = CONST_HTONS(9),        // a mail rename domain name (EXPERIMENTAL)
    RR_TYPE_NULL              = CONST_HTONS(10),       // a null RR (EXPERIMENTAL)
    RR_TYPE_WKS               = CONST_HTONS(11),       // a well known service description
    RR_TYPE_PTR               = CONST_HTONS(12),       // a domain name pointer
    RR_TYPE_HINFO             = CONST_HTONS(13),       // host information
    RR_TYPE_MINFO             = CONST_HTONS(14),       // mailbox or mail list information
    RR_TYPE_MX                = CONST_HTONS(15),       // mail exchange
    RR_TYPE_TXT               = CONST_HTONS(16),       // text strings
    RR_TYPE_RP                = CONST_HTONS(17),       // RFC 1183
    RR_TYPE_AFSDB             = CONST_HTONS(18),       // RFC 1183
    RR_TYPE_X25               = CONST_HTONS(19),       // RFC 1183
    RR_TYPE_ISDN              = CONST_HTONS(20),       // RFC 1183
    RR_TYPE_RT                = CONST_HTONS(21),       // RFC 1183
    RR_TYPE_NSAP              = CONST_HTONS(22),       // RFC 1706
    RR_TYPE_NSAP_PTR          = CONST_HTONS(23),       // RFC 1348
    RR_TYPE_SIG               = CONST_HTONS(24),       // 2535typecode
    RR_TYPE_KEY               = CONST_HTONS(25),       // 2535typecode
    RR_TYPE_PX                = CONST_HTONS(26),       // RFC 2163
    RR_TYPE_GPOS              = CONST_HTONS(27),       // RFC 1712
    RR_TYPE_AAAA              = CONST_HTONS(28),       // ipv6 address
    RR_TYPE_LOC               = CONST_HTONS(29),       // LOC record  RFC 1876
    RR_TYPE_NXT               = CONST_HTONS(30),       // 2535typecode
    RR_TYPE_EID               = CONST_HTONS(31),       // draft-ietf-nimrod-dns-01.txt
    RR_TYPE_NIMLOC            = CONST_HTONS(32),       // draft-ietf-nimrod-dns-01.txt
    RR_TYPE_SRV               = CONST_HTONS(33),       // SRV record RFC 2782
    RR_TYPE_ATMA              = CONST_HTONS(34),       // http://www.jhsoft.com/rfc/af-saa-0069.000.rtf
    RR_TYPE_NAPTR             = CONST_HTONS(35),       // RFC 2915
    RR_TYPE_KX                = CONST_HTONS(36),       // RFC 2230
    RR_TYPE_CERT              = CONST_HTONS(37),       // RFC 2538
    RR_TYPE_A6                = CONST_HTONS(38),       // RFC 2874
    RR_TYPE_DNAME             = CONST_HTONS(39),       // RFC 2672
    RR_TYPE_SINK              = CONST_HTONS(40),       // dnsind-kitchen-sink-02.txt
    RR_TYPE_OPT               = CONST_HTONS(41),       // Pseudo OPT record...
    RR_TYPE_APL               = CONST_HTONS(42),       // RFC 3123
    RR_TYPE_DS                = CONST_HTONS(43),       // draft-ietf-dnsext-delegation
    RR_TYPE_SSHFP             = CONST_HTONS(44),       // SSH Key Fingerprint
    RR_TYPE_IPSECKEY          = CONST_HTONS(45),       // draft-richardson-ipseckey-rr-11.txt
    RR_TYPE_RRSIG             = CONST_HTONS(46),       // RFC 4034
    RR_TYPE_NSEC              = CONST_HTONS(47),       // RFC 4034
    RR_TYPE_DNSKEY            = CONST_HTONS(48),       // RFC 4034
    RR_TYPE_DHCID             = CONST_HTONS(49),       // RFC 4701
    RR_TYPE_NSEC3             = CONST_HTONS(50),       // RFC 5155
    RR_TYPE_NSEC3PARAM        = CONST_HTONS(51),       // RFC 5155
    RR_TYPE_NSEC3PARAMS       = CONST_HTONS(51),       // RFC 5155
    RR_TYPE_TLSA              = CONST_HTONS(52),       // RFC 6698
    RR_TYPE_SMIMEA            = CONST_HTONS(53),       // RFC 8192

    RR_TYPE_HIP               = CONST_HTONS(55),       // RFC 8005
    RR_TYPE_RNINFO            = CONST_HTONS(56),
    RR_TYPE_RKEY              = CONST_HTONS(57),
    RR_TYPE_TALINK            = CONST_HTONS(58),       // draft-ietf-dnsop-trust-history
    RR_TYPE_CDS               = CONST_HTONS(59),       // RFC 7344
    RR_TYPE_CDNSKEY           = CONST_HTONS(60),       // RFC 7344
    RR_TYPE_OPENPGPKEY        = CONST_HTONS(61),       // RFC 7929
    RR_TYPE_CSYNC             = CONST_HTONS(62),       // RFC 7477
    RR_TYPE_ZONEMD            = CONST_HTONS(63),       // draft-wessels-dns-zone-digest
    RR_TYPE_SVCB              = CONST_HTONS(64),       // draft-ietf-dnsop-svcb-https-00
    RR_TYPE_HTTPS             = CONST_HTONS(65),       // draft-ietf-dnsop-svcb-https-00

    RR_TYPE_SPF               = CONST_HTONS(99),       // RFC 7208
    RR_TYPE_UINFO             = CONST_HTONS(100),      // IANA-Reserved
    RR_TYPE_UID               = CONST_HTONS(101),      // IANA-Reserved
    RR_TYPE_GID               = CONST_HTONS(102),      // IANA-Reserved
    RR_TYPE_UNSPEC            = CONST_HTONS(103),      // IANA-Reserved
    RR_TYPE_NID               = CONST_HTONS(104),      // RFC 6742
    RR_TYPE_L32               = CONST_HTONS(105),      // RFC 6742
    RR_TYPE_L64               = CONST_HTONS(106),      // RFC 6742
    RR_TYPE_LP                = CONST_HTONS(107),      // RFC 6742
    RR_TYPE_EUI48             = CONST_HTONS(108),      // RFC 7043
    RR_TYPE_EUI64             = CONST_HTONS(109),      // RFC 7043

    RR_TYPE_TKEY              = CONST_HTONS(249),      // RFC 2930
    RR_TYPE_TSIG              = CONST_HTONS(250),      // RFC-ietf-dnsop-rfc2845bis-09
    RR_TYPE_IXFR              = CONST_HTONS(251),      // RFC 1995
    RR_TYPE_AXFR              = CONST_HTONS(252),      // RFC 5936
    RR_TYPE_MAILB             = CONST_HTONS(253),      // A request for mailbox-related records (MB, MG or MR)
    RR_TYPE_MAILA             = CONST_HTONS(254),      // A request for mail agent RRs (Obsolete - see MX)
    RR_TYPE_ANY               = CONST_HTONS(255),      // any type (wildcard)
    RR_TYPE_URRL              = CONST_HTONS(256),      // RFC 7553
    RR_TYPE_CAA               = CONST_HTONS(257),      // RFC 8659
    RR_TYPE_AVC               = CONST_HTONS(258),
    RR_TYPE_DOA               = CONST_HTONS(259),      // draft-durand-doa-over-dns
    RR_TYPE_AMTRELAY          = CONST_HTONS(260),      // RFC 8777

    RR_TYPE_TA                = CONST_HTONS(32768),    // http://www.watson.org/~weiler/INI1999-19.pdf
    RR_TYPE_DLV               = CONST_HTONS(32769),    // RFC 4431, 5074, DNSSEC Lookaside Validation

#define RR_TYPE_INVALID       CONST_HTONS(65000)       // This may need to change if 65000 is declared.

    /* RFC 6895 section 3.1 */
    RR_TYPE_PRIVATE_LO        = CONST_HTONS(65280),    // 0xFF00
    RR_TYPE_PRIVATE_HI        = CONST_HTONS(65534),    // 0xFFFE

    RR_TYPE_EXPERIMENTAL_ADDR = CONST_HTONS(65535),    // Cloudflare's proposed ADDR (A+AAAA) query

    RR_TYPE_FIRST             = CONST_HTONS(0),
    RR_TYPE_LAST              = CONST_HTONS(65535),
} __attribute__ ((__packed__));    // Tell gcc to use the smallest type (a uint16_t)

#define RR_TYPE_COUNT   (RR_TYPE_LAST - RR_TYPE_FIRST + 1)    // Don't do this in the enum, or it won't fit in a uint16_t

typedef enum rr_type rr_type_t;

static inline bool
rr_type_security(rr_type_t type)
{
    switch (type) {
    case RR_TYPE_DNSKEY:
    case RR_TYPE_DS:
    case RR_TYPE_NSEC:
    case RR_TYPE_NSEC3:
    case RR_TYPE_RRSIG:
        return true;
    default:
        return false;
    }
}

#include "rr-type-proto.h"

#endif
