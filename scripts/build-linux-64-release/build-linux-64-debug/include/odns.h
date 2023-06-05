#ifndef ODNS_H
#define ODNS_H

/*-
 * The format for the ODNS_AD OPT data is as follows:
 *  - A 6B header composed of
 *    * 4B "magic", should always be 0x4F444E53 ("ODNS")
 *    * 1B version
 *      * ODNS_VERSION_1BYTE_FIELDTYPE - field specifiers are 1 byte
 *      * ODNS_VERSION_2BYTE_FIELDTYPE - field specifiers are 2 bytes
 *    * 1B flags
 *      * ODNS_FLAG_FALSIFIED        - Contains falsified information (QUERYLOG_FLAG_NO_STATS set by the resolver)
 *      * ODNS_FLAG_NO_CLIENTSUBNET  - Don't send clientsubnet at level 0
 *      * ODNS_FLAG_NO_STATS         - This query should not be logged for the stats systems
 *      * ODNS_FLAG_REVALIDATE       - Force DNSSEC re-validation
 *      * ODNS_FLAG_UNTRUSTED_QUERY  - Not a trusted client
 *      * ODNS_FLAG_MINIMIZATION_OFF - Turn qname minimization off
 *  - The remaining OPT data will be a a number of <type, value> pairs.  The type
 *    is a 1B bit flag which also indicates the length of the value:
 *      Type    Len   Contents
 *      ----   -----  --------
 *      0x0001   16B  Active Directory user ID
 *      0x0002   16B  Active Directory machine ID
 *      0x0004    4B  Forwarder virtual appliance ID
 *      0x0008    4B  Organization ID
 *      0x0010    4B  Remote IPv4
 *      0x0020   16B  Remote IPv6
 *      0x0040    8B  VPN client device ID
 *      0x0080    4B  "pretend" client IPv4
 *    Fields past here require version 1 (ODNS_VERSION_2BYTE_FIELDTYPE) for 2-byte type field
 *      0x0100   16B  "pretend" client IPv6
 *      0x0200   64B  Client Reporting ID
 *      0x0400    NA  Not currently used
 *      0x0800    4B  Origin ID
 *      0x1000    1B  Policy Type
 *      0x2000    2B+ Encapsulation data (variable length)
 *      0x4000 <=64B  Alternate user ID (variable length)
 *
 * This is defined at https://confluence.office.opendns.com/display/trac3/Protoss+EDNS0+Format
 */

#include <kit.h>

#include "netsock.h"

struct confset;

#define ODNS_MAGIC                   "ODNS"    /* ODNS_AD/ODNS_VPN EDNS message */
#define ODNS_VERSION_1BYTE_FIELDTYPE 0
#define ODNS_VERSION_2BYTE_FIELDTYPE 1

struct odns_hdr {
    uint8_t magic[4];
    uint8_t version;
    uint8_t flags;
} __attribute__ ((__packed__));

#define ODNS_FIELD_USER              (1 << 0)     /* 0x0001 */
#define ODNS_FIELD_HOST              (1 << 1)     /* 0x0002 */
#define ODNS_FIELD_VA                (1 << 2)     /* 0x0004 */
#define ODNS_FIELD_ORG               (1 << 3)     /* 0x0008 */
#define ODNS_FIELD_REMOTEIP4         (1 << 4)     /* 0x0010 */
#define ODNS_FIELD_REMOTEIP6         (1 << 5)     /* 0x0020 */
#define ODNS_FIELD_DEVICE            (1 << 6)     /* 0x0040 */
#define ODNS_FIELD_CLIENTIP4         (1 << 7)     /* 0x0080 */
#define ODNS_FIELD_CLIENTIP6         (1 << 8)     /* 0x0100 - requires version 1 (for two-byte types) */
#define ODNS_FIELD_CLIENTREPORTINGID (1 << 9)     /* 0x0200 - requires version 1 (for two-byte types) */
#define ODNS_FIELD_RESERVED          (1 << 10)    /* 0x0400 - RESERVED FOR connect-to-cloud */
#define ODNS_FIELD_ORIGIN            (1 << 11)    /* 0x0800 - requires version 1 (for two-byte types) */
#define ODNS_FIELD_POLICYTYPE        (1 << 12)    /* 0x1000 - requires version 1 (for two-byte types) */
#define ODNS_FIELD_ENCAP_PACKET      (1 << 13)    /* 0x2000 - requires version 1 (for two-byte types) */
#define ODNS_FIELD_ALT_UID           (1 << 14)    /* 0x4000 - requires version 1 (for two-byte types) */

#define ODNS_FIELD_REMOTEIP          (ODNS_FIELD_REMOTEIP4 | ODNS_FIELD_REMOTEIP6)
#define ODNS_FIELD_CLIENTIP          (ODNS_FIELD_CLIENTIP4 | ODNS_FIELD_CLIENTIP6)

#define ODNS_LEN_VA                      4
#define ODNS_LEN_ORG                     4
#define ODNS_LEN_USER                    KIT_GUID_SIZE
#define ODNS_LEN_HOST                    KIT_GUID_SIZE
#define ODNS_LEN_ALT_UID                 KIT_MD5_SIZE
#define ODNS_LEN_REMOTEIP4               sizeof(struct in_addr)
#define ODNS_LEN_REMOTEIP6               sizeof(struct in6_addr)
#define ODNS_LEN_DEVICE                  KIT_DEVICEID_SIZE
#define ODNS_LEN_CLIENTIP4               sizeof(struct in_addr)
#define ODNS_LEN_CLIENTIP6               sizeof(struct in6_addr)
#define ODNS_MINLEN_CLIENTREPORTINGID    3
#define ODNS_MAXLEN_CLIENTREPORTINGID    64
#define ODNS_CLIENTREPORTINGID_TYPE_IMSI 0   /* The only known client-reporting-id type so far */
#define ODNS_LEN_ORIGIN                  4
#define ODNS_LEN_POLICYTYPE              1

#define ODNS_FLAG_FALSIFIED           0x01   /* EDNS data was falsified and QUERYLOG_FLAG_NO_STATS should be set */
#define ODNS_FLAG_NO_CLIENTSUBNET     0x02   /* Don't send clientsubnet info */
#define ODNS_FLAG_NO_STATS            0x04   /* Client requested QUERYLOG_FLAG_NO_STATS be set */
#define ODNS_FLAG_REVALIDATE          0x08   /* Client requested QUERY_FLAG_REVALIDATE be set */
#define ODNS_FLAG_UNTRUSTED_QUERY     0x10   /* Forwarder is acting on behalf of an untrusted client */
#define ODNS_FLAG_MINIMIZATION_OFF    0x20   /* QName minimization should not be used on this query */
#define ODNS_FLAG_MASK                0x3f

#define ODNS_INTERNAL_FLAG_LOCAL       0x01   /* Client request came from a localip value */
#define ODNS_INTERNAL_FLAG_TIMEOUT     0x02   /* The resolver request timed out */
#define ODNS_INTERNAL_FLAG_GUEST       0x04   /* No user is associated with the client request */

#define ODNS_POLICYTYPE_DNS           0x00   /* Looking for a DNS policy */
#define ODNS_POLICYTYPE_SWG           0x01   /* Looking for an SWG policy */

#define ODNS_AF_ENCAP_SOURCEIP (AF_INET6 + AF_INET)   /* 'encapip SOURCEIP' AF family value stored */

/* Structure containing ODNS_AD or ODNS_VPN data, usually from a forwarder EDNS packet */
struct odns {
    uint32_t            org_id;
    uint32_t            va_id;                    /* va_id *IS* the VA's origin_id */
    struct kit_guid     host_id;
    struct kit_guid     user_id;

    uint8_t             alt_user_id_type;
    struct kit_md5      alt_user_id;

    struct kit_deviceid device_id;
    struct netaddr      remoteip;             /* Who asked the forwarder */
    struct netaddr      clientip;             /* The (faked) client.  Also used by ENCAP mode forwarder for passing Encapsulation IP */
    uint8_t            *clientreportingid;
    uint32_t            origin_id;
    uint16_t            fields;               /* Bits indicating which fields are set */
    uint8_t             flags;
    uint8_t             internal_flags;       /* Flag values never sent to the resolver */
    uint8_t             policytype;           /* DNS policy or SWG policy? */
};

#define ODNS_MAX_LEN             \
    (sizeof(struct odns_hdr) +   \
     1 + ODNS_LEN_USER +         \
     1 + ODNS_LEN_HOST +         \
     1 + ODNS_LEN_VA +           \
     1 + ODNS_LEN_ORG +          \
     1 + ODNS_LEN_REMOTEIP6)

#include "odns-proto.h"

#endif
