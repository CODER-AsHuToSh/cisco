#ifndef CIDRLIST_H
#define CIDRLIST_H

#include "cidr-parse.h"
#include "conf.h"

#define CIDR_MATCH_ALL ~0U

struct cidr_ipv4;
struct cidr_ipv6;
struct object_hash;
struct object_fingerprint;
struct xray;

#define LOADFLAGS_CIDRLIST_CIDR  0x01    /* Only CIDRs are allowed */
#define LOADFLAGS_CIDRLIST_IP    0x02    /* Only IPs are allowed */

struct cidrlist {
    struct conf conf;
    enum cidr_parse how;
    struct object_hash *oh;      /* This object is a member of this hash */

    struct {
        struct cidr_ipv4 *cidr;  /* Array of INADDR cidrs */
        unsigned alloc;          /* Allocated size of cidr array */
        unsigned count;          /* Number of addresses in cidr array */
    } in4;

    struct {
        struct cidr_ipv6 *cidr;  /* Array of INADDR6 cidrs */
        unsigned alloc;          /* Allocated size of cidr array */
        unsigned count;          /* Number of addresses in cidr array */
    } in6;

    uint8_t fingerprint[];       /* Only the object hash (oh) knows the length! */
};

extern module_conf_t CONF_DNAT_SERVERS;
extern module_conf_t CONF_IPALLOWLIST;
extern module_conf_t CONF_IPBLOCKLIST;
extern module_conf_t CONF_RATELIMIT_ALLOWLIST;
extern module_conf_t CONF_TRUSTED_NETWORKS;
extern module_conf_t CONF_LOCAL_ADDRESSES;
extern module_conf_t CONF_IPPROXY;

/* Structure for storing a randomized index list */
struct random_list_index {
    unsigned count;
    unsigned n;
    unsigned item[];
};

#include "cidrlist-proto.h"

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define CIDRLIST_ADD4    ((const char *)cidrlist_append + 0)
#   define CIDRLIST_ADD6    ((const char *)cidrlist_append + 1)
#   define CIDRLIST_APPEND4 ((const char *)cidrlist_append + 2)
#   define CIDRLIST_APPEND6 ((const char *)cidrlist_append + 3)
#endif

#endif
