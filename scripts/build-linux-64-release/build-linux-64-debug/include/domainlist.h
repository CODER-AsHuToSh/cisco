#ifndef DOMAINLIST_H
#define DOMAINLIST_H

#include "conf.h"

struct object_fingerprint;
struct xray;

#define LOADFLAGS_DL_LINEFEED_REQUIRED  0x01    /* Input must be linefeed delimited (input from file) */
#define LOADFLAGS_DL_IGNORE_JUNK        0x02    /* Ignore domains with non-host ([a-zA-Z0-9._-]) characters - don't fail to load */
#define LOADFLAGS_DL_ALLOW_EMPTY        0x04    /* Allow empty domainlists */
#define LOADFLAGS_DL_TRIM_URLS          0x08    /* Trim characters from '/' onwards */
#define LOADFLAGS_DL_EXACT              0x10    /* Exact matches only */

enum domainlist_match {
    DOMAINLIST_MATCH_EXACT,
    DOMAINLIST_MATCH_SUBDOMAIN,
};

extern module_conf_t CONF_ADDR_NS;               // Probe for support of the Cloudflare ADDR query if your NS's domain matches
extern module_conf_t CONF_DNAT_NS;
extern module_conf_t CONF_DNS_TUNNELING_EXCLUSION;
extern module_conf_t CONF_DNSCRYPT_BLOCKLIST;
extern module_conf_t CONF_DOMAIN_ALLOWLIST;
extern module_conf_t CONF_DOMAIN_DROPLIST;
extern module_conf_t CONF_DOMAIN_FREEZELIST;
extern module_conf_t CONF_DO_NOT_PROXY;          // Don't proxy these high volume sites
extern module_conf_t CONF_REPORT_EXCLUSIONS;
extern module_conf_t CONF_SSL_DOMAIN_ALLOWLIST;  // Don't proxy these http newly-seen-domains - they're known to use SSL
extern module_conf_t CONF_TYPO_EXCEPTIONS;
extern module_conf_t CONF_MINIMIZATION_EXCEPTIONS;
extern module_conf_t CONF_URL_PROXY;
extern module_conf_t CONF_URL_PROXY_HTTPS;

#include "domainlist-proto.h"

#endif
