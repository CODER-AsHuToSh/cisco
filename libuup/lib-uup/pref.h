#ifndef PREF_H
#define PREF_H

#include <kit.h>
#include <stdio.h>

#include "conf.h"
#include "domainlist.h"
#include "pref-categories.h"

struct categorization;
struct cidrlist;
struct uint32list;
struct urllist;

#define PREF_DEFAULT_GLOBALORG 1

/* The comments below indicate the corresponding column or (in the */
/* case of domain lists) table in the accounts database. */

/* Bundle flags. See https://confluence.office.opendns.com/display/trac3/configuration-prefs-flags
 * Note that these must fit in a pref_bundleflags_t. If you add a flag here, add it to the string table in pref.c
 */
#define PREF_BUNDLEFLAGS_CLOSED_NETWORK         (1 << 0)      /*       0x01 network.status */
/*      <UNUSED>                                (1 << 1)       *       0x02 NOT USED CURRENTLY */
/*      <UNUSED>                                (1 << 2)       *       0x04 NOT USED CURRENTLY */
#define PREF_BUNDLEFLAGS_SUSPICIOUS_RESPONSE    (1 << 3)      /*       0x08 policy.response_filtering */
#define PREF_BUNDLEFLAGS_TYPO_CORRECTION        (1 << 4)      /*       0x10 policy.type_correction */
/*      <UNUSED>                                (1 << 5)       *       0x20 NOT USED CURRENTLY */
#define PREF_BUNDLEFLAGS_EXPIRED_RRS            (1 << 6)      /*       0x40 policy.smartcache */
/*      <UNUSED>                                (1 << 7)       *       0x80 NOT USED CURRENTLY */
/*      <UNUSED>                                (1 << 8)       *     0x0100 NOT USED CURRENTLY */
/*      <UNUSED>                                (1 << 9)       *     0x0200 NOT USED CURRENTLY */
/*      <UNUSED>                                (1 << 10)      *     0x0400 NOT USED CURRENTLY */
#define PREF_BUNDLEFLAGS_ALLOWLIST_ONLY         (1 << 11)     /*     0x0800 timepolicy.whitelist_only */
#define PREF_BUNDLEFLAGS_BPB                    (1 << 12)     /*     0x1000 policy.block_page_bypass */
#define PREF_BUNDLEFLAGS_URL_PROXY_HTTPS        (1 << 13)     /*     0x2000 policy.url_proxy_https */
#define PREF_BUNDLEFLAGS_URL_PROXY              (1 << 14)     /*     0x4000 policy.url_proxy */
#define PREF_BUNDLEFLAGS_NO_STATS               (1 << 15)     /*     0x8000 bundle.reporting == "disabled" */
#define PREF_BUNDLEFLAGS_SECURITY_STATS_ONLY    (1 << 16)     /*   0x010000 bundle.reporting == "security" */
#define PREF_BUNDLEFLAGS_RATE_NON_CUSTOMER      (1 << 17)     /*   0x020000 Set rate limit for non-customers (trial accounts) */
#define PREF_BUNDLEFLAGS_RATE_RESTRICTED        (1 << 18)     /*   0x040000 Manually restricted rate limit */
#define PREF_BUNDLEFLAGS_SIG_FILE_INSPECTION    (1 << 19)     /*   0x080000 SIG micro-service file inspection */
#define PREF_BUNDLEFLAGS_SIG_AMP_INSPECTION     (1 << 20)     /*   0x100000 SIG micro-service AMP inspection */
#define PREF_BUNDLEFLAGS_SIG_TG_SANDBOX         (1 << 21)     /*   0x200000 SIG micro-service threat grid (TG) sandbox */
#define PREF_BUNDLEFLAGS_SAFE_SEARCH            (1 << 22)     /*   0x400000 Turn on forced safe search for this org */
#define PREF_BUNDLEFLAGS_SAML                   (1 << 23)     /*   0x800000 The policy supports SAML identities */
#define PREF_BUNDLEFLAGS_SWG_DISPLAY_BLOCK_PAGE (1 << 24)     /* 0x01000000 Display block page for SWG policy */

/* Org flags. See https://confluence.office.opendns.com/display/trac3/configuration-prefs-flags
 * Note that these must fit in a pref_orgflags_t. If you add a flag here, add it to the string table in pref.c
 */
/*      <UNUSED>                                               (1ULL << 0)     * 0x0001 NOT USED CURRENTLY */
#define PREF_ORGFLAGS_PROXY_NEWLY_SEEN_DOMAINS                 (1ULL << 1)    /* 0x0002 Redirect newly seen domains to SIG proxy */
#define PREF_ORGFLAGS_INCLUDE_TALOS_CATEGORIES                 (1ULL << 2)    /* 0x0004 Used in the categorization file to limit talos-domains lookups */
/*      <UNUSED>                                               (1ULL << 3)     * 0x0008 NOT USED CURRENTLY */
#define PREF_ORGFLAGS_GDPR_EU                                  (1ULL << 4)    /* 0x0010 - mapped to QUERYLOG_FLAG_GDPR_EU using options:gdprmask */
#define PREF_ORGFLAGS_GDPR_US                                  (1ULL << 5)    /* 0x0020 - mapped to QUERYLOG_FLAG_GDPR_US using options:gdprmask */
#define PREF_ORGFLAGS_SWG_ENABLED                              (1ULL << 6)    /* 0x0040 - Enable Secure Web Gateway (using a PAC file) */
#define PREF_ORGFLAGS_REALTIME_DNS_TUNNEL_BLOCKING             (1ULL << 7)    /* 0x0080 - Enable Realtime DNS Tunneling detection */
#define PREF_ORGFLAGS_O365_BYPASS                              (1ULL << 8)    /* 0x0100 - Prevent SSL decryption at the proxy */
#define PREF_ORGFLAGS_BYPASS_SWG_FROM_TUNNEL                   (1ULL << 9)    /* 0x0200 - Bypass SWG from tunnel (whatever that means) */
#define PREF_ORGFLAGS_DNSSEC_ENFORCE_ENABLED                   (1ULL << 10)   /* 0x0400 - Enforce DNSSEC validation results */
#define PREF_ORGFLAGS_ALL_DOMAINTAGGING                        (1ULL << 25)   /* 0x0200000 - All domaintagging */
#define PREF_ORGFLAGS_HALF_DOMAINTAGGING                       (1ULL << 26)   /* 0x0400000 - Half domaintagging */
#define PREF_ORGFLAGS_RESEARCH_ALGORITHMS_CATEGORIZE           (1ULL << 32)   /* 0x100000000 - Enable research algorithms categorization */
#define PREF_ORGFLAGS_RESEARCH_ALGORITHMS_BLOCKING             (1ULL << 33)   /* 0x200000000 - Enable research algorithms block categorization */
#define PREF_ORGFLAGS_AGGREGATE_REPORTING_ONLY                 (1ULL << 39)   /* 0x8000000000 - This org's traffic should be aggregated */
#define PREF_ORGFLAGS_MAX                                      UINT64_MAX

#define NO_ORG_ITEM ((unsigned)-1)                         /* No org -- aka org0 */

/* Many of these CATEGORY_BIT_* defines are used by libopendns-prefs */
#define CATEGORY_BIT_DRIVEBY_DOWNLOADS   60
#define CATEGORY_BIT_DYNAMIC_DNS         61
#define CATEGORY_BIT_MOBILE_THREATS      62
#define CATEGORY_BIT_HIGH_RISK_SITES     63
#define CATEGORY_BIT_BOTNET              64
#define CATEGORY_BIT_BOTNET2             65
#define CATEGORY_BIT_MALWARE             66
#define CATEGORY_BIT_MALWARE2            67
#define CATEGORY_BIT_PHISH               68
#define CATEGORY_BIT_SUSPICIOUS          69
#define CATEGORY_BIT_BLOCKLIST           71
#define CATEGORY_BIT_ALLOWLIST           72
#define CATEGORY_BIT_GLOBAL_ALLOWLIST    73
#define CATEGORY_BIT_SINKHOLE            74
#define CATEGORY_BIT_ATTACK              75
#define CATEGORY_BIT_IWF                 85
#define CATEGORY_BIT_NEWLY_SEEN_DOMAINS 108
#define CATEGORY_BIT_DNS_TUNNELING      110
#define CATEGORY_BIT_APPLICATION        148
#define CATEGORY_BIT_CTIRU              149    /* Terrorism */
#define CATEGORY_BIT_BLOCKAPP           151
#define CATEGORY_BIT_ALLOWAPP           152
#define CATEGORY_BIT_NODECRYPT          155
#define CATEGORY_BIT_WARNLIST           158 /* Bit reserved for SWG_warn feature if needed by libopendns-prefs */
#define CATEGORY_BIT_WARNAPP            159 /* Bit reserved for SWG_warn feature if needed by libopendns-prefs */

#define PREF_NOLIST                    ((unsigned)-1)
#define PREF_NOLISTID                  ((uint32_t)-1)
#define PREF_NOT_FOUND                 ((unsigned)-1)

#define LTYPE2ACTYPE(ltype)            ((ltype) & 0x03)
#define LTYPE2NUM(ltype)               (((ltype) & ~AT_POLICY) >> 2)
#define LTYPEVALID(ltype)              ((ltype) <= (MAXLTYPE | AT_POLICY))
#define ACTYPEVALID(actype)            ((actype) <= MAXACTYPE)
#define NUM2LTYPE(i)                   ((i) << 2)

/* The account type */
#define AT_BUNDLE         0x00          /* [bundles] use mysql bundle IDs, [lists] use mysql domainlist IDs */
#define AT_ORIGIN         0x01          /* [bundles] use mysql origin IDs, [lists] use mysql origin IDs */
#define AT_POLICY         0x02          /* [bundles] use mysql policy IDs, [lists] use mysql policy IDs */
#define MAXACTYPE         AT_POLICY

/* The Account Type (AT) list action, OR'd with the account type as the [lists] id */
#define AT_LIST_DESTBLOCK        0x00    /* (0 << 2) */
#define AT_LIST_EXCEPT           0x04    /* (1 << 2) */
#define AT_LIST_DESTALLOW        0x08    /* (2 << 2) */
#define AT_LIST_URL_PROXY_HTTPS  0x0c    /* (3 << 2) */
#define AT_LIST_DESTNODECRYPT    0x10    /* (4 << 2) */
#define AT_LIST_APPBLOCK         0x14    /* (5 << 2) */
#define AT_LIST_APPALLOW         0x18    /* (6 << 2) */
#define AT_LIST_APPNODECRYPT     0x1c    /* (7 << 2) */
#define AT_LIST_DESTWARN         0x20    /* (8 << 2) */
#define AT_LIST_APPWARN          0x24    /* (9 << 2) */
#define AT_LIST_MASK             0xFC
#define MAXLTYPE                 AT_LIST_APPWARN

#define AT_LIST_USED             0x80    /* Indicates that this list is referenced by one or more bundles */
#define AT_LIST_NONE                0    /* Used for lists objects, which have no ltype values            */

/* List element types. Names must be in alphabetical order because Brain orders lists this way. */

#define PREF_LIST_ELEMENTTYPE_NAMES        { "application", "cidr", "domain", "url" }
#define PREF_LIST_ELEMENTTYPE_NAME_MAXSIZE sizeof("application")

enum pref_list_elementtype {
    PREF_LIST_ELEMENTTYPE_APPLICATION,
    PREF_LIST_ELEMENTTYPE_CIDR,
    PREF_LIST_ELEMENTTYPE_DOMAIN,
    PREF_LIST_ELEMENTTYPE_URL,
} __attribute__((__packed__));

#define PREF_LIST_ELEMENTTYPE_COUNT   (PREF_LIST_ELEMENTTYPE_URL + 1)
#define PREF_LIST_ELEMENTTYPE_INVALID PREF_LIST_ELEMENTTYPE_COUNT
#define PREF_LIST_ELEMENTTYPE_BIT(et) (1 << (et))

#define LIST_POINTER_NULL        ((list_pointer_t){NULL})
#define LIST_POINTER_IS_NULL(lp) (lp.domainlist == NULL)

#define SETTINGGROUP_IDX_COUNT 5

typedef uint8_t actype_t;
typedef uint8_t ltype_t;
typedef uint8_t settinggroup_idx_t;
typedef enum pref_list_elementtype elementtype_t;

struct preflistrefblock {
    unsigned *block;
    unsigned count;
    unsigned alloc;
};

typedef union {
    struct domainlist *domainlist;
    struct urllist *urllist;
    struct cidrlist *cidrlist;
    struct uint32list *applicationlist;
} list_pointer_t;

struct preflist {
    ltype_t        ltype;              /* While in prefbuilder, may be OR'ed with AT_LIST_USED */
    uint32_t       id;
    elementtype_t  elementtype;        /* This replaces the name field, which was an offset into a list of names */
    list_pointer_t lp;
    uint8_t        bit;
} __attribute__((__packed__));

#define PREFLIST_LTYPE(list) ((list)->ltype & ~AT_LIST_USED)

typedef uint32_t pref_bundleflags_t;

struct prefsettinggroup {
    settinggroup_idx_t idx;
    uint32_t           id;                         /* original settinggroup_* id */
    pref_bundleflags_t bundleflags;                /* These flags (including parent and global) are added to the bundle flags */
    pref_categories_t  blocked_categories;
    pref_categories_t  nodecrypt_categories;
    pref_categories_t  warn_categories;
} __attribute__((__packed__));

struct prefbundle {
    actype_t actype;                               /* While in prefbuilder, may be OR'ed with BUNDLE_EXT_REFS */
    uint32_t id;                                   /* original bundleid/policyid/originid from brain */
    uint32_t priority;
    pref_bundleflags_t bundleflags;                /* PREF_BUNDLEFLAGS_* */
    pref_categories_t base_blocked_categories;
    pref_categories_t base_nodecrypt_categories;
    pref_categories_t base_warn_categories;
    uint32_t sgids[SETTINGGROUP_IDX_COUNT];        /* Unresolved settinggroup references */

    unsigned dest_block;                           /* resource.listref index - for destination lists (domains, cidrs, urls) */
    unsigned exceptions;                           /* resource.listref index */
    unsigned dest_allow;                           /* resource.listref index - for destination lists (domains, cidrs, urls) */
    unsigned url_proxy_https;                      /* resource.listref index */
    unsigned dest_nodecrypt;                       /* resource.listref index - for destination lists (domains, cidrs, urls) */
    unsigned dest_warn;                            /* resource.listref index - for destination lists (domains, cidrs, urls) */
    unsigned app_block;                            /* resource.listref index - for application lists */
    unsigned app_allow;                            /* resource.listref index - for application lists */
    unsigned app_nodecrypt;                        /* resource.listref index - for application lists */
    unsigned app_warn;                             /* resource.listref index - for application lists */

    unsigned ext_dest_block;                       /* resource.extlistref index */
    unsigned ext_dest_allow;                       /* resource.extlistref index */
    unsigned ext_url_proxy_https;                  /* resource.extlistref index */
    unsigned ext_dest_nodecrypt;                   /* resource.extlistref index */
    unsigned ext_dest_warn;                        /* resource.extlistref index */
    unsigned ext_app_block;                        /* resource.extlistref index */
    unsigned ext_app_allow;                        /* resource.extlistref index */
    unsigned ext_app_nodecrypt;                    /* resource.extlistref index */
    unsigned ext_app_warn;                         /* resource.extlistref index */
} __attribute__((__packed__));

typedef uint64_t pref_orgflags_t;
#define PREF_ORG_MAX_BITS (sizeof(pref_orgflags_t) * 8)

struct preforg {
    uint32_t id;
    pref_orgflags_t   orgflags;       /* PREF_ORGFLAGS_* */
    pref_categories_t unmasked;       /* Unmasked (masked by ccb) categories */
    uint32_t retention;               /* stats retention period */
    uint32_t warnperiod;              /* "warn" page access period */
    uint32_t originid;                /* this org's originid */
    uint32_t parentid;                /* "owning" orgid - we may find lists, categories and/or security data there */
} __attribute__((__packed__));

struct prefidentity {
    uint32_t originid;
    uint32_t origintypeid;            /* A reference to the accounts.origin_type table */
    unsigned org;                     /* resource.org index */
    actype_t actype;
    unsigned bundle;                  /* resource.bundle index */
} __attribute__((__packed__));

struct prefblock {
    struct {
        struct preflist *list;                  /* elements index into resource.names */
        unsigned *listref;                      /* elements index into resource.list */
        uint32_t *extlistref;
        struct prefsettinggroup *settinggroup;
        struct prefbundle *bundle;              /* elements index into resource.listref */
        struct preforg *org;
    } resource;
    struct {
        unsigned lists;                         /* Number of resource.list entries */
        unsigned settinggroups;                 /* Number of resource.settinggroup entries */
        unsigned bundles;                       /* Number of resource.bundle entries */
        unsigned orgs;                          /* Number of resource.org entries */
        unsigned identities;                    /* Number of identity entries */
    } count;
    struct prefidentity *identity;              /* Elements index into resource.org and resource.bundle */
};

enum pref_index_type {
    PREF_INDEX_NONE = 0,
    PREF_INDEX_IDENTITY,
    PREF_INDEX_BUNDLE,
};

enum pref_cook_level {
    PREF_COOK_RAW,        /* cooked_* are unusable */
    PREF_COOK_SIMMER,     /* cooked_* are populated but with prefs only (libopendns-prefs users) */
    PREF_COOK_BOIL,       /* cooked_* are populated with prefs, listener and geoip data (resolver) */
};

typedef struct {
    enum pref_index_type type;            /* What 'index' indexes */
    const struct prefblock *blk;          /* Where to find the org item */
    const struct prefblock *parentblk;    /* Where to find parent (org->parentid) data */
    const struct prefblock *globalblk;    /* Where to find global (options::global_parent_org) data */
    unsigned index;                       /* Offset of an ident or bundle */

    /* These fields are cached - so that we don't have to keep indexing the same thing again and again */
    const struct preforg *org;
    const struct preforg *parentorg;
    const struct preforg *globalorg;

    /* These fields are cached to avoid re-computing them and to include listener & geoip pref-overloads */
    enum pref_cook_level cooked;
    pref_orgflags_t cooked_orgflags;
    pref_bundleflags_t cooked_bundleflags;
    pref_categories_t cooked_categories;
    pref_categories_t cooked_nodecrypt_categories;
    pref_categories_t cooked_warn_categories;
} pref_t;

#define PREF_VALID(p)                   ((p)->type != PREF_INDEX_NONE)
#define PREF_IDENT(p)                   ((p)->type == PREF_INDEX_IDENTITY ? (p)->blk->identity + (p)->index : NULL)
#define PREF_BUNDLE(p)                  ((p)->type == PREF_INDEX_BUNDLE ? (p)->blk->resource.bundle + (p)->index : \
                                         (p)->type == PREF_INDEX_IDENTITY ? (p)->blk->resource.bundle + PREF_IDENT(p)->bundle : \
                                         NULL)
#define PREF_ORG(p)                     (PREF_VALID(p) ? (p)->org : NULL)
#define PREF_PARENTORG(p)               (PREF_ORG(p) && PREF_ORG(p)->parentid ? (p)->parentorg : NULL)
#define PREF_GLOBALORG(p)               (PREF_VALID(p) ? (p)->globalorg : NULL)
#define PREF_EXTDESTLISTREFID(p, ltype) (PREF_VALID(p) ? *(&PREF_BUNDLE(p)->ext_dest_block + LTYPE2NUM(ltype) - ((ltype) > AT_LIST_EXCEPT ? 1 : 0)) : PREF_NOLIST)
#define PREF_EXTDESTLISTID(p, ltype, n) (PREF_EXTDESTLISTREFID(p, ltype) == PREF_NOLIST ? PREF_NOLISTID : (uint32_t)(p)->blk->resource.extlistref[PREF_EXTDESTLISTREFID(p, ltype) + (n)])
#define PREF_DESTLISTREFID(p, ltype)    (PREF_VALID(p) ? *(&PREF_BUNDLE(p)->dest_block + LTYPE2NUM(ltype)) : PREF_NOLIST)
#define PREF_DESTLISTID(p, ltype, n)    (PREF_DESTLISTREFID(p, ltype) == PREF_NOLIST ? PREF_NOLIST : (p)->blk->resource.listref[PREF_DESTLISTREFID(p, ltype) + (n)])
#define PREF_DESTLIST(p, ltype, n)      (PREF_DESTLISTID(p, ltype, n) == PREF_NOLIST ? NULL : (p)->blk->resource.list + PREF_DESTLISTID(p, ltype, n))
#define PREF_DESTLIST_NAME(p, ltype, n) (PREF_DESTLIST(p, ltype, n) ? pref_list_elementtype_to_name(PREF_DESTLIST(p, ltype, n)->elementtype) : NULL)
#define PREF_IS_ORIGIN_ZERO(p)          (!(PREF_ORG(p) && PREF_ORG(p)->id))

// For prefbuilder
extern const struct kit_sortedelement_class preflist_element;
extern const struct kit_sortedelement_class prefsettinggroup_element;
extern const struct kit_sortedelement_class prefbundle_element;
extern const struct kit_sortedelement_class preforg_element;

struct application;
struct listener;

#include "pref-proto.h"

static inline const pref_categories_t *
pref_categories(pref_t *me)
{
    if (me->cooked == PREF_COOK_RAW)
        pref_cook(me);
    return &me->cooked_categories;
}

static inline const pref_categories_t *
pref_nodecrypt_categories(pref_t *me)
{
    if (me->cooked == PREF_COOK_RAW)
        pref_cook(me);
    return &me->cooked_nodecrypt_categories;
}

static inline const pref_categories_t *
pref_warn_categories(pref_t *me)
{
    if (me->cooked == PREF_COOK_RAW)
        pref_cook(me);
    return &me->cooked_warn_categories;
}

static inline pref_bundleflags_t
pref_bundleflags(pref_t *me)
{
    if (me->cooked == PREF_COOK_RAW)
        pref_cook(me);
    return me->cooked_bundleflags;
}

static inline pref_orgflags_t
pref_orgflags(pref_t *me)
{
    if (me->cooked == PREF_COOK_RAW)
        pref_cook(me);

    return me->cooked_orgflags;
}

#endif
