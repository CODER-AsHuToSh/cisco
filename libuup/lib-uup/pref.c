#include <kit-alloc.h>

#if SXE_DEBUG
#include <kit-bool.h>
#endif

#include "application.h"
#include "categorization.h"
#include "cidrlist.h"
#include "dns-name.h"
#include "pref-overloads.h"
#include "pref.h"
#include "uint32list.h"
#include "urllist.h"
#include "xray.h"

static uint32_t pref_globalorg = PREF_DEFAULT_GLOBALORG;

/**
 * Set the value of the global org id; the global org provides base preferences inheritted by parent (MSP) and other orgs
 *
 * @param globalorg Global org id
 */
void
pref_set_globalorg(uint32_t globalorg)
{
    pref_globalorg = globalorg;
}

/**
 * Compare a preflist's key to the specified (ltype,id,elementtype) tuple.
 *
 * @note Used to test whether the result of preflist_find is the index of a preflist that's an exact match.
 */
int
preflist_cmp_key(const struct preflist *me, ltype_t ltype, uint32_t id, elementtype_t elementtype)
{
    return PREFLIST_LTYPE(me) < ltype       ? -1 : PREFLIST_LTYPE(me) > ltype       ?  1
         : me->id             < id          ? -1 : me->id             > id          ?  1
         : me->elementtype    < elementtype ? -1 : me->elementtype    > elementtype ?  1 : 0;
}

static int
preflist_cmp(const void *vlhs, const void *vrhs)
{
    const struct preflist *rhs = vrhs;

    return preflist_cmp_key(vlhs, PREFLIST_LTYPE(rhs), rhs->id, rhs->elementtype);
}

static const char *
preflist_fmt(const void *me)
{
    const struct preflist *key = me;
    static __thread char       string[4][1 + 1 + 10 + 1 +  PREF_LIST_ELEMENTTYPE_NAME_MAXSIZE + 1];
    static __thread unsigned   next = 0;

    snprintf(string[next = (next + 1) % 4], sizeof(string[0]), "%X:%" PRIu32 ":%s",
             key->ltype, key->id, pref_list_elementtype_to_name(key->elementtype));
    return string[next];
}

const struct kit_sortedelement_class preflist_element = {
    sizeof(struct preflist),
    0,
    preflist_cmp,
    preflist_fmt
};

bool
ltype_matches_elementtype(ltype_t ltype, elementtype_t elementtype)
{
    switch (elementtype) {
    case PREF_LIST_ELEMENTTYPE_APPLICATION:
        switch (ltype & AT_LIST_MASK) {
        case AT_LIST_DESTBLOCK:
        case AT_LIST_EXCEPT:
        case AT_LIST_DESTALLOW:
        case AT_LIST_URL_PROXY_HTTPS:
        case AT_LIST_DESTNODECRYPT:
        case AT_LIST_DESTWARN:
            return false;
        }
        break;
    case PREF_LIST_ELEMENTTYPE_CIDR:
    case PREF_LIST_ELEMENTTYPE_DOMAIN:
    case PREF_LIST_ELEMENTTYPE_URL:
        switch (ltype & AT_LIST_MASK) {
        case AT_LIST_APPBLOCK:
        case AT_LIST_APPALLOW:
        case AT_LIST_APPNODECRYPT:
        case AT_LIST_APPWARN:
            return false;
        }
        break;
    }

    return true;
}

/**
 * Find a list in an array of preflists, returning the matching or closest index
 *
 * @param me/count             Pointer to the array of preflists and the number of preflists in the array
 * @param ltype/id/elementtype The key to look for in the array
 */
unsigned
preflist_find(const struct preflist *me, unsigned count, ltype_t ltype, uint32_t id, elementtype_t elementtype)
{
    struct preflist key;
    bool            match;    // Not used

    key.ltype = ltype;
    key.id = id;
    key.elementtype = elementtype;

    return kit_sortedarray_find(&preflist_element, me, count, &key, &match);
}

const struct preflist *
preflist_get(const struct preflist *me, unsigned count, ltype_t ltype, uint32_t id, elementtype_t elementtype)
{
    struct preflist key;

    key.ltype = ltype;
    key.id = id;
    key.elementtype = elementtype;

    return ltype_matches_elementtype(ltype, elementtype) ? kit_sortedarray_get(&preflist_element, me, count, &key) : NULL;
}

static int
prefsettinggroup_cmp(const void *vlhs, const void *vrhs)
{
    const struct prefsettinggroup *lhs = vlhs;
    const struct prefsettinggroup *rhs = vrhs;

    return lhs->idx < rhs->idx ? -1 : lhs->idx > rhs->idx ? 1 : lhs->id < rhs->id ? -1 : lhs->id > rhs->id ? 1 : 0;
}

static const char *
prefsettinggroup_fmt(const void *me)
{
    const struct prefsettinggroup *settinggroup = (const struct prefsettinggroup *)me;
    static __thread char           string[4][1 + 1 + 10 + 1];
    static __thread unsigned       next = 0;

    snprintf(string[next = (next + 1) % 4], sizeof(string[0]), "%X:%" PRIu32, settinggroup->idx, settinggroup->id);
    return string[next];
}

const struct kit_sortedelement_class prefsettinggroup_element = {
    sizeof(struct prefsettinggroup),
    0,
    prefsettinggroup_cmp,
    prefsettinggroup_fmt
};

const struct prefsettinggroup *
prefsettinggroup_get(const struct prefsettinggroup *me, unsigned count, settinggroup_idx_t idx, uint32_t id)
{
    struct prefsettinggroup key;
    key.idx = idx;
    key.id  = id;
    return kit_sortedarray_get(&prefsettinggroup_element, me, count, &key);
}

static int
prefbundle_cmp(const void *vlhs, const void *vrhs)
{
    const struct prefbundle *lhs = vlhs;
    const struct prefbundle *rhs = vrhs;

    return lhs->actype < rhs->actype ? -1 : lhs->actype > rhs->actype ? 1 : lhs->id < rhs->id ? -1 : lhs->id > rhs->id ? 1 : 0;
}

static const char *
prefbundle_fmt(const void *me)
{
    const struct prefbundle *bundle = (const struct prefbundle *)me;
    static __thread char     string[4][1 + 1 + 10 + 1];
    static __thread unsigned next = 0;

    snprintf(string[next = (next + 1) % 4], sizeof(string[0]), "%X:%" PRIu32, bundle->actype, bundle->id);
    return string[next];
}

const struct kit_sortedelement_class prefbundle_element = {
    sizeof(struct prefbundle),
    0,
    prefbundle_cmp,
    prefbundle_fmt
};

const struct prefbundle *
prefbundle_get(const struct prefbundle *me, unsigned count, actype_t actype, uint32_t id)
{
    struct prefbundle key;
    key.actype = actype;
    key.id     = id;
    return kit_sortedarray_get(&prefbundle_element, me, count, &key);
}

static int
preforg_cmp(const void *vlhs, const void *vrhs)
{
    const struct preforg *lhs = vlhs;
    const struct preforg *rhs = vrhs;

    return lhs->id == rhs->id ? 0 : lhs->id < rhs->id ? -1 : 1;
}

static const char *
preforg_fmt(const void *u)
{
    static __thread char     string[4][12];
    static __thread unsigned next = 0;

    snprintf(string[next = (next + 1) % 4], sizeof(string[0]), "%" PRIu32, ((const struct preforg *)u)->id);
    return string[next];
}

const struct kit_sortedelement_class preforg_element = {
    sizeof(struct preforg),
    0,
    preforg_cmp,
    preforg_fmt
};

const struct preforg *
preforg_get(const struct preforg *me, unsigned count, uint32_t id)
{
    return me ? kit_sortedarray_get(&preforg_element, me, count, &id) : NULL;
}

static const char *pref_list_elementtype_names[] = PREF_LIST_ELEMENTTYPE_NAMES;

/**
 * Convert a name into one of the element types (added in 2.3)
 */
elementtype_t
pref_list_name_to_elementtype(const char *name)
{
    elementtype_t elementtype;

    for (elementtype = 0; elementtype < PREF_LIST_ELEMENTTYPE_COUNT; elementtype++)
        if (strcmp(name, pref_list_elementtype_names[elementtype]) == 0)
            return elementtype;

    return PREF_LIST_ELEMENTTYPE_INVALID;    // User assigned names are no longer supported
}

/**
 * Convert an element type back to a name (added in 2.4)
 */
const char *
pref_list_elementtype_to_name(elementtype_t elementtype)
{
    SXEA6(elementtype < PREF_LIST_ELEMENTTYPE_COUNT, "Invalid elementtype %u", elementtype);
    return pref_list_elementtype_names[elementtype];
}

uint32_t
pref_get_globalorg(void)
{
    return pref_globalorg;
}

static void
pref_init_common(pref_t *me, const struct prefblock *blk, const struct prefblock *pblk, const struct prefblock *gblk,
                 unsigned idx)
{
    SXEA6(blk, "Cannot pref_init with no pref block");
    me->index     = idx;
    me->blk       = blk;
    me->parentblk = NULL;
    me->parentorg = NULL;
    me->globalorg = NULL;

    if (me->org != NULL && me->org->parentid) {
        me->parentblk = pblk == NULL ? blk : pblk;
        me->parentorg = prefblock_org(me->parentblk, me->org->parentid);
    }
    else
        SXEA6(pblk == NULL, "Given a parent prefblock with an orgid with no parent");

    me->globalblk = NULL;

    if (pref_globalorg) {
        me->globalblk = gblk == NULL ? blk : gblk;
        me->globalorg = prefblock_org(me->globalblk, pref_globalorg);
    }

    me->cooked = PREF_COOK_RAW;
}

void
pref_init_byidentity(pref_t *me, const struct prefblock *blk, const struct prefblock *pblk, const struct prefblock *gblk,
                     unsigned idx)
{
    const struct prefidentity *ident = blk->identity + idx;

    SXEL6("pref_init_byidentity(me,blk,pblk,gblk,idx=%u)", idx);
    me->type  = PREF_INDEX_IDENTITY;
    me->org   = ident->org != NO_ORG_ITEM ? blk->resource.org + ident->org : NULL;
    pref_init_common(me, blk, pblk, gblk, idx);
}

void
pref_init_bybundle(pref_t *me, const struct prefblock *blk, const struct prefblock *pblk, const struct prefblock *gblk,
                   uint32_t orgid, unsigned idx)
{
    me->type  = PREF_INDEX_BUNDLE;
    me->org   = orgid ? prefblock_org(blk, orgid) : NULL;
    pref_init_common(me, blk, pblk, gblk, idx);
}

void
pref_fini(pref_t *me)
{
    me->type = PREF_INDEX_NONE;
}

static const char *
flags_to_buf(uint64_t flags, unsigned flag_count, const char **flag_strings, char *buf, size_t size)
{
    char        bittxt[6];
    const char *tagtxt;
    unsigned    bpos;
    unsigned    bit;

    buf[bpos = 0] = '\0';

    for (bit = 0; bit < flag_count; bit++)
        if ((1ULL << bit) & flags) {
            if ((tagtxt = flag_strings[bit]) == NULL) {
                snprintf(bittxt, sizeof(bittxt), "bit%u", bit);
                tagtxt = bittxt;
            }

            bpos += snprintf(buf + bpos, size - bpos, "%s%s", bpos ? ", " : "", tagtxt);

            if (bpos >= size) {
                SXEA6(bpos < size, "Overflowed buffer (buf) in %s()", __FUNCTION__);
                break;    /* COVERAGE EXCLUSION - Can't be reached with a test that tries flags 0xffffffff */
            }
        }

    return buf;
}

#define PREF_BUNDLEFLAG_BITS (CHAR_BIT * sizeof(pref_bundleflags_t))

static const char *prefbundle_flag_strings[PREF_BUNDLEFLAG_BITS] = {
    "CLOSED_NETWORK",
    NULL,                     /* 0x000002 NOT CURRENTLY USED */
    NULL,                     /* 0x000004 NOT CURRENTLY USED */
    "SUSPICIOUS_RESPONSE",
    "TYPO_CORRECTION",
    NULL,                     /* 0x000020 NOT CURRENTLY USED */
    "EXPIRED_RRS",
    NULL,                     /* 0x000080 NOT CURRENTLY USED */
    NULL,                     /* 0x000100 NOT CURRENTLY USED */
    NULL,                     /* 0x000200 NOT CURRENTLY USED */
    NULL,                     /* 0x000400 NOT CURRENTLY USED */
    "ALLOWLIST_ONLY",
    "BPB",
    "URL_PROXY_HTTPS",
    "URL_PROXY",
    "NO_STATS",
    "SECURITY_STATS_ONLY",
    "RATE_NON_CUSTOMER",
    "RATE_RESTRICTED",
    "SIG_FILE_INSPECTION",
    "SIG_AMP_INSPECTION",
    "SIG_TG_SANDBOX",
    "SAFE_SEARCH",
    "SAML",
    "SWG_DISPLAY_BLOCK_PAGE"
};

const char *
pref_bundleflags_to_str(pref_bundleflags_t flags)
{
    static __thread char buf[1024];
    return flags_to_buf(flags, PREF_BUNDLEFLAG_BITS, prefbundle_flag_strings, buf, sizeof(buf));
}

#define PREF_ORGFLAG_BITS (CHAR_BIT * sizeof(pref_orgflags_t))

static const char *preforg_flag_strings[PREF_ORGFLAG_BITS] = {
    NULL,                         // 0x0001 NOT USED CURRENTLY
    "PROXY_NEWLY_SEEN_DOMAINS",
    "INCLUDE_TALOS_CATEGORIES",
    NULL,                         // 0x0008 NOT USED CURRENTLY
    "GDPR_EU",
    "GDPR_US",
    "SWG_ENABLED",
    "REALTIME_DNS_TUNNEL_BLOCKING",
    "O365_BYPASS",
    "BYPASS_SWG_FROM_TUNNEL",
    "DNSSEC_ENFORCE_ENABLED",
    "CDFW_L7",                                 // Not used by resolvers
    "ENABLE_RANGE_HEADERS",                    // Not used by resolvers
    "DLP",                                     // Not used by resolvers
    "EVENT_SYNC_TO_CLOUD_ENDPOINT",            // Not used by resolvers
    "POLICY_RULE_SETTINGS",                    // Not used by resolvers
    "SWG_SKIP_RESOLVER_FOR_AVCDL",             // Not used by resolvers
    "ACCESS_TO_DL_IN_RULES",                   // Not used by resolvers
    "DECRYPT_BY_IP",                           // Not used by resolvers
    "ENABLE_SWG_NAT",                          // Not used by resolvers
    "ENABLE_SWG_SINGLE_PORT",                  // Not used by resolvers
    "VERIZON_DNS",                             // Not used by resolvers
    "UMBRELLA_IP_SURROGATES",                  // Not used by resolvers
    "EVALUATE_APPLICATION_IN_RULES",           // Not used by resolvers
    "WSA_PROXY_CHAIN_IDENTITY",                // Not used by resolvers
    "ALL_DOMAINTAGGING",
    "HALF_DOMAINTAGGING",
    "ENABLE_NATAAS_SSL_PASSTHROUGH",           // Not used by resolvers
    "RBI_BIT0",                                // Not used by resolvers
    "RBI_BIT1",                                // Not used by resolvers
    "CDFW_AVC",                                // Not used by resolvers
    "CDFW_IPS",                                // Not used by resolvers
    "RESEARCH_ALGORITHMS_CATEGORIZE",
    "RESEARCH_ALGORITHMS_BLOCKING",
    "DISABLE_SWG_NAT",                         // Not used by resolvers
    "ENABLE_IP_SURROGATE_SAML_REAUTH",         // Not used by resolvers
    "SWG_NAT_FOR_DECRYPT",                     // Not used by resolvers
    "SWG_CAPTCHA_WARN",                        // Not used by resolvers
    "NETWORK_IDENTITY_WITH_ANYCONNECT",        // Not used by resolvers
    "AGGREGATE_REPORTING_ONLY"
};

const char *
pref_orgflags_to_str(pref_orgflags_t flags)
{
    static __thread char buf[1024];
    return flags_to_buf(flags, PREF_ORGFLAG_BITS, preforg_flag_strings, buf, sizeof(buf));
}

/*
 * Create a prefblock with 'n' identities, each pointing to their own bundle and org.
 * This is used by dnscache to manage default interface prefs.
 */
struct prefblock *
prefblock_new_empty(unsigned n)
{
    struct prefbundle *bundle;
    struct prefblock *me;
    unsigned i;

    SXEA1(me = kit_calloc(1, sizeof(*me)), "Failed to allocate an empty prefblock");
    SXEA1(me->identity = kit_calloc(n, sizeof(*me->identity)), "Failed to allocate %u listener identities of size %zu", n, sizeof(*me->identity));
    SXEA1(me->resource.bundle = kit_calloc(n, sizeof(*me->resource.bundle)), "Failed to allocate %u listener bundles of size %zu", n, sizeof(*me->resource.bundle));
    SXEA1(me->resource.org = kit_calloc(n, sizeof(*me->resource.org)), "Failed to allocate %u listener orgs of size %zu", n, sizeof(*me->resource.org));
    for (i = 0; i < n; i++) {
        me->identity[i].bundle = i;
        me->identity[i].org = i;
        bundle = me->resource.bundle + i;
        pref_categories_setnone(&bundle->base_blocked_categories);
        pref_categories_setnone(&bundle->base_nodecrypt_categories);
        pref_categories_setnone(&bundle->base_warn_categories);
        bundle->dest_block = bundle->exceptions = bundle->dest_allow = bundle->url_proxy_https = bundle->dest_nodecrypt = bundle->dest_warn = PREF_NOLIST;
        bundle->app_block = bundle->app_allow = bundle->app_nodecrypt = bundle->app_warn = PREF_NOLIST;
        bundle->ext_dest_block = bundle->ext_dest_allow = bundle->ext_url_proxy_https = bundle->ext_dest_nodecrypt = bundle->ext_dest_warn = PREF_NOLIST;
        bundle->ext_app_block = bundle->ext_app_allow = bundle->ext_app_nodecrypt = bundle->ext_app_warn = PREF_NOLIST;
        bundle->priority = UINT32_MAX;
    }
    me->count.identities = me->count.bundles = n;

    return me;
}

void
prefblock_free(struct prefblock *me)
{
    /* Allocated by prefbuilder, obtained from prefbuilder_consume() */
    if (me) {
        kit_free(me->resource.list);
        kit_free(me->resource.listref);
        kit_free(me->resource.extlistref);
        kit_free(me->resource.settinggroup);
        kit_free(me->resource.bundle);
        kit_free(me->resource.org);
        kit_free(me->identity);
        kit_free(me);
    }
}

/*
 * If the pref's org wants newly seen domains to be proxied, test whether domain is newly seen.
 */
bool
pref_proxy_newly_seen_domain(pref_t *me, pref_categories_t *categories, const uint8_t *name, struct xray *x)
{
    if (pref_orgflags(me) & PREF_ORGFLAGS_PROXY_NEWLY_SEEN_DOMAINS
     && pref_categories_getbit(categories, CATEGORY_BIT_NEWLY_SEEN_DOMAINS)) {
        XRAY6(x, "%s is a newly seen domain and org %u proxies them", dns_name_to_str1(name), PREF_ORG(me)->id);
        return true;
    }

    return false;
}

/* find a domain in a pref_t */
bool
pref_domainlist_match(const pref_t *me, pref_categories_t *match, ltype_t ltype, const uint8_t *name,
                      enum domainlist_match matchtype, struct xray *x)
{
    const struct preflist *list;
    const struct prefblock *blk;
    pref_categories_t cat;
    char pname[32];
    uint32_t lid;
    unsigned i;
    bool ret;

    ret = false;
    pref_categories_setnone(&cat);

    for (i = 0; (list = PREF_DESTLIST(me, ltype, i)) != NULL; i++)
        if (list->elementtype == PREF_LIST_ELEMENTTYPE_DOMAIN && (!ret || !pref_categories_getbit(&cat, list->bit))) {
            /* This list is of interest and the list type hasn't been matched yet */
            snprintf(pname, sizeof(pname), "preflist %02X:%u:%s", ltype | PREF_BUNDLE(me)->actype, list->id, PREF_DESTLIST_NAME(me, ltype, i));

            if (domainlist_match(list->lp.domainlist, name, matchtype, x, pname)) {
                pref_categories_setbit(&cat, list->bit);
                ret = true;
            }
        }

    SXEL6("Searched for domain %s in a total of %u type %X list%s under bundle %X:%u - hits now %s",
          dns_name_to_str1(name), i, ltype, i == 1 ? "" : "s", PREF_BUNDLE(me)->actype, PREF_BUNDLE(me)->id, kit_bool_to_str(ret));

    if (me->parentblk || me->globalblk) {
        for (i = 0; (lid = PREF_EXTDESTLISTID(me, ltype, i)) != PREF_NOLISTID; i++)
            if (((list = prefblock_list(blk = me->parentblk, ltype, lid, PREF_LIST_ELEMENTTYPE_DOMAIN)) != NULL
              || (list = prefblock_list(blk = me->globalblk, ltype, lid, PREF_LIST_ELEMENTTYPE_DOMAIN)) != NULL)
             && list->elementtype == PREF_LIST_ELEMENTTYPE_DOMAIN && (!ret || !pref_categories_getbit(&cat, list->bit))) {
                /* This list is of interest and the list type hasn't been matched yet */
                snprintf(pname, sizeof(pname), "preflist %02X:%u:%s", ltype | PREF_BUNDLE(me)->actype, list->id, pref_list_elementtype_to_name(list->elementtype));

                if (domainlist_match(list->lp.domainlist, name, matchtype, x, pname)) {
                    pref_categories_setbit(&cat, list->bit);
                    ret = true;
                }
            }

        SXEL6("Searched for domain %s in a total of %u parent/global list%s - hits now %s",
              dns_name_to_str1(name), i, i == 1 ? "" : "s", kit_bool_to_str(ret));
    }

    if (match)
        pref_categories_union(match, match, &cat);

    return ret;
}

/**
 * Find an application domain in a pref_t (a domain match against url lists)
 *
 * @param me             Prefs to search in; all application preflists hanging off me will be searched
 * @param match          NULL or categories matched; matched category bits are added to any bits already set
 * @param ltype          The list type
 * @param name           DNS (domain) name to search for
 * @param find           Categories to find
 * @param categorization The dynamic categorization
 * @param conf           Current confset, which includes the application-lists
 * @param x              NULL or pointer to an X-ray object used to track diagnostics
 *
 * @return the appid or 0 if not found
 */
uint32_t
pref_applicationlist_domain_match(pref_t *me, pref_categories_t *match, ltype_t ltype, const uint8_t *name,
                                  pref_categories_t *find, const struct categorization *categorization,
                                  const struct confset *conf, struct xray *x)
{
    const struct preflist  *list;
    const struct prefblock *blk;
    uint32_t                appid, lid, ret;
    pref_categories_t       cat;
    unsigned                i, n;

    SXEE6("(me=?,match=?,ltype=%02X,name='%s',find='%s',categorization=?,conf=?,x=?)",
          ltype, dns_name_to_str1(name), pref_categories_idstr(find));

    pref_categories_setnone(&cat);
    ret = 0;

    for (i = 0; (list = PREF_DESTLIST(me, ltype, i)) != NULL; i++)
        if (list->elementtype == PREF_LIST_ELEMENTTYPE_APPLICATION && (!ret || !pref_categories_getbit(&cat, list->bit)))
            for (n = 0; n < list->lp.applicationlist->count; n++) {
                appid = list->lp.applicationlist->val[n];

                if (categorization_match_appid(categorization, conf, &cat, appid, name, pref_bundleflags(me), pref_orgflags(me),
                                               find, x)) {
                    pref_categories_setbit(&cat, list->bit);
                    ret = appid;
                }
            }

    SXEL6("Searched for application domain %s in a total of %u type %02X list%s under bundle %X:%u - match now %u",
          dns_name_to_str1(name), i, ltype, i == 1 ? "" : "s", PREF_BUNDLE(me)->actype, PREF_BUNDLE(me)->id, ret);

    if (me->parentblk || me->globalblk) {
        for (i = 0; (lid = PREF_EXTDESTLISTID(me, ltype, i)) != PREF_NOLISTID; i++)
            if (((list = prefblock_list(blk = me->parentblk, ltype, lid, PREF_LIST_ELEMENTTYPE_APPLICATION)) != NULL
              || (list = prefblock_list(blk = me->globalblk, ltype, lid, PREF_LIST_ELEMENTTYPE_APPLICATION)) != NULL)
             && list->elementtype == PREF_LIST_ELEMENTTYPE_APPLICATION && (!ret || !pref_categories_getbit(&cat, list->bit)))
                /* This list is of interest */
                for (n = 0; n < list->lp.applicationlist->count; n++) {
                    appid = list->lp.applicationlist->val[n];

                    if (categorization_match_appid(categorization, conf, &cat, appid, name, pref_bundleflags(me),
                                                   pref_orgflags(me), find, x)) {
                        pref_categories_setbit(&cat, list->bit);
                        ret = appid;
                    }
                }

        SXEL6("Searched for application domain %s in a total of %u type %02X parent/global list%s - match now %u",
              dns_name_to_str1(name), i, ltype, i == 1 ? "" : "s", ret);
    }

    if (match)
        pref_categories_union(match, match, &cat);

    SXER6("return %u // appid, categories %s", ret, match ? pref_categories_idstr(match) : "<NULL>");
    return ret;
}

/**
 * Find an application domain block/allow proxy in a pref_t (a domain match against url lists)
 *
 * @param me             Prefs to search in; all application preflists hanging off me will be searched
 * @param name           DNS (domain) name to search for
 * @param ltype          The list type
 * @param categorization The dynamic categorization
 * @param conf           Current confset, which includes the application-lists
 * @param x              NULL or pointer to an X-ray object used to track diagnostics
 *
 * @return the appid or 0 if not found
 *
 * @note If a match is found, the resolver will answer the originating client with the proxy address
 *       (url-proxy.conf.opendns.com or url-proxy-https.conf.opendns.com).
 */
uint32_t
pref_applicationlist_proxy(pref_t *me, const uint8_t *name, ltype_t ltype, const struct categorization *categorization,
                           const struct confset *conf, struct xray *x)
{
    const struct preflist  *list;
    const struct prefblock *blk;
    uint32_t                appid, lid, ret;
    unsigned                i, n;

    SXEE6("(me=?,name='%s',ltype=%X,categorization=?,conf=?,x=?)", dns_name_to_str1(name), ltype);

    ret = 0;

    if (categorization_might_proxy(categorization, conf, name, pref_bundleflags(me), pref_orgflags(me), x)) {
        SXEL6("%s might match an application proxy url.... searching", dns_name_to_str1(name));
        for (i = 0; (list = PREF_DESTLIST(me, ltype, i)) != NULL; i++)
            if (list->elementtype == PREF_LIST_ELEMENTTYPE_APPLICATION)
                for (n = 0; n < list->lp.applicationlist->count; n++) {
                    appid = list->lp.applicationlist->val[n];

                    if (categorization_proxy_appid(categorization, conf, appid, name, pref_bundleflags(me), pref_orgflags(me), x))
                        ret = appid;
                }

        SXEL6("Searched for application proxy domain %s in a total of %u type %02X list%s under bundle %X:%u - match now %u",
              dns_name_to_str1(name), i, ltype, i == 1 ? "" : "s", PREF_BUNDLE(me)->actype, PREF_BUNDLE(me)->id, ret);

        if (me->parentblk || me->globalblk)
            for (i = 0; (lid = PREF_EXTDESTLISTID(me, ltype, i)) != PREF_NOLISTID; i++)
                if (((list = prefblock_list(blk = me->parentblk, ltype, lid, PREF_LIST_ELEMENTTYPE_APPLICATION)) != NULL
                  || (list = prefblock_list(blk = me->globalblk, ltype, lid, PREF_LIST_ELEMENTTYPE_APPLICATION)) != NULL)
                 && list->elementtype == PREF_LIST_ELEMENTTYPE_APPLICATION)
                    /* This list is of interest */
                    for (n = 0; n < list->lp.applicationlist->count; n++) {
                        appid = list->lp.applicationlist->val[n];

                        if (categorization_proxy_appid(categorization, conf, appid, name, pref_bundleflags(me),
                                                       pref_orgflags(me), x))
                            ret = appid;
                    }

            SXEL6("Searched for application proxy domain %s in a total of %u type %02X parent/global list%s",
                  dns_name_to_str1(name), i, ltype, i == 1 ? "" : "s");
    }

    SXER6("return %u // appid", ret);

    return ret;
}

/* find an application url in a pref_t, return the appid */
uint32_t
pref_applicationlist_url_match(pref_t *me, const struct application *app, ltype_t ltype, const char *url, size_t ulen, pref_categories_t *match)
{
    const struct preflist *list;
    const struct prefblock *blk;
    uint32_t appid, lid, ret;
    unsigned i, n;

    SXEE6("(me=?, app=?, ltype=%02X, url='%.*s')", ltype, (int)ulen, url);

    ret = 0;
    for (i = 0; (list = PREF_DESTLIST(me, ltype, i)) != NULL; i++)
        if (list->elementtype == PREF_LIST_ELEMENTTYPE_APPLICATION && (!ret || !pref_categories_getbit(match, list->bit)))
            for (n = 0; n < list->lp.applicationlist->count; n++) {
                appid = list->lp.applicationlist->val[n];
                if (application_match_url_byid(app, appid, url, ulen)) {
                    pref_categories_setbit(match, list->bit);
                    ret = appid;
                }
            }

    SXEL6("Searched for application url in a total of %u type %02X list%s under bundle %X:%u - match now %s appid %u",
          i, ltype, i == 1 ? "" : "s", PREF_BUNDLE(me)->actype, PREF_BUNDLE(me)->id, kit_bool_to_str(ret), ret);

    if (me->parentblk || me->globalblk) {
        for (i = 0; (lid = PREF_EXTDESTLISTID(me, ltype, i)) != PREF_NOLISTID; i++)
            if (((list = prefblock_list(blk = me->parentblk, ltype, lid, PREF_LIST_ELEMENTTYPE_APPLICATION)) != NULL
              || (list = prefblock_list(blk = me->globalblk, ltype, lid, PREF_LIST_ELEMENTTYPE_APPLICATION)) != NULL)
             && list->elementtype == PREF_LIST_ELEMENTTYPE_APPLICATION && (!ret || !pref_categories_getbit(match, list->bit)))
                /* This list is of interest */
                for (n = 0; n < list->lp.applicationlist->count; n++) {
                    appid = list->lp.applicationlist->val[n];
                    if (application_match_url_byid(app, appid, url, ulen)) {
                        pref_categories_setbit(match, list->bit);
                        ret = appid;
                    }
                }

        SXEL6("Searched for application url in a total of %u type %02X parent/global list%s - match now %s appid %u",
              i, ltype, i == 1 ? "" : "s", kit_bool_to_str(ret), ret);
    }

    SXER6("return %u // appid, categories %s", ret, pref_categories_idstr(match));

    return ret;
}

/*-
 * Returns comma seperated list of application ids in a pref
 *
 * @param me           Pointer to the pref_t to match in
 * @param ltype        List type (e.g. AT_LIST_APPBLOCK or AT_LIST_APPNODECRYP)T
 * @param app_list_str app list is copied to this char array
 * @param max_buf_len  size of char array buffer
 *
 * @return             return true if successful, false otherwise
 */
bool
pref_get_app_list_str(pref_t *me, ltype_t ltype, char *app_list_str, int max_buf_len)
{
    const struct preflist *list;
    const struct prefblock *blk;
    uint32_t appid, lid;
    unsigned i, n;
    int count = 0;
    int offset = 0;
    int len;
    bool ret;
    char *pos = app_list_str;

    SXEE6("(me=?, ltype=%02X )", ltype);

    if (app_list_str == NULL || max_buf_len <= 0){
        ret = false;
        goto EXIT;
    }

    for (i = 0; (list = PREF_DESTLIST(me, ltype, i)) != NULL; i++)
        if (list->elementtype == PREF_LIST_ELEMENTTYPE_APPLICATION)
            for (n = 0; n < list->lp.applicationlist->count; n++) {
                appid = list->lp.applicationlist->val[n];
                if (n) {
                    len = snprintf(pos + offset, max_buf_len - offset, ",");
                    if (len <= 0 || len >= max_buf_len - offset) {
                        ret = false;
                        app_list_str[0] = '\0';
                        goto EXIT;
                    }
                    offset += len;
                }
                len = snprintf(pos + offset, max_buf_len - offset, "%d", appid);
                if (len <= 0 || len >= max_buf_len - offset) {
                    ret = false;
                    app_list_str[0] = '\0';
                    goto EXIT;
                }
                offset += len;
                count++;
            }

    SXEL6("Searched in a total of %u type %02X list%s under bundle %X:%u - app_ids total %d",
           i, ltype, i == 1 ? "" : "s", PREF_BUNDLE(me)->actype, PREF_BUNDLE(me)->id, count);
    if (me->parentblk || me->globalblk) {
        for (i = 0; (lid = PREF_EXTDESTLISTID(me, ltype, i)) != PREF_NOLISTID; i++)
            if (((list = prefblock_list(blk = me->parentblk, ltype, lid, PREF_LIST_ELEMENTTYPE_APPLICATION)) != NULL
              || (list = prefblock_list(blk = me->globalblk, ltype, lid, PREF_LIST_ELEMENTTYPE_APPLICATION)) != NULL)
             && list->elementtype == PREF_LIST_ELEMENTTYPE_APPLICATION)
                /* This list is of interest */
                for (n = 0; n < list->lp.applicationlist->count; n++) {
                    appid = list->lp.applicationlist->val[n];
                    if (n || count) {
                        len = snprintf(pos + offset, max_buf_len - offset, ",");
                        if (len <= 0 || len >= max_buf_len - offset) {
                            ret = false;
                            app_list_str[0] = '\0';
                            goto EXIT;
                        }
                        offset += len;
                    }
                    len = snprintf(pos + offset, max_buf_len - offset, "%d", appid);
                    if (len <= 0 || len >= max_buf_len - offset) {
                        ret = false;
                        app_list_str[0] = '\0';
                        goto EXIT;
                    }
                    offset += len;
                    count++;
                }
    }
    app_list_str[offset] = '\0';
    SXEL6("Searched in a total of %u type %02X parent/global list%s - app_ids total %d",
          i, ltype, i == 1 ? "" : "s", count);
    ret = true;

EXIT:

    SXER6("return %d // app_list %s", ret, app_list_str);

    return ret;
}

/*-
 * Find application id in pref_t application list
 *
 * @param me         Pointer to the pref_t to match in
 * @param ltype      List type (e.g. AT_LIST_APPBLOCK or AT_LIST_APPALLOW)
 * @param url_appid  Application ID (of incoming request)
 * @param match      Pointer to pref categories. If not NULL, found category bits will be ORed in to categories
 *
 * @return           return true in the case of match, false otherwise
 */

bool
pref_applicationlist_appid_match(pref_t *me, ltype_t ltype, const uint32_t url_appid, pref_categories_t *match)
{
    const struct preflist *list;
    const struct prefblock *blk;
    uint32_t appid, lid;
    unsigned i, n;
    bool ret = false;

    SXEE6("(me=?, ltype=%02X, url_appid=%u)", ltype, url_appid);

    for (i = 0; (list = PREF_DESTLIST(me, ltype, i)) != NULL; i++)
        if (list->elementtype == PREF_LIST_ELEMENTTYPE_APPLICATION && (!ret || !pref_categories_getbit(match, list->bit)))
            for (n = 0; n < list->lp.applicationlist->count; n++) {
                appid = list->lp.applicationlist->val[n];
                if (url_appid == appid) {
                    pref_categories_setbit(match, list->bit);
                    ret = true;
                }
            }

    SXEL6("Searched for appid %u in a total of %u type %02X list%s under bundle %X:%u - match now %s",
          url_appid, i, ltype, i == 1 ? "" : "s", PREF_BUNDLE(me)->actype, PREF_BUNDLE(me)->id, kit_bool_to_str(ret));

    if (me->parentblk || me->globalblk) {
        for (i = 0; (lid = PREF_EXTDESTLISTID(me, ltype, i)) != PREF_NOLISTID; i++)
            if (((list = prefblock_list(blk = me->parentblk, ltype, lid, PREF_LIST_ELEMENTTYPE_APPLICATION)) != NULL
              || (list = prefblock_list(blk = me->globalblk, ltype, lid, PREF_LIST_ELEMENTTYPE_APPLICATION)) != NULL)
             && list->elementtype == PREF_LIST_ELEMENTTYPE_APPLICATION && (!ret || !pref_categories_getbit(match, list->bit)))
                /* This list is of interest */
                for (n = 0; n < list->lp.applicationlist->count; n++) {
                    appid = list->lp.applicationlist->val[n];
                    if (url_appid == appid) {
                        pref_categories_setbit(match, list->bit);
                        ret = true;
                    }
                }

        SXEL6("Searched for appid %u in a total of %u type %02X parent/global list%s - match now %s",
              url_appid, i, ltype, i == 1 ? "" : "s", kit_bool_to_str(ret));
    }

    SXER6("return %s // categories %s", kit_bool_to_str(ret), pref_categories_idstr(match));

    return ret;
}

/*-
 * Find a url destination list match in a pref_t
 *
 * @param me         Pointer to the pref_t to match in
 * @param categories Pointer to pref categories. If not NULL, found category bits will be ORed in to categories
 * @param ltype      List type (e.g. AT_LIST_DESTBLOCK or AT_LIST_DESTALLOW)
 * @param url        The url being matched
 * @param length     The length of the url
 * @param x          XRAY information. May be NULL.
 *
 * @return           the number of preflists matched
 */
bool
pref_urllist_match(const pref_t *me, pref_categories_t *categories, ltype_t ltype, const char *url, unsigned length, struct xray *x)
{
    const struct preflist *list;
    const struct prefblock *blk;
    pref_categories_t      cat;
    uint32_t               lid;
    unsigned               i;
    bool                   ret = false;

    SXE_UNUSED_PARAMETER(x);   /* match functions usually produce XRAY output, but the proxy doesn't have XRAY! */

    pref_categories_setnone(&cat);

    for (i = 0; (list = PREF_DESTLIST(me, ltype, i)) != NULL; i++)
        if (list->elementtype == PREF_LIST_ELEMENTTYPE_URL && (!ret || !pref_categories_getbit(&cat, list->bit))) {
            /* This list is of interest and the list type hasn't been matched yet */
            if (urllist_match(list->lp.urllist, url, length)) {
                pref_categories_setbit(&cat, list->bit);
                ret = true;
            }
        }

    SXEL6("Searched for url %.*s in a total of %u list%s", length, url, i, i == 1 ? "" : "s");

    if (me->parentblk || me->globalblk) {
        for (i = 0; (lid = PREF_EXTDESTLISTID(me, ltype, i)) != PREF_NOLISTID; i++)
            if (((list = prefblock_list(blk = me->parentblk, ltype, lid, PREF_LIST_ELEMENTTYPE_URL)) != NULL
              || (list = prefblock_list(blk = me->globalblk, ltype, lid, PREF_LIST_ELEMENTTYPE_URL)) != NULL)    /* COVERAGE EXCLUSION: Need a test; exposed by wrapping */
             && list->elementtype == PREF_LIST_ELEMENTTYPE_URL && (!ret || !pref_categories_getbit(&cat, list->bit))) {
                /* This list is of interest and the list type hasn't been matched yet */
                if (urllist_match(list->lp.urllist, url, length)) {
                    pref_categories_setbit(&cat, list->bit);
                    ret = true;
                }
            }

        SXEL6("Searched for url %.*s in a total of %u parent/global list%s", length, url, i, i == 1 ? "" : "s");
    }

    if (categories)
        pref_categories_union(categories, categories, &cat);

    return ret;
}

bool
pref_cidrlist_match(const pref_t *me, pref_categories_t *categories, ltype_t ltype, const struct netaddr *addr)
{
    const struct preflist  *list;
    const struct prefblock *blk;
    pref_categories_t      cat;
    uint32_t               lid;
    unsigned               i;
    bool                   ret = false;

    pref_categories_setnone(&cat);

    for (i = 0; (list = PREF_DESTLIST(me, ltype, i)) != NULL; i++)
        if (list->elementtype == PREF_LIST_ELEMENTTYPE_CIDR && (!ret || !pref_categories_getbit(&cat, list->bit))) {
            if (cidrlist_search(list->lp.cidrlist, addr, NULL, NULL)) {
                pref_categories_setbit(&cat, list->bit);
                ret = true;
            }
        }

    SXEL6("Searched for cidr %s in a total of %u list%s", netaddr_to_str(addr), i, i == 1 ? "" : "s");
    if (me->parentblk || me->globalblk) {
        for (i = 0; (lid = PREF_EXTDESTLISTID(me, ltype, i)) != PREF_NOLISTID; i++)
            if (((list = prefblock_list(blk = me->parentblk, ltype, lid, PREF_LIST_ELEMENTTYPE_CIDR)) != NULL
              || (list = prefblock_list(blk = me->globalblk, ltype, lid, PREF_LIST_ELEMENTTYPE_CIDR)) != NULL)    /* COVERAGE EXCLUSION: Need a test; exposed by wrapping */
             && list->elementtype == PREF_LIST_ELEMENTTYPE_CIDR && (!ret || !pref_categories_getbit(&cat, list->bit))) {
                /* This list is of interest and the list type hasn't been matched yet */
                if (cidrlist_search(list->lp.cidrlist, addr, NULL, NULL)) {
                    pref_categories_setbit(&cat, list->bit);
                    ret = true;
                }
            }
        SXEL6("Searched for cidr %s in a total of %u parent/global list%s", netaddr_to_str(addr), i, i == 1 ? "" : "s");
    }

    if (categories)
        pref_categories_union(categories, categories, &cat);

    return ret;
}

struct cidrlist *
cidrlist_new_from_pref(const pref_t *me, ltype_t ltype)
{
    const struct preflist *list;
    const struct prefblock *blk;
    struct cidrlist *cl;
    uint32_t lid;
    unsigned i;

    cl = cidrlist_new(PARSE_IP_OR_CIDR);

    for (i = 0; cl && (list = PREF_DESTLIST(me, ltype, i)) != NULL; i++)
        if (list->elementtype == PREF_LIST_ELEMENTTYPE_CIDR && !cidrlist_append(cl, list->lp.cidrlist)) {
            cidrlist_refcount_dec(cl);
            cl = NULL;
        }

    if (me->parentblk || me->globalblk)
        for (i = 0; cl && (lid = PREF_EXTDESTLISTID(me, ltype, i)) != PREF_NOLISTID; i++)
            if (((list = prefblock_list(blk = me->parentblk, ltype, lid, PREF_LIST_ELEMENTTYPE_CIDR)) != NULL
              || (list = prefblock_list(blk = me->globalblk, ltype, lid, PREF_LIST_ELEMENTTYPE_CIDR)) != NULL)    /* COVERAGE EXCLUSION: Need a test; exposed by wrapping */
             && list->elementtype == PREF_LIST_ELEMENTTYPE_CIDR && !cidrlist_append(cl, list->lp.cidrlist)) {
                cidrlist_refcount_dec(cl);
                cl = NULL;
            }

    cidrlist_sort(cl);

    return cl;
}

static int
qsort_strcmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

size_t
preflist_buf_size(const struct preflist *preflist)
{
    switch (preflist->elementtype) {
    case PREF_LIST_ELEMENTTYPE_CIDR:   return cidrlist_buf_size(preflist->lp.cidrlist);
    case PREF_LIST_ELEMENTTYPE_DOMAIN: return domainlist_buf_size(preflist->lp.domainlist);
    default:                           return 0;                          /* COVERAGE EXCLUSION: URLPREFS/APPLICATIONPREFS  */
    }
}

const char *
preflist_to_buf(const struct preflist *preflist, char *buf, size_t sz, size_t *len_out)
{
    switch (preflist->elementtype) {
    case PREF_LIST_ELEMENTTYPE_CIDR:   return cidrlist_to_buf(  preflist->lp.cidrlist,   buf, sz, len_out);
    case PREF_LIST_ELEMENTTYPE_DOMAIN: return domainlist_to_buf(preflist->lp.domainlist, buf, sz, len_out);
    default:                           return NULL;                       /* COVERAGE EXCLUSION: URLPREFS/APPLICATIONPREFS  */
    }
}

void
preflist_refcount_dec(struct preflist *preflist)
{
    switch (preflist->elementtype) {
    case PREF_LIST_ELEMENTTYPE_APPLICATION:
        uint32list_refcount_dec(preflist->lp.applicationlist);
        break;

    case PREF_LIST_ELEMENTTYPE_CIDR:
        cidrlist_refcount_dec(preflist->lp.cidrlist);
        break;

    case PREF_LIST_ELEMENTTYPE_DOMAIN:
        domainlist_refcount_dec(preflist->lp.domainlist);
        break;

    case PREF_LIST_ELEMENTTYPE_URL:
        urllist_refcount_dec(preflist->lp.urllist);
        break;
    }
}

const char *
pref_sorted_list(const pref_t *pref, ltype_t ltype)
{
    static __thread char *buf;
    static __thread size_t bufsz;
    char **idx, *p, *unsorted;
    size_t sz, thisused, used;
    struct preflist *list;
    unsigned i, n;

    if (pref == NULL) {
        /* Release memory */
        kit_free(buf);
        buf = NULL;
        bufsz = 0;
        return NULL;
    }

    sz = 0;

    for (i = 0; (list = PREF_DESTLIST(pref, ltype, i)) != NULL; i++) {
        sz += preflist_buf_size(list);
    }

    if (sz == 0)
        return "";

    SXEA1(unsorted = kit_malloc(sz), "Failed to allocate %zu bytes for the unsorted list", sz);    /* Maybe too big for alloca() */
    used = 0;

    for (i = 0; (list = PREF_DESTLIST(pref, ltype, i)) != NULL; i++)
        if (preflist_to_buf(list, unsorted + used, sz - used, &thisused)) {
            used += thisused;
            unsorted[used++] = ' ';
        }

    if (used)
        unsorted[--used] = '\0';

    /*
     * Sort & uniq them.  Note, we can't ask the domainlist to do this for us
     * as the domainlist sorts things in reversed-name order.
     */
    for (n = 0, p = unsorted; p; p = strchr(p, ' '), p = p ? p + 1 : NULL)
        n++;
    SXEA1(idx = kit_malloc(n * sizeof(*idx)), "Failed to allocate %u pointers for sorting the list", n);    /* Maybe too big for alloca() */
    for (i = 0, p = unsorted; p; p = strchr(p, ' '), p = p ? p + 1 : NULL) {
        idx[i++] = p;
        if (p != unsorted)
            p[-1] = '\0';
    }
    qsort(idx, n, sizeof(*idx), qsort_strcmp);

    if (sz > bufsz)
        SXEA1(buf = kit_realloc(buf, bufsz = sz), "Couldn't realloc %zu bytes", sz);
    for (p = buf, i = 0; i < n; i++)
        if (i == 0 || strcmp(idx[i - 1], idx[i]) != 0) {
            p = stpcpy(p, idx[i]);
            *p++ = ' ';
        }
    *--p = '\0';

    kit_free(unsorted);
    kit_free(idx);

    return buf;
}

const struct preflist *
prefblock_list(const struct prefblock *me, ltype_t ltype, uint32_t id, elementtype_t elementtype)
{
    return me ? preflist_get(me->resource.list, me->count.lists, ltype, id, elementtype) : NULL;
}

const struct prefsettinggroup *
prefblock_settinggroup(const struct prefblock *me, settinggroup_idx_t idx, uint32_t id)
{
    return me ? prefsettinggroup_get(me->resource.settinggroup, me->count.settinggroups, idx, id) : NULL;
}

void
pref_cook(pref_t *me)
{
    const struct prefsettinggroup *psg;
    const struct prefbundle *bundle;
    const struct preforg *org;
    unsigned i;

    SXEA6(PREF_VALID(me), "Invalid pref passed to pref_cook");

    if (me->cooked == PREF_COOK_RAW) {
        org = PREF_ORG(me);
        bundle = PREF_BUNDLE(me);
        me->cooked_orgflags = org ? org->orgflags : 0;
        me->cooked_bundleflags = bundle->bundleflags;
        me->cooked_categories = bundle->base_blocked_categories;
        me->cooked_nodecrypt_categories = bundle->base_nodecrypt_categories;
        me->cooked_warn_categories = bundle->base_warn_categories;

        for (i = 0; i < SETTINGGROUP_IDX_COUNT; i++) {
            psg = NULL;

            if (me->parentblk && bundle->sgids[i])
                psg = prefblock_settinggroup(me->parentblk, i, bundle->sgids[i]);

            if (!psg && me->globalblk && bundle->sgids[i])
                psg = prefblock_settinggroup(me->globalblk, i, bundle->sgids[i]);

            if (psg) {
                me->cooked_bundleflags |= psg->bundleflags;
                pref_categories_union(&me->cooked_categories, &me->cooked_categories, &psg->blocked_categories);
                pref_categories_union(&me->cooked_nodecrypt_categories, &me->cooked_nodecrypt_categories, &psg->nodecrypt_categories);
                pref_categories_union(&me->cooked_warn_categories, &me->cooked_warn_categories, &psg->warn_categories);
            }
        }

        /* These bits are implicitly included in all policies - the "cooked" policy category bits */
        pref_categories_setbit(&me->cooked_categories, CATEGORY_BIT_BLOCKLIST);
        pref_categories_setbit(&me->cooked_categories, CATEGORY_BIT_ALLOWLIST);
        pref_categories_setbit(&me->cooked_categories, CATEGORY_BIT_GLOBAL_ALLOWLIST);
        pref_categories_setbit(&me->cooked_categories, CATEGORY_BIT_BLOCKAPP);
        pref_categories_setbit(&me->cooked_categories, CATEGORY_BIT_ALLOWAPP);

        me->cooked = PREF_COOK_SIMMER;
    }
}

/* Combines cooked prefs flags & categories with listener address and country-code/region configuration */
void
pref_cook_with_overloads(pref_t *me, const pref_t *listener_pref, pref_orgflags_t listener_overridable_orgflags,
                         pref_bundleflags_t listener_overridable_bundleflags,
                         const pref_categories_t *listener_overridable_categories, const char country_code[3],
                         uint32_t country_region, const struct confset *conf)
{
    const struct overloaded_pref *op = pref_overloads_bycc(pref_overloads_conf_get(conf, CONF_PREF_OVERLOADS), country_code, country_region);
    const pref_categories_t *base_blocked_categories, *overridable_categories;
    pref_bundleflags_t bundleflags, overridable_bundleflags;
    pref_orgflags_t orgflags, overridable_orgflags;
    pref_categories_t bbpc, opc;

    if (me->cooked == PREF_COOK_RAW)
        pref_cook(me);

    if (me->cooked == PREF_COOK_SIMMER) {
        /*-
         * Now cook myself some more based on the listener and the geo location
         *
         * XORing 'listenerbits' and 'prefbits' pulls out what we want to change.
         * ANDing with 'overridable' limits those changes.
         * XORing back into 'listenerbits' applies those sanctioned changes.
         */

        orgflags = PREF_ORG(listener_pref)->orgflags;
        overridable_orgflags = listener_overridable_orgflags;

        if (op) {
            orgflags |= op->orgflags;
            overridable_orgflags &= op->overridable_orgflags;
        }

        if (!me->org) {
            /* We have no orgflags at all, so nothing should be overridden */
            overridable_orgflags = 0;
            SXEL7("Updated org0 overidable orgflags to 0");
        }

        me->cooked_orgflags     = ((orgflags ^ me->cooked_orgflags) & overridable_orgflags) ^ orgflags;

        bundleflags             = PREF_BUNDLE(listener_pref)->bundleflags;
        overridable_bundleflags = listener_overridable_bundleflags;

        if (op) {
            bundleflags |= op->bundleflags;
            overridable_bundleflags &= op->overridable_bundleflags;
        }

        me->cooked_bundleflags = ((bundleflags ^ me->cooked_bundleflags) & overridable_bundleflags) ^ bundleflags;

        if (op) {
            pref_categories_intersect(&opc, listener_overridable_categories, &op->overridable_categories);
            overridable_categories = &opc;
            pref_categories_union(&bbpc, &PREF_BUNDLE(listener_pref)->base_blocked_categories, &op->categories);
            base_blocked_categories = &bbpc;
        } else {
            overridable_categories  = listener_overridable_categories;
            base_blocked_categories = &PREF_BUNDLE(listener_pref)->base_blocked_categories;
        }

        pref_categories_usable(&me->cooked_categories, base_blocked_categories, &me->cooked_categories, overridable_categories);
        me->cooked = PREF_COOK_BOIL;
    }
}

const struct prefbundle *
prefblock_bundle(const struct prefblock *me, actype_t actype, uint32_t id)
{
    return me ? prefbundle_get(me->resource.bundle, me->count.bundles, actype, id) : NULL;
}

const struct preforg *
prefblock_org(const struct prefblock *me, uint32_t id)
{
    return me ? preforg_get(me->resource.org, me->count.orgs, id) : NULL;
}

unsigned
prefblock_count_total(const struct prefblock *me)
{
    return me->count.lists + me->count.settinggroups + me->count.bundles + me->count.orgs + me->count.identities;
}

pref_categories_t *
pref_unmasked(const pref_t *me, pref_categories_t *unmasked)
{
    const struct preforg *org;

    pref_categories_setnone(unmasked);
    if ((org = PREF_ORG(me)) != NULL)
        pref_categories_union(unmasked, unmasked, &org->unmasked);
    if ((org = PREF_PARENTORG(me)) != NULL)
        pref_categories_union(unmasked, unmasked, &org->unmasked);
    if ((org = PREF_GLOBALORG(me)) != NULL)
        pref_categories_union(unmasked, unmasked, &org->unmasked);

    return unmasked;
}
