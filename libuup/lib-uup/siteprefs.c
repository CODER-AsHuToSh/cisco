/*
 * Description of the format of this config file:
 *   https://confluence.office.opendns.com/display/trac3/Protoss+resolver+config+file+format
 */
#include <inttypes.h>    /* Required by ubuntu */

#if __FreeBSD__
#include <sys/socket.h>
#endif

#if SXE_DEBUG
#include <arpa/inet.h>
#include <kit-bool.h>
#include <kit.h>
#endif

#include "cidr-ipv4.h"
#include "cidr-ipv6.h"
#include "odns.h"
#include "oolist.h"
#include "siteprefs-private.h"
#include "unaligned.h"
#include "xray.h"

/*
 * The 2 siteprefs key formats supported are as follows:
 *     1:<assetid>::<cidr>
 *     2:<orgid>:<asset-type>:<cidr>
 *
 * Note: For sorting ease and correctness in brain, it is necessary to have
 * an equal number of fields in all keys. Therefore type-1 key has a dummy
 * key-field at 3rd position.
 */
struct siteprefs_key {
    uint8_t type;                /* Internal network mapped to (1) a specific external identity or (2) an asset type */
    union {
        uint8_t asset[4];        /* The assetid (VA originid) in network byte order. Only used if key is type-1 */
        uint8_t orgid[4];        /* Only used if key is type-2 */
    };
    uint8_t asset_type[4];       /* The internal network origin-type-id of the asset. Only used for type-2 keys */
    union {
        struct cidr_ipv4 cidr4;
        struct cidr_ipv6 cidr6;  /* IPv4 CIDRs are identified by cidr6.maskbits == 255 - see KEY_IS_V4() and KEY_IS_V6() */
    };
} __attribute__((__packed__));

#define SIZEOF_FIRST_3_KEY_FIELDS offsetof(struct siteprefs_key, cidr4)

/*-
 * A struct siteprefs is a struct fileprefs plus a struct conf.  The fileprefs
 * part looks like this:
 *
 *  keys                         idents
 *  .-----------------.         .------------------------------------.
 *  | siteprefs_key0  |         | originid | orgid | actype | bundle |
 *  |-----------------|         |------------------------------------|
 *  | siteprefs_key1  |         | ident1                             |
 *  .                 .         .                                    .
 *  .                 .         .                                    .
 *  .-----------------.         .------------------------------------|
 *  | siteprefs_keyN  |         | identN                             |
 *  `-----------------'         `------------------------------------'
 *
 * keysz is set to sizeof(struct siteprefs_key).
 *
 * Searches are performed using bsearch() to locate a random
 * record that matches the desired VA.  We then interate
 * backwards and forwards through those records to locate the
 * relevant matches.
 */

#define SITEPREFS_KEYS(me)         ((struct siteprefs_key *)(me)->fp.keys)
#define SITEPREFS_KEY(me, i)       ((struct siteprefs_key *)(me)->fp.keys + (i))
#define KEY_MASKBITS_V4            255
#define KEY_IS_V4(k)               ((k)->cidr6.maskbits == KEY_MASKBITS_V4)
#define KEY_IS_V6(k)               ((k)->cidr6.maskbits != KEY_MASKBITS_V4)
#define CONSTCONF2SITEPREFS(confp) (const struct siteprefs *)((confp) ? (const char *)(confp) - offsetof(struct siteprefs, conf) : NULL)
#define CONF2SITEPREFS(confp)      (struct siteprefs *)((confp) ? (char *)(confp) - offsetof(struct siteprefs, conf) : NULL)

module_conf_t CONF_SITEPREFS;

static struct conf *siteprefs_allocate(const struct conf_info *info, struct conf_loader *cl);
static void siteprefs_free(struct conf *base);

static const struct conf_type siteprefsct = {
    "siteprefs",
    siteprefs_allocate,
    siteprefs_free,
};

void
siteprefs_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(&siteprefsct, NULL, name, fn, loadable,
                       LOADFLAGS_FP_ALLOW_OTHER_TYPES | LOADFLAGS_FP_ELEMENTTYPE_DOMAIN
                     | LOADFLAGS_FP_ELEMENTTYPE_APPLICATION, NULL, 0);
}

const struct siteprefs *
siteprefs_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &siteprefsct, "siteprefs_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2SITEPREFS(base);
}

/*
 * We just want to find *any* entry for the given type (assetid or orgid,asset_type).
 * This function compares the first three key-fields only. The 4th key-field
 * i.e., cidr needs to be compared separately when needed.
 */
static int
siteprefs_key_fields_compare(const void *k, const void *member)
{
    return memcmp(k, member, SIZEOF_FIRST_3_KEY_FIELDS);
}

static int
siteprefs_key_cidr_compare(const void *vk, const void *vmember)
{
    const struct siteprefs_key *k = vk;
    const struct siteprefs_key *member = vmember;

    /* v6 always compares as less than v4 */
    if (KEY_IS_V6(k)) {
        if (KEY_IS_V4(member))
            return -1;
#ifdef __linux__
        return cidr_ipv6_sort_compar_r(&k->cidr6, &member->cidr6, NULL);
#else
        return cidr_ipv6_sort_compar_r(NULL, &k->cidr6, &member->cidr6);
#endif
    } else if (KEY_IS_V6(member))
        return 1;

#ifdef __linux__
    return cidr_ipv4_sort_compar_r(&k->cidr4, &member->cidr4, NULL);
#else
    return cidr_ipv4_sort_compar_r(NULL, &k->cidr4, &member->cidr4);
#endif
}

/**
 * Determine whether key's CIDR contains member's IP address (the start of it's CIDR range).
 *
 * @return true If key contains member, false if not or if they are not both V6 or V4 addresses
 */
static bool
siteprefs_key_cidr_contains(const struct siteprefs_key *key, const struct siteprefs_key *member)
{
    if (KEY_IS_V6(key)) {
        if (KEY_IS_V4(member))
            return false;

        return cidr_ipv6_contains_net(&key->cidr6, &member->cidr6);
    }

    if (KEY_IS_V6(member))
        return false;         /* COVERAGE EXCLUSION: Can't happen due to IP V6 CIDRs always preceding V4 CIDRs in siteprefs */

    return CIDR_IPV4_CONTAINS_NET(&key->cidr4, &member->cidr4);
}

static const char *
siteprefs_key_cidr_to_str(const struct siteprefs_key *key)
{
    return KEY_IS_V6(key) ? cidr_ipv6_to_str(&key->cidr6, false) : cidr_ipv4_to_str(&key->cidr4, false);
}

/* Convert a key to a string. Allow up to the last 4 returned strings coexist, so that this can be used by kit_sortedarray
 */
static const char *
siteprefs_key_to_str(const void *vkey)
{
    static __thread char        txt[4][INET6_ADDRSTRLEN + sizeof("1:4294967295::4294967295:[]/128") - 1];
    static __thread int         last = 3;
    const struct siteprefs_key *key  = vkey;
    size_t                      off;

    last = (last + 1) % 4;

    if (key->type == SITEPREFS_KEY_TYPE1)
        off = snprintf(txt[last], sizeof(txt[last]), "%u:%" PRIu32 ":", key->type, unaligned_ntohl(key->asset));
    else
        off = snprintf(txt[last], sizeof(txt[last]), "%u:%" PRIu32 ":%" PRIu32, key->type, unaligned_ntohl(key->orgid),
                       unaligned_ntohl(key->asset_type));

    if (off < sizeof(txt[last]))
        off += snprintf(txt[last] + off, sizeof(txt[last]) - off, ":%s", siteprefs_key_cidr_to_str(key));

    return txt[last];
}

static int
siteprefs_key_compare(const void *vk, const void *vmember)
{
    const struct siteprefs_key *k = vk;
    const struct siteprefs_key *member = vmember;
    int ret;

    if ((ret = siteprefs_key_fields_compare(k, member)) == 0)
        ret = siteprefs_key_cidr_compare(k, member);

    SXEL7("siteprefs_key_compare(%s, %s) returns %d", siteprefs_key_to_str(k), siteprefs_key_to_str(member), ret);
    return ret;
}

/* Class structure to allow siteprefs identities index to be used as a sorted array
 */
static struct kit_sortedelement_class siteprefs_key_class = {
    .size      = sizeof(struct siteprefs_key),    // Sizeof the element
    .keyoffset = 0,                               // Offset of the key within the element
    .cmp       = siteprefs_key_compare,           // Comparitor for element keys
    .fmt       = siteprefs_key_to_str,            // Formatter for element keys; return the LRU of 4 static buffers
};

static bool
siteprefs_matched(const struct siteprefs *me, uint8_t type, int item, pref_t *pref, struct oolist **other_origins,
                  struct xray *x)
{
    pref_t                   pref_new;
    const struct prefbundle *bundle_cur, *bundle_new;
    struct prefidentity     *ident;

    pref_init_byidentity(&pref_new, me->fp.values, NULL, NULL, item);
    oolist_add(other_origins, &pref_new, ORIGIN_SRC_SITE);
    bundle_cur = PREF_BUNDLE(pref);
    bundle_new = PREF_BUNDLE(&pref_new);
    ident      = PREF_IDENT(&pref_new);
    XRAY7(x, "siteprefs match: found: bundle %x:%d, priority %u, origin %u for candidate item %u with cidr %s%s",
          ident->actype, bundle_new->id, bundle_new->priority, ident->originid, item,
          siteprefs_key_cidr_to_str(SITEPREFS_KEY(me, item)), type == SITEPREFS_KEY_TYPE1 ? "" : " (type 2)" );

    /* If there is no current pref or the new one is better
     */
    if (bundle_cur == NULL || bundle_new->priority < bundle_cur->priority) {
        *pref = pref_new;
        return true;
    }

    return false;
}

/* Lookup a preference based on the IDs passed along from the forwarder.
 */
bool
siteprefs_get(pref_t *pref, const struct siteprefs *me, struct odns *odns, struct oolist **other_origins, struct xray *x)
{
    struct siteprefs_key     key;
    unsigned                 found;
    int                      item;
    bool                     matched_key;

    SXEE7("(pref=?,me=%p,odns={%s},other_origins=%p,x=?)", me, odns ? odns_content(odns) : "NULL", *other_origins);
    pref_fini(pref);

    if (me && odns && odns->fields & ODNS_FIELD_VA && odns->fields & (ODNS_FIELD_REMOTEIP4 | ODNS_FIELD_REMOTEIP6)) {
        key.type = SITEPREFS_KEY_TYPE1;
        unaligned_htonl(&key.asset, odns->va_id);
        unaligned_htonl(&key.asset_type, 0U);        // This is an unused key-field in type-1 key

        if (odns->remoteip.family == AF_INET) {
            key.cidr4.addr     = ntohl(odns->remoteip.in_addr.s_addr);
            key.cidr4.mask     = ~0U;
            key.cidr6.maskbits = KEY_MASKBITS_V4;    // Special value that signifies that this is a V4 CIDR
        } else {
            SXEA6(odns->remoteip.family == AF_INET6, "Expected odns->remoteip.family to be either AF_INET or AF_INET6");
            key.cidr6.addr     = odns->remoteip.in6_addr;
            key.cidr6.maskbits = 128;
        }

        /* Find the exact match (unlikely) or the first key that is greater than the one we're looking up.
         */
        found = kit_sortedarray_find(&siteprefs_key_class, me->fp.keys, PREFS_COUNT(me, identities), &key, &matched_key);

        if (matched_key)    // Jackpot: There's a cidr whose key is an exact match
            siteprefs_matched(me, key.type, found, pref, other_origins, x);

        /* While there is a key less than or equal to the search key whose type/asset matches
         */
        for (item = found - 1; item >= 0 && siteprefs_key_fields_compare(SITEPREFS_KEY(me, item), &key) == 0; item--)
            if (siteprefs_key_cidr_contains(SITEPREFS_KEY(me, item), &key))   // If the CIDR contains the key
                if (siteprefs_matched(me, key.type, item, pref, other_origins, x))
                    matched_key = true;

        if (!matched_key) {
            SXEL7(": debug: va %u with cidr %s doesn't match", odns->va_id, siteprefs_key_cidr_to_str(&key));
            goto OUT;
        }

        /* Lookup the type-2 index using the asset-type and orgid from the type-1 result, finding the most-specific CIDR match
         */
        key.type = SITEPREFS_KEY_TYPE2;
        unaligned_htonl(&key.orgid, PREF_ORG(pref) ? PREF_ORG(pref)->id : 0);
        unaligned_htonl(&key.asset_type, PREF_IDENT(pref)->origintypeid);

        /* Find the exact match (unlikely) or the first key that is greater than the one we're looking up.
         */
        found = kit_sortedarray_find(&siteprefs_key_class, me->fp.keys, PREFS_COUNT(me, identities), &key, &matched_key);

        if (matched_key)    // Jackpot: There's a cidr whose key is an exact match
            siteprefs_matched(me, key.type, found, pref, other_origins, x);

        /* While there is a key less than or equal to the search key whose type/asset matches
         */
        for (item = found - 1; item >= 0 && siteprefs_key_fields_compare(SITEPREFS_KEY(me, item), &key) == 0; item--)
            if (siteprefs_key_cidr_contains(SITEPREFS_KEY(me, item), &key))    // If the CIDR contains the key
                siteprefs_matched(me, key.type, item, pref, other_origins, x);
    }

OUT:
    if (PREF_VALID(pref))
        XRAY7(x, "siteprefs match: using: bundle %x:%d, priority %u, origin %u",
              PREF_IDENT(pref)->actype, PREF_BUNDLE(pref)->id, PREF_BUNDLE(pref)->priority, PREF_IDENT(pref)->originid);
    else if (!me)
        SXEL7("siteprefs match: none (no siteprefs)");
    else if (!odns)
        SXEL7("siteprefs match: none (no EDNS)");
    else if (odns->fields & ODNS_FIELD_VA && odns->fields & ODNS_FIELD_REMOTEIP4)
        SXEL7("siteprefs match: none");
    else
        SXEL7("siteprefs match: none (inappropriate EDNS fields)");

    SXER7("return %s // %s, pref { %p, %p, %p, %u }", kit_bool_to_str(PREF_VALID(pref)),
          PREF_VALID(pref) ? "valid" : "invalid", pref->blk, pref->parentblk, pref->globalblk, pref->index);
    return PREF_VALID(pref);
}

const struct preforg *
siteprefs_org(const struct siteprefs *me, uint32_t id)
{
    return me ? prefblock_org(me->fp.values, id) : NULL;
}

static const char *
siteprefs_parse_cidr(const struct conf_loader *cl, struct siteprefs *me, struct siteprefs_key *k, const char *field)
{
    const char *p;

    if ((p = cidr_ipv4_sscan_verbose(&k->cidr4, conf_loader_path(cl), conf_loader_line(cl), field, PARSE_CIDR_ONLY)) != NULL && *p++ == ':') {
        k->cidr6.maskbits = 255;    /* Marked as an IPv4 CIDR */
    } else if ((p = cidr_ipv6_sscan_verbose(&k->cidr6, conf_loader_path(cl), conf_loader_line(cl), field, PARSE_CIDR_ONLY)) == NULL || *p++ != ':') {
        SXEL2("%s(): siteprefs v%u: %s: %u: Unrecognised line (invalid CIDR)", __FUNCTION__, me->fp.version, conf_loader_path(cl), conf_loader_line(cl));
        return NULL;
    }
    return p;
}

static int
siteprefs_parsekey(struct fileprefs *fp, int item, const struct conf_loader *cl, const char *line)
{
    struct siteprefs *me = (struct siteprefs *)fp;
    struct siteprefs_key *k = SITEPREFS_KEY(me, item);
    int consumed, consumed2, cmp, ret = 0;
    uint32_t assetid, asset_type, orgid;
    const char *p;
    char colon;

    SXEA6(fp->version == SITEPREFS_VERSION, "Trying to parse siteprefs key for version %u", fp->version);

    if (sscanf(line, "1:%" PRIu32 ":%c%n", &assetid, &colon, &consumed) == 2 && colon == ':') {
        k->type = SITEPREFS_KEY_TYPE1;
        unaligned_htonl(k->asset, assetid);
        unaligned_htonl(k->asset_type, 0U); // This is an unused key-field in type-1 key
        if(!(p = siteprefs_parse_cidr(cl, me, k, line + consumed)))
            return 0;
        ret = p - line;
    } else if (sscanf(line, "2:%" PRIu32 "%c%n", &orgid, &colon, &consumed) == 2 && colon == ':') {
        k->type = SITEPREFS_KEY_TYPE2;
        unaligned_htonl(k->orgid, orgid);
        if (sscanf(line + consumed, "%" PRIu32 "%c%n", &asset_type, &colon, &consumed2) != 2 || colon != ':') {
            SXEL2("%s(): siteprefs v%u: %s: %u: Unrecognised line (invalid asset_type)", __FUNCTION__, me->fp.version, conf_loader_path(cl), conf_loader_line(cl));
            return 0;
        }
        unaligned_htonl(k->asset_type, asset_type);

        if(!(p = siteprefs_parse_cidr(cl, me, k, line + consumed + consumed2)))
            return 0;
        ret = p - line;
    }  else {
        SXEL2("%s(): siteprefs v%u: %s: %u: Unrecognised line (invalid assetid or orgid)", __FUNCTION__, me->fp.version, conf_loader_path(cl), conf_loader_line(cl));
        return 0;
    }

    if (item && (cmp = siteprefs_key_compare(k - 1, k)) >= 0) {
        SXEL2("%s(): siteprefs v%u: %s: %u: Invalid line (%s%s)", __FUNCTION__, me->fp.version,
              conf_loader_path(cl), conf_loader_line(cl), cmp ? "out of order" : "duplicate",
              KEY_IS_V4(k - 1) && KEY_IS_V6(k) ? " - v6 CIDRs must preceed v4 CIDRs" : "");
        return 0;
    }
    return ret;
}

/* Given a fileprefs and a key index, return the key as a string
 */
static const char *
siteprefs_get_key_as_str(struct fileprefs *fp, unsigned i)
{
    struct siteprefs *me = (struct siteprefs *)fp;

    SXEA6(i < FILEPREFS_COUNT(fp, identities), ": key %u is out of range; need less than %u", i, FILEPREFS_COUNT(fp, identities));
    return siteprefs_key_to_str(SITEPREFS_KEY(me, i));
}

static struct fileprefops siteprefs_ops = {
    .type               = "siteprefs",
    .keysz              = sizeof(struct siteprefs_key),
    .parsekey           = siteprefs_parsekey,
    .key_to_str         = siteprefs_get_key_as_str,
    .free               = fileprefs_free,
    .supported_versions = { SITEPREFS_VERSION, 0 }
};

static struct conf *
siteprefs_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct siteprefs *me;

    SXEA6(info->type == &siteprefsct, "%s() with unexpected conf_type %s", __FUNCTION__, info->type->name);

    if ((me = siteprefs_new(cl, info->loadflags)) != NULL)
        conf_report_load(me->fp.ops->type, me->fp.version);

    return me ? &me->conf : NULL;
}

struct siteprefs *
siteprefs_new(struct conf_loader *cl, unsigned loadflags)
{
    struct siteprefs *me;

    if ((me = (struct siteprefs *)fileprefs_new(cl, &siteprefs_ops, sizeof(*me), loadflags)) != NULL)
        conf_setup(&me->conf, &siteprefsct);

    return me;
}

static void
siteprefs_free(struct conf *base)
{
    struct siteprefs *me = CONF2SITEPREFS(base);

    fileprefs_free(&me->fp);
}

void
siteprefs_refcount_inc(struct siteprefs *me)
{
    CONF_REFCOUNT_INC(me);
}

void
siteprefs_refcount_dec(struct siteprefs *me)
{
    CONF_REFCOUNT_DEC(me);
}

const struct prefblock *
siteprefs_get_prefblock(const struct siteprefs *me, uint32_t orgid)
{
    SXE_UNUSED_PARAMETER(orgid);

    return me ? me->fp.values : NULL;
}
