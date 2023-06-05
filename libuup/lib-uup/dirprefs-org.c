#include <inttypes.h>    /* Required by ubuntu */

#include "conf-loader.h"
#include "dirprefs-org.h"
#include "odns.h"
#include "unaligned.h"
#include "xray.h"

struct dirprefs_org_key {
    uint8_t orgid[4];
    uint8_t type;
    union {
        uint8_t         asset[4];
        struct kit_guid guid;
        struct kit_md5  alt_uid;
    } id;
};

#define DIRPREFS_ORG_KEYS(fp)     ((struct dirprefs_org_key *)(fp)->keys)
#define DIRPREFS_ORG_KEY(fp, i)   ((struct dirprefs_org_key *)(fp)->keys + (i))

/* Compare two keys */
static int
dirprefs_org_compare(const void *k, const void *member)
{
    size_t cmpsize = 0;
    const struct dirprefs_org_key *key = (const struct dirprefs_org_key *)k;

    /* Determine how much of the key structure to compare based on its type */
    switch (key->type) {
    case DIRPREFS_TYPE_ORG:
        cmpsize = sizeof(key->orgid) + sizeof(key->type);
        break;
    case DIRPREFS_TYPE_ASSET:
        cmpsize = sizeof(key->orgid) + sizeof(key->type) + sizeof(key->id.asset);
        break;
    case DIRPREFS_TYPE_GUID:
    case DIRPREFS_TYPE_ALT_UID:
        cmpsize = sizeof(struct dirprefs_org_key);
        break;
    }

    return memcmp(key, member, cmpsize);
}

#if SXE_DEBUG
static const char *
dirprefs_key_to_str(struct dirprefs_org_key *k)
{
    static __thread char str[128];

    switch (k->type) {
    case DIRPREFS_TYPE_ORG:
        snprintf(str, sizeof(str), "ORG: %02hhx%02hhx%02hhx%02hhx:0::",
                 k->orgid[0], k->orgid[1], k->orgid[2], k->orgid[3]);
        break;
    case DIRPREFS_TYPE_ASSET:
        snprintf(str, sizeof(str), "ASSET: %02hhx%02hhx%02hhx%02hhx:1:%02hhx%02hhx%02hhx%02hhx:",
                 k->orgid[0], k->orgid[1], k->orgid[2], k->orgid[3],
                 k->id.asset[0], k->id.asset[1], k->id.asset[2], k->id.asset[3]);
        break;
    case DIRPREFS_TYPE_GUID:
        snprintf(str, sizeof(str), "GUID: %02hhx%02hhx%02hhx%02hhx:2:%s:",
                 k->orgid[0], k->orgid[1], k->orgid[2], k->orgid[3],
                 kit_guid_to_str(&k->id.guid));
        break;
    case DIRPREFS_TYPE_ALT_UID:
        snprintf(str, sizeof(str), "ALT_UID: H%02hhx%02hhx%02hhx%02hhx:3:%s:",
                 k->orgid[0], k->orgid[1], k->orgid[2], k->orgid[3],
                 kit_md5_to_str(&k->id.alt_uid));
        break;
    }

    return str;
}
#endif

static int    /* returns # bytes consumed */
dirprefs_org_parsekey(struct fileprefs *fp, int item, const struct conf_loader *cl, const char *line)
{
    struct dirprefs_org_key *k = DIRPREFS_ORG_KEY(fp, item);
    int cmp, consumed;
    uint32_t orgid, assetid;
    char colon;

    SXEA6(fp->version == DIRPREFS_VERSION, "Trying to parse dirprefs-org key for version %u", fp->version);

    if (sscanf(line, "%" PRIu32 ":0:%c%n", &orgid, &colon, &consumed) == 2 && colon == ':') {
        k->type = DIRPREFS_TYPE_ORG;
        unaligned_htonl(k->orgid, orgid);
    } else if (sscanf(line, "%" PRIu32 ":1:%" PRIu32 "%c%n", &orgid, &assetid, &colon, &consumed) == 3 && colon == ':') {
        k->type = DIRPREFS_TYPE_ASSET;
        unaligned_htonl(k->orgid, orgid);
        unaligned_htonl(k->id.asset, assetid);
    } else if (sscanf(line,
                      "%" PRIu32 ":2:%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%c%n",
                      &orgid,
                      &k->id.guid.bytes[0],  &k->id.guid.bytes[1],  &k->id.guid.bytes[2],  &k->id.guid.bytes[3],
                      &k->id.guid.bytes[4],  &k->id.guid.bytes[5],  &k->id.guid.bytes[6],  &k->id.guid.bytes[7],
                      &k->id.guid.bytes[8],  &k->id.guid.bytes[9],  &k->id.guid.bytes[10], &k->id.guid.bytes[11],
                      &k->id.guid.bytes[12], &k->id.guid.bytes[13], &k->id.guid.bytes[14], &k->id.guid.bytes[15],
                      &colon, &consumed) == 18 && colon == ':') {
        k->type = DIRPREFS_TYPE_GUID;
        unaligned_htonl(k->orgid, orgid);
    } else if (sscanf(line,
                      "%" PRIu32 ":3:H%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%c%n",
                      &orgid,
                      &k->id.alt_uid.bytes[0],  &k->id.alt_uid.bytes[1],  &k->id.alt_uid.bytes[2],  &k->id.alt_uid.bytes[3],
                      &k->id.alt_uid.bytes[4],  &k->id.alt_uid.bytes[5],  &k->id.alt_uid.bytes[6],  &k->id.alt_uid.bytes[7],
                      &k->id.alt_uid.bytes[8],  &k->id.alt_uid.bytes[9],  &k->id.alt_uid.bytes[10], &k->id.alt_uid.bytes[11],
                      &k->id.alt_uid.bytes[12], &k->id.alt_uid.bytes[13], &k->id.alt_uid.bytes[14], &k->id.alt_uid.bytes[15],
                      &colon, &consumed) == 18 && colon == ':') {
        k->type = DIRPREFS_TYPE_ALT_UID;
        unaligned_htonl(k->orgid, orgid);
    } else {
        SXEL2("%s(): dirprefs v%u: %s: %u: Unrecognised line (invalid key format)", __FUNCTION__, fp->version, conf_loader_path(cl), conf_loader_line(cl));
        return 0;
    }

    SXEL7("%s(){} // key: %s", __FUNCTION__, dirprefs_key_to_str(k));

    if (item && (cmp = dirprefs_org_compare(k - 1, k)) >= 0) {
        SXEL2("%s(): dirprefs v%u: %s: %u: Invalid line (%s)", __FUNCTION__, fp->version,
              conf_loader_path(cl), conf_loader_line(cl), cmp ? "out of order" : "duplicate");
        return 0;
    }

    return consumed;
}

static char
dirprefs_type2txt(enum dirprefs_type type)
{
    return '0' + type;
}

static const char *
dirprefs_org_key_to_str(struct fileprefs *fp, unsigned i)
{
    static __thread char txt[46];
    struct dirprefs_org_key *key;
    size_t off;

    SXEA6(i < FILEPREFS_COUNT(fp, identities), "%s(): key %u is out of range; need less than %u", __FUNCTION__, i, FILEPREFS_COUNT(fp, identities));
    key = DIRPREFS_ORG_KEY(fp, i);

    *txt = '\0';
    off = snprintf(txt, sizeof(txt), "%" PRIu32 ":%c:", unaligned_ntohl(key->orgid), dirprefs_type2txt(key->type));
    if (off < sizeof(txt))
        switch (key->type) {
        case DIRPREFS_TYPE_ASSET:
            snprintf(txt + off, sizeof(txt) - off, "%" PRIu32, unaligned_ntohl(key->id.asset));
            break;
        case DIRPREFS_TYPE_GUID:
            snprintf(txt + off, sizeof(txt) - off, "%s", kit_guid_to_str(&key->id.guid));
            break;
        case DIRPREFS_TYPE_ALT_UID:
            snprintf(txt + off, sizeof(txt) - off, "H%s", kit_md5_to_str(&key->id.alt_uid));
            break;
        }

    return txt;
}

static struct fileprefops dirprefs_org_ops = {
    .type               = "dirprefs",
    .keysz              = sizeof(struct dirprefs_org_key),
    .parsekey           = dirprefs_org_parsekey,
    .key_to_str         = dirprefs_org_key_to_str,
    .free               = fileprefs_free,
    .supported_versions = { DIRPREFS_VERSION, 0 }
};

void *
dirprefs_org_new(uint32_t orgid, struct conf_loader *cl, const struct conf_info *info)
{
    struct prefs_org *dpo;

    if ((dpo = (struct prefs_org *)fileprefs_new(cl, &dirprefs_org_ops, sizeof(struct prefs_org), info->loadflags))) {
        conf_segment_init(&dpo->cs, orgid, cl, dpo->fp.loadflags & LOADFLAGS_FP_FAILED);

        if (!(dpo->fp.loadflags & LOADFLAGS_FP_FAILED) && !prefs_org_valid(dpo, conf_loader_path(cl)))
            dpo->fp.loadflags |= LOADFLAGS_FP_FAILED;
    }

    return dpo;
}

/*
 * Lookup a preference based on the IDs passed along from the forwarder.
 */
const char *
dirprefs_org_get(pref_t *pref, const struct prefs_org *me, const struct odns *odns, struct oolist **other_origins, enum dirprefs_type *type, struct xray *x)
{
    struct dirprefs_org_key find, *match;
    const struct prefidentity *ident;
    const struct prefbundle *bundle;
    const char *best_what, *what;
    pref_t p;

    SXEE7("(pref=? me=%p odns=%p other_origins=%p, type=?, x=?)", me, odns, *other_origins);

    best_what = "<unknown>";
    pref_fini(pref);
    unaligned_htonl(&find.orgid, odns->org_id);

    if (odns->fields & ODNS_FIELD_ALT_UID) {
        find.type = DIRPREFS_TYPE_ALT_UID;
        find.id.alt_uid = odns->alt_user_id;

        if ((match = bsearch(&find, me->fp.keys, PREFS_COUNT(me, identities), sizeof(find), dirprefs_org_compare)) != NULL) {
            pref_init_byidentity(&p, me->fp.values, NULL, NULL, match - DIRPREFS_ORG_KEYS(&me->fp));
            ident = PREF_IDENT(&p);
            bundle = PREF_BUNDLE(&p);
            oolist_add(other_origins, &p, ORIGIN_SRC_AD_ALTUID);
            what = "alt_uid";
            XRAY7(x, "dirprefs match: found: bundle %x:%d, priority %u, origin %u for %s", ident->actype, bundle->id, bundle->priority, ident->originid, what);
            if (!PREF_VALID(pref) || bundle->priority < PREF_BUNDLE(pref)->priority) {
                *type = DIRPREFS_TYPE_ALT_UID;
                *pref = p;
                best_what = what;
            }
        }
    }

    if (odns->fields & ODNS_FIELD_USER) {
        find.type    = DIRPREFS_TYPE_GUID;
        find.id.guid = odns->user_id;

        if ((match = bsearch(&find, me->fp.keys, PREFS_COUNT(me, identities), sizeof(find), dirprefs_org_compare)) != NULL) {
            pref_init_byidentity(&p, me->fp.values, NULL, NULL, match - DIRPREFS_ORG_KEYS(&me->fp));
            ident = PREF_IDENT(&p);
            bundle = PREF_BUNDLE(&p);
            oolist_add(other_origins, &p, ORIGIN_SRC_AD_USER);
            what = "user";
            XRAY7(x, "dirprefs match: found: bundle %x:%d, priority %u, origin %u for %s", ident->actype, bundle->id, bundle->priority, ident->originid, what);
            if (!PREF_VALID(pref) || bundle->priority < PREF_BUNDLE(pref)->priority) {
                *type = DIRPREFS_TYPE_GUID;
                *pref = p;
                best_what = what;
            }
        }
    }

    if (odns->fields & ODNS_FIELD_HOST) {
        find.type    = DIRPREFS_TYPE_GUID;
        find.id.guid = odns->host_id;

        if ((match = bsearch(&find, me->fp.keys, PREFS_COUNT(me, identities), sizeof(find), dirprefs_org_compare)) != NULL) {
            pref_init_byidentity(&p, me->fp.values, NULL, NULL, match - DIRPREFS_ORG_KEYS(&me->fp));
            ident = PREF_IDENT(&p);
            bundle = PREF_BUNDLE(&p);
            oolist_add(other_origins, &p, ORIGIN_SRC_AD_HOST);
            what = "host";
            XRAY7(x, "dirprefs match: found: bundle %x:%d, priority %u, origin %u for %s", ident->actype, bundle->id, bundle->priority, ident->originid, what);
            if (!PREF_VALID(pref) || bundle->priority < PREF_BUNDLE(pref)->priority) {
                *type = DIRPREFS_TYPE_GUID;
                *pref = p;
                best_what = what;
            }
        }
    }

    if (odns->fields & ODNS_FIELD_VA) {
        if (!PREF_VALID(pref) || PREF_BUNDLE(pref)->priority > 0) {
            find.type = DIRPREFS_TYPE_ASSET;
            unaligned_htonl(&find.id, odns->va_id);
            if ((match = bsearch(&find, me->fp.keys, PREFS_COUNT(me, identities), sizeof(find), dirprefs_org_compare)) != NULL) {
                pref_init_byidentity(&p, me->fp.values, NULL, NULL, match - DIRPREFS_ORG_KEYS(&me->fp));
                ident = PREF_IDENT(&p);
                bundle = PREF_BUNDLE(&p);
                oolist_add(other_origins, &p, ORIGIN_SRC_AD_VA);    /* This is a no-op as ident->originid *SHOULD* be the same as odns->va_id... right? */
                what = "asset";
                XRAY7(x, "dirprefs match: found: bundle %x:%d, priority %u, origin %u for %s", ident->actype, bundle->id, bundle->priority, ident->originid, what);
                if (!PREF_VALID(pref) || bundle->priority < PREF_BUNDLE(pref)->priority) {
                    *type = DIRPREFS_TYPE_ASSET;
                    *pref = p;
                    best_what = what;
                }
            }
        }
    }

    /* Note, there are no known DIRPREFS_TYPE_ORG entries in production dirprefs files */
    find.type = DIRPREFS_TYPE_ORG;
    if ((match = bsearch(&find, me->fp.keys, PREFS_COUNT(me, identities), sizeof(find), dirprefs_org_compare)) != NULL) {
        pref_init_byidentity(&p, me->fp.values, NULL, NULL, match - DIRPREFS_ORG_KEYS(&me->fp));
        ident = PREF_IDENT(&p);
        bundle = PREF_BUNDLE(&p);
        oolist_add(other_origins, &p, ORIGIN_SRC_AD_ORG);
        what = "org";
        XRAY7(x, "dirprefs match: found: bundle %x:%d, priority %u, origin %u for %s", ident->actype, bundle->id, bundle->priority, ident->originid, what);
        if (!PREF_VALID(pref) || bundle->priority < PREF_BUNDLE(pref)->priority) {
            *type = DIRPREFS_TYPE_ORG;
            *pref = p;
            best_what = what;
        }
    }

    if (PREF_VALID(pref))
        SXEL6("dirprefs match: using: pref %p, priority %u, origin %u for %s", PREF_IDENT(pref), PREF_BUNDLE(pref)->priority, PREF_IDENT(pref)->originid, best_what);
    else
        XRAY6(x, "dirprefs match: none");

    SXER7("return %d // %s, pref { %p, %p, %p, %u }", PREF_VALID(pref), PREF_VALID(pref) ? "valid" : "invalid", pref->blk, pref->parentblk, pref->globalblk, pref->index);
    return PREF_VALID(pref) ? best_what : NULL;
}
