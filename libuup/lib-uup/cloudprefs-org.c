#include <inttypes.h>    /* Required by ubuntu */
#include <stdio.h>

#include "cloudprefs-org.h"
#include "xray.h"

struct cloudprefs_org_key {
    uint32_t originid;
};

#define CLOUDPREFS_ORG_KEYS(fp)     ((struct cloudprefs_org_key *)(fp)->keys)
#define CLOUDPREFS_ORG_KEY(fp, i)   ((struct cloudprefs_org_key *)(fp)->keys + (i))

/* Compare two keys */
static int
cloudprefs_org_compare(const void *k, const void *member)
{
    const struct cloudprefs_org_key *key = k;
    const struct cloudprefs_org_key *m = member;

    return key->originid - m->originid;
}

static int    /* returns # bytes consumed */
cloudprefs_org_parsekey(struct fileprefs *fp, int item, const struct conf_loader *cl, const char *line)
{
    struct cloudprefs_org_key *k = CLOUDPREFS_ORG_KEY(fp, item);
    uint32_t orgid, originid;
    int cmp, consumed;
    char colon;

    SXEA6(fp->version == CLOUDPREFS_VERSION, "Trying to parse cloudprefs-origin key for version %u", fp->version);

    if (sscanf(line, "%" PRIu32 ":%" PRIu32 "%c%n", &orgid, &originid, &colon, &consumed) == 3 && colon == ':')
        k->originid =  originid;
    else {
        SXEL2("%s(): cloudprefs v%u: %s: %u: Unrecognised line (invalid key format)", __FUNCTION__, fp->version, conf_loader_path(cl), conf_loader_line(cl));
        return 0;
    }

    SXEL7("%s(){} // key: %x", __FUNCTION__, k->originid);

    if (item && (cmp = cloudprefs_org_compare(k - 1, k)) >= 0) {
        SXEL2("%s(): cloudprefs v%u: %s: %u: Invalid line (%s)", __FUNCTION__, fp->version,
              conf_loader_path(cl), conf_loader_line(cl), cmp ? "out of order" : "duplicate");
        return 0;
    }

    return consumed;
}

const char *
cloudprefs_org_key_to_str(struct fileprefs *fp, unsigned i)
{
    static __thread char txt[12];
    struct cloudprefs_org_key *key;

    SXEA6(i < FILEPREFS_COUNT(fp, identities), "%s(): key %u is out of range; need less than %u", __FUNCTION__, i, FILEPREFS_COUNT(fp, identities));
    key = CLOUDPREFS_ORG_KEY(fp, i);

    snprintf(txt, sizeof(txt), "%" PRIu32 ":", key->originid);

    return txt;
}

static struct fileprefops cloudprefs_org_ops = {
    .type               = "cloudprefs",
    .keysz              = sizeof(struct cloudprefs_org_key),
    .parsekey           = cloudprefs_org_parsekey,
    .key_to_str         = cloudprefs_org_key_to_str,
    .free               = fileprefs_free,
    .supported_versions = { CLOUDPREFS_VERSION, 0 }
};

void *
cloudprefs_org_new(uint32_t originid, struct conf_loader *cl, const struct conf_info *info)
{
    struct prefs_org *cpo;

    if ((cpo = (struct prefs_org *)fileprefs_new(cl, &cloudprefs_org_ops, sizeof(struct prefs_org), info->loadflags))) {
        conf_segment_init(&cpo->cs, originid, cl, cpo->fp.loadflags & LOADFLAGS_FP_FAILED);

        if (!(cpo->fp.loadflags & LOADFLAGS_FP_FAILED)) {
            if (cpo->cs.id == 0) {
                /* Prefs for org zero should have no org entries */
                if (cpo->fp.values->count.orgs != 0) {
                    SXEL2("%s: Expected zero org entries in 'orgs' section for org 0 but found %u", conf_loader_path(cl), cpo->fp.values->count.orgs);
                    cpo->fp.loadflags |= LOADFLAGS_FP_FAILED;
                }
            } else if (!prefs_org_valid(cpo, conf_loader_path(cl)))
                cpo->fp.loadflags |= LOADFLAGS_FP_FAILED;
        }
    }

    return cpo;
}

/*
 * Lookup a preference based on the origin id (from the EDNS0 IDs).
 */
const char *
cloudprefs_org_get(pref_t *pref, const struct prefs_org *me, const char *name, uint32_t origin_id, struct oolist **other_origins, struct xray *x)
{
    struct cloudprefs_org_key find, *match;
    const struct prefidentity *ident;
    const struct prefbundle *bundle;
    const char *what;
    pref_t p;

    SXEE7("(pref=?, me=%p, name=%s, origin_id=%u, other_origins=%p, x=%p)", me, name, origin_id, *other_origins, x);
    what = "<unknown>";
    pref_fini(pref);
    find.originid = origin_id;

    if ((match = bsearch(&find, me->fp.keys, PREFS_COUNT(me, identities), sizeof(find), cloudprefs_org_compare)) != NULL) {
        pref_init_byidentity(&p, me->fp.values, NULL, NULL, match - CLOUDPREFS_ORG_KEYS(&me->fp));
        ident = PREF_IDENT(&p);
        bundle = PREF_BUNDLE(&p);
        oolist_add(other_origins, &p, ORIGIN_SRC_AD_ORG);
        what = "origin";
        XRAY7(x, "%s match: found: bundle %x:%d, priority %u, origin %u for %s", name, ident->actype, bundle->id,
              bundle->priority, ident->originid, what);
        *pref = p;
    }

    if (PREF_VALID(pref))
        SXEL6("%s match: using: pref %p, priority %u, origin %u for %s", name, PREF_IDENT(pref),
              PREF_BUNDLE(pref)->priority, PREF_IDENT(pref)->originid, what);
    else
        XRAY6(x, "%s match: no such origin", name);

    SXER7("return %d // %s, pref { %p, %p, %p, %u }", PREF_VALID(pref), PREF_VALID(pref) ? "valid" : "invalid", pref->blk,
          pref->parentblk, pref->globalblk, pref->index);
    return PREF_VALID(pref) ? what : NULL;
}
