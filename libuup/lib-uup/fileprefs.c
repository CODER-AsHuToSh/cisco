#include <errno.h>
#include <kit-alloc.h>
#include <mockfail.h>

#if SXE_DEBUG
#include <kit-bool.h>
#endif

#include "cidrlist.h"
#include "fileprefs.h"
#include "object-hash.h"
#include "uint32list.h"
#include "urllist.h"

#define SUM_BYTES_MAX  64      /* Maximum size of fingerprint for list content (up to SHA512 in future) */
#define OKVERS_INCR    5

static struct object_hash *applicationlisthash;
static struct object_hash *cidrlisthash;
static struct object_hash *domainlisthash;
static struct object_hash *urllisthash;

void
fileprefs_freehashes(void)
{
    /* They had better be empty! */
    object_hash_free(applicationlisthash);
    applicationlisthash = NULL;
    object_hash_free(cidrlisthash);
    cidrlisthash = NULL;
    object_hash_free(domainlisthash);
    domainlisthash = NULL;
    object_hash_free(urllisthash);
    urllisthash = NULL;
}

static bool strict_prefs_enabled;

void
fileprefs_set_strict(bool enabled)
{
    strict_prefs_enabled = enabled;
}

void
fileprefs_free(struct fileprefs *me)
{
    unsigned i;

    SXEE7("(me=?) // count.identities=%u type=%s count.lists=%u", FILEPREFS_COUNT(me, identities), me->ops->type, FILEPREFS_COUNT(me, lists));

    /*
     * Every list has a reference to an applicationlist, cidrlist, domainlist, or urllist.
     * (domain|cidr|url|uint32)list refcounts are all owned at the list level.
     */
    for (i = 0; i < FILEPREFS_COUNT(me, lists); i++)
        preflist_refcount_dec(&me->values->resource.list[i]);

    kit_free(me->keys);
    prefblock_free(me->values);
    kit_free(me);

    SXER7("return");
}

/*
 * Only lines beginning with '[' and ending with ']' and containing ':' are section headers
 */
static bool
line_is_sectionheader(const char *line, char **eol_out, char **colon_out)
{
    return *line == '[' && (*eol_out = strchr(line, ']')) != NULL
        && ((*eol_out)[1] == '\0' || strcmp(*eol_out + 1, "\n") == 0) && (*colon_out = strchr(line, ':')) != NULL;
}

/*
 * Log an error, always returning false.
 */
bool
fileprefs_log_error(struct fileprefs *me, const char *line, const char *func, const struct conf_loader *cl, const char *type,
                    const char *inval, unsigned read, unsigned total)
{
    char *eol, *colon;

    if (line_is_sectionheader(line, &eol, &colon))
        SXEL2("%s(): %s v%u: %s: %u: Unexpected %.*s] header - read %u [%s] item%s, not %u",
              func, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl),
              (int)(colon - line), line, read, type, read == 1 ? "" : "s", total);
    else
        SXEL2("%s(): %s v%u: %s: %d: Unrecognised %s line (invalid %s)",
              func, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl), type, inval);

    return false;
}

bool
fileprefs_readlist(struct fileprefs *me, struct prefbuilder *pb, struct conf_loader *cl, const char *line)
{
    struct object_fingerprint of;
    list_pointer_t            lp;
    const char               *p, *cidr_consumed;
    uint64_t                  id;
    unsigned                  actiontype, elementtype, ltype, len;
    int                       bit, consumed;
    bool                      ltype_requires_empty_bit;
    char                      colon;
    char                      name[PREF_LIST_ELEMENTTYPE_NAME_MAXSIZE];
    uint8_t                   fingerprint[SUM_BYTES_MAX];

    if (me->loadflags & LOADFLAGS_FP_NO_LTYPE) {
        ltype = AT_LIST_NONE;

        if (sscanf(line, "%" PRIu64 "%c%n", &id, &colon, &consumed) != 2 || colon != ':' || id != (uint32_t)id)
            return fileprefs_log_error(me, line, __FUNCTION__, cl, "list", "id:", pb->list.count, pb->list.alloc);
    }
    else {
        if (sscanf(line, "%X:%" PRIu64 "%c%n", &ltype, &id, &colon, &consumed) != 3 || colon != ':' || id != (uint32_t)id)
            return fileprefs_log_error(me, line, __FUNCTION__, cl, "list", "ltype:id:", pb->list.count, pb->list.alloc);

        if (!LTYPEVALID(ltype)) {
            SXEL4("%s(): %s v%d: %s: %d: Unrecognised list line (invalid ltype)",
                __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
            return true;
        }
    }

    line += consumed;

    if ((p = strchr(line, ':')) == NULL) {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised list line (no elementtype terminator)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }

    name[0] = '\0';

    if ((len = p - line) > 0 && len < PREF_LIST_ELEMENTTYPE_NAME_MAXSIZE) {
        memcpy(name, line, len);
        name[len] = '\0';
    }

    if ((elementtype = pref_list_name_to_elementtype(name)) == PREF_LIST_ELEMENTTYPE_INVALID) {
        if (!(me->loadflags & LOADFLAGS_FP_STRICT_REFS)) {
            SXEL4("%s(): %s v%d: %s: %d: Unrecognised list line (invalid elementtype '%.*s')", __FUNCTION__, me->ops->type,
                  me->version, conf_loader_path(cl), conf_loader_line(cl), len, line);
            return true;
        }

        SXEL2("%s(): %s v%d: %s: %d: Unrecognised list line (invalid elementtype '%.*s')", __FUNCTION__, me->ops->type,
              me->version, conf_loader_path(cl), conf_loader_line(cl), len, line);
        return false;
    }

    if (!(me->loadflags & LOADFLAGS_FP_ELEMENTTYPE(elementtype))) {
        // Add to the discarded list so that bundle references to it can also be discarded
        if (!prefbuilder_disclist(pb, ltype, id, elementtype)) {
            SXEL2("%s(): %s v%d: %s: %d: Cannot mark preflist %02X:%u:%s as discarded", __FUNCTION__,
                  me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl), ltype, (unsigned)id, name);
            return false;
        }

        if (me->loadflags & LOADFLAGS_FP_ALLOW_OTHER_TYPES) {
            SXEL6("%s(): %s v%d: %s: %d: Discarding list line (unwanted elementtype %s, loadflags %X)", __FUNCTION__,
                  me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl), name, me->loadflags);
            return true;
        }

        if (!(me->loadflags & LOADFLAGS_FP_STRICT_REFS)) {
            SXEL4("%s(): %s v%d: %s: %d: Invalid list line (unexpected elementtype %s, loadflags %X)", __FUNCTION__,
                  me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl), name, me->loadflags);
            return true;
        }

        SXEL2("%s(): %s v%d: %s: %d: Invalid list line (unexpected elementtype %s, loadflags %X)", __FUNCTION__,
              me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl), name, me->loadflags);
        return false;
    }

    line       = p + 1;
    actiontype = ltype & AT_LIST_MASK;

    /*
     * Empty bit fields are required for except, url-proxy-https, dest-nodecrypt, and app-nodecrypt lists
     */
    ltype_requires_empty_bit = (actiontype == AT_LIST_EXCEPT || actiontype == AT_LIST_URL_PROXY_HTTPS
                             || actiontype == AT_LIST_DESTNODECRYPT || actiontype == AT_LIST_APPNODECRYPT);

    if (*line == ':' && (ltype_requires_empty_bit || me->loadflags & LOADFLAGS_FP_NO_LTYPE)) {
        bit = 0;
        line++;
    }
    else if (*line == ':' || ltype_requires_empty_bit) {
        SXEL2("%s(): %s v%d: %s: %d: Invalid category bit field for list type %02X",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl), actiontype);
        return false;
    }
    else if (sscanf(line, "%d%c%n", &bit, &colon, &consumed) != 2 || colon != ':' || bit == 0) {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised bit for list type %02X",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl), actiontype);
        return false;
    }
    else
        line += consumed;

    if ((of.len = kit_hex2bin(fingerprint, line, SUM_BYTES_MAX)) == 0 || line[of.len * 2] != ':') {
        SXEL2("%s(): %s v%d: %s: %d: List type %02X name %s must have a fingerprint (even number of hex digits)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl), actiontype, name);
        return false;
    }

    of.fp  = fingerprint;
    line  += of.len * 2 + 1;
    lp.domainlist = NULL;    // Shut up compiler warning.

    switch (elementtype) {
    case PREF_LIST_ELEMENTTYPE_APPLICATION:
        of.hash = applicationlisthash;

        if ((lp.applicationlist = uint32list_new(line, &of)) == NULL)
            SXEL2("%s(): %s v%d: %s: %d: Unrecognised list line (parsing uint32list failed)",
                  __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));

        applicationlisthash = of.hash;
        break;

    case PREF_LIST_ELEMENTTYPE_CIDR:
        of.hash = cidrlisthash;

        if (((lp.cidrlist = cidrlist_new_from_string(line, ", \t\n", &cidr_consumed, &of, PARSE_IP_OR_CIDR)) == NULL)
         || (cidr_consumed == NULL) || (*cidr_consumed != '\0')) {
            SXEL2("%s(): %s v%d: %s: %d: Unrecognised list line (parsing cidrlist failed)",
                  __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        }

        cidrlisthash = of.hash;
        break;

    case PREF_LIST_ELEMENTTYPE_DOMAIN:
        of.hash = domainlisthash;

        if ((lp.domainlist = domainlist_new_from_buffer(line, strlen(line), &of, ltype == AT_LIST_URL_PROXY_HTTPS ?
                                                        LOADFLAGS_DL_EXACT : LOADFLAGS_NONE)) == NULL) {
            SXEL2("%s(): %s v%d: %s: %d: Unrecognised list line (parsing domainlist failed)",
                  __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        }

        domainlisthash = of.hash;
        break;

    case PREF_LIST_ELEMENTTYPE_URL:
        of.hash = urllisthash;

        if ((lp.urllist = urllist_new_from_buffer(line, strlen(line), &of, LOADFLAGS_NONE)) == NULL) {
            SXEL2("%s(): %s v%d: %s: %d: Unrecognised list line (parsing urllist failed)",
                  __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        }

        urllisthash = of.hash;
        break;
    }

    if (LIST_POINTER_IS_NULL(lp))
        return false;

    if (!prefbuilder_addlist(pb, ltype, id, elementtype, lp, bit)) {
        SXEL2("%s(): %s v%d: %s: %d: Cannot create preflist %02X:%u:%s", __FUNCTION__, me->ops->type, me->version,
              conf_loader_path(cl), conf_loader_line(cl), ltype, (unsigned)id, name);

        switch (elementtype) {
        case PREF_LIST_ELEMENTTYPE_APPLICATION:
            uint32list_refcount_dec(lp.applicationlist);
            break;

        case PREF_LIST_ELEMENTTYPE_CIDR:
            cidrlist_refcount_dec(lp.cidrlist);
            break;                                                                 /* COVERAGE EXCLUSION: CIDRPREFS */

        case PREF_LIST_ELEMENTTYPE_DOMAIN:
            domainlist_refcount_dec(lp.domainlist);
            break;

        case PREF_LIST_ELEMENTTYPE_URL:
            urllist_refcount_dec(lp.urllist);                                      /* COVERAGE EXCLUSION: URLPREFS */
            break;
        }

        return false;
    }

    return true;
}

static bool
fileprefs_readsettinggroup(struct fileprefs *me, struct prefbuilder *pb, struct conf_loader *cl, const char *line)
{
    pref_categories_t blocked_categories, nodecrypt_categories, warn_categories;
    unsigned long flags, sgid, sgidx;
    int consumed;
    char *end;

    if ((sgidx = kit_strtoul(line, &end, 10)) >= SETTINGGROUP_IDX_COUNT || errno != 0 || end == line || *end != ':')
        return fileprefs_log_error(me, line, __FUNCTION__, cl, "settinggroup", "idx", pb->settinggroup.count,
                                   pb->settinggroup.alloc);

    line = end + 1;
    sgid = kit_strtoul(line, &end, 10);

    if (sgid != (uint32_t)sgid || errno != 0 || end == line || *end != ':') {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised settinggroup line (invalid id)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }

    line  = end + 1;
    flags = kit_strtoul(line, &end, 16);

    if (flags != (pref_bundleflags_t)flags || errno != 0 || end == line || *end != ':') {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised settinggroup line (invalid flags)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }

    line = end + 1;
    consumed = pref_categories_sscan(&blocked_categories, line);
    if (consumed == 0 || line[consumed] != ':') {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised settinggroup line (invalid blocked-categories)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }

    line += consumed + 1;
    consumed = pref_categories_sscan(&nodecrypt_categories, line);
    if (consumed == 0 || line[consumed] != ':') {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised settinggroup line (invalid nodecrypt-categories)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }

    line += consumed + 1;
    consumed = pref_categories_sscan(&warn_categories, line);
    if (consumed == 0 || (line[consumed] != '\0' && line[consumed] != '\n')) {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised settinggroup line (invalid warn-categories)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }

    if (!prefbuilder_addsettinggroup(pb, sgidx, sgid, flags, &blocked_categories, &nodecrypt_categories, &warn_categories)) {
        SXEL2("%s(): %s v%d: %s: %d: Cannot create settinggroup %lu:%lu",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl), sgidx, sgid);
        return false;
    }

    return true;
}

static const char *ltype_str[] = {
    "block dest",
    "exception",
    "allow dest",
    "url proxy",
    "nodecrypt dest",
    "block app",
    "allow app",
    "nodecrypt app",
    "warn dest",
    "warn app"
};

static bool
fileprefs_readbundle(struct fileprefs *me, struct prefbuilder *pb, struct conf_loader *cl, const char *line)
{
    uint64_t bundleid, flags, listid, priority, settinggroup_id;
    uint32_t settinggroup_ids[SETTINGGROUP_IDX_COUNT];
    pref_categories_t categories;
    char colon, *end, term;
    unsigned actype;
    ltype_t ltype;
    int consumed;
    unsigned i;

    if (sscanf(line, "%X:%"PRIu64":%"PRIu64":%"PRIx64"%c%n", &actype, &bundleid, &priority, &flags, &colon, &consumed) != 5
     || colon != ':')
        return fileprefs_log_error(me, line, __FUNCTION__, cl, "bundle", "actype:bundleid:priority:flags:", pb->bundle.count,
                                   pb->bundle.alloc);

    line += consumed;

    if (bundleid != (uint32_t)bundleid || priority != (uint32_t)priority || flags != (pref_bundleflags_t)flags) {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised bundle line (overflow in actype:bundleid:priority:flags:)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }

    if (!ACTYPEVALID(actype)) {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised bundle line (invalid actype)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }

    consumed = pref_categories_sscan(&categories, line);

    if (consumed == 0 || line[consumed] != ':') {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised bundle line (invalid categories)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }

    line += consumed;
    memset(settinggroup_ids, 0, sizeof(settinggroup_ids));

    for (i = 0; i < SETTINGGROUP_IDX_COUNT && (i == 0 || *line != ':'); i++) {
        settinggroup_id = kit_strtoull(++line, &end, 10);

        // There will only be 0 or 4 ids, but we allow the list to be truncated.
        if (end == line) {
            break;
        }

        if (settinggroup_id != (uint32_t)settinggroup_id || (*end != ' ' && *end != ':') ||  errno != 0) {
            SXEL2("%s(): %s v%d: %s: %d: Unrecognised bundle line (invalid settinggroup id)",
                  __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
            return false;
        }

        settinggroup_ids[i] = settinggroup_id;
        line = end;
    }

    // List of setting groups must be : terminated
    if (*line != ':') {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised bundle line (invalid settinggroup-ids terminator)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }

    line++;

    if (!prefbuilder_addbundle(pb, (actype_t)actype, bundleid, priority, flags, &categories, settinggroup_ids)) {
        SXEL2("%s(): %s v%d: %s: %d: Cannot create bundle %X:%" PRIu64,
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl), actype, bundleid);
        return false;
    }

    /* Each ltype has a field in the bundle. There are no longer any spare fields */
    for (i = 0; NUM2LTYPE(i) <= MAXLTYPE; i++) {
        ltype = NUM2LTYPE(i) | actype;
        term = NUM2LTYPE(i) < MAXLTYPE ? ':' : '\n';    /* The fields list is the last one on the bundle line */

        while (*line) {
            while (*line == ' ')
                line++;

            if (*line == '\0' || *line == term)
                break;

            if (sscanf(line, "%" PRIu64 "%n", &listid, &consumed) != 1 || (line[consumed] != ' ' && line[consumed] != term)
             || listid != (uint32_t)listid) {
                SXEL2("%s(): %s v%d: %s: %d: Unrecognised bundle line (invalid %s list '%.*s')", __FUNCTION__,
                      me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl), ltype_str[i], consumed, line);
                return false;
            }

            line += consumed;

            if (!prefbuilder_attachlist(pb, bundleid, ltype, listid, LOADFLAGS_FP_TO_ELEMENTTYPES(me->loadflags))) {
                SXEL2("%s(): %s v%d: %s: %d: Cannot attach bundle %X:%" PRIu64 " to list %02X:%" PRIu64 " (list pos %u)",
                      __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl), actype, bundleid,
                      ltype, listid, i);
                return false;
            }
        }
        if (*line == term)
            line++;
    }

    return *line == '\0';
}

static bool
fileprefs_readorg(struct fileprefs *me, struct prefbuilder *pb, struct conf_loader *cl, const char *line)
{
    pref_categories_t unmasked;
    uint64_t flags, orgid, retention, warnperiod, originid, parentid;
    int consumed;
    char *end;

    orgid = kit_strtoull(line, &end, 10);
    if (end == line || *end != ':' || errno != 0) {
        return fileprefs_log_error(me, line, __FUNCTION__, cl, "org",
                                   errno == ERANGE || orgid != (uint32_t)orgid ? "orgid - overflow" : "orgid",
                                   pb->org.count, pb->org.alloc);
    }
    line = end + 1;

    flags = kit_strtoull(line, &end, 16);
    if (end == line || *end != ':' || errno != 0) {
        return fileprefs_log_error(me, line, __FUNCTION__, cl, "org",
                                   errno == ERANGE ? "orgflags - overflow" : "orgflags",
                                   pb->org.count, pb->org.alloc);
    }
    line = end + 1;

    consumed = pref_categories_sscan(&unmasked, line);
    if (consumed == 0 || line[consumed] != ':') {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised org line (invalid unmasked categories)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }
    line += consumed + 1;

    retention = kit_strtoull(line, &end, 10);
    if (end == line || *end != ':' || errno != 0 || retention != (uint32_t)retention) {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised org line (invalid retention)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }
    line = end + 1;

    warnperiod = kit_strtoull(line, &end, 10);
    if (end == line || *end != ':' || errno != 0 || warnperiod != (uint32_t)warnperiod) {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised org line (invalid warn period)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }
    line = end + 1;

    originid = kit_strtoull(line, &end, 10);
    if (end == line || *end != ':' || errno != 0 || originid != (uint32_t)originid) {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised org line (invalid originid)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }
    line = end + 1;

    parentid = kit_strtoull(line, &end, 10);
    if (end == line || (*end != '\0' && *end != '\n') || errno != 0 || parentid != (uint32_t)parentid) {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised org line (invalid parentid)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }

    if (!prefbuilder_addorg(pb, orgid, flags, &unmasked, retention, warnperiod, originid, parentid)) {
        SXEL2("%s(): %s v%d: %s: %d: Cannot create org %" PRIu64,
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl), orgid);
        return false;
    }

    return true;
}

static bool
fileprefs_readident(struct fileprefs *me, struct prefbuilder *pb, struct conf_loader *cl, const char *line)
{
    uint64_t bundleid, orgid, originid, origintypeid;
    unsigned actype;
    int consumed;

    SXEA6(me->ops->parsekey != NULL, "Reading an identity, but the file type doesn't support parsing keys");

    if ((consumed = me->ops->parsekey(me, pb->count, cl, line)) == 0)
        return false;

    line += consumed;
    if (sscanf(line, "%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%X:%" PRIu64 "%n", &originid, &origintypeid, &orgid, &actype, &bundleid, &consumed) != 5) {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised identity line",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }
    if (originid != (uint32_t)originid || origintypeid != (uint32_t)origintypeid || orgid != (uint32_t)orgid || bundleid != (uint32_t)bundleid) {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised identity line (overflow in originid:origintypeid:orgid:actype:bundleid)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }

    if (!ACTYPEVALID(actype)) {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised list line (invalid actype)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }
    if (line[consumed] != '\0' && line[consumed] != '\n') {
        SXEL2("%s(): %s v%d: %s: %d: Unrecognised identity line (trailing junk)",
              __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        return false;
    }

    if (!prefbuilder_addidentity(pb, originid, origintypeid, orgid, (actype_t)actype, bundleid)) {
        if (me->loadflags & LOADFLAGS_FP_STRICT_REFS) {
            SXEL2("%s(): %s v%d: %s: %d: Cannot add identity; invalid bundleid or orgid",
                  __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
            return false;
        } else {
            SXEL4("%s(): %s v%d: %s: %d: Cannot add identity; invalid bundleid or orgid",
                  __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
            prefbuilder_shrink(pb);
        }
    }

    return true;
}

/**
 * Initialize fileprefs; used by lists
 *
 * @param me        Pointer to the structure to initialize
 * @param ops       Pointer to the class object that defines the prefs type
 * @param loadflags Fileprefs load flags
 */
void
fileprefs_init(struct fileprefs *me, const struct fileprefops *ops, unsigned loadflags)
{
    me->version   = 0;
    me->ops       = ops;
    me->loadflags = loadflags;
}

/**
 * Load a prefs file section. Also used for lists files
 *
 * @param me         Fileprefs object
 * @param cl         Confloader object initialized to load the file
 * @param pb         Prefbuilder object
 * @param okvers     Zero terminated array of valid version numbers for this file
 * @param section    Pointer to a pointer to the current section (initially NULL)
 * @param count      Pointer to an unsigned integer populated with the header count if a header was found or skipped
 *
 * @return FILEPREFS_SECTION_NOT_FOUND Next line is not a fileprefs section header; in this case, the line is unread
 *         FILEPREFS_SECTION_ERROR     Error parsing the header or skipped lines
 *         FILEPREFS_SECTION_LOADED    Found a valid section header and loaded it, ignoring it if it was for the wrong version
 */
enum fileprefs_section_status
fileprefs_load_section(struct fileprefs *me, struct conf_loader *cl, struct prefbuilder *pb, const unsigned *okvers,
                       const struct fileprefs_section **section, unsigned *count)
{
    const struct fileprefs_section *next, *sections;
    const char                     *line, *p, *colon2;
    char                           *colon1, *end, *eol;
    unsigned long                   c, v;
    unsigned                        i, num_sections;
    bool                            skip;

    static const struct fileprefs_section default_sections[] = {
        { "lists",        sizeof("lists") - 1,        prefbuilder_alloclist,         fileprefs_readlist,         0 },
        { "settinggroup", sizeof("settinggroup") - 1, prefbuilder_allocsettinggroup, fileprefs_readsettinggroup, 0 },
        { "bundles",      sizeof("bundles") - 1,      prefbuilder_allocbundle,       fileprefs_readbundle,       0 },
        { "orgs",         sizeof("orgs") - 1,         prefbuilder_allocorg,          fileprefs_readorg,          0 },
        { "identities",   sizeof("identities") - 1,   prefbuilder_allocident,        fileprefs_readident,        1 },
    };

    sections     = me->ops->sections ?: default_sections;
    num_sections = me->ops->sections ? me->ops->num_sections : sizeof(default_sections) / sizeof(*default_sections);
    SXEA6(*section == NULL || (*section >= sections && *section < sections + num_sections), "Invalid *section passed");

    if (!(line = conf_loader_readline(cl)))    // On EOF, return not found
        return FILEPREFS_SECTION_NOT_FOUND;

    if (!line_is_sectionheader(line, &eol, &colon1)) {
        conf_loader_unreadline(cl);
        return FILEPREFS_SECTION_NOT_FOUND;
    }

    colon2 = strchr(colon1 + 1, ':');
    p      = colon1 + 1;
    c      = kit_strtoul(p, &end, 10);

    if (errno || end != (colon2 ?: eol)) {
        SXEL2("%s: %u: Invalid section header count", conf_loader_path(cl), conf_loader_line(cl));
        return FILEPREFS_SECTION_ERROR;
    }

    skip = false;

    if (colon2)   // There's a version section!
        for (skip = true, p = colon2, v = 0; ++p < eol; p = end) {
            if ((v = kit_strtoul(p, &end, 10)) == 0 || errno != 0 || end == p || (*end != ' ' && *end != ']')) {
                SXEL2("%s: %u: Invalid section header version(s)", conf_loader_path(cl), conf_loader_line(cl));
                return FILEPREFS_SECTION_ERROR;
            }

            if (v == me->version)
                skip = false;

            for (i = 0; okvers[i]; i++)
                if (okvers[i] == v)
                    break;

            if (!okvers[i]) {
                SXEL2("%s: %u: Section header version %lu not specified in file header", conf_loader_path(cl), conf_loader_line(cl), v);
                return FILEPREFS_SECTION_ERROR;
            }
        }

    next = NULL;    // Shut up old gcc on debian 9 that's too dumb to know all accesses of next are in !skip blocks

    if (!skip) {
        for (next = *section ? *section + 1 : sections; next < sections + num_sections; next++)
            if (line + next->namelen + 1 == colon1 && strncmp(line + 1, next->name, next->namelen) == 0)
                break;

        if (next >= sections + num_sections) {
            SXEL2("%s: %u: Invalid section header '%.*s'", conf_loader_path(cl), conf_loader_line(cl),
                  (int)(colon1 - line - 1), line + 1);
            return FILEPREFS_SECTION_ERROR;
        }

        *section = next;
    }

    *count = c;

    if (*count != c) {
        SXEL2("%s: %u: Section header count overflow", conf_loader_path(cl), conf_loader_line(cl));
        return FILEPREFS_SECTION_ERROR;
    }

    if (!skip && c > 0) {
        if (next->last) {
            if (!me->ops->keysz) {
                SXEL2("%s: %u: identities section header count must be 0", conf_loader_path(cl), conf_loader_line(cl));
                return FILEPREFS_SECTION_ERROR;
            }

            if ((me->keys = MOCKFAIL(fileprefs_load_section, NULL, kit_calloc(c, me->ops->keysz))) == NULL) {
                SXEL2("Couldn't calloc %u*%zu %s value bytes", *count, me->ops->keysz, me->ops->type);
                return FILEPREFS_SECTION_ERROR;
            }
        }

        if (pb && !next->alloc(pb, c))
            return FILEPREFS_SECTION_ERROR;
    }

    for (i = 0; i < c; i++) {
        if ((line = conf_loader_readline(cl)) == NULL) {
            if (skip)
                SXEL2("%s(): %s v%u: %s: %u: Unexpected EOF in skipped section - read %u item%s, not %lu", __FUNCTION__,
                      me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl), i, i == 1 ? "" : "s", c);
            else
                SXEL2("%s(): %s v%u: %s: %u: Unexpected EOF - read %u [%s] item%s, not %lu",__FUNCTION__, me->ops->type,
                      me->version, conf_loader_path(cl), conf_loader_line(cl), i, next->name, i == 1 ? "" : "s", c);

            return FILEPREFS_SECTION_ERROR;
        }

        if (skip) {
            if (line_is_sectionheader(line, &eol, &colon1)) {
                SXEL2("%s(): %s v%u: %s: %u: Unexpected %.*s header in skipped section - read %u item%s, not %lu",
                        __FUNCTION__, me->ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl),
                        (int)(eol - line + 1), line, i, i == 1 ? "" : "s", c);
                return FILEPREFS_SECTION_ERROR;
            }

            continue;
        }

        if (!next->read(me, pb, cl, line))
            return FILEPREFS_SECTION_ERROR;
    }

    return FILEPREFS_SECTION_LOADED;
}

/**
 * Load the header of a prefs file. Also used for lists files and other configuration files.
 *
 * @param me     Pointer to a fileorefs object
 * @param cl     Pointer to a confloader object initialized to load the file
 * @param count  Pointer to an unsigned integer to be populated with the file count
 * @param okvers Pointer to a pointer to be populated with a pointer to a zero terminated array of valid version numbers
 *
 * @return true on success
 */
bool
fileprefs_load_fileheader(struct fileprefs *me, struct conf_loader *cl, unsigned *count, unsigned **okvers)
{
    unsigned i, pos, ver, *newokvers, nokvers, szokvers;
    bool result = false;
    char verbuf[1024];
    const char *line;
    size_t len;
    char *end;

    if (conf_loader_err(cl))
        goto SXE_EARLY_OUT;

    if ((line = conf_loader_readline(cl)) == NULL) {
        if (conf_loader_eof(cl))
            SXEL2("%s(): %s: No content found", __FUNCTION__, conf_loader_path(cl));

        goto SXE_EARLY_OUT;
    }

    len = strlen(me->ops->type);

    if (strncmp(line, me->ops->type, len) != 0 || line[len] != ' ') {
        SXEL2("%s(): %s: %u: Invalid header; must contain '%s'", __FUNCTION__, conf_loader_path(cl), conf_loader_line(cl),
              me->ops->type);
        goto SXE_EARLY_OUT;
    }

    SXEA6(*okvers == NULL, "Uninitialized okvers pointer passed");
    nokvers = szokvers = 0;
    line += len;

    while (*line == ' ') {
        line++;

        if ((ver = kit_strtoul(line, &end, 10)) == 0 || errno != 0 || end == line + len + 1 || (*end != '\0' && *end != ' ' && *end != '\n')) {
            SXEL2("%s(): %s: %u: Invalid header version(s); must be numeric", __FUNCTION__, conf_loader_path(cl), conf_loader_line(cl));
            goto SXE_EARLY_OUT;
        }

        if (nokvers + 1 >= szokvers) {
            if ((newokvers = MOCKFAIL(fileprefs_load_fileheader, NULL, kit_realloc(*okvers, (szokvers + OKVERS_INCR) * sizeof(*newokvers)))) == NULL) {
                SXEL2("%s: %u: Couldn't allocate %u*%zu version bytes", conf_loader_path(cl), conf_loader_line(cl), szokvers + OKVERS_INCR, sizeof(*newokvers));
                goto SXE_EARLY_OUT;
            }
            *okvers = newokvers;
            szokvers += OKVERS_INCR;
        }

        (*okvers)[nokvers++] = ver;
        (*okvers)[nokvers] = 0;

        if (ver > me->version)
            for (i = 0; me->ops->supported_versions[i]; i++)
                if (me->ops->supported_versions[i] == ver)
                    me->version = ver;

        line += (const char *)end - line;
    }

    if (!me->version) {
        strcpy(verbuf, "[");
        for (i = 0, pos = 1; me->ops->supported_versions[i]; i++) {
            snprintf(verbuf + pos, sizeof(verbuf) - pos - 1, "%u ", me->ops->supported_versions[i]);
            pos += strlen(verbuf + pos);
        }
        strcpy(verbuf + (pos == 1 ? pos : pos - 1), "]");
        SXEL2("%s(): %s: %u: Invalid version(s); must be from the set %s", __FUNCTION__, conf_loader_path(cl), conf_loader_line(cl), verbuf);
        goto SXE_EARLY_OUT;
    }

    if ((line = conf_loader_readline(cl)) == NULL) {
        if (conf_loader_eof(cl))
            SXEL2("%s(): %s: %u: No count line found", __FUNCTION__, conf_loader_path(cl), conf_loader_line(cl));
        goto SXE_EARLY_OUT;
    }

    if (strncmp(line, "count ", 6) != 0) {
        SXEL2("%s(): %s: %u: Invalid count; must begin with 'count '", __FUNCTION__, conf_loader_path(cl), conf_loader_line(cl));
        goto SXE_EARLY_OUT;
    }

    *count = kit_strtoul(line + 6, &end, 10);

    if (end == line + 6 || (*end != '\0' && *end != '\n') || errno != 0) {
        SXEL2("%s(): %s: %u: Invalid count; must be a numeric value", __FUNCTION__, conf_loader_path(cl), conf_loader_line(cl));
        goto SXE_EARLY_OUT;
    }

    result = true;

SXE_EARLY_OUT:;
    if (!result)
        *count = 0;

    SXEL6("%s(fp=?, cl=?){} // file=%s, version=%u, count=%d, result %s", __FUNCTION__, conf_loader_path(cl), me->version, *count, kit_bool_to_str(result));
    return result;
}

/* Allocate and construct a new prefs file object, loading the file content using the conf loader */
struct fileprefs *
fileprefs_new(struct conf_loader *cl, struct fileprefops *ops, size_t sz, unsigned loadflags)
{
    const struct fileprefs_section *section = NULL;
    struct fileprefs               *me, *retme;
    struct prefbuilder              pref_builder;
    unsigned                        total, loaded, count, *okvers;
    uint32_t                        pbflags;
    enum fileprefs_section_status   status;

    SXEE6("(cl=?, ops=%s_ops, sz=%zu, loadflags=%04X) // path=%s", ops->type, sz, loadflags, conf_loader_path(cl));
    SXEA6(sz >= sizeof(*me), "Cannot allocate a super-fileprefs that's smaller than the base");

    retme   = NULL;
    okvers  = NULL;
    pbflags = loadflags & LOADFLAGS_FP_ALLOW_BUNDLE_EXTREFS ? PREFBUILDER_FLAG_NONE : PREFBUILDER_FLAG_NO_EXTERNAL_REFS;
    prefbuilder_init(&pref_builder, pbflags, cl, NULL);

    if ((me = MOCKFAIL(fileprefs_new, NULL, kit_calloc(1, sz))) == NULL) {
        SXEL2("Cannot allocate %zu fileprefs bytes", sz);
        goto OUT;
    }

    fileprefs_init(me, ops, loadflags | (strict_prefs_enabled ? LOADFLAGS_FP_STRICT_REFS : 0));

    if (!fileprefs_load_fileheader(me, cl, &total, &okvers))
        goto OUT;

    for (loaded = 0;
         (status = fileprefs_load_section(me, cl, &pref_builder, okvers, &section, &count)) == FILEPREFS_SECTION_LOADED;
         loaded += count) {
    }

    if (status == FILEPREFS_SECTION_ERROR)
        goto OUT;

    if (!conf_loader_eof(cl)) {
        if (section == NULL)
            SXEL2("%s(): %s v%u: %s: %u: Expected section header",
                __FUNCTION__, ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        else
            SXEL2("%s(): %s v%u: %s: %u: Unexpected [%s] line - wanted only %u item%s",
                __FUNCTION__, ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl),
                section->name, count, count == 1 ? "" : "s");

        goto OUT;
    }

    if (loaded != total) {
        SXEL2("%s(): %s v%u: %s: %u: Incorrect total count %u - read %u data line%s",
              __FUNCTION__, ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl),
              total, loaded, loaded == 1 ? "" : "s");
        goto OUT;
    }

    if ((me->values = prefbuilder_consume(&pref_builder)) == NULL) {
        SXEL2("%s(): %s v%u: %s: %u: prefbuilder failure",
              __FUNCTION__, ops->type, me->version, conf_loader_path(cl), conf_loader_line(cl));
        goto OUT;
    }

    me->total = loaded;
    retme     = me;

OUT:
    if (retme != me) {
        if (loadflags & LOADFLAGS_FP_SEGMENTED) {
            /*
             * The flags indicate that this is a segmented preference, the failed
             * pref structure should be stored for reporting purposes.
             */
            me->loadflags |= LOADFLAGS_FP_FAILED;
            retme = me;
        }
        else
            me->ops->free(me);
    }

    kit_free(okvers);
    prefbuilder_fini(&pref_builder);

    SXER6("return %p // type %s, %u records, %s", retme, ops->type,
          retme ? (retme->loadflags & LOADFLAGS_FP_FAILED ? 0 : retme->total) : 0,
          !retme || (retme->loadflags & LOADFLAGS_FP_FAILED) ? "failed" : "passed");

    if ((retme == NULL) || (retme->loadflags & LOADFLAGS_FP_FAILED))
        errno = EINVAL;

    return retme;
}

/* XXX: This should go when HardCIDR stops needing it (via devprefs_policy() and netprefs_policy()) */
bool
fileprefs_get_policy(const struct fileprefs *me, pref_t *pref, actype_t actype, uint32_t orgid, uint32_t id)
{
    const struct prefbundle *pb;

    SXEE7("(me=%p, pref=%p, actype=%X, id=%u)", me, pref, actype, id);

    if (me && (pb = prefblock_bundle(me->values, actype, id)) != NULL)
        pref_init_bybundle(pref, me->values, NULL, NULL, orgid, pb - me->values->resource.bundle);
    else
        pref_fini(pref);

    SXER7("return %d // %s, pref { %p, %p, %p, %u }", PREF_VALID(pref), PREF_VALID(pref) ? "valid" : "invalid",
          pref->blk, pref->parentblk, pref->globalblk, pref->index);
    return PREF_VALID(pref);
}
