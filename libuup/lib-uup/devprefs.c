#include <inttypes.h>    /* Required by ubuntu */

#if SXE_DEBUG
#include <kit-bool.h>
#endif

#include "devprefs-private.h"
#include "unaligned.h"
#include "xray.h"

/*-
 * A struct devprefs is a struct fileprefs:
 *
 *  keys                     idents
 *  .-------------.         .------------------------------------.
 *  | device_id0  |         | originid | orgid | actype | bundle |
 *  |-------------|         |------------------------------------|
 *  | device_id1  |         | ident1                             |
 *  .             .         .                                    .
 *  .             .         .                                    .
 *  .-------------.         .------------------------------------|
 *  | device_idN  |         | identN                             |
 *  `-------------'         `------------------------------------'
 *
 * keysz is set to sizeof(uint64_t).
 */

#define DEVPREFS_KEYS(me)         ((struct kit_deviceid *)(me)->fp.keys)
#define DEVPREFS_KEY(me, i)       ((struct kit_deviceid *)(me)->fp.keys + (i))
#define CONSTCONF2DEVPREFS(confp) (const struct devprefs *)((confp) ? (const char *)(confp) - offsetof(struct devprefs, conf) : NULL)
#define CONF2DEVPREFS(confp)      (struct devprefs *)((confp) ? (char *)(confp) - offsetof(struct devprefs, conf) : NULL)

module_conf_t CONF_DEVPREFS;     /* per-org devprefs */
module_conf_t CONF_DEVPREFS0;    /* org0 devprefs */

static struct conf *devprefs_allocate(const struct conf_info *info, struct conf_loader *cl);
static void devprefs_free(struct conf *base);

static const struct conf_type devprefsct = {
    "devprefs",
    devprefs_allocate,
    devprefs_free,
};

/**
 * This variant is for the resolver. When devprefs no longer contain CIDRs, remove LOADFLAGS_FP_ALLOW_OTHER_TYPES.
 */
void
devprefs_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(&devprefsct, NULL, name, fn, loadable, LOADFLAGS_FP_ALLOW_OTHER_TYPES |
                       LOADFLAGS_FP_ELEMENTTYPE_DOMAIN | LOADFLAGS_FP_ELEMENTTYPE_APPLICATION, NULL, 0);
}

/**
 * This variant is for Hard Cider, until they no longer need to access CIDR lists in devprefs.
 */
void
devprefs_register_just_cidr(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(&devprefsct, NULL, name, fn, loadable, LOADFLAGS_FP_ALLOW_OTHER_TYPES | LOADFLAGS_FP_ELEMENTTYPE_CIDR, NULL, 0);
}

const struct devprefs *
devprefs_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &devprefsct, "devprefs_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2DEVPREFS(base);
}

static int
devprefs_compare(const void *key, const void *member)
{
    return memcmp(key, member, sizeof(struct kit_deviceid));
}

bool
devprefs_get(pref_t *pref, const struct devprefs *me, const char *name, struct kit_deviceid *device_id, struct xray *x)
{
    const struct kit_deviceid *key;

    SXEE7("(pref=?, me=%p, name=%s, device_id=%s, x=?)", me, name, kit_deviceid_to_str(device_id));
    pref_fini(pref);

    if (me != NULL) {
        if ((key = bsearch(device_id, me->fp.keys, PREFS_COUNT(me, identities), sizeof(*key), devprefs_compare)) != NULL) {
            pref_init_byidentity(pref, me->fp.values, NULL, NULL, key - DEVPREFS_KEYS(me));
            XRAY7(x, "%s match: found: bundle %x:%d, priority %u, origin %u for deviceid=%s",
                  name, PREF_IDENT(pref)->actype, PREF_BUNDLE(pref)->id, PREF_BUNDLE(pref)->priority,
                  PREF_IDENT(pref)->originid, kit_deviceid_to_str(device_id));
        } else
            XRAY7(x, "%s match: none for deviceid=%s", name, kit_deviceid_to_str(device_id));
    }

    SXER7("return %s // %s, pref { %p, %p, %p, %u }", kit_bool_to_str(PREF_VALID(pref)),
          PREF_VALID(pref) ? "valid" : "invalid", pref->blk, pref->parentblk, pref->globalblk, pref->index);
    return PREF_VALID(pref);
}

/* XXX: This should go when HardCIDR stops needing it */
bool
devprefs_get_policy(const struct devprefs *me, pref_t *pref, actype_t actype, uint32_t orgid, uint32_t id)
{
    return fileprefs_get_policy(me ? &me->fp : NULL, pref, actype, orgid, id);
}

const struct preforg *
devprefs_org(const struct devprefs *me, uint32_t id)
{
    return me ? prefblock_org(me->fp.values, id) : NULL;
}

static int    /* returns # bytes consumed */
devprefs_parsekey(struct fileprefs *fp, int item, const struct conf_loader *cl, const char *line)
{
    struct devprefs *me = (struct devprefs *)fp;
    int cmp, consumed;
    uint64_t hdevice;
    char colon;

    SXEA6(fp->version == DEVPREFS_VERSION, "Trying to parse devprefs key for version %u", fp->version);

    if (sscanf(line, "%" SCNx64 "%c%n", &hdevice, &colon, &consumed) != 2 || colon != ':') {
        SXEL2("%s(): devprefs v%u: %s: %u: Unrecognised line (invalid key format)",
              __FUNCTION__, me->fp.version, conf_loader_path(cl), conf_loader_line(cl));
        return 0;
    }

    unaligned_htonll(DEVPREFS_KEY(me, item), hdevice);
    if (item && (cmp = memcmp(DEVPREFS_KEY(me, item - 1), DEVPREFS_KEY(me, item), sizeof(struct kit_deviceid))) >= 0) {
        SXEL2("%s(): devprefs v%u: %s: %u: Invalid line (%s)", __FUNCTION__, me->fp.version,
              conf_loader_path(cl), conf_loader_line(cl), cmp ? "out of order" : "duplicate");
        return 0;
    }

    return consumed;
}

static const char *
devprefs_key_to_str(struct fileprefs *fp, unsigned i)
{
    struct devprefs *me = (struct devprefs *)fp;
    static __thread char txt[17];

    SXEA6(i < FILEPREFS_COUNT(fp, identities), "%s(): key %u is out of range; need less than %u", __FUNCTION__, i, FILEPREFS_COUNT(fp, identities));

    snprintf(txt, sizeof(txt), "%s", kit_deviceid_to_str(DEVPREFS_KEY(me, i)));

    return txt;
}

static struct fileprefops devprefs_ops = {
    .type               = "devprefs",
    .keysz              = sizeof(uint64_t),
    .parsekey           = devprefs_parsekey,
    .key_to_str         = devprefs_key_to_str,
    .free               = fileprefs_free,
    .supported_versions = { DEVPREFS_VERSION, 0 }
};

static struct conf *
devprefs_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct devprefs *me;

    SXEA6(info->type == &devprefsct, "%s() with unexpected conf_type %s", __FUNCTION__, info->type->name);
    if ((me = devprefs_new(cl, info->loadflags)) != NULL)
        conf_report_load(me->fp.ops->type, me->fp.version);

    return me ? &me->conf : NULL;
}

struct devprefs *
devprefs_new(struct conf_loader *cl, unsigned loadflags)
{
    struct devprefs *me;

    if ((me = (struct devprefs *)fileprefs_new(cl, &devprefs_ops, sizeof(*me), loadflags)) != NULL)
        conf_setup(&me->conf, &devprefsct);

    return me;
}

static void
devprefs_free(struct conf *base)
{
    struct devprefs *me = CONF2DEVPREFS(base);

    fileprefs_free(&me->fp);
}

void
devprefs_refcount_inc(struct devprefs *me)
{
    CONF_REFCOUNT_INC(me);
}

void
devprefs_refcount_dec(struct devprefs *me)
{
    CONF_REFCOUNT_DEC(me);
}

const struct prefblock *
devprefs_get_prefblock(const struct devprefs *me, uint32_t orgid)
{
    SXE_UNUSED_PARAMETER(orgid);

    return me ? me->fp.values : NULL;
}
