#if __FreeBSD__
#include <sys/socket.h>
#endif

#include "cidr-ipv4.h"
#include "cidr-ipv6.h"
#include "netprefs-private.h"
#include "radixtree128.h"
#include "radixtree32.h"
#include "xray.h"

#define NETPREFS_IPV4_KEYS(me)    ((struct cidr_ipv4 *)(me)->keys)
#define NETPREFS_IPV4_KEY(me, i)  ((struct cidr_ipv4 *)((struct cidr_ipv6 *)(me)->keys + (i)))
#define NETPREFS_IPV6_KEYS(me)    ((struct cidr_ipv6 *)(me)->keys)
#define NETPREFS_IPV6_KEY(me, i)  ((struct cidr_ipv6 *)(me)->keys + (i))
#define NETPREFS_INDEX(me, ptr)   ((struct cidr_ipv6 *)(ptr) - (struct cidr_ipv6 *)(me)->fp.keys)
#define CONSTCONF2NETPREFS(confp) (const struct netprefs *)((confp) ? (const char *)(confp) - offsetof(struct netprefs, conf) : NULL)
#define CONF2NETPREFS(confp)      (struct netprefs *)((confp) ? (char *)(confp) - offsetof(struct netprefs, conf) : NULL)

/*-
 * A struct netprefs contains a struct fileprefs:
 *
 *  keys               values
 *  .--------.         .------------------------------------.
 *  | cidr0  |         | originid | orgid | actype | bundle |
 *  |--------|         |------------------------------------|
 *  | cidr1  |         | ident1                             |
 *  .        .         .                                    .
 *  .        .         .                                    .
 *  .--------.         .------------------------------------|
 *  | cidrN  |         | identN                             |
 *  `--------'         `------------------------------------'
 *
 * keysz is set to sizeof(struct cidr_ipv6) -- most of this space is wasted as
 * we're usually storing a struct cidr_ipv4
 *
 * Note, netprefs are not required to be in order and are searched
 * using the netprefs::radixtree32 and netprefs::radixtree128 objects.
 */

module_conf_t CONF_NETPREFS;     /* per-org netprefs */
module_conf_t CONF_NETPREFS0;    /* org0 netprefs */

static struct conf *netprefs_allocate(const struct conf_info *info, struct conf_loader *cl);
static void netprefs_free(struct conf *base);

static const struct conf_type netprefsct = {
    "netprefs",
    netprefs_allocate,
    netprefs_free,
};

/**
 * This variant is for the resolver. When netprefs no longer contain CIDRs, remove LOADFLAGS_FP_ALLOW_OTHER_TYPES.
 */
void
netprefs_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(&netprefsct, NULL, name, fn, loadable,
                       LOADFLAGS_FP_ALLOW_OTHER_TYPES | LOADFLAGS_FP_ELEMENTTYPE_DOMAIN
                     | LOADFLAGS_FP_ELEMENTTYPE_APPLICATION, NULL, 0);
}

/**
 * This variant is probably not used. It replaces "netprefs_register_allow_junk_domains".
 */
void
netprefs_register_just_cidr(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(&netprefsct, NULL, name, fn, loadable, LOADFLAGS_FP_ALLOW_OTHER_TYPES | LOADFLAGS_FP_ELEMENTTYPE_CIDR, NULL, 0);
}

const struct netprefs *
netprefs_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &netprefsct, "netprefs_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2NETPREFS(base);
}

int
netprefs_get(pref_t *pref, const struct netprefs *me, const char *name, const struct netaddr *addr, struct xray *x, const char *hint)
{
    struct cidr_ipv6 *k6;
    struct cidr_ipv4 *k4;
    int mask;

    SXEE7("(pref=?, netprefs=%p, name=%s, addr=%s, x=?, hint=%s)", me, name, netaddr_to_str(addr), hint);

    pref_fini(pref);
    mask = -1;
    if (me != NULL) {
        switch (addr->family) {
        case AF_INET:
            if ((k4 = radixtree32_get(me->radixtree32, addr->in_addr)) != NULL) {
                pref_init_byidentity(pref, me->fp.values, NULL, NULL, NETPREFS_INDEX(me, k4));
                mask = cidr_ipv4_maskbits(k4);
            }
            break;
        case AF_INET6:
            if ((k6 = radixtree128_get(me->radixtree128, &addr->in6_addr)) != NULL) {
                pref_init_byidentity(pref, me->fp.values, NULL, NULL, NETPREFS_INDEX(me, k6));
                mask = k6->maskbits;
            }
            break;
        }

        if (mask == -1)
            XRAY7(x, "%s match: none for addr=%s which is %s", name, netaddr_to_str(addr), hint);
        else
            XRAY7(x, "%s match: found: bundle %x:%d, priority %u, origin %u for addr=%s which is %s",
                  name, PREF_IDENT(pref)->actype, PREF_BUNDLE(pref)->id, PREF_BUNDLE(pref)->priority,
                  PREF_IDENT(pref)->originid, netaddr_to_str(addr), hint);
    }

    SXER7("return %d // %svalid mask, pref { %p, %p, %p, %u }", mask,
          mask == -1 ? "in" : "", pref->blk, pref->parentblk, pref->globalblk, pref->index);

    return mask;
}

/* XXX: This should go when HardCIDR stops needing it */
bool
netprefs_get_policy(const struct netprefs *me, pref_t *pref, actype_t actype, uint32_t orgid, uint32_t id)
{
    return fileprefs_get_policy(me ? &me->fp : NULL, pref, actype, orgid, id);
}

const struct preforg *
netprefs_org(const struct netprefs *me, uint32_t id)
{
    return me ? prefblock_org(me->fp.values, id) : NULL;
}

static int    /* returns # bytes consumed */
netprefs_parsekey(struct fileprefs *fp, int item, const struct conf_loader *cl, const char *line)
{
    struct netprefs *me = (struct netprefs *)fp;
    const char *p;

    SXEA6(fp->version == NETPREFS_VERSION, "Trying to parse netprefs key for version %u", fp->version);

    if ((p = cidr_ipv4_sscan_verbose(NETPREFS_IPV4_KEY(fp, item), conf_loader_path(cl), conf_loader_line(cl), line, PARSE_CIDR_ONLY)) != NULL && *p++ == ':') {
        NETPREFS_IPV6_KEY(fp, item)->maskbits = 255;    /* To indicate an IPv4 CIDR */
        if (me->radixtree32 == NULL && (me->radixtree32 = radixtree32_new()) == NULL) {
            SXEL2("Not enough memory to allocate a radixtree32");
            return 0;
        }
        if (!radixtree32_put(me->radixtree32, NETPREFS_IPV4_KEY(fp, item))) {
            SXEL2("Failed to insert a new radixtree32 node");
            return 0;
        }
    } else if  ((p = cidr_ipv6_sscan_verbose(NETPREFS_IPV6_KEY(fp, item), conf_loader_path(cl), conf_loader_line(cl), line, PARSE_CIDR_ONLY)) != NULL && *p++ == ':') {
        if (me->radixtree128 == NULL && (me->radixtree128 = radixtree128_new()) == NULL) {
            SXEL2("Not enough memory to allocate a radixtree128");
            return 0;
        }
        if (!radixtree128_put(me->radixtree128, NETPREFS_IPV6_KEY(fp, item))) {
            SXEL2("Failed to insert a new radixtree128 node");
            return 0;
        }
    } else {
        SXEL2("%s(): netprefs v%u: %s: %u: Unrecognised line (invalid CIDR)",
              __FUNCTION__, fp->version, conf_loader_path(cl), conf_loader_line(cl));
        return 0;
    }

    return p - line;
}

static void
netprefs_fpfree(struct fileprefs *fp)
{
    struct netprefs *me = (struct netprefs *)fp;

    SXEA1(!me->conf.refcount, "Unexpected fileprefs free call with a conf refcount");
    netprefs_free(&me->conf);
}

static const char *
netprefs_key_to_str(struct fileprefs *fp, unsigned i)
{
    static __thread char txt[INET6_ADDRSTRLEN + sizeof("[]/128") - 1];
    struct cidr_ipv6 *key6;
    struct cidr_ipv4 *key4;

    SXEA6(i < FILEPREFS_COUNT(fp, identities), "%s(): key %u is out of range; need less than %u", __FUNCTION__, i, FILEPREFS_COUNT(fp, identities));
    key6 = NETPREFS_IPV6_KEY(fp, i);

    switch (key6->maskbits) {
    case 255:    /* Actually a struct cidr_ipv4 */
        key4 = NETPREFS_IPV4_KEY(fp, i);
        snprintf(txt, sizeof(txt), "%s", cidr_ipv4_to_str(key4, false));
        break;
    default:
        snprintf(txt, sizeof(txt), "%s", cidr_ipv6_to_str(key6, false));
        break;
    }

    return txt;
}

static struct fileprefops netprefs_ops = {
    .type               = "netprefs",
    .keysz              = sizeof(struct cidr_ipv6),    // XXX: What a waste of space (most CIDRs are IPv4)
    .parsekey           = netprefs_parsekey,
    .key_to_str         = netprefs_key_to_str,
    .free               = netprefs_fpfree,
    .supported_versions = { NETPREFS_VERSION, 0 }
};

static struct conf *
netprefs_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct netprefs *me;

    SXEA6(info->type == &netprefsct, "%s() with unexpected conf_type %s", __FUNCTION__, info->type->name);
    if ((me = netprefs_new(cl, info->loadflags)) != NULL)
        conf_report_load(me->fp.ops->type, me->fp.version);

    return me ? &me->conf : NULL;
}

struct netprefs *
netprefs_new(struct conf_loader *cl, unsigned loadflags)
{
    struct netprefs *me;

    if ((me = (struct netprefs *)fileprefs_new(cl, &netprefs_ops, sizeof(*me), loadflags)) != NULL)
        conf_setup(&me->conf, &netprefsct);

    return me;
}

static void
netprefs_free(struct conf *base)
{
    struct netprefs *me = CONF2NETPREFS(base);

    radixtree32_delete(me->radixtree32);
    radixtree128_delete(me->radixtree128);
    fileprefs_free(&me->fp);
}

void
netprefs_refcount_inc(struct netprefs *me)
{
    CONF_REFCOUNT_INC(me);
}

void
netprefs_refcount_dec(struct netprefs *me)
{
    CONF_REFCOUNT_DEC(me);
}

const struct prefblock *
netprefs_get_prefblock(const struct netprefs *me, uint32_t orgid)
{
    SXE_UNUSED_PARAMETER(orgid);

    return me ? me->fp.values : NULL;
}
