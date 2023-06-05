#include <ctype.h>
#include <errno.h>
#include <kit.h>
#include <kit-alloc.h>
#include <mockfail.h>

#include "cidr-ipv4.h"
#include "cidr-ipv6.h"
#include "conf-loader.h"
#include "geoip.h"
#include "radixtree128.h"
#include "radixtree32.h"

#define GEOIP_NOT_V6 255    /* A "special" IPv6 mask value to indicate that the CIDR (in the union) is IPv4 */

struct ccmap {
    union {
        struct cidr_ipv4 v4;
        struct cidr_ipv6 v6;
    } __attribute__ ((__packed__));
    char cc[3];
    uint32_t region;
} __attribute__ ((__packed__));

struct geoip {
    struct conf conf;
    struct ccmap *keys;
    struct radixtree32 *v4;
    struct radixtree128 *v6;
};

#define CONSTCONF2GEOIP(confp) (const struct geoip *)((confp) ? (const char *)(confp) - offsetof(struct geoip, conf) : NULL)
#define CONF2GEOIP(confp)      (struct geoip *)((confp) ? (char *)(confp) - offsetof(struct geoip, conf) : NULL)
#define CIDR_IPV42CCMAP(v4)    (struct ccmap *)((v4) ? (char *)(v4) - offsetof(struct ccmap, v4) : NULL)
#define CIDR_IPV62CCMAP(v6)    (struct ccmap *)((v6) ? (char *)(v6) - offsetof(struct ccmap, v6) : NULL)

module_conf_t CONF_GEOIP;
module_conf_t CONF_REGIONIP;

static struct conf *geoip_allocate(const struct conf_info *info, struct conf_loader *cl);
static void geoip_free(struct conf *base);

static const struct conf_type geoipct = {
    "geoip",
    geoip_allocate,
    geoip_free,
};

void
geoip_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(&geoipct, NULL, name, fn, loadable, LOADFLAGS_NONE, NULL, 0);
}

const struct geoip *
geoip_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &geoipct, "geoip_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2GEOIP(base);
}

static struct geoip *
geoip_new(struct conf_loader *cl)
{
    unsigned count, item, version;
    struct geoip *me, *retme;
    const char *line, *p;
    unsigned long region;
    char *end;

    SXEE6("(cl=%s)", conf_loader_path(cl));
    me = retme = NULL;
    count = 0;

    if ((line = conf_loader_readline(cl)) == NULL || sscanf(line, "geoip %u\n", &version) != 1) {
        SXEL2("%s: %u: Failed to read type/version", conf_loader_path(cl), conf_loader_line(cl));
        goto OUT;
    }
    if (version != GEOIP_VERSION) {
        SXEL2("%s: %u: Invalid version %u", conf_loader_path(cl), conf_loader_line(cl), version);
        goto OUT;
    }
    if ((line = conf_loader_readline(cl)) == NULL || sscanf(line, "count %u\n", &count) != 1) {
        SXEL2("%s: %u: v%u: Invalid count line", conf_loader_path(cl), conf_loader_line(cl), version);
        goto OUT;
    }

    if ((me = MOCKFAIL(GEOIP_NEW, NULL, kit_calloc(1, sizeof(*me)))) == NULL) {
        SXEL2("%s: Failed to calloc a geoip structure", conf_loader_path(cl));
        goto OUT;
    }
    conf_setup(&me->conf, &geoipct);
    if ((me->keys = MOCKFAIL(GEOIP_KEYS_NEW, NULL, kit_malloc(sizeof(*me->keys) * count))) == NULL) {
        SXEL2("%s: Failed to allocate geoip keys (%u entries)", conf_loader_path(cl), count);
        goto OUT;
    }

    for (item = 0; (line = conf_loader_readline(cl)) != NULL && item < count; item++) {
        if ((p = cidr_ipv4_sscan_verbose(&me->keys[item].v4, conf_loader_path(cl), conf_loader_line(cl),
                                         line, PARSE_IP_OR_CIDR)) != NULL) {
            me->keys[item].v6.maskbits = GEOIP_NOT_V6;
            if (me->v4 == NULL && (me->v4 = radixtree32_new()) == NULL) {
                SXEL2("%s: %u: Not enough memory to allocate a radixtree32", conf_loader_path(cl), conf_loader_line(cl));
                goto OUT;
            }
            if (!radixtree32_put(me->v4, &me->keys[item].v4)) {
                SXEL2("%s: %u: Failed to insert a new radixtree32 node", conf_loader_path(cl), conf_loader_line(cl));
                goto OUT;
            }
        } else if ((p = cidr_ipv6_sscan_verbose(&me->keys[item].v6, conf_loader_path(cl), conf_loader_line(cl),
                                                line, PARSE_IP_OR_CIDR)) != NULL) {
            if (me->v6 == NULL && (me->v6 = radixtree128_new()) == NULL) {
                SXEL2("%s: %u: Not enough memory to allocate a radixtree128", conf_loader_path(cl), conf_loader_line(cl));
                goto OUT;
            }
            if (!radixtree128_put(me->v6, &me->keys[item].v6)) {
                SXEL2("%s: %u: Failed to insert a new radixtree128 node", conf_loader_path(cl), conf_loader_line(cl));
                goto OUT;
            }
        } else {
            SXEL2("%s: %u: v%u: Unrecognised line (invalid CIDR)",
                  conf_loader_path(cl), conf_loader_line(cl), GEOIP_VERSION);
            goto OUT;
        }
        if (!isspace(*p++)) {
            SXEL2("%s: %u: v%u lines must have two space separated columns",
                  conf_loader_path(cl), conf_loader_line(cl), GEOIP_VERSION);
            goto OUT;
        }
        while (isspace(*p))
            p++;
        if (!isalpha(p[0]) || !isalpha(p[1])) {
            SXEL2("%s: %u: v%u lines must have a two character country code",
                  conf_loader_path(cl), conf_loader_line(cl), GEOIP_VERSION);
            goto OUT;
        }
        me->keys[item].cc[0] = p[0];
        me->keys[item].cc[1] = p[1];
        me->keys[item].cc[2] = '\0';
        p += 2;
        if (*p == '-' && (region = kit_strtoul(p + 1, &end, 10)) != 0 && !errno && (me->keys[item].region = region) == region)
            p = end;
        else
            me->keys[item].region = 0;

        while (isspace(*p))
            p++;
        if (*p) {
            SXEL2("%s: %u: trailing garbage found", conf_loader_path(cl), conf_loader_line(cl));
            goto OUT;
        }
    }

    if (item != count) {
        SXEL2("%s: %u: v%u: Expected %u but got %u entr%s",
              conf_loader_path(cl), conf_loader_line(cl), version, count, item, item == 1 ? "y" : "ies");
        goto OUT;
    }
    if (!conf_loader_eof(cl)) {
        SXEL2("%s: %u: v%u: More entries present in the file than expected",
              conf_loader_path(cl), conf_loader_line(cl), version);
        goto OUT;
    }

    retme = me;

OUT:
    if (retme != me) {
        CONF_REFCOUNT_DEC(me);
        errno = EINVAL;
    }

    SXER6("return %p // %u records", retme, count);

    return retme;
}

static struct conf *
geoip_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct geoip *me;

    SXEA6(info->type == &geoipct, "%s() with unexpected conf_type %s", __FUNCTION__, info->type->name);
    if ((me = geoip_new(cl)) != NULL)
        conf_report_load(info->type->name, GEOIP_VERSION);
    return me ? &me->conf : NULL;
}

const char *
geoip_cc(const struct geoip *me, const struct netaddr *addr, uint32_t *region)
{
    struct cidr_ipv6 *v6;
    struct cidr_ipv4 *v4;
    struct ccmap *map;

    SXEE7("(me=%p, addr=%s, x=?)", me, netaddr_to_str(addr));

    map = NULL;
    if (me) {
        switch (addr->family) {
        case AF_INET:
            v4 = radixtree32_get(me->v4, addr->in_addr);
            map = CIDR_IPV42CCMAP(v4);
            break;
        case AF_INET6:
            v6 = radixtree128_get(me->v6, &addr->in6_addr);
            map = CIDR_IPV62CCMAP(v6);
            break;
        }
        SXEL6("%s is country code %s", netaddr_to_str(addr), map ? map->cc : "<none>");    /* COVERAGE EXCLUSION: Debug output. Why does gcov care? */
    }

    if (region)
        *region = map ? map->region : 0;

    SXER7("return %s // region %u", map ? map->cc : "<null>", map ? map->region : 0);
    return map ? map->cc : NULL;
}

static void
geoip_free(struct conf *base)
{
    struct geoip *me = CONF2GEOIP(base);

    if (me) {
        radixtree32_delete(me->v4);
        radixtree128_delete(me->v6);
        kit_free(me->keys);
        kit_free(me);
    }
}
