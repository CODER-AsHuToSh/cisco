#include <kit-alloc.h>
#include <mockfail.h>

#include "fileprefs.h"
#include "networks-private.h"
#include "radixtree128.h"
#include "radixtree32.h"
#include "xray.h"

/*-
 * A struct network is a mapping from a CIDR to an origin id, origin type id, and org id.
 *
 *  keys                     values
 *  .-------------.         .-----------------------------------.
 *  | cidr0       |         | originid | origin_type_id | orgid |
 *  |-------------|         |-----------------------------------|
 *  | cidr1       |         | value1                            |
 *  .-------------.         .-----------------------------------|
 *  .             .         .                                   .
 *  .             .         .                                   .
 *  .-------------.         .-----------------------------------|
 *  | cidrN       |         | valueN                            |
 *  `-------------'         `-----------------------------------'
 *
 * key size is set to sizeof(struct cidr_ipv6); all value fields are uint32_t
 *
 * Note, networks are not required to be in order and are searched
 * using the networks::radixtree32 and networks::radixtree128 objects.
 */

#define CONSTCONF2NETWORKS(confp) (const struct networks *)((confp) ? (const char *)(confp) - offsetof(struct networks, conf) : NULL)
#define CONF2NETWORKS(confp)      (struct networks *)((confp) ? (char *)(confp) - offsetof(struct networks, conf) : NULL)

#define NETWORK_FROM_CIDR(cidr) (const struct network *)((const uint8_t *)(cidr) - offsetof(struct network, addr))

module_conf_t CONF_NETWORKS;

static struct conf *networks_allocate(const struct conf_info *info, struct conf_loader *cl);
static void networks_free(struct conf *base);

static const struct conf_type networksct = {
    "networks",
    networks_allocate,
    networks_free,
};

void
networks_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(&networksct, NULL, name, fn, loadable, LOADFLAGS_NONE, NULL, 0);
}

const struct networks *
networks_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &networksct, "networks_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2NETWORKS(base);
}

const struct network *
networks_get(const struct networks *me, const struct netaddr *addr, struct xray *x)
{
    struct cidr_ipv6 *k6;
    struct cidr_ipv4 *k4;
    const struct network *network = NULL;

    SXEE7("(networks=%p, addr=%s, x=?)", me, netaddr_to_str(addr));

    if (me != NULL) {
        switch (addr->family) {
        case AF_INET:
            if ((k4 = radixtree32_get(me->radixtree32, addr->in_addr)) != NULL) {
                network = NETWORK_FROM_CIDR(k4);
            }
            break;
        case AF_INET6:
            if ((k6 = radixtree128_get(me->radixtree128, &addr->in6_addr)) != NULL) {
                network = NETWORK_FROM_CIDR(k6);
            }
            break;
        }

        if (network == NULL)
            XRAY7(x, "networks match: none for addr=%s", netaddr_to_str(addr));
        else
            XRAY7(x, "networks match: found: org %" PRIu32 " origin %" PRIu32 " for addr=%s",
                  network->org_id, network->origin_id, netaddr_to_str(addr));
    }

    SXER7("return %p // org_id=%" PRIu32 ", origin_id=%" PRIu32, network, network ? network->org_id : 0,
          network ? network->origin_id : 0);

    return network;
}

static struct conf *
networks_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct networks *me;

    SXEA6(info->type == &networksct, "%s() with unexpected conf_type %s", __FUNCTION__, info->type->name);
    SXE_UNUSED_PARAMETER(info);

    if ((me = networks_new(cl)) != NULL)
        conf_report_load("networks", NETWORKS_VERSION);

    return me ? &me->conf : NULL;
}

struct networks *
networks_new(struct conf_loader *cl)
{
    struct fileprefs file_prefs;
    struct networks *me;
    unsigned        *ok_vers = NULL;
    const char      *line;
    unsigned         count, i, running, total, version;
    char             separator;

    static struct fileprefops networks_ops = {
        .type = "networks",
        .supported_versions = {NETWORKS_VERSION, 0}
    };

    SXEE6("(cl=%s)", conf_loader_path(cl));
    me    = NULL;
    count = 0;
    fileprefs_init(&file_prefs, &networks_ops, 0);

    // First line should be 'networks' followed by at least one integer version number
    if (!fileprefs_load_fileheader(&file_prefs, cl, &total, &ok_vers))
        goto EARLY_OUT;

    if ((me = MOCKFAIL(NETWORKS_NEW, NULL, kit_malloc(sizeof(*me)))) == NULL) {
        SXEL2("%s: Failed to malloc a networks structure", conf_loader_path(cl));
        goto EARLY_OUT;
    }

    conf_setup(&me->conf, &networksct);
    me->count   = 0;
    me->networks = NULL;
    me->radixtree32 = NULL;
    me->radixtree128 = NULL;

    if ((me->radixtree32 = radixtree32_new()) == NULL) {
        SXEL2("%s: Failed to allocate radixtree32", conf_loader_path(cl));
        goto ERROR_OUT;
    }

    if ((me->radixtree128 = radixtree128_new()) == NULL) {
        SXEL2("%s: Failed to allocate radixtree128", conf_loader_path(cl));
        goto ERROR_OUT;
    }

    for (running = 0; running < total; running += count) {
        if ((line = conf_loader_readline(cl)) == NULL || sscanf(line, "[networks:%u:%u]\n", &count, &version) != 2) {
            SXEL2("%s: %u: Failed to read '[networks:<count>:<version>]'", conf_loader_path(cl), conf_loader_line(cl));
            goto ERROR_OUT;
        }

        if (version == NETWORKS_VERSION) {
            if ((me->count = count) > 0
                && (me->networks = MOCKFAIL(NETWORKS_ARRAY_NEW, NULL, kit_malloc(count * sizeof(*me->networks)))) == NULL) {
                SXEL2("%s: Failed to malloc a network array", conf_loader_path(cl));
                goto ERROR_OUT;
            }

            for (i = 0; i < count; i++) {
                uint64_t origin_id;                      // Read as 64 bit to detect 32 bit overflows
                uint64_t org_id;                         // Read as 64 bit to detect 32 bit overflows
                uint64_t origin_type;                    // For now, just discard this field
                struct network *network = &me->networks[i];
                const char *p;

                separator = '\n';

                if ((line = conf_loader_readline(cl)) == NULL) {
                    SXEL2("%s: %u: Count %u, but only %u networks", conf_loader_path(cl), conf_loader_line(cl), count, i);
                    goto ERROR_OUT;
                }

                if ((p = cidr_ipv4_sscan_verbose(&network->addr.v4, conf_loader_path(cl), conf_loader_line(cl), line, PARSE_CIDR_ONLY)) != NULL && *p++ == ':') {
                    network->family = AF_INET;
                } else if ((p = cidr_ipv6_sscan_verbose(&network->addr.v6, conf_loader_path(cl), conf_loader_line(cl), line, PARSE_CIDR_ONLY)) != NULL && *p++ == ':') {
                    network->family = AF_INET6;
                } else {
                    SXEL2("%s: %u: expected CIDR at start of line: %s", conf_loader_path(cl), conf_loader_line(cl), line);
                    goto ERROR_OUT;
                }

                if (sscanf(p, "%10" SCNu64 ":%10" SCNu64 ":%10" SCNu64 "%c",
                                &origin_id, &origin_type, &org_id, &separator) < 4)
                    SXEL2("%s: %u: Expected <origin-id>:<origin-type-id>:<organization-id>, not '%s'",
                            conf_loader_path(cl), conf_loader_line(cl), p);
                else if ((network->origin_id = origin_id) != origin_id)
                    SXEL2("%s: %u: Origin id %" PRIu64 " overflows 32 bits", conf_loader_path(cl), conf_loader_line(cl), origin_id);
                else if ((network->org_id = org_id) != org_id)
                    SXEL2("%s: %u: Org id %" PRIu64 " overflows 32 bits", conf_loader_path(cl), conf_loader_line(cl), org_id);
                else if (separator != '\n')
                    SXEL2("%s: %u: Org id is followed by '%c', not end of line", conf_loader_path(cl), conf_loader_line(cl),
                            separator);
                else {
                    if (network->family == AF_INET) {
                        if (!radixtree32_put(me->radixtree32, &network->addr.v4)) {
                            SXEL2("Failed to insert a new radixtree32 node");
                            goto ERROR_OUT;
                        }
                    } else {
                        SXEA6(network->family == AF_INET6, "Family should be v4 or v6: %u", network->family);
                        if (!radixtree128_put(me->radixtree128, &network->addr.v6)) {
                            SXEL2("Failed to insert a new radixtree128 node");
                            goto ERROR_OUT;
                        }
                    }

                    continue;
                }

                goto ERROR_OUT;
            }
        }
        else
            for (i = 0; i < count; i++) {
                if ((line = conf_loader_readline(cl)) == NULL)
                    SXEL2("%s: %u: Section count %u, but only %u lines at EOF", conf_loader_path(cl), conf_loader_line(cl),
                            count, i);
                else if (strncmp(line, "[networks", sizeof("[networks") - 1) == 0)
                    SXEL2("%s: %u: Section count %u but '[networks:' found after %u lines",
                            conf_loader_path(cl), conf_loader_line(cl), count, i);
                else
                    continue;

                goto ERROR_OUT;
            }
    }

    if (running == total && (line = conf_loader_readline(cl)) == NULL)
        goto EARLY_OUT;

    SXEL2("%s: %u: More than %u total line%s", conf_loader_path(cl), conf_loader_line(cl), total, total == 1 ? "" : "s");

ERROR_OUT:
    if (me) {
        kit_free(me->networks);
        radixtree32_delete(me->radixtree32);
        radixtree128_delete(me->radixtree128);
        kit_free(me);
        me = NULL;
    }

EARLY_OUT:
    if (ok_vers)
        kit_free(ok_vers);

    SXER6("return %p // %u records", me, count);
    return me;
}

static void
networks_free(struct conf *base)
{
    struct networks *me = CONF2NETWORKS(base);

    if (me) {
        kit_free(me->networks);
        radixtree32_delete(me->radixtree32);
        radixtree128_delete(me->radixtree128);
        kit_free(me);
    }
}
