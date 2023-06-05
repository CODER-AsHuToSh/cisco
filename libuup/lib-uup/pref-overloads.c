/*-
 * The configuration file passed to pref_overloads_allocate() should have this format:
 *   pref-overloads 2
 *   <type>:<index>:<orgflags>:<overridable-orgflags>:<bundleflags>:<overridable-bundleflags>:<categories>:<overridable-categories>
 *   ....
 */

#include <ctype.h>
#include <errno.h>
#include <kit-alloc.h>
#include <mockfail.h>

#include "conf-loader.h"
#include "pref-overloads.h"

#define REALLOC_COUNT          10    /* How many new entries we realloc at a time */

struct ip4_pref {
    struct in_addr v4;
    struct overloaded_pref pref;
} __attribute__ ((__packed__));

struct ip6_pref {
    struct in6_addr v6;
    struct overloaded_pref pref;
} __attribute__ ((__packed__));

struct country_pref {
    char country_code[3];
    uint32_t region;
    struct overloaded_pref pref;
} __attribute__ ((__packed__));

struct pref_overloads {
    struct conf conf;
    struct overloaded_pref default_listener;
    struct ip4_pref *ip4_block;
    size_t ip4_count;
    struct ip6_pref *ip6_block;
    size_t ip6_count;
    struct country_pref *country_block;
    size_t country_count;
};

#define CONSTCONF2PO(confp) (const struct pref_overloads *)((confp) ? (const char *)(confp) - offsetof(struct pref_overloads, conf) : NULL)
#define CONF2PO(confp) (struct pref_overloads *)((confp) ? (char *)(confp) - offsetof(struct pref_overloads, conf) : NULL)

module_conf_t CONF_PREF_OVERLOADS;

static struct conf *pref_overloads_allocate(const struct conf_info *info, struct conf_loader *cl);
static void pref_overloads_free(struct conf *base);

static const struct conf_type poct = {
    "pref-overloads",
    pref_overloads_allocate,
    pref_overloads_free,
};

void
pref_overloads_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(&poct, NULL, name, fn, loadable, LOADFLAGS_NONE, NULL, 0);
}

const struct pref_overloads *
pref_overloads_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &poct, "pref_overloads_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2PO(base);
}

static int
consumeaddr(struct netaddr *addr, const char *str)
{
    char buf[INET6_ADDRSTRLEN];
    sa_family_t family;
    const char *end;
    int consumed;

    if (*str == '[') {
        if ((end = strchr(++str, ']')) == NULL || end - str >= INET6_ADDRSTRLEN || end[1] != ':')
            return -1;
        consumed = end - str + 3;
        family = AF_INET6;
    } else if ((end = strchr(str, ':')) != NULL && end - str <= INET6_ADDRSTRLEN) {
        consumed = end - str + 1;
        family = AF_INET;
    } else
        return -1;

    memcpy(buf, str, end - str);
    buf[end - str] = '\0';
    return netaddr_from_str(addr, buf, family) ? consumed : -1;
}

static int
cccmp(const void *a, const void *b)
{
     return memcmp(a, b, 2) ?: (int)((const struct country_pref *)a)->region - (int)((const struct country_pref *)b)->region;
}

static int
v4cmp(const void *a, const void *b)
{
     return memcmp(a, b, 4);
}

static int
v6cmp(const void *a, const void *b)
{
     return memcmp(a, b, 16);
}

static struct conf *
pref_overloads_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct country_pref *country_block, *country_pref;
    size_t ip4_alloc, ip6_alloc, country_alloc;
    struct ip4_pref *ip4_block, *ip4_pref;
    struct ip6_pref *ip6_block, *ip6_pref;
    struct pref_overloads *me, *retme;
    struct overloaded_pref *pref;
    unsigned fieldnum, version;
    unsigned long region;
    const char *line, *p;
    struct netaddr addr;
    char colon, *end;
    uint64_t flags;
    int consumed;
    unsigned i;

    SXEA6(info->type == &poct, "%s() with unexpected conf_type %s", __FUNCTION__, info->type->name);

    me = retme = NULL;

    if ((line = conf_loader_readline(cl)) == NULL || sscanf(line, "pref-overloads %u\n", &version) != 1) {
        SXEL2("%s: %u: Failed to read type/version", conf_loader_path(cl), conf_loader_line(cl));
        goto SXE_EARLY_OUT;
    }
    if (version != PREF_OVERLOADS_VERSION) {
        SXEL2("%s: %u: Invalid version %d (must be %d)", conf_loader_path(cl), conf_loader_line(cl),
              version, PREF_OVERLOADS_VERSION);
        goto SXE_EARLY_OUT;
    }

    if ((me = MOCKFAIL(PREF_OVERLOADS_NEW, NULL, kit_calloc(1, sizeof(*me)))) == NULL) {
        SXEL2("%s: Failed to calloc a pref-overloads structure", conf_loader_path(cl));
        goto SXE_EARLY_OUT;
    }
    conf_setup(&me->conf, info->type);
    pref_categories_setall(&me->default_listener.overridable_categories);
    me->default_listener.overridable_bundleflags = ~(pref_bundleflags_t)0;
    me->default_listener.overridable_orgflags = ~(pref_orgflags_t)0;

    ip4_alloc = ip6_alloc = country_alloc = 0;
    while ((line = conf_loader_readline(cl)) != NULL) {
        if (strncmp(line, "country:", 8) == 0) {
            if (country_alloc == me->country_count) {
                country_alloc += REALLOC_COUNT;
                if ((country_block = MOCKFAIL(PREF_OVERLOADS_CC_NEW, NULL, kit_realloc(me->country_block, country_alloc * sizeof(*country_block)))) == NULL) {
                    SXEL2("%s: Failed to allocate country prefs (%zu entries)", conf_loader_path(cl), country_alloc);
                    goto SXE_EARLY_OUT;
                }
                me->country_block = country_block;
            }
            country_pref = me->country_block + me->country_count;
            p = line + 8;
            if (!isalpha(p[0]) || !isalpha(p[1]) || (p[2] != ':' && p[2] != '-')) {
                SXEL2("%s: %u: Field 1 invalid: Expected 2 character country code", conf_loader_path(cl), conf_loader_line(cl));
                goto SXE_EARLY_OUT;
            }
            country_pref->country_code[0] = *p++;
            country_pref->country_code[1] = *p++;
            country_pref->country_code[2] = '\0';
            if (*p == '-') {
                if ((region = strtoul(p + 1, &end, 10)) == 0 || errno || *end != ':' || (country_pref->region = region) != region) {
                    SXEL2("%s: %u: Field 1 invalid: Expected a geo region number", conf_loader_path(cl), conf_loader_line(cl));
                    goto SXE_EARLY_OUT;
                }
                p = end;
            } else
                country_pref->region = 0;
            p++;
            pref = &country_pref->pref;
            me->country_count++;
        } else if (strncmp(line, "listener:", 9) == 0) {
            p = line + 9;
            if (*p == ':') {
                /* The default 'listener' case has an empty IP address */
                pref = &me->default_listener;
                p++;
            } else {
                if ((consumed = consumeaddr(&addr, p)) == -1) {
                    SXEL2("%s: %u: Field 1 invalid: Expected an IP address", conf_loader_path(cl), conf_loader_line(cl));
                    goto SXE_EARLY_OUT;
                }
                if (addr.family == AF_INET) {
                    if (ip4_alloc == me->ip4_count) {
                        ip4_alloc += REALLOC_COUNT;
                        if ((ip4_block = MOCKFAIL(PREF_OVERLOADS_IP4_NEW, NULL, kit_realloc(me->ip4_block, ip4_alloc * sizeof(*ip4_block)))) == NULL) {
                            SXEL2("%s: Failed to allocate ip4 prefs (%zu entries)", conf_loader_path(cl), ip4_alloc);
                            goto SXE_EARLY_OUT;
                        }
                        me->ip4_block = ip4_block;
                    }
                    ip4_pref = me->ip4_block + me->ip4_count;
                    memcpy(&ip4_pref->v4, &addr.addr, NETADDR_SIZE(&addr));
                    pref = &ip4_pref->pref;
                    me->ip4_count++;
                } else {
                    if (ip6_alloc == me->ip6_count) {
                        ip6_alloc += REALLOC_COUNT;
                        if ((ip6_block = MOCKFAIL(PREF_OVERLOADS_IP6_NEW, NULL, kit_realloc(me->ip6_block, ip6_alloc * sizeof(*ip6_block)))) == NULL) {
                            SXEL2("%s: Failed to allocate ip6 prefs (%zu entries)", conf_loader_path(cl), ip6_alloc);
                            goto SXE_EARLY_OUT;
                        }
                        me->ip6_block = ip6_block;
                    }
                    ip6_pref = me->ip6_block + me->ip6_count;
                    memcpy(&ip6_pref->v6, &addr.addr, NETADDR_SIZE(&addr));
                    pref = &ip6_pref->pref;
                    me->ip6_count++;
                }
                p += consumed;
            }
        } else {
            SXEL2("%s: %u: Field 0 invalid: Expected 'country' or 'listener'", conf_loader_path(cl), conf_loader_line(cl));
            goto SXE_EARLY_OUT;
        }

        const struct {
            const char *name;
            pref_orgflags_t *var;
        } org_field[] = {
            { "orgflags", &pref->orgflags },
            { "overridable_orgflags", &pref->overridable_orgflags },
        };
        unsigned last = sizeof(org_field) / sizeof(*org_field);

        SXEA6(sizeof(*org_field[0].var) == sizeof(pref_orgflags_t), "Expected pref_orgflags to be 64 bits");
        SXEA6(last == 2, "Expected exactly 2 org flag fields");

        /* Parse "orgflags:overridable_orgflags:" */
        for (fieldnum = 2, i = 0; i < last; i++) {
            flags = kit_strtoull(p, &end, 16);
            if (end == line || *end != ':' || errno != 0) {
                SXEL2("%s: %u: Field %u invalid: Expected hex %s", conf_loader_path(cl), conf_loader_line(cl), fieldnum, org_field[i].name);
                goto SXE_EARLY_OUT;
            }
            *org_field[i].var = flags;
            fieldnum++;
            p = end + 1;
        }

        const struct {
            const char *name;
            uint32_t *var;
        } bundle_field[] = {
            { "bundleflags", &pref->bundleflags },
            { "overridable_bundleflags", &pref->overridable_bundleflags },
        };
        last = sizeof(bundle_field) / sizeof(*bundle_field);

        SXEA6(sizeof(*bundle_field[0].var) == sizeof(pref_bundleflags_t), "Expected pref_bundleflags to be 32 bits");
        SXEA6(last == 2, "Expected exactly 2 bundle flag fields");

        /* Parse "bundleflags:overridable_bundleflags:" */
        for (i = 0; i < last; i++) {
            if (sscanf(p, "%" PRIx64 "%c%n", &flags, &colon, &consumed) != 2 || colon != ':' || flags != (uint32_t)flags) {
                SXEL2("%s: %u: Field %u invalid: Expected hex %s", conf_loader_path(cl), conf_loader_line(cl), fieldnum, bundle_field[i].name);
                goto SXE_EARLY_OUT;
            }
            *bundle_field[i].var = flags;
            fieldnum++;
            p += consumed;
        }

        /* Parse "categories:overridable-categories" */
        if ((consumed = pref_categories_sscan(&pref->categories, p)) == 0 || p[consumed] != ':') {
            SXEL2("%s: %u: Field %u invalid: Expected hex categories", conf_loader_path(cl), conf_loader_line(cl), fieldnum);
            goto SXE_EARLY_OUT;
        }
        fieldnum++;
        p += consumed + 1;
        if ((consumed = pref_categories_sscan(&pref->overridable_categories, p)) == 0 || (p[consumed] != '\n' && p[consumed] != '\0')) {
            SXEL2("%s: %u: Field %u invalid: Expected hex overridable-categories", conf_loader_path(cl), conf_loader_line(cl), fieldnum);
            goto SXE_EARLY_OUT;
        }
    }

    if (conf_loader_eof(cl)) {
        if (me->country_block) {
            me->country_block = kit_reduce(me->country_block, me->country_count * sizeof(*me->country_block));
            qsort(me->country_block, me->country_count, sizeof(*me->country_block), cccmp);
        }
        if (me->ip4_block) {
            me->ip4_block = kit_reduce(me->ip4_block, me->ip4_count * sizeof(*me->ip4_block));
            qsort(me->ip4_block, me->ip4_count, sizeof(*me->ip4_block), v4cmp);
        }
        if (me->ip6_block) {
            me->ip6_block = kit_reduce(me->ip6_block, me->ip6_count * sizeof(*me->ip6_block));
            qsort(me->ip6_block, me->ip6_count, sizeof(*me->ip6_block), v6cmp);
        }

        retme = me;
        conf_report_load(info->type->name, PREF_OVERLOADS_VERSION);
    }

SXE_EARLY_OUT:
    if (me != retme) {
        CONF_REFCOUNT_DEC(me);
        errno = EINVAL;
    }

    return retme ? &retme->conf : NULL;
}

static void
pref_overloads_free(struct conf *base)
{
    struct pref_overloads *me = CONF2PO(base);

    SXEE6("(pref_overloads=%p)", me);

    if (me) {
        kit_free(me->ip4_block);
        kit_free(me->ip6_block);
        kit_free(me->country_block);
        kit_free(me);
    }

    SXER6("return");
}

const struct overloaded_pref *
pref_overloads_default_listener(const struct pref_overloads *me)
{
    static struct overloaded_pref def;
    static bool init;

    if (!me && !init) {
        def.orgflags = 0;
        def.overridable_orgflags = ~(pref_orgflags_t)0;
        def.bundleflags = 0;
        def.overridable_bundleflags = ~(pref_bundleflags_t)0;
        pref_categories_setnone(&def.categories);
        pref_categories_setall(&def.overridable_categories);
        init = true;
    }
    return me ? &me->default_listener : &def;
}

const struct overloaded_pref *
pref_overloads_byip(const struct pref_overloads *me, const struct netaddr *addr)
{
    struct ip4_pref *ip4_pref;
    struct ip6_pref *ip6_pref;

    if (me) {
        if (addr->family == AF_INET) {
            if ((ip4_pref = bsearch(&addr->addr, me->ip4_block, me->ip4_count, sizeof(*me->ip4_block), v4cmp)) != NULL)
                return &ip4_pref->pref;
        } else if ((ip6_pref = bsearch(&addr->addr, me->ip6_block, me->ip6_count, sizeof(*me->ip6_block), v6cmp)) != NULL)
            return &ip6_pref->pref;
    }

    return NULL;
}

const struct overloaded_pref *
pref_overloads_bycc(const struct pref_overloads *me, const char country_code[3], uint32_t region)
{
    struct country_pref *cp, key;

    memcpy(key.country_code, country_code, sizeof(key.country_code));
    key.region = region;

    if (me) {
        if ((cp = bsearch(&key, me->country_block, me->country_count, sizeof(*me->country_block), cccmp)) != NULL)
            return &cp->pref;
        if (region) {
            key.region = 0;
            if ((cp = bsearch(&key, me->country_block, me->country_count, sizeof(*me->country_block), cccmp)) != NULL)
                return &cp->pref;
        }
    }

    return NULL;
}
