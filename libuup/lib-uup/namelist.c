#include <errno.h>
#include <kit-alloc.h>
#include <mockfail.h>

#include "conf-loader.h"
#include "dns-name.h"
#include "namelist.h"
#include "parseline.h"

struct namelist_node {
    struct namelist_node *next;
    uint8_t name[];
};

struct namelist {
    struct conf conf;
    struct namelist_node *first;
};

#define CONSTCONF2NL(confp) (const struct namelist *)((confp) ? (const char *)(confp) - offsetof(struct namelist, conf) : NULL)
#define CONF2NL(confp)      (struct namelist *)((confp) ? (char *)(confp) - offsetof(struct namelist, conf) : NULL)

module_conf_t CONF_TYPO_EXCEPTION_PREFIXES;

static struct conf *namelist_allocate(const struct conf_info *info, struct conf_loader *cl);
static void namelist_free(struct conf *base);

static const struct conf_type nlct = {
    "namelist",
    namelist_allocate,
    namelist_free,
};

void
namelist_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(&nlct, NULL, name, fn, loadable, LOADFLAGS_NONE, NULL, 0);
}

const struct namelist *
namelist_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &nlct, "namelist_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2NL(base);
}

static struct conf *
namelist_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    uint8_t name[DNS_MAXLEN_NAME];
    struct namelist_node *node;
    struct namelist *me;
    const char *line;
    unsigned    name_len;

    SXEA6(info->type == &nlct, "%s() with unexpected conf_type %s", __FUNCTION__, info->type->name);

    if ((me = MOCKFAIL(NAMELIST_ALLOCATE, NULL, kit_malloc(sizeof(*me)))) == NULL) {
        SXEL2("Failed to allocate a struct namelist");
        goto ERROR;
    }

    conf_setup(&me->conf, info->type);
    me->first = NULL;

    while ((line = conf_loader_readline(cl)) != NULL) {
        name_len = sizeof(name);
        if (dns_name_sscan_len(line, WHITESPACE, name, &name_len) == NULL) {
            SXEL2("%s: %u: Invalid domain name", conf_loader_path(cl), conf_loader_line(cl));
            goto ERROR;
        }

        if ((node = MOCKFAIL(NAMELIST_ALLOCATE_NODE, NULL, kit_malloc(sizeof(*node) + name_len))) == NULL) {
            SXEL2("Failed to allocate a namelist_node");
            goto ERROR;
        }

        memcpy(node->name, name, name_len);
        node->next = me->first;
        me->first = node;
    }

    if (conf_loader_eof(cl) && !conf_loader_err(cl))
        return &me->conf;

ERROR:                      /* COVERAGE EXCLUSION: Why gcov 7+ do we need this here???? */
    CONF_REFCOUNT_DEC(me);
    errno = EINVAL;
    return NULL;
}

static void
namelist_free(struct conf *base)
{
    struct namelist *me = CONF2NL(base);
    struct namelist_node *next;

    if (me) {
        while (me->first) {
            next = me->first->next;
            kit_free(me->first);
            me->first = next;
        }
        kit_free(me);
    }
}

bool
namelist_prefix_match(const struct namelist *me, const uint8_t *name)
{
    const struct namelist_node *node;

    for (node = me ? me->first : NULL; node; node = node->next)
        if (dns_name_has_prefix(name, node->name))
            return true;

    return false;
}
