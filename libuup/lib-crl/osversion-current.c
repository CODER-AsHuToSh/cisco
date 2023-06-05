#include <cjson/cJSON.h>
#include <kit-alloc.h>
#include <mockfail.h>

#include "json-file.h"
#include "osversion-current.h"
#include "conf-loader.h"
#include "conf-meta.h"

#define OSVERSION_CURRENT_VERSION 1.0    // Current version of the file format

struct osversion_current {
    struct conf      conf;
    struct json_file jsonfile;
};

#define CONSTCONF2OSVERSION_CURRENT(confp) \
        (const struct osversion_current *)((confp) ? (const char *)(confp) - offsetof(struct osversion_current, conf) : NULL)
#define CONF2OSVERSION_CURRENT(confp) \
        (struct osversion_current *)((confp) ? (char *)(confp) - offsetof(struct osversion_current, conf) : NULL)

static const struct conf_type osversion_current_conf_type;
module_conf_t CONF_OSVERSION_CURRENT;

struct osversion_current *
osversion_current_new(struct conf_loader *cl)
{
    struct osversion_current *me;

    SXEE6("(cl=?) // conf_loader_path(cl)='%s'", conf_loader_path(cl));

    if ((me = MOCKFAIL(OSVERSION_CURRENT_NEW, NULL, kit_calloc(1, sizeof(*me)))) == NULL) {
        SXEL2("&%s: Couldn't allocate %zu bytes", conf_loader_path(cl), sizeof(*me));
        goto OUT;
    }

    if (json_file_load(&me->jsonfile, cl, "osversion-current", "catalog")) {
        if (me->jsonfile.version != OSVERSION_CURRENT_VERSION)
            SXEL2("%s: JSON object version is %f, expected %f", conf_loader_path(cl), me->jsonfile.version,
                  OSVERSION_CURRENT_VERSION);
        else {
            conf_setup(&me->conf, &osversion_current_conf_type);
            goto OUT;
        }
    }

    if (me) {
        kit_free(me);
        me = NULL;
    }

OUT:
    SXER6("return %p;", me);
    return me;
}

static struct conf *
osversion_current_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct osversion_current *me;

    SXEA6(info->type == &osversion_current_conf_type, ": unexpected conf_type %s", info->type->name);

    if ((me = osversion_current_new(cl)) != NULL)
        conf_report_load(info->type->name, me->jsonfile.version);

    return me ? &me->conf : NULL;
}

static void
osversion_current_free(struct conf *base)
{
    struct osversion_current *me = CONF2OSVERSION_CURRENT(base);

    SXEA6(base->type == &osversion_current_conf_type, ": unexpected conf_type %s", base->type->name);
    json_file_fini(&me->jsonfile);
    kit_free(me);
}

static const struct conf_type osversion_current_conf_type = {
    "osversion_current",
    osversion_current_allocate,
    osversion_current_free,
};

/**
 * Register an osversion-current file with the conf system
 *
 * @param m       Pointer to the module identifier for the policy directory
 * @param name    Name of the policy (e.g. rules for umbrella unified policy, rules-auth-latitude for posture policy)
 * @param fn      File name pattern containing a %u to be replaced by the org id
 * @param filter  Unused filter parameter
 */
void
osversion_current_register(module_conf_t *m, const char *name, const char *fn, const char *filter)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    SXE_UNUSED_PARAMETER(filter);
    *m = conf_register(&osversion_current_conf_type, NULL, name, fn, true, LOADFLAGS_NONE, NULL, 0);
}

const struct osversion_current *
osversion_current_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &osversion_current_conf_type, ": unexpected conf_type %s", base->type->name);
    return CONSTCONF2OSVERSION_CURRENT(base);
}

const cJSON *
osversion_current_get_data(const struct osversion_current *me)
{
    return me->jsonfile.data;
}

