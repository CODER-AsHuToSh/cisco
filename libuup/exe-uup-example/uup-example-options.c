/*
 * Code to implement an example options file using a key-value format
 */

#include <errno.h>
#include <kit-alloc.h>

#if __FreeBSD__
#include <sys/socket.h>
#endif

#include "conf-loader.h"
#include "digest-store.h"
#include "key-value-config.h"
#include "key-value-entry.h"
#include "uup-example-options.h"

#define OPTIONS_OFFSET_CONF offsetof(struct example_options, conf)
#define CONSTCONF2OPT(confp) (const struct example_options *)((confp) ? (const char *)(confp) - OPTIONS_OFFSET_CONF : NULL)
#define CONF2OPT(confp)      (struct example_options *)((confp) ? (char *)(confp) - OPTIONS_OFFSET_CONF : NULL)

static struct example_options default_options = {
    .digest_store_freq           = DIGEST_STORE_DEFAULT_UPDATE_FREQ,
    .digest_store_period         = DIGEST_STORE_DEFAULT_MAXIMUM_AGE,
    .graphitelog_interval        = 60,
    .graphitelog_json_limit      = 25,
    .example_option              = 10,
};

module_conf_t CONF_OPTIONS;

static struct conf *options_allocate(const struct conf_info *info, struct conf_loader *cl);
static void options_free(struct conf *base);

static const struct conf_type optct = {
    "options",
    options_allocate,
    options_free,
};

void
example_options_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(&optct, NULL, name, fn, loadable, LOADFLAGS_NONE, NULL, 0);
}

static const struct key_value_entry *option_config;
static unsigned                      option_config_entries;

void
example_options_configure(const struct key_value_entry *optcfg, unsigned entries)
{
    option_config         = optcfg;
    option_config_entries = entries;
}

const struct example_options *
example_options_conf_get(const struct confset *set, module_conf_t m)
{
    const struct example_options *opts = &default_options;
    const struct conf *base = set ? confset_get(set, m) : NULL;

    SXEE6("(set=%p,m=%u)", set, m);

    if (base) {
        SXEA6(base->type == &optct, ": unexpected conf_type %s", base->type->name);
        opts = CONSTCONF2OPT(base);
    }
    else if (default_options.conf.type == NULL) {
        default_options.conf.type = &optct;
    }

    SXER6("return opts=%p", opts);
    return opts;
}

struct example_options *
example_options_new(struct conf_loader *cl)
{
    struct conf *conf = key_value_config_new(cl, sizeof(default_options), offsetof(struct example_options, conf),
                                             &default_options, option_config, option_config_entries, &optct, NULL, NULL);
    return (struct example_options *)((uint8_t *)conf - offsetof(struct example_options, conf));
}

static struct conf *
options_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct example_options *me;

    SXE_UNUSED_PARAMETER(info);
    SXEA6(info->type == &optct, ": unexpected conf_type %s", info->type->name);
    me = example_options_new(cl);
    return me ? &me->conf : NULL;
}

static void
options_free(struct conf *base)
{
    if (base) {
        struct example_options *me = CONF2OPT(base);
        SXEA6(base->type == &optct, ": unexpected conf_type %s", base->type->name);
        kit_free(me->digest_store_dir);
        kit_free(me);
    }
}
