#ifndef UUP_EXAMPLE_OPTIONS_H
#define UUP_EXAMPLE_OPTIONS_H

#include <stdint.h>

#include "conf.h"
#include "key-value-config.h"
#include "netsock.h"

struct example_options {
    struct conf conf;                   /* Must be the initial field in this structure to work with the key-value API */

    /* Digest configuration for conf loader */
    char    *digest_store_dir;          /* digest_store directory name */
    unsigned digest_store_freq;         /* digest_store update frequency in seconds */
    unsigned digest_store_period;       /* digest_store maximum age in seconds */

    /* Options for stuff from libkit */
    unsigned infolog_flags;
    unsigned graphitelog_interval;      /* The interval for logging counters for graphite */
    unsigned graphitelog_json_limit;    /* The max number of counters per JSON object in the graphite log */

    /* Example application options */
    unsigned example_option;            /* An example option */
};

extern module_conf_t CONF_OPTIONS;

void example_options_register(module_conf_t *m, const char *name, const char *fn, bool loadable);
void example_options_configure(const struct key_value_entry *optcfg, unsigned entries);
const struct example_options *example_options_conf_get(const struct confset *set, module_conf_t m);
struct example_options *example_options_new(struct conf_loader *cl);

#endif
