/*
 * Example code to configure the conf system and run an update loop
 */

#include <err.h>
#include <fcntl.h>
#include <sys/wait.h>

#include <conf.h>
#include <conf-worker.h>
#include <digest-store.h>
#include <policy.h>

#include <kit.h>
#include <kit-alloc.h>
#include <kit-bool.h>
#include <kit-graphitelog.h>
#include <kit-infolog.h>
#include <kit-random.h>
#include <sxe-log.h>

#include "uup-example-config.h"
#include "uup-example-options.h"
#include "uup-example-rules.h"

/*
 * exitval is set by signal handlers so that service can exit gracefully at the end of tests and gcov instrumentation can
 * write out its .gcda files
 */
static volatile sig_atomic_t exitval = -1;

/* Define the options that can be overridden by the options file */
static const struct key_value_entry options_config[] = {
    KEY_VALUE_ENTRY_STRING(  struct example_options, digest_store_dir,        NULL),
    KEY_VALUE_ENTRY_UNSIGNED(struct example_options, digest_store_freq,       0, 65535),
    KEY_VALUE_ENTRY_UNSIGNED(struct example_options, digest_store_period,     0, 65535),
    KEY_VALUE_ENTRY_UNSIGNED(struct example_options, infolog_flags,           0, 65535),
    KEY_VALUE_ENTRY_UNSIGNED(struct example_options, graphitelog_interval,    1, 60 * 60),
    KEY_VALUE_ENTRY_UNSIGNED(struct example_options, graphitelog_json_limit,  1, 65535),
    KEY_VALUE_ENTRY_UNSIGNED(struct example_options, example_option,          1, 1234),
};

/**
 * Allocate service config and set defaults
 * @return configuration
 */
struct uup_example_config *
uup_example_new_config(void)
{
    struct uup_example_config *config;

    SXEA1(config = kit_calloc(1, sizeof(*config)), "Failed to allocate uup-example config");

    config->stat_delay       = 1000 * 1000;  /* default usleep() time = 1 second */

    config->graphitelog_path = NULL;
    config->graphitelog_fd   = -1;
    config->rules_port = DEFAULT_RULES_PORT;
    config->rules_addr = DEFAULT_RULES_ADDR;


    int threads = 1 +  // Main conf loop
                  1;   // Rukes loop
    kit_counters_initialize(MAXCOUNTERS, threads, true);  // allow unmanaged threads for http-client
    kit_memory_initialize(true);                     // On any failure to allocate memory, the service will be aborted.

    return config;
}

/**
 * Deallocate the configuration and perform any other cleanup tasks
 * @param config
 */
void
uup_example_cleanup(struct uup_example_config *config)
{
    kit_free(config);
}

/**
 * Initialize the configuration system and various items from libkit
 * @return
 */
bool
uup_example_setup_conf(struct uup_example_config *config)
{
    static bool initialized = false;

    SXEE6("(config=%p)", config);
    SXEA1(!initialized, "uup_example_setup_conf called more than once");

    kit_random_init(open("/dev/urandom", O_RDONLY));
    kit_time_cached_update();

    /* Configure the pref file loading system */
    conf_initialize(config->config_directory, config->last_good_path, true, NULL);
    crl_initialize(32, 0);    // Start with 32 token stack for policy
    example_options_register(&CONF_OPTIONS, "options", "options", true);
    example_options_configure(options_config, sizeof(options_config) / sizeof(*options_config));

    policy_register(&CONF_RULES, "rules", "rules/rules.%u.org.gz", NULL);

    /* Do an initial load */
    if (!confset_load(NULL)) {
        SXEL3("Unable to find any configuration files in directory %s%s",
              config->config_directory ? "/" : "", config->config_directory ?: "");
    } else {
        SXEA1(config->conf = confset_acquire(NULL), "Unexpected NULL confset");

        /* Set the initial infolog flags for startup logging */
        const struct example_options *options = example_options_conf_get(config->conf, CONF_OPTIONS);
        kit_infolog_flags = options->infolog_flags;
    }

    kit_time_cached_update();
    initialized = true;

    SXER6("return %s", kit_bool_to_str(initialized));
    return initialized;
}

/*
 * Signal handler to shutdown the config loop
 */
void
uup_example_terminate(int sig)
{
    conf_worker_terminate();    // This is safe to call in a signal handler
    exitval = sig;              // Need to exit so gcov instrumentation can write out its .gcda files
}

/**
 * Update the libraries based on the current configuration
 *
 * @param nconf The configuration set
 */
static void
uup_example_update_config(struct confset *nconf)
{
    SXEE6("(nconf=%p)", nconf);

    const struct example_options *options = example_options_conf_get(nconf, CONF_OPTIONS);
    kit_infolog_flags = options->infolog_flags;

    digest_store_set_options(options->digest_store_dir, options->digest_store_freq, options->digest_store_period);
    kit_graphitelog_update_set_options(options->graphitelog_json_limit, options->graphitelog_interval);

    kit_infolog_printf("Example option has been set to %u", options->example_option);

    SXER6("return");
}

/**
 * This is the main config loop for the example application
 *
 * @param config
 *
 * @return The exit value
 */
int
uup_example_conf_loop(struct uup_example_config *config)
{
    struct sigaction sa;
    uint64_t delay;
    struct confset *prev_conf = NULL;

    SXEE6("(config=%p, update_fn=?)", config);

    /* Setup signal handles */
    SXEL6("Setting up signal handlers so that we can terminate cleanly");
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = uup_example_terminate;
    sigaction(SIGHUP, &sa, NULL);
    sa.sa_handler = uup_example_terminate;
    sigaction(SIGINT, &sa, NULL);
    sa.sa_handler = uup_example_terminate;
    sigaction(SIGTERM, &sa, NULL);

    if (config->conf)    /* If there was an initial config then call the update function */
        uup_example_update_config(config->conf);

    /* Main loop */
    while (exitval == -1) {
        delay = config->stat_delay / 1000;

        if (!confset_load(&delay)) {
            usleep(delay * 1000);
            digest_store_unchanged(config->conf);
            continue;
        }

        prev_conf = config->conf;
        SXEA1(config->conf = confset_acquire(NULL), "Unexpected NULL confset");
        uup_example_update_config(config->conf);
        confset_free(prev_conf, CONFSET_FREE_IMMEDIATE);
        kit_time_cached_update();
        digest_store_changed(config->conf);
    }

    kit_infolog_printf("UUP example config loop shutting down%s",
                       exitval == SIGHUP ? " (sighup)" : exitval == SIGINT ? " (sigint)" : exitval == SIGTERM ? " (sigterm)" : "");

    crl_parse_finalize_thread();
    crl_finalize();
    confset_free(config->conf, CONFSET_FREE_IMMEDIATE);
    config->conf = NULL;
    conf_worker_finalize();    // Free any per worker thread resources allocated by the main conf thread

    SXER6("return %d", (int)exitval);
    return exitval;
}
