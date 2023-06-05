/*
 * An example application using libuup
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <kit.h>
#include <kit-alloc.h>
#include <kit-infolog.h>
#include <sxe-log.h>

#include "crl.h"
#include "uup-example-config.h"
#include "uup-example-options.h"
#include "uup-example-rules.h"

/**
 * Print usage text
 */
static void
uup_example_usage(void)
{
    fprintf(stderr,
            "usage: uup-example [options]\n"
            "       start the example application\n\n"
            "options:\n"
            "  -f <dir>  directory that contains config (default .)\n"
            "  -h        display this usage text\n"
            "  -a <ip>   IP address for rules server (default %s)\n"
            "  -p <port> port for rules server (default %u)\n"
            "  -s <dir>  save known-good configuration files here for emergency use on startup\n"
            "  -G <path> Graphite stats log file\n",
            DEFAULT_RULES_ADDR,
            DEFAULT_RULES_PORT);
}

static bool
uup_example_parse_args(struct uup_example_config *config, int argc, char **argv)
{
    char *endptr;
    unsigned long temp;
    int c;
    bool ret = true;

    /* Parse the command line options */
    while ((c = getopt(argc, argv, "a:f:hp:s:G:")) != -1) {
        switch (c) {
            case 'a':
                config->rules_addr = optarg;
                break;

            case 'f':
                config->config_directory = optarg;
                break;

            case 'h':
                ret = false;
                goto DONE;

            case 's':
                config->last_good_path = optarg;
                break;

            case 'p':
                errno = 0;
                temp = kit_strtoul(optarg, &endptr, 0);
                config->rules_port = temp;
                if ((config->rules_port <= 0) || (config->rules_port != temp) || (errno != 0) || (*endptr != 0)) {
                    errx(1, "Invalid port specifier '%s'", optarg);
                }
                break;

            case 'G':
                if (config->graphitelog_fd != -1)
                    errx(1, "Should only specify one graphitelog file");
                if ((config->graphitelog_fd = open(optarg, O_APPEND | O_CREAT | O_NONBLOCK | O_RDWR, 0644)) == -1)
                    errx(1, "Cannot open %s to append", optarg);
                config->graphitelog_path = optarg;
                break;

            default:
                ret = false;
                fprintf(stderr, "Unknown option '-%c'", c);
                goto DONE;
        }
    }

    if (optind < argc) {
        errx(1, "Unexpected arguments after options\n");
    }

DONE:
    if (!ret) {
        uup_example_usage();
        exit(1);
    }

    return ret;
}

int
main(int argc, char **argv)
{
    int ret = 1;
    struct uup_example_config *config = uup_example_new_config();

    if (!uup_example_parse_args(config, argc, argv)) {
        goto EXIT;
    }

    kit_infolog_printf("UUP Example Application started");
    kit_infolog_printf("  config directory: %s", config->config_directory);
    kit_infolog_printf("  graphitelog path: %s", config->graphitelog_path ?: "<unset>");

    /* Setup the configuration system */
    if (!uup_example_setup_conf(config)) {
        goto EXIT;
    }

    /* Start the rules TCP server */
    if (!uup_example_rules_start(config)) {
        goto EXIT;
    }

    /* Enter the configuration loading loop */
    ret = uup_example_conf_loop(config);

EXIT:
    uup_example_cleanup(config);
    kit_infolog_printf("Exiting");

    return ret;
}
