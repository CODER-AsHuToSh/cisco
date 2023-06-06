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
#include "uup-rules.h"
#include <time.h>
#include <sys/time.h>

// #include "cJSON.h"


/**
 * Print usage text
 */


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
        exit(1);
    }

    return ret;
}

double getHighResolutionTime(void);



int
main(int argc, char **argv)
{
    // const char *jsonString;
    // size_t bufferSize = 0;
    // printf("ENTER THE JSON STRING");
    // getline(&jsonString, &bufferSize, stdin);

    double start_time1, end_time1,start_time2, end_time2;
    double execution_time,execution_time2;

    const char *jsonString = "{\"org\":1234,\"value\":-123}";
    int ret = 1;
    struct uup_example_config *config = uup_example_new_config();

    if (!uup_example_parse_args(config, argc, argv)) {
        goto EXIT;
    }
    printf("UUP Example Application started \n");
    printf("gconfig directory: %s \n", config->config_directory);
    printf("graphitelog path: %s \n", config->graphitelog_path ?: "<unset>");

    printf("HELLO ASHUTOSH \n");


    cJSON *json = cJSON_Parse(jsonString);



    if (json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            printf("Error before: %s\n", error_ptr);
        }
        goto EXIT;
    }

    start_time1 = getHighResolutionTime();


    printf(" \n \n \n \n CONFIGURATION STARTED \n \n \n \n \n ");


    if (!uup_example_setup_conf(config)) {
        goto EXIT;
    }



    end_time1 = getHighResolutionTime();


    execution_time = (double)(end_time1 - start_time1);


    printf(" \n \n \n \n CONFIGURATION FINISHED,USE STARTED AND EXECUTION TIME FOR CONFIGURATION IS  %.2f \n \n \n \n ",execution_time);

    start_time2=getHighResolutionTime();





    if(!uup_example_rules_startt(config,json))
    {
        goto EXIT;
    }

    end_time2 = getHighResolutionTime();
    execution_time2 = (double)(end_time2 - start_time2);



    printf("BYEE ASHUTOSH  %.2f \n",execution_time2);


    return 0;





    

EXIT:
    kit_infolog_printf("Exiting");

    return ret;
}


double getHighResolutionTime(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}
