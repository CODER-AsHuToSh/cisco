#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crl.h"

char buffer[4096];

const char *status[] = { "OK", "TRUNCATED", "NO MEMORY", "INVALID", "WRONG TYPE"};

int
main(void)
{
    struct crl_value     *value;
    struct crl_source     source;
    struct crl_namespace *namespace;
    cJSON                *json;
    char                 *line, *newline;

    crl_initialize(0, 0);

    while (fgets(buffer, sizeof(buffer), stdin)) {
        newline  = strchr(buffer, '\n');
        *newline = '\0';

        if (strncmp(buffer, "push ", 5) == 0) {
            line = buffer + 5;

            if (!(json = cJSON_ParseWithOpts(line, NULL, true)))
                printf("Error parsing JSON '%s'\n", line);
            else {
                namespace = malloc(sizeof(*namespace));
                crl_namespace_push_object(namespace, json);
            }
        }
        else if (strncmp(buffer, "test ", 5) == 0) {
            line = buffer + 5;

            crl_source_init(&source, line, "test", 1, CRL_VERSION_UUP);

            if (!(value = crl_new_expression(&source)))
                printf("Error %s parsing CRL '%s'\n", status[source.status], line);
            else {
                printf("%s\n", crl_value_test(value) ? "true" : "false");
                crl_value_free(value);
            }
        }
        else
            printf("Try 'test CRL' or 'push JSON'\n");
    }

    return 0;
}
