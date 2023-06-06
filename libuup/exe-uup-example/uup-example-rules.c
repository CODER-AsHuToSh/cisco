/*
 * This TCP server listens for a single new-line terminated JSON message which
 * must contain a numeric "org" field with the organization ID, other fields will
 * be used as facts by the rules engine.  It will generate a new-line terminated
 * JSON response.
 */

#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

#include <kit.h>
#include <kit-alloc.h>
#include <kit-bool.h>


#include "conf.h"
#include "crl.h"
#include "policy.h"

#include "uup-example-config.h"
#include "uup-example-rules.h"

module_conf_t CONF_RULES;
static __thread int              conf_generation = 0;        // Current generation of the configuration set per thread
static __thread struct confset **conf_set_ptr    = NULL;     // Allocated pointer to the configuration set aquired per thread

/**
 * Launch the rules processing thread
 * @param config
 * @return
 */
bool
uup_example_rules_start(struct uup_example_config *config)
{
    bool ret;
    struct uup_example_rules_args *args;

    SXEE6("(config=%p)", config);
    SXEA1(args = kit_malloc(sizeof(*args)), "Failed to allocate graphitelog_thread");
    args->port = config->rules_port;
    args->addr = config->rules_addr;





    if ((ret = pthread_create(&config->rules_thr, NULL, uup_example_rules_thread, args)) != 0) {
        SXEL1(": pthread_create failed to launch rukes thread: %s", strerror(ret));
        ret = false;
        goto ERROR_OUT;
    }




    ret = true;

ERROR_OUT:
    SXER6("return %s", kit_bool_to_str(ret));
    return ret;
}

/*
 * Callback to add attributes to the response
 */
static bool
rules_cb(void *value, const struct crl_value *action, const struct crl_value *attrs, cJSON **error_out,
         uint32_t org_id, unsigned i)
{
    const struct crl_value *attr;
    cJSON *response = value;

    SXE_UNUSED_PARAMETER(action);
    SXE_UNUSED_PARAMETER(error_out);
    SXE_UNUSED_PARAMETER(org_id);
    SXE_UNUSED_PARAMETER(i);

    SXEL6("(value=%p action=%s attrs=? error_out=? org_id=%u i=%u)", value, crl_value_to_str(action), org_id, i);

    /* Add the rule_id if present */
    if ((attr = crl_attributes_get_value(attrs, "rule_id")) && crl_value_get_type(attr) == CRL_TYPE_JSON
        && cJSON_IsNumber(attr->pointer)) {
        cJSON_AddNumberToObject(response, "rule_id", ((cJSON *)attr->pointer)->valuedouble);
    }

    /* Add the rule data if present */
    if ((attr = crl_attributes_get_value(attrs, "data")) && crl_value_get_type(attr) == CRL_TYPE_JSON) {
        cJSON_AddItemToObject(response, "rule_data", cJSON_Duplicate((cJSON *)attr->pointer, true));
    }

    return true; /* If we wanted to evaluate every rule this would return `false` */
}

/*
 * Runs the TCP server, parses JSON messages, and returns a JSON response
 */
void *
uup_example_rules_thread(void *a)
{
    struct uup_example_rules_args *args = (struct uup_example_rules_args *)a;
    int parentfd;
    int childfd;
    int optval;
    struct sockaddr_in serveraddr;
    struct sockaddr_in clientaddr;
    socklen_t clientlen = sizeof(clientaddr);

    char buf[RULES_BUF_SIZE];
    ssize_t n;

    cJSON *facts, *json, *error, *response_json;
    unsigned long org_id;
    const struct policy *policies;
    const struct policy_org *org_policy;
    struct confset *conf_set_old = NULL;
    const struct crl_value *action = NULL;
    char *response = NULL;

    SXEL6(": starting server on %s:%u", args->addr, args->port);

    SXEA1(conf_set_ptr = kit_malloc(sizeof(*conf_set_ptr)), "Failed to allocate conf ptr");

    /* Create a listening socket */
    parentfd = socket(AF_INET, SOCK_STREAM, 0);
    if (parentfd < 0) {
        SXEL1(":Failed to open listening socket: %s", strerror(errno));
        goto ERROR_OUT;
    }
    optval = 1;
    if (setsockopt(parentfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int)) < 0) {
        SXEL1(":ERROR setting SO_REUSEADDR: %s", strerror(errno));
        goto ERROR_OUT;
    }
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = inet_addr(args->addr);
    serveraddr.sin_port = htons(args->port);
    if (bind(parentfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) {
        SXEL1(":ERROR on binding: %s", strerror(errno));
        goto ERROR_OUT;
    }
    if (listen(parentfd, 5) < 0) {
        SXEL1(":ERROR on listen: %s", strerror(errno));
        goto ERROR_OUT;
    }

    SXEL3(": Rules Server launched listening on %s:%d", inet_ntoa(serveraddr.sin_addr), args->port);

    /* Loop and listen for incoming json data */
    while(true) {
        facts = NULL;

        childfd = accept(parentfd, (struct sockaddr *) &clientaddr, &clientlen);
        if (childfd < 0) {
            SXEL1(":ERROR on accept: %s", strerror(errno));
            goto ERROR_OUT;
        }

        bzero(buf, RULES_BUF_SIZE);
        n = read(childfd, buf, RULES_BUF_SIZE);
        if (n < 0) {
            SXEL1(":ERROR reading from socket");
            goto ERROR_OUT;
        }

        SXEL3("Received %zu/%zu bytes: %s", strlen(buf), n, buf);

        response_json = cJSON_CreateObject();

        /* Parse and validate the received data as json */
        if (!(facts = cJSON_Parse(buf))) {
            cJSON_AddItemToObject(response_json, "error", cJSON_CreateString("Received invalid json"));
            goto RESPOND;
        }
        if (!cJSON_IsObject(facts)) {
            cJSON_AddItemToObject(response_json, "error", cJSON_CreateString("Expected data to be a JSON object"));
            goto RESPOND;
        }
        json = cJSON_GetObjectItem(facts, "org");
        if ((json == NULL) || !cJSON_IsNumber(json)) {
            cJSON_AddItemToObject(response_json, "error", cJSON_CreateString("Expected numeric 'org' field"));
            goto RESPOND;
        }

        /* Get the org ID and add it to the response */
        org_id = (unsigned long)json->valuedouble;
        cJSON_AddItemToObject(response_json, "org", cJSON_CreateNumber(org_id));

        /* Lookup the configuration */
        if (!(*conf_set_ptr = confset_acquire(&conf_generation) ?: conf_set_old)) {
            SXEL1(":Unable to acquire configuration");
            goto ERROR_OUT;
        }
        if (conf_set_old && conf_set_old != *conf_set_ptr) {
            confset_release(conf_set_old);
            conf_set_old = NULL;
        }
        if (!(policies = policy_conf_get(*conf_set_ptr, CONF_RULES))) {
            cJSON_AddItemToObject(response_json, "error", cJSON_CreateString("Unable to find any rules files"));
            goto RESPOND;
        }

        /* Look for a rules file for the parsed org_id */
        if (!(org_policy = policy_find_org(policies, org_id))) {
            snprintf(buf, RULES_BUF_SIZE, "Unable to find a policy for org %lu", org_id);
            cJSON_AddItemToObject(response_json, "error", cJSON_CreateString(buf));
            goto RESPOND;
        }

        /* Execute the policy rules with the provided facts and a callback to process the rule attributes */
        action = policy_org_apply(org_policy, org_id, facts, &error, rules_cb, response_json);
        if (action == NULL) {
            snprintf(buf, RULES_BUF_SIZE, "Rules execution resulted in no action: %s",
                     error ? cJSON_GetStringValue(error) : "no errors");
            cJSON_AddItemToObject(response_json, "error", cJSON_CreateString(buf));
            goto RESPOND;
        }

        /* Add the action to the response */
        snprintf(buf, RULES_BUF_SIZE, "%s", crl_value_to_str(action));
        cJSON_AddItemToObject(response_json, "action", cJSON_CreateString(buf));

RESPOND:
        response = cJSON_PrintUnformatted(response_json);

        SXEL3(": Returning %s", response);

        if ((write(childfd, response, strlen(response)) < 0)
         || (write(childfd, "\n", 1) < 0)) {
            SXEL2(": Failed to write response: %s", strerror(errno));
        }
        close(childfd);
        cJSON_Delete(facts);
        cJSON_Delete(response_json);
        kit_free(response);

        conf_set_old = *conf_set_ptr;
    }

ERROR_OUT:
    SXEL3(": done");
    uup_example_terminate(15); /* Signal the config thread to exit */
    return NULL;
}