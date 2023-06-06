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
#include "uup-rules.h"


module_conf_t CONF_RULES;
static __thread int              conf_generation = 0;        // Current generation of the configuration set per thread
static __thread struct confset **conf_set_ptr    = NULL;     // Allocated pointer to the configuration set aquired per thread




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






bool
uup_example_rules_startt(struct uup_example_config *config,cJSON *facts)
{
    bool ret=true;
    struct uup_example_rules_args *args;

    SXEE6("(config=%p)", config);
    SXEA1(args = kit_malloc(sizeof(*args)), "Failed to allocate graphitelog_thread");
    args->port = config->rules_port;
    args->addr = config->rules_addr;



    char buf[RULES_BUF_SIZE];
    // ssize_t n;


    cJSON *json, *error, *response_json;
    unsigned long org_id;
    const struct policy *policies;
    const struct policy_org *org_policy;
    struct confset *conf_set_old = NULL;
    const struct crl_value *action = NULL;
    char *response = NULL;
    bzero(buf, RULES_BUF_SIZE);

    SXEA1(conf_set_ptr = kit_malloc(sizeof(*conf_set_ptr)), "Failed to allocate conf ptr");
    response_json = cJSON_CreateObject();

    if (!facts) {
        cJSON_AddItemToObject(response_json, "error", cJSON_CreateString("Received invalid json"));
        goto ERROR_OUT;
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

    org_id = (unsigned long)json->valuedouble;
    cJSON_AddItemToObject(response_json, "org", cJSON_CreateNumber(org_id));
    
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

    goto RESPOND;

    ret = true;
    return ret;

RESPOND:
        response = cJSON_PrintUnformatted(response_json);

        SXEL3(": Returning %s", response);

        printf("%s \n",response);

        return ret;


        // conf_set_old = *conf_set_ptr;
    

ERROR_OUT:
    printf("%s \n",response);
    SXER6("return %s", kit_bool_to_str(ret));
    return ret;
}

