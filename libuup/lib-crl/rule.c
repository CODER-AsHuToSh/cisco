#include <kit-alloc.h>

#include "crl.h"
#include "rule.h"

void
rule_init(struct rule *rule)
{
    SXEL7("%s(rule=%p) {}", __FUNCTION__, rule);
    rule->attributes = NULL;
    rule->cond_line  = NULL;
    rule->condition  = NULL;
    rule->action     = NULL;
}

void
rule_fini(struct rule *rule)
{
    SXEL7("%s(rule=%p) {}", __FUNCTION__, rule);
    crl_value_free(rule->action);
    crl_value_free(rule->condition);
    kit_free(rule->cond_line);
    crl_value_free(rule->attributes);
    kit_free(rule->attr_line);
}
