#include <kit-alloc.h>
#include <mockfail.h>
#include <stdlib.h>

#include "atomic.h"
#include "conf-loader.h"
#include "crl.h"
#include "fileprefs.h"
#include "policy-org.h"
#include "prefbuilder.h"

struct policy_loader {
    struct policy_org *policy;
    const char        *filter;
    unsigned           length;
};

static void
policy_org_free(struct policy_org *me)
{
    unsigned i;

    if (me->global_line) {
        kit_free(me->global_line);
        crl_value_free(me->global_attr);
    }

    if (me->rules) {
        for (i = 0; i < me->count; i++)
            rule_fini(&me->rules[i]);

        kit_free(me->rules);
    }

    kit_free(me);
}

void
policy_org_refcount_dec(void *obj)
{
    struct policy_org *me = obj;

    if (me) {
        SXEA1(me->cs.refcount, "Attempt to remove a reference from a policy_org that has none");

        if (ATOMIC_DEC_INT_NV(&me->cs.refcount) == 0) {
            SXEL7("(me=%p): freeing %u rules because refcount is 0", me, me->count);
            policy_org_free(me);
        }
    }
}

void
policy_org_refcount_inc(void *obj)
{
    struct policy_org *me = obj;

    if (me)
        ATOMIC_INC_INT(&me->cs.refcount);
}

/* Just validate that if there is a section, it is non-empty
 */
static bool
policy_alloc_ignore(struct prefbuilder *pref_builder, unsigned num_lines)
{
    SXE_UNUSED_PARAMETER(pref_builder);
    SXE_UNUSED_PARAMETER(num_lines);
    SXEA6(num_lines, "Should never be called with num_lines == 0");
    return true;
}

/* Just track that a line has been read
 */
static bool
policy_read_ignore(struct fileprefs *fp, struct prefbuilder *pref_builder, struct conf_loader *cl, const char *line)
{
    SXE_UNUSED_PARAMETER(fp);
    SXE_UNUSED_PARAMETER(cl);
    SXE_UNUSED_PARAMETER(line);
    pref_builder->count++;
    return true;
}

/* Verify that the global section has only one line
 */
static bool
policy_alloc_globals(struct prefbuilder *pref_builder, unsigned num_lines)
{
    SXE_UNUSED_PARAMETER(pref_builder);
    SXE_UNUSED_PARAMETER(num_lines);

    if (num_lines != 1) {
        SXEL2(": Global section should never have %u lines (there can only be 1)", num_lines);
        return false;
    }

    return true;
}

/* Parse the global attributes line
 */
static bool
policy_read_global(struct fileprefs *fp, struct prefbuilder *pref_builder, struct conf_loader *cl, const char *line)
{
    struct policy_org *policy = ((struct policy_loader *)pref_builder->user)->policy;
    struct crl_source  source;

    SXE_UNUSED_PARAMETER(fp);

    // Make a copy of the line for attributes to point into.
    if (!(policy->global_line = MOCKFAIL(POLICY_DUP_GLOBALLINE, NULL, kit_strdup(line)))) {
        SXEL2(": Failed to allocate memory to duplicate the global attribute line");
        return false;
    }

    crl_source_init(&source, policy->global_line, conf_loader_path(cl), conf_loader_line(cl), policy->version);

    if (!(policy->global_attr = crl_new_attributes(&source)))
        return false;

    if (!crl_source_is_exhausted(&source)) {
        SXEL2("%s: %u: Expected end of line after global attributes, got '%s'", conf_loader_path(cl), conf_loader_line(cl),
              source.left);
        return false;
    }

    return true;
}

static bool
policy_alloc_rules(struct prefbuilder *pref_builder, unsigned num_rules)
{
    struct policy_org *me = ((struct policy_loader *)pref_builder->user)->policy;

    SXEA6(me,        "Pointer to policy structure in pref_builder->policy_loader must not be NULL");
    SXEA6(num_rules, "Should never be called with num_rules == 0");

    pref_builder->loader->flags |= CONF_LOADER_CHOMP;    // Hack to turn on chomping of trailing newlines from loaded lines
    pref_builder->count          = 0;                    // Reset the number of elements read so far to 0
    me->count                    = num_rules;

    if ((me->rules = MOCKFAIL(POLICY_ALLOCRULES, NULL, kit_malloc(num_rules * sizeof(*me->rules)))) == NULL) {
        SXEL2(": Failed to malloc a rules array");
        return false;
    }

    return true;
}

static bool
policy_read_rule(struct fileprefs *fp, struct prefbuilder *pb, struct conf_loader *cl, const char *line)
{
    struct crl_source              source;
    struct policy_loader *loader = pb->user;
    struct rule          *rule   = &loader->policy->rules[pb->count];

    SXE_UNUSED_PARAMETER(fp);
    rule_init(rule);

    // Make a copy of the line for attributes to point into.
    if (!(rule->attr_line = MOCKFAIL(POLICY_DUP_ATTRLINE, NULL, kit_strdup(line)))) {
        SXEL2(": Failed to allocate memory to duplicate an attribute line");
        return false;
    }

    crl_source_init(&source, rule->attr_line, conf_loader_path(cl), conf_loader_line(cl), loader->policy->version);

    if (!(rule->attributes = crl_new_attributes(&source)))
        goto ERROR_OUT;

    if (!crl_source_is_exhausted(&source)) {
        SXEL2("%s: %u: Expected end of line after attributes, got '%s'", conf_loader_path(cl), conf_loader_line(cl),
              source.left);
        goto ERROR_OUT;
    }

    if (!(line = conf_loader_readline(cl))) {
        SXEL2("%s: %u: Failed to read condition:action line after attribute line", conf_loader_path(cl), conf_loader_line(cl));
        goto ERROR_OUT;
    }

    // If configured then search for the filter string in the line.
    if (loader->filter && strstr(line, loader->filter) == NULL) {
        SXEL7("Skipping line that doesn't match filter '%s'", loader->filter);
        rule_fini(rule);
        return true;
    }

    // Make a copy of the line for condition:action to point into.
    if (!(rule->cond_line = MOCKFAIL(POLICY_DUP_CONDLINE, NULL, kit_strdup(line)))) {
        SXEL2(": Failed to allocate memory to duplicate a condition:action line");
        goto ERROR_OUT;
    }

    crl_source_init(&source, rule->cond_line, conf_loader_path(cl), conf_loader_line(cl), loader->policy->version);

    if (!(rule->condition = crl_new_expression(&source)))
        goto ERROR_OUT;

    if (*crl_source_skip_space(&source) != ':') {
        SXEL2("%s: %u: Expected a ':' after condition, got '%s'", conf_loader_path(cl), conf_loader_line(cl), source.left);
        goto ERROR_OUT;
    }

    source.left++;

    if (!(rule->action = crl_new_expression(&source)))
        goto ERROR_OUT;

    if (!crl_source_is_exhausted(&source)) {
        SXEL2("%s: %u: Expected end of line after action, got '%s'", conf_loader_path(cl), conf_loader_line(cl), source.left);
        goto ERROR_OUT;
    }

    pb->count++;
    return true;

ERROR_OUT:
    rule_fini(rule);
    return false;
}

void *
policy_org_new(uint32_t orgid, struct conf_loader *cl, const struct conf_info *info)
{
    struct fileprefs                prefs;
    struct prefbuilder              builder;
    struct policy_loader            loader;
    struct policy_org              *me      = NULL;
    unsigned                       *ok_vers = NULL;
    const struct fileprefs_section *section = NULL;
    unsigned                        count, loaded, total;
    enum fileprefs_section_status   status;

    static const struct fileprefs_section rules_sections[] = {
        {
            .name    = "organization_configuration",
            .namelen = sizeof("organization_configuration") - 1,
            .alloc   = policy_alloc_ignore,
            .read    = policy_read_ignore
        },
        {
            .name    = "global",
            .namelen = sizeof("global") - 1,
            .alloc   = policy_alloc_globals,
            .read    = policy_read_global
        },
        {
            .name    = "rulesets",
            .namelen = sizeof("rulesets") - 1,
            .alloc   = policy_alloc_ignore,
            .read    = policy_read_ignore
        },
        {
            .name    = "rules",
            .namelen = sizeof("rules") - 1,
            .alloc   = policy_alloc_rules,
            .read    = policy_read_rule,
        }
    };

    static struct fileprefops policy_ops = {
        .type               = "rules",
        .sections           = rules_sections,
        .num_sections       = 4,
        .supported_versions = { 1, POLICY_VERSION, 0 }
    };

    SXEE6("(orgid=%u,conf_loader_path(cl)=%s,info->loadflags=0x%x)",
          (unsigned)orgid, conf_loader_path(cl), (unsigned)info->loadflags);\
    fileprefs_init(&prefs, &policy_ops, info->loadflags);

    if (!fileprefs_load_fileheader(&prefs, cl, &total, &ok_vers))
        goto EARLY_OUT;

    if ((me = MOCKFAIL(POLICY_ORG_NEW, NULL, kit_calloc(1, sizeof(*me)))) == NULL) {
        SXEL2("%s: Cannot allocate %zu bytes for a policy_org object", conf_loader_path(cl), sizeof(*me));
        goto EARLY_OUT;
    }

    me->version   = prefs.version;    // Save the version (used by policy.c for conf_report_load)
    loader.policy = me;
    loader.filter = info->userdata;
    loader.length = info->userdata ? strlen(info->userdata) : 0;
    prefbuilder_init(&builder, 0, cl, &loader);

    for (loaded = 0;
         (status = fileprefs_load_section(&prefs, cl, &builder, ok_vers, &section, &count)) == FILEPREFS_SECTION_LOADED;
         loaded += count) {
    }

    if (status == FILEPREFS_SECTION_ERROR)
        goto ERROR_OUT;

    if (!conf_loader_eof(cl)) {
        if (section == NULL)
            SXEL2("%s: %u: Expected section header", conf_loader_path(cl), conf_loader_line(cl));
        else
            SXEL2("%s: %u: Unexpected [%s] line - wanted only %u item%s", conf_loader_path(cl), conf_loader_line(cl),
                  section->name, count, count == 1 ? "" : "s");

        goto ERROR_OUT;
    }

    if (loaded != total) {
        SXEL2("%s: %u: Incorrect total count %u - read %u data line%s", conf_loader_path(cl), conf_loader_line(cl),
              total, loaded, loaded == 1 ? "" : "s");
        goto ERROR_OUT;
    }

    SXEA6(me->count || me->rules == NULL, "If all sections skipped or all rules filtered out, rules shouldn't be allocated");

    if (builder.count < me->count) {    // Some rules were filtered out
        SXEA6(loader.filter, "Builder parse %u of %u rules, but there's no filter", builder.count, me->count);

        if (builder.count == 0) {    // All rules were filtered out
            kit_free(me->rules);
            me->rules = NULL;
        }
        else
            me->rules = kit_reduce(me->rules, builder.count * sizeof(me->rules[0]));

        me->count = builder.count;
    }

    SXEA6(builder.count == me->count, "Pref builder count %u != policy count %u", builder.count, me->count);
    conf_segment_init(&me->cs, orgid, cl, false);
    goto EARLY_OUT;

ERROR_OUT:
    if (me) {
        me->count = builder.count;    // Don't try to free skipped rules
        policy_org_free(me);
        me = NULL;
    }

    prefbuilder_fini(&builder);

EARLY_OUT:
    kit_free(ok_vers);
    SXER6("return %p // policy_org_new, count=%u", me, me ? me->count : 0);
    return me;
}

/**
 * Apply a policy.
 *
 * @param org_policy     The per org policy to apply
 * @param org_id         The org id that the policy applies to
 * @param facts_json     The facts to use when evaluating the policy or NULL
 * @param error_out      Set to a cJSON string encoding the system error encountered or NULL on no error
 * @param special_action Pointer to a function that takes a caller supplied value, the action, the evaluated rule attributes,
 *                       error_out, and the org_id and rule index, and returns true to short circuit, false to continue
 * @param special_value  Value passed to special action
 *
 * @return The action from the matching rule (which will usually be an identifier) or NULL on error or no match
 */
const struct crl_value *
policy_org_apply(const struct policy_org *me, uint32_t org_id, cJSON *facts_json, cJSON **error_out,
                 bool (*special_action)(void *value, const struct crl_value *action, const struct crl_value *attrs,
                                        cJSON **error_out, uint32_t org_id, unsigned i),
                 void *special_value)
{
    struct crl_namespace attr_namespace, facts_namespace, global_namespace;
    struct crl_value    *evaled_attrs, *evaled_globals;
    struct crl_value    *action;
    unsigned             i;
    crl_test_ret_t       ret;
    bool                 attrs_alloced, globals_alloced;
    char                 error[1024];

    // Would be nice if me included the orgid, but the cost would be 4 bytes extra per org policy
    SXEE6("(me=?,org_id=%" PRIu32 ",facts_json=?,error_out=?,special_action%c=NULL,special_value=?)",
          org_id, special_action ? '!' : '=');
    action         = NULL;
    *error_out     = NULL;
    evaled_attrs   = NULL;
    evaled_globals = NULL;

    if (facts_json)
        crl_namespace_push_object(&facts_namespace, facts_json);

    if (me->global_attr) {
        if (!(evaled_globals = crl_attributes_eval(me->global_attr, &globals_alloced))) {
            snprintf(error, sizeof(error), "Failed to evaluate org %" PRIu32 " global attributes", org_id);
            *error_out = cJSON_CreateString(error);
            goto EARLY_OUT;
        }

        crl_namespace_push_attributes(&global_namespace, evaled_globals);
    }

    for (i = 0; *error_out == NULL && i < me->count; i++) {    // For each rule in the policy
        if (!(evaled_attrs = crl_attributes_eval(me->rules[i].attributes, &attrs_alloced))) {
            snprintf(error, sizeof(error), "Failed to evaluate org %" PRIu32 " rule %u attributes", org_id, i);
            *error_out = cJSON_CreateString(error);
            break;
        }

        crl_namespace_push_attributes(&attr_namespace, evaled_attrs);

        if ((ret = crl_value_test(me->rules[i].condition)) == CRL_TEST_ERROR) {    // On error, return an error
            snprintf(error, sizeof(error), "Internal error testing org %" PRIu32 " rule %u", org_id, i);
            *error_out = cJSON_CreateString(error);    // Break after cleaning up attributes
        }

        SXEA1(crl_namespace_pop() == &attr_namespace, "Failed to pop the attributes namespace");

        if (*error_out == NULL && ret == CRL_TEST_TRUE) {
            action = me->rules[i].action;

            if (!special_action || (*special_action)(special_value, action, evaled_attrs, error_out, org_id, i))
                i = me->count;    // Break after cleaning up attributes
        }

        if (attrs_alloced)
            crl_value_free(evaled_attrs);
    }

EARLY_OUT:
    if (evaled_globals) {
        SXEA1(crl_namespace_pop() == &global_namespace, "Failed to pop the global namespace");

        if (globals_alloced)
            crl_value_free(evaled_globals);
    }

    if (facts_json)
        SXEA1(crl_namespace_pop() == &facts_namespace, "Failed to pop the id/posture namespace");

    SXER6("return action=%p", *error_out ? NULL : action);
    return *error_out ? NULL : action;
}
