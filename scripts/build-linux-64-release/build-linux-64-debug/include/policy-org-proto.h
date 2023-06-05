/*
 * Generated by genxface.pl - DO NOT EDIT OR COMMIT TO SOURCE CODE CONTROL!
 */
#ifdef __cplusplus
extern "C" {
#endif

void policy_org_refcount_dec(void *obj) ;
void policy_org_refcount_inc(void *obj) ;
void * policy_org_new(uint32_t orgid, struct conf_loader *cl, const struct conf_info *info) ;

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
const struct crl_value * policy_org_apply(const struct policy_org *me, uint32_t org_id, cJSON *facts_json, cJSON **error_out,
                 bool (*special_action)(void *value, const struct crl_value *action, const struct crl_value *attrs,
                                        cJSON **error_out, uint32_t org_id, unsigned i),
                 void *special_value) ;

#ifdef __cplusplus
}
#endif
