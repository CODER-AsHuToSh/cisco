/*
 * Generated by genxface.pl - DO NOT EDIT OR COMMIT TO SOURCE CODE CONTROL!
 */
#ifdef __cplusplus
extern "C" {
#endif


/**
 * Initialize the common rules language engine
 *
 * @param initial_count     Initial number of values allocated for the value stack (default 8)
 * @param maximum_increment Number of values allocated will double until this value is reached (default 4096)
 */
void crl_initialize(unsigned initial_count, unsigned maximum_increment) ;

/* Return any memory allocated by the main thread
 */
void crl_finalize(void) ;
struct crl_value * crl_new_attributes(struct crl_source *source) ;
const struct crl_value * crl_attributes_get_value(const struct crl_value *attrs, const char *key) ;
struct crl_value * crl_new_expression(struct crl_source *source) ;

/**
 * Compare two CRL values, returning CRL_TEST_ERROR on error, CRL_TEST_FALSE on failure, or CRL_TEST_TRUE on success
 *
 * @param lhs/rhs Left and right hand sides of the comparison
 * @param type    One of CRL_TYPE_EQUALS, CRL_TYPE_GREATER, CRL_TYPE_GREATER_OR_EQUAL, CRL_TYPE_LESS, or CRL_TYPE_LESS_OR_EQUAL
 */
crl_test_ret_t crl_value_compare(const struct crl_value *lhs, const struct crl_value *rhs, uint32_t type) ;

/*-
 * Test a CRL value, returning CRL_TEST_ERROR on error, CRL_TEST_FALSE if false, or CRL_TEST_TRUE if true
 */
crl_test_ret_t crl_value_test(const struct crl_value *value) ;

/**
 * If value is not already a JSON value, evaluate it
 *
 * @param value          Pointer to the CRL value to evaluate
 * @param is_alloced_out Pointer to a bool set to true iff the JSON returned was allocated.
 *
 * @return Pointer to the JSON value if already a JSON value, pointer to the result for CRL, or NULL on error.
 */
cJSON * crl_value_eval(const struct crl_value *value, bool *is_alloced_out) ;

/**
 * Evaluate all attribute values. If any value was not already a JSON, a new attribute set of evaluated values is created.
 *
 * @param attr       Pointer to the CRL attributes to evaluate
 * @param is_new_out Pointer to a bool set to true iff the attributes returned are newly allocated.
 *
 * @return Pointer to a new attributes (allocated), the input attr if not, or NULL on failure to allocate.
 */
struct crl_value * crl_attributes_eval(struct crl_value *attr, bool *is_new_out) ;

/* Finalize a value. If called on a value on the stack, that value should be the last value parsed that is still on the stack.
 */
struct crl_value * crl_value_fini(struct crl_value *value) ;
void crl_value_free(struct crl_value *value) ;

/**
 * Compare a CRL identifier to a string
 *
 * @return CRL_TEST_TRUE if the string matches the identifier, CRL_TEST_FALSE if not, or CRL_TEST_ERROR if the CRL value is
 *         not an idenitifer
 */
crl_test_ret_t crl_identifier_equal_str(const struct crl_value *value, const char *string) ;

/**
 * Convert a CRL value to a string
 *
 * @note Each time this function is called in a thread, the string value may be overwritten
 *
 * @note This belongs in crl.c in libuup.  Should constify the APIs
 */
const char * crl_value_to_str(const struct crl_value *value) ;

#ifdef __cplusplus
}
#endif
