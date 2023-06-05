/*
 * Generated by genxface.pl - DO NOT EDIT OR COMMIT TO SOURCE CODE CONTROL!
 */
#ifdef __cplusplus
extern "C" {
#endif

const char * json_to_str(cJSON *json) ;

/**
 * Get the cJSON type, removing flags
 */
int json_get_type(cJSON *json) ;

/* Required because cJSON annoyingly makes true and false different types.
 */
bool json_type_is_bool(int type) ;

/*
 * Initialize the JSON interface
 */
void json_initialize(void) ;

/* Return memory allocated by the main thread
 */
void json_finalize(void) ;

/**
 * Compare two JSON values, returning CRL_TEST_ERROR on error, CRL_TEST_FALSE on failure, or CRL_TEST_TRUE on success
 *
 * @param lhs/rhs Left and right hand sides of the comparison
 * @param type    One of CRL_TYPE_EQUALS, CRL_TYPE_GREATER, CRL_TYPE_GREATER_OR_EQUAL, CRL_TYPE_LESS, or CRL_TYPE_LESS_OR_EQUAL
 * @param cmp_out NULL or a pointer to an int where the cmp value (<0 for <, 0 for ==, or >0 for >) will be stored
 *
 * @return CRL_TEST_ERROR, CRL_TEST_FALSE, or CRL_TEST_TRUE; on CRL_ERROR, *cmp_out will not be modified
 */
crl_test_ret_t json_value_compare(cJSON *lhs_json, cJSON *rhs_json, uint32_t cmp_type, int *cmp_out) ;

/*-
 * Test a JSON value, returning CRL_TEST_ERROR on error, CRL_TEST_FALSE if false, or CRL_TEST_TRUE if true
 */
crl_test_ret_t json_value_test(cJSON *json) ;

/**
 * Get the value of a JSON number as a double
 *
 * @note cJSON implements a cJSON_GetNumberValue function in more recent versions of the library
 */
double json_number_get_double(cJSON *json) ;

#ifdef __cplusplus
}
#endif
