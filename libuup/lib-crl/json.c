#include <kit-alloc.h>
#include <sxe-log.h>

#if __linux__
#include <bsd/string.h>    // Do after sxe-log.h so this won't create its own __printflike
#else
#include <string.h>
#endif

#include "json.h"

unsigned json_init_count = 0;
cJSON   *json_bool_true  = NULL;
cJSON   *json_bool_false = NULL;
cJSON   *json_null       = NULL;
cJSON   *json_builtins   = NULL;

#ifdef SXE_DEBUG

static __thread char json_str[1024];

const char *
json_to_str(cJSON *json)
{
    char *string = cJSON_PrintUnformatted(json);

    if (string) {
        strlcpy(json_str, string, sizeof(json_str));
        cJSON_free(string);
    }
    else
        strlcpy(json_str, "NULL", sizeof(json_str));

    return json_str;
}

#endif

/**
 * Get the cJSON type, removing flags
 */
int
json_get_type(cJSON *json)
{
    return json->type & ~(cJSON_IsReference | cJSON_StringIsConst);
}

/* Required because cJSON annoyingly makes true and false different types.
 */
bool
json_type_is_bool(int type)
{
    return type == cJSON_False || type == cJSON_True;
}

static void *
json_malloc(size_t sz)
{
    return kit_malloc(sz);
}

static void
json_free(void *ptr)
{
    kit_free(ptr);
}

/*
 * Initialize the JSON interface
 */
void
json_initialize(void)
{
    cJSON_Hooks hooks = {json_malloc, json_free};

    if (json_init_count++ > 0)
        return;

    cJSON_InitHooks(&hooks);
    SXEA1((json_builtins   = cJSON_CreateObject())
       && (json_bool_true  = cJSON_AddTrueToObject( json_builtins, "true"))
       && (json_bool_false = cJSON_AddFalseToObject(json_builtins, "false"))
       && (json_null       = cJSON_AddNullToObject( json_builtins, "null")),
          "Failed to construct JSON builtins");
}

/* Return memory allocated by the main thread
 */
void
json_finalize(void)
{
    SXEA1(json_init_count, "Must call json_initialize before calling %s", __FUNCTION__);

    if (--json_init_count > 0)
        return;

    cJSON_Delete(json_builtins);
    json_builtins = NULL;
}

/**
 * Compare two JSON values, returning CRL_TEST_ERROR on error, CRL_TEST_FALSE on failure, or CRL_TEST_TRUE on success
 *
 * @param lhs/rhs Left and right hand sides of the comparison
 * @param type    One of CRL_TYPE_EQUALS, CRL_TYPE_GREATER, CRL_TYPE_GREATER_OR_EQUAL, CRL_TYPE_LESS, or CRL_TYPE_LESS_OR_EQUAL
 * @param cmp_out NULL or a pointer to an int where the cmp value (<0 for <, 0 for ==, or >0 for >) will be stored
 *
 * @return CRL_TEST_ERROR, CRL_TEST_FALSE, or CRL_TEST_TRUE; on CRL_ERROR, *cmp_out will not be modified
 */
crl_test_ret_t
json_value_compare(cJSON *lhs_json, cJSON *rhs_json, uint32_t cmp_type, int *cmp_out)
{
    int      lhs_type = json_get_type(lhs_json);
    int      rhs_type = json_get_type(rhs_json);
    int      cmp_val  = 0;
    unsigned i;

    if (lhs_type != rhs_type && (!json_type_is_bool(lhs_type) || !json_type_is_bool(lhs_type))) {
        SXEL2("Can't compare a cJSON type %u to a %u", lhs_json->type, rhs_json->type);
        return CRL_TEST_ERROR;
    }

    if (lhs_type == cJSON_String)
        cmp_val = strcmp(cJSON_GetStringValue(lhs_json), cJSON_GetStringValue(rhs_json));
    else if (lhs_type == cJSON_Number)    // Note: cJSON_GetNumberValue not implemented in cJSON 1.7.10
        cmp_val = lhs_json->valuedouble == rhs_json->valuedouble ? 0 : lhs_json->valuedouble < rhs_json->valuedouble ? -1 : 1;
    else if (json_type_is_bool(lhs_type)) {
        if (cmp_type == CRL_TYPE_EQUALS)
            return lhs_type == rhs_type ? CRL_TEST_TRUE : CRL_TEST_FALSE;
        else if (cmp_type == CRL_TYPE_NOT_EQUAL)
            return lhs_type != rhs_type ? CRL_TEST_TRUE : CRL_TEST_FALSE;
        else {
            SXEL2("Can't compare order of cJSON values of type 'bool'");
            return CRL_TEST_ERROR;
        }
    }
    else if (lhs_type == cJSON_Array) {
        // If cJSON sucked less, [in]equality check(s) could be optimized by comparing lengths.
        for (i = 0; cmp_val == 0; i++) {
            /* This will be wretchedly slow, as cJSON traverses the linear list for each array access.
             */
            cJSON *lhs_element = cJSON_GetArrayItem(lhs_json, i);
            cJSON *rhs_element = cJSON_GetArrayItem(rhs_json, i);

            if (lhs_element == NULL) {
                if (rhs_element == NULL)
                    cmp_val = 0;
                else
                    cmp_val = -1;

                break;
            }

            if (rhs_element == NULL) {
                cmp_val = 1;
                break;
            }

            if (json_value_compare(lhs_element, rhs_element, cmp_type, &cmp_val) == CRL_TEST_ERROR)
                return CRL_TEST_ERROR;
        }
    } else {
        SXEL2("Can't compare cJSON values of type %u", lhs_type);
        return CRL_TEST_ERROR;    // For now, only JSON strings, numbers, bools, and arrays can be compared
    }

    if (cmp_out)
        *cmp_out = cmp_val;

    switch (cmp_type) {
    case CRL_TYPE_EQUALS:           return cmp_val == 0 ? CRL_TEST_TRUE : CRL_TEST_FALSE;
    case CRL_TYPE_GREATER:          return cmp_val >  0 ? CRL_TEST_TRUE : CRL_TEST_FALSE;
    case CRL_TYPE_GREATER_OR_EQUAL: return cmp_val >= 0 ? CRL_TEST_TRUE : CRL_TEST_FALSE;
    case CRL_TYPE_LESS:             return cmp_val <  0 ? CRL_TEST_TRUE : CRL_TEST_FALSE;
    case CRL_TYPE_LESS_OR_EQUAL:    return cmp_val <= 0 ? CRL_TEST_TRUE : CRL_TEST_FALSE;
    case CRL_TYPE_NOT_EQUAL:        return cmp_val != 0 ? CRL_TEST_TRUE : CRL_TEST_FALSE;
    }

    SXEA1(false, "Invalid comparison type %u", cmp_type);    /* COVERAGE EXCLUSION - Can't happen */
    return CRL_TEST_ERROR;
}

/*-
 * Test a JSON value, returning CRL_TEST_ERROR on error, CRL_TEST_FALSE if false, or CRL_TEST_TRUE if true
 */
crl_test_ret_t
json_value_test(cJSON *json)
{
    int type = json_get_type(json);

    switch (type) {
    case cJSON_True:
        return CRL_TEST_TRUE;

    case cJSON_Number:
        return json->valuedouble != 0.0 ? CRL_TEST_TRUE : CRL_TEST_FALSE;

    case cJSON_String:
        return cJSON_GetStringValue(json)[0] != '\0' ? CRL_TEST_TRUE : CRL_TEST_FALSE;

    case cJSON_Array:
    case cJSON_Object:
        return json->child != NULL ? CRL_TEST_TRUE : CRL_TEST_FALSE;
    }

    if (type != cJSON_False && type != cJSON_NULL) {
        SXEL2("Test of unexpected cJSON type %u", type);
        return CRL_TEST_ERROR;
    }

    return CRL_TEST_FALSE;
}

/**
 * Get the value of a JSON number as a double
 *
 * @note cJSON implements a cJSON_GetNumberValue function in more recent versions of the library
 */
double
json_number_get_double(cJSON *json)
{
    SXEA6(json_get_type(json) == cJSON_Number, "Can only get the numeric value of a number");
    return json->valuedouble;
}
