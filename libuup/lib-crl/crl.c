#ifdef __FreeBSD__
#include <stdlib.h>
#else
#include <alloca.h>
#endif
#include <cjson/cJSON.h>
#include <ctype.h>
#include <kit-alloc.h>
#include <mockfail.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "crl.h"
#include "json.h"

/**
 * Initialize the common rules language engine
 *
 * @param initial_count     Initial number of values allocated for the value stack (default 8)
 * @param maximum_increment Number of values allocated will double until this value is reached (default 4096)
 */
void
crl_initialize(unsigned initial_count, unsigned maximum_increment)
{
    SXEE6("(initial_count=%u,maximum_increment=%u)", initial_count, maximum_increment);
    json_initialize();
    crl_parse_initialize(initial_count, maximum_increment, json_builtins);
    SXER6("return");
}

/* Return any memory allocated by the main thread
 */
void
crl_finalize(void)
{
    json_finalize();
}

struct crl_value *
crl_new_attributes(struct crl_source *source)
{
    struct crl_value *me;
    unsigned          idx;

    if ((idx = crl_parse_attributes(source)) == CRL_ERROR)
        return NULL;

    if (!(me = crl_value_dup(idx, "attribute set"))) {
        source->status = CRL_STATUS_NOMEM;
        return NULL;
    }

    crl_value_pop(idx);
    return me;
}

const struct crl_value *
crl_attributes_get_value(const struct crl_value *attrs, const char *key)
{
    unsigned count, i;

    SXEA6(attrs->type == CRL_TYPE_ATTRIBUTES, "Expected attributes, got type %s", crl_type_to_str(attrs->type));
    count = attrs->count;

    for (attrs++, i = 0; i < count; attrs += attrs->count, i++)
        if (strcmp(attrs->string, key) == 0)
            return attrs + 1;

    return NULL;
}

struct crl_value *
crl_new_expression(struct crl_source *source)
{
    struct crl_value *me = NULL;
    unsigned          idx;

    SXEE6("(source=?)");

    if ((idx = crl_parse_expression(source, NULL)) == CRL_ERROR)
        goto OUT;

    if (!(me = crl_value_dup(idx, "expression"))) {
        source->status = CRL_STATUS_NOMEM;
        goto OUT;
    }

    crl_value_pop(idx);

OUT:
    SXER6("return %s%s", me ? "me; // me->type == " : "NULL;", me ? crl_type_to_str(me->type) : "");
    return me;
}

/**
 * Compare two CRL values, returning CRL_TEST_ERROR on error, CRL_TEST_FALSE on failure, or CRL_TEST_TRUE on success
 *
 * @param lhs/rhs Left and right hand sides of the comparison
 * @param type    One of CRL_TYPE_EQUALS, CRL_TYPE_GREATER, CRL_TYPE_GREATER_OR_EQUAL, CRL_TYPE_LESS, or CRL_TYPE_LESS_OR_EQUAL
 */
crl_test_ret_t
crl_value_compare(const struct crl_value *lhs, const struct crl_value *rhs, uint32_t type)
{
    cJSON         *lhs_json, *rhs_json;
    crl_test_ret_t ret;
    bool           lhs_is_alloced, rhs_is_alloced;

    if (!(lhs_json = crl_value_eval(lhs, &lhs_is_alloced)))
        return CRL_TEST_ERROR;

    ret = !(rhs_json = crl_value_eval(rhs, &rhs_is_alloced)) ? CRL_TEST_ERROR
                                                             : json_value_compare(lhs_json, rhs_json, type, NULL);

    if (rhs_is_alloced)
        cJSON_free(rhs_json);

    if (lhs_is_alloced)
        cJSON_Delete(lhs_json);

    return ret;
}

/*-
 * Test a CRL value, returning CRL_TEST_ERROR on error, CRL_TEST_FALSE if false, or CRL_TEST_TRUE if true
 */
crl_test_ret_t
crl_value_test(const struct crl_value *value)
{
    cJSON         *json, *container, *element;
    int            json_type;
    crl_test_ret_t ret;
    bool           json_is_alloced, container_is_alloced;

    SXEE7("(value->type=%s)", crl_type_to_str(value->type));

    json                 = NULL;              // Tell GCC to STFU
    container            = NULL;              // Tell GCC to STFU
    ret                  = CRL_TEST_ERROR;    // Defaults to error
    json_is_alloced      = false;
    container_is_alloced = false;

    switch (crl_value_get_type(value)) {
    case CRL_TYPE_IDENTIFIER:
        if (!(json = crl_value_eval(value, &json_is_alloced)))
            goto EARLY_OUT;    // error

        ret = json_value_test(json);
        goto EARLY_OUT;

    case CRL_TYPE_JSON:
        ret = json_value_test(value->pointer);
        goto EARLY_OUT;

    case CRL_TYPE_ATTRIBUTES:
        ret = value->count ? CRL_TEST_TRUE : CRL_TEST_FALSE;
        goto EARLY_OUT;

    case CRL_TYPE_NEGATION:
        ret = crl_test_not(crl_value_test(value + 1));
        goto EARLY_OUT;

    case CRL_TYPE_IN:
        if (!(json = crl_value_eval(value + 1, &json_is_alloced))
         || !(container = crl_value_eval(value + 1 + value->count, &container_is_alloced)))
            goto EARLY_OUT;    // error

        switch (json_type = json_get_type(container)) {
        case cJSON_Array:
            cJSON_ArrayForEach(element, container) {
                if ((ret = json_value_compare(json, element, CRL_TYPE_EQUALS, NULL)) != CRL_TEST_FALSE)
                    goto EARLY_OUT;
            }

            ret = CRL_TEST_FALSE;
            goto EARLY_OUT;

        case cJSON_Object:
        case cJSON_String:
            if (json->type != cJSON_String) {
                SXEL2("Invalid check for a JSON value of type %d in a%s", json->type,
                      json_type == cJSON_Object ? "n object" : " string");
                goto EARLY_OUT;    // error
            }

            if (json_type == cJSON_Object)
                ret = cJSON_HasObjectItem(container, cJSON_GetStringValue(json)) ? CRL_TEST_TRUE : CRL_TEST_FALSE;
            else
                ret = strstr(cJSON_GetStringValue(container), cJSON_GetStringValue(json)) ? CRL_TEST_TRUE : CRL_TEST_FALSE;

            goto EARLY_OUT;
        }

        SXEL2("Invalid check for inclusion in a JSON value of type %d", container->type);
        goto EARLY_OUT;    // error

    case CRL_TYPE_EQUALS:
        ret = crl_value_compare(value + 1, value + 1 + value->count, CRL_TYPE_EQUALS);
        goto EARLY_OUT;

    case CRL_TYPE_GREATER:
        ret = crl_value_compare(value + 1, value + 1 + value->count, CRL_TYPE_GREATER);
        goto EARLY_OUT;

    case CRL_TYPE_GREATER_OR_EQUAL:
        ret = crl_value_compare(value + 1, value + 1 + value->count, CRL_TYPE_GREATER_OR_EQUAL);
        goto EARLY_OUT;

    case CRL_TYPE_LESS:
        ret = crl_value_compare(value + 1, value + 1 + value->count, CRL_TYPE_LESS);
        goto EARLY_OUT;

    case CRL_TYPE_LESS_OR_EQUAL:
        ret = crl_value_compare(value + 1, value + 1 + value->count, CRL_TYPE_LESS_OR_EQUAL);
        goto EARLY_OUT;

    case CRL_TYPE_NOT_EQUAL:
        ret = crl_value_compare(value + 1, value + 1 + value->count, CRL_TYPE_NOT_EQUAL);
        goto EARLY_OUT;

    case CRL_TYPE_CONJUNCTION:
    case CRL_TYPE_DISJUNCTION:
        // Short circuit if LHS can't be evaluated
        if (!(json = crl_value_eval(value + 1, &json_is_alloced)))
            goto EARLY_OUT;    // error

        ret = json_value_test(json);

        if (json_is_alloced) {
            cJSON_Delete(json);
            json_is_alloced = false;
        }

        // Short circuit on error or if false (conjunction) or true (disjunction)
        if (ret != (crl_value_get_type(value) == CRL_TYPE_CONJUNCTION ? CRL_TEST_TRUE : CRL_TEST_FALSE))
            goto EARLY_OUT;

        if (!(json = crl_value_eval(value + 1 + value->count, &json_is_alloced))) {
            ret = CRL_TEST_ERROR;
            goto EARLY_OUT;
        }

        ret = json_value_test(json);
        goto EARLY_OUT;

    /* These types are evaluated, and the results tested. Maybe we should pass a flag to crl_value_eval so it can optimize?
     */
    case CRL_TYPE_INTERSECT:
    case CRL_TYPE_FIND:
    case CRL_TYPE_SUBSCRIPTED:
        if ((json = crl_value_eval(value, &json_is_alloced)))
            ret = json_value_test(json);

        goto EARLY_OUT;
    }

    SXEL2("Test of unexpected CRL type %s", crl_type_to_str(value->type));

EARLY_OUT:
    if (container_is_alloced)
        cJSON_Delete(container);

    if (json_is_alloced)
        cJSON_Delete(json);

    SXER7("return %s", ret == CRL_TEST_ERROR ? "CRL_TEST_ERROR" : ret == CRL_TEST_TRUE ? "CRL_TEST_TRUE" : "CRL_TEST_FALSE");
    return ret;
}

/**
 * If value is not already a JSON value, evaluate it
 *
 * @param value          Pointer to the CRL value to evaluate
 * @param is_alloced_out Pointer to a bool set to true iff the JSON returned was allocated.
 *
 * @return Pointer to the JSON value if already a JSON value, pointer to the result for CRL, or NULL on error.
 */
cJSON *
crl_value_eval(const struct crl_value *value, bool *is_alloced_out)
{
    struct crl_namespace    find_namespace;
    const struct crl_value *value_rhs;
    cJSON                  *json, *element, *subs, *json_rhs, *elem_rhs, *elem_dup;
    char                   *ident;
    int                     json_type;
    unsigned                length;
    crl_test_ret_t          result;
    bool                    subs_is_alloced, json_is_empty, rhs_is_alloced;

    SXEE7("(value=%p) // value->type=%s", value, crl_type_to_str(value->type));
    *is_alloced_out = false;
    rhs_is_alloced  = false;
    json            = NULL;
    json_rhs        = NULL;
    subs            = NULL;
    subs_is_alloced = false;

    switch (crl_value_get_type(value)) {
    case CRL_TYPE_IDENTIFIER:
        json = crl_namespace_lookup(value->string, value->count);
        goto EARLY_OUT;

    case CRL_TYPE_JSON:
        json = value->pointer;
        goto EARLY_OUT;

    case CRL_TYPE_CONJUNCTION:
    case CRL_TYPE_DISJUNCTION:
    case CRL_TYPE_EQUALS:
    case CRL_TYPE_GREATER:
    case CRL_TYPE_GREATER_OR_EQUAL:
    case CRL_TYPE_LESS:
    case CRL_TYPE_LESS_OR_EQUAL:
    case CRL_TYPE_NEGATION:
    case CRL_TYPE_NOT_EQUAL:
        json = (result = crl_value_test(value)) == CRL_TEST_ERROR ? NULL : result ? json_bool_true : json_bool_false;
        goto EARLY_OUT;

    case CRL_TYPE_IN:
        if (!(subs     = crl_value_eval(value + 1, &subs_is_alloced))
         || !(json_rhs = crl_value_eval(value + 1 + value->count, &rhs_is_alloced)))
            goto ERROR_OUT;

        switch (json_type = json_get_type(json_rhs)) {
        case cJSON_Array:
            cJSON_ArrayForEach(element, json_rhs) {
                if (json_value_compare(subs, element, CRL_TYPE_EQUALS, NULL) != CRL_TEST_FALSE) {
                    json = json_bool_true;
                    goto EARLY_OUT;
                }
            }

            json = json_bool_false;
            goto EARLY_OUT;

        case cJSON_Object:
        case cJSON_String:
            if (json_get_type(subs) != cJSON_String) {
                SXEL2("Invalid check for a JSON value of type %d in a%s", json_get_type(subs),
                      json_type == cJSON_Object ? "n object" : " string");
                goto EARLY_OUT;    // error
            }

            if (json_type == cJSON_Object) {
                json = cJSON_GetObjectItemCaseSensitive(json_rhs, cJSON_GetStringValue(subs));
                json = json ?: json_null;
            }
            else
                json = strstr(cJSON_GetStringValue(json_rhs), cJSON_GetStringValue(subs)) ? json_bool_true : json_bool_false;

            goto EARLY_OUT;

        case cJSON_NULL:         // Allow "element IN (member IN object)" when member IN object is NULL.
            json = json_null;
            goto EARLY_OUT;

        default:
            SXEL2(": Invalid check for inclusion in a JSON value of type %d", json_type);
            goto ERROR_OUT;
        }

    case CRL_TYPE_FIND:
        if (!(json = crl_value_eval(value + 1, is_alloced_out)))
            goto EARLY_OUT;    // Return NULL

        if (json_get_type(json) != cJSON_Array) {
            SXEL2(": Left hand side of a FIND expression must be an array, not JSON type %d", json_get_type(json));
            goto ERROR_OUT;
        }

        // Allocate an empty subset and return it on no match so that it can be distiguished from an error.
        if (!(subs = MOCKFAIL(CRL_VALUE_CREATE_ARRAY, NULL, cJSON_CreateArray()))) {
            SXEL2(": Failed to create array for result of FIND expression");
            goto ERROR_OUT;
        }

        subs_is_alloced = true;
        json_is_empty   = true;
        value_rhs       = value + 1 + value->count;

        cJSON_ArrayForEach(element, json) {
            if (json_is_empty) {            // Looks like the JSON array isn't empty after all
                subs_is_alloced = false;    // Signal that subs should be deallocated if there are no objects in array
                json_is_empty   = false;
            }

            if (json_get_type(element) != cJSON_Object && value_rhs->type != CRL_TYPE_WHERE) {
                SXEL2(": Elements of left hand side of a WHEREless FIND expression must be objects, not JSON type %d",
                      json_get_type(element));
                continue;
            }

            subs_is_alloced = true;    // Signal that subs array has at least one object in the JSON array.

            if (value_rhs->type != CRL_TYPE_WHERE) {    // No WHERE clause, so the element is the namespace
                crl_namespace_push_object(&find_namespace, element);
                result = crl_value_test(value_rhs);
            } else {
                if (json_rhs == NULL) {
                    SXEA6(value_rhs[1].type == CRL_TYPE_IDENTIFIER, "Left hand side of a WHERE clause must be an identifier");
                    ident = alloca(length = value_rhs[1].count);    // Must copy to insure NUL termination
                    memcpy(ident, value_rhs[1].string, length);
                    ident[length] = '\0';

                    if (!(json_rhs = MOCKFAIL(CRL_VALUE_CREATE_OBJECT, NULL, cJSON_CreateObject()))) {
                        SXEL2(": Failed to create object for namespace of FIND/WHERE expression");
                        goto ERROR_OUT;
                    }

                    rhs_is_alloced = true;
                }

                if (!(elem_dup = MOCKFAIL(CRL_VALUE_FIND_DUPLICATE, NULL, cJSON_Duplicate(element, true)))) {
                    SXEL2(": Failed to duplicate element to use in FIND/WHERE expression");
                    goto ERROR_OUT;
                }

                cJSON_AddItemToObject(json_rhs, ident, elem_dup);         // In cJSON 1.7.10, this is a void function
                SXEL7("Added ident '%s' value %s to namespace object", ident, json_to_str(elem_dup));
                crl_namespace_push_object(&find_namespace, json_rhs);
                result = crl_value_test(value_rhs + 2);
                cJSON_DeleteItemFromObject(json_rhs, ident);
            }

            if (result == CRL_TEST_ERROR) {    // On error
                SXEA1(&find_namespace == crl_namespace_pop(), "Expected to pop find_namespace");
                goto ERROR_OUT;
            }

            if (result == CRL_TEST_TRUE) {    // Make a reference to the found object to avoid freeing it twice
                if (!(elem_dup = MOCKFAIL(CRL_VALUE_CREATE_REFERENCE, NULL, cJSON_CreateObjectReference(element->child)))) {
                    SXEL2(": Failed to create a reference to an object in a FIND expression");
                    SXEA1(&find_namespace == crl_namespace_pop(), "Expected to pop find_namespace");
                    goto ERROR_OUT;
                }

                cJSON_AddItemToArray(subs, elem_dup);
            }

            SXEA1(&find_namespace == crl_namespace_pop(), "Expected to pop find_namespace");
        }

        if (!subs_is_alloced) {    // If there were elements but none of them were objects, this is an error
            cJSON_Delete(subs);
            subs = NULL;
        }

        if (*is_alloced_out)
            cJSON_Delete(json);

        json            = subs;
        subs_is_alloced = false;
        *is_alloced_out = json ? true : false;
        goto EARLY_OUT;

    case CRL_TYPE_LENGTH:
        if (!(json = crl_value_eval(value + 1, is_alloced_out)))
            goto EARLY_OUT;    // Return NULL

        switch (json_get_type(json)) {
        case cJSON_String:
            length = strlen(cJSON_GetStringValue(json));
            break;

        case cJSON_Array:
            length = cJSON_GetArraySize(json);
            break;

        default:
            SXEL2(": Attempt to find the length of an unexpected JSON type %d", json_get_type(json));
            goto ERROR_OUT;
        }

        if (*is_alloced_out)
            cJSON_Delete(json);

        if (!(json = MOCKFAIL(CRL_VALUE_CREATE_NUMBER, NULL, cJSON_CreateNumber(length)))) {
            SXEL2(": Failed to create JSON number for LENGTH");
            *is_alloced_out = false;
            goto EARLY_OUT;    // Return NULL
        }

        *is_alloced_out = true;
        goto EARLY_OUT;

    case CRL_TYPE_TIME:
        if (crl_value_get_type(value_rhs = value + 1) != CRL_TYPE_JSON || json_get_type(value_rhs->pointer) != cJSON_NULL) {
            SXEL2(": TIME's argument must be 'null' (get current time)");
            goto ERROR_OUT;
        }

        if (!(json = MOCKFAIL(CRL_VALUE_CREATE_TIME, NULL, cJSON_CreateNumber((double)time(NULL))))) {
            SXEL2(": Failed to create JSON number for the time");
            *is_alloced_out = false;
            goto EARLY_OUT;    // Return NULL
        }

        *is_alloced_out = true;
        goto EARLY_OUT;

    case CRL_TYPE_SUBSCRIPTED:
        if (!(json = crl_value_eval(value + 1, is_alloced_out))
         || !(subs = crl_value_eval(value + 1 + value->count, &subs_is_alloced)))
            goto ERROR_OUT;

        switch (json_get_type(json)) {
        case cJSON_Array:
            if (json_get_type(subs) != cJSON_Number) {
                SXEL2(": Attempt to use a non-numeric JSON type %d as an array subscript", json_get_type(subs));
                goto ERROR_OUT;
            }

            if (!(element = cJSON_GetArrayItem(json, (int)subs->valuedouble))) {
                SXEL2(": Subscript %d is out of range", (int)subs->valuedouble);
                goto ERROR_OUT;
            }

            break;

        case cJSON_Object:
            if (json_get_type(subs) != cJSON_String) {
                SXEL2("%s: Attempt to use a non-string JSON type %d as an object member name", __func__, json_get_type(subs));
                goto ERROR_OUT;
            }

            if (!(element = cJSON_GetObjectItemCaseSensitive(json, cJSON_GetStringValue(subs)))) {
                SXEL2("%s: Member name %s is not a member of object", __func__, cJSON_GetStringValue(subs));
                SXEL7("object=%s", json_to_str(json));
                goto ERROR_OUT;
            }

            break;

        default:
            SXEL2("%s: Attempt to subscript an unexpected JSON type %d", __func__, json_get_type(json));
            goto ERROR_OUT;
        }

        if (*is_alloced_out) {    // If the array/object is allocated, duplicate the element/member and free the array/object
            if (!(element = MOCKFAIL(CRL_VALUE_CJSON_DUPLICATE, NULL, cJSON_Duplicate(element, true)))) {
                SXEL2("%s: Failed to duplicate an allocated %s", __func__,
                      json_get_type(json) == cJSON_Array ? "array element" : "object member");
                goto ERROR_OUT;
            }

            cJSON_Delete(json);
        }

        json = element;
        goto EARLY_OUT;

    case CRL_TYPE_INTERSECT:
        if (!(json     = crl_value_eval(value + 1, is_alloced_out))
         || !(json_rhs = crl_value_eval(value + 1 + value->count, &rhs_is_alloced)))
            goto ERROR_OUT;

        if (json_get_type(json) != cJSON_Array) {
            SXEL2("%s: Left hand side of an INTERSECT expression must be an array, not JSON type %d", __func__,
                  json_get_type(json));
            goto ERROR_OUT;
        }

        if (json_get_type(json_rhs) != cJSON_Array) {
            SXEL2("%s: Right hand side of an INTERSECT expression must be an array, not JSON type %d", __func__,
                  json_get_type(json_rhs));
            goto ERROR_OUT;
        }

        // Allocate an empty array for the intersection.
        if (!(subs = MOCKFAIL(CRL_VALUE_CREATE_INTERSECT, NULL, cJSON_CreateArray()))) {
            SXEL2("%s: Failed to create array for result of FIND expression", __func__);
            goto ERROR_OUT;
        }

        subs_is_alloced = true;

        cJSON_ArrayForEach(element, json) {
            cJSON_ArrayForEach(elem_rhs, json_rhs) {
                if ((result = json_value_compare(element, elem_rhs, CRL_TYPE_EQUALS, NULL)) == CRL_TEST_ERROR)
                    goto ERROR_OUT;

                if (result == CRL_TEST_TRUE) {
                    if (!(elem_dup = MOCKFAIL(CRL_VALUE_CJSON_INTERSECT, NULL, cJSON_Duplicate(element, true)))) {
                        SXEL2("%s: Failed to duplicate an element in an INTERSECT expression", __func__);
                        goto ERROR_OUT;
                    }

                    cJSON_AddItemToArray(subs, elem_dup);
                }
            }
        }

        if (*is_alloced_out)
            cJSON_Delete(json);

        json            = subs;
        subs_is_alloced = false;
        *is_alloced_out = true;
        goto EARLY_OUT;

    case CRL_TYPE_SUM:
        if (!(json     = crl_value_eval(value + 1, is_alloced_out))
         || !(json_rhs = crl_value_eval(value + 1 + value->count, &rhs_is_alloced)))
            goto ERROR_OUT;

        if (json_get_type(json) != cJSON_Number) {
            SXEL2(": Left hand side of a + expression must be a number, not JSON type %d", json_get_type(json));
            goto ERROR_OUT;
        }

        if (json_get_type(json_rhs) != cJSON_Number) {
            SXEL2(": Right hand side of a + expression must be a number, not JSON type %d", json_get_type(json_rhs));
            goto ERROR_OUT;
        }

        // Allocate the sum
        if (!(subs = MOCKFAIL(CRL_VALUE_CREATE_SUM, NULL,
                              cJSON_CreateNumber(json_number_get_double(json) + json_number_get_double(json_rhs))))) {
            SXEL2("%s: Failed to create result of + expression", __func__);
            goto ERROR_OUT;
        }

        if (*is_alloced_out)
            cJSON_Delete(json);

        json            = subs;
        *is_alloced_out = true;
        goto EARLY_OUT;
    }

    SXEL2("%s: Unexpected CRL type %s cannot be evaluated to JSON", __func__, crl_type_to_str(value->type));
    goto EARLY_OUT;    // Return NULL

ERROR_OUT:
    if (*is_alloced_out) {
        cJSON_Delete(json);
        *is_alloced_out = false;
    }

    json = NULL;

EARLY_OUT:
    if (subs_is_alloced)
        cJSON_Delete(subs);

    if (rhs_is_alloced)
        cJSON_Delete(json_rhs);    /* COVERAGE EXCLUSION: Test when there is more than one way to allocate a RHS */

    SXER7("return json=%s // json->type=%d, *is_alloced_out=%s",
          json ? json_to_str(json) : "NULL", json ? json->type : -1, *is_alloced_out ? "true" : "false");
    return json;
}

/**
 * Evaluate all attribute values. If any value was not already a JSON, a new attribute set of evaluated values is created.
 *
 * @param attr       Pointer to the CRL attributes to evaluate
 * @param is_new_out Pointer to a bool set to true iff the attributes returned are newly allocated.
 *
 * @return Pointer to a new attributes (allocated), the input attr if not, or NULL on failure to allocate.
 */
struct crl_value *
crl_attributes_eval(struct crl_value *attr, bool *is_new_out)
{
    struct crl_value *evaluated;
    unsigned          count, i, j;
    bool              is_alloced;

    SXEA6(attr->type == CRL_TYPE_ATTRIBUTES, "Expected CRL attributes");
    SXEE7("(attr=%p)", attr);
    *is_new_out = false;
    count       = attr->count;
    evaluated   = NULL;

    for (i = 0; i < count; i++)
        if (crl_value_get_type(&attr[2 * (i + 1)]) != CRL_TYPE_JSON)
            break;

    if (i >= count) {    // All attribute values are JSON. Just return them.
        evaluated = attr;
        goto EARLY_OUT;
    }

    if (!(evaluated = MOCKFAIL(CRL_VALUE_ATTRIBUTES_EVAL, NULL, kit_malloc((1 + 2 * count) * sizeof(*attr))))) {
        SXEL2("%s: Failed to allocate %zu bytes of attributes", __func__, (1 + 2 * count) * sizeof(*attr));
        goto EARLY_OUT; // return NULL
    }

    memcpy(evaluated, attr, (2 * i + 1) * sizeof(*attr));    // Copy attribute value and any leading JSON values over

    for (j = 0; j < i; j++)    // For each leading attribute that is already JSON, mark it as a copy
        evaluated[2 * j + 2].type |= CRL_IS_REFERENCE;

    for (attr += 1 + 2 * i; i < count; i++) {
        if (crl_value_get_type(attr + 1) == CRL_TYPE_JSON) {
            memcpy(&evaluated[2 * i + 1], attr, 2 * sizeof(*attr));    // Copy the key/value pair
            evaluated[2 * i + 2].type |= CRL_IS_REFERENCE;
            continue;
        }

        memcpy(&evaluated[2 * i + 1], attr, sizeof(*attr));    // Copy the key
        evaluated[2 * i + 1].count = 2;
        evaluated[2 * i + 2].type  = CRL_TYPE_JSON;             // Value will not be a copy of the original value

        if (!(evaluated[2 * i + 2].pointer = crl_value_eval(attr + 1, &is_alloced))) {
            kit_free(evaluated);
            evaluated = NULL;
            goto EARLY_OUT;
        }

        if (!is_alloced)
            evaluated[2 * i + 2].type |= CRL_IS_REFERENCE;

        attr += attr->count;
    }

    *is_new_out = true;

EARLY_OUT:
    SXER7("return evaluated=%p; // *is_new_out=%s", evaluated, *is_new_out ? "true" : "false");
    return evaluated;
}


/* Finalize a value. If called on a value on the stack, that value should be the last value parsed that is still on the stack.
 */
struct crl_value *
crl_value_fini(struct crl_value *value)
{
    unsigned count;

    SXEA1(value, "Attempt to fininalize a NULL value");

    switch (value->type) {
    case CRL_TYPE_JSON:
        cJSON_Delete(value->pointer);
        value->pointer = NULL;
        return ++value;

    case CRL_TYPE_ATTRIBUTES:
        count = value->count;
        value++;

        while (count--)
            if (value[1].type == (CRL_TYPE_JSON | CRL_IS_REFERENCE))
                value += 2;    // Skip the key and the value
            else
                value = crl_value_fini(value + 1);    // + 1 to skip the key

        return value;

    case CRL_TYPE_NEGATION:
    case CRL_TYPE_LENGTH:
    case CRL_TYPE_TIME:
        return crl_value_fini(value + 1);    // + 1 to skip the operator

    case CRL_TYPE_IN:
    case CRL_TYPE_EQUALS:
    case CRL_TYPE_CONJUNCTION:
    case CRL_TYPE_FIND:
    case CRL_TYPE_SUBSCRIPTED:
    case CRL_TYPE_INTERSECT:
    case CRL_TYPE_GREATER:
    case CRL_TYPE_GREATER_OR_EQUAL:
    case CRL_TYPE_LESS:
    case CRL_TYPE_LESS_OR_EQUAL:
    case CRL_TYPE_NOT_EQUAL:
    case CRL_TYPE_WHERE:
    case CRL_TYPE_SUM:
        crl_value_fini(value + 1);                          // LHS
        return crl_value_fini(value + 1 + value->count);    // RHS

    default:
        return ++value;
    }
}

void
crl_value_free(struct crl_value *value)
{
    if (value)
        crl_value_fini(value);

    kit_free(value);
}

/**
 * Compare a CRL identifier to a string
 *
 * @return CRL_TEST_TRUE if the string matches the identifier, CRL_TEST_FALSE if not, or CRL_TEST_ERROR if the CRL value is
 *         not an idenitifer
 */
crl_test_ret_t
crl_identifier_equal_str(const struct crl_value *value, const char *string)
{
    if (crl_value_get_type(value) != CRL_TYPE_IDENTIFIER)
        return CRL_TEST_ERROR;

    if (strncmp(value->string, string, value->count) == 0 && string[value->count] == '\0')
        return CRL_TEST_TRUE;

    return CRL_TEST_FALSE;
}

/**
 * Convert a CRL value to a string
 *
 * @note Each time this function is called in a thread, the string value may be overwritten
 *
 * @note This belongs in crl.c in libuup.  Should constify the APIs
 */
const char *
crl_value_to_str(const struct crl_value *value)
{
    static __thread char buf[1024];

    switch (crl_value_get_type(value)) {
    case CRL_TYPE_IDENTIFIER:
        if (value->count <= sizeof(buf) - 4) {
            memcpy(buf, value->string, value->count);
            buf[value->count] = '\0';
        }
        else {
            memcpy(buf, value->string, sizeof(buf) - 4);
            strcpy(&buf[sizeof(buf) - 4], "...");
        }

        break;

    default:
        snprintf(buf, sizeof(buf), "CRL Type %s", crl_type_to_str(crl_value_get_type(value)));
    }

    return buf;
}
