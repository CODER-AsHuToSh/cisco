#include <cjson/cJSON.h>
#include <kit-alloc.h>
#include <math.h>
#include <mockfail.h>
#include <string.h>
#include <tap.h>
#include <time.h>

#include "common-test.h"
#include "crl.h"
#include "json.h"

static char line1[4096];
static char line2[4096];

static void
test_source_init(struct crl_source *source, char *buf, size_t size, const char *file, unsigned line, const char *content)
{
    strncpy(buf, content, size - 1);
    crl_source_init(source, buf, file, line, CRL_VERSION_UUP);
}

/* Prepare for a malloc failure test that allows for 'count' values to be allocated before failing
 */
static void
test_fail_malloc_after(unsigned count)
{
    struct crl_source source;

    crl_parse_finalize_thread();
    crl_parse_initialize(1 + count, 1, NULL);
    test_source_init(&source, line1, sizeof(line1), "file", 1, "id");
    crl_parse_identifier(&source);    // Force initial allocation
}

static crl_test_ret_t
test_value_test_version(const char *expr, unsigned version)
{
    struct crl_source source;
    struct crl_value *value;
    int               ret;

    test_source_init(&source, line1, sizeof(line1), "file", 1, expr);
    source.version = version;
    SXEA1(value = crl_new_expression(&source), "Failed to parse expression '%s'", expr);
    ret = crl_value_test(value);
    crl_value_free(value);
    return ret;
}

static crl_test_ret_t
test_value_test(const char *expr)
{
    return test_value_test_version(expr, CRL_VERSION_UUP);
}

static cJSON *
test_value_eval(const char *expr, bool *is_alloced_out)
{
    struct crl_source source;
    struct crl_value *value;
    cJSON            *ret;

    test_source_init(&source, line1, sizeof(line1), "file", 1, expr);
    value = crl_new_expression(&source);
    SXEA1(source.left[0] == '\0', "The entire expression wasn't parsed. Remainder: '%s'", source.left);
    ret = crl_value_eval(value, is_alloced_out);
    crl_value_free(value);
    return ret;
}

static struct crl_value *
test_attributes_eval(const char *expr, bool *is_alloced_out)
{
    struct crl_source source;
    struct crl_value *value, *ret;

    test_source_init(&source, line1, sizeof(line1), "file", 1, expr);
    value = crl_new_attributes(&source);
    SXEA1(source.left[0] == '\0', "The entire attribute set wasn't parsed. Remainder: '%s'", source.left);
    ret = crl_attributes_eval(value, is_alloced_out);
    crl_value_free(value);
    return ret;
}

int
main(void)
{
    struct crl_namespace    test_namespace, test_posture, attr_namespace;
    struct crl_source       source;
    struct crl_value       *attrs, *evals, *value;
    const struct crl_value *attr_value;
    cJSON                  *object, *array, *inner;
    uint64_t                start_allocations;
    bool                    is_alloced;

    plan_tests(283);

    kit_memory_initialize(false);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");
    // KIT_ALLOC_SET_LOG(1);    // Turn off when done

    SXEA1(object = cJSON_CreateObject(),                                 "Failed to create test namespace object");
    SXEA1(cJSON_AddStringToObject(object, "endpoint.os.type",    "win"), "Failed to add endpoint.os.type");
    SXEA1(cJSON_AddStringToObject(object, "endpoint.os.version", "10"),  "Failed to add endpoint.os.version");
    crl_namespace_push_object(&test_namespace, object);

    line1[sizeof(line1) - 1] = '\0';
    KIT_ALLOC_SET_LOG(1);    // Turn off when done
    crl_initialize(0, 0);

    test_source_init(&source, line1, sizeof(line1), "file", 1, "");
    ok(attrs = crl_new_attributes(&source), "Successfully parsed empty attributes");
    ok(crl_source_is_exhausted(&source),    "Fully parsed the source ''");
    is(attrs->type,  CRL_TYPE_ATTRIBUTES,   "Value is a list of attributes");
    is(attrs->count, 0,                     "List of attributes has no elements");
    crl_value_free(attrs);

    test_source_init(&source, line1, sizeof(line1), "file", 1, "key := \"value\"");
    ok(attrs = crl_new_attributes(&source),                             "Successfully parsed a single attribute");
    is(*crl_source_skip_space(&source), '\0',                           "Fully parsed the source 'key = \"value\"'");
    is(attrs->type, CRL_TYPE_ATTRIBUTES,                                "Value is a list of attributes");
    is(attrs->count, 1,                                                 "List of attributes has one element");
    ok((attr_value = crl_attributes_get_value(attrs, "key")),           "Found 'key' in attributes");
    is(attr_value->type, CRL_TYPE_JSON,                                 "It's value is of type JSON");
    is_eq(cJSON_GetStringValue(attr_value->pointer) ?: "NULL", "value", "It's value is the JSON string 'value'");
    is(crl_attributes_get_value(attrs, "lock"), NULL,                   "Did not find 'lock' in attributes");
    crl_value_free(attrs);

    test_source_init(&source, line1, sizeof(line1), "file", 1, "NOT []:");
    ok(value = crl_new_expression(&source),                "Successfully parsed 'NOT []:'");
    is(*crl_source_skip_space(&source), ':',               "Fully parsed the source 'NOT []'");
    is(value->type,                     CRL_TYPE_NEGATION, "Value is a negation");
    is(crl_value_test(value), CRL_TEST_TRUE,               "NOT [] is true");
    crl_value_free(value);

    test_source_init(&source, line1, sizeof(line1), "file", 1, "NOT (bogus.id IN [\"win\", \"macos\", \"ios\", \"linux\"])");
    ok(value = crl_new_expression(&source),                  "Successfully parsed 'NOT bogus.id IN [list]'");
    is(*crl_source_skip_space(&source), '\0',                "Fully parsed the source 'NOT bogus.id IN [list]'");
    is(value->type,                     CRL_TYPE_NEGATION,   "Value is a negation");
    is(value[1].type,                   CRL_TYPE_IN,         "Of an IN expression");
    is(value[2].type,                   CRL_TYPE_IDENTIFIER, "Whose LHS is an identifier");
    is(value[3].type,                   CRL_TYPE_JSON,       "And whose RHS is JSON");
    is(crl_value_test(value),           CRL_TEST_ERROR,      "'NOT bogus.id IN [list]' is an error");
    crl_value_free(value);

    test_source_init(&source, line1, sizeof(line1), "file", 1, "NOT (endpoint.os.type IN [\"win\", \"macos\", \"ios\", \"linux\"])");
    ok(value = crl_new_expression(&source),   "Successfully parsed 'NOT endpoint.os.type IN [list]'");
    is(crl_value_test(value), CRL_TEST_FALSE, "'NOT endpoint.os.type IN [list]' is false");
    crl_value_free(value);

    test_source_init(&source, line1, sizeof(line1), "file", 1, "(NOT (endpoint.os.type = \"win\" AND endpoint.os.version IN [\"10\"]))");
    ok(value = crl_new_expression(&source),   "Successfully parsed '(NOT (endpoint.os.type = \"win\" AND endpoint.os.version IN [\"10\"]))'");
    is(*crl_source_skip_space(&source), '\0', "Fully parsed '(NOT (endpoint.os.type = \"win\" AND endpoint.os.version IN [\"10\"]))'");
    is(crl_value_test(value), CRL_TEST_FALSE, "'(NOT (endpoint.os.type = \"win\" AND endpoint.os.version IN [\"10\"]))' is false");
    crl_value_free(value);

    diag("tests invloving attriibutes evaluated against simulated posture");
    {
        // Generate a simulated posture and push it onto the stack of namespaces
        object = cJSON_CreateObject();
        array  = cJSON_AddArrayToObject(object, "endpoint.certificates");
        inner  = cJSON_CreateObject();
        cJSON_AddStringToObject(inner, "sha1", "1234567890abcdef1234567890abcdef12345678");
        cJSON_AddItemToArray(array, inner);
        crl_namespace_push_object(&test_posture, object);

        test_source_init(&source, line1, sizeof(line1), "file", 1,
                         "endpoint.certificates FIND (sha1 = \"1234567890abcdef1234567890abcdef12345678\")");
        ok(value = crl_new_expression(&source), "Successfully parsed 'endpoint.certificates FIND (sha1 = \"xxxx...\")'");
        ok(object = crl_value_eval(value, &is_alloced),
        "Successfully evaluated 'endpoint.certificates FIND (sha1 = \"xxxx...\")'");
        ok(is_alloced, "Evaluating a FIND should yeild an allocated subset");
        cJSON_Delete(object);
        crl_value_free(value);

        test_source_init(&source, line1, sizeof(line1), "file", 1,
            "reason := \"Cert_Check\", "
            "certlist := endpoint.certificates FIND (sha1 = \"1234567890abcdef1234567890abcdef12345678\"), y := 1");
        ok(attrs = crl_new_attributes(&source),                      "Successfully parsed attributes with a FIND expression");
        is(*crl_source_skip_space(&source), '\0',                    "Fully parsed attributes with a FIND expression");
        ok(attr_value = crl_attributes_get_value(attrs, "certlist"), "Successfully got value of 'certlist' attribute");
        is(attr_value[0].type, CRL_TYPE_FIND,                        "Value is a find expression");
        is(attr_value[1].type, CRL_TYPE_IDENTIFIER,                  "Whose LHS is an identifier");
        is(attr_value[2].type, CRL_TYPE_EQUALS,                      "And whose RHS is an equals expression");
        is(attr_value[3].type, CRL_TYPE_IDENTIFIER,                  "Whose LHS is an identifier");
        is(attr_value[4].type, CRL_TYPE_JSON,                        "And whose RHS is JSON");
        ok(attr_value = crl_attributes_get_value(attrs, "y"),        "Successfully got value of 'y' attribute");

        ok(evals = crl_attributes_eval(attrs, &is_alloced), "Evaluated the attributes against the namespaces");
        ok(is_alloced,                                      "Evaluated attributes are an alloced copy");
        is(evals->count, 3,                                 "There are 3 evaluated attributes");
        is(evals[2].type, CRL_TYPE_JSON | CRL_IS_REFERENCE, "First attribute should be a reference to a JSON value");
        is_eq(evals[3].string, "certlist",                  "Second attribute's name is certlist");
        is(evals[4].type, CRL_TYPE_JSON,                    "Second attribute should be a constructed JSON value");
        is((array = evals[4].pointer)->type, cJSON_Array,   "Second attribute is a JSON array");
        object = cJSON_GetArrayItem(array, 0);
        is(object->type, cJSON_Object | cJSON_IsReference,  "Array's first element is a JSON object reference");
        is((inner = object->child)->type, cJSON_String,     "Objects first member is a JSON string");

        test_source_init(&source, line2, sizeof(line2), "file", 2,
            "NOT (LENGTH certlist = 1 AND certlist[0][\"sha1\"] = \"1234567890abcdef1234567890abcdef12345678\"): (block)");
        ok(value = crl_new_expression(&source),   "Successfully parsed LENGTH and element/member expression");
        is(*crl_source_skip_space(&source), ':',  "Fully parsed the source up to the ':' separator");
        is(crl_value_test(value), CRL_TEST_ERROR, "Condition was an error without evaluated attributes");
        crl_namespace_push_attributes(&attr_namespace, evals);
        is(crl_value_test(value), CRL_TEST_FALSE, "Condition tested false with evaluated attributes");
        is(&attr_namespace, crl_namespace_pop(),  "Popped the evaluated attributes namespace");

        crl_value_free(value);
        crl_value_free(evals);
        crl_value_free(attrs);

        is(&test_posture, crl_namespace_pop(), "Popped the posture namespace");
        cJSON_Delete(test_posture.object);
    }

    diag("coverage for crl-parse.c");
    {
        uint32_t type;
        unsigned idx;

        for (type = CRL_TYPE_IDENTIFIER; type <= CRL_TYPE_MAX; type++)
            ok(crl_type_to_str(type), "Converted %u to '%s'", type, crl_type_to_str(type));

        type = CRL_TYPE_JSON | CRL_IS_REFERENCE;
        ok(crl_type_to_str(type),              "Converted %u to '%s'", type, crl_type_to_str(type));
        ok(!crl_type_to_str(CRL_TYPE_MAX + 1), "Failed to convert %u to string", CRL_TYPE_MAX + 1);

        crl_parse_finalize_thread();    // This should be called per worker thread
        crl_parse_initialize(1, 1, NULL);
        test_source_init(&source, line1, sizeof(line1), "file", 1, "id1 id2 id3");
        is(crl_parse_identifier(&source), 0,         "This triggers the initial stack allocation");
        is(crl_parse_identifier(&source), 1,         "This triggers the first increase by the maximum_increment");

        MOCKFAIL_START_TESTS(6, CRL_VALUE_PUSH);
        is(crl_parse_identifier(&source), CRL_ERROR, "Allocation failure expanding stack parsing an identifier");
        is(crl_parse_json(&source, NULL), CRL_ERROR, "Allocation failure expanding stack parsing JSON");
        is(crl_parse_attributes(&source), CRL_ERROR, "Allocation failure expanding stack parsing attributes");
        test_source_init(&source, line1, sizeof(line1), "file", 1, "NOT");
        is(crl_parse_monadic_expr(&source, NULL), CRL_ERROR, "Allocation failure expanding stack parsing 'NOT'");
        test_source_init(&source, line1, sizeof(line1), "file", 1, "LENGTH");
        is(crl_parse_monadic_expr(&source, NULL), CRL_ERROR, "Allocation failure expanding stack parsing 'LENGTH'");
        is(source.status, CRL_STATUS_NOMEM,          "Status is out of memory");
        MOCKFAIL_END_TESTS();
        crl_parse_finalize_thread();    // Next crl_value_push will reinitialize crl-parse

        test_source_init(&source, line1, sizeof(line1), "file", 1, " ");
        is(crl_parse_identifier(&source), CRL_ERROR, "End of data before identifier");
        is(source.status, CRL_STATUS_OK,             "Status is OK");
        test_source_init(&source, line1, sizeof(line1), "file", 1, "0bad-identifier");
        is(crl_parse_identifier(&source), CRL_ERROR, "Bad identifier");
        is(source.status, CRL_STATUS_WRONG_TYPE,     "Status is WRONG_TYPE");

        test_source_init(&source, line1, sizeof(line1), "file", 1, "bad-JSON");
        is(crl_parse_json(&source, NULL), CRL_ERROR, "Bad JSON");
        is(crl_parse_json(&source, ""),   CRL_ERROR, "Bad JSON after ''");

        test_source_init(&source, line1, sizeof(line1), "file", 1, "attribute.with.trailing.semicolon := 0;");
        ok(attrs = crl_new_attributes(&source), "Parsed attribute with trailing ';'");
        is(source.status, CRL_STATUS_OK,        "Status is OK");
        is_eq(source.left, ";",                 "The semicolon is all that's left");
        crl_value_free(attrs);
        test_source_init(&source, line1, sizeof(line1), "file", 1, ";");
        ok(attrs = crl_new_attributes(&source), "Parsed empty attribute set with trailing ';'");
        is(attrs->count, 0,                     "And it is empty");
        crl_value_free(attrs);
        test_source_init(&source, line1, sizeof(line1), "file", 1, "x:=0,;");
        is(crl_parse_attributes(&source), CRL_ERROR, "A comma must be followed by an attribute");
        is(source.status, CRL_STATUS_INVAL,          "Status is INVALID");
        test_source_init(&source, line1, sizeof(line1), "file", 1, "x+=1,;");
        is(crl_parse_attributes(&source), CRL_ERROR, "An identifier must be followed by ':='");
        is(source.status, CRL_STATUS_INVAL,          "Status is INVALID");

        test_source_init(&source, line1, sizeof(line1), "file", 1, "(");
        is(crl_parse_elementary_expr(&source, NULL), CRL_ERROR, "'(' must be followed by an expression");
        test_source_init(&source, line1, sizeof(line1), "file", 1, "(x x");
        is(crl_parse_elementary_expr(&source, NULL), CRL_ERROR, "'(expr' must be followed by ')'");
        is(source.status, CRL_STATUS_INVAL,                     "Status is INVALID");
        test_source_init(&source, line1, sizeof(line1), "file", 1, "x[");
        is(crl_parse_elementary_expr(&source, NULL), CRL_ERROR, "'x[' must be followed by an expression");
        test_source_init(&source, line1, sizeof(line1), "file", 1, "x[x x");
        is(crl_parse_elementary_expr(&source, NULL), CRL_ERROR, "'[expr' must be followed by ']'");
        is(source.status, CRL_STATUS_INVAL,                     "Status is INVALID");

        test_fail_malloc_after(1);
        test_source_init(&source, line1, sizeof(line1), "file", 1, "x[1]");
        MOCKFAIL_START_TESTS(2, CRL_VALUE_PUSH);
        is(crl_parse_elementary_expr(&source, NULL), CRL_ERROR, "Allocation failure expanding stack for subscript");
        is(source.status, CRL_STATUS_NOMEM, "Status is out of memory");
        MOCKFAIL_END_TESTS();
        crl_parse_finalize_thread();    // Next crl_value_push will reinitialize crl-parse

        test_source_init(&source, line1, sizeof(line1), "file", 1, "L");
        ok(crl_parse_monadic_expr(&source, NULL) != CRL_ERROR, "Parsed an identifier that starts with L");
        test_source_init(&source, line1, sizeof(line1), "file", 1, "N");
        ok(crl_parse_monadic_expr(&source, NULL) != CRL_ERROR, "Parsed an identifier that starts with N");

        test_source_init(&source, line1, sizeof(line1), "file", 1, "x F");
        ok((idx = crl_parse_dyadic_expr(&source, NULL)) != CRL_ERROR, "Parse an invalid dyadic operator F");
        value = crl_value_dup(idx, "value");
        is_strncmp(value->string, "x??", value->count, "Since F is not a dyadic operator, x is returned");
        crl_value_free(value);

        test_source_init(&source, line1, sizeof(line1), "file", 1, "x I");
        ok(crl_parse_dyadic_expr(&source, NULL) != CRL_ERROR, "Parse an invalid dyadic operator I");

        test_source_init(&source, line1, sizeof(line1), "file", 1, "x WTF");
        ok(crl_parse_dyadic_expr(&source, NULL) != CRL_ERROR, "Parse an invalid dyadic operator WTF");

        test_source_init(&source, line1, sizeof(line1), "file", 1, "x = (");
        is(crl_parse_dyadic_expr(&source, NULL),  CRL_ERROR, "Failed to parse a comparison with an invalid RHS");

        test_fail_malloc_after(1);
        test_source_init(&source, line1, sizeof(line1), "file", 1, "x = 0");
        MOCKFAIL_START_TESTS(1, CRL_VALUE_PUSH);
        is(crl_parse_dyadic_expr(&source, NULL), CRL_ERROR, "Allocation failure expanding stack for RHS of '='");
        MOCKFAIL_END_TESTS();

        test_fail_malloc_after(1);
        test_source_init(&source, line1, sizeof(line1), "file", 1, "x > 0");
        MOCKFAIL_START_TESTS(1, CRL_VALUE_PUSH);
        is(crl_parse_dyadic_expr(&source, NULL), CRL_ERROR, "Allocation failure expanding stack for RHS of '>'");
        MOCKFAIL_END_TESTS();

        test_fail_malloc_after(1);
        test_source_init(&source, line1, sizeof(line1), "file", 1, "x FIND 0");
        MOCKFAIL_START_TESTS(1, CRL_VALUE_PUSH);
        is(crl_parse_dyadic_expr(&source, NULL), CRL_ERROR, "Allocation failure expanding stack for RHS of FIND");
        MOCKFAIL_END_TESTS();

        test_fail_malloc_after(1);
        test_source_init(&source, line1, sizeof(line1), "file", 1, "x WHERE 0");
        MOCKFAIL_START_TESTS(1, CRL_VALUE_PUSH);
        is(crl_parse_dyadic_expr(&source, NULL), CRL_ERROR, "Allocation failure expanding stack for RHS of WHERE");
        MOCKFAIL_END_TESTS();

        test_fail_malloc_after(1);
        test_source_init(&source, line1, sizeof(line1), "file", 1, "x IN 0");
        MOCKFAIL_START_TESTS(1, CRL_VALUE_PUSH);
        is(crl_parse_dyadic_expr(&source, NULL), CRL_ERROR, "Allocation failure expanding stack for RHS of IN");
        MOCKFAIL_END_TESTS();

        test_fail_malloc_after(1);
        test_source_init(&source, line1, sizeof(line1), "file", 1, "x AND y");
        MOCKFAIL_START_TESTS(1, CRL_VALUE_PUSH);
        is(crl_parse_expression(&source, NULL), CRL_ERROR, "Allocation failure expanding stack for RHS of AND");
        MOCKFAIL_END_TESTS();

        test_fail_malloc_after(1);
        test_source_init(&source, line1, sizeof(line1), "file", 1, "x OR y");
        MOCKFAIL_START_TESTS(1, CRL_VALUE_PUSH);
        is(crl_parse_expression(&source, NULL), CRL_ERROR, "Allocation failure expanding stack for RHS of OR");
        MOCKFAIL_END_TESTS();

        crl_parse_finalize_thread();    // Next crl_value_push will reinitialize crl-parse
    }

    diag("coverage for crl.c");
    {
        struct crl_value mock_value;

        mock_value.type = CRL_TYPE_MAX + 1;
        is(crl_value_test(&mock_value), CRL_TEST_ERROR, "Can't test a value with a bogus type");

        test_source_init(&source, line1, sizeof(line1), "file", 1, "x:=");
        is(crl_new_attributes(&source), NULL, "':=' must be followed by an expression");

        test_source_init(&source, line1, sizeof(line1), "file", 1, "attr := 0");
        MOCKFAIL_START_TESTS(1, CRL_VALUE_DUP);
        is(crl_new_attributes(&source), NULL, "Allocation failure duplicating attributes");
        MOCKFAIL_END_TESTS();

        test_source_init(&source, line1, sizeof(line1), "file", 1, "x AND (");
        is(crl_new_expression(&source),  NULL, "Failed to construct a conjuction with an invalid RHS");

        test_source_init(&source, line1, sizeof(line1), "file", 1, "x AND y");
        MOCKFAIL_START_TESTS(1, CRL_VALUE_DUP);
        is(crl_new_expression(&source), NULL, "Allocation failure duplicating expression");
        MOCKFAIL_END_TESTS();

        is(test_value_test("\"string\" = 1"),            CRL_TEST_ERROR, "Comparing a string to a number returns false");
        is(test_value_test("{\"m\": 0} = {\"m\": 0}"),   CRL_TEST_ERROR, "Can't compare objects (yet?)");
        is(test_value_test("LENGTH \"x\" = LENGTH [1]"), CRL_TEST_TRUE,  "Compared evaluated values to make sure they're freed when done");

        is(json_value_test(object = cJSON_CreateRaw("raw")), CRL_TEST_ERROR, "Test of RAW JSON is not supported");
        cJSON_Delete(object);

        is(test_value_test("1"),                CRL_TEST_TRUE,  "Test a non-zero number is true");
        is(test_value_test("0"),                CRL_TEST_FALSE, "Test zero is false");
        is(test_value_test("\"string\""),       CRL_TEST_TRUE,  "Test a non-empty string is true");
        is(test_value_test("\"\""),             CRL_TEST_FALSE, "Test the empty string is false");
        is(test_value_test("endpoint.os.type"), CRL_TEST_TRUE,  "Test that a valid identifier whose value is true is true");
        is(test_value_test("not.a.valid.id"),   CRL_TEST_ERROR, "Test an invalid identifier is an error");

        test_source_init(&source, line1, sizeof(line1), "file", 1, "attr := 0");
        value = crl_new_attributes(&source);
        is(crl_value_test(value), 1, "Test a non-empty attribute set is true");
        crl_value_free(value);
        test_source_init(&source, line1, sizeof(line1), "file", 1, "");
        value = crl_new_attributes(&source);
        is(crl_value_test(value), 0, "Test an empty attribute set is false");
        crl_value_free(value);

        is(test_value_test("1 IN []"),             CRL_TEST_FALSE, "Inclusion in an empty list fails");
        is(test_value_test("1 IN 1"),              CRL_TEST_ERROR, "Inclusion in a number is an error");
        is(test_value_test("invalid.id AND true"), CRL_TEST_ERROR, "A conjunction with an invalid identifier on the LHS is an error");
        is(test_value_test("true AND invalid.id"), CRL_TEST_ERROR, "A conjunction with an invalid identifier on the RHS is an error");
        is(test_value_test("LENGTH endpoint.os.type AND true"), 1,
           "Test that a conjunction with an evaluated expression on the LHS doesn't leak memory");
        is(test_value_test("x FIND y = z"), CRL_TEST_ERROR, "FIND can't (yet) be tested");
        is(test_value_test("LENGTH \"\" IN ([{\"m\": [0]}] FIND m)[0][\"m\"]"), CRL_TEST_TRUE,
           "Test inclusion with evaluated expressions to make sure they're freed");

        test_source_init(&source, line1, sizeof(line1), "file", 1, "attr := 0");
        value = crl_new_attributes(&source);
        ok(!crl_value_eval(value, &is_alloced), "Can't evaluate an attr set to JSON");
        crl_value_free(value);

        ok(!test_value_eval("invalid.id FIND true", &is_alloced), "Failing to evaluate LHS of FIND fails the whole eval");
        ok(!test_value_eval("0 FIND true",          &is_alloced), "LHS of FIND must be an array (for now)");
        ok(!test_value_eval("[0] FIND true",        &is_alloced), "LHS of FIND must be an array of objects (for now)");
        ok(!test_value_eval("[{}] FIND invalid.id", &is_alloced), "Error in RHS of FIND results in an error");

        ok(array = test_value_eval("[] FIND true",  &is_alloced), "FIND in an empty array succeeds");
        ok(is_alloced,                                            "FIND result is allocated");
        ok(cJSON_IsArray(array),                                  "FIND result is an array");
        is(cJSON_GetArraySize(array), 0,                          "FIND in an empty array is an empty array");
        cJSON_Delete(array);

        MOCKFAIL_START_TESTS(1, CRL_VALUE_CREATE_ARRAY);
        ok(!test_value_eval("[{\"m\": 1}] FIND m", &is_alloced),  "Failure to create an array fails FIND");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(1, CRL_VALUE_CREATE_REFERENCE);
        ok(!test_value_eval("[{\"m\": 1}] FIND m", &is_alloced),  "Failure to create an object reference fails FIND");
        MOCKFAIL_END_TESTS();

        ok(object = test_value_eval("([{\"m\": 1}] FIND m) FIND m", &is_alloced),
           "Successfully found an object with a true member, finding in the found sublist to verify no memory leaks");
        ok(is_alloced, "Resulting sublist is allocated");
        cJSON_Delete(object);

        ok(!test_value_eval("LENGTH 0", &is_alloced),                     "Can't take the length of a number");

        ok(object = test_value_eval("LENGTH ([{\"m\": 1}] FIND m)", &is_alloced),
           "Taking the length of a generated list, the list is freed");
        cJSON_Delete(object);

        MOCKFAIL_START_TESTS(1, CRL_VALUE_CREATE_NUMBER);
        ok(!test_value_eval("LENGTH \"\"", &is_alloced), "Failure to create a JSON number fails LENGTH");
        MOCKFAIL_END_TESTS();

        ok(!test_value_eval("invalid.id[0]",     &is_alloced), "Failing to evaluate subscripted invalid identifier");
        ok(!test_value_eval("[][\"m\"]",         &is_alloced), "Can't use a string as an array subscript");
        ok(!test_value_eval("[][0]",             &is_alloced), "Invalid subscript");
        ok(!test_value_eval("{\"m\": 1}[0]",     &is_alloced), "Can't use a number as a member name");
        ok(!test_value_eval("{\"m\": 1}[\"n\"]", &is_alloced), "Failing to evaluate subscripted invalid identifier");
        ok(!test_value_eval("0[0]",              &is_alloced), "Failing to evaluate subscripted integer");

        ok(object = test_value_eval("([{\"m\": 1}] FIND m)[LENGTH \"\"]", &is_alloced),
           "Make sure dynamic expression don't leak memory");
        is(object->type, cJSON_Object, "Returned JSON value is an object");
        ok(is_alloced,                 "Returned JSON value was allocated");
        cJSON_Delete(object);

        MOCKFAIL_START_TESTS(1, CRL_VALUE_CJSON_DUPLICATE);
        ok(!test_value_eval("([{\"m\": 1}] FIND m)[LENGTH \"\"]", &is_alloced), "Failed to duplicate subscripted element");
        MOCKFAIL_END_TESTS();

        test_source_init(&source, line1, sizeof(line1), "file", 1, "attr := 0");
        attrs = crl_new_attributes(&source);
        ok(evals = crl_attributes_eval(attrs, &is_alloced), "Evaluated simple attributes");
        is(attrs, evals, "When there are no expressions requiring evaluation, just get the attributes back");
        ok(!is_alloced,  "This doesn't require memory be allocated");
        crl_value_free(attrs);

        MOCKFAIL_START_TESTS(1, CRL_VALUE_ATTRIBUTES_EVAL);
        ok(!test_attributes_eval("attr := endpoint.os.type", &is_alloced), "Failed to allocate evaluated attributes");
        MOCKFAIL_END_TESTS();

        ok(evals = test_attributes_eval("x := 1, y := LENGTH endpoint.os.type, z := endpoint.os.type", &is_alloced),
           "Evaluated attributes");
        ok(is_alloced,                          "Evaluated attribute set is allocated");
        ok(evals[2].type & CRL_IS_REFERENCE,    "Constant 1st attribute is a reference");
        ok(!(evals[4].type & CRL_IS_REFERENCE), "Evaluated 2nd attribute is a not a reference");
        crl_value_free(evals);

        ok(!test_attributes_eval("x := invalid.id", &is_alloced), "Failed to evaluate attributes with a bad reference");
    }

    diag("Tests for intersection");
    {
        test_source_init(&source, line2, sizeof(line2), "file", 2, "[] INTERSECT []");
        ok(value = crl_new_expression(&source),   "Successfully parsed INTERSECT of two empty arrays");
        is(crl_value_test(value), CRL_TEST_FALSE, "The intersection is empty and so tests false");
        crl_value_free(value);

        test_source_init(&source, line2, sizeof(line2), "file", 2, "[1, 2, 3] INTERSECT [4, 2, 0]");
        ok(value = crl_new_expression(&source),  "Successfully parsed INTERSECT of two numeric arrays");
        is(crl_value_test(value), CRL_TEST_TRUE, "The intersection is non-empty and so tests passed");
        crl_value_free(value);

        test_source_init(&source, line2, sizeof(line2), "file", 2, "[[]] INTERSECT [[]]");
        ok(value = crl_new_expression(&source),  "Successfully parsed INTERSECT of two arrays of arrays");
        is(crl_value_test(value), CRL_TEST_TRUE, "The intersection is non-empty and so tests passed");
        crl_value_free(value);

        is(test_value_test("invalid.id INTERSECT []"), CRL_TEST_ERROR, "Error INTERSECTing with invalid identifier on the LHS");
        is(test_value_test("0 INTERSECT []"),          CRL_TEST_ERROR, "Error INTERSECTing with a number on the LHS");
        is(test_value_test("[] INTERSECT 0"),          CRL_TEST_ERROR, "Error INTERSECTing with a number on the RHS");
        is(test_value_test("[1] INTERSECT [[]]"),      CRL_TEST_ERROR,
           "Error INTERSECTing: can't compare arrays whose elements can't be compared");
        is(test_value_test("([1] INTERSECT [1]) INTERSECT ([1] INTERSECT [1])"), CRL_TEST_TRUE,
           "Intersect evaluated values to make sure they're freed when done");

        test_fail_malloc_after(1);
        test_source_init(&source, line1, sizeof(line1), "file", 1, "[] INTERSECT []");
        MOCKFAIL_START_TESTS(1, CRL_VALUE_PUSH);
        is(crl_parse_dyadic_expr(&source, NULL), CRL_ERROR, "Allocation failure expanding stack for RHS of INTERSECT");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(1, CRL_VALUE_CREATE_INTERSECT);
        is(test_value_test("[] INTERSECT []"), CRL_TEST_ERROR, "Error INTERSECTing when allocation of array fails");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(1, CRL_VALUE_CJSON_INTERSECT);
        is(test_value_test("[1] INTERSECT [1]"), CRL_TEST_ERROR, "Error INTERSECTing when allocation of element fails");
        MOCKFAIL_END_TESTS();
    }

    diag("Tests for version 1 support");
    {
        test_source_init(&source, line2, sizeof(line2), "file", 2, "a := 1");
        source.version = CRL_VERSION_SWG;
        is(crl_parse_attributes(&source), CRL_ERROR, "In version 1 CRL attributes, assignments use =");

        test_source_init(&source, line2, sizeof(line2), "file", 2, "e = a[");
        source.version = CRL_VERSION_SWG;
        is(crl_parse_attributes(&source), CRL_ERROR, "In version 1 CRL attributes, RHS must be a valid elementary expression");
    }

#   define IDENT64   "abcdefghijklmnopqrstuvwxyz123456abcdefghijklmnopqrstuvwxyz123456"
#   define IDENT512  IDENT64 IDENT64 IDENT64 IDENT64 IDENT64 IDENT64 IDENT64 IDENT64
#   define IDENT2048 IDENT512 IDENT512 IDENT512 IDENT512

    diag("Cover crl_indentifier_equal_str and crl_value_to_str functions");
    {
        test_source_init(&source, line2, sizeof(line2), "file", 2, "\"string\"");
        ok(value = crl_new_expression(&source),                       "Successfully parsed string");
        is(crl_identifier_equal_str(value, "string"), CRL_TEST_ERROR, "Can't call clr_identifier_equal_str on a string");
        is_eq(crl_value_to_str(value), "CRL Type CRL_TYPE_JSON",      "JSON types are currently unsupported by to_str");
        crl_value_free(value);

        test_source_init(&source, line2, sizeof(line2), "file", 2, "identifier");
        ok(value = crl_new_expression(&source),                       "Successfully parsed identifier");
        is(crl_identifier_equal_str(value, "string"), CRL_TEST_FALSE, "Identifier name is not 'string'");
        is_eq(crl_value_to_str(value), "identifier",                  "Identifier to string works");
        crl_value_free(value);

        const char *str;
        size_t      len;

        test_source_init(&source, line2, sizeof(line2), "file", 2, IDENT2048);
        ok(value = crl_new_expression(&source),                       "Successfully parsed huge identifier");
        is(crl_identifier_equal_str(value, IDENT2048), CRL_TEST_TRUE, "Huge identifier name is correct");
        is(len = strlen(str = crl_value_to_str(value)), 1023,         "to_str truncates it to 1023 characters");
        is_eq(&str[len - 3], "...",                                   "Truncation indicator is present");
        crl_value_free(value);
    }

    diag("Tests for string IN string and OR operator");     // Parentheses force full parsing and evaluation
    {
        is(test_value_test("(\"rin\" IN \"string\")"),   CRL_TEST_TRUE,  "'rin' is IN 'string'");
        is(test_value_test("(\"RIN\" IN \"string\")"),   CRL_TEST_FALSE, "'RIN' is not IN 'string'");
        is(test_value_test("(1 IN  \"string\")"),        CRL_TEST_ERROR, "LHS of IN must be a string if RHS is a string");
        is(test_value_test("(true OR invalid)"),         CRL_TEST_TRUE,  "'true OR invalid' short circuits to true");
        is(test_value_test("(false OR true)"),           CRL_TEST_TRUE,  "'false OR true' is true");
        is(test_value_test("(true OR false AND false)"), CRL_TEST_TRUE,  "'true OR false AND false' is true");
    }

    diag("Tests for number >=|>|<=|<|!= number, string and bool");     // Parentheses force full parsing and evaluation
    {
        is(test_value_test("(1 >= 0)"),          CRL_TEST_TRUE,  "1 >= 0 is true");
        is(test_value_test("(1 >= 1)"),          CRL_TEST_TRUE,  "1 >= 1 is true");
        is(test_value_test("(1 >= 2)"),          CRL_TEST_FALSE, "1 >= 2 is false");
        is(test_value_test("(1 >= \"banana\")"), CRL_TEST_ERROR, "1 >= \"banana\" is an error");
        is(test_value_test("(1 <= 0)"),          CRL_TEST_FALSE, "1 <= 0 is false");
        is(test_value_test("(1 > 1)"),           CRL_TEST_FALSE, "1 > 1 is false");
        is(test_value_test("(1 < 2)"),           CRL_TEST_TRUE,  "1 < 2 is true");
        is(test_value_test("(\"2\" > \"10\")"),  CRL_TEST_TRUE,  "\"2\" > \"10\" is true");
        is(test_value_test("(1 != 2)"),          CRL_TEST_TRUE,  "1 != 2 is true");
        is(test_value_test("(1 != 1)"),          CRL_TEST_FALSE, "1 != 1 is false");
        is(test_value_test("(true != fals""e)"), CRL_TEST_TRUE,  "true != fals""e is true");    // "" added to ignore convention
        is(test_value_test("(true > false)"),    CRL_TEST_ERROR, "true > false is an error");

        test_source_init(&source, line1, sizeof(line1), "file", 1, "(1 !! 1)");
        is(crl_parse_expression(&source, NULL),  CRL_ERROR, "Failed to parse as !! is not a valid operator");
    }

    diag("Test for array comparison");
    {
        is(test_value_test("([] = [])"),       CRL_TEST_TRUE,  "[] = [] is true");
        is(test_value_test("([] = [0])"),      CRL_TEST_FALSE, "[] = [0] is false");
        is(test_value_test("([] < [0])"),      CRL_TEST_TRUE,  "[] < [0] is true");
        is(test_value_test("([0] = [])"),      CRL_TEST_FALSE, "[0] = [] is false");
        is(test_value_test("([0] < [])"),      CRL_TEST_FALSE, "[0] < [] is false");
        is(test_value_test("([0] < [[]])"),    CRL_TEST_ERROR, "[0] < [[]] is an error (elements are incomparable)");
        is(test_value_test("([1,2] < [1,3])"), CRL_TEST_TRUE,  "[1,2] < [1, 3] is true");
    }

    diag("Test for enhanced FIND/WHERE operator");
    {
        test_source_init(&source, line1, sizeof(line1), "file", 1, "([] FIND WHERE x = 1)");
        ok(!crl_new_expression(&source), "Can't parse if variable missing between FIND/WHERE");
        test_source_init(&source, line1, sizeof(line1), "file", 1, "([] FIND 1 WHERE x = 1)");
        ok(!crl_new_expression(&source), "Can't parse if non-variable between FIND/WHERE");

        is(test_value_test("([] FIND x WHERE x = 1)"),  CRL_TEST_FALSE, "Can't find anything in an empty list");
        is(test_value_test("([0] FIND x WHERE x = 1)"), CRL_TEST_FALSE, "Can't find 1 in [0]");
        is(test_value_test("([[8,1,3], [9,2,4], [10,0,3]] FIND x WHERE (x[0] = [9,2,5][0] AND x <= [9,2,5]))"), CRL_TEST_TRUE,
           "Found a version in a list whose major number matches ours and is <= ours");
        is(test_value_test("([[8,1,3], [9,2,4], [10,0,3]] FIND x WHERE (x[0] = [10,0,2][0] AND x <= [10,0,2]))"), CRL_TEST_FALSE,
           "Found a version in a list whose major number matches ours and is > ours");
        is(test_value_test("([[8,1,3], [9,2,4], [10,0,3]] FIND x WHERE (x[0] = [7,25,3][0] AND x <= [7,25,3]))"), CRL_TEST_FALSE,
           "Did not find a version in the list whose major number matches ours");

        MOCKFAIL_START_TESTS(1, CRL_VALUE_CREATE_OBJECT);
        is(test_value_test("([1] FIND x WHERE x = 1)"), CRL_TEST_ERROR, "Error when FIND/WHERE namespace allocation fails");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(1, CRL_VALUE_FIND_DUPLICATE);
        is(test_value_test("([1] FIND x WHERE x = 1)"), CRL_TEST_ERROR, "Error when FIND/WHERE element duplication fails");
        MOCKFAIL_END_TESTS();
    }

    diag("Tests for TIME and '+' operator");
    {
        ok(!test_value_eval("TIME(\"2022-01-29T15:43:42\")", &is_alloced), "TIME(\"stamp\") can't be evaluated");

        MOCKFAIL_START_TESTS(1, CRL_VALUE_CREATE_TIME);
        ok(!test_value_eval("TIME(null)", &is_alloced), "Error when TIME allocation fails");
        MOCKFAIL_END_TESTS();

        ok(object = test_value_eval("TIME(null)", &is_alloced),    "TIME(null) can be evaluated");
        ok(is_alloced,                                             "TIME(null) allocates a cJSON to store the time");
        is(json_get_type(object), cJSON_Number,                    "Times are implemented as numbers");
        ok(fabs(time(NULL) - json_number_get_double(object)) < 2.0,"Time is correct");
        cJSON_Delete(object);

        test_fail_malloc_after(1);
        test_source_init(&source, line1, sizeof(line1), "file", 1, "1 + 1");
        MOCKFAIL_START_TESTS(1, CRL_VALUE_PUSH);
        is(crl_parse_expression(&source, NULL), CRL_ERROR, "Allocation failure expanding stack for RHS of +");
        MOCKFAIL_END_TESTS();

        ok(object = test_value_eval("1 + 1", &is_alloced), "'1 + 1' can be evaluated");
        ok(is_alloced,                                     "'1 + 1' allocates a cJSON to store the sum");
        is(json_get_type(object), cJSON_Number,            "Sums are implemented as numbers");
        ok(json_number_get_double(object) == 2.0,          "'1 + 1' == 2");
        cJSON_Delete(object);

        is(test_value_test("2 = LENGTH \"x\" + LENGTH \"y\""), CRL_TEST_TRUE, "Order of ops is correct, no leaks");

        ok(!test_value_eval("(x + 1)", &is_alloced),   "Left operand of + must be defined");
        ok(!test_value_eval("(1 + x)", &is_alloced),   "Right operand of + must be defined");
        ok(!test_value_eval("\"1\" + 1", &is_alloced), "LHS of + must be a number");
        ok(!test_value_eval("1 + \"1\"", &is_alloced), "RHS of + must be a number");

        MOCKFAIL_START_TESTS(1, CRL_VALUE_CREATE_SUM);
        ok(!test_value_eval("1 + 1", &is_alloced), "Error when SUM allocation fails");
        MOCKFAIL_END_TESTS();
    }

    diag("Tests for IN operator evaluation (i.e. using it as a 'safe get'");
    {
        ok(!test_value_eval("(x IN 1)", &is_alloced),    "Left operand of IN must be defined");
        ok(!test_value_test("((1 IN []) = true)"),       "Failed array membership explicitly evaluated");
        ok(!test_value_eval("(1 IN \"\")", &is_alloced), "Can't test for a number as a substring");
        ok(!test_value_test("((\"x\" IN \"\") = true)"), "Failed string membership explicitly evaluated");
        ok(!test_value_eval("(1 IN 1)", &is_alloced),    "Right operand of IN must be not be a number");

        ok(inner = test_value_eval("\"e\" IN {}", &is_alloced), "Looked for 'e' in {}");
        is(json_get_type(inner), cJSON_NULL,                    "Got a cJSON_NULL");
        ok(!is_alloced,                                         "It wasn't allocated");

        ok(inner = test_value_eval("\"m\" IN \"o\" IN {}", &is_alloced), "Looked for 'm' in 'o' in {}");
        is(json_get_type(inner), cJSON_NULL,                             "Got a cJSON_NULL");
        ok(!is_alloced,                                                  "It wasn't allocated");

        test_source_init(&source, line2, sizeof(line2), "file", 2, "\"v\" IN \"w\" IN {\"w\": {\"v\":10}}");
        ok(value = crl_new_expression(&source),        "Successfully parsed double IN expression");
        ok(inner = crl_value_eval(value, &is_alloced), "Looked for 'v' in 'w' in {'w':{'v':10}}");
        is(json_get_type(inner), cJSON_Number,         "Got a cJSON_Number");
        ok(!is_alloced,                                "It wasn't allocated");
        crl_value_free(value);
    }

    diag("Tests for bug fixes");
    {
        cJSON *ns_object;
        is(test_value_test("LENGTH \"\" AND true"), CRL_TEST_FALSE,
           "Testing a conjunction whose LHS is allocated but false doesn't double free");

        // DPT-1059 - CRL V1 Needs To Allow Uppercase Boolean Values
        is(test_value_test("True"),                           CRL_TEST_ERROR, "Testing a misspelling of 'true' is an error");
        is(test_value_test_version("True",  CRL_VERSION_SWG), CRL_TEST_TRUE,  "Testing 'True' succeeds in SWG version of CRL");
        is(test_value_test_version("False", CRL_VERSION_SWG), CRL_TEST_FALSE, "Testing 'False' succeeds in SWG version of CRL");

        // DPT-1246 - CRL parser segfault (double free) on error (see bug for full offending expression)
        test_source_init(&source, line1, sizeof(line1), "file", 1, "([] FIND x WHERE (x[\"expiry\"] >= TIME AND x))");
        ok(!crl_new_expression(&source), "Successfully failed to parse convoluted expression");

        // DPT-1247 - CRL should support IN for objects and object refs
        inner  = cJSON_CreateString("test.string");
        object = cJSON_CreateObject();
        cJSON_AddItemToObject(object, "test.member", inner);
        ns_object = cJSON_CreateObject();
        cJSON_AddItemReferenceToObject(ns_object, "test.object", object);
        crl_namespace_push_object(&test_namespace, ns_object);
        is(test_value_test("\"test.member\" IN test.object"), CRL_TEST_TRUE,
                           "Found a member in an object that is a reference from the namespace object");
        is(crl_namespace_pop(), &test_namespace, "Popped the test namespace");
        cJSON_Delete(ns_object);
        cJSON_Delete(object);       // This would be a double free if it wasn't added to array as a reference
    }

    crl_parse_finalize_thread();    // This should be called per worker thread
    crl_finalize();
    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    return exit_status();
}
