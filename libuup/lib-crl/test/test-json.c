#include <kit-alloc.h>
#include <tap.h>

#include "common-test.h"
#include "json.h"

int
main(void)
{
    cJSON   *object;
    uint64_t start_allocations;

    plan_tests(9);

    kit_memory_initialize(false);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");
    // KIT_ALLOC_SET_LOG(1);    // Turn off when done

    json_initialize();
    ok(json_builtins,  "Initialized json builtins");
    json_initialize();
    json_finalize();
    ok(json_builtins,  "JSON builtins are still there");

    cJSON *json_true         = cJSON_CreateTrue();
    cJSON *json_false        = cJSON_CreateFalse();
    cJSON *json_builtin_true = cJSON_GetObjectItem(json_builtins, "true");

    is(json_value_compare(json_true, json_builtin_true, CRL_TYPE_EQUALS, NULL), CRL_TEST_TRUE,  "true is true");
    is(json_value_compare(json_true, json_false,        CRL_TYPE_EQUALS, NULL), CRL_TEST_FALSE, "true is not false");

    is_eq(json_to_str(NULL), "NULL", "NULL JSON object pointer converts to string 'NULL'");
    object = cJSON_CreateNull();
    is_eq(json_to_str(object), "null", "JSON null object converts to string 'null'");
    cJSON_Delete(object);

    json_finalize();
    ok(!json_builtins, "JSON builtins are gone");

    cJSON_Delete(json_false);
    cJSON_Delete(json_true);
    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    return exit_status();
}
