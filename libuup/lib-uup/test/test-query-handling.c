#include <string.h>
#include <tap.h>

#include "conf.h"
#include "query-handling.h"

static int test_generation = 0;

static void
test_update(int generation)
{
    is(generation, 0, "Generation is as expected");
    query_handling_set_allowlisted_txt(test_update, 1, "allowlisted");
    test_generation = 1;
}

int
main(void)
{
    const char *txt;
    int i;

    plan_tests(QUERY_HANDLING_MAX + 8);
    conf_initialize(".", ".", false, NULL);

    for (i = 0; i <= QUERY_HANDLING_MAX; i++) {
        txt = query_handling_str(i);
        ok(strcmp(txt, "unknown") != 0, "Found handling text for id %d", i);
    }

    txt = query_handling_str(i);
    is_eq(txt, "unknown", "Got 'unknown' handling text for id %d", i);

    txt = query_handling_str(QUERY_HANDLING_MAX + 1);
    is_eq(txt, "unknown", "Got 'unknown' handling text for id %d", QUERY_HANDLING_MAX + 1);

    is_eq(query_handling_str(QUERY_HANDLING_ALLOWLISTED), "allowlisted", "Correct default string for ALLOWLISTED");
    query_handling_set_allowlisted_txt(NULL, 0, "whitelisted");
    is_eq(query_handling_str(QUERY_HANDLING_ALLOWLISTED), "whitelisted", "Correct overridden string for ALLOWLISTED");
    query_handling_set_allowlisted_txt(test_update, 0, "whitelisted");
    is_eq(query_handling_str(QUERY_HANDLING_ALLOWLISTED), "allowlisted", "Correct updated string for ALLOWLISTED");
    is(test_generation, 1,                                               "Generation updated as expected");
    return exit_status();
}
