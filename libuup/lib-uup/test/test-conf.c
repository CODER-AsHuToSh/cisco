#include <mockfail.h>
#include <tap.h>

#include "domainlist.h"

int
main(void)
{
    module_conf_t m[5];
    plan_tests(10);

    conf_initialize(".", ".", false, NULL);
    memset(m, '\0', sizeof m);

    MOCKFAIL_START_TESTS(1, conf_register);
    domainlist_register(m + 0, "bob", "bobfile", true);
    ok(!m[0], "Cannot register 'bob' when allocations fail");
    MOCKFAIL_END_TESTS();

    domainlist_register(m, "bob", "bobfile", true);
    is(m[0], 1, "Registered 'bob' as module 1 when allocations work");

    domainlist_register(m + 1, "fred", "fredfile", false);
    is(m[1], 2, "Registered 'fred' as module 2");

    domainlist_register(m + 2, "fred", "fredfile2", false);
    is(m[2], 3, "Registered 'fred' again with a different file name, this time as module 3");

    domainlist_register(m + 3, "fred", "fredfile3", true);
    is(m[3], 0, "Registering 'fred' again as loadable failed");

    domainlist_register(m + 4, "bob", "fredfile2", true);
    is(m[3], 0, "Registering 'bob' again as loadable failed");

    conf_unregister(m[1]);
    m[1] = 0;
    domainlist_register(m + 1, "tom", "tomfile", false);
    is(m[1], 2, "Registered 'tom' as module 2 (re-used)");

    diag("Verify the conf_fn2name function");
    {
        char input[PATH_MAX + 1];
        char output[PATH_MAX];
        const char *result;

        memset(input, 'x', sizeof(input) - 1);
        input[sizeof(input) - 1] = '\0';
        result = conf_fn2name(output, input);

        ok(sizeof(input) > PATH_MAX, "Expects that input is greater than PATH_MAX");
        ok(result == output, "Expects that result and output are the same");
        ok(strlen(output) == PATH_MAX - 1, "Output truncated successfully");
    }

    return exit_status();
}
