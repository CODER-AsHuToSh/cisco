#include <sxe-util.h>
#include <string.h>
#include <tap.h>

#include "kit.h"

int
main(int argc, char **argv)
{
    const char *dot, *host;
    unsigned dots;

    SXE_UNUSED_PARAMETER(argc);
    SXE_UNUSED_PARAMETER(argv);

    plan_tests(3);

    host = kit_hostname();
    ok(host, "kit_hostname() returns some name ('%s')", host ?: "NULL");

    host = kit_short_hostname();
    ok(host, "kit_short_hostname() returns some name ('%s')", host ?: "NULL");

    for (dots = 0; (dot = strchr(host, '.')) != NULL; host = dot + 1, dots++)
        ;
    ok(dots < 2, "The short hostname contains less than two dots");

    return exit_status();
}
