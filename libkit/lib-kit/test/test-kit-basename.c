#include <sxe-util.h>
#include <string.h>
#include <tap.h>

#include "kit.h"

int
main(int argc, char **argv)
{
    const char *path, *res;

    SXE_UNUSED_PARAMETER(argc);
    SXE_UNUSED_PARAMETER(argv);

    plan_tests(3);

    path = "filename";
    res = kit_basename(path);
    is_eq(path, res, "kit_basename() returns same value for a relative filename");

    path = "path/filename";
    res = kit_basename(path);
    ok(!strcmp(res, "filename"), "kit_basename() returns proper base for a relative path");

    path = "/path/path2/filename";
    res = kit_basename(path);
    ok(!strcmp(res, "filename"), "kit_basename() returns proper base for an absolute path");

    return exit_status();
}
