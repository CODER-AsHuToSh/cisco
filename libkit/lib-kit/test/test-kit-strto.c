#include <limits.h>
#include <errno.h>
#include <sxe-util.h>
#include <tap.h>

#include "kit.h"

int
main(int argc, char **argv)
{
    const char *str;
    char *endptr;

    SXE_UNUSED_PARAMETER(argc);
    SXE_UNUSED_PARAMETER(argv);

    plan_tests(50);

    diag("Verify normal valid parsing");
    {
        is(kit_strtoul("12345678", NULL, 10), 12345678, "strtoul parses correctly");
        is(errno, 0, "errno is not set");

        is(kit_strtoull("0", NULL, 0), 0, "strtoull correctly parses 0");
        is(errno, 0, "errno is not set");

        is(kit_strtoull("0x0", NULL, 0), 0, "strtoull correctly parses 0x0");
        is(errno, 0, "errno is not set");

        is(kit_strtoul("  \t  0", NULL, 10), 0, "strtoul correctly parses 0 with leading whitespace");
        is(errno, 0, "errno is not set");

        is(kit_strtoul("-1", NULL, 10), ULONG_MAX, "strtoul correctly parses -1");
        is(errno, 0, "errno is not set");

        is(kit_strtoull("-1", NULL, 10), ULLONG_MAX, "strtoull correctly parses -1");
        is(errno, 0, "errno is not set");

        is(kit_strtol("-0", NULL, 10), 0, "strtol correctly parses -0");
        is(errno, 0, "errno is not set");

        is(kit_strtoll("+0", NULL, 10), 0, "strtoll correctly parses +0");
        is(errno, 0, "errno is not set");

        is(kit_strtod("1.234", NULL), 1.234, "strtod parses correctly");
        is(errno, 0, "errno is not set");

        is(kit_strtod("   0.0000", NULL), 0, "strtod correctly parses 0");
        is(errno, 0, "errno is not set");

        str = "0.0a";
        is(kit_strtod(str, &endptr), 0, "strtod correctly parses 0");
        is(errno, 0, "errno is not set");
        is(str + 3, endptr, "strtod of 0.0a sets endpointer to a");
        is(*endptr, 'a', "strtod of 0.0a sets endpointer to a");
    }

    diag("Verify setting errno for invalid parsing");
    {
        str = "AX0BCWWW";
        is(kit_strtoul(str, &endptr, 10), 0, "invalid decimal value returns zero");
        is(errno, EINVAL, "invalid value sets errno");
        is(str, endptr, "invalid parsing sets endptr=str");

        str = "1234";
        is(kit_strtoul(str, &endptr, 10), 1234, "valid parsing to clear errno");
        is(errno, 0, "errno was cleared after valid parsing");
        is(str + 4, endptr, "valid parsing advanced endptr");

        is(kit_strtoull("0xlooojoiji", NULL, 16), 0, "invalid hex value returns zero");
        is(errno, EINVAL, "invalid value sets errno");

        is(kit_strtoul("    a0", NULL, 10), 0, "invalid decimal value after whitespace");
        is(errno, EINVAL, "invalid value sets errno");

        is(kit_strtoul("   +ostte", NULL, 10), 0, "invalid decimal value after whitespace and +");
        is(errno, EINVAL, "invalid value sets errno");

        is(kit_strtod("asd", NULL), 0, "strtod parsing invalid string");
        is(errno, EINVAL, "invalid value sets errno");

        is(kit_strtoul("xx0", NULL, 0), 0, "xx0 doesn't parse as hex");
        is(errno, EINVAL, "invalid value sets errno");

        is(kit_strtoul("  ++0", NULL, 0), 0, "Multiple +/- doesn't parse");
        is(errno, EINVAL, "invalid value sets errno");

        is(kit_strtoul("0xffffffffffffffff", NULL, 16), ULONG_MAX, "Test for upper bound");
        is(errno, 0, "errno is not set");

        is(kit_strtoul("0x1ffffffffffffffff", NULL, 16), ULONG_MAX, "Test for overflow");
        is(errno, ERANGE, "There was an overflow and errno was set to ERANGE");

        is(kit_strtoull("0xffffffffffffffff", NULL, 16), ULLONG_MAX, "Test for upper bound");
        is(errno, 0, "errno is not set");

        is(kit_strtoull("0x1ffffffffffffffff", NULL, 16), ULLONG_MAX, "Test for overflow");
        is(errno, ERANGE, "There was an overflow and errno was set to ERANGE");
    }

    return exit_status();
}
