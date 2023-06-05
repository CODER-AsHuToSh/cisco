#include <sxe-util.h>
#include <tap.h>

#include "kit.h"

int
main(int argc, char **argv)
{
    int64_t nsec1, nsec2;
    int32_t sec1, sec2;

    SXE_UNUSED_PARAMETER(argc);
    SXE_UNUSED_PARAMETER(argv);

    plan_tests(10);

    is_eq(kit_clocktype(), "monotonic", "We're using a monotonic clock");

    diag("See time cached");
    {
        kit_time_cached_update();
        ok(sec1 = kit_time_cached_sec(), "kit_time_cached_sec() returns seconds");
        usleep(100);
        is(sec2 = kit_time_cached_sec(), sec1, "kit_time_cached_sec() returns the same value multiple times");

        nsec1 = kit_time_cached_nsec();
        usleep(100);
        is(nsec2 = kit_time_cached_nsec(), nsec1, "kit_time_cached_nsec() returns the same value multiple times");
    }

    diag("See time change");
    {
        usleep(1000000);
        kit_time_cached_update();
        isnt(sec2 = kit_time_cached_sec(), sec1, "kit_time_cached_sec() returns a different value after an update");
        isnt(nsec2 = kit_time_cached_nsec(), nsec1, "kit_time_cached_nsec() returns a different value after an update");
    }

    diag("See time half-change");
    {
        usleep(1000000);
        sec1 = kit_time_sec();
        nsec1 = kit_time_nsec();

        isnt(sec1, sec2, "kit_time_sec() returns a different value when time passes");
        isnt(nsec1, nsec2, "kit_time_nsec() returns a different value when time passes");

        is(kit_time_cached_sec(), sec2, "kit_time_cached_sec() returns the same value - not updated");
        is(kit_time_cached_nsec(), nsec2, "kit_time_cached_nsec() returns the same value - not updated");
    }

    return exit_status();
}
