/*
 * This test mainly for coverage purposes, verifying randomness is impossible.
 * As kit-random is a simplified wrapper for kit-arc4random it is more
 * thoroughly tested in test-kit-arc4random.c.
 */

#include <fcntl.h>
#include <string.h>
#include <tap.h>

#include "kit-random.h"

int
main(void)
{
    int seedfd;

    plan_tests(1);

    ok(seedfd = open("/dev/urandom", O_RDONLY), "Opened seed");

    kit_random_init(seedfd);
    kit_random32();
    kit_random16();
    kit_random8();

    return exit_status();
}
