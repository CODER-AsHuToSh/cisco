/*
 * Simple and efficient API wrapping arc4random.
 */

#include <limits.h>
#include <sxe-log.h>

#include "kit-random.h"

void
kit_random_init(int seed_fd)
{
    SXEE7("(fd=%d)", seed_fd);
    kit_arc4random_init(seed_fd);
    SXER7("return");
}

uint32_t
kit_random32(void)
{
    return kit_arc4random();
}

uint16_t
kit_random16(void)
{
    static __thread unsigned outleft;
    static __thread uint32_t rnd;

    if (!outleft) {
        rnd = kit_random32();
        outleft = sizeof(rnd) / sizeof(uint16_t);
    }
    outleft--;

    return (uint16_t)(rnd >> (outleft * CHAR_BIT * sizeof(uint16_t)));
}

uint8_t
kit_random8(void)
{
    static __thread unsigned outleft;
    static __thread uint32_t rnd;

    if (!outleft) {
        rnd = kit_random32();
        outleft = sizeof(rnd) / sizeof(uint8_t);
    }
    outleft--;

    return (uint8_t)(rnd >> (outleft * CHAR_BIT * sizeof(uint8_t)));
}
