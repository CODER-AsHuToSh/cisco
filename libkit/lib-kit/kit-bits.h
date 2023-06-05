// Kit bit masks are weird in that bit 0 is stored as 0x80 in the first byte of the bit mask. This is done so that they can
// store network byte ordered subnet masks. Subnet mask /25 is stored as 0xFF, 0xFF, 0FF, 0x80.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kit-bits-proto.h"

static inline void
kit_bits_set(void *me, size_t i)
{

    ((uint8_t *)me)[i / 8] |= 1 << (7 - i % 8);
}

static inline void
kit_bits_clear(void *me, size_t i)
{
    ((uint8_t *)me)[i / 8] &= ~(1 << (7 - i % 8));
}

static inline bool
kit_bits_isset(const void *me, size_t i)
{
    return (((const uint8_t *)me)[i / 8] & (1 << (7 - i % 8))) != 0;
}
