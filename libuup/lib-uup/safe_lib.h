/* Mock implementation of safe C library
 */

#include <string.h>

#define EOK 0

typedef int    errno_t;
typedef size_t rsize_t;

static inline errno_t
memcpy_s(void *__restrict__ dest, rsize_t dmax, const void *__restrict__ src, rsize_t n)
{
    (void)dmax;
    memcpy(dest, src, n);
    return EOK;
}

static inline errno_t
memmove_s(void *dest, rsize_t dmax, const void *src, rsize_t n)
{
    (void)dmax;
    memmove(dest, src, n);
    return EOK;
}

#ifndef __FreeBSD__    // FreeBSD includes the following safe_c functions in string.h

static inline errno_t
memset_s(void *s, rsize_t smax, int c, rsize_t n)
{
    (void)smax;
    memset(s, c, n);
    return EOK;
}

#endif
