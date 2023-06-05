#include <kit-alloc.h>
#include <mockfail.h>
#include <string.h>

#if SXE_DEBUG
#include <kit-bool.h>
#endif

#include "infolog.h"
#include "xray.h"

#define XRAY_FLAG_NONE   0x00
#define XRAY_FLAG_CLIENT 0x01
#define XRAY_FLAG_LOG    0x02

static bool
xray_init(struct xray *x, uint16_t size, uint8_t flags)
{
    SXEA6(size, "Expected a size, got 0");

    if (x->addr && size > x->size)
        SXEL7("Attempted to re-init to a larger size - ignored");
    else if (x->addr == NULL && (x->addr = MOCKFAIL(xray_init_for_client, NULL, kit_malloc(size))) == NULL)
        SXEL2("Couldn't allocate %u xray bytes", size);
    else {
        x->used = 0;
        if (x->size < size)
            x->size = size;
        x->flags |= flags;
    }

    SXEL7("%s(x=?, size=%u, flags=%u){} // result %s, addr=%p, flags=%u", __FUNCTION__, size, flags, kit_bool_to_str(size <= x->size), x->addr, x->flags);
    return size <= x->size;
}

bool
xray_init_for_client(struct xray *x, uint16_t size)
{
    SXEA6(x->addr == NULL, "Internal error: Expected NULL but %p=x->addr", x->addr);
    return xray_init(x, size, XRAY_FLAG_CLIENT);
}

void
xray_fini_for_client(struct xray *x)
{
    x->used = 0;
    x->flags &= ~XRAY_FLAG_CLIENT;
    if (x->flags == XRAY_FLAG_NONE)
        xray_fini(x);
}

bool
xraying_for_client(const struct xray *x)
{
    return x && x->addr && x->flags & XRAY_FLAG_CLIENT;
}

bool
xray_init_for_log(struct xray *x)
{
    return xray_init(x, 257, XRAY_FLAG_LOG);
}

void
xray_fini(struct xray *x)
{
    SXEL7("%s(x=?){} // addr=%p", __FUNCTION__, x->addr);
    kit_free(x->addr);
    x->addr = NULL;
    x->size = 0;
    x->used = 0;
    x->flags = XRAY_FLAG_NONE;
}

#define INFOLOGXRAY(n, ...) do { if ((n) == 6) INFOLOG(XRAY6, __VA_ARGS__); else INFOLOG(XRAY7, __VA_ARGS__); } while (0)
#define        SXEL(n, ...) do { if ((n) == 6)          SXEL6(__VA_ARGS__); else          SXEL7(__VA_ARGS__); } while (0)

/* Lines are appended into a fixed size buffer */
__printflike(3, 4) void
xray(struct xray *x, unsigned n, const char *fmt, ...)
{
    int len, maxsz;
    va_list ap;

    if (x && x->addr && x->size > x->used + 1) {
        maxsz = x->size - x->used - 1;
        maxsz = maxsz > 256 ? 256 : maxsz;    /* line is max 256 characters (including NUL) */

        va_start(ap, fmt);
        len = vsnprintf((char *)x->addr + 1 + x->used, maxsz, fmt, ap);
        va_end(ap);
        if (len >= maxsz)
            len = maxsz - 1;

        if (x->flags & XRAY_FLAG_LOG)
            INFOLOGXRAY(n, "XRAY%d: %.*s", n, len, x->addr + 1 + x->used);
        SXEL(n, "xray('%.*s'){} // appending 1+%u bytes @ offset %u", len, (char *)x->addr + 1 + x->used, len, x->used);
        if (x->flags & XRAY_FLAG_CLIENT) {
            x->addr[x->used] = len;
            x->used += 1 + len;
        }
    }
}

void
xray_long_line(struct xray *x, const char *prefix1, const char *prefix2, const char *data)
{
    int allowed, len, p1len, p2len, skip, total;

    total = strlen(data);
    p1len = prefix1 ? strlen(prefix1) : 0;
    p2len = prefix2 ? strlen(prefix2) : 0;

    while (p1len >= 255) {
        XRAY6(x, "%.*s", 255, prefix1);
        prefix1 += 255;
        p1len -= 255;
    }
    if (p1len + p2len >= 255) {
        XRAY6(x, "%s%.*s", prefix1, 255 - p1len, prefix2);
        prefix2 += 255 - p1len;
        p2len -= 255 - p1len;
        prefix1 = NULL;
        p1len = 0;
        while (p2len >= 255) {
            XRAY6(x, "%.*s", 255, prefix2);
            prefix2 += 255;
            p2len -= 255;
        }
    }

    allowed = 255 - p1len - p2len;

    while (total > 0) {
        len = allowed;
        if (total > len)
            while (len && data[len - 1] != ',')
                len--;
        skip = len ? 1 : 0;
        if (!len)
            len = allowed;
        XRAY6(x, "%s%s%.*s", prefix1 ? prefix1 : "", prefix2 ? prefix2 : "", len, data);
        total -= len + skip;
        data += len + skip;
        if (!prefix1 || strcmp(prefix1, "+ ") != 0 || prefix2) {
            prefix2 = NULL;
            allowed = 255 - strlen(prefix1 = "+ ");
        }
    }
}
