#ifndef XRAY_H
#define XRAY_H

#include <sxe-util.h>

/*-
 * We usually call
 *
 *   * XRAY6(x, ...) to log interesting diagnostics
 *   * XRAY7(x, ...) to log interesting-but-frequent diagnostics
 *
 * If the data exceeds 255 characters, it's truncated.
 * The data can be seen when
 *   * querying from a trusted-network with xray.opendns.com
 *     the data turns up as RRs in the glue section of the response
 *     the data is truncated where our response packet size becomes too big
 *   * Setting xraylog in the options file to include a domain
 *     Queries for that domain and any of its subdomains are sent to the log
 *     The messages are only seen in the log with the appropriate infolog_flags
 *       * 0x10 for INFOLOG_FLAGS_XRAY6
 *       * 0x20 for INFOLOG_FLAGS_XRAY7
 *   * For debug builds
 *     A SXEL6("xray(....)") or SXEL7("xray(....)") message is logged to stdout
 *
 * Sometimes XRAY6() or XRAY7() output needs resources to first calcuate its
 * arguments.  It's therefore possible to split it up:
 *
 *     if (XRAYING(x)) {
 *         char *data = complicated_calculation();
 *         if (data == NULL)
 *             data = something_that_would_be_messy_if_written_inline_in_XRAY6();
 *         xray(x, 6, "%s", data);
 *     }
 *
 * Sometimes data is so interesting that we don't want to truncate it at all.
 * To split data up into multiple XRAY6() calls, use
 *
 *     xray_long_line(x, prefix1, prefix2, ...)
 *
 * where either or both of prefix1 and prefix2 may be NULL if you don't want to
 * prefix the data with a constant string.
 */

#define XRAYING(x)            ((x) && (x)->addr)
#define XRAYING_FOR_CLIENT(x) (XRAYING(x) && xraying_for_client(x))
#define XRAYN(x, n, ...)                 \
    do {                                 \
        if (XRAYING(x))                  \
            xray((x), (n), __VA_ARGS__); \
          else {                         \
            SXEL##n(__VA_ARGS__);        \
        }                                \
    } while (0)
#define XRAY6(x, ...) XRAYN(x, 6, __VA_ARGS__)
#define XRAY7(x, ...) XRAYN(x, 7, __VA_ARGS__)

#define INFOLOGXRAY6(n, x, ...) do { INFOLOG(n, __VA_ARGS__); XRAY6(x, __VA_ARGS__); } while (0)
#define INFOLOGXRAY7(n, x, ...) do { INFOLOG(n, __VA_ARGS__); XRAY7(x, __VA_ARGS__); } while (0)

struct xray {
    uint8_t *addr;
    uint16_t used;
    uint16_t size;
    uint8_t flags;       /* XRAY_FLAG_* - not exposed externally */
};

#include "xray-proto.h"

#endif
