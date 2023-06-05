#ifndef INFOLOG_H
#define INFOLOG_H

#include "kit-infolog.h"

#define INFOLOG_FLAGS_CLIENT            (1 << 0)  /* 0x00001 */
#define INFOLOG_FLAGS_CONF              (1 << 1)  /* 0x00002 */
#define INFOLOG_FLAGS_CONF_VERBOSE      (1 << 2)  /* 0x00004 */
#define INFOLOG_FLAGS_MALFORMED         (1 << 3)  /* 0x00008 */
#define INFOLOG_FLAGS_XRAY6             (1 << 4)  /* 0x00010 */
#define INFOLOG_FLAGS_XRAY7             (1 << 5)  /* 0x00020 */
#define INFOLOG_FLAGS_VALIDATE_FAIL     (1 << 6)  /* 0x00040 */
#define INFOLOG_FLAGS_VALIDATE_OK       (1 << 7)  /* 0x00080 */
#define INFOLOG_FLAGS_NS_IS_ALIAS       (1 << 8)  /* 0x00100 */
#define INFOLOG_FLAGS_DNAT_CLIENT       (1 << 9)  /* 0x00200 */
#define INFOLOG_FLAGS_WITHOUT_EDNS      (1 << 10) /* 0x00400 */
#define INFOLOG_FLAGS_SECURITY_LOOKUP   (1 << 11) /* 0x00800 */
#define INFOLOG_FLAGS_EDNS_DISABLED     (1 << 12) /* 0x01000 */
#define INFOLOG_FLAGS_MEMORY_GROWTH     (1 << 13) /* 0x02000 */
#define INFOLOG_FLAGS_JEMALLOC_STATS    (1 << 14) /* 0x04000 */
#define INFOLOG_FLAGS_ECS               (1 << 15) /* 0x08000 */
#define INFOLOG_FLAGS_CLOSE_ERROR       (1 << 16) /* 0x10000 */

#define INFOLOG_FLAGS_DEFAULT           INFOLOG_FLAGS_CONF

#endif
