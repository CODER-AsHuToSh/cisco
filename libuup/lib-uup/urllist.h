#ifndef URLLIST_H
#define URLLIST_H

struct conf_type;
struct object_fingerprint;

#define LOADFLAGS_UL_LINEFEED_REQUIRED  0x01    /* Input must be linefeed delimited (input from file) */
#define LOADFLAGS_UL_ALLOW_EMPTY_LISTS  0x02    /* Don't return NULL on empty list */
#define LOADFLAGS_UL_STRICT             0x04    /* Fail on normalize failure/overflow */

#include "urllist-proto.h"

#endif
