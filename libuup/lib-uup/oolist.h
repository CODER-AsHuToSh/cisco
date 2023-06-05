#ifndef OOLIST_H
#define OOLIST_H

/*
 * Maintain a short list of originids
 * Duplicates are ignored
 * Zeros are ignored
 */

#include <stdbool.h>
#include <stdint.h>

#include "pref.h"

// Flags for oolist_to_buf
#define OOLIST_IN_HEX   0x01
#define OOLIST_NO_ORGS  0x02
#define OOLIST_COMPLETE 0x04

// Flags used by oolist_add to indicate the presence of multiple orgs
#define OOLIST_FLAGS_NONE             0x00
#define OOLIST_FLAGS_MULTIPLE_ORGS    0x01

enum origin_src {
    ORIGIN_SRC_NO_MATCH = 0,
    ORIGIN_SRC_NETWORK,
    ORIGIN_SRC_NETWORK_SWG,
    ORIGIN_SRC_SITE,
    ORIGIN_SRC_DEVICE,
    ORIGIN_SRC_AD_ORG,
    ORIGIN_SRC_AD_USER,
    ORIGIN_SRC_AD_HOST,
    ORIGIN_SRC_AD_ALTUID,
    ORIGIN_SRC_AD_VA,
};

struct oolist_entry {
    uint32_t org;
    uint32_t origin;
    uint32_t origintype;
    uint32_t retention;
    uint32_t parent;
    enum origin_src src;
};

struct oolist;

#include "oolist-proto.h"

/* Note, NULL is valid -- the empty list */
static inline struct oolist *oolist_new(void) { return NULL; }

static inline const char *
oolist_to_buf_hex(const struct oolist *list, char *buf, size_t bufsz)
{
    return oolist_to_buf(list, buf, bufsz, NULL, OOLIST_IN_HEX);
}

static inline const char *
oolist_origins_to_buf_hex(const struct oolist *list, char *buf, size_t bufsz)
{
    return oolist_to_buf(list, buf, bufsz, NULL, OOLIST_IN_HEX | OOLIST_NO_ORGS);
}

static inline const char *
oolist_origins_to_buf(const struct oolist *list, char *buf, size_t bufsz)
{
    return oolist_to_buf(list, buf, bufsz, NULL, OOLIST_COMPLETE);
}

#endif
