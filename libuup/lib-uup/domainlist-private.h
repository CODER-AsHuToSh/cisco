#ifndef DOMAINLIST_PRIVATE_H
#define DOMAINLIST_PRIVATE_H

#include "domainlist.h"

#define DOMAINLIST_CACHE_INITIAL_STR_SIZE 100U
#define DOMAINLIST_NAME_OFFSET(dl, i) (                     \
    (dl)->name_offset_size == 1 ? (dl)->name_offset_08[i] : \
    (dl)->name_offset_size == 2 ? (dl)->name_offset_16[i] : \
    (dl)->name_offset_32[i]                                 \
)

/*
 * - as of Dec 2012 there are ~ 500k unique name_bundles with lengths falling into the following groups:
 *  - domainlists which need an 8 bit offset: 447666 containing 2406103 domains // saves 16842721 bytes versus 64 bit pointer
 *  - domainlists which need a 16 bit offset:  67986 containing 3329229 domains // saves 19975374 bytes versus 64 bit pointer
 *  - domainlists which need a 32 bit offset:     75 containing 1332404 domains // saves  5329616 bytes versus 64 bit pointer
 * - we save ~ 40 MB RAM by making name_offset[] an array of 1, 2, or 4 byte sized offsets instead of pointers
 * - the longest list is about 105k names but that is probably a (dynamic ip updater?) bug
 */

struct domainlist {
    struct conf   conf;
    char         *name_bundle;          /* list of sorted reversed domains as one long string */
    unsigned      name_bundle_len;      /* length of name_bundle                              */
    int           name_amount;          /* amount of offsets in name_offset[]                 */
    union {                             /* individual domain offsets into name_bundle         */
        void     *name_offset;
        uint8_t  *name_offset_08;
        uint16_t *name_offset_16;
        uint32_t *name_offset_32;
    };
    struct object_hash *oh;             /* This object is a member of this hash               */
    uint8_t name_offset_size;           /* size (in bytes) of offsets in name_offset[]        */
    uint8_t exact;                      /* How were we loaded?                                */
    uint8_t fingerprint[];              /* Only the object hash (oh) knows the length!        */
};

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define DOMAINLIST_NEW_FROM_BUFFER ((const char *)domainlist_new_from_buffer + 0)
#   define DOMAINLIST_PARSE           ((const char *)domainlist_new_from_buffer + 1)
#   define DOMAINLIST_NEW_INDEX       ((const char *)domainlist_new_from_buffer + 2)
#endif

#endif
