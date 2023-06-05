#ifndef CCB_H
#define CCB_H

#include "conf.h"
#include "pref-categories.h"
#include "query-handling.h"

#define CCB_VERSION     2

/* Special handling priorities for proxy offloads - these share a namespace with QUERY_HANDLING_* */
#define CCB_HANDLING_PROXY_ALLOWAPP             (QUERY_HANDLING_MAX + 1)
#define CCB_HANDLING_PROXY_BLOCKAPP             (QUERY_HANDLING_MAX + 2)
#define CCB_HANDLING_PROXY_NSD                  (QUERY_HANDLING_MAX + 3)
#define CCB_HANDLING_PROXY_URL_PROXY            (QUERY_HANDLING_MAX + 4)
#define CCB_HANDLING_PROXY_URL_PROXY_HTTPS      (QUERY_HANDLING_MAX + 5)
#define CCB_HANDLING_PROXY_ORG_BLOCK_GREYLIST   (QUERY_HANDLING_MAX + 6)

enum ccb_parse_result {
    CCB_PARSE_OK,
    CCB_PARSE_EOF,
    CCB_PARSE_FAIL,
};

struct ccb;

extern module_conf_t CONF_CCB;
extern const unsigned ccb_handling_entries; /* # handling codes in ccb_handling */

#include "ccb-proto.h"

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define CCB_PREF_CATEGORIES_STR        ((const char *)ccb_pref_categories_str + 0)
#   define CCB_PREF_CATEGORIES_STR_EXTEND ((const char *)ccb_pref_categories_str + 1)
#   define CCB_PARSE_CATEGORY             ((const char *)ccb_pref_categories_str + 2)
#   define CCB_CREATE                     ((const char *)ccb_pref_categories_str + 3)
#   define CCB_CREATE_BITMAP              ((const char *)ccb_pref_categories_str + 4)
#endif

#endif
