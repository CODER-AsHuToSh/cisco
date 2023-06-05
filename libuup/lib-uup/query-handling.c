#include <stdint.h>
#include <sxe-log.h>

#if SXE_DEBUG
#include <string.h>
#endif

#include "query-handling.h"

static void      (*volatile ccb_update)(int generation) = NULL;
static __thread int         ccb_generation              = 0;
static __thread const char *allowlisted_txt             = NULL;

void
query_handling_set_allowlisted_txt(void (*update), int generation, const char *text)
{
    ccb_update      = update;
    ccb_generation  = generation;
    allowlisted_txt = text;
}

const uint8_t *
query_handling_label(int handling)
{
    /*
     * This function lists all of the possible lander name prefixes.
     * Non-lander handling strings are returned from query_handling_str().
     */
    switch (handling) {
    case QUERY_HANDLING_APPLICATION:     return (const uint8_t *)"\13application";
    case QUERY_HANDLING_BLOCKED:         return (const uint8_t *)"\7blocked";
    case QUERY_HANDLING_BOTNET:          return (const uint8_t *)"\6botnet";
    case QUERY_HANDLING_BPB:             return (const uint8_t *)"\3bpb";
    case QUERY_HANDLING_DOMAINTAGGING:   return (const uint8_t *)"\15domaintagging";
    case QUERY_HANDLING_MALWARE:         return (const uint8_t *)"\7malware";
    case QUERY_HANDLING_PHISH:           return (const uint8_t *)"\5phish";
    case QUERY_HANDLING_SECURITY:        return (const uint8_t *)"\10security";
    case QUERY_HANDLING_SINKHOLE:        return (const uint8_t *)"\10sinkhole";
    case QUERY_HANDLING_SUSPICIOUS:      return (const uint8_t *)"\12suspicious";
    case QUERY_HANDLING_URL_PROXY:       return (const uint8_t *)"\11url-proxy";
    case QUERY_HANDLING_URL_PROXY_HTTPS: return (const uint8_t *)"\17url-proxy-https";
    }

    return NULL;
}

const char *
query_handling_str(int handling)
{
    const uint8_t *label;
    const char *ret = "unknown";

    if ((label = query_handling_label(handling)) != NULL) {
        SXEA6(label[label[0] + 1] == '\0', "query_handling_label(%d) does not return a single-component label", handling);
        ret = (const char *)label + 1;

        switch (handling) {
        case QUERY_HANDLING_URL_PROXY:
            ret = "url-proxy";
            break;
        case QUERY_HANDLING_URL_PROXY_HTTPS:
            ret = "url-proxy-https";
            break;
        }
    }
    else    /* If it's not a handling label (lander), it may be one of these pseudo handling strings */
        switch (handling) {
        case QUERY_HANDLING_EXPIRED:
            ret = "expired";
            break;
        case QUERY_HANDLING_NORMAL:
            ret = "normal";
            break;
        case QUERY_HANDLING_REFUSED:
            ret = "refused";
            break;
        case QUERY_HANDLING_ALLOWLISTED:
            if (ccb_update)
                ccb_update(ccb_generation);

            ret = allowlisted_txt ?: "allowlisted";
            break;
        case QUERY_HANDLING_WARN:
            ret = "warn";
            break;
        }

    SXEA6(strlen(ret) <= QUERY_HANDLING_STR_MAXLEN, "Handling string \"%s\" is too long (max %zu) - Client ID handling will be upset",
          ret, QUERY_HANDLING_STR_MAXLEN);
    return ret;
}

