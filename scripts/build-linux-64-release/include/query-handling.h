#ifndef QUERY_HANDLING_H
#define QUERY_HANDLING_H

/* todo: QUERY_HANDLING_* should be an enum */  /* redirects-to                           */
#define QUERY_HANDLING_APPLICATION      0       /* application.conf.opendns.com           */
#define QUERY_HANDLING_BLOCKED          1       /* blocked.conf.opendns.com               */
#define QUERY_HANDLING_BOTNET           2       /* botnet.conf.opendns.com                */
#define QUERY_HANDLING_BPB              3       /* bpb.conf.opendns.com                   */
#define QUERY_HANDLING_DOMAINTAGGING    4       /* domaintagging.conf.opendns.com         */
#define QUERY_HANDLING_EXPIRED          5       /* -                                      */
#define QUERY_HANDLING_MALWARE          6       /* malware.conf.opendns.com               */
#define QUERY_HANDLING_NORMAL           7       /* -                                      */
#define QUERY_HANDLING_PHISH            8       /* phish.conf.opendns.com                 */
#define QUERY_HANDLING_REFUSED          9       /* -                                      */
#define QUERY_HANDLING_SECURITY        10       /* security.conf.opendns.com              */
#define QUERY_HANDLING_SINKHOLE        11       /* sinkhole.conf.opendns.com              */
#define QUERY_HANDLING_SUSPICIOUS      12       /* suspicious.conf.opendns.com            */
#define QUERY_HANDLING_URL_PROXY       13       /* url-proxy.conf.opendns.com             */
#define QUERY_HANDLING_URL_PROXY_HTTPS 14       /* url-proxy-https.conf.opendns.com       */
#define QUERY_HANDLING_ALLOWLISTED     15       /* -                                      */
#define QUERY_HANDLING_WARN            16       /* -  currently not used by the resolver  */
#define QUERY_HANDLING_MAX             16

#define QUERY_HANDLING_STR_MAXLEN      (sizeof "url-proxy-https" - 1)

#include "query-handling-proto.h"

#endif
