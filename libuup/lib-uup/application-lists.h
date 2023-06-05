#ifndef APPLICATION_LISTS_H
#define APPLICATION_LISTS_H

#define APPLICATION_VERSION 1

#define LOADFLAGS_APPLICATION_URLS_AS_PROXY  0x01    /* Convert urls to proxy domains */
#define LOADFLAGS_APPLICATION_IGNORE_DOMAINS 0x02    /* Ignore data in the [domains] or [data] section */

#include "conf-info.h"
#include "conf-segment.h"

struct domainlist;
struct urllist;

struct application_lists {
    struct domainlist *dl;
    struct domainlist *pdl;
    struct urllist *ul;
    struct conf_meta *cm;
    struct conf_segment cs;
};

struct conf_loader;

#include "application-lists-proto.h"

#endif
