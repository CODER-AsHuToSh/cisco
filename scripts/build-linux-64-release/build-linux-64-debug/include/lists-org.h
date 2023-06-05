#ifndef LISTS_LISTS_H
#define LISTS_LISTS_H

#define LISTS_VERSION 1

// For now, there are no loadflags for lists

#include "conf-segment.h"
#include "pref.h"

struct domainlist;
struct urllist;

struct lists_org {
    struct preflist    *lists;    // Array of preflists
    unsigned            count;    // Number of preflists
    struct conf_meta   *cm;
    struct conf_segment cs;
};

struct conf_loader;

#include "lists-org-proto.h"

#endif
