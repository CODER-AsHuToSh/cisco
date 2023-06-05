#ifndef CATEGORIZATION_H
#define CATEGORIZATION_H

#define CATEGORIZATION_VERSION 1

#include "pref.h"

struct xray;

struct categorization;

enum categorizationtype {
    CATTYPE_NONE,
    CATTYPE_DOMAINTAGGING,
    CATTYPE_DOMAINLIST,
    CATTYPE_EXACT_DOMAINLIST,
    CATTYPE_IPLIST,
    CATTYPE_CIDRLIST,
    CATTYPE_APPLICATION,
};

#include "categorization-proto.h"

#endif
