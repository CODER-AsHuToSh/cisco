#ifndef SITEPREFS_H
#define SITEPREFS_H

struct odns;
struct oolist;

#define SITEPREFS_VERSION 12

enum siteprefs_type {
    SITEPREFS_KEY_TYPE1 = 1,
    SITEPREFS_KEY_TYPE2 = 2
};

extern module_conf_t CONF_SITEPREFS;

#include "siteprefs-proto.h"

#endif
