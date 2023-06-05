#ifndef DIRPREFS_ORG_H
#define DIRPREFS_ORG_H

#include "oolist.h"
#include "prefs-org.h"

struct odns;

#define DIRPREFS_VERSION 15

enum dirprefs_type {
    DIRPREFS_TYPE_NONE = -1,
    DIRPREFS_TYPE_ORG = 0,
    DIRPREFS_TYPE_ASSET = 1,
    DIRPREFS_TYPE_GUID = 2,
    DIRPREFS_TYPE_ALT_UID = 3
};

#include "dirprefs-org-proto.h"

#endif
