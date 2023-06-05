#ifndef PREFS_ORG_H
#define PREFS_ORG_H

#include "conf-segment.h"
#include "fileprefs.h"

struct prefs_org {
    struct fileprefs fp;
    struct conf_segment cs;
};

#include "prefs-org-proto.h"

#endif
