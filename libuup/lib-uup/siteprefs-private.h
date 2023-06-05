#ifndef SITEPREFS_PRIVATE_H
#define SITEPREFS_PRIVATE_H

#include "fileprefs.h"
#include "siteprefs.h"

struct siteprefs {
    struct fileprefs fp;
    struct conf conf;
};

#endif
