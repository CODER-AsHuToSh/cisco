#ifndef DEVPREFS_PRIVATE_H
#define DEVPREFS_PRIVATE_H

#include "devprefs.h"
#include "fileprefs.h"

struct devprefs {
    struct fileprefs fp;
    struct conf conf;
};

#endif
