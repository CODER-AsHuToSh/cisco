#ifndef CONF_META_H
#define CONF_META_H

struct conf_meta {
    char *name;
};

struct conf_loader;

#include "conf-meta-proto.h"

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define CONF_META_ALLOC     ((const char *)conf_meta_new + 0)
#   define CONF_META_NAMEALLOC ((const char *)conf_meta_new + 1)
#endif

#endif
