#ifndef PREF_OVERLOADS_H
#define PREF_OVERLOADS_H

#include "pref.h"

#define PREF_OVERLOADS_VERSION     2

struct pref_overloads;

extern module_conf_t CONF_PREF_OVERLOADS;

struct overloaded_pref {
    pref_orgflags_t orgflags;
    pref_orgflags_t overridable_orgflags;
    pref_bundleflags_t bundleflags;
    pref_bundleflags_t overridable_bundleflags;
    pref_categories_t categories;
    pref_categories_t overridable_categories;
} __attribute__ ((__packed__));

#include "pref-overloads-proto.h"

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define PREF_OVERLOADS_NEW     ((const char *)pref_overloads_register + 0)
#   define PREF_OVERLOADS_CC_NEW  ((const char *)pref_overloads_register + 1)
#   define PREF_OVERLOADS_IP4_NEW ((const char *)pref_overloads_register + 2)
#   define PREF_OVERLOADS_IP6_NEW ((const char *)pref_overloads_register + 3)
#endif

#endif
