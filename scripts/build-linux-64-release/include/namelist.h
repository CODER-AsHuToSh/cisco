#ifndef NAMELIST_H
#define NAMELIST_H

#include <conf.h>

extern module_conf_t CONF_TYPO_EXCEPTION_PREFIXES;

#include "namelist-proto.h"

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define NAMELIST_ALLOCATE      ((const char *)namelist_register + 0)
#   define NAMELIST_ALLOCATE_NODE ((const char *)namelist_register + 1)
#endif

#endif
