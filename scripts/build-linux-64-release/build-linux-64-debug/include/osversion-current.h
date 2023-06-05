#ifndef OSVERSION_CURRENT_H
#define OSVERSION_CURRENT_H

#include "conf.h"

struct osversion_current;

extern module_conf_t CONF_OSVERSION_CURRENT;

#include "osversion-current-proto.h"

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define OSVERSION_CURRENT_NEW ((const char *)osversion_current_new + 0)
#endif

#endif
