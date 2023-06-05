#ifndef GEOIP_H
#define GEOIP_H

#define GEOIP_VERSION 1

extern module_conf_t CONF_GEOIP;
extern module_conf_t CONF_REGIONIP;
struct geoip;

#include "geoip-proto.h"

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define GEOIP_NEW      ((const char *)geoip_register + 0)
#   define GEOIP_KEYS_NEW ((const char *)geoip_register + 1)
#endif

#endif
