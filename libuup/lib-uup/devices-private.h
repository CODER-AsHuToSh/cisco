#ifndef DEVICES_PRIVATE_H
#define DEVICES_PRIVATE_H

#include "devices.h"

struct devices {
    struct conf     conf;
    struct device  *devices;
    unsigned        count;
};

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define DEVICES_NEW      ((const char *)devices_new + 0)
#   define DEVICE_ARRAY_NEW ((const char *)devices_new + 1)
#endif

#endif
