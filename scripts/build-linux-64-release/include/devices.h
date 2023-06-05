#ifndef DEVICES_H
#define DEVICES_H

#include <kit.h>

struct xray;

#define DEVICES_VERSION 1

struct device {
    struct kit_deviceid device_id;
    uint32_t org_id;
    uint32_t origin_id;
};

extern module_conf_t CONF_DEVICES;

#include "devices-proto.h"

#endif
