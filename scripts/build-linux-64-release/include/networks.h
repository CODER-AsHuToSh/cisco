#ifndef NETWORKS_H
#define NETWORKS_H

#include "cidr-ipv4.h"
#include "cidr-ipv6.h"

struct xray;

#define NETWORKS_VERSION 1

struct network {
    union {
        struct cidr_ipv4 v4;
        struct cidr_ipv6 v6;
    } addr;
    sa_family_t family;

    uint32_t org_id;
    uint32_t origin_id;
};

extern module_conf_t CONF_NETWORKS;

#include "networks-proto.h"

#endif
