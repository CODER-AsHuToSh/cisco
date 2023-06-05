#ifndef UINT16SET_H
#define UINT16SET_H

struct uint16set {
    unsigned count;
    struct {
        uint16_t start;    /* The uint16set_compare() function depends on 'start' being first in each item[] element */
        unsigned end;
    } item[1];
};

#include "uint16set-proto.h"

#endif
