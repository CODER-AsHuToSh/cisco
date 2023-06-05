#ifndef GRAPHITELOG_H
#define GRAPHITELOG_H

struct kit_graphitelog_thread {
    unsigned counter_slot;
    int fd;
};

#include "kit-graphitelog-proto.h"

#endif
