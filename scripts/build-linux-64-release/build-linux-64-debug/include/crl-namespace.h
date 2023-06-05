#ifndef CRL_NAMESPACE_H
#define CRL_NAMESPACE_H

#include <cjson/cJSON.h>

struct crl_namespace {
    union {
        cJSON            *object;
        struct crl_value *attributes;
    };
    struct crl_namespace *next;
    unsigned              type;
};

#include "crl-namespace-proto.h"

#endif
