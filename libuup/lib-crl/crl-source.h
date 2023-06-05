#ifndef CRL_SOURCE_H
#define CRL_SOURCE_H

#include <errno.h>
#include <stdbool.h>

#define CRL_STATUS_OK         0    // Initial state
#define CRL_STATUS_TRUNC      1    // Value is truncated
#define CRL_STATUS_NOMEM      2    // Memory allocation failed
#define CRL_STATUS_INVAL      3    // Invalid value
#define CRL_STATUS_WRONG_TYPE 4    // Value is of the wrong type

#define CRL_VERSION_SWG       1    // Version of CRL used in SWG and Latitude user/group policies
#define CRL_VERSION_UUP       2    // Version of CRL user in Latitude posture policies

struct crl_source {
    char       *text;
    char       *left;
    const char *file;
    unsigned    line;
    unsigned    version;    // Version of CRL (1 == SWG, 2 == Latitude)
    unsigned    status;
};

#include "crl-source-proto.h"

#endif
