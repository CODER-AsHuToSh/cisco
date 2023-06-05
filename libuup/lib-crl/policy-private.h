#ifndef POLICY_PRIVATE_H
#define POLICY_PRIVATE_H

#include "policy.h"

#define LOADFLAGS_POLICY LOADFLAGS_NONE

struct policy_index {
    unsigned slot;
    unsigned offset;
};

struct policy {
    struct conf         conf;
    time_t              mtime;    // last modification
    unsigned            count;    // # allocated policy_org entries
    struct policy_org **orgs;     // a block of 'count' pointers to policy_orgs
};

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define POLICY_CLONE             ((const char *)policy_register + 0)
#   define POLICY_CLONE_POLICY_ORGS ((const char *)policy_register + 1)
#   define POLICY_MORE_POLICY_ORGS  ((const char *)policy_register + 2)
#endif

#endif
