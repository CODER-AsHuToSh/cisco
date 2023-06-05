#ifndef POLICY_POLICY_H
#define POLICY_POLICY_H

#define POLICY_VER_MIN 1    // Minimum version still supported (usually the same as POLICY_VERSION)
#define POLICY_VERSION 2    // Latest version

// For now, there are no loadflags for policy

#include "conf-meta.h"
#include "conf-segment.h"
#include "rule.h"

struct domainlist;
struct urllist;

struct policy_org {
    char                  *global_line;    // A duplicated and mutable copy of the line for global attributes to point into.
    struct crl_value      *global_attr;    // Global attributes or NULL if there is no global section
    struct rule           *rules;          // Array of rules
    unsigned               count;          // Number of rules
    unsigned               version;        // Rules version
    struct conf_meta      *cm;
    struct conf_segment    cs;
};

struct conf_loader;

#include "policy-org-proto.h"

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define POLICY_ORG_NEW        ((const char *)policy_org_new + 0)
#   define POLICY_ALLOCRULES     ((const char *)policy_org_new + 1)
#   define POLICY_DUP_ATTRLINE   ((const char *)policy_org_new + 2)
#   define POLICY_DUP_CONDLINE   ((const char *)policy_org_new + 3)
#   define POLICY_DUP_GLOBALLINE ((const char *)policy_org_new + 4)
#endif

#endif
