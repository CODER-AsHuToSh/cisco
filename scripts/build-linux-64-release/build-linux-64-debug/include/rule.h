#ifndef RULE_H
#define RULE_H

#include "crl.h"

struct rule {
    char             *attr_line;    // A duplicated and mutable copy of the line for attributes to point into.
    struct crl_value *attributes;
    char             *cond_line;    // A duplicated and mutable copy of the line for condition to point into.
    struct crl_value *condition;
    struct crl_value *action;
};

#include "rule-proto.h"

#endif
