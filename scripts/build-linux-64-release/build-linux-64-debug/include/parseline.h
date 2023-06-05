#ifndef PARSELINE_H
#define PARSELINE_H

#include <stdbool.h>
#include <stdio.h>

#include "parseline-proto.h"

#define WHITESPACE "\t\n\v\f\r "

static inline int
parseline_spaces(const char *line, const char **key, size_t *key_len, const char **value, size_t *value_len)
{
    return parseline(line, key, key_len, value, value_len, WHITESPACE, true);
}

#endif
