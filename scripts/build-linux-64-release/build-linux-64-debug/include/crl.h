#ifndef CRL_H
#define CRL_H

#include <stdint.h>

#include "crl-namespace.h"
#include "crl-source.h"

#define CRL_ERROR (~0U)    // Stack index returned on failure to parse

#define CRL_IS_REFERENCE          0x80000000    // Set in the JSON type to indicate that the JSON is not to be freed
#define CRL_TYPE_IDENTIFIER       0             // An identifier of the form [a-zA-z][._a-zA-Z0-9]+
#define CRL_TYPE_JSON             1             // An arbitrary JSON value
#define CRL_TYPE_ATTRIBUTES       2             // A list of 0 or more key/value pairs
#define CRL_TYPE_NEGATION         3             // A NOTed expression
#define CRL_TYPE_IN               4             // An IN expression
#define CRL_TYPE_EQUALS           5             // An = comparison
#define CRL_TYPE_CONJUNCTION      6             // A logical conjunction (AND)
#define CRL_TYPE_FIND             7             // A find expression (find a subset of a list of objects)
#define CRL_TYPE_LENGTH           8             // A length expression
#define CRL_TYPE_SUBSCRIPTED      9             // A subscripted expression
#define CRL_TYPE_INTERSECT        10            // Am INTERSECT expression
#define CRL_TYPE_DISJUNCTION      11            // A logical disjunction (OR)
#define CRL_TYPE_GREATER          12            // A > comparison
#define CRL_TYPE_GREATER_OR_EQUAL 13            // A >= comparison
#define CRL_TYPE_LESS             14            // A < comparison
#define CRL_TYPE_LESS_OR_EQUAL    15            // A <= comparison
#define CRL_TYPE_NOT_EQUAL        16            // A != comparison
#define CRL_TYPE_WHERE            17            // A where clause; this can only be the RHS of a find expression
#define CRL_TYPE_TIME             18            // A timestamp
#define CRL_TYPE_SUM              19            // A sum
#define CRL_TYPE_MAX              19            // Largest valid type

// Values returned by test and equal functions
typedef enum crl_test_ret {
    CRL_TEST_ERROR = -1,
    CRL_TEST_FALSE =  0,
    CRL_TEST_TRUE  =  1
} crl_test_ret_t;

struct crl_value {
    uint32_t type;
    uint32_t count;
    union {
        char    *string;
        void    *pointer;
        intptr_t integer;
    };
};

static inline uint32_t
crl_value_get_type(const struct crl_value *value)
{
    return value->type & ~CRL_IS_REFERENCE;
}

#include "crl-parse-proto.h"
#include "crl-proto.h"

static inline crl_test_ret_t
crl_test_not(crl_test_ret_t ret)
{
    switch (ret) {
    case CRL_TEST_FALSE: return CRL_TEST_TRUE;
    case CRL_TEST_TRUE:  return CRL_TEST_FALSE;
    default:             return CRL_TEST_ERROR;
    }
}

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define CRL_VALUE_PUSH             ((const char *)crl_initialize + 0)
#   define CRL_VALUE_DUP              ((const char *)crl_initialize + 1)
#   define CRL_VALUE_CREATE_ARRAY     ((const char *)crl_initialize + 2)
#   define CRL_VALUE_CREATE_REFERENCE ((const char *)crl_initialize + 3)
#   define CRL_VALUE_CREATE_NUMBER    ((const char *)crl_initialize + 4)
#   define CRL_VALUE_CJSON_DUPLICATE  ((const char *)crl_initialize + 5)
#   define CRL_VALUE_ATTRIBUTES_EVAL  ((const char *)crl_initialize + 6)
#   define CRL_VALUE_CREATE_INTERSECT ((const char *)crl_initialize + 7)
#   define CRL_VALUE_CJSON_INTERSECT  ((const char *)crl_initialize + 8)
#   define CRL_VALUE_CREATE_OBJECT    ((const char *)crl_initialize + 9)
#   define CRL_VALUE_FIND_DUPLICATE   ((const char *)crl_initialize + 10)
#   define CRL_VALUE_CREATE_TIME      ((const char *)crl_initialize + 11)
#   define CRL_VALUE_CREATE_SUM       ((const char *)crl_initialize + 12)
#endif

#endif
