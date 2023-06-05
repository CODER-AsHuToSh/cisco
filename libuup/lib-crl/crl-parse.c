#include <cjson/cJSON.h>
#include <ctype.h>
#include <kit-alloc.h>
#include <mockfail.h>
#include <stdio.h>
#include <string.h>

#include "crl.h"

static unsigned                   crl_value_initial_count                   = 8;
static unsigned                   crl_value_maximum_increment               = 4096 / sizeof(struct crl_value);
static __thread struct crl_value *crl_value_stack                           = NULL;
static __thread unsigned          crl_value_maximum                         = 0;
static __thread unsigned          crl_value_next                            = 0;
static cJSON                     *json_builtins;

const char *
crl_type_to_str(uint32_t type)
{
    switch (type) {
    case CRL_TYPE_IDENTIFIER:              return "CRL_TYPE_IDENTIFIER";
    case CRL_TYPE_JSON:                    return "CRL_TYPE_JSON";
    case CRL_TYPE_JSON | CRL_IS_REFERENCE: return "CRL_TYPE_JSON|CRL_IS_REFERENCE";
    case CRL_TYPE_ATTRIBUTES:              return "CRL_TYPE_ATTRIBUTES";
    case CRL_TYPE_NEGATION:                return "CRL_TYPE_NEGATION";
    case CRL_TYPE_IN:                      return "CRL_TYPE_IN";
    case CRL_TYPE_EQUALS:                  return "CRL_TYPE_EQUALS";
    case CRL_TYPE_CONJUNCTION:             return "CRL_TYPE_CONJUNCTION";
    case CRL_TYPE_FIND:                    return "CRL_TYPE_FIND";
    case CRL_TYPE_LENGTH:                  return "CRL_TYPE_LENGTH";
    case CRL_TYPE_SUBSCRIPTED:             return "CRL_TYPE_SUBSCRIPTED";
    case CRL_TYPE_INTERSECT:               return "CRL_TYPE_INTERSECT";
    case CRL_TYPE_DISJUNCTION:             return "CRL_TYPE_DISJUNCTION";
    case CRL_TYPE_GREATER_OR_EQUAL:        return "CRL_TYPE_GREATER_OR_EQUAL";
    case CRL_TYPE_GREATER:                 return "CRL_TYPE_GREATER";
    case CRL_TYPE_LESS:                    return "CRL_TYPE_LESS";
    case CRL_TYPE_LESS_OR_EQUAL:           return "CRL_TYPE_LESS_OR_EQUAL";
    case CRL_TYPE_NOT_EQUAL:               return "CRL_TYPE_NOT_EQUAL";
    case CRL_TYPE_WHERE:                   return "CRL_TYPE_WHERE";
    case CRL_TYPE_TIME:                    return "CRL_TYPE_TIME";
    case CRL_TYPE_SUM:                     return "CRL_TYPE_SUM";
    }

    return NULL;
}

/**
 * Initialize the common rules language parser
 *
 * @param initial_count     Initial number of values allocated for the value stack (default 8)
 * @param maximum_increment Number of values allocated will double until this value is reached (default 4096)
 */
void
crl_parse_initialize(unsigned initial_count, unsigned maximum_increment, cJSON *json_builtins_object)
{
    crl_value_initial_count     = initial_count        ?: crl_value_initial_count;
    crl_value_maximum_increment = maximum_increment    ?: crl_value_maximum_increment;
    json_builtins               = json_builtins_object ?: json_builtins;
}

/* Return any memory allocated by the current thread
 */
void
crl_parse_finalize_thread(void)
{
    kit_free(crl_value_stack);
    crl_value_stack   = NULL;
    crl_value_maximum = 0;
    crl_value_next    = 0;
}

/* Pop a value and all the values that follow it off the value stack, effectively freeing them
 */
void
crl_value_pop(unsigned idx)
{
    SXEA6(idx < crl_value_next, "Invalid attempt to scratch the heap");
    crl_value_next = idx;
}

/**
 * Push a new value onto the value stack, effectively allocating it
 *
 * @param free_on_error Set to automatically free the old stack and clean it up on error.
 *
 * @return Index of the new value or CRL_ERROR on failure to allocate memory.
 */
static unsigned
crl_value_push(struct crl_source *source, bool free_on_error)
{
    struct crl_value *old_values = crl_value_stack;

    if (crl_value_next >= crl_value_maximum) {
        SXEA6(crl_value_next == crl_value_maximum, "Next should never be more than 1 past the end of the array");

        if (crl_value_maximum == 0)
            crl_value_maximum = crl_value_initial_count;
        else if (2 * crl_value_maximum < crl_value_maximum_increment)
            crl_value_maximum *= 2;
        else
            crl_value_maximum += crl_value_maximum_increment;

        crl_value_stack
            = MOCKFAIL(CRL_VALUE_PUSH, NULL, kit_realloc(crl_value_stack, crl_value_maximum * sizeof(*crl_value_stack)));

        if (!crl_value_stack) {
            SXEL2("%s: Failed to allocate %u values", __func__, crl_value_maximum);

            if (free_on_error)
                kit_free(old_values);
            else
                crl_value_stack = old_values;

            crl_value_maximum = 0;
            crl_value_next    = 0;
            source->status    = CRL_STATUS_NOMEM;
            return CRL_ERROR;
        }
    }

    return crl_value_next++;
}

// Given that the current character is alphabetic, find the first non-identifier after it, populating the value structure
char *
crl_peek_identifier(struct crl_source *source, struct crl_value *value)
{
    char *name = source->left;
    char *next;

    for (next = name + 1; isalnum(*next) || *next == '_' || *next == '.'; next++) {
    }

    value->type   = CRL_TYPE_IDENTIFIER;
    value->count  = next - name;
    value->string = name;
    return next;
}

unsigned
crl_parse_identifier(struct crl_source *source)
{
    char    *name;
    unsigned idx;

    if (!*(name = crl_source_skip_space(source)))    // End of data
        return CRL_ERROR;

    if (!isalpha(*name)) {
        source->status = CRL_STATUS_WRONG_TYPE;
        return CRL_ERROR;
    }

    if ((idx = crl_value_push(source, true)) == CRL_ERROR)    // Malloc failure
        return CRL_ERROR;

    source->left = crl_peek_identifier(source, &crl_value_stack[idx]);
    return idx;
}

unsigned
crl_parse_json(struct crl_source *source, const char *after)
{
    cJSON      *json;
    const char *last;
    unsigned    idx;

    if ((idx = crl_value_push(source, true)) == CRL_ERROR)
        return CRL_ERROR;

    if (!(json = cJSON_ParseWithOpts(source->left, &last, false))) {
        if (after)
            SXEL2("%s: %u: Expected JSON after '%s'", source->file, source->line, after);
        else
            SXEL2("%s: %u: Expected JSON", source->file, source->line);

        SXEL6("cJSON ErrorPtr-2..ErrorPtr+13:");
        SXED6(cJSON_GetErrorPtr() - 2, 16);
        source->status = CRL_STATUS_INVAL;
        return CRL_ERROR;
    }

    source->left                 = (char *)(uintptr_t)last;    // Cast because cJSON wants what it parses to be const, but we don't
    crl_value_stack[idx].type    = CRL_TYPE_JSON;
    crl_value_stack[idx].pointer = json;
    return idx;
}

/**
 * Parse a comma separated list of attributes. Attribute values may be CRL expressions.
 *
 * @param Object defining the text to parse
 *
 * @return Index in the parse stack of the parsed attributes or CRL_ERROR on error.
 *
 * @note The attribute value's count is the number of key/value pairs which follow it.
 */
unsigned
crl_parse_attributes(struct crl_source *source)
{
    unsigned attributes_index, i;

    if ((attributes_index = crl_value_push(source, true)) == CRL_ERROR)
        return CRL_ERROR;

    crl_value_stack[attributes_index].count = 0;
    crl_value_stack[attributes_index].type  = CRL_TYPE_ATTRIBUTES;

    while (*source->left) {
        struct crl_value *identifier;
        unsigned          id_index;

        if (source->version != CRL_VERSION_SWG && crl_value_stack[attributes_index].count) {
            if (*crl_source_skip_space(source) != ',')    // Commas are required between attributes after version 1
                break;

            source->left++;
        }

        if ((id_index = crl_parse_identifier(source)) == CRL_ERROR) {
            if (!crl_value_stack[attributes_index].count)    // Empty attributes line
                break;

            SXEL2("%s: %u: Expected identifier after ',', got '%s'", source->file, source->line, source->left);
            source->status = CRL_STATUS_INVAL;
            goto ERROR_OUT;
        }

        identifier = &crl_value_stack[id_index];

        if (source->version == CRL_VERSION_SWG) {    // SWG version of CRL is used for Latitude user/group access policies
            if (*crl_source_skip_space(source) != '=') {
                SXEL2("%s: %u: Expected '=' after '%.*s', got '%s'", source->file, source->line, identifier->count,
                      identifier->string, source->left);
                source->status = CRL_STATUS_INVAL;
                goto ERROR_OUT;
            }
        } else {                                     // POSTURE version of CRL is used for Latitude posture polices
            if (*crl_source_skip_space(source) != ':' || *(source->left + 1) != '=') {
                SXEL2("%s: %u: Expected ':=' after '%.*s', got '%s'", source->file, source->line, identifier->count,
                      identifier->string, source->left);
                source->status = CRL_STATUS_INVAL;
                goto ERROR_OUT;
            }
        }

        identifier->string[identifier->count] = '\0';    // NUL terminate the identifier
        source->left += source->version == CRL_VERSION_SWG ? 1 : 2;    // Point to the character after the '='

        if (source->version == CRL_VERSION_SWG) {    // SWG version of CRL is used for Latitude user/group access policies
            if (crl_parse_elementary_expr(source, identifier->string) == CRL_ERROR)
                goto ERROR_OUT;
        } else {                                     // POSTURE version of CRL is used for Latitude posture polices
            if (crl_parse_expression(source, identifier->string) == CRL_ERROR)
                goto ERROR_OUT;
        }

        crl_value_stack[id_index].count = crl_value_next - id_index;    // Key count is the count of the value's tokens + 1
        crl_value_stack[attributes_index].count++;
    }

    return attributes_index;

ERROR_OUT:
    for (i = 1; i <= crl_value_stack[attributes_index].count; i++)
        if (crl_value_stack[attributes_index + 2 * i].type == CRL_TYPE_JSON)
            cJSON_Delete(crl_value_stack[attributes_index + 2 * i].pointer);

    source->status = CRL_STATUS_INVAL;
    return CRL_ERROR;
}

unsigned
crl_parse_elementary_expr(struct crl_source *source, const char *after)
{
    struct crl_value *element;
    unsigned          elem_index, saved_status, sub_index;

    saved_status = source->status;

    if (*crl_source_skip_space(source) == '(') {
        source->left++;

        if ((elem_index = crl_parse_expression(source, after = "(")) == CRL_ERROR)
            return CRL_ERROR;

        if (*crl_source_skip_space(source) != ')') {
            SXEL2("%s: %u: Expected ')' after '(', got '%s'", source->file, source->line, source->left);
            source->status = CRL_STATUS_INVAL;
            // TODO: This nonsense can be avoided if all allocations are done on the stack, but that requires implementing JSON parsing
            crl_value_fini(&crl_value_stack[elem_index]);    // Free any JSON allocated
            return CRL_ERROR;
        }

        source->left++;
    }
    else if ((elem_index = crl_parse_identifier(source)) == CRL_ERROR) {
        if (source->status != CRL_STATUS_WRONG_TYPE || (elem_index = crl_parse_json(source, after)) == CRL_ERROR)
            return CRL_ERROR;

        source->status = saved_status;
    }
    else {    // An identifier was parsed
        cJSON *builtin;
        char   saved;

        SXEA6(json_builtins, "The CRL parser is not initialized");
        saved = crl_value_stack[elem_index].string[crl_value_stack[elem_index].count];
        crl_value_stack[elem_index].string[crl_value_stack[elem_index].count] = '\0';     // Temporarily '\0' terminate

        if (source->version == CRL_VERSION_SWG) {    // For backward compatibility, allow SWG CRL files to use 'True' and 'False'
            if (crl_value_stack[elem_index].count == 4 && memcmp(crl_value_stack[elem_index].string, "True", 4) == 0)
                crl_value_stack[elem_index].string[0] = 't';
            else if (crl_value_stack[elem_index].count == 5 && memcmp(crl_value_stack[elem_index].string, "False", 5) == 0)
                crl_value_stack[elem_index].string[0] = 'f';
        }

        builtin = cJSON_GetObjectItemCaseSensitive(json_builtins, crl_value_stack[elem_index].string);
        crl_value_stack[elem_index].string[crl_value_stack[elem_index].count] = saved;    // Restore the next character

        // If it's a built in JSON terminal (true, false, null), return a JSON object
        if (builtin) {
            crl_value_stack[elem_index].type    = CRL_TYPE_JSON | CRL_IS_REFERENCE;    // Don't free the builtins
            crl_value_stack[elem_index].pointer = builtin;
        }
    }

    while (*crl_source_skip_space(source) == '[') {
        if ((sub_index = crl_value_push(source, true)) == CRL_ERROR)    // Malloc failure
            return CRL_ERROR;

        after = "[";
        element = &crl_value_stack[elem_index];
        memmove(element + 1, element, sizeof(*element) * (sub_index - elem_index));    // Make room for the = expression
        element->type  = CRL_TYPE_SUBSCRIPTED;
        element->count = sub_index - elem_index;    // Number of values in the LHS of the expression
        source->left++;

        if (crl_parse_monadic_expr(source, after) == CRL_ERROR)
            return CRL_ERROR;

        if (*crl_source_skip_space(source) != ']') {
            SXEL2("%s: %u: Expected ']' after '[', got '%s'", source->file, source->line, source->left);
            source->status = CRL_STATUS_INVAL;
            return CRL_ERROR;
        }

        source->left++;
    }

    return elem_index;
}

#define CRL_NOMATCH (CRL_ERROR - 1)

/* After a first letter match, see if the remainder of the identifier is a specific keyword and if so, parse the expression
 */
static unsigned
parse_monadic_keyword(struct crl_source *source, const char *keyword, unsigned len, uint32_t type)
{
    struct crl_value  value;
    char             *next = crl_peek_identifier(source, &value);
    unsigned          idx;

    if (value.count == len && memcmp(&value.string[1], &keyword[1], len - 1) == 0) {
        if ((idx = crl_value_push(source, true)) == CRL_ERROR)    // Malloc failure
            return CRL_ERROR;

        crl_value_stack[idx].type = type;
        source->left              = next;
        return crl_parse_monadic_expr(source, keyword) != CRL_ERROR ? idx : CRL_ERROR;    // Parse operand
    }

    return CRL_NOMATCH;
}

unsigned
crl_parse_monadic_expr(struct crl_source *source, const char *after)
{
    unsigned idx;

    switch (*crl_source_skip_space(source)) {
    case 'N':
        if ((idx = parse_monadic_keyword(source, "NOT", sizeof("NOT") - 1, CRL_TYPE_NEGATION)) != CRL_NOMATCH)
            return idx;

        break;

    case 'L':
        if ((idx = parse_monadic_keyword(source, "LENGTH", sizeof("LENGTH") - 1, CRL_TYPE_LENGTH)) != CRL_NOMATCH)
            return idx;

        break;

    case 'T':
        if ((idx = parse_monadic_keyword(source, "TIME", sizeof("TIME") - 1, CRL_TYPE_TIME)) != CRL_NOMATCH)
            return idx;

        break;
    }

    return crl_parse_elementary_expr(source, after);
}

// Currently, expressions are grouped right to left. Left to right is tricky.
unsigned
crl_parse_additive_expr(struct crl_source *source, const char *after)
{
    struct crl_value *add;
    char              first;
    unsigned          add_index;
    unsigned          rhs_index;

    if ((add_index = crl_parse_monadic_expr(source, after)) == CRL_ERROR)    // An additive must begin with a monad
        return CRL_ERROR;

    switch (first = *crl_source_skip_space(source)) {
    case '+':
        if ((rhs_index = crl_value_push(source, false)) == CRL_ERROR)    // Malloc failure
            goto ERROR_OUT;

        after = "+";
        add = &crl_value_stack[add_index];
        memmove(add + 1, add, sizeof(*add) * (rhs_index - add_index));    // Make room for the = expression
        add->type  = CRL_TYPE_SUM;
        add->count = rhs_index - add_index;    // Number of values in the LHS of the expression
        source->left++;
        break;

    default:
        return add_index;
    }

    if (crl_parse_additive_expr(source, after) != CRL_ERROR)
        return add_index;

// TODO: This nonsense can be avoided if all allocations are done on the stack, but that requires implementing JSON parsing
ERROR_OUT:
    crl_value_fini(&crl_value_stack[add_index]);    // Free any JSON allocated
    return CRL_ERROR;
}

// Currently, expressions are grouped right to left. Left to right is tricky.
unsigned
crl_parse_dyadic_expr(struct crl_source *source, const char *after)
{
    struct crl_value  value;
    struct crl_value *dyad;
    char              first, *next;
    unsigned          dyad_index;
    unsigned          rhs_index;

    if ((dyad_index = crl_parse_additive_expr(source, after)) == CRL_ERROR)    // A dyad must begin with an additive expression
        return CRL_ERROR;

    switch (first = *crl_source_skip_space(source)) {
    case '=':
        if ((rhs_index = crl_value_push(source, false)) == CRL_ERROR)    // Malloc failure
            goto ERROR_OUT;

        after = "=";
        dyad = &crl_value_stack[dyad_index];
        memmove(dyad + 1, dyad, sizeof(*dyad) * (rhs_index - dyad_index));    // Make room for the = expression
        dyad->type  = CRL_TYPE_EQUALS;
        dyad->count = rhs_index - dyad_index;    // Number of values in the LHS of the expression
        source->left++;
        break;

    case 'F':
        next = crl_peek_identifier(source, &value);

        if (value.count == 4 && memcmp(&value.string[1], "IND", 3) == 0) {    // FIND operator
            if ((rhs_index = crl_value_push(source, false)) == CRL_ERROR)    // Malloc failure
                goto ERROR_OUT;

            after = "FIND";
            dyad = &crl_value_stack[dyad_index];
            memmove(dyad + 1, dyad, sizeof(*dyad) * (rhs_index - dyad_index));    // Make room for the FIND expression
            dyad->type   = CRL_TYPE_FIND;
            dyad->count  = rhs_index - dyad_index;    // Number of values in the LHS of the expression
            source->left = next;
            break;
        }

        return dyad_index;

    case 'I':
        next = crl_peek_identifier(source, &value);

        if (value.count == 2 && value.string[1] == 'N') {    // IN operator
            if ((rhs_index = crl_value_push(source, false)) == CRL_ERROR)    // Malloc failure
                goto ERROR_OUT;

            after = "IN";
            dyad = &crl_value_stack[dyad_index];
            memmove(dyad + 1, dyad, sizeof(*dyad) * (rhs_index - dyad_index));    // Make room for the IN expression
            dyad->type   = CRL_TYPE_IN;
            dyad->count  = rhs_index - dyad_index;    // Number of values in the LHS of the expression
            source->left = next;
            break;
        }
        else if (value.count == 9 && memcmp(&value.string[1], "NTERSECT", 8) == 0) {    // INTERSECT operator
            if ((rhs_index = crl_value_push(source, false)) == CRL_ERROR)    // Malloc failure
                goto ERROR_OUT;

            after = "INTERSECT";
            dyad = &crl_value_stack[dyad_index];
            memmove(dyad + 1, dyad, sizeof(*dyad) * (rhs_index - dyad_index));    // Make room for the IN expression
            dyad->type   = CRL_TYPE_INTERSECT;
            dyad->count  = rhs_index - dyad_index;    // Number of values in the LHS of the expression
            source->left = next;
            break;
        }

        return dyad_index;

    case 'W':
        next = crl_peek_identifier(source, &value);

        if (value.count == 5 && memcmp(&value.string[1], "HERE", 4) == 0) {    // WHERE keyword
            if (crl_value_stack[dyad_index].type != CRL_TYPE_IDENTIFIER) {
                SXEL2("%s: %u: Expected an identifier before 'WHERE', got %s", source->file, source->line,
                      crl_type_to_str(crl_value_stack[dyad_index].type));
                source->status = CRL_STATUS_INVAL;
                return CRL_ERROR;
            }

            if ((rhs_index = crl_value_push(source, false)) == CRL_ERROR)    // Malloc failure
                goto ERROR_OUT;

            after = "WHERE";
            dyad = &crl_value_stack[dyad_index];
            memmove(dyad + 1, dyad, sizeof(*dyad) * (rhs_index - dyad_index));    // Make room for the WHERE clause
            dyad->type   = CRL_TYPE_WHERE;
            dyad->count  = rhs_index - dyad_index;    // Number of values in the LHS of the expression
            source->left = next;
            break;
        }

        return dyad_index;

    case '>':
    case '<':
    case '!':
        if ((rhs_index = crl_value_push(source, false)) == CRL_ERROR)    // Malloc failure
            goto ERROR_OUT;

        dyad = &crl_value_stack[dyad_index];
        memmove(dyad + 1, dyad, sizeof(*dyad) * (rhs_index - dyad_index));    // Make room for the = expression
        dyad->count = rhs_index - dyad_index;                                 // Number of values in the LHS of the expression

        if (*crl_source_skip_char(source) == '=') {
            source->left++;

            switch (first) {
            case '>':
                after      = ">=";
                dyad->type = CRL_TYPE_GREATER_OR_EQUAL;
                break;

            case '<':
                after      = "<=";
                dyad->type = CRL_TYPE_LESS_OR_EQUAL;
                break;

            case '!':
                after      = "!=";
                dyad->type = CRL_TYPE_NOT_EQUAL;
                break;
            }
        } else if (first == '>') {
            after      = ">";
            dyad->type = CRL_TYPE_GREATER;
        } else if (first == '<') {
            after      = "<";
            dyad->type = CRL_TYPE_LESS;
        } else {
            SXEL2("%s: %u: Expected '=' after '!'", source->file, source->line);
            goto ERROR_OUT;
        }

        break;

    default:
        return dyad_index;
    }

    if (crl_parse_dyadic_expr(source, after) != CRL_ERROR)
        return dyad_index;

// TODO: This nonsense can be avoided if all allocations are done on the stack, but that requires implementing JSON parsing
ERROR_OUT:
    crl_value_fini(&crl_value_stack[dyad_index]);    // Free any JSON allocated
    return CRL_ERROR;
}

/**
 * Parse a CRL conjunction.
 *
 * @return Index of the the expression on the stack or CRL_ERROR on error.
 *
 * @note Conjunctive expressions are grouped right to left but executed left to right.
 */
unsigned
crl_parse_conjunction(struct crl_source *source, const char *after)
{
    struct crl_value  value;
    struct crl_value *expression;
    char             *next;
    unsigned          expr_index;
    unsigned          rhs_index;

    if ((expr_index = crl_parse_dyadic_expr(source, after)) == CRL_ERROR)    // A conjunction must begin with a dyad
        return CRL_ERROR;

    switch (*crl_source_skip_space(source)) {
    case 'A':
        next = crl_peek_identifier(source, &value);

        if (value.count == 3 && value.string[1] == 'N' && value.string[2] == 'D') {    // AND operator
            if ((rhs_index = crl_value_push(source, false)) == CRL_ERROR)    // Malloc failure
                goto REALLOC_ERROR;

            after      = "AND";
            expression = &crl_value_stack[expr_index];
            memmove(expression + 1, expression, sizeof(*expression) * (rhs_index - expr_index));    // Make room for the AND
            expression->type  = CRL_TYPE_CONJUNCTION;
            expression->count = rhs_index - expr_index;    // Number of values in the LHS of the expression
            source->left      = next;
            break;
        }

        /* FALLTHRU */

    default:
        return expr_index;
    }

    return crl_parse_conjunction(source, after) == CRL_ERROR ? CRL_ERROR : expr_index;

// TODO: This nonsense can be avoided if all allocations are done on the stack, but that requires implementing JSON parsing
REALLOC_ERROR:
    crl_value_fini(&crl_value_stack[expr_index]);    // Free any JSON allocated
    return CRL_ERROR;
}

/**
 * Parse a CRL expression.
 *
 * @param source CRL source code
 * @param after  NULL at the beginning of the expression or the last element parsed (used in diagnostics)
 *
 * @return Index of the the expression on the stack or CRL_ERROR on error.
 *
 * @note Disjunctive expressions are grouped right to left but executed left to right.
 */
unsigned
crl_parse_expression(struct crl_source *source, const char *after)
{
    struct crl_value  value;
    struct crl_value *expression;
    char             *next;
    unsigned          expr_index;
    unsigned          rhs_index;

    if ((expr_index = crl_parse_conjunction(source, after)) == CRL_ERROR)    // A disjunction must begin with a conjunction
        return CRL_ERROR;

    switch (*crl_source_skip_space(source)) {
    case 'O':
        next = crl_peek_identifier(source, &value);

        if (value.count == 2 && value.string[1] == 'R') {    // OR operator
            if ((rhs_index = crl_value_push(source, false)) == CRL_ERROR)    // Malloc failure
                goto REALLOC_ERROR;

            after      = "OR";
            expression = &crl_value_stack[expr_index];
            memmove(expression + 1, expression, sizeof(*expression) * (rhs_index - expr_index));    // Make room for the OR
            expression->type  = CRL_TYPE_DISJUNCTION;
            expression->count = rhs_index - expr_index;    // Number of values in the LHS of the expression
            source->left      = next;
            break;
        }

        /* FALLTHRU */

    default:
        return expr_index;
    }

    return crl_parse_expression(source, after) == CRL_ERROR ? CRL_ERROR : expr_index;

// TODO: This nonsense can be avoided if all allocations are done on the stack, but that requires implementing JSON parsing
REALLOC_ERROR:
    crl_value_fini(&crl_value_stack[expr_index]);    // Free any JSON allocated

    if (after == NULL) {
        kit_free(crl_value_stack);
        crl_value_stack = NULL;
    }

    return CRL_ERROR;
}

/**
 * Duplicate a parsed CRL value
 *
 * @param idx         The index of the value on the parsed value stack
 * @param description What the value is (used in error messages)
 *
 * @return The value on success, NULL if out of memory
 *
 * @note On failure to duplicate, frees any memory allocated by to the value on the stack (memory leak prevention)
 */
struct crl_value *
crl_value_dup(unsigned idx, const char *description)
{
    struct crl_value *me;
    size_t            size = (crl_value_next - idx) * sizeof(*me);

    if (!(me = MOCKFAIL(CRL_VALUE_DUP, NULL, kit_malloc(size)))) {
        SXEL2("%s: Failed to allocate %zu byte %s", __func__, size, description);
        crl_value_fini(&crl_value_stack[idx]);    // Free up any memory allocated for the thing we failed to duplicate
        return NULL;
    }

    memcpy(me, &crl_value_stack[idx], size);
    return me;
}
