/*
 * This provides a safer wrapper to the strto*() functions
 *
 * NOTE:
 *   These wrapper functions are not POSIX compliant as they clear the previous
 * value of errno before calling strto*().  This violates
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/errno.html
 *   Clearing the errno is normally supposed to be done by a function's
 * caller, however this approach is much cleaner for the current use of these
 * functions (ie within opendnscache).
 */

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <sxe-log.h>

#include "kit.h"

/*
 * Correct for deficiencies in the linux implementation by checking that return
 * values of zero were really for a value of zero, setting errno if not.
 */
static void
check_zero_result(const char *str, char **endptr, int base)
{
    int pos = 0;

    if (endptr && (str == *endptr)) {
        errno = EINVAL;
        return;
    }

    while (isspace(str[pos])) {
        pos++;
    }

    if (str[pos] == '-' || str[pos] == '+') {
        pos++;
    }

    if (str[pos] != '0') {
        errno = EINVAL;
        return;
    } else if (((base == 0) || (base == 16)) && str[pos + 1] == 'x') {
        if (str[pos + 2] != '0') {
            errno = EINVAL;
            return;
        }
    }
}

/**
 * @note Sets errno to 0 on success or an error code on failure
 */
unsigned long
kit_strtoul(const char *str, char **endptr, int base)
{
    unsigned long ret;

    errno = 0;

    ret = strtoul(str, endptr, base);
    if ((ret == 0) && (errno == 0)) {
        check_zero_result(str, endptr, base);
    }

    return ret;
}

/**
 * @note Sets errno to 0 on success or an error code on failure
 */
unsigned long long
kit_strtoull(const char *str, char **endptr, int base)
{
    unsigned long long ret;

    errno = 0;

    ret = strtoull(str, endptr, base);
    if ((ret == 0) && (errno == 0)) {
        check_zero_result(str, endptr, base);
    }

    return ret;
}

/**
 * @note Sets errno to 0 on success or an error code on failure
 */
long int
kit_strtol(const char *str, char **endptr, int base)
{
    long ret;

    errno = 0;

    ret = strtol(str, endptr, base);
    if ((ret == 0) && (errno == 0)) {
        check_zero_result(str, endptr, base);
    }

    return ret;
}

/**
 * @note Sets errno to 0 on success or an error code on failure
 */
long long int
kit_strtoll(const char *str, char **endptr, int base)
{
    long long ret;

    errno = 0;

    ret = strtoll(str, endptr, base);
    if ((ret == 0) && (errno == 0)) {
        check_zero_result(str, endptr, base);
    }

    return ret;
}

/**
 * @note Sets errno to 0 on success or an error code on failure
 */
double
kit_strtod(const char *str, char **endptr)
{
    double ret;

    errno = 0;

    ret = strtod(str, endptr);
    if ((ret == 0) && (errno == 0)) {
        check_zero_result(str, endptr, 10);
    }

    return ret;
}
