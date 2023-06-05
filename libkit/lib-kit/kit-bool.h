#include <stdbool.h>

static inline const char *
kit_bool_to_str(bool flag)
{
    return flag ? "true" : "false";
}
