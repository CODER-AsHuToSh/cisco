#include <string.h>

#include "kit.h"

const char *
kit_basename(const char *path)
{
    const char *basepath;

    if ((basepath = strrchr(path, '/')) != NULL)
        basepath++;
    else
        basepath = path;

    return basepath;
}
