#ifndef __URL_NORMALIZE_H__
#define __URL_NORMALIZE_H__

#define URL_HOST_LEN_MAX 253

typedef enum {
    URL_NORM_FAILED = -1,
    URL_NORM_SUCCESS,
    URL_NORM_TRUNCATED
} URL_NORM_RETURN;

#include "url-normalize-proto.h"

#endif
