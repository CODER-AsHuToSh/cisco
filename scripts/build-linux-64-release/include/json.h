/* Generic JSON interface. Currently, wraps cJSON */

#ifndef JSON_H
#define JSON_H

#include <cjson/cJSON.h>

#include "crl.h"

// FUTURE: struct json;    // An alias for cJSON

extern cJSON *json_bool_true;
extern cJSON *json_bool_false;
extern cJSON *json_null;
extern cJSON *json_builtins;

#include "json-proto.h"

#endif
