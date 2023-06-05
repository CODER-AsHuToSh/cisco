#ifndef JSON_FILE_H
#define JSON_FILE_H

#include "json.h"
#include "conf.h"

struct json_file {
    double version;    // The major version of the data
    cJSON *object;     // The JSON object parsed from  the JSON file
    cJSON *data;       // Pointer to the data in the object
};

#include "json-file-proto.h"

#endif
