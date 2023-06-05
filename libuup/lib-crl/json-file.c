#include <ctype.h>
#include <kit-alloc.h>
#include <mockfail.h>

#if __linux__
#include <bsd/string.h>    // Do after sxe-log.h so this won't create its own __printflike
#else
#include <string.h>
#endif

#include "json.h"
#include "json-file.h"
#include "conf-loader.h"
#include "conf-meta.h"

/**
 * Load a JSON file
 *
 * @param me     A json_file structure to populate
 * @param cl     A conf loader of a JSON file containg a JSON object
 * @param type   The type name expected in the JSON object, whose value is the data
 * @param member If the actual JSON object is nested inside a JSON object that isn't wanted, the member name, else NULL.
 */
bool
json_file_load(struct json_file *me, struct conf_loader *cl, const char *type, const char *member)
{
    char       *content = NULL;
    const char *pos;
    cJSON      *value;
    size_t      len, memberlen;

    SXEE6("(me=?,cl=?,type=%s,member=%s) // conf_loader_path(cl)='%s'", type, member, conf_loader_path(cl));

    me->object = NULL;

    if (conf_loader_err(cl))
        goto OUT;

    // This will fragment memory, but cJSON requires the whole content to parse. Future: need to incrementally parse JSON.
    if ((content = conf_loader_readfile(cl, &len, 0)) == NULL || conf_loader_err(cl)) {
        SXEL2("%s: Unable to load file (%s)", conf_loader_path(cl),
              conf_loader_err(cl) ? strerror(conf_loader_err(cl)) : "errno = 0");
        goto OUT;
    }

    if (!content[0]) {
        SXEL2("%s: No content found", conf_loader_path(cl));
        goto OUT;
    }

    pos = content;

    if (member) {
        memberlen = strlen(member);

        for (pos++; (pos = strnstr(pos, member, len - (pos - content))); pos += memberlen)
            if (pos[-1] == '"' && pos[memberlen] == '"') {
                pos += memberlen + 1;

                while (isspace(*pos))
                    pos++;

                if (*pos == ':') {
                    pos++;
                    break;
                }
            }

        if (pos == NULL) {
            SXEL2("%s: Member name \"%s\" not found in %zu bytes", conf_loader_path(cl), member, len);
            goto OUT;
        }
    }

    if ((me->object = cJSON_ParseWithOpts(pos, &pos, member == NULL)) == NULL)    // If no member, must consume entire content
        SXEL2("%s: Error parsing JSON at byte %zu of %zu", conf_loader_path(cl), pos - content + 1, len);
    else if (!cJSON_IsObject(me->object))
        SXEL2("%s: Content is not a JSON object", conf_loader_path(cl));
    else if ((me->data = cJSON_GetObjectItem(me->object, type)) == NULL)
        SXEL2("%s: JSON object does not include a '%s' member", conf_loader_path(cl), type);
    else if ((value = cJSON_GetObjectItem(me->object, "version")) == NULL)
        SXEL2("%s: JSON object does not include a 'version' member", conf_loader_path(cl));
    else if ((value = cJSON_GetArrayItem(value, 0)) == NULL || !cJSON_IsNumber(value))
        SXEL2("%s: JSON object version is not an array or is empty, or its first element is non-numeric", conf_loader_path(cl));
    else {
        me->version = json_number_get_double(value);
        goto OUT;
    }

    if (me->object) {
        cJSON_Delete(me->object);
        me->object = NULL;
    }

OUT:
    if (content)
        kit_free(content);

    SXER6("return %s;%s%s", me->object ? "true" : "false", me->object ? " // data=" : "", me->object ? json_to_str(me->data) : "");
    return me->object != NULL;
}

void
json_file_fini(struct json_file *me)
{
    cJSON_Delete(me->object);
}

