#include <kit-alloc.h>
#include <mockfail.h>

#include "conf-loader.h"
#include "conf-meta.h"
#include "parseline.h"

struct conf_meta *
conf_meta_new(struct conf_loader *cl, unsigned lines)
{
    const char *key, *line, *val;
    struct conf_meta *me, *retme;
    size_t klen, vlen;
    int fields;
    unsigned i;

    SXEE6("(cl=?, lines=%u) // path=%s", lines, conf_loader_path(cl));

    retme = NULL;
    if ((me = MOCKFAIL(CONF_META_ALLOC, NULL, kit_calloc(1, sizeof(*me)))) == NULL) {
        SXEL2("%s: %u: Cannot allocate %zu conf-meta bytes", conf_loader_path(cl), conf_loader_line(cl), sizeof(*me));
        goto SXE_EARLY_OUT;
    }
    for (i = 0; i < lines; i++) {
        if ((line = conf_loader_readline(cl)) == NULL) {
            SXEL2("%s: %u: Found %u meta lines, expected %u", conf_loader_path(cl), conf_loader_line(cl), i, lines);
            goto SXE_EARLY_OUT;
        }
        fields = parseline_spaces(line, &key, &klen, &val, &vlen);
        if (fields == 2) {
            if (word_match("name", key, klen)) {
                kit_free(me->name);
                if ((me->name = MOCKFAIL(CONF_META_NAMEALLOC, NULL, kit_malloc(vlen + 1))) == NULL) {
                    SXEL2("%s: %u: Cannot allocate %zu name bytes", conf_loader_path(cl), conf_loader_line(cl), vlen + 1);
                    goto SXE_EARLY_OUT;
                }
                memcpy(me->name, val, vlen);
                me->name[vlen] = '\0';
            } else
                SXEL6("conf-meta: Skipping unrecognized meta key '%.*s'", (int)klen, key);
        } else
            SXEA1(fields == 1, "parseline gave %d fields", fields);
    }

    retme = me;

SXE_EARLY_OUT:
    if (retme == NULL)
        conf_meta_free(me);

    SXER6("return %p // %u records", retme, retme ? lines : 0);

    return retme;
}

void
conf_meta_free(struct conf_meta *me)
{
    if (me) {
        kit_free(me->name);
        kit_free(me);
    }
}
