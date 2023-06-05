#include <errno.h>
#include <kit-alloc.h>
#include <kit.h>
#include <mockfail.h>

#include "conf-loader.h"
#include "key-value-config.h"
#include "parseline.h"

struct sxel5_output_arg {
    const char *base_name;
};

static __printflike(3, 4) size_t
sxel5_output(const char *key, void *v, const char *fmt, ...)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    struct sxel5_output_arg *arg = v;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    char buf[256];
    va_list ap;
    size_t ret;

    va_start(ap, fmt);                               /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    ret = vsnprintf(buf, sizeof(buf), fmt, ap);      /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    va_end(ap);                                      /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    SXEL5("%s::%s=%s", arg->base_name, key, buf);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    return ret;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

/**
 * Allocate, initialize, and load a configuration structure of the type defined by the key_value_entry parameters
 *
 * @return A pointer to the 'struct conf' embedded in the configuration structure.
 */
struct conf *
key_value_config_new(struct conf_loader *cl,
                     size_t config_size,
                     size_t conf_offset,
                     const void *defaults,
                     const struct key_value_entry *config,
                     const unsigned config_entries,
                     const struct conf_type *kv_ct,
                     void (*pre_fn)(void *),
                     bool (*post_fn)(void *, struct conf_loader *))
{
    const char             *line, *key, *value;
    uint8_t                *me;
    struct conf            *ret = NULL;
    size_t                  key_len, value_len;
    struct key_value_source source;
    int                     optional;
    unsigned                n;
    struct sxel5_output_arg arg;

    SXEA6(config_size >= conf_offset + sizeof(struct conf),
          "The key value config must at least have room for the embedded struct conf");

    if ((me = MOCKFAIL(key_value_config_new, NULL, kit_malloc(config_size))) == NULL) {
        SXEL2("Failed to allocate options");    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        goto OUT;                               /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    if (defaults)    // Set any default values
        memcpy(me, defaults, config_size);

    if (pre_fn)    // Execute any additional initializations
        pre_fn(me);

    conf_setup((struct conf *)(me + conf_offset), kv_ct);
    SXEL4("key-value:: // parsing file: %s", conf_loader_path(cl));

    while ((line = conf_loader_readline(cl)) != NULL) {
        if (parseline_spaces(line, &key, &key_len, &value, &value_len) == 2) {
            if (key_len > 1 && key[key_len - 1] == '?') {          /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                key_len--;                                         /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                optional = 1;                                      /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            } else
                optional = 0;                                      /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

            for (n = 0; n < config_entries; n++)                   /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                if (word_match(config[n].name, key, key_len)) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                    source.fn = conf_loader_path(cl);              /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                    source.lineno = conf_loader_line(cl);          /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                    source.key = config[n].name;                   /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                    SXEA6(config[n].offset < config_size,
                          "Entry %.*s's offset %zu is invalid in a %zu byte config structure", (int)key_len, key,
                          config[n].offset, config_size);
                    SXEA6(config[n].offset < conf_offset || config[n].offset >= conf_offset + sizeof(struct conf),
                          "Entry %.*s's offset %zu is inside the %zu byte conf structure at offset %zu", (int)key_len, key,
                          config[n].offset, sizeof(struct conf), conf_offset);

                    if (!config[n].text_to_entry(&source, me + config[n].offset, value, value_len, &config[n].params))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                        goto OUT;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

                    arg.base_name = kit_basename(conf_loader_path(cl));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                    config[n].entry_format(config[n].name, (const char *)me + config[n].offset, &arg, sxel5_output);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

                    break;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                }

            if (n == config_entries) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                if (optional)             /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                    SXEL3("%s:%u: '%.*s': Unrecognised key (ignored; marked as optional)", conf_loader_path(cl), conf_loader_line(cl), (int)key_len, key);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                else {
                    SXEL2("%s:%u: '%.*s': Unrecognised key", conf_loader_path(cl), conf_loader_line(cl), (int)key_len, key);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                    goto OUT;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                }
            }
        } else {
            SXEL2("%s:%u: Not a key value pair", conf_loader_path(cl), conf_loader_line(cl));
            goto OUT;
        }
    }

    if (conf_loader_eof(cl)) {                      /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        if (post_fn)                                /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            /* Execute and post-processing */
            if (!post_fn(me, cl))                   /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                goto OUT;                           /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

        ret = (struct conf *)(me + conf_offset);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

OUT:
    if (!ret) {
        conf_refcount_dec((struct conf *)(me + conf_offset), CONFSET_FREE_IMMEDIATE);
        errno = EINVAL;
    }

    return ret;
}
