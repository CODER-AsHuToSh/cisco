#include <dirent.h>
#include <errno.h>
#include <kit.h>
#include <stdio.h>

#include "conf.h"
#include "digest-store.h"

/*
 * This module is used entirely from the main config thread, so no __thread is necessary...
 */
static unsigned    store_changed;
static time_t      store_time;
static const char *store_dir    = NULL;
static unsigned    store_freq   = DIGEST_STORE_DEFAULT_UPDATE_FREQ;
static unsigned    store_maxage = DIGEST_STORE_DEFAULT_MAXIMUM_AGE;

/**
 * Set the options for storing digests. May be called dynamically to update the options.
 *
 * @param dir        Name of the directory in which to store the digests
 * @param freq       Update frequency in seconds
 * @param maxage     Maximum age in seconds
 */
void
digest_store_set_options(const char *dir, unsigned freq, unsigned maxage)
{
    store_dir    = dir;
    store_freq   = freq;
    store_maxage = maxage;
}

static void
digest_store_purge(const char *dir, DIR *dsd, time_t now, time_t expire)
{
    unsigned long found;
    struct dirent *ent;
    char fn[PATH_MAX];
    size_t dlen, flen;
    char *end;

    dlen = 0;
    while ((ent = readdir(dsd)) != NULL)
        if ((found = kit_strtoul(ent->d_name, &end, 10)) != 0 && end > ent->d_name && !*end && errno == 0) {
            /* Numeric */
            if (found <= (unsigned long)expire || found > (unsigned long)now) {
                if (!dlen && (dlen = snprintf(fn, sizeof(fn), "%s/", dir)) >= sizeof(fn) - 1) {
                    SXEL2("digest store path too deep (%zu bytes), no room for base part!", dlen);
                    break;    /* COVERAGE EXCLUSION: todo: test with ridiculous path */
                }
                if ((flen = snprintf(fn + dlen, sizeof(fn) - dlen, "%s", ent->d_name)) < sizeof(fn) - dlen)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                    unlink(fn);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            }
        }
}

struct digest_data {
    const char *path;
    FILE *fp;
};

static void
digest_cb(void *v, const char *key, const char *value)
{
    struct digest_data *dd = v;

    fprintf(dd->fp, "%s %s%s%s\n", dd->path, key ?: "", key ? " " : "", value);
}

static void
digest_object_cb(const struct conf *base, const struct conf_info *info, void *data)
{
    struct digest_data dd;

    dd.path = info->name;
    dd.fp = data;
    conf_query_digest(base, info, "", &dd, digest_cb);
}

static void
digest_store_write(const struct confset *conf)
{
    char fn1[PATH_MAX], fn2[PATH_MAX];
    unsigned long found, newest;
    time_t now, expire;
    struct dirent *ent;
    char *end;
    DIR *dsd;
    FILE *fp;

    /* If there is no digest store directory configured, silently early out. This saves a lot of noise in test logs, since
     * tests typically don't configure the digest store directory, and this function gets called periodically.
     */
    if (store_dir == NULL)
        return;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    SXEE7("(conf=%p) // store_dir=%s", conf, store_dir);    // Happens periodically
    now = time(NULL);

    if (now <= store_time + (time_t)store_freq) {
        SXEL7("Current time %lu is not less than last store time %lu + digest store frequency %lu",
                now, store_time, (time_t)store_freq);
        goto OUT;   /* Not yet */
    }

    store_time = now;

    if ((dsd = opendir(store_dir)) != NULL) {
        SXEL7("Opened digest store directory %s", store_dir);
        expire = now - store_maxage;

        if (store_maxage) {
            SXEL7("Digest store maximum age is %d", store_maxage);

            if (!store_changed) {
                /* Try to make a hard link to the newest file */
                newest = 0;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                while ((ent = readdir(dsd)) != NULL)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                    if ((found = kit_strtoul(ent->d_name, &end, 10)) != 0 && end > ent->d_name && !*end && errno == 0) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                        /* Numeric */
                        if (found > newest && found > (unsigned long)expire && found <= (unsigned long)now)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                            newest = found;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                    }
                rewinddir(dsd);
                if (newest) {
                    if (snprintf(fn1, sizeof(fn1), "%s/%lu", store_dir, newest) >= (int)sizeof(fn1)
                     || snprintf(fn2, sizeof(fn2), "%s/%lu", store_dir, (unsigned long)now) >= (int)sizeof(fn2))
                        SXEL2("digest store link: path overflow");                             /* COVERAGE EXCLUSION: todo: use large paths */
                    else if (link(fn1, fn2) == -1)
                        SXEL2("digest store link %s => %s: %s", fn1, fn2, strerror(errno));    /* COVERAGE EXCLUSION: todo: mock link() failure */
                } else
                    store_changed = 1;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            }

            if (store_changed) {
                if (snprintf(fn1, sizeof(fn1), "%s/%lu", store_dir, (unsigned long)now) >= (int)sizeof(fn1))
                    SXEL2("digest store write: path overflow");                /* COVERAGE EXCLUSION: todo: use large paths */
                else if ((fp = fopen(fn1, "wx")) != NULL) {
                    confset_foreach(conf, digest_object_cb, fp);

                    if (fclose(fp) == -1)
                        SXEL2("digest store %s: %s", fn1, strerror(errno));    /* COVERAGE EXCLUSION: todo: emulate no space on device */
                    else
                        store_changed = 0;
                } else
                    SXEL2("digest store %s: %s", fn1, strerror(errno));        /* COVERAGE EXCLUSION: todo: emulate out of inodes */
            }
        }

        digest_store_purge(store_dir, dsd, now, expire);
        closedir(dsd);
    } else
        SXEL2("digest store %s: Cannot open directory", store_dir);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

OUT:
    SXER7("return");    // Happens periodically
}

void
digest_store_changed(const struct confset *conf)
{
    store_changed = 1;
    digest_store_write(conf);
}

void
digest_store_unchanged(const struct confset *conf)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    digest_store_write(conf);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
