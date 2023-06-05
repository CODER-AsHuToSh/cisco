#include <errno.h>
#include <kit-alloc.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>

#if __FreeBSD__
#include <stdio.h>
#endif

#include "conf-info.h"
#include "pref-segments.h"

#define CONF_DIRECTORY_MAXLEN   (PATH_MAX - 64)    /* Leave room in path for config file names             */

static const char *conf_info_directory;       /* Under which all conf is found */
static int conf_info_relative_offset = -1;    /* Offset past conf_info_directory and '/' */

void
conf_info_init(const char *confdir)
{
    static bool initialized = false;

    SXEE6("(confdir=%s)", confdir ?: "<NULL>");

    SXEA1(!initialized, "conf_info_init() called more than once");
    conf_info_directory = confdir;
    conf_info_relative_offset = confdir ? strlen(confdir) + 1 : 0;    /* The 1 is for the '/' */
    SXEA1(conf_info_relative_offset <= CONF_DIRECTORY_MAXLEN, "conf_init called with confdir of %u characters, maximum is %u",
          conf_info_relative_offset - 1, CONF_DIRECTORY_MAXLEN - 1);
    initialized = true;

    SXER6("return");
}

const char *
conf_info_relative_path(const char *path)
{
    SXEA6(!conf_info_directory || (strncmp(path, conf_info_directory, conf_info_relative_offset - 1) == 0 && path[conf_info_relative_offset - 1] == '/'),
          "%s(): Path '%s' is not in conf info directory '%s'!", __FUNCTION__, path, conf_info_directory);
    return path + conf_info_relative_offset;
}

void
conf_info_assert_pathok(const char *path)
{
    SXEA1(conf_info_relative_offset != -1, "%s() without conf_info_init()", __FUNCTION__);
    SXEA1(conf_info_directory == NULL || *path != '/', "Cannot register absolute path '%s' with config directory '%s'", path, conf_info_directory);
}

struct conf_info *
conf_info_new(const struct conf_type *type, const char *name, const char *path, const struct conf_segment_ops *seg,
              uint32_t loadflags, const void *userdata, size_t userdatalen)
{
    struct conf_info *info;
    size_t namelen, pathlen, sz;

    SXEA1(conf_info_relative_offset != -1, "%s() without conf_info_init()", __FUNCTION__);
    SXEA6(!userdatalen || userdata, "userdatalen given without userdata");

    namelen = strlen(name);
    pathlen = conf_info_relative_offset + strlen(path);
    sz = sizeof(*info) + namelen + 1 + pathlen + 1;
    SXEA1(info = kit_calloc(1, sz), "Cannot create a new conf_info size %zu for '%s'", sz, name);
    info->type = type;
    info->loadflags = loadflags;
    info->userdata = userdatalen ? kit_malloc(userdatalen) : NULL;
    memcpy(info->userdata, userdata, userdatalen);
    info->path = (char *)(info + 1) + namelen + 1;
    strcpy(info->name, name);
    snprintf(info->path, pathlen + 1, "%s%s%s", conf_info_directory ?: "", conf_info_directory ? "/" : "", path);

    if ((info->seg = seg))
        SXEA1(info->manager = pref_segments_new(info->path), "%s: Failed to register a manager", info->path);

    return info;
}

void
conf_info_free(struct conf_info *info)
{
    if (info) {
        SXEL6("%s(info=?) {} // name=%s, path=%s", __FUNCTION__, info->name, info->path);

        SXEA6(!info->refcount, "Cannot drop a conf_info with references");
        if (info->manager)
            pref_segments_free(info->manager);
        kit_free(info->userdata);
        kit_free(info);
    }
}

bool
conf_info_ischanged(const struct conf_info *info)
{
    char path[PATH_MAX];
    bool ischanged;
    struct stat st;

    if (info->manager) {
        if (info->manager->state == SEGMENT_STATE_NEW) {
            ischanged = pref_segments_ischanged(info->manager);
        } else {
            /* Manager has already started and was re-queued */
            ischanged = true;
        }
    } else if (stat(info->path, &st) == -1 && errno == ENOENT) {
        snprintf(path, sizeof(path), "%s.gz", info->path);
        ischanged = stat(path, &st) == -1 && errno == ENOENT ? !!info->st.ino : 0;
    } else
        ischanged = info->st.dev != st.st_dev || info->st.ino != st.st_ino || info->st.size != st.st_size || info->st.mtime != st.st_mtime;

    if (ischanged)
        SXEL7("%s(info=?) {} // changed, name=%s, path=%s", __FUNCTION__, info->name, info->path);

    return ischanged;
}
