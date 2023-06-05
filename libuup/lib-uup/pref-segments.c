#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <kit-alloc.h>
#include <kit.h>
#include <mockfail.h>
#include <string.h>
#include <sys/stat.h>

#if __FreeBSD__
#include <stdio.h>
#include <sys/param.h>
#endif

#include "pref-segments.h"

#if SXE_DEBUG
/*
 * Print out the state of the segment management conf job
 */
struct {
    enum segment_state state;
    const char *txt;
} segment_state_txt[] = {
        { SEGMENT_STATE_NEW, "NEW" },
        { SEGMENT_STATE_REQUEUED, "REQUEUED" },
        { SEGMENT_STATE_RUNNING, "RUNNING" }
};

const char *
segment_state_to_str(enum segment_state state)
{
    unsigned i;
    for (i = 0; i < sizeof(segment_state_txt); i++) {
        if (state == segment_state_txt[i].state) {
            return segment_state_txt[i].txt;
        }
    }
    return "UNKNOWN";
}
#endif

static struct prefdir *
prefdir_new_branch(struct kit_fsevent *fsev, char *path, const char *sub)
{
    struct prefdir *me;
    size_t dlen, glen, slen;
    const char *glob, *mon;

    glob = kit_basename(path);
    dlen = glob == path ? 0 : glob - path - 1;
    glen = strlen(glob);
    slen = sub ? strlen(sub) : 0;

    if ((me = MOCKFAIL(PREF_SEGMENTS_PREFDIR_NEW_BRANCH, NULL, kit_malloc(sizeof(*me) + dlen + glen + slen))) == NULL)
        SXEL2("Couldn't allocate a struct prefdir with %zu extra bytes", dlen + glen + slen);
    else {
        SLIST_INIT(&me->file);
        SLIST_INIT(&me->subdir);

        memcpy(me->path, path, dlen);
        me->path[dlen] = '\0';
        me->dlen = dlen;

        memcpy(me->path + dlen + 1, glob, glen);
        me->path[dlen + 1 + glen] = '\0';
        me->glen = glen;

        if (sub)
            memcpy(me->path + dlen + 1 + glen + 1, sub, slen);
        me->path[dlen + 1 + glen + 1 + slen] = '\0';

        mon = *PREFDIR_DIR(me) ? PREFDIR_DIR(me) : ".";
        me->wd = kit_fsevent_add_watch(fsev, mon, KIT_FSEVENT_CREATE|KIT_FSEVENT_DELETE|KIT_FSEVENT_MOVED_TO|KIT_FSEVENT_MOVED_FROM|KIT_FSEVENT_MODIFY);
        SXEL6("%s(): Watching %s for %s matching %s", __FUNCTION__, mon, PREFDIR_ISLEAF(me) ? "files" : "directories", PREFDIR_GLOB(me));
    }

    return me;
}

static struct preffile *
preffile_new(const char *dir, const char *base, const char *glob)
{
    struct preffile *me;
    size_t len, flen, pos;
    const char *baseptr, *globptr;
    uint32_t id;

    flen = strlen(baseptr = base);

    globptr = glob;
    for (pos = 0; baseptr[pos] == globptr[pos] && baseptr[pos] != '\0'; baseptr++, globptr++)
        ;
    if (globptr[pos] != baseptr[pos]) {
        SXEA6(globptr[pos] == '?' && globptr[pos + 1] == '*', "Unexpected preffile glob match");
        len = flen - strlen(glob) + 2;
        SXEA6(len > 0 && len < flen, "Unexpected digit match length %zu", len);
        for (id = 0; len--; pos++) {
            if (!isdigit(baseptr[pos]))
                return NULL;
            id *= 10;
            id += baseptr[pos] - '0';
        }
    } else
        id = 0;

    SXEL7("Adding file '%s' to directory '%s' (id %u, glob '%s')", base, *dir ? dir : ".", id, glob);

    len = strlen(dir);
    if ((me = MOCKFAIL(PREF_SEGMENTS_PREFFILE_NEW, NULL, kit_malloc(sizeof(*me) + len + 1 + flen))) == NULL)
        SXEL2("Couldn't allocate preffile struct with %zu extra bytes", len + 1 + flen);
    else {
        if (len) {
            memcpy(me->path, dir, len);
            me->path[len] = '/';
        } else
            len = -1;
        memcpy(me->path + len + 1, base, flen);
        me->path[len + 1 + flen] = '\0';
        me->id = id;
        me->flags = me->private_flags = PREFFILE_CLEAN;
        me->epoch = 0;
    }

    return me;
}

struct preffile *
preffile_copy(const struct preffile *me)
{
    struct preffile *copy = NULL;
    size_t len;

    if (me) {
         len = strlen(me->path);
         if ((copy = MOCKFAIL(PREF_SEGMENTS_PREFFILE_COPY, NULL, kit_malloc(sizeof(*copy) + len))) == NULL)
             SXEL2("Couldn't allocate a preffile copy");
         else
             memcpy(copy, me, sizeof(*copy) + len);
    }

    return copy;
}

void
preffile_free(struct preffile *me)
{
    kit_free(me);
}

static struct prefdir *prefdir_new(struct preffile_list *dirty, struct kit_fsevent *fsev, const char *path);

static void
prefdir_parse(struct prefdir *me, struct preffile_list *dirty, struct kit_fsevent *fsev, const char *sub)
{
    char newpath[PATH_MAX];
    struct prefdir *subdir;
    struct preffile *file;
    struct dirent *ent;
    const char *dir;
    struct stat st;
    size_t sz;
    DIR *d;

    dir = *PREFDIR_DIR(me) ? PREFDIR_DIR(me) : ".";
    SXEL7("Reading new directory: %s", dir);
    if ((d = opendir(dir)) == NULL) {
        SXEL7("%s: Cannot open directory", dir);
        return;
    }

    while ((ent = readdir(d)) != NULL)
        if (fnmatch(PREFDIR_GLOB(me), ent->d_name, FNM_PATHNAME|FNM_PERIOD) == 0) {
            sz = snprintf(newpath, sizeof(newpath), "%s%s%s", PREFDIR_DIR(me), *PREFDIR_DIR(me) ? "/" : "", ent->d_name);
            if (sz < sizeof(newpath) && stat(newpath, &st) == 0) {
                if (sub && S_ISDIR(st.st_mode)) {
                    /* Add an entire prefdir tree to our subdir list */
                    sz += snprintf(newpath + sz, sizeof(newpath) - sz, "/%s", sub);
                    if (sz < sizeof(newpath)) {
                        if ((subdir = prefdir_new(dirty, fsev, newpath)) != NULL)
                            SLIST_INSERT_HEAD(&me->subdir, subdir, next);
                    } else
                        SXEL3("Discarding '%s%s%s/%s: path too long", PREFDIR_DIR(me), *PREFDIR_DIR(me) ? "/" : "", ent->d_name, sub);
                } else if (!sub && !S_ISDIR(st.st_mode) && (file = preffile_new(PREFDIR_DIR(me), ent->d_name, PREFDIR_GLOB(me))) != NULL) {
                    SLIST_INSERT_HEAD(&me->file, file, next);
                    STAILQ_INSERT_TAIL(dirty, file, dirty);
                    file->private_flags |= PREFFILE_ADDED;
                }
            } else
                SXEL6("Discarding '%s%s%s/...: path too long", PREFDIR_DIR(me), *PREFDIR_DIR(me) ? "/" : "", ent->d_name);
        }

    closedir(d);
}

static void
prefdir_free(struct prefdir *me, struct kit_fsevent *fsev, struct preffile_list *dirty)
{
    struct prefdir *subdir;
    struct preffile *file;

    if (me) {
        while ((file = SLIST_FIRST(&me->file)) != NULL) {
            SLIST_REMOVE_HEAD(&me->file, next);
            if (!dirty)
                kit_free(file);
            else {
                if (!file->private_flags)
                    STAILQ_INSERT_TAIL(dirty, file, dirty);
                file->private_flags |= PREFFILE_REMOVED;
                file->epoch = 0;
            }
        }
        while ((subdir = SLIST_FIRST(&me->subdir)) != NULL) {
            SLIST_REMOVE_HEAD(&me->subdir, next);
            prefdir_free(subdir, fsev, dirty);
        }
        kit_fsevent_rm_watch(fsev, me->wd);
        SXEL6("%s(): Stopped watching %s for %s matching %s",
              __FUNCTION__, *PREFDIR_DIR(me) ? PREFDIR_DIR(me) : ".",
              PREFDIR_ISLEAF(me) ? "files" : "directories", PREFDIR_GLOB(me));
        kit_free(me);
    }
}

static struct prefdir *
prefdir_new(struct preffile_list *dirty, struct kit_fsevent *fsev, const char *path)
{
    const char *last, *ptr, *slash;
    char dir[PATH_MAX];
    struct prefdir *me;
    int wild;

    last = NULL;
    wild = 0;
    for (ptr = path; ; ptr++) {
        switch (*ptr) {
        case '?':
        case '*':
            wild = 1;
            break;
        case '%':
            if (ptr[1] == 'u') {
                if (last) {
                    SXEL3("%s: multiple %%u patterns are not allowed", path);
                    return NULL;
                }
                last = ptr;
            }
            break;
        case '/':
            if (last) {
                SXEL3("%s: a %%u pattern in a subdirectory is not allowed", path);
                return NULL;
            }
            if (!wild)
                break;
            /* FALLTHRU */
        case '\0':
            if (wild) {
                if (*ptr == '\0') {
                    SXEL3("%s: wildcards in last path component are invalid (only %%u is allowed)", path);
                    return NULL;
                }
                /*
                 * The following checks are important to early out at creation
                 * time rather than later when missing path components turn up.
                 */
                slash = strrchr(ptr, '/');
                if (!(last = strstr(ptr, "%u")) || (slash && slash > last)) {
                    SXEL3("%s: wildcard paths must have %%u in the final component", path);
                    return NULL;
                }
                if (strchr(slash ? slash : ptr, '?') || strchr(slash ? slash : ptr, '*')) {
                    SXEL3("%s: wildcards in last path component are invalid (only %%u is allowed)", path);
                    return NULL;
                }
                if (strstr(last + 1, "%u")) {
                    SXEL3("%s: multiple %%u patterns are not allowed", path);
                    return NULL;
                }
                last = NULL;
            }
            if ((size_t)(ptr - path) >= sizeof(dir)) {
                SXEL3("%.*s...: Path too long", (int)sizeof(dir) / 5, path);
                return NULL;
            }
            SXEL7("%s(): Parsed '%s', wild is %sset, last is %sset, %zu characters",
                  __FUNCTION__, path, wild ? "" : "un", last ? "" : "un", ptr - path);
            memcpy(dir, path, ptr - path);
            dir[ptr - path] = '\0';
            ptr = *ptr ? ptr + 1 : NULL;
            if (last) {
                dir[last - path] = '?';
                dir[last - path + 1] = '*';
            }
            if ((me = prefdir_new_branch(fsev, dir, ptr)) != NULL)
                prefdir_parse(me, dirty, fsev, ptr);
            return me;
        }
    }
}

struct pref_segments *
pref_segments_new(const char *path)
{
    struct pref_segments *me;
    size_t len;

    SXEE6("(path=%s)", path);

    /*
     * paths may contain wildcard characters in their path components, but
     * not in the filename part.
     */

    SXEA1(me = kit_malloc(sizeof(*me)), "Cannot allocate a pref_segments structure");
    len = strlen(path);
    SXEA1(me->path = kit_malloc(len + 1), "Cannot allocate pref_segments path (length %zu)", len);
    kit_fsevent_init(&me->fsev);
    STAILQ_INIT(&me->dirty);
    SLIST_INIT(&me->free);
    strcpy(me->path, path);

    me->state = SEGMENT_STATE_NEW;
    SXEA1(pthread_mutex_init(&me->lock, NULL) == 0,  "Can't initialize pref-segments mutex: %s", strerror(errno));

    if ((me->hier = prefdir_new(&me->dirty, &me->fsev, path)) == NULL) {
        pref_segments_free(me);
        me = NULL;
    }

    SXER6("return me=%p", me);
    return me;
}

void
pref_segments_free(struct pref_segments *me)
{
    SXEE6("(me=%p)", me);
    struct preffile *file;

    if (me) {
        while (STAILQ_FIRST(&me->dirty) != NULL)
            STAILQ_REMOVE_HEAD(&me->dirty, dirty);

        while ((file = SLIST_FIRST(&me->free)) != NULL) {
            SLIST_REMOVE_HEAD(&me->free, next);
            kit_free(file);
        }

        prefdir_free(me->hier, &me->fsev, NULL);
        kit_fsevent_fini(&me->fsev);
        kit_free(me->path);
        kit_free(me);
    }

    SXER6("return");
}

static struct prefdir *
prefdir_find(struct prefdir *me, int wd)
{
    struct prefdir *subdir, *found;

    if (me->wd == wd)
        return me;

    found = NULL;
    SLIST_FOREACH(subdir, &me->subdir, next)
        if ((found = prefdir_find(subdir, wd)) != NULL)
            break;

    return found;
}

static bool
preffile_matches_base(struct preffile *me, const char *base)
{
    size_t flen, len;

    len = strlen(base);
    flen = strlen(me->path);
    if (flen == len || (flen > len && me->path[flen - len - 1] == '/'))
        return strcmp(me->path + flen - len, base) == 0;

    return false;
}

static bool
prefdir_matches_base(struct prefdir *me, const char *base)
{
    size_t len;

    len = strlen(base);
    if (me->dlen == len || (me->dlen > len && PREFDIR_DIR(me)[me->dlen - len - 1] == '/'))
        return strcmp(me->path + me->dlen - len, base) == 0;

    return false;
}

static bool
pref_segments_update(struct pref_segments *me)
{
    struct prefdir *dir, *subdir, *prevdir;
    struct preffile *file, *prevfile;
    struct kit_fsevent_iterator iter;
    char newpath[PATH_MAX];
    kit_fsevent_ev_t *event;
    size_t sz;

    kit_fsevent_iterator_init(&iter);

    while ((event = kit_fsevent_read(&me->fsev, &iter)) != NULL) {
        if (MOCKFAIL(PREF_SEGMENTS_FSEVENT_OVERFLOW, 1, KIT_FSEVENT_EV_ERROR(event)))
            return false;
        if ((dir = prefdir_find(me->hier, KIT_FSEVENT_EV_FD(event))) != NULL && fnmatch(PREFDIR_GLOB(dir), KIT_FSEVENT_EV_NAME(event), FNM_PATHNAME|FNM_PERIOD) == 0) {
            if (PREFDIR_ISLEAF(dir)) {
                /* File operation */
                if (!KIT_FSEVENT_EV_ISDIR(event)) {
                    prevfile = NULL;
                    SLIST_FOREACH(file, &dir->file, next) {
                        if (preffile_matches_base(file, KIT_FSEVENT_EV_NAME(event)))
                            break;
                        prevfile = file;
                    }
                    if (KIT_FSEVENT_EV_IS(event, KIT_FSEVENT_CREATE|KIT_FSEVENT_MOVED_TO)) {
                        SXEL6("kit_fsevent: File %s created (%s)", KIT_FSEVENT_EV_NAME(event), file ? "already existed" : "didn't previously exist");
                        if (file != NULL) {
                            /* something was moved on top of an existing file */
                            if (!file->private_flags)
                                STAILQ_INSERT_TAIL(&me->dirty, file, dirty);
                            file->private_flags |= PREFFILE_MODIFIED;
                            file->epoch = 0;
                        } else if ((file = preffile_new(PREFDIR_DIR(dir), KIT_FSEVENT_EV_NAME(event), PREFDIR_GLOB(dir))) != NULL) {
                            SLIST_INSERT_HEAD(&dir->file, file, next);
                            STAILQ_INSERT_TAIL(&me->dirty, file, dirty);
                            file->private_flags |= PREFFILE_ADDED;
                        }
                    } else if (KIT_FSEVENT_EV_IS(event, KIT_FSEVENT_DELETE|KIT_FSEVENT_MOVED_FROM)) {
                        SXEL6("kit_fsevent: File %s deleted (%s)", KIT_FSEVENT_EV_NAME(event), file ? "already existed" : "didn't previously exist");
                        if (file != NULL) {
                            if (prevfile)
                                SLIST_REMOVE_AFTER(prevfile, next);
                            else
                                SLIST_REMOVE_HEAD(&dir->file, next);
                            if (!file->private_flags)
                                STAILQ_INSERT_TAIL(&me->dirty, file, dirty);
                            file->private_flags |= PREFFILE_REMOVED;
                            file->epoch = 0;
                        }
                    } else if (KIT_FSEVENT_EV_IS(event, KIT_FSEVENT_MODIFY)) {
                        SXEL6("kit_fsevent: File %s modified (%s)", KIT_FSEVENT_EV_NAME(event), file ? "already existed" : "didn't previously exist");
                        if (file != NULL) {
                            if (!file->private_flags)
                                STAILQ_INSERT_TAIL(&me->dirty, file, dirty);
                            file->private_flags |= PREFFILE_MODIFIED;
                            file->epoch = 0;
                        } else {
                            SXEA6(0, "%s/%s: File modified, but I didn't already know about it!", PREFDIR_DIR(dir), KIT_FSEVENT_EV_NAME(event));
                            if ((file = preffile_new(PREFDIR_DIR(dir), KIT_FSEVENT_EV_NAME(event), PREFDIR_GLOB(dir))) != NULL) {
                                SLIST_INSERT_HEAD(&dir->file, file, next);
                                STAILQ_INSERT_TAIL(&me->dirty, file, dirty);
                                file->private_flags |= PREFFILE_MODIFIED;    /* COVERAGE EXCLUSION: Don't know how to "miss" a file turning up!! */
                            }
                        }
                    } else
                        SXEA6(0, "Unexpected kit_fsevent event mask %u", KIT_FSEVENT_EV_IS(event, 0xffff));
                }
            } else {
                /* Structure operation */
                if (KIT_FSEVENT_EV_ISDIR(event)) {
                    if (KIT_FSEVENT_EV_IS(event, KIT_FSEVENT_CREATE|KIT_FSEVENT_MOVED_TO|KIT_FSEVENT_DELETE|KIT_FSEVENT_MOVED_FROM)) {
                        prevdir = NULL;
                        SLIST_FOREACH(subdir, &dir->subdir, next) {
                            if (prefdir_matches_base(subdir, KIT_FSEVENT_EV_NAME(event))) {
                                if (prevdir)
                                    SLIST_REMOVE_AFTER(prevdir, next);
                                else
                                    SLIST_REMOVE_HEAD(&dir->subdir, next);
                                prefdir_free(subdir, &me->fsev, &me->dirty);
                                break;
                            }
                            prevdir = subdir;
                        }
                        if (KIT_FSEVENT_EV_IS(event, KIT_FSEVENT_CREATE|KIT_FSEVENT_MOVED_TO)) {
                            sz = snprintf(newpath, sizeof(newpath), "%s%s%s", PREFDIR_DIR(dir), *PREFDIR_DIR(dir) ? "/" : "", KIT_FSEVENT_EV_NAME(event));
                            if (sz < sizeof(newpath)) {
                                SXEA6(subdir == NULL, "%s: Directory created, but I already knew about it!", newpath);
                                SXEL6("kit_fsevent: Directory %s created", newpath);
                                sz += snprintf(newpath + sz, sizeof(newpath) - sz, "/%s", PREFDIR_SUB(dir));
                                if (sz < sizeof(newpath) && (subdir = prefdir_new(&me->dirty, &me->fsev, newpath)) != NULL)
                                    SLIST_INSERT_HEAD(&dir->subdir, subdir, next);
                           } else
                               SXEL6("Discarding '%s%s%s/...: path too long", PREFDIR_DIR(dir), *PREFDIR_DIR(dir) ? "/" : "", KIT_FSEVENT_EV_NAME(event));
                        } else if (KIT_FSEVENT_EV_IS(event, KIT_FSEVENT_DELETE|KIT_FSEVENT_MOVED_FROM))
                            SXEL6("kit_fsevent: Directory %s deleted (%s)", KIT_FSEVENT_EV_NAME(event), subdir ? "and un-monitored" : "but not monitored");
                    } else
                        SXEA6(KIT_FSEVENT_EV_IS(event, KIT_FSEVENT_MODIFY), "Unexpected kit_fsevent event mask %u", KIT_FSEVENT_EV_IS(event, 0xffff));
                }
            }
        }
    }

    return true;
}

static void
pref_segments_reset(struct pref_segments *me)
{
    struct prefdir *hier;
    struct kit_fsevent nfsev;

    SXEL3("Reloading %s (kit_fsevent overflow) - %s", me->path, KIT_FSEVENT_ERRCHK);

    while (STAILQ_FIRST(&me->dirty) != NULL)
        STAILQ_REMOVE_HEAD(&me->dirty, dirty);
    kit_fsevent_init(&nfsev);
    SXEA1(hier = prefdir_new(&me->dirty, &nfsev, me->path), "Couldn't re-create kit_fsevent setup for %s", me->path);
    prefdir_free(me->hier, &me->fsev, NULL);
    kit_fsevent_fini(&me->fsev);
    me->fsev = nfsev;
    me->hier = hier;
}

bool
pref_segments_ischanged(struct pref_segments *me)
{
    struct preffile *dirty;
    uint64_t now;

    if (!pref_segments_update(me))
        pref_segments_reset(me);

    now = 0;
    STAILQ_FOREACH(dirty, &me->dirty, dirty) {
        if (!dirty->epoch)
            return true;
        if (!now)
            now = kit_time_nsec();
        if (dirty->epoch <= now)
            return true;
        /* This entry isn't ready yet... keep looking */
    }
    return false;
}

const struct preffile *
pref_segments_changed(struct pref_segments *me)
{
    struct preffile *dirty, *next, *prev;
    uint64_t now;

    /* Only update the segment list at the beginning of the load */
    if ((me->state == SEGMENT_STATE_NEW) && !pref_segments_update(me))
        pref_segments_reset(me);

    while ((dirty = SLIST_FIRST(&me->free)) != NULL) {
        SLIST_REMOVE_HEAD(&me->free, next);
        kit_free(dirty);
    }

    now = 0;
    prev = NULL;
    STAILQ_FOREACH_SAFE(dirty, &me->dirty, dirty, next) {
        SXEA6(dirty->private_flags != PREFFILE_CLEAN, "Oops, found a clean preffile in the dirty list");
        if (dirty->epoch) {
            if (!now)
                now = kit_time_nsec();
            if (dirty->epoch > now) {
                prev = dirty;
                dirty = NULL;
                continue;    /* don't return this (yet) */
            }
        }
        dirty->flags = dirty->private_flags;
        dirty->private_flags = PREFFILE_CLEAN;
        if (prev)
            STAILQ_REMOVE_AFTER(&me->dirty, prev, dirty);
        else
            STAILQ_REMOVE_HEAD(&me->dirty, dirty);
        if (dirty->flags & PREFFILE_REMOVED)
            SLIST_INSERT_HEAD(&me->free, dirty, next);
        break;
    }

    return dirty;
}

bool
pref_segments_setpath(struct pref_segments *me, const char *path)
{
    struct preffile_list dirtylist;
    struct preffile *dirty;
    struct prefdir *hier;
    struct kit_fsevent nfsev;
    char *npath;
    size_t len;

    if (strcmp(me->path, path) == 0)
        return true;

    SXEL6("pref-segments path changed: '%s' => '%s'", me->path, path);
    len = strlen(path);
    SXEA1(npath = kit_malloc(len + 1), "Failed to realloc path length %zu", len + 1);
    STAILQ_INIT(&dirtylist);
    kit_fsevent_init(&nfsev);
    if ((hier = prefdir_new(&dirtylist, &nfsev, path)) == NULL) {
        /* Oops, no-go! */
        SXEA6(STAILQ_FIRST(&dirtylist) == NULL, "%s: prefdir_new() failed, but left garbage in the dirty list", path);
        kit_free(npath);
        kit_fsevent_fini(&nfsev);
        return false;
    }
    kit_free(me->path);
    me->path = npath;
    strcpy(me->path, path);

    prefdir_free(me->hier, &me->fsev, &me->dirty);
    kit_fsevent_fini(&me->fsev);
    while ((dirty = STAILQ_FIRST(&dirtylist)) != NULL) {
        STAILQ_REMOVE_HEAD(&dirtylist, dirty);
        STAILQ_INSERT_TAIL(&me->dirty, dirty, dirty);
    }
    me->fsev = nfsev;
    me->hier = hier;

    return true;
}

#if SXE_DEBUG
static struct preffile *
prefdir_findfile(struct prefdir *me, const struct preffile *pf)
{
    struct prefdir *subdir;
    struct preffile *found;

    SLIST_FOREACH(found, &me->file, next)
        if (pf == found)
            return found;

    SLIST_FOREACH(subdir, &me->subdir, next)
        if ((found = prefdir_findfile(subdir, pf)) != NULL)
            return found;

    return NULL;
}
#endif

void
pref_segments_retry(struct pref_segments *me, const struct preffile *pf, unsigned timeout)
{
    bool requeue;
    union {
        const struct preffile *constpf;
        struct preffile *pf;
    } u;

    requeue = false;
    if (pf->private_flags == PREFFILE_CLEAN) {
        if (pf->flags & PREFFILE_REMOVED) {
            if (SLIST_FIRST(&me->free) == pf) {
                SLIST_REMOVE_HEAD(&me->free, next);
                requeue = true;
            } else
                SXEA6(0, "Couldn't find preffile %s in free list", pf->path);
        } else {
            SXEA6(prefdir_findfile(me->hier, pf) == pf, "Couldn't find unhandled preffile %s", pf->path);
            requeue = true;
        }

    } else
        SXEA6(0, "%s: Invalid preffile - not returned from pref_segments_changed() recently enough!", pf->path);

    if (requeue) {
        u.constpf = pf;    /* de-constify *OUR* pointer - we believe the caller in non-SXE_DEBUG code */
        u.pf->private_flags = u.pf->flags | PREFFILE_RETRY;
        u.pf->flags = PREFFILE_CLEAN;
        u.pf->epoch = kit_time_nsec() + timeout * 1000000000ULL;
        STAILQ_INSERT_TAIL(&me->dirty, u.pf, dirty);
    }
}
