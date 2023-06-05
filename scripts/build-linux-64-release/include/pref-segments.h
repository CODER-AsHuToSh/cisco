#ifndef PREF_SEGMENTS_H
#define PREF_SEGMENTS_H

#include <pthread.h>
#include <stdbool.h>

#include "kit-fsevent.h"
#include "kit-queue.h"
                                        /*    for private_flags values    */
                                        /* |  dirty list  |  file list  | */
#define PREFFILE_CLEAN     0x00         /* |       no     |    yes      | */
#define PREFFILE_MODIFIED  0x01         /* |      yes     |    yes      | */
#define PREFFILE_ADDED     0x02         /* |      yes     |    yes      | */
#define PREFFILE_REMOVED   0x04         /* |      yes     |     no      | */
#define PREFFILE_RETRY     0x08         /* pref_segments_retry() was called - might be in the retry list */

struct preffile {
    uint32_t id;                        /* %u value from the original path */
    uint8_t flags;                      /* PREFFILE_* bits above */
    uint8_t private_flags;              /* Only different from flags when PREFFILE_CLEAN */
    uint64_t epoch;                     /* Shouldn't be looked at before this time */
    bool failed;                        /* Previous load attempt failed */
    SLIST_ENTRY(preffile) next;         /* Headed by prefdir's file list */
    STAILQ_ENTRY(preffile) dirty;
    char path[1];                       /* file name */
};

struct prefdir {
    int wd;                             /* watch descriptor */
    SLIST_HEAD(, preffile) file;        /* config_files in this dir */
    SLIST_HEAD(, prefdir) subdir;       /* subdirs in this dir */
    SLIST_ENTRY(prefdir) next;
    uint16_t dlen;                      /* path's dir length */
    uint16_t glen;                      /* path's glob length */
    char path[3];                       /* dir\0glob\0sub\0 */
};

#define PREFDIR_DIR(pd)                 ((pd)->path)
#define PREFDIR_GLOB(pd)                ((pd)->path + (pd)->dlen + 1)
#define PREFDIR_SUB(pd)                 ((pd)->path + (pd)->dlen + 1 + (pd)->glen + 1)
#define PREFDIR_ISLEAF(pd)              (!*PREFDIR_SUB(pd))

STAILQ_HEAD(preffile_list, preffile);

enum segment_state {
    SEGMENT_STATE_NEW,
    SEGMENT_STATE_REQUEUED,
    SEGMENT_STATE_RUNNING
};

#define DEFAULT_PARALLEL_SEGMENTS 10

struct pref_segments {
    struct kit_fsevent fsev;
    char *path;                      /* path (with wildcards etc) used in new() or setpath() */
    struct prefdir *hier;            /* hierarchy of prefdirs being watched */
    struct preffile_list dirty;
    SLIST_HEAD(, preffile) free;

    time_t start;
    unsigned parallel;                       /* Number of segments to queue for parallel loading*/
    enum segment_state state;

    /*
     * Shared state for parallel segment loading
     */
    uint64_t alloc;
    unsigned updates, pending, failed, done; /* Atomic segment counters */

    struct conf *me, *obase;
    pthread_mutex_t lock; /* Access to 'me' needs to be protected */
};

#include "pref-segments-proto.h"

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define PREF_SEGMENTS_PREFDIR_NEW_BRANCH ((const char *)pref_segments_new + 0)
#   define PREF_SEGMENTS_PREFFILE_NEW       ((const char *)pref_segments_new + 1)
#   define PREF_SEGMENTS_PREFFILE_COPY      ((const char *)pref_segments_new + 2)
#   define PREF_SEGMENTS_FSEVENT_OVERFLOW   ((const char *)pref_segments_new + 3)
#endif

#endif
