#include <errno.h>
#include <kit-alloc.h>
#include <kit-random.h>
#include <mockfail.h>

#if SXE_DEBUG
#include <kit-bool.h>
#endif

#if __linux__
#include <bsd/string.h>
#endif

#include "atomic.h"
#include "conf-dispatch.h"
#include "conf-worker.h"
#include "dns-name.h"
#include "infolog.h"
#include "prefs-org.h"
#include "rr-type.h"
#include "unaligned.h"

#define SEGMENT_RETRY_FREQUENCY       5     // How frequently to retry loading a segment that fails */
#define CONF_DEFAULT_REJECT_DIRECTORY ""    // By default, no reject directory is configured

static const char    *conf_lastgood_directory;       // Directory for last successfully loaded files stored as a fallback
static pthread_t     *worker_threads;                // Array of conf worker threads
static unsigned       worker_target;                 // Desired number of workers after all queued pthread_joins
static unsigned       worker_count;                  // Current number of workers
static struct netsock conf_default_report_server = CONF_DEFAULT_REPORT_SERVER;

/* Per worker thread variables. These must be copies, not references.
 */
static __thread char               conf_reject_directory[PATH_MAX] = CONF_DEFAULT_REJECT_DIRECTORY;
static __thread int                conf_lastgood_compression       = CONF_DEFAULT_LASTGOOD_COMPRESSION;
static __thread struct netsock    *conf_report_server              = &conf_default_report_server;
static __thread struct conf_loader conf_file_loader;

/**
 * Set per thread options used by conf worker threads
 *
 * @param reject_directory           Directory where files rejected by the loader are saved or NULL for no saving of rejects
 * @param lastgood_compression_level Compression level to use for last-good files
 * @param report_server              Report server netsock. If it's a.family set to 0, reporting will be disabled.
 *
 * @note A copy is made so that the options can be released immediately upon return, as loading can be fairly slow
 */
void
conf_worker_set_thread_options(const char *reject_directory, int lastgood_compression_level,    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                               const struct netsock *report_server)
{
    static __thread struct netsock conf_thread_report_server;    // Store per thread option value here

    if (reject_directory)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        strlcpy(conf_reject_directory, reject_directory, sizeof(conf_reject_directory));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    else
        conf_reject_directory[0] = '\0';    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    conf_lastgood_compression = lastgood_compression_level;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    conf_thread_report_server = *report_server;                /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    conf_report_server        = &conf_thread_report_server;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

void
conf_report_load(const char *type, unsigned version)
{
    char prefix[DNS_MAXLEN_STRING + 1], ver[12];
    uint8_t pkt[DNS_MAXLEN_NAME + 16], *p;
    socklen_t slen;
    union {
        struct sockaddr     sa;
        struct sockaddr_in  sin4;
        struct sockaddr_in6 sin6;
    } sock;
    int fd;
    rr_type_t tmp_type;

    if (conf_report_server->a.family && (fd = socket(conf_report_server->a.family, SOCK_DGRAM, 0)) >= 0) {
        snprintf(ver, sizeof(ver), ".%u", version);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        snprintf(prefix, sizeof(prefix), "%s%s.%s", kit_hostname(), version ? ver : "", type);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL6("Notifying %s.%s/IN/NULL @%s", prefix, dns_name_to_str1(CONF_LOAD_REPORT_SUFFIX),
              netsock_to_str(conf_report_server));

        p = unaligned_htons(pkt, kit_random16());               /* DNS ID */    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        p = unaligned_memcpy(p, "\0\0\0\1\0\0\0\0\0\0", 10);    /* Flags, question/RR counts */    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

        if (dns_name_sscan(prefix, "", p)) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            p = unaligned_memcpy(p + dns_name_len(p) - 1, CONF_LOAD_REPORT_SUFFIX, dns_name_len(CONF_LOAD_REPORT_SUFFIX));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            tmp_type = RR_TYPE_NULL;                                 /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            p = unaligned_memcpy(p, &tmp_type, sizeof(tmp_type));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            p = unaligned_htons(p, DNS_CLASS_IN);                    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            slen = netsock_to_sockaddr(conf_report_server, &sock.sa, sizeof(sock));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            sendto(fd, pkt, (char *)p - (char *)pkt, 0, &sock.sa, slen);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        }

        close(fd);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    } else
        SXEL7("No notification of %s v%u", type, version);
}

static struct conf *
conf_reload(struct conf_info *info)
{
    unsigned delivery, latency, loadtime;
    const char *basefn, *bdir, *bsuffix;
    char goodfn[PATH_MAX];
    struct conf *base;
    time_t start;
    bool failed = true;

    /* The first time in, we don't backup the file as it would delay startup unnecessarily */
    bdir = confset_fully_loaded() ? conf_lastgood_directory : NULL;
    bsuffix = bdir ? ".last-good" : NULL;

    time(&start);
    if (confset_fully_loaded())
        INFOLOG(CONF, "loading %s", info->name);
    SXEL5("loading %s", info->name);

    base = NULL;
    if (conf_loader_open(&conf_file_loader, info->path, bdir, bsuffix, conf_lastgood_compression, CONF_LOADER_DEFAULT)) {
        if ((base = info->type->allocate(info, &conf_file_loader)) != NULL) {
            conf_loader_done(&conf_file_loader, info);
            delivery = info->st.ctime - info->st.mtime;
            latency = start - info->st.ctime;
            loadtime = time(NULL) - start;
            failed = false;
            if (confset_fully_loaded())
                INFOLOG(CONF, "loaded %s (delivery %u, latency %u, loadtime %u)", info->name, delivery, latency, loadtime);
            SXEL5("loaded %s (delivery %u, latency %u, loadtime %u)", info->name, delivery, latency, loadtime);
            goto SXE_EARLY_OUT;
        }
    } else if (errno == ENOENT) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        INFOLOG(CONF_VERBOSE, "loading %s failed: No such file or directory", info->name);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        /* We ignore the disappearance - is this correct? */
        /* This gives different results when we restart the resolver!! */
        goto SXE_EARLY_OUT;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    if (conf_reject_directory[0])
        conf_loader_reject(&conf_file_loader, conf_info_relative_path(info->path), conf_reject_directory);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    if (conf_lastgood_directory && !confset_fully_loaded()) {
        /* First time -- see if there's a .last-good version */
        basefn = kit_basename(info->path);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        snprintf(goodfn, sizeof(goodfn), "%s/%s.last-good", conf_lastgood_directory, basefn);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

        if (conf_loader_open(&conf_file_loader, goodfn, NULL, NULL, 0, CONF_LOADER_DEFAULT)) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            if ((base = info->type->allocate(info, &conf_file_loader)) != NULL) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                conf_loader_done(&conf_file_loader, info);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                kit_infolog_printf("loaded %s (%s failed)", goodfn, info->name);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                SXEL5("loaded %s (%s failed)", goodfn, info->name);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            } else {
                kit_infolog_printf("parsing %s and %s failed", info->name, goodfn);    /* COVERAGE EXCLUSION: todo: need a test that changes file permissions */
                SXEL5("parsing %s and %s failed", info->name, goodfn);                 /* COVERAGE EXCLUSION: todo: need a test that changes file permissions */
            }
        } else if (errno == ENOENT) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            kit_infolog_printf("parsing %s failed, %s not available", info->name, goodfn);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            SXEL5("parsing %s failed, %s not available", info->name, goodfn);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        } else {
            kit_infolog_printf("parsing %s failed, %s cannot be opened", info->name, goodfn);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            SXEL5("parsing %s failed, %s cannot be opened", info->name, goodfn);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        }
    } else {
        INFOLOG(CONF, "parsing %s failed", info->name);
        SXEL5("parsing %s failed", info->name);
    }

SXE_EARLY_OUT:
    info->failed_load = failed;

    return base;
}

/*
 * Handle the removal of a single pref segment
 */
static void
conf_remove_segment(struct conf_info *info, const struct preffile *segment)
{
    const struct conf_segment *cs;
    const char *basefn;
    char goodfn[PATH_MAX];
    unsigned i = info->seg->id2slot(info->manager->me, segment->id);

    SXEE7("(info=%p,segment=%p) // path=%s flags=%x", info, segment, segment->path, segment->flags);

    SXEA6(segment->flags & PREFFILE_REMOVED, "Segment does not have REMOVED flag set");

    if ((cs = info->seg->slot2segment(info->manager->me, i)) == NULL || cs->id != segment->id)
        SXEL6("%s was removed, but I didn't know about it", segment->path);
    else {
        info->manager->alloc -= cs->alloc;
        if (cs->loaded) {
            /* Only update the modtime if the segment being removed had been loaded */
            info->seg->settimeatleast(info->manager->me, time(NULL));
        }
        info->seg->freeslot(info->manager->me, i);
        if (conf_lastgood_directory) {
            basefn = kit_basename(segment->path);
            if (snprintf(goodfn, sizeof(goodfn), "%s/%s.last-good", conf_lastgood_directory, basefn) < (int)sizeof(goodfn))
                unlink(goodfn);
        }

        ATOMIC_INC_INT(&info->manager->updates);

        if (segment->id) {
            INFOLOG(CONF, "removed %s segment %u", info->name, segment->id);
            SXEL5("removed %s segment %u", info->name, segment->id);
        }
    }

    ATOMIC_INC_INT(&info->manager->done);

    SXER7("return // path=%s", segment->path);
}

/*
 * Return the number of segments that can be queued at once for parallel
 * loading.  When a number of conf_worker threads are configured then a multiple
 * of that value is used to allow the threads to be fully utilized.
 */
static unsigned
conf_parallel_segments(void)
{
    unsigned parallel = worker_target * 2;

    if (parallel >= DEFAULT_PARALLEL_SEGMENTS)
        SXEL7("Using %d parallel segments", parallel);
    else {
        parallel = DEFAULT_PARALLEL_SEGMENTS;
        SXEL7("Using the default of %d parallel segments", parallel);
    }

    return parallel;
}

/*
 * This is the management task for segmented preferences (dirprefs, cloudprefs).
 * The management task will initially set up its shared state, and every time it
 * is taken off the todo queue and executed will check if there are pending
 * segment updates and add a number of those updates to the todo queue.  This
 * task then puts itself back on the queue if there are still any pending
 * segments to process.
 *
 * No delay is added when this management task is re-queued, as it will cycle as
 * fast as the queued segments can be processed until all segments have been
 * completed, adding new segments until that occurs.
 */
static struct conf *
conf_segment_manager(struct conf *inbase, struct conf_info *info)
{
    const struct preffile *pf;
    struct conf_dispatch cd;
    unsigned loadtime;
    unsigned segments_queued;

    SXEE7("(inbase=%p, info=%p) // lastgood='%s', rejectdir='%s', compression=%d, manager=%p, state=%s, pending=%d",
          inbase, info, conf_lastgood_directory, conf_reject_directory, conf_lastgood_compression, info->manager,
          segment_state_to_str(info->manager->state), info->manager->pending);

    if (info->manager->state == SEGMENT_STATE_NEW) {
        /*
         * This is the first call to the manager during a load operation and
         * will setup the shared manager state.
         *
         * If this is the initial loading during startup then inbase will be NULL,
         * so the individual tasks won't unnecessarily backup the files since
         * doing so would delay startup.
         */
        info->manager->obase = inbase;

        if ((info->manager->me = info->seg->clone(inbase)) == NULL) {
            SXEL2("Couldn't clone a %s conf object", info->name);
            goto SXE_EARLY_OUT;
        }

        info->manager->parallel = conf_parallel_segments();
        info->manager->updates = 0;
        info->manager->pending = 0;
        info->manager->failed = 0;
        info->manager->done = 0;
        time(&info->manager->start);
        info->manager->alloc = info->alloc;

        SXEL7("New run, %s backup", info->manager->obase ? "no" : "will");

        if (confset_fully_loaded())
            INFOLOG(CONF, "loading %s", info->name);
        SXEL5("loading %s", info->name);
    }

    segments_queued = 0;

    info->manager->state = SEGMENT_STATE_RUNNING;

    /*
     * Add segments to the todo queue until it hits the segment limit.  This
     * limit is used both to allow other tasks to enter the queue and to
     * restrict the resources consumed by pending jobs.
     */
    pthread_mutex_lock(&info->manager->lock);
    while ((info->manager->pending < info->manager->parallel)
           && ((pf = pref_segments_changed(info->manager)) != NULL)) {
        if (pf->flags & PREFFILE_REMOVED) {
            /*
             * Segment removals should be both quick and rare, as such they are
             * done within this management task.
             */
            conf_remove_segment(info, pf);
        } else {
            /*
             * Segment updates or creations are done within their own tasks, the
             * management task enques them and later waits for all pending
             * segments to complete.
             */
            pthread_mutex_unlock(&info->manager->lock);

            SXEL7("Queuing segment %p. path=%s ", pf, pf->path);

            cd.data = info->manager->me;
            cd.info = info;
            cd.segment = pf;

            ATOMIC_INC_INT(&info->manager->pending);

            conf_dispatch_put(&cd, CONF_DISPATCH_TODO);
            segments_queued++;

            pthread_mutex_lock(&info->manager->lock);
        }
    }
    pthread_mutex_unlock(&info->manager->lock);

    /* If there are any pending segments then requeue this manager job. */
    if (info->manager->pending > 0) {
        info->manager->state = SEGMENT_STATE_REQUEUED;
        if (segments_queued) {
            SXEL5("%s: queued %d segments", info->name, segments_queued);
        }
        goto SXE_EARLY_OUT;
    }

    /*
     * All segments have been loaded, complete the overall task
     */
    SXEL7("All segments loaded");

    memset(info->digest, '\0', sizeof(info->digest));
    memset(&info->st, '\0', sizeof(info->st));
    info->alloc = info->manager->alloc;
    info->st.mtime = info->seg->settimeatleast(info->manager->me, 0);
    info->updates += info->manager->updates;

    if (info->manager->updates)
        info->seg->loaded(info->manager->me);

    if (info->manager->failed) {
        INFOLOG(CONF, "parsing %s failed", info->name);
        SXEL5("parsing %s failed", info->name);
    } else {
        loadtime = time(NULL) - info->manager->start;
        if (confset_fully_loaded())
            INFOLOG(CONF, "loaded %s (loadtime %u)", info->name, loadtime);
        SXEL5("loaded %s (loadtime %u)", info->name, loadtime);
    }

    /* Segment loading is complete, reset the manager's state */
    info->manager->state = SEGMENT_STATE_NEW;

SXE_EARLY_OUT:

    if (info->manager->state != SEGMENT_STATE_REQUEUED) {
        if (info->manager->me && !info->manager->updates) {
            conf_refcount_dec(info->manager->me, CONFSET_FREE_IMMEDIATE);
            info->manager->me = NULL;
        }
    }

    if (info->manager->me == NULL)
        errno = EINVAL;

    SXER7("return %p // %u pending, %u updates, state %s", info->manager->me, info->manager->pending, info->manager->updates,
          segment_state_to_str(info->manager->state));

    return info->manager->me;
}

/*
 * Attempt to load a single pref segment.  If loading fails then this will
 * instead try to load an earlier known-good segment file.
 */
static struct conf *
conf_reload_segment(struct conf *inbase, struct conf_info *info, const struct preffile *segment)
{
    const char *basefn, *bdir, *bsuffix;
    unsigned loadtime;
    bool failed = false, updated = false, loaded_last_good = false;
    unsigned delivery, latency;
    time_t orgstart;
    struct prefs_org *po, *po_tmp;
    char goodfn[PATH_MAX];
    const struct conf_segment *cs;
    unsigned slot;

    SXEE7("(inbase=%p,info=%p,segment=%p) // path=%s flags=%x",
          inbase, info, segment, segment->path, segment->flags);

    /* The first time in, we don't backup the file as it would delay startup unnecessarily */
    bdir = confset_fully_loaded() ? conf_lastgood_directory : NULL;
    bsuffix = bdir ? ".last-good" : NULL;
    SXEA6(!(segment->flags & PREFFILE_REMOVED), "Segment was removed?");
    time(&orgstart);

    if (!conf_loader_open(&conf_file_loader, segment->path, bdir, bsuffix, conf_lastgood_compression, CONF_LOADER_DEFAULT))
        failed = true;

    if (((po = (struct prefs_org *)info->seg->newsegment(segment->id, &conf_file_loader, info)) == NULL)
     || (po->fp.loadflags & LOADFLAGS_FP_FAILED)) {
        failed = true;

        if (po == NULL) {
            goto SXE_EARLY_OUT;
        }
    }

    loaded_last_good = false;

    if (failed) {
        if (conf_reject_directory[0])
            conf_loader_reject(&conf_file_loader, conf_info_relative_path(segment->path), conf_reject_directory);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

        pthread_mutex_lock(&info->manager->lock);
        pref_segments_retry(info->manager, segment, SEGMENT_RETRY_FREQUENCY);
        pthread_mutex_unlock(&info->manager->lock);

        if (conf_lastgood_directory && !confset_fully_loaded()) {
            /* First time -- see if there's a last-good version */
            basefn = kit_basename(segment->path);
            errno = snprintf(goodfn, sizeof(goodfn), "%s/%s.last-good", conf_lastgood_directory, basefn)
                    >= (int)sizeof(goodfn) ? ENOENT : 0;

            if (errno || !conf_loader_open(&conf_file_loader, goodfn, NULL, NULL, 0, CONF_LOADER_DEFAULT)) {
                if (errno == ENOENT) {
                    kit_infolog_printf("parsing segment %u (%s) failed, %s not available", segment->id, segment->path, goodfn);
                    SXEL5("parsing segment %u (%s) failed, %s not available", segment->id, segment->path, goodfn);
                } else {
                    kit_infolog_printf("parsing segment %u (%s) failed, %s cannot be opened", segment->id, segment->path, goodfn);
                    SXEL5("parsing segment %u (%s) failed, %s cannot be opened", segment->id, segment->path, goodfn);
                }
            } else {
                po_tmp = MOCKFAIL(conf_worker_load, NULL,
                                  (struct prefs_org *)info->seg->newsegment(segment->id, &conf_file_loader, info));

                if (po_tmp == NULL) {
                    kit_infolog_printf("parsing segment %u (%s) failed, %s also failed", segment->id, segment->path, goodfn);
                    SXEL5("parsing segment %u (%s) failed, %s also failed", segment->id, segment->path, goodfn);
                } else {
                    /*
                     * The last-good file was loaded successfully, replace the failed
                     * pref_orgs with the one from the last-good load.
                     */
                    loaded_last_good = true;
                    prefs_org_refcount_dec(po);
                    po = po_tmp;

                    kit_infolog_printf("parsing segment %u (%s) failed, used %s instead", segment->id, segment->path, goodfn);
                    SXEL5("parsing segment %u (%s) failed, used %s instead", segment->id, segment->path, goodfn);
                }
            }
        } else {
            kit_infolog_printf("parsing segment %u (%s) failed", segment->id, segment->path);
            SXEL5("parsing segment %u (%s) failed", segment->id, segment->path);
        }
    }

    pthread_mutex_lock(&info->manager->lock);
    slot = info->seg->id2slot(info->manager->me, segment->id);
    if (!info->seg->usesegment(info->manager->me, po, slot, &info->manager->alloc)) {
        pthread_mutex_unlock(&info->manager->lock);
        info->seg->freesegment(po);
        po = NULL;
        failed = true;
        goto SXE_EARLY_OUT;
    }

    info->seg->slotfailedload(info->manager->me, slot, failed);

    if (!loaded_last_good && !(po->fp.loadflags & LOADFLAGS_FP_FAILED)) {
        const char *what;

        cs = info->seg->slot2segment(info->manager->me, slot);
        pthread_mutex_unlock(&info->manager->lock);

        SXEA6(cs && cs->id == segment->id, "Cannot find the conf segment that was just added");

        delivery = cs->ctime - cs->mtime;
        latency = orgstart - cs->ctime;
        loadtime = time(NULL) - orgstart;

        what = segment->flags & PREFFILE_ADDED ? "added" : "modified";
        if (confset_fully_loaded())
            INFOLOG(CONF, "%s %s segment %u (delivery %u, latency %u, loadtime %u)", what, info->name, segment->id, delivery, latency, loadtime);
        SXEL5("%s %s segment %u from file %s (delivery %u, latency %u, loadtime %u)", what, info->name, segment->id, segment->path, delivery, latency, loadtime);
    } else {
        pthread_mutex_unlock(&info->manager->lock);
    }

    updated = true;

SXE_EARLY_OUT:

    if (po == NULL) {
        /*
         * As the pref_org isn't allocated the failure could not have been
         * recorded above, do so here if there was an org already present.
         */
        pthread_mutex_lock(&info->manager->lock);
        slot = info->seg->id2slot(info->manager->me, segment->id);
        if ((cs = info->seg->slot2segment(info->manager->me, slot)) != NULL
            && (cs->id == segment->id)) {
            info->seg->slotfailedload(info->manager->me, slot, true);
        }
        pthread_mutex_unlock(&info->manager->lock);
    }

    if (failed) {
        ATOMIC_INC_INT(&info->manager->failed);
    }

    if (updated) {
        ATOMIC_INC_INT(&info->manager->updates);
    }

    ATOMIC_INC_INT(&info->manager->done);
    ATOMIC_DEC_INT_NV(&info->manager->pending);

    SXER7("return %p", inbase);

    return inbase;
}

/**
 * Load a single conf file
 *
 * @note This function can be called directly on startup from the config thread
 */
struct conf *
conf_worker_load(struct conf *obase, struct conf_info *info, const struct preffile *segment)
{
    struct conf *ret;

    if (!info->loadable || !conf_info_ischanged(info)) {
        INFOLOG(CONF_VERBOSE, "Skipping %s (unchanged)", info->name);
        ret = NULL;
    } else {
        SXEL7("%s(obase=%p,info=%p,segment=%p){} // loading... name=%s, lastgood=%s, clev=%d, rejectdir=%s, firstload=%s",
              __FUNCTION__, obase, info, segment, info->name, conf_lastgood_directory, conf_lastgood_compression,
              conf_reject_directory, kit_bool_to_str(!confset_fully_loaded()));

        conf_update_thread_options();

        if (segment) {
            ret = conf_reload_segment(obase, info, segment);
        } else if (info->manager) {
            ret = conf_segment_manager(obase, info);
        } else {
            SXEA6(segment == NULL, "segment pointer should be NULL for non-segment loads"); // TODO: Remove?
            ret = conf_reload(info);

            /*
             * XXX: Clear info->st.dev!
             *
             * Our failure to load a file implies that the file has been
             * updated and that therefore the info->st data refers to a file
             * that no longer exists on disk.  If we retain info->st,
             * there's a possibility that a new file will be put in place
             * quickly with the same size and timestamp and will "happen"
             * to get the same inode!
             *
             * This is really imperfect - it's possible that this might happen
             * without us getting the opportunity to fail a reload... but this
             * code makes our tests easier!
             */
            if (ret == NULL)
                info->st.dev = 0;
        }
    }

    return ret;
}

/**
 * Process a single conf job.
 *
 * @note This function will be called directly from the config thread in the case where the conf thread count is 0
 */
bool
conf_worker_process_one_job(bool block)
{
    struct conf_dispatch cd;
    conf_dispatch_handle_t h;

    do {
        kit_time_cached_update();
        if (!(h = conf_dispatch_getwork(&cd, block)))
            return false;
        if (CONF_DISPATCH_ISFREE(cd)) {
            conf_free(cd.data);
            conf_dispatch_deadwork(h);
        }
    } while (CONF_DISPATCH_ISFREE(cd));

    if (CONF_DISPATCH_ISLOAD(cd)) {
        cd.data = conf_worker_load(cd.data, cd.info, cd.segment);
    } else {
        cd.thr = pthread_self();
    }
    kit_time_cached_update();

    if (cd.segment) {
        /* Segment of a managed pref is complete so return the job to the deadwork queue */
        conf_dispatch_deadwork(h);
    } else if (cd.info && cd.info->manager && cd.info->manager->state == SEGMENT_STATE_REQUEUED) {
        /* The segment manager has queued segments, place it back on the todo queue */
        conf_dispatch_requeue(&cd, h);
    } else {
        conf_dispatch_donework(&cd, h);
    }

    /* We return false if we did no work.  If blocking, that means exit, otherwise nothing to do */
    return CONF_DISPATCH_ISLOAD(cd);
}

unsigned
conf_worker_get_count(void)
{
    return worker_count;
}

unsigned
conf_worker_get_target(void)
{
    return worker_target;
}

static volatile bool timetodie = false;

static void *
conf_worker_thread_main(void *dummy)
{
    unsigned slot;

    SXEE6("()");
    SXE_UNUSED_PARAMETER(dummy);
    slot = kit_counters_init_dynamic_thread();

    while (!timetodie && conf_worker_process_one_job(true)) {
    }

    conf_loader_fini(&conf_file_loader);
    kit_counters_fini_dynamic_thread(slot);
    SXER6("return");
    fflush(stderr);
    return NULL;
}

/**
 * Signal the conf_worker threads to gracefully terminate
 *
 * @note This initiates the terminations, but they happen asynchronously. thread_join the conf_worker thread to synchronize.
 */
void
conf_worker_terminate(void)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    timetodie = true;          /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}                              /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

bool
conf_worker_under_spinlock(void)
{
    return worker_count != 0;
}

void
conf_worker_harvest_thread(const pthread_t thr)
{
    unsigned i;

    for (i = 0; i < worker_count; i++)
        if (worker_threads[i] == thr)
            break;

    SXEA1(i < worker_count, "Cannot harvest thread %lu - invalid thread", (unsigned long)thr);

    pthread_join(thr, NULL);
    memmove(worker_threads + i, worker_threads + i + 1, (worker_count - i - 1) * sizeof(*worker_threads));
    worker_count--;
    SXEA6(worker_count >= worker_target, "Purged thread %u but target is %u", worker_count, worker_target);
}

/**
 * Set the desired number of worker threads
 *
 * @note A count of 1 will be treated as a count of 0. i.e. the main conf thread will do the work.
 */
void
conf_worker_set_count(unsigned count)
{
    int adjust, ok;
    unsigned n;

    count  = count > 1 ? count : 0;
    adjust = (int)count - (int)worker_target;

    if (adjust > 0) {
        SXEL5("Starting %d conf-worker threads", adjust);
        n = worker_count + adjust;
        SXEA1(worker_threads = kit_realloc(worker_threads, n * sizeof(*worker_threads)), "Cannot realloc conf threads to %u", n);
        kit_counters_prepare_dynamic_threads(adjust);

        for (; worker_count < n; worker_count++)
            SXEA1((ok = pthread_create(worker_threads + worker_count, NULL, conf_worker_thread_main, NULL)) == 0,
                  "pthread_create: %s // conf_worker_thread()", strerror(ok));
    }

    if (adjust < 0) {
        SXEL5("Terminating %d conf-worker threads", -adjust);

        for (; adjust < 0; adjust++)
            conf_dispatch_put(NULL, CONF_DISPATCH_TODO);
    }

    worker_target = count;
}

/* Private function called by conf_initialize
 */
void
conf_worker_initialize(const char *lastgood_directory, bool report_by_default)
{
    conf_lastgood_directory = lastgood_directory;

    if (!report_by_default)
        conf_default_report_server.a.family = 0;    // Disable the default report server
}

/* Private function called by confset_unload to allow tests to free allocated memory
 */
void
conf_worker_finalize(void)
{
    SXEA1(worker_count == 0, "%s() can't teardown conf-workers (%u remain%s) - tidy them up in your test!",
          __FUNCTION__, worker_count, worker_count == 1 ? "s" : "");

    kit_free(worker_threads);
    conf_loader_fini(&conf_file_loader);    // Free memory used by the main conf thread
    worker_threads = NULL;
}
