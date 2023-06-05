#include <kit-alloc.h>
#include <kit-queue.h>
#include <kit.h>
#include <mockfail.h>
#include <sxe-util.h>

#if __FreeBSD__
#include <sys/socket.h>
#else
#include <bsd/string.h>
#endif

#if SXE_DEBUG
#include <kit-bool.h>
#endif

#include "atomic.h"
#include "conf-dispatch.h"
#include "conf-segment.h"
#include "conf.h"
#include "infolog.h"



#define CONF_REGISTRAR_CHUNK 10

/*-
 * This is how things hang together here.
 *
 *    old_set             older_set           current.set         *current.info[]                       current.index  conf-dispatch.c
 *   .----------------.  .----------------.  .----------------.  .---------------------------------------.  .---.         .------.
 *   |dirprefs object |  |dirprefs object |  |dirprefs object |  |name dirprefs,  refcount 4, loadable 1 |  | N |         | ref  |
 *   |----------------|  |----------------|  |----------------|  |---------------------------------------|  |---|         |      |
 *   |options object  |  |options object  |  |options object  |  |name options,   refcount 4, loadable 1 |  | 3 |         | ref  |
 *   |----------------|  |----------------|  |----------------|  |---------------------------------------|  |---|         |      |
 *   |NULL            |  |devprefs object |  |NULL            |  |name devprefs,  refcount 1, loadable 0 |  | 0 |         |      |
 *   |----------------|  |----------------|  |----------------|  |---------------------------------------|  |---|         |      |
 *   |NULL            |  |NULL            |  |devprefs object |  |name devprefs,  refcount 2, loadable 1 |  | 1 |         | ref  |
 *   |----------------|  |----------------|  |----------------|  |---------------------------------------|  |---|         |      |
 *   |NULL            |  |NULL            |  |NULL            |  |name siteprefs, refcount 1, loadable 1 |  | 4 |         | ref  |
 *   |----------------|  |----------------|  |----------------|  |---------------------------------------|  |---|         |      |
 *
 *          ....                ....                ....                          ....                       ...           ......
 *
 *   |                |  |                |  |                |  |                                       |  |   |         |      |
 *   |----------------|  |----------------|  |----------------|  |---------------------------------------|  |---|         |      |
 *   |ccb object      |  |NULL            |  |ccb object      |  |name ccb,       refcount 3, loadable 1 |  |   |         | ref  |
 *   `----------------'  `----------------'  `----------------'  `---------------------------------------'  `---'         `------'
 *
 * The current.info conf_info pointer array describes what's registered and how many confset objects are out there referring to the conf_info.
 * A conf_info element can only be recycled when refcount reaches 0 AND registered reaches 0.
 * - "registered" counts the number of times exactly the same name & path were registered
 * - If the path is different, the info gets a new current.info[] slot
 * A conf_info with loadable 0 cannot be used to create a new object in a confset and doesn't appear in current.index.
 * The conf-dispatch.c module keeps references to all loadable conf_infos.
 * - indexes move back and forth between the IDLE (waiting for a time), LIVE (being loaded) and DONE (load finished) queues
 * - When a conf_info becomes unloadable, its index will be removed from conf-dispatch.c next time it "turns up" and the refcount will be decremented
 * The current.index is an ordered (by name) array of registered conf_info indices.
 */

enum conf_state {
    CONF_UNINITIALIZED,
    CONF_NOTLOADED,
    CONF_LOADED,
};

static enum conf_state conf_state = CONF_UNINITIALIZED;

struct confset {
    unsigned items;              /* Number of conf entries */
    struct conf *conf[];
};

static struct {
    pthread_spinlock_t lock;     /* Taken *AFTER* genlock */
    unsigned *index;             /* name index */
    unsigned alloc;              /* The number of current.info[] entries allocated */
    unsigned unused;             /* The number of NULL current.info[] entries - included in current.set->items */
    struct conf_info **info;     /* Array of current.set->items conf_info pointers */
    unsigned loadablegen;        /* The generation number of info[]->loadable changes */

    pthread_spinlock_t genlock;  /* protect current.generation and current.set (the pointer), taken *BEFORE* lock */
    volatile int generation;     /* generation # of current set */
    struct confset *set;         /* The current set */
} current;

static struct conf_type loadabletype = {
    "loadabletype",
    NULL,
    NULL,
};

#define MODULE_IN_SET(set, m) ((set) && (m) && (m) <= (set)->items)
#define ALLOC_BLOCK 10

enum clone_how {
    CLONE_CURRENT,     /* Just like current.set, NULL loadables set to 'loadable' */
    CLONE_LOADABLE,    /* All loadables set to 'loadable' */
};

static struct confset *
confset_clone(const struct confset *oset, enum clone_how how, struct conf *loadable)
{
    unsigned i, items, nalloc;
    struct confset *nset;

    SXEA6(conf_state != CONF_UNINITIALIZED, "conf_initialize() not yet called");
    SXEA6(how == CLONE_CURRENT || loadable, "Doesn't make sense to use CLONE_LOADABLE with NULL");

    nset = NULL;
    do {
        SXEA6(oset == NULL || current.alloc >= oset->items, "You didn't get that set from here!");
        items = oset ? oset->items : 0;
        if (current.set && items < current.set->items)
            items = current.set->items;
        nalloc = current.alloc + (items + 2 >= current.alloc ? ALLOC_BLOCK : 0);
        SXEA1(nset = kit_realloc(nset, sizeof(*nset) + nalloc * sizeof(*nset->conf)), "Couldn't allocate conf set of %u items", nalloc);

        pthread_spin_lock(&current.lock);
        if (nalloc >= current.alloc) {
            items = oset ? oset->items : 0;
            if (current.set && items < current.set->items)
                items = current.set->items;
            for (i = 0; i < items; i++) {
                nset->conf[i] = !current.info[i] || !current.info[i]->loadable ? NULL :
                                how == CLONE_LOADABLE ? loadable :
                                (oset && oset->items > i ? oset->conf[i] : current.set->conf[i]) ?: loadable;
                if (nset->conf[i]) {
                    conf_refcount_inc(nset->conf[i]);
                    current.info[i]->refcount++;
                }
            }
            nset->items = i;
        }
        pthread_spin_unlock(&current.lock);
    } while (nalloc < current.alloc);

    return nset;
}

static void
conf_set_one_loadable(unsigned i)
{
    SXEA6(MODULE_IN_SET(current.set, i + 1) && current.info[i] && current.info[i]->registered,
          "Cannot set module %u loadable - invalid module", i);
    current.info[i]->loadable = 1;
    current.loadablegen++;
    current.info[i]->refcount++;    /* Dispatch queue members get a refcount */
}

static void
conf_create_dispatch_entry(unsigned i)
{
    struct conf_dispatch cd;

    cd.idx = i;
    cd.data = NULL;
    cd.info = current.info[i];
    cd.segment = NULL;
    SXEA6(CONF_DISPATCH_ISLOAD(cd), "Failed to create a LOAD job");
    conf_dispatch_put(&cd, CONF_DISPATCH_TODO);
}

/*-
 * Register a config file.
 *
 * @param type:      The type
 * @param seg:       For segmented configs, the requisite dispatch functions
 * @param name:      How it turns up in digest files and other diag messages
 * @param path:      The path relative to the conf_directory
 * @param loadable:  Whether it's immediately loadable or is being added to a registrar
 * @param loadflags: Passed to the loader.  LOADFLAGS_* flags are specific to the type
 */
module_conf_t
conf_register(const struct conf_type *type, const struct conf_segment_ops *seg, const char *name, const char *path, bool loadable,
              uint32_t loadflags, const void *userdata, size_t userdatalen)
{
    unsigned i, items, nalloc, namei, *nindex, *oindex, used;
    struct conf_info *info, **ninfo, **oinfo;
    struct confset *nset, *oset;
    module_conf_t ret;
    int cmp, finished;
    bool dispatch;

    SXEE6("(type=?, seg=%p, name=%s, path=%s, loadable=%s, loadflags=0x%02x, userdata=%p, userdatalen=%zu) // type->name=%s",
          seg, name, path, kit_bool_to_str(loadable), loadflags, userdata, userdatalen, type->name);

    SXEA6(conf_state != CONF_UNINITIALIZED, "conf_initialize() not yet called");
    SXEA6((seg && !type->allocate) || (!seg && type->allocate), "Make up your mind - segmented prefs don't allocate, non-segmented files do!");
    conf_info_assert_pathok(path);

    finished = 0;
    ret = 0;
    do {
        while (current.set == NULL || (current.set->items == current.alloc && current.unused == 0)) {
            nalloc = current.alloc + ALLOC_BLOCK;
            SXEL7("Expanding allocated conf registrations from %u to %u", current.alloc, nalloc);
            oset = nset = kit_malloc(sizeof(*nset) + nalloc * sizeof(*nset->conf));
            oindex = nindex = kit_malloc(sizeof(*nindex) * nalloc);
            oinfo = ninfo = kit_malloc(sizeof(*ninfo) * nalloc);

            if (MOCKFAIL(conf_register, 1, (!nset || !nindex || !ninfo))) {
                kit_free(nset);
                kit_free(nindex);
                kit_free(ninfo);
                SXEL2("Couldn't allocate conf data for %u entries", nalloc);
                goto OUT;
            }

            pthread_spin_lock(&current.lock);
            if (nalloc > current.alloc) {
                oset = current.set;
                if (oset) {
                    used = oset->items;
                    memcpy(nset, oset, sizeof(*nset) + used * sizeof(*nset->conf));
                } else
                    nset->items = used = 0;
                current.set = nset;

                oindex = current.index;
                memcpy(nindex, oindex, sizeof(*nindex) * used);    /* current.unused is zero */
                current.index = nindex;

                oinfo = current.info;
                memcpy(ninfo, oinfo, sizeof(*ninfo) * used);
                current.info = ninfo;

                SXEL6("Increased current.alloc from %u to %u", current.alloc, nalloc);
                current.alloc = nalloc;
            }
            pthread_spin_unlock(&current.lock);

            kit_free(oset);
            kit_free(oindex);
            kit_free(oinfo);
        }

        /* We *SHOULD* have enough space now.... races permitting! */
        pthread_spin_lock(&current.lock);

        dispatch = false;
        ret = 0;
        SXEA1(current.set->items >= current.unused, "too many unused items (%u > %u)", current.unused, current.set->items);

        items = current.set->items - current.unused;
        SXEL6("Looking through %u index items for '%s'", items, name);
        for (namei = 0; namei < items; namei++) {
            info = current.info[current.index[namei]];
            if ((cmp = strcmp(info->name, name)) == 0 && info->registered) {
                if (loadable)
                    SXEL2("%s: Config name already registered as %s", name, info->path);    /* For application startup dups! */
                else if (strcmp(conf_info_relative_path(info->path), path) == 0 && info->type == type) {
                    info->registered++;                /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                    ret = current.index[namei] + 1;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                    SXEL6("%s: Config name & path re-registered, returning module %u", name, ret);
                } else {
                    SXEL6("%s: Config name re-registered as %s (was module %u, path %s, %sloadable)", name, path,
                          current.index[namei] + 1, conf_info_relative_path(info->path), info->loadable ? "" : "not ");
                    continue;
                }
                finished = 1;
                break;
            } else if (cmp > 0)
                break;
        }

        if (!finished) {
            SXEL7("Creating a new registration entry at name index %u", namei);

            if (current.unused) {
                items += current.unused;
                for (i = 0; i < items; i++)
                    if (current.info[i] == NULL)
                        break;
                SXEA1(i < items, "Cannot find unused entry in conf set (%u used) - expected to find %u", items, current.unused);
                SXEL6("%s: registering as mod %u of %u at path %s", name, i + 1, items, path);
                items -= current.unused--;
            } else if ((i = current.set->items) < current.alloc) {
                current.set->items++;
                SXEL6("%s: registering as mod %u at path %s", name, i + 1, path);
            }

            if (i < current.set->items) {
                if (namei < items)
                    memmove(current.index + namei + 1, current.index + namei, (items - namei) * sizeof(*current.index));
                current.index[namei] = i;
                current.set->conf[i] = NULL;
                current.info[i] = conf_info_new(type, name, path, seg, loadflags, userdata, userdatalen);
                current.info[i]->registered = 1;
                if (loadable) {
                    conf_set_one_loadable(i);
                    dispatch = true;
                }
                finished = 1;
                ret = i + 1;
            }
        }

        pthread_spin_unlock(&current.lock);
        if (dispatch)
            conf_create_dispatch_entry(ret - 1);
    } while (!finished);

OUT:
    SXER6("return %u // module_conf_t", ret);
    return ret;
}

static struct conf_info *
conf_info_remove(unsigned i)
{
    struct conf_info *info;
    unsigned namei, used;

    /*
     * Called with current.lock held, extracts the conf_info * and corrects the index.
     * The extracted conf_info should be freed outside of the lock.
     */
    info = current.info[i];
    current.info[i] = NULL;

    SXEA1(current.set->items >= current.unused, "too many unused items (%u > %u)", current.unused, current.set->items);
    used = current.set->items - current.unused++;
    for (namei = 0; namei < used; namei++)
        if (current.index[namei] == i)
            break;
    SXEA1(namei < used, "Lost module %u's name entry", namei + 1);
    memmove(current.index + namei, current.index + namei + 1, (used - namei - 1) * sizeof(*current.index));

    return info;
}

void
conf_unregister(module_conf_t m)
{
    struct conf_info *info;

    SXEE6("(module=%u)", m);

    SXEA6(conf_state != CONF_UNINITIALIZED, "conf_initialize() not yet called");
    if (MODULE_IN_SET(current.set, m)) {
        info = NULL;
        if (current.info[m - 1])
            SXEL6("Unregistering '%s', registered %u => %u", current.info[m - 1]->name, current.info[m - 1]->registered, current.info[m - 1]->registered - 1);
        pthread_spin_lock(&current.lock);
        if (current.info[m - 1] && !--current.info[m - 1]->registered) {
            current.info[m - 1]->loadable = 0;
            if (!current.info[m - 1]->refcount)
                info = conf_info_remove(m - 1);
            current.loadablegen++;
        }
        pthread_spin_unlock(&current.lock);
        conf_info_free(info);
    }
    SXER6("return");
}

void
conf_setup(struct conf *base, const struct conf_type *type)
{
    base->type = type;
    base->refcount = 1;
}

void
conf_free(struct conf *me)
{
    if (me && me->type->free)
        me->type->free(me);
}

void
conf_refcount_dec(struct conf *me, enum confset_free_method freehow)
{
    struct conf_dispatch cd;

    if (me != NULL && ATOMIC_DEC_INT_NV(&me->refcount) == 0 && me->type->free)
        switch (freehow) {
        case CONFSET_FREE_DISPATCH:
            cd.idx = 0;
            cd.data = me;
            cd.info = NULL;
            cd.segment = NULL;
            SXEA6(CONF_DISPATCH_ISFREE(cd), "Failed to create a FREE job");
            conf_dispatch_put(&cd, CONF_DISPATCH_TODO);
            break;
        case CONFSET_FREE_IMMEDIATE:
            conf_free(me);
            break;
        }
}

void
conf_refcount_inc(struct conf *me)
{
    if (me != NULL)
        ATOMIC_INC_INT(&me->refcount);
}

void
conf_query_digest(const struct conf *base, const struct conf_info *info, const char *sub, void *v, void (*cb)(void *, const char *, const char *))
{
    char hex[MD5_DIGEST_LENGTH * 2 + 3];
    char *end, txt[12 + sizeof(hex)];
    unsigned long fromslot, toslot;
    const struct conf_segment *cs;
    unsigned i;

    if (!info->manager || !info->seg) {
        if (*sub == '\0') {
            kit_bin2hex(hex, info->digest, sizeof(info->digest), KIT_BIN2HEX_LOWER);
            snprintf(hex + sizeof(hex) - 3, 3, "%s%s",
                     info->alloc ? "" : "!",
                     info->failed_load ? "*" : "");
            cb(v, NULL, hex);
        }
    } else {
        fromslot = toslot = 0;
        if (*sub != '\0') {
            /* valid formats are: <from>-<to> for ranges or <org> or a specific org */
            fromslot = kit_strtoul(sub, &end, 0);                    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            if (end == sub)                                          /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                return;                                              /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            if (*end == '\0') {                                      /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                /* Looking for a specific org (orgid=fromslot) */    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                i = info->seg->id2slot(base, fromslot);              /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                if ((cs = info->seg->slot2segment(base, i)) == NULL || cs->id != fromslot)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                    return;                                    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                fromslot = i;                                  /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                toslot = i + 1;                                /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            } else if (*end == '-' && end[1] != '\0') {        /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                toslot = kit_strtoul(end + 1, &end, 0) + 1;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                if (*end)                                      /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                  return;                                      /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            } else
                return;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        }
        if (base)
            for (i = fromslot; !toslot || i < toslot; i++) {
                if ((cs = info->seg->slot2segment(base, i)) == NULL)
                    break;
                kit_bin2hex(hex, cs->digest, sizeof(cs->digest), KIT_BIN2HEX_LOWER);
                snprintf(txt, sizeof(txt), "%u %s%s%s", cs->id, hex,
                         info->seg->slotisempty(base, i) ? "!" : "",
                         cs->failed_load ? "*" : "");
                cb(v, NULL, txt);
            }
    }
}

void
conf_query_modtime(const struct conf *base, const struct conf_info *info, void *v, void (*cb)(void *, const char *, const char *))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    char modtime[11];

    SXE_UNUSED_PARAMETER(base);
    snprintf(modtime, sizeof(modtime), "%lu", (unsigned long)info->st.mtime);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    cb(v, NULL, modtime);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

static void (*application_update_thread_options)(void) = NULL;

/**
 * Called by any libuup function that uses options before using an option to update the current thread's copy of the options
 */
void
conf_update_thread_options(void)
{
    if (application_update_thread_options)
        (*application_update_thread_options)();
}

/**
 * Initialize the entire module and application startup
 *
 * @param confdir           Directory where config files are stored
 * @param lastgood          Directory where the last successfully loaded files are stored as a fallback
 * @param report_by_default True if load reports should be sent by default, false if not (e.g. in tests)
 * @param update            Function to call before using any options to make sure they're up to date (NULL to use defaults)
 */
void
conf_initialize(const char *confdir, const char *lastgood, bool report_by_default, void (*update)(void))
{
    SXEE6("(confdir=%s,lastgood=%s,report_by_default=%s,update%c=NULL)", confdir ?: "<NULL>", lastgood ?: "<NULL>",
          kit_bool_to_str(report_by_default), update ? '!' : '=');
    SXEA1(conf_state == CONF_UNINITIALIZED, "conf_initialize() called more than once");

    conf_worker_initialize(lastgood, report_by_default);
    conf_info_init(confdir);
    pthread_spin_init(&current.lock, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_init(&current.genlock, PTHREAD_PROCESS_PRIVATE);
    conf_state                        = CONF_NOTLOADED;
    application_update_thread_options = update;

    SXER6("return");
}

bool
confset_fully_loaded(void)
{
    return conf_state == CONF_LOADED;
}

static void
conf_info_dereference(module_conf_t m)
{
    struct conf_info *info;

    info = NULL;
    pthread_spin_lock(&current.lock);
    if (!--current.info[m - 1]->refcount && !current.info[m - 1]->registered) {
        SXEA6(!current.info[m - 1]->loadable, "Didn't expect to want to delete a loadable conf");
        info = conf_info_remove(m - 1);
    }
    pthread_spin_unlock(&current.lock);

    conf_info_free(info);
}

struct updatecb {
    void *v;
    void (*cb)(void *, struct confset *, const struct confset *);
    SLIST_ENTRY(updatecb) next;
};

static SLIST_HEAD(, updatecb) updatecbs = SLIST_HEAD_INITIALIZER(&updatecbs);

/**
 * Register a function that will be called during the creation of a new confset, allowing it to be modified.
 *
 * @note Callbacks will be called in the context of the main config thread; allows generation/addition of secondary files
 */
bool
conf_update_add_callback(void *v, void (*cb)(void *, struct confset *, const struct confset *))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    struct updatecb *updatecb;
    bool ret = false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    if ((updatecb = MOCKFAIL(conf_update_add_callback, NULL, kit_malloc(sizeof(*updatecb)))) == NULL)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL3("Cannot allocate a conf update callback");    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    else {
        updatecb->v = v;                                  /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        updatecb->cb = cb;                                /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SLIST_INSERT_HEAD(&updatecbs, updatecb, next);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        ret = true;                                       /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    return ret;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

static void
conf_callback(struct confset *nset, const struct confset *oset)
{
    struct updatecb *updatecb;

    SLIST_FOREACH(updatecb, &updatecbs, next)                                 \
        updatecb->cb(updatecb->v, nset, oset);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
conf_update_rm_callback(void *v)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    struct updatecb *updatecb, *next;

    if ((updatecb = SLIST_FIRST(&updatecbs)) != NULL) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        if (updatecb->v == v) {                            /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            SLIST_REMOVE_HEAD(&updatecbs, next);           /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            kit_free(updatecb);                            /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        } else {
            while ((next = SLIST_NEXT(updatecb, next)) != NULL && next->v != v)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                updatecb = next;                       /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            if (next) {                                /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                SLIST_REMOVE_AFTER(updatecb, next);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                kit_free(next);                        /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            }
        }
    }
}    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

/* This is for testing - it's not prototyped in any header file, or used by the release build */
void *(*test_register_race_alloc)(void *nset, size_t sz);

/**
 * Function to load a single module, used in the application to force the options module to be loaded first.
 *
 * @param module The module identifier (e.g. CONF_OPTIONS).
 */
void
confset_load_one(module_conf_t module)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    struct confset   *oset, *nset;
    struct conf_info *info;
    struct conf      *base;

    SXEA6(conf_state != CONF_UNINITIALIZED, "conf_initialize() not yet called");
    SXEA6(current.set != NULL, "No configuration types have been registered");

    if (MODULE_IN_SET(current.set, module)) {               /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL7("Checking the %u module file", module);
        oset = confset_clone(NULL, CLONE_CURRENT, NULL);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        info = current.info[module - 1];                    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

        if (info && info->loadable && (base = conf_worker_load(NULL, info, NULL)) != NULL) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            nset                   = oset;            /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            nset->conf[module - 1] = base;            /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            pthread_spin_lock(&current.lock);         /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            current.info[module - 1]->refcount++;     /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            pthread_spin_unlock(&current.lock);       /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            pthread_spin_lock(&current.genlock);      /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            oset        = current.set;                /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            current.set = nset;                       /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            current.generation++;                     /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            pthread_spin_unlock(&current.genlock);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        }

        confset_free(oset, CONFSET_FREE_IMMEDIATE);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }
}    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

/* Only called by the conf thread.  Workers need to confset_acquire()
 */
bool
confset_load(uint64_t *delay_ms)
{
    struct confset      *nset, *oset;
    unsigned             items, todo;
    struct conf_dispatch cd;
    size_t               sz;

    SXEE7("(delay_ms=%p) // *delay_ms=%lld", delay_ms, delay_ms ? (long long)*delay_ms : 0LL);

    SXEA6(conf_state != CONF_UNINITIALIZED, "conf_initialize() not yet called");
    SXEA6(current.set != NULL, "No configuration types have been registered");

    if (conf_worker_get_count() == 0)
        delay_ms = NULL;    /* We'll queue everything and let the caller usleep() */

    /* schedule everything that needs to be done */
    for (todo = 0; conf_dispatch_getwait(&cd, delay_ms); todo++) {
        cd.data = current.set->conf[cd.idx];
        cd.segment = NULL;
        conf_dispatch_put(&cd, CONF_DISPATCH_TODO);
    }

    SXEL7("loading %u configuration file%s %ssynchronously", todo, todo == 1 ? "" : "s", conf_worker_get_count() ? "a" : "");

    if (conf_worker_get_count() == 0) {    // It's up to me! Synchronously process everything
        INFOLOG(CONF_VERBOSE, "loading configuration files synchronously");

        while (conf_worker_process_one_job(false)) {
        }
    }

    /* Harvest all results, stuffing everything that was completed back into the WAIT queue */
    nset = NULL;
    todo = 0;
    SXEL7("Harvest the conf-dispatch DONE queue blocking=%s", kit_bool_to_str(current.generation <= 1 || !conf_worker_get_target()));
    while (conf_dispatch_getresult(&cd, current.generation <= 1 || !conf_worker_get_target() ? conf_worker_under_spinlock : NULL)) {
        SXEA6(!CONF_DISPATCH_ISFREE(cd), "Unexpected dispatch result - FREEs aren't returned!");
        if (CONF_DISPATCH_ISEXIT(cd)) {
            SXEL7("Harvest thread %lu", (unsigned long)cd.thr);
            conf_worker_harvest_thread(cd.thr);
        } else if (!cd.info->loadable) {
            if (cd.data)
                SXEL7("Loaded %s, but too late - it's no longer loadable", conf_name(NULL, cd.idx + 1));
            conf_refcount_dec(cd.data, CONFSET_FREE_IMMEDIATE);
            if (!nset && cd.idx < current.set->items && current.set->conf[cd.idx])
                nset = confset_clone(NULL, CLONE_CURRENT, NULL);
            if (nset && cd.idx < nset->items && nset->conf[cd.idx]) {
                /* Although it was loadable when we created nset */
                conf_refcount_dec(nset->conf[cd.idx], CONFSET_FREE_IMMEDIATE);
                nset->conf[cd.idx] = NULL;
                conf_info_dereference(cd.idx + 1);                  /* COVERAGE EXCLUSION: todo: This is almost impossible to reliably reproduce */
            }
            SXEL7("Dereferencing unloadable file '%s', refcount => %u", cd.info->name, cd.info->refcount - 1);
            conf_info_dereference(cd.idx + 1);                      /* because we aren't requeueing */
        } else {
            if (cd.data) {
                SXEL7("Loaded %s", conf_name(NULL, cd.idx + 1));
                if (!nset)
                    nset = confset_clone(NULL, CLONE_CURRENT, NULL);
                else if (nset->items <= cd.idx) {
                    nset = confset_clone(oset = nset, CLONE_CURRENT, NULL);
                    confset_free(oset, CONFSET_FREE_IMMEDIATE);     /* COVERAGE EXCLUSION: Not consistently covered */
                }
                SXEA1(nset->items > cd.idx, "set items %u is less than expected (%u)", nset->items, cd.idx + 1);
                if (nset->conf[cd.idx])
                    conf_refcount_dec(nset->conf[cd.idx], CONFSET_FREE_IMMEDIATE);
                else {
                    pthread_spin_lock(&current.lock);
                    current.info[cd.idx]->refcount++;
                    pthread_spin_unlock(&current.lock);
                }
                nset->conf[cd.idx] = cd.data;
                todo++;
            }
            conf_dispatch_put(&cd, CONF_DISPATCH_WAIT);
        }
    }

    SXEL7("Updated %u configuration file%s", todo, todo == 1 ? "" : "s");
    if (nset) {
        oset = NULL;                         /* Silence compiler warnings */
        conf_callback(nset, current.set);

        do {
            items = current.alloc + (nset->items + 2 >= current.alloc ? ALLOC_BLOCK : 0);
            sz = sizeof(*nset) + items * sizeof(*nset->conf);
            nset = MOCKFAIL(confset_load, test_register_race_alloc(nset, sz), kit_realloc(nset, sz));
            SXEA1(nset, "Couldn't realloc conf set of %u items", items);

            pthread_spin_lock(&current.genlock);
            if (items >= current.alloc) {
                oset = current.set;
                current.set = nset;
                for (; current.set->items < oset->items; current.set->items++)
                    current.set->conf[current.set->items] = NULL;
                if (++current.generation < 2)
                    current.generation = 2;
            }
            pthread_spin_unlock(&current.genlock);
        } while (items < current.alloc);

        confset_free(oset, CONFSET_FREE_IMMEDIATE);
    }

    conf_state = CONF_LOADED;
    SXER7("return %s // generation %d", kit_bool_to_str(current.generation == 1 || nset), current.generation);
    return current.generation == 1 || nset;
}

static void
dispatch_purge_cb(struct conf_dispatch *cd)
{
    conf_info_dereference(cd->idx + 1);
}

/**
 * Finalize the entire module
 *
 * @note Only (currently) used by test programs, so that they can prove all memory has been freed
 */
void
confset_unload(void)
{
    struct updatecb   *updatecb;
    struct conf_info **oinfo;
    struct confset    *oset;
    unsigned           i, *oindex;

    SXEE6("()");
    SXEA1(conf_state != CONF_UNINITIALIZED, "conf_initialize() not yet called");

    conf_dispatch_purge(dispatch_purge_cb);

    if (current.set)
        for (i = 0; i < current.set->items; i++) {
            if (current.set->conf[i]) {
                conf_refcount_dec(current.set->conf[i], CONFSET_FREE_IMMEDIATE);
                current.set->conf[i] = NULL;
                conf_info_dereference(i + 1);
            }
            if (current.info[i])
                conf_unregister(i + 1);
        }

    while ((updatecb = SLIST_FIRST(&updatecbs)) != NULL)
        conf_update_rm_callback(updatecb->v);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    pthread_spin_lock(&current.lock);
    current.unused = 0;
    current.alloc = 0;
    oset = current.set;
    current.set = NULL;
    oinfo = current.info;
    current.info = NULL;
    oindex = current.index;
    current.index = NULL;
    pthread_spin_unlock(&current.lock);

    kit_free(oset);
    kit_free(oinfo);
    kit_free(oindex);

    conf_worker_finalize();
    current.generation = 0;
    conf_state         = CONF_NOTLOADED;
    SXER6("return");
}

struct confset *
confset_acquire(int *generation)
{
    struct confset *set;

    SXEA6(conf_state != CONF_UNINITIALIZED, "conf_initialize() not yet called");
    set = NULL;

    if (generation == NULL || *generation != current.generation) {
        pthread_spin_lock(&current.genlock);

        if (generation == NULL || *generation != current.generation) {
            set = confset_clone(NULL, CLONE_CURRENT, NULL);
            if (generation)
                *generation = current.generation;
        }

        pthread_spin_unlock(&current.genlock);

        if (set)
            SXEL7("%s(generation=%p){} // return %p, *generation=%d", __FUNCTION__, generation, set, generation ? *generation : 0);
    }

    return set;
}

void
confset_free(struct confset *set, enum confset_free_method freehow)
{
    unsigned i;

    SXEE7("(set=%p, freehow=%s)", set, freehow == CONFSET_FREE_IMMEDIATE ? "CONFSET_FREE_IMMEDIATE" : "CONFSET_FREE_DISPATCH");
    SXEA6(conf_state != CONF_UNINITIALIZED, "conf_initialize() not yet called");

    if (set) {
        for (i = 0; i < set->items; i++)
            if (set->conf[i]) {
                conf_refcount_dec(set->conf[i], freehow);
                conf_info_dereference(i + 1);
            }
        kit_free(set);
    }

    SXER7("return");
}

void
confset_release(struct confset *set)
{
    confset_free(set, CONFSET_FREE_DISPATCH);
}

const struct conf *
confset_get(const struct confset *set, module_conf_t m)
{
    int lock = set == current.set;
    struct conf *base;

    SXEA6(conf_state != CONF_UNINITIALIZED, "conf_initialize() not yet called");
    if (lock)
        pthread_spin_lock(&current.lock);

    base = MODULE_IN_SET(set, m) ? set->conf[m - 1] : NULL;

    if (lock)
        pthread_spin_unlock(&current.lock);

    return base;
}

struct conf *
confset_get_writable(struct confset *set, module_conf_t m)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    SXEA6(conf_state != CONF_UNINITIALIZED, "conf_init() not yet called");
    return MODULE_IN_SET(set, m) ? set->conf[m - 1] : NULL;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
confset_foreach(const struct confset *set, void (*fn)(const struct conf *, const struct conf_info *, void *), void *data)
{
    struct conf loadableconf = { &loadabletype, 0 };
    unsigned i, *idx, items;
    struct confset *cloned;

    SXEE6("(set=%p, fn=?, data=%p)", set, data);

    if (conf_state == CONF_UNINITIALIZED) {
       SXEL6("conf_initialize() not yet called");
       goto OUT;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    SXEL7("Cloning %p so that all registered confs are held", set);
    cloned = confset_clone(set, CLONE_CURRENT, &loadableconf);

    pthread_spin_lock(&current.lock);
    items = current.set ? current.set->items - current.unused : 0;
    idx = alloca(items * sizeof(*idx));
    memcpy(idx, current.index, items * sizeof(*idx));
    pthread_spin_unlock(&current.lock);
    SXEL6("%s: Using %u items from the current index to order %u items", __FUNCTION__, items, cloned->items);

    /* Iterate through the sorted list, but only callback for items in the cloned set */
    for (i = 0; i < items; i++)
        if (MODULE_IN_SET(cloned, idx[i] + 1) && cloned->conf[idx[i]])
            fn(cloned->conf[idx[i]] == &loadableconf ? NULL : cloned->conf[idx[i]], current.info[idx[i]], data);
        else
            SXEL6("%s: Skipping index %u - not actually registered", __FUNCTION__, idx[i]);

    confset_release(cloned);
    SXEA6(!loadableconf.refcount, "Unexpected loadableconf refcount %u", loadableconf.refcount);

OUT:
    SXER6("return");
}

/**
 * Set the options used by the conf thread
 *
 * @param worker_count Number of independent worker threads, or 0 to load all config in the main conf thread
 */
void
conf_set_global_options(unsigned worker_count)
{
    conf_worker_set_count(worker_count);
    SXEL7("Set number of conf workers to %u", worker_count);
}

void
conf_registrar_init(struct conf_registrar *me)
{
    memset(me, '\0', sizeof(*me));
}

bool
conf_registrar_add(struct conf_registrar *me, module_conf_t m)
{
    module_conf_t *newm;

    SXEA6(me->num <= me->max, "Impossible: num %u, max %u", me->num, me->max);
    if (m) {
        if (me->num == me->max) {
            if ((newm = MOCKFAIL(conf_registrar_add, NULL, kit_realloc(me->m, (me->max + CONF_REGISTRAR_CHUNK) * sizeof(*newm)))) == NULL) {
                SXEL2("Failed to reallocate conf-registrar modules to %zu bytes", (me->max + CONF_REGISTRAR_CHUNK) * sizeof(*newm));
                return false;
            }
            me->m = newm;
            me->max += CONF_REGISTRAR_CHUNK;
        }
        me->m[me->num++] = m;
    }
    return m ? true : false;
}

void
conf_registrar_set_loadable(struct conf_registrar *me)
{
    unsigned i, items;

    for (i = 0; i != me->num; ) {
        char *was_loadable;

        items = current.set->items + 2;
        was_loadable = alloca(items);
        memset(was_loadable, '\0', items);

        pthread_spin_lock(&current.lock);
        if (items >= current.set->items)
            for (; i < me->num; i++) {
                SXEA6(me->m[i], "Missing module at position %u", i);
                SXEA6(current.set->items >= me->m[i], "Out of range module at position %u", i);
                SXEA6(current.info[me->m[i] - 1], "Invalid module at position %u", i);
                if (!(was_loadable[i] = current.info[me->m[i] - 1]->loadable))
                    conf_set_one_loadable(me->m[i] - 1);
            }
        pthread_spin_unlock(&current.lock);

        if (i)
            for (i = 0; i < me->num; i++)
                if (!was_loadable[i])
                    conf_create_dispatch_entry(me->m[i] - 1);
    }
}

void
conf_registrar_fini(struct conf_registrar *me)
{
    unsigned i;

    for (i = 0; i < me->num; i++)
        conf_unregister(me->m[i]);
    kit_free(me->m);
#if SXE_DEBUG
    conf_registrar_init(me);
#endif
}

const char *
conf_name(const struct confset *set, module_conf_t m)
{
    /*
     * If set == NULL, we assume the caller has 'm' registered
     * If set != NULL, we only find the name if they have a refcount
     */
    return set == NULL || (MODULE_IN_SET(set, m) && set->conf[m - 1]) ? current.info[m - 1]->name : NULL;
}

/*-
 * This function is used to convert conf filenames used by
 * config files that load other config files into a module
 * registration name
 *
 * For example this method would translate:
 *
 *   192.168.0.1.crt => 192-168-0-1-crt
 *   customer.opendns.com.crt => customer-opendns-com-crt
 */
const char *
conf_fn2name(char name[PATH_MAX], const char *fn)
{
    unsigned len, pos;

    if ((len = strlcpy(name, fn, PATH_MAX)) >= PATH_MAX)
        len = PATH_MAX - 1;

    while ((pos = strcspn(name, "/.:")) < len)
        name[pos] = '-';    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    return name;
}

