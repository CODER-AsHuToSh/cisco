/*
 * This module implements fast thread safe counters. libkit uses it to track memory allocations.
 *
 * Theory of operation: Each thread has its own set of counters, which it can modify without locking. When a count is needed,
 * it's summed up from all the per thread counts. This is safe to do locklessly because the counts are stored in inherently
 * atomic integers.
 *
 * Currently, threads that don't explicitly allocate counters can use shared counters which are modified using atomic
 * instructions. This is comparatively slow, and so should be avoided. A typical use would be for threads created under the
 * control of a third party library. In future, we may deal with this via an injectable shim library that takes over thread
 * creation.
 */

#include "kit-alloc-private.h"
#include "kit-counters.h"

#include <pthread.h>
#include <string.h>
#include <sxe-util.h>

#define COUNTER_ISVALID(c) (((c) != INVALID_COUNTER) && ((c) <= num_counters))

// Counters states
#define COUNTER_DYNAMIC    1
#define COUNTER_STATIC     2
#define COUNTER_USED       4

static struct combine_handler {
    kit_counter_t counter;
    unsigned long long (*handler)(int);
} combine_handlers[MAXCOUNTERS];

static bool          initialized         = false;
static bool          thread0_initialized = false;
static bool          allow_shared        = false;
static kit_mibfn_t   mibfns[MAXCOUNTERS];
static kit_counter_t sorted_index[MAXCOUNTERS];
static char         *counter_txt[MAXCOUNTERS];
static unsigned      max_counters;
static unsigned      num_counters;
static unsigned      num_handlers;
pthread_spinlock_t   counter_lock;                      // For updating maxthreads
static unsigned      maxthreads;                        // How many threads
static uint8_t      *counter_state;                     // State of counters per thread

/* Counters
 */
static struct kit_counters **volatile         all_counters;              // All per thread counters
static struct kit_counters                    thread0_counters;          // Counter structure for the main thread
static struct kit_counters                    dead_thread_counters;      // Counter structure for dead dynamic threads
static struct kit_counters                    shared_counters;           // Counter structure for third party threads (atomic)
static __thread struct kit_counters *volatile thread_counters = NULL;    // Pointer to counter structure for local thread

/*
 * Maintain an array of counter indexes in sorted (by txt value) order, so that sorted text
 * output can be easily produced (counters are not necessarily registered in sorted order).
 */
static void
add_to_sorted_index(kit_counter_t counter, const char *txt)
{
    unsigned i, x;

    for (x = 0; x < (num_counters - 1) && strcmp(txt, counter_txt[sorted_index[x]]) >= 0; x++)
        ;

    for (i = num_counters - 1; i > x && i > 0; i--)
        sorted_index[i] = sorted_index[i - 1];

    sorted_index[x] = counter;
}

/*
 * Register a new counter, along with optional combine handler and mibfn.
 */
static kit_counter_t
add_counter(const char *txt, unsigned long long (*combine_handler)(int), kit_mibfn_t mibfn)
{
    kit_counter_t counter;

    if (!kit_memory_is_initialized())       // Make sure memory counters are initialized before calling kit-alloc functions
        kit_memory_init_internal(false);    // Do a soft initialize on the counters

    counter = ++num_counters;
    SXEA1(counter < MAXCOUNTERS, "Counter %d exceeds MAXCOUNTERS (%d).", counter, MAXCOUNTERS);
    SXEA1(!counter_txt[counter], "Adding counter %d with value '%s' when it already has a value '%s'.", counter, txt, counter_txt[counter]);
    SXEA1(counter_txt[counter] = kit_strdup(txt), "Failed to allocate %zu bytes for counter text.", strlen(txt));
    add_to_sorted_index(counter, counter_txt[counter]);

    if (combine_handler) {
        combine_handlers[num_handlers].counter = counter;
        combine_handlers[num_handlers].handler = combine_handler;
        num_handlers++;
    }

    mibfns[counter] = mibfn;
    return counter;
}

unsigned
kit_num_counters(void)
{
    return num_counters;
}

bool
kit_counter_isvalid(kit_counter_t c)
{
    return COUNTER_ISVALID(c);
}

kit_counter_t
kit_sorted_index(unsigned i)
{
    return sorted_index[i];
}

const char *
kit_counter_txt(kit_counter_t c)
{
    return COUNTER_ISVALID(c) ? counter_txt[c] : NULL;
}

/* Assign and return a new counter */
kit_counter_t
kit_counter_new(const char *txt)
{
    return add_counter(txt, NULL, NULL);
}

/* Assign and return a new counter, specifying a combine handler */
kit_counter_t
kit_counter_new_with_combine_handler(const char *txt, unsigned long long (*combine_handler)(int))
{
    return add_counter(txt, combine_handler, NULL);
}

/* Assign and return a new counter, specifying a mib function */
kit_counter_t
kit_counter_new_with_mibfn(const char *txt, kit_mibfn_t mibfn)
{
    return add_counter(txt, NULL, mibfn);
}

/* Determine whether the current thread has its own counters or needs to use the slower shared counters
 */
static inline bool
kit_counters_are_shared(void)
{
    if (thread_counters)
        return false;

    if (!thread0_initialized) {
        thread_counters     = &thread0_counters;
        thread0_initialized = true;
        return false;
    }

    SXEA1(allow_shared, "Shared counters have been disabled and this thread's counters aren't initialized");
    return true;
}

void
kit_counter_incr(kit_counter_t c)
{
    if (c > num_counters)
        return;

    if (kit_counters_are_shared()) {
        if (c == INVALID_COUNTER)    // Make sure unitialized shared counters don't slow us down
            shared_counters.val[c]++;
        else
            __atomic_add_fetch(&shared_counters.val[c], 1, __ATOMIC_SEQ_CST);
    }
    else
        thread_counters->val[c]++;
}

void
kit_counter_decr(kit_counter_t c)
{
    if (c > num_counters)
        return;

    if (kit_counters_are_shared()) {
        if (c == INVALID_COUNTER)    // Make sure unitialized shared counters don't slow us down
            shared_counters.val[c]--;
        else
            __atomic_add_fetch(&shared_counters.val[c], -1LL, __ATOMIC_SEQ_CST);
    }
    else
        thread_counters->val[c]--;
}

/**
 * Initialize counters
 *
 * @params counts        Maximum number of counters supported; defaults to MAXCOUNTERS and currently aborts if greater
 * @params threads       Maximum number of threads supported; more can be requested with kit_counters_prepare_dynamic_threads
 * @params allow_sharing True (default) to allow shared counters (which are slower) to be used after initialization
 *
 * @notes Counters may be used at startup by the main thread before this function is called.
 */
void
kit_counters_initialize(unsigned counts, unsigned threads, bool allow_sharing)
{
    unsigned i;

    SXEE6("(counts=%u,threads=%u,allow_sharing=%s)", counts, threads, allow_sharing ? "true" : "false");
    SXEA1(counts <= MAXCOUNTERS, "Currently, counts cannot be greater than %u", MAXCOUNTERS);
    SXEA1(threads,               "At least one counter slot is required");
    SXEA1(!initialized,          "%s(): Already initialized!",   __FUNCTION__);

    if (!thread0_initialized) {    // If no counter has been touched
        SXEA6(!thread_counters, "Per thread counters are set without initializing the main thread");
        thread_counters     = &thread0_counters;
        thread0_initialized = true;
    }

    SXEA6(!all_counters && !counter_state, "%s(): Partially initialized!",   __FUNCTION__);
    pthread_spin_init(&counter_lock, PTHREAD_PROCESS_PRIVATE);
    initialized  = true;
    max_counters = counts;
    maxthreads   = threads;
    allow_shared = allow_sharing;
    SXEA1(counter_state = kit_malloc(maxthreads * sizeof(*counter_state)),
          "Failed to allocate %zu bytes for per-thread counter_state", maxthreads * sizeof(*counter_state));

    for (i = 0; i < maxthreads; i++)
        counter_state[i] = COUNTER_STATIC;

    SXEA1(all_counters = kit_malloc(maxthreads * sizeof(*all_counters)),
          "Failed to allocate %zu bytes for per-thread counter block pointers", maxthreads * sizeof(*all_counters));

    all_counters[0]   = &thread0_counters;
    counter_state[0] |= COUNTER_USED;
    memset(&thread0_counters, 0, sizeof(thread0_counters));    // Throw away any early counts, some of which will be invalid

    for (i = 1; i < maxthreads; i++)
        SXEA1(all_counters[i] = kit_calloc(1, sizeof(*all_counters[i])),
              "Failed to allocate %zu bytes for a thread counter block", maxthreads * sizeof(*all_counters[i]));

    SXER6("return");
}

/**
 * Allow a thread to test whether it's counters have been initialized.
 *
 * @note If this API is called before any use of counters, it returns true. For unmanaged threads, it always returns false.
 */
bool
kit_counters_usable(void)
{
    return !thread0_initialized || thread_counters;
}

/* Create a combined structure of the counters for 'threadnum', or all threads if threadnm is -1 */
void
kit_counters_combine(struct kit_counters *out_counter, int threadnum)
{
    unsigned from, i, n, to;

    SXEA6(all_counters && out_counter, "Can't combine counters that aren't initialized");
    from = threadnum == -1 ? 0 : (unsigned)threadnum;
    to   = threadnum == -1 ? maxthreads : (unsigned)threadnum < maxthreads ? (unsigned)threadnum + 1 : maxthreads;

    /* Total up every field */
    pthread_spin_lock(&counter_lock);

    for (i = from; i < to; i++)
        if (counter_state[i] & COUNTER_USED)
            for (n = 0; n <= num_counters; n++)
                out_counter->val[n] += all_counters[i]->val[n];

    if (threadnum == -1)
        for (n = 0; n <= num_counters; n++) {
            out_counter->val[n] += dead_thread_counters.val[n];
            out_counter->val[n] += shared_counters.val[n];
        }

    pthread_spin_unlock(&counter_lock);

    /* Update "special" fields that are not continuously updated */
    for (i = 0; i < num_handlers; i++)
        out_counter->val[combine_handlers[i].counter] = combine_handlers[i].handler(threadnum);
}

/* Set the per-thread pointer to a counter structure */
void
kit_counters_init_thread(unsigned slot)
{
    SXEA6(initialized,                           "Counters not yet initialized");
    SXEA1(slot < maxthreads,                     "thread initialized as slot %u, but slot_count is %u", slot, maxthreads);
    SXEA1(!(counter_state[slot] & COUNTER_USED), "thread initialized as slot %u, but that slot is already in use", slot);
    thread_counters      = all_counters[slot];
    counter_state[slot] |= COUNTER_USED;
}

void
kit_counters_fini_thread(unsigned slot)
{
    SXEA6(initialized,                           "Counters not yet initialized");
    SXEA1(slot < maxthreads,                     "thread finailized at slot %u, but slot_count is %u", slot, maxthreads);
    SXEA1(counter_state[slot] & COUNTER_USED,    "thread finalized at slot %u, but that slot isn't in use", slot);
    SXEA1(thread_counters == all_counters[slot], "thread finalized at wrong slot %u", slot);
    kit_counters_combine(&dead_thread_counters, slot);
    memset(thread_counters, '\0', sizeof(*thread_counters));
    thread_counters = &dead_thread_counters;    /* So that thread destructors can call kit_free() - see pthread_key_create() */
    counter_state[slot] &= ~COUNTER_USED;
}

/**
 * Get a per thread, total, or shared counter value
 *
 * @param c         Counter
 * @param threadnum Thread slot number, KIT_THREAD_TOTAL for all threads, or KIT_THREAD_SHARED for the shared count
 *
 * @return The per thread or global counter value
 *
 * @note Unit tests may use this function to check for calls to modify the invalid counter by passing c == 0
 */
unsigned long long
kit_counter_get_data(kit_counter_t c, int threadnum)
{
    unsigned long long out_counter = 0;
    unsigned from, i, to;

    SXEA6(threadnum >= 0 || threadnum == KIT_THREAD_TOTAL || threadnum == KIT_THREAD_SHARED, "Invalid threadnum");
    SXEA6(thread0_initialized,                            "%s: Main thread not initialized!",    __FUNCTION__);
    SXEA6(allow_shared || threadnum != KIT_THREAD_SHARED, "%s: Shared counters are not enabled", __FUNCTION__);

    if (c <= num_counters && threadnum < (int)maxthreads) {
        if (!initialized) {
            SXEA1(thread_counters == &thread0_counters, "Can only be called by the main thread before counter initialization");
            out_counter = thread_counters->val[c];
        } else if (threadnum == KIT_THREAD_SHARED) {
            out_counter = shared_counters.val[c];
        } else {
            from = threadnum == KIT_THREAD_TOTAL ? 0          : (unsigned)threadnum;
            to   = threadnum == KIT_THREAD_TOTAL ? maxthreads : (unsigned)threadnum + 1;
            pthread_spin_lock(&counter_lock);

            for (i = from; i < to; i++)
                if (counter_state[i] & COUNTER_USED)
                    out_counter += all_counters[i]->val[c];

            if (threadnum == KIT_THREAD_TOTAL) {
                out_counter += dead_thread_counters.val[c];
                out_counter += shared_counters.val[c];
            }

            pthread_spin_unlock(&counter_lock);
        }

        /* Update if we're a "special" field */
        for (i = 0; i < num_handlers; i++)
            if (combine_handlers[i].counter == c) {
                out_counter = combine_handlers[i].handler(threadnum);
                break;
            }
    }

    return out_counter;
}

void
kit_counter_add(kit_counter_t c, unsigned long long value)
{
    if (c > num_counters)
        return;

    if (kit_counters_are_shared()) {
        if (c == INVALID_COUNTER)    // Make sure unitialized shared counters don't slow us down
            shared_counters.val[c] += value;
        else
            __atomic_add_fetch(&shared_counters.val[c], value, __ATOMIC_SEQ_CST);
    }
    else
        thread_counters->val[c] += value;
}

unsigned long long
kit_counter_get(kit_counter_t c)
{
    return c == INVALID_COUNTER ? 0 : kit_counter_get_data(c, -1);
}

void
kit_counter_zero(kit_counter_t c)
{
    if (c > num_counters)
        return;

    if (kit_counters_are_shared())
        shared_counters.val[c] = 0;
    else
        thread_counters->val[c] = 0;
}

unsigned
kit_counters_init_dynamic_thread(void)
{
    unsigned slot;

    SXEA6(initialized, "Counters not yet initialized");

    pthread_spin_lock(&counter_lock);

    for (slot = 0; slot < maxthreads; slot++)
        if (counter_state[slot] == COUNTER_DYNAMIC)
            break;

    SXEA1(slot < maxthreads, "Cannot locate a dynamic thread slot");
    thread_counters = all_counters[slot];
    counter_state[slot] |= COUNTER_USED;

    pthread_spin_unlock(&counter_lock);

    memset(thread_counters, '\0', sizeof(*thread_counters));
    return slot;
}

void
kit_counters_prepare_dynamic_threads(unsigned count)
{
    struct kit_counters **ncounters, **ocounters;
    uint8_t *nstate, nthreads, *ostate;
    unsigned done, i;

    SXEA6(initialized, "Counters not yet initialized");

    if (count) {
        pthread_spin_lock(&counter_lock);

        for (done = i = 0; i < maxthreads && done < count; i++)
            if (!counter_state[i]) {
                counter_state[i] = COUNTER_DYNAMIC;
                done++;
            }

        pthread_spin_unlock(&counter_lock);

        while (done < count) {
            nthreads = maxthreads + count - done;
            SXEA1(nstate = kit_malloc(nthreads * sizeof(*nstate)),
                  "Failed to allocate %zu bytes for per-thread counter_state", nthreads * sizeof(*nstate));
            SXEA1(ncounters = kit_malloc(nthreads * sizeof(*ncounters)),
                  "Failed to allocate %zu bytes for per-thread counter block pointers", nthreads * sizeof(*ncounters));

            for (i = maxthreads; i < nthreads; i++) {
                nstate[i] = COUNTER_DYNAMIC;
                SXEA1(ncounters[i] = kit_malloc(sizeof(*ncounters[i])),
                      "Failed to allocate %zu bytes for a thread counter block", sizeof(*ncounters[i]));
            }

            ocounters = NULL;
            ostate    = NULL;
            pthread_spin_lock(&counter_lock);

            if (maxthreads == nthreads - count + done) {
                /* Good, nothing's changed!  There should only be one thing calling us anyway */
                memcpy(ncounters, all_counters, maxthreads * sizeof(*ncounters));
                memcpy(nstate, counter_state, maxthreads * sizeof(*nstate));
                ostate = counter_state;
                ocounters = all_counters;
                counter_state = nstate;
                all_counters = ncounters;
                done += nthreads - maxthreads;
                maxthreads = nthreads;
            }

            pthread_spin_unlock(&counter_lock);
            kit_free(ocounters);
            kit_free(ostate);
        }
    }
}

void
kit_counters_fini_dynamic_thread(unsigned slot)
{
    SXEA6(initialized, "Counters not yet initialized");
    SXEA1(slot < maxthreads, "thread finalized as slot %u, but slot_count is %u", slot, maxthreads);
    SXEA1(counter_state[slot] == (COUNTER_USED|COUNTER_DYNAMIC), "thread finalized as slot %u, but that slot is not dynamic and in use", slot);
    kit_counters_combine(&dead_thread_counters, slot);
    thread_counters = &dead_thread_counters;    /* So that thread destructors can call kit_free() - see pthread_key_create() */
    counter_state[slot] = 0;
}

bool
kit_mibintree(const char *tree, const char *mib)
{
    size_t len = strlen(tree);

    return memcmp(tree, mib, len) == 0 && (len == 0 || mib[len] == '\0' || mib[len] == '.');
}

void
kit_counters_mib_text(const char *subtree, void *v, kit_counters_mib_callback_t cb, int threadnum, unsigned cflags)
{
    struct kit_counters counter_totals;
    unsigned long long val;
    const char *name;
    kit_mibfn_t mibfn;
    char buf[100];
    kit_counter_t c;
    unsigned i;

    SXEE6("(subtree=%s,v=%p,cb=%p,threadnum=%d)", subtree, v, cb, threadnum);

    memset(&counter_totals, '\0', sizeof(counter_totals));
    kit_counters_combine(&counter_totals, threadnum);

    for (i = 0; i < num_counters; i++) {
        c = kit_sorted_index(i);
        SXEA6(kit_counter_isvalid(c), "Invalid counter %u at index %u", c, i);

        val = counter_totals.val[c];
        name = kit_counter_txt(c);
        mibfn = mibfns[c];

        if (mibfn) {
            /* If the mib isn't part of the tree, is the tree in part of the mib?  If so, it *may* match */
            if (kit_mibintree(subtree, name) || kit_mibintree(name, subtree))
                mibfn(c, subtree, name, v, cb, threadnum, cflags);
        } else if (kit_mibintree(subtree, name)) {
            snprintf(buf, sizeof(buf), "%llu", val);
            cb(v, name, buf);
        }
    }

    SXER6("return");
}
