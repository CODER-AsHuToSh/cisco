#include "kit-alloc-private.h"

#include <fcntl.h>
#include <mockfail.h>
#include <stdlib.h>
#include <string.h>
#include <sxe-util.h>
#include <jemalloc.h>

#ifdef __linux__
#include <malloc.h>
#endif

#ifdef __GLIBC__
#pragma GCC diagnostic ignored "-Waggregate-return"    // To allow use of glibc mallinfo
#endif

/*-
 * As of December 2012, the stock malloc implementation in linux is not
 * clever enough to handle the allocations requirements of opendnscache.
 *
 * This can be demonstrated by monitoring the following data:
 *
 *    VSZ of the process
 *        ps -axwwovsz,comm | sed -n 's, opednscache,,p'
 *
 *    # Inflight allocations & total
 *        my %stats = map { m{^"(\S+)\s(.+)"$} } `dig +short txt stats.opendns.com \@127.0.0.1`;
 *        my $inflight = $stats{'memory.calloc'} +
 *                       $stats{'memory.malloc'} -
 *                       $stats{'memory.free'};
 *        my $total = $stats{'memory.bytes'};
 *
 * On a busy resolver running with -c 800000000, you will see $inflight
 * settle at around 8,044,000 allocations and 1565 MB total.  It will
 * increase as pref files are loaded and then settle back to these numbers
 * afterwards.
 *
 * When it is settled, using jemalloc, the process VSZ starts at about
 * 2000 MB and increases to around 2450 MB after about 10 minutes.
 * It stabilizes at this value.
 *
 * Using the stock system malloc, the process VSZ starts at about
 * 2200 MB and increases to around 3219 MB in the first 10 minutes.
 * After that, on a machine with 3GB of RAM, it starts to swap and
 * takes so long to load a prefs file that there's another one there
 * before it's done.
 */

#if SXE_DEBUG
int kit_alloc_diagnostics;
#define KIT_ALLOC_LOG(...) do { if (kit_alloc_diagnostics) SXEL6(__VA_ARGS__); } while (0)
#else
#define KIT_ALLOC_LOG(...) do { } while (0)
#endif

// The level to which kit-memory has been initialized
enum kit_memory_init_level {
    KIT_MEMORY_INIT_NONE,    // Uninitialized
    KIT_MEMORY_INIT_SOFT,    // Internally initialized by kit_counters with minimal defaults; primarily for memory leak checks
    KIT_MEMORY_INIT_HARD     // Initialized by the user of libkit; this can only be done once
} kit_memory_init_level = KIT_MEMORY_INIT_NONE;

struct kit_memory_counters kit_memory_counters;                     // Global counters
size_t                     kit_memory_allocated_max     = 0;        // Tracks the high watermark ever allocated with jemalloc
static bool                kit_memory_assert_on_enomem  = false;    // By default, return NULL on failure to allocate memory

#ifdef __linux__
static int proc_statm_fd = -1;    // Open file descriptor on /proc/<pid>/statm; must be opened before calling chroot
#endif

static unsigned long long
counter_bytes_combine_handler(int threadnum)
{
    return threadnum <= 0 ? kit_allocated_bytes() : 0;
}

/**
 * Initialize the memory interface
 *
 * @param hard True if this is an external call to initialize kit-memory
 *
 * @note This function should only be called internally (by kit-memory and kit-counters).
 */
void
kit_memory_init_internal(bool hard)
{
    enum kit_memory_init_level old_level = kit_memory_init_level;

    SXEA1(kit_memory_init_level != KIT_MEMORY_INIT_HARD, "Kit memory is already initialized");

    // Set this immediately to prevent infinite recursion via kit_counters_add
    kit_memory_init_level = hard ? KIT_MEMORY_INIT_HARD : KIT_MEMORY_INIT_SOFT;

    if (old_level != KIT_MEMORY_INIT_NONE)    // If kit-memory was already initialized, return
        return;

    kit_memory_counters.bytes   = kit_counter_new_with_combine_handler("memory.bytes", counter_bytes_combine_handler);
    kit_memory_counters.calloc  = kit_counter_new("memory.calloc");
    kit_memory_counters.fail    = kit_counter_new("memory.fail");
    kit_memory_counters.free    = kit_counter_new("memory.free");
    kit_memory_counters.malloc  = kit_counter_new("memory.malloc");
    kit_memory_counters.realloc = kit_counter_new("memory.realloc");

#ifdef __linux__
    char proc_statm_path[PATH_MAX];
    int  pid;

    pid = getpid();
    snprintf(proc_statm_path, sizeof(proc_statm_path), "/proc/%d/statm", pid);
    proc_statm_fd = open(proc_statm_path, O_RDONLY);
#endif

#if SXE_DEBUG
    const char *KIT_ALLOC_DIAGNOSTICS = getenv("KIT_ALLOC_DIAGNOSTICS");

    if (KIT_ALLOC_DIAGNOSTICS && KIT_ALLOC_DIAGNOSTICS[0] && KIT_ALLOC_DIAGNOSTICS[0] != '0')
        kit_alloc_diagnostics = 1;
#endif
}

/**
 * Initialize the kit memory management interface; this should done once, normally on an application wide basis
 *
 * @param assert_on_enomem true to enable assertions on memory allocation failure, false (default) to make sure no one changes
 */
void
kit_memory_initialize(bool assert_on_enomem)
{
    kit_memory_assert_on_enomem = assert_on_enomem;
    kit_memory_init_internal(true);
}

bool
kit_memory_is_initialized(void)
{
    return kit_memory_init_level != KIT_MEMORY_INIT_NONE;
}

__attribute__((malloc)) void *
KIT_ALLOC_MANGLE(kit_malloc)(size_t size KIT_ALLOC_SOURCE_PROTO)
{
    void *result = je_malloc(size);

    SXEA1(!kit_memory_assert_on_enomem || result, "%s: failed to allocate %zu bytes of memory", __FUNCTION__, size);
    kit_counter_incr(KIT_COUNTER_MEMORY_MALLOC);

    if (result == NULL)
        kit_counter_incr(KIT_COUNTER_MEMORY_FAIL);    /* COVERAGE EXCLUSION: todo: mock malloc() to create failure */

    KIT_ALLOC_LOG("%s: %d: %p = kit_malloc(%zu)", file, line, result, size);
    return result;
}

__attribute__((malloc)) void *
KIT_ALLOC_MANGLE(kit_calloc)(size_t num, size_t size KIT_ALLOC_SOURCE_PROTO)
{
    void *result = je_calloc(num, size);

    SXEA1(!kit_memory_assert_on_enomem || result, "%s: failed to allocate %zu %zu byte objects", __FUNCTION__, num, size);
    kit_counter_incr(KIT_COUNTER_MEMORY_CALLOC);

    if (result == NULL)
        kit_counter_incr(KIT_COUNTER_MEMORY_FAIL);    /* COVERAGE EXCLUSION: todo: mock calloc() to create failure */

    KIT_ALLOC_LOG("%s: %d: %p = kit_calloc(%zu, %zu)", file, line, result, num, size);
    return result;
}

void
KIT_ALLOC_MANGLE(kit_free)(void *ptr KIT_ALLOC_SOURCE_PROTO)
{
    if (ptr) {
        KIT_ALLOC_LOG("%s: %d: kit_free(%p)", file, line, ptr);
        kit_counter_incr(KIT_COUNTER_MEMORY_FREE);
        SXEA6(!(((long)ptr) & 7), "ungranular free(%p)", ptr);
    }
#if SXE_DEBUG
    else if (kit_alloc_diagnostics > 1)
        SXEL6("%s: %d: kit_free((nil))", file, line);
#endif

    je_free(ptr);
}

/*-
 * Special case for realloc() since it can behave like malloc() or free() !
 */
void *
KIT_ALLOC_MANGLE(kit_realloc)(void *ptr, size_t size KIT_ALLOC_SOURCE_PROTO)
{
    void *result = je_realloc(ptr, size);

    if (result == NULL && (size || ptr == NULL)) {
        SXEA1(!kit_memory_assert_on_enomem, "%s: failed to reallocate object to %zu bytes", __FUNCTION__, size);
        kit_counter_incr(KIT_COUNTER_MEMORY_FAIL);    /* COVERAGE EXCLUSION: todo: mock realloc() to create failure */
    }

    if (ptr == NULL && result != NULL)
        kit_counter_incr(KIT_COUNTER_MEMORY_MALLOC);
    else if (size == 0 && result == NULL)
        kit_counter_incr(KIT_COUNTER_MEMORY_FREE);
    else
        kit_counter_incr(KIT_COUNTER_MEMORY_REALLOC);

    KIT_ALLOC_LOG("%s: %d: %p = kit_realloc(%p, %zu)", file, line, result, ptr, size);
    return result;
}

void *
KIT_ALLOC_MANGLE(kit_reduce)(void *ptr, size_t size KIT_ALLOC_SOURCE_PROTO)
{
    void *result;

    /*-
     * We're aiming for two things here:
     * - Don't turn realloc(NULL, 0) into malloc(0)
     * - If realloc() fails, return the original
     */
    if (ptr) {
        if ((result = MOCKFAIL(KIT_ALLOC_MANGLE(kit_reduce), NULL, je_realloc(ptr, size))) == NULL) {
            if (size == 0)
                kit_counter_incr(KIT_COUNTER_MEMORY_FREE);
            else {
                kit_counter_incr(KIT_COUNTER_MEMORY_FAIL);
                result = ptr;
            }
        }

        if (result != ptr)
            KIT_ALLOC_LOG("%s: %d: %p = kit_realloc(%p, %zu)", file, line, result, ptr, size);
    } else {
        SXEA1(!size, "Cannot kit_reduce() NULL to size %zu", size);
        result = NULL;
    }

    return result;
}

__attribute__((malloc)) char *
KIT_ALLOC_MANGLE(kit_strdup)(const char *txt KIT_ALLOC_SOURCE_PROTO)
{
    size_t len    = strlen(txt);
    void  *result = je_malloc(len + 1);

    if (result == NULL) {
        SXEA1(!kit_memory_assert_on_enomem, "%s: failed to allocate %zu bytes of memory", __FUNCTION__, len + 1);
        kit_counter_incr(KIT_COUNTER_MEMORY_FAIL);    /* COVERAGE EXCLUSION: todo: mock malloc() to create failure */
    }

    kit_counter_incr(KIT_COUNTER_MEMORY_MALLOC);

    if (result)
        strcpy(result, txt);

    KIT_ALLOC_LOG("%s: %d: %p = kit_strdup(%p[%zu])", file, line, result, txt, len + 1);
    return result;
}

#if SXE_DEBUG

/*-
 * The debug version of jemalloc is built with --enable-debug and
 * --enable-fill.  We enable junk and redzone by default so that we
 * detect memory underflows and some overflows.
 *
 * It's worth noting that this triggers an assert():
 *     char *ptr = je_malloc(8);
 *     ptr[8] = 'x';
 *     je_free(ptr);
 *
 * But this doesn't, due to the rounding that jemalloc does:
 *     char *ptr = je_malloc(3);
 *     ptr[3] = 'x';
 *     je_free(ptr);
 */
const char *je_malloc_conf = "junk:true,redzone:true";

#else // For the non-debug build, the following diag wrappers are needed for openssl hooks

void *
kit_malloc_diag(size_t size, const char *file, int line)
{
    SXE_UNUSED_PARAMETER(file);
    SXE_UNUSED_PARAMETER(line);
    return kit_malloc(size);
}

void *
kit_realloc_diag(void *ptr, size_t size, const char *file, int line)
{
    SXE_UNUSED_PARAMETER(file);
    SXE_UNUSED_PARAMETER(line);
    return kit_realloc(ptr, size);
}

void
kit_free_diag(void *ptr, const char *file, int line)
{
    SXE_UNUSED_PARAMETER(file);
    SXE_UNUSED_PARAMETER(line);
    kit_free(ptr);
}

#endif

size_t
kit_allocated_bytes(void)
{
    static bool   kit_mib_init          = false;    // Set to true once memory mib ids are initialized
    static size_t kit_epoch_mib[1];                 // Binary mib id of the "epoch"
    static size_t kit_epoch_mib_len     = 1;        // Number of elements in the mib id
    static size_t kit_allocated_mib[2];             // Binary mib id of "stats.allocated"
    static size_t kit_allocated_mib_len = 2;        // Number of elements in the mib id
    size_t        len, alloc;
    uint64_t      epoch;

    if (!kit_mib_init) {
        // To optimize collection of je_malloc statistics, get binary MIB ids
        //
        SXEA1(!je_mallctlnametomib("epoch", kit_epoch_mib, &kit_epoch_mib_len)
           && !je_mallctlnametomib("stats.allocated", kit_allocated_mib, &kit_allocated_mib_len),
              "Failed to generated binary mib id for je_malloc's epoch or stats.allocated");
        kit_mib_init = true;
    }

    epoch = 1;
    len = sizeof(epoch);
    je_mallctlbymib(kit_epoch_mib, kit_epoch_mib_len, &epoch, &len, &epoch, len);

    len = sizeof(alloc);
    je_mallctlbymib(kit_allocated_mib, kit_allocated_mib_len, &alloc, &len, NULL, 0);

    if (alloc > kit_memory_allocated_max)
        kit_memory_allocated_max = alloc;

    return alloc;
}

uint64_t
kit_thread_allocated_bytes(void)
{
    static __thread uint64_t *allocatedp, *deallocatedp;
    size_t len;

    len = sizeof(allocatedp);
    if (!allocatedp) {
        je_mallctl("thread.allocatedp", &allocatedp, &len, NULL, 0);
        SXEA1(allocatedp, "Couldn't obtain thread.allocatedp, is jemalloc built with --enable-stats?");
    }

    len = sizeof(deallocatedp);
    if (!deallocatedp) {
        je_mallctl("thread.deallocatedp", &deallocatedp, &len, NULL, 0);
        SXEA1(deallocatedp, "Couldn't obtain thread.deallocatedp, is jemalloc built with --enable-stats?");
    }

    return *allocatedp - *deallocatedp;
}

bool
kit_memory_log_growth(__printflike(1, 2) int (*printer)(const char *format, ...))
{
    static size_t jemalloc_allocated_max = 0;
    size_t        jemalloc_allocated_cur = kit_allocated_bytes();
    bool          growth                 = false;

    if (jemalloc_allocated_cur > jemalloc_allocated_max) {
        (*printer)("Maximum memory allocated via jemalloc %zu (previous maximum %zu)\n", jemalloc_allocated_cur,
                   jemalloc_allocated_max);
        jemalloc_allocated_max = jemalloc_allocated_cur;
        growth                 = true;
    }

#ifdef __GLIBC__
    static size_t   glibc_allocated_max = 0;    // High watermark of glibc bytes allocated
    struct mallinfo glibc_mallinfo;

    glibc_mallinfo = mallinfo();

    if ((size_t)glibc_mallinfo.uordblks > glibc_allocated_max) {
        (*printer)("Maximum memory allocated via glibc %zu (previous maximum %zu)\n", (size_t)glibc_mallinfo.uordblks,
                   glibc_allocated_max);
        glibc_allocated_max = (size_t)glibc_mallinfo.uordblks;
        growth              = true;
    }
#endif

#ifdef __linux__
    static size_t rss_max = 0;    // High watermark of RSS pages allocated
    long long     rss_cur;
    char          buf[256];       // Buffer for /proc/<pid>/statm contents (e.g. "14214701 8277571 1403 269 0 14138966 0")
    ssize_t       len;
    char         *rss_str;
    char         *end_ptr;

    // If the /proc/<pid>/statm is open, seek to start and read contents
    if (proc_statm_fd >= 0 && lseek(proc_statm_fd, 0, SEEK_SET) != (off_t)-1
     && (len = read(proc_statm_fd, buf, sizeof(buf) - 1)) >= 0) {
        buf[len] = '\0';

        if ((rss_str = strchr(buf, ' '))) {    // Find the RSS number in the string
            rss_str++;

            // Try to convert to a number and, if a new maximum, log it
            if ((rss_cur = strtoll(rss_str, &end_ptr, 10)) > 0 && *end_ptr == ' ' && (size_t)rss_cur > rss_max) {
                (*printer)("Maximum memory allocated in RSS pages %zu (previous maximum %zu)\n", (size_t)rss_cur, rss_max);
                rss_max = (size_t)rss_cur;
                growth  = true;
            }
        }
    }
#endif

    return growth;
}

struct printer_visitor {
    int                      written;
    __printflike(1, 2) int (*printer)(const char *format, ...);
};

static void
memory_stats_line(void *visitor_void, const char *line)
{
    struct printer_visitor *visitor = visitor_void;

    if (visitor->written < 0)
        return;    /* COVERAGE EXCLUSION - Test printer failure case */

    int written = (*visitor->printer)("%s", line);

    if (written >= 0)
        visitor->written += written;
    else
        visitor->written  = written;    /* COVERAGE EXCLUSION - Test printer failure case */
}

bool
kit_memory_log_stats(__printflike(1, 2) int (*printer)(const char *format, ...), const char *options)
{
    struct printer_visitor visitor;

    visitor.written = 0;
    visitor.printer = printer;
    je_malloc_stats_print(memory_stats_line, &visitor, options ?: "gblxe");
    return visitor.written > 0;
}
