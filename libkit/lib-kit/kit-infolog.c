#include <kit.h>
#include <kit-safe-rw.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>     /* for syscall(), SYS_gettid */

#if __FreeBSD__
#include <sys/socket.h>
#endif

#include "kit-infolog.h"

#define DELAY_BETWEEN_IDENTICAL_LOG_ENTRIES     1
#define ALLOWED_BURST_FOR_IDENTICAL_LOG_ENTRIES 10U

unsigned kit_infolog_flags;

__printflike(1, 2) int
kit_infolog_printf(const char *format, ...)
{
    static __thread char buf[KIT_INFOLOG_MAX_LINE];
    static __thread char previous_buf[KIT_INFOLOG_MAX_LINE];
    static __thread uint32_t last_log_ts = 0U;
    static __thread unsigned burst_counter = 0U;
    uint32_t now = kit_time_sec();
    int i, len;
    va_list ap;

#ifdef __APPLE__
    pid_t thread_id = syscall(SYS_thread_selfid);
#elif defined(__FreeBSD__)
    pthread_t thread_id = pthread_self();
#else /* __linux__ */
    pid_t thread_id = syscall(SYS_gettid);
#endif

    len = snprintf(buf, sizeof(buf), "%ld ", (long)thread_id);
    SXEA6((size_t)len < sizeof(buf), "An unsigned hex value doesn't fit in %zu bytes", sizeof(buf));

    va_start(ap, format);
    i = vsnprintf(buf + len, sizeof(buf) - len, format, ap);

    if ((size_t)i < sizeof(buf) - len)
        len += i; //
    else {
        memcpy(buf + sizeof(buf) - sizeof("..."), "...", sizeof("..."));
        len = sizeof(buf) - 1;
    }

    va_end(ap);

    if (len && buf[len - 1] != '\n')
        buf[len++] = '\n';    /* Not NUL terminated */

    if (memcmp(previous_buf, buf, len) == 0) {
        burst_counter++; //

        if (burst_counter > ALLOWED_BURST_FOR_IDENTICAL_LOG_ENTRIES
         && now - last_log_ts < DELAY_BETWEEN_IDENTICAL_LOG_ENTRIES)
            return 0;
    } else
        burst_counter = 0;

    last_log_ts = now;
    memcpy(previous_buf, buf, len);
    kit_safe_write(STDERR_FILENO, buf, len, -1);
    return len;
}
