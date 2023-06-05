#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <kit-alloc.h>
#include <kit-counters.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if __FreeBSD__
#include <sys/param.h>
#endif

#include "unaligned.h"

#include "common-test.h"

__printflike(2, 3) const char *
create_data(const char *testname, const char *data, ...)
{
    const char *fn;
    char *block;
    ssize_t len;
    va_list ap;

    va_start(ap, data);
    SXEA1((len = vasprintf(&block, data, ap)) != -1, "Failed to vasprintf() data");
    va_end(ap);

    fn = create_binary_data(testname, block, len);
    free(block);
    return fn;
}

const char *
create_binary_data(const char *testname, const void *data, size_t len)
{
    static char filename[PATH_MAX];
    int fd;

    snprintf(filename, sizeof(filename), "/tmp/%s.XXXXXXXX", testname);
    if ((fd = mkstemp(filename)) == -1) {
        perror("mkstemp");
        exit(1);
    }

    if (write(fd, data, len) != (ssize_t)len) {
        perror("write");
        exit(1);
    }
    close(fd);

    return filename;
}

#define DOT ".common-test-tmpfile"

__printflike(2, 3) bool
create_atomic_file(const char *fn, const char *data, ...)
{
    char *block;
    ssize_t len;
    va_list ap;
    ssize_t wr;
    int fd;

    if ((fd = open(DOT, O_WRONLY|O_CREAT, 0666)) == -1)
        return false;

    va_start(ap, data);
    SXEA1((len = vasprintf(&block, data, ap)) != -1, "Failed to vasprintf() data");
    va_end(ap);

    wr = write(fd, block, len);
    close(fd);
    free(block);

    return wr == len && rename(DOT, fn) == 0;
}

uint64_t
memory_allocations()
{
    SXEA1(kit_memory_is_initialized(), "You forgot to initialize memory");

    return kit_counter_get(KIT_COUNTER_MEMORY_CALLOC) +
           kit_counter_get(KIT_COUNTER_MEMORY_MALLOC) -
           kit_counter_get(KIT_COUNTER_MEMORY_FREE);
}

unsigned
rrmdir(const char *dir)
{
    struct dirent *ent;
    char fn[PATH_MAX];
    struct stat st;
    int err;
    DIR *d;

    err = 0;
    if ((d = opendir(dir)) != NULL) {
        while ((ent = readdir(d)) != NULL) {
            snprintf(fn, sizeof(fn), "%s/%s", dir, ent->d_name);

            if (lstat(fn, &st) == -1) {
                perror(fn);
                err++;
            } else if (!S_ISDIR(st.st_mode))
                remove(fn);
            else if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0)
                err += rrmdir(fn);
        }
        closedir(d);
    } else if (errno != ENOENT) {
        perror(dir);
        err++;
    }

    rmdir(dir);

    return err;
}

int
showdir(const char *dir, FILE *out)
{
    char buf[1024], fn[PATH_MAX];
    struct dirent *ent;
    unsigned lines, n;
    struct stat st;
    FILE *fp;
    DIR *d;

    lines = 0;
    if ((d = opendir(dir)) != NULL) {
        n = 0;
        while ((ent = readdir(d)) != NULL)
            if (*ent->d_name != '.') {
                snprintf(fn, sizeof(fn), "%s/%s", dir, ent->d_name);

                if (lstat(fn, &st) != -1 && S_ISREG(st.st_mode) && (fp = fopen(fn, "r")) != NULL) {
                    if (out) {
                        fprintf(out, "File %u\n", n);
                        fputs("---- 8>< ----\n", out);
                    }
                    while (fgets(buf, sizeof(buf), fp) != NULL) {
                        lines++;
                        if (out)
                            fputs(buf, out);
                    }
                    fclose(fp);
                    if (out)
                        fputs("---- 8>< ----\n", out);
                }
            }

        closedir(d);
    }

    return lines;
}

#define SXELOG_BUFSZ 8192
static struct {
    char buf[SXELOG_BUFSZ];
    ssize_t len;
    SXE_LOG_LEVEL passthru;
    void (*ologit)(SXE_LOG_LEVEL, const char *);
    pthread_mutex_t lock;
} sxelog;

void
test_clear_sxel(void)
{
    pthread_mutex_lock(&sxelog.lock);
    sxelog.len    = 0;
    sxelog.buf[0] = '\0';
    pthread_mutex_unlock(&sxelog.lock);
}

static char *
test_shift_sxel_nolock(void)
{
    static __thread char buf[SXELOG_BUFSZ];
    const char *lf;
    ssize_t len;

    if (sxelog.len) {
        lf = memchr(sxelog.buf, '\n', sxelog.len);
        len = lf ? lf - sxelog.buf + 1 : sxelog.len;
        memcpy(buf, sxelog.buf, len);
        memmove(sxelog.buf, sxelog.buf + len, sxelog.len - len + 1);
        sxelog.len -= len;
    } else
        len = 0;
    buf[len] = '\0';

    return buf;
}

char *
test_shift_sxel(void)    /* Give the caller a writable version of the first log line, consuming it */
{
    char *ret;

    pthread_mutex_lock(&sxelog.lock);
    ret = test_shift_sxel_nolock();
    pthread_mutex_unlock(&sxelog.lock);

    return ret;
}

const char *
test_tail_sxel(void)    /* Give the caller a view-only look at the last log line */
{
    static __thread char buf[SXELOG_BUFSZ];
    const char *lf;
    ssize_t len;

    pthread_mutex_lock(&sxelog.lock);
    if (sxelog.len) {
        lf = memrchr(sxelog.buf, '\n', sxelog.len - (sxelog.buf[sxelog.len - 1] == '\n'));
        lf = lf == NULL ? sxelog.buf : lf + 1;
        len = sxelog.len - (lf - sxelog.buf);
        memcpy(buf, lf, len);
    } else
        len = 0;
    buf[len] = '\0';
    pthread_mutex_unlock(&sxelog.lock);

    return buf;
}

const char *
test_all_sxel(void)
{
    return sxelog.buf;
}

static void
logit(SXE_LOG_LEVEL level, const char *line)
{
    size_t len;

    pthread_mutex_lock(&sxelog.lock);
    if (level >= sxelog.passthru)
        sxelog.ologit(level, line);
    else if ((len = strlen(line)) != 0) {
        while (sxelog.len && len >= sizeof(sxelog.buf) - sxelog.len)
            test_shift_sxel_nolock();
        if (len >= sizeof(sxelog.buf) - sxelog.len)
            len = sizeof(sxelog.buf) - sxelog.len - 1;
        memcpy(sxelog.buf + sxelog.len, line, len);
        sxelog.buf[sxelog.len += len] = '\0';
    }
    pthread_mutex_unlock(&sxelog.lock);
}

void
test_capture_sxel(void)
{
    SXEA1(sxelog.ologit == NULL, "You've already called test_capture_sxel()");
    pthread_mutex_init(&sxelog.lock, NULL);
    sxelog.ologit = sxe_log_hook_line_out(logit);
    test_passthru_sxel(SXE_LOG_LEVEL_DUMP /* 7 */);    // Ignore dump so that tests don't cack on messages hacked in to debug code
}

/**
 * @param level Log level at which to stop capturing logs or SXE_LOG_LEVEL_OVER_MAXIMUM (8) to capture all (even dump) messages
 */
void
test_passthru_sxel(SXE_LOG_LEVEL level)
{
    sxelog.passthru = level;
}

void
test_uncapture_sxel(void)
{
    SXEA1(sxelog.ologit != NULL, "You haven't yet called test_capture_sxel()");
    SXEA1(sxe_log_hook_line_out(sxelog.ologit) == logit, "Someone else called sxe_log_hook_line_out()");
    pthread_mutex_destroy(&sxelog.lock);
    sxelog.ologit = NULL;
}

void
ok_sxel_error(unsigned lineno, const char *fmt, ...)
{
    char    str[1024];
    va_list ap;

    if (fmt == NULL)
        is_eq(test_shift_sxel(), "", "Found no errors at line %u", lineno);
    else {
        SXEA1(strcmp(fmt, ""), "The argument passed in should not be an empty string");
        va_start(ap, fmt);

        if (sizeof(str) <= (unsigned)vsnprintf(str, sizeof(str), fmt, ap))
            fail("Test overflowed 1024 byte string buffer at line %u: '%s'", lineno, str);
        else
            is_strstr(test_shift_sxel(), str, "Found the correct error at line %u: %s", lineno, str);

        va_end(ap);
    }
}

bool
ok_sxel_allerrors(unsigned lineno, const char *str)
{
    bool ret = *str ? is_strstr(test_all_sxel(), str, "Found the correct error at line %u: %s", lineno, str)
                    : is_eq(test_all_sxel(), "", "Found no errors at line %u", lineno);
    test_clear_sxel();
    return ret;
}
