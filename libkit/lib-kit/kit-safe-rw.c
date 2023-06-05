#include "kit-safe-rw.h"
#include <errno.h>
#include <poll.h>

#include <sxe-log.h>

ssize_t
kit_safe_write(const int fd, const void *const buf_, size_t count, const int timeout)
{
    struct pollfd  pfd;
    const char    *buf = (const char *) buf_;
    ssize_t        written, result;
    size_t         tmp_count = count;

    pfd.fd = fd;
    pfd.events = POLLOUT;

    while (tmp_count > (size_t) 0) {
        while ((written = write(fd, buf, tmp_count)) <= (ssize_t) 0) {
            if (errno == EAGAIN) {
                if (poll(&pfd, (nfds_t) 1, timeout) == 0) {
                    errno = ETIMEDOUT;
                    goto SXE_EARLY_OUT;
                }
            } else if (errno != EINTR)
                goto SXE_EARLY_OUT;
        }
        buf += written;
        tmp_count -= written;
    }

SXE_EARLY_OUT:
    result = (ssize_t)(buf - (const char *)buf_);

    SXEL7("kit_safe_write(fd=%d, buf=%p, count=%zu, timeout=%d){} // %zd", fd, buf_, count, timeout, result);
    return result;
}

ssize_t
kit_safe_read(const int fd, void *const buf_, size_t count)
{
    unsigned char *buf = (unsigned char *) buf_;
    ssize_t        readnb;
    ssize_t        result;

    SXEE7("(fd=%d, buf=%p, count=%zu)", fd, buf, count);

    do {
        while ((readnb = read(fd, buf, count)) < 0 && errno == EINTR)
            ;
        if (readnb < 0) {
            result = readnb;
            goto SXE_EARLY_OUT;
        }
        if (readnb == 0)
            break;
        count -= readnb;
        buf += readnb;
    } while (count > 0);

    result = (ssize_t)(buf - (unsigned char *)buf_);

SXE_EARLY_OUT:
    SXER7("return %zd", result);

    return result;
}
