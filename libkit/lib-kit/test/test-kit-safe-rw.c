#include <sxe-util.h>
#include <fcntl.h>
#include <tap.h>
#include <errno.h>

#include "kit-safe-rw.h"

int
main(int argc, char **argv)
{
    char ch, buf[70000];
    ssize_t ret;
    unsigned i;
    int p[2];

    SXE_UNUSED_PARAMETER(argc);
    SXE_UNUSED_PARAMETER(argv);

    plan_tests(11);

    for (i = 0, ch = 'a'; i < sizeof(buf) - 1; i++, ch = ch == 'z' ? 'a' : ch + 1)
        buf[i] = ch;
    buf[i] = '\0';

    ok(pipe2(p, O_NONBLOCK) == 0, "Created a non-blocking pipe");
    ret = kit_safe_write(p[1], buf, sizeof(buf), 1);
    ok(ret != sizeof(buf), "Writing to one end of the pipe was truncated");
    is(errno, ETIMEDOUT, "errno is set to ETIMEOUT");
    close(p[0]);
    close(p[1]);

    ret = kit_safe_write(-1, buf, 10, 1);
    ok(ret != 10, "Writing to a dead file descriptor fails");
    is(errno, EBADF, "errno is set to EBADF");

    ok(pipe2(p, O_NONBLOCK) == 0, "Created a non-blocking pipe");
    ret = kit_safe_write(p[1], buf, 10, 1);
    ok(ret == 10, "Wrote 10 bytes to the pipe");
    ret = kit_safe_read(p[0], buf, 10);
    ok(ret == 10, "Read 10 bytes from the pipe");
    close(p[1]);
    ret = kit_safe_read(p[0], buf + 10, 10);
    ok(ret == 0, "Closed the other end, then read 0 bytes from the pipe");
    close(p[0]);

    ret = kit_safe_read(-1, buf, 10);
    ok(ret != 10, "Reading from a dead file descriptor fails");
    is(errno, EBADF, "errno is set to EBADF");

    return exit_status();
}
