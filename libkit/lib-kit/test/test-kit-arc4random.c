#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <tap.h>

#include "kit-arc4random.h"

int
main(void)
{
    int p[2], status;
    uint8_t buf[100];
    char ch;

    plan_tests(8);

    kit_arc4random_init(open("/dev/urandom", O_RDONLY));
    ok(!kit_arc4random_internals_initialized(), "kit_arc4random internals are not initialized after kit_arc4random_init()");
    kit_arc4random();
    ok(kit_arc4random_internals_initialized(), "kit_arc4random internals are initialized after kit_arc4random() use");
    kit_arc4random_stir();
    kit_arc4random_buf(buf, 100);
    ok(kit_arc4random_uniform(5) < 5, "kit_arc4random_uniform returned valid random number");

    ok(pipe(p) == 0, "Created an unnamed pipe");
    if (fork()) {
        close(p[1]);
        is(read(p[0], &ch, 1), 1, "Read the first result");
        ok(!ch, "kit_arc4random child internals are not initialized after fork()");
        is(read(p[0], &ch, 1), 1, "Read the second result");
        ok(ch, "kit_arc4random child internals are initialized after kit_arc4random() use");
        close(p[0]);
        wait(&status);
    } else {
        close(p[0]);
        ch = kit_arc4random_internals_initialized();
        if (write(p[1], &ch, 1) != 1)
            diag("Write failed");
        kit_arc4random();
        ch = kit_arc4random_internals_initialized();
        if (write(p[1], &ch, 1) != 1)
            diag("Write failed");
        close(p[1]);
    }

    return exit_status();
}
