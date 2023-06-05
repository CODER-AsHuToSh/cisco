#include <kit-alloc.h>
#include <mockfail.h>
#include <string.h>

#include "common-test.h"
#include "xray.h"

int
main(void)
{
    char buf[271], buf2[271], buf3[521];
    uint64_t start_allocations;
    const char *sxediag;
    struct xray x;
    unsigned i, pid;

    plan_tests(45);

    /* SXELOG adds the PID to each log entry on FreeBSD, so adjust the size for including this */
#if __FreeBSD__
    pid = 12;
#else
    pid = 0;
#endif

    memset(&x, '\0', sizeof(x));

    kit_memory_initialize(false);
    /* KIT_ALLOC_SET_LOG(1); */    /* for kit-alloc-analyze data */
    ok(start_allocations = memory_allocations(), "We have memory allocations at startup time");

    test_capture_sxel();

    MOCKFAIL_START_TESTS(3, xray_init_for_client);
    diag("Test malloc failures");
    test_clear_sxel();
    ok(!xray_init_for_client(&x, 100), "xray_init_for_client() fails when allocations fail");
    ok(!x.addr, "xray_init_for_client() left the address empty");
    is_strstr(test_all_sxel(), "Couldn't allocate 100 xray bytes", "Got the expected error");
    MOCKFAIL_END_TESTS();

    diag("Test that calling xray(x, ...) with an uninitialized 'x' does nothing");
    test_clear_sxel();
    xray(&x, 6, "This diagnostic goes nowhere, x is not uninitialized");
    is(x.used, 0, "Our xray() call did nothing");

    diag("Test normal initalization");
    ok(xray_init_for_client(&x, 100), "xray_init_for_client() succeeds");
    ok(x.addr, "xray_init_for_client() set its address");
    ok(xraying_for_client(&x), "xraying_for_client() succeeds");
    xray_fini_for_client(&x);
    ok(!x.addr, "xray_fini() cleared the address");

    diag("We can't handle tiny client xray allocations followed by a log xray request");
    ok(xray_init_for_client(&x, 100), "xray_init_for_client() succeeds");
    ok(!xray_init_for_log(&x), "xray_init_for_log() fails because it wants at least 257 bytes of buffer");
    xray_fini(&x);

    diag("We can xray for a client and to the log");
    ok(xray_init_for_client(&x, 500), "xray_init_for_client() succeeds");
    ok(xray_init_for_log(&x), "xray_init_for_log() succeeds too");
    for (i = 0; i + 10 < sizeof(buf); i += 10)
        strcpy(buf + i, "abcdefghi ");
    is(strlen(buf), 270, "Created a text buffer of 270 bytes -- bigger than 256");

    diag("Testing trimming behaviour");
    test_clear_sxel();
    xray(&x, 6, "%s", buf);
    is(x.used, 256, "Our xray() call was trimmed at 255+1 bytes");
    DEBUG_DIAGS_START(2);
    sxediag = test_shift_sxel();
    is_strstr(sxediag, "appending 1+255 bytes", "Got the right SXEL6 diagnostic message");
    is(strlen(sxediag), 345 + pid, "The SXEL6 diagnostic was truncated correctly");
    DEBUG_DIAGS_END();

    xray(&x, 6, "%.*s", 243, buf);
    is(x.used, 499, "Our 2nd xray() call was trimmed at 242+1 bytes");

    xray(&x, 6, "%s", buf);
    is(x.used, 499, "Our 3rd xray() call was a no-op");

    xray_fini(&x);

    diag("Testing xray_long_line()");
    ok(xray_init_for_client(&x, 1024), "xray_init_for_client() succeeds");
    test_clear_sxel();
    xray_long_line(&x, "test-xray: ", "xray_long_line(): ", buf);
    is(x.used, 303, "Our xray_long_line() call logged 303 bytes");
    xray_fini(&x);

    diag("Testing behaviour for rediculous prefix1 strings");
    ok(xray_init_for_client(&x, 1024), "xray_init_for_client() succeeds");
    for (i = 0; i + 9 < sizeof(buf); i += 9)
        strcpy(buf + i, "prefix-1 ");
    is(strlen(buf), 270, "Created a prefix1 buffer of 270 bytes -- bigger than 256");
    test_clear_sxel();
    xray_long_line(&x, buf, "prefix2 ", "data");
    is(x.used, 284, "Our xray_long_line() with a huge prefix1 logged 284 bytes");
    DEBUG_DIAGS_START(3);
    sxediag = test_all_sxel();
    is_strstr(sxediag, "appending 1+255 bytes", "Got the right SXEL6 overflow diagnostic message");
    is_strstr(sxediag, "appending 1+27 bytes", "Got the right SXEL6 tail diagnostic message");
    is(strlen(sxediag), 463 + pid * 2, "The SXEL6 diagnostic was split correctly");
    DEBUG_DIAGS_END();
    xray_fini(&x);

    diag("Testing behaviour for rediculous prefix1 *AND* prefix2 strings");
    ok(xray_init_for_client(&x, 1024), "xray_init_for_client() succeeds");
    for (i = 0; i + 8 < sizeof(buf); i += 8)
        strcpy(buf + i, "prefix1 ");
    is(strlen(buf), 264, "Created a prefix1 buffer of 264 bytes -- bigger than 256 and fits evenly at 254 bytes");
    for (i = 0; i + 8 < sizeof(buf2); i += 8)
        strcpy(buf2 + i, "prefix2 ");
    is(strlen(buf), 264, "Created a prefix2 buffer of 264 bytes -- bigger than 256");
    test_clear_sxel();
    xray_long_line(&x, buf, buf2, "data");
    is(x.used, 535, "Our xray_long_line() with a huge prefix1 and prefix2 logged 535 bytes");
    DEBUG_DIAGS_START(4);
    sxediag = test_all_sxel();
    is_strstr(sxediag, "appending 1+255 bytes @ offset 0", "Got the right first SXEL6 overflow diagnostic message");
    is_strstr(sxediag, "appending 1+255 bytes @ offset 256", "Got the right second SXEL6 overflow diagnostic message");
    is_strstr(sxediag, "appending 1+22 bytes", "Got the right SXEL6 tail diagnostic message");
    is(strlen(sxediag), 805 + pid * 3, "The SXEL6 diagnostic was split correctly");
    DEBUG_DIAGS_END();
    xray_fini(&x);

    diag("Testing behaviour for rediculous prefix1 *AND* *SUPER-rediculous* prefix2 strings");
    ok(xray_init_for_client(&x, 1024), "xray_init_for_client() succeeds");
    for (i = 0; i + 8 < sizeof(buf); i += 8)
        strcpy(buf + i, "prefix1 ");
    is(strlen(buf), 264, "Created a prefix1 buffer of 264 bytes -- bigger than 256 and fits evenly at 254 bytes");
    for (i = 0; i + 8 < sizeof(buf3); i += 8)
        strcpy(buf3 + i, "prefix2 ");
    is(strlen(buf), 264, "Created a prefix2 buffer of 264 bytes -- bigger than 256");
    test_clear_sxel();
    xray_long_line(&x, buf, buf3, "data");
    is(x.used, 792, "Our xray_long_line() with a huge prefix1 and even bigger prefix2 logged 792 bytes");
    DEBUG_DIAGS_START(5);
    sxediag = test_all_sxel();
    is_strstr(sxediag, "appending 1+255 bytes @ offset 0", "Got the right first SXEL6 overflow diagnostic message");
    is_strstr(sxediag, "appending 1+255 bytes @ offset 256", "Got the right second SXEL6 overflow diagnostic message");
    is_strstr(sxediag, "appending 1+255 bytes @ offset 512", "Got the right third SXEL6 overflow diagnostic message");
    is_strstr(sxediag, "appending 1+23 bytes", "Got the right SXEL6 tail diagnostic message");
    is(strlen(sxediag), 1153 + pid * 4, "The SXEL6 diagnostic was split correctly");
    DEBUG_DIAGS_END();
    xray_fini(&x);

    test_uncapture_sxel();

    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    /* KIT_ALLOC_SET_LOG(0); */    /* for kit-alloc-analyze data */

    return exit_status();
}
