#ifndef COMMON_TEST_H
#define COMMON_TEST_H

#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include <sxe-log.h>
#include <tap.h>

#if SXE_DEBUG
/*
 * for verifying SXEL6/SXEL7 output (unusual to test diagnostics, but needed sometimes) eg.
 *     test_capture_sxel();
 *     do_something_clever();
 *     DEBUG_DIAGS_START(1);
 *     is_strstr(test_shift_sxel(), "This is a diag message", "Got the right SXEL6 or SXEL7 diagnostic message");
 *     DEBUG_DIAGS_END();
 *     is_strstr(test_shift_sxel(), "This is an error message message", "Got the right SXEL1-SXEL5 message");
 *     test_uncapture_sxel();
 */
#define DEBUG_DIAGS_START(n)
#define DEBUG_DIAGS_END()
#else
#define DEBUG_DIAGS_START(n)    skip_start(1, n, "DEBUG DIAGNOSTICS aren't available")
#define DEBUG_DIAGS_END()       skip_end
#endif

__printflike(2, 3) const char *create_data(const char *testname, const char *data, ...);
const char *create_binary_data(const char *testname, const void *data, size_t len);
__printflike(2, 3) bool create_atomic_file(const char *fn, const char *data, ...);
uint64_t memory_allocations(void);
unsigned rrmdir(const char *dir);
int  showdir(const char *dir, FILE *out);
void test_capture_sxel(void);             /* Capture SXEL* */
void test_passthru_sxel(SXE_LOG_LEVEL);   /* Pass logs of this level and above through to the previous handler */
void test_uncapture_sxel(void);           /* Turn capture off */
void test_clear_sxel(void);               /* Empty the buffer */
const char *test_all_sxel(void);          /* All of the buffered log lines */
char *test_shift_sxel(void);              /* Get and consume the first buffered log line */
const char *test_tail_sxel(void);         /* Peek at the last buffered log line */
void ok_sxel_error(unsigned lineno, const char *fmt, ...);
bool ok_sxel_allerrors(unsigned lineno, const char *str);

#define OK_SXEL_ERROR(...)      ok_sxel_error(__LINE__, __VA_ARGS__)
#define OK_SXEL_ALLERRORS(str)  ok_sxel_allerrors(__LINE__, (str))

#endif
