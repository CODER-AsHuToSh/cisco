#include <string.h>
#include <tap.h>

#include "kit-infolog.h"

int
main(void)
{
    int  output;
    int  stderr_saved;
    char temp[] = "test-infolog.temp.XXXXXX";
    char buf[4096];
    char *bufptr;
    int count;

    plan_tests(4);

    SXEA1(output = mkstemp(temp),                   "Failed to create temporary output file");
    SXEA1((stderr_saved = dup(STDERR_FILENO)) >= 0, "Failed to saved STDERR_FILENO");
    dup2(output, STDERR_FILENO);
    kit_infolog_printf("%2048s", "this should be truncated");
    dup2(stderr_saved, STDERR_FILENO);
    SXEA1(lseek(output, 0, SEEK_SET) == 0, "Failed to rewind output file");

    ok(read(output, buf, sizeof(buf)) >= KIT_INFOLOG_MAX_LINE, "Output at least %u", KIT_INFOLOG_MAX_LINE);
    is_strncmp(&buf[KIT_INFOLOG_MAX_LINE - 4], "...\n", 4,     "... at end of truncated line");
    diag("%s/%s", getcwd(buf, sizeof(buf)), temp);

    dup2(output, STDERR_FILENO);
    for (count = 0; count < 20; count++) {
        kit_infolog_printf("This is an identical line");
    }
    SXEA1(lseek(output, 0, SEEK_SET) == 0, "Failed to rewind output file");

    ok(read(output, buf, sizeof(buf)) > 0, "Read all data from kit_infolog");
    diag("Data1:\n%s", buf);

    bufptr = buf;
    count = 0;
    while ((bufptr = strstr(bufptr, "identical")) != NULL) {
        count++;
        bufptr++;
    }
    is(count, 11, "kit_infolog burst was limited");
    diag("Data2:\n%s", buf);

    unlink(temp);
    return exit_status();
}
