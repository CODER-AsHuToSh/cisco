#include <kit-alloc.h>
#include <sys/stat.h>

#include "common-test.h"
#include "conf-loader.h"

int
main(void)
{
    uint64_t start_allocations;
    struct conf_loader loader;
    const char *filename;
    char *data;
    size_t len;

    plan_tests(9);

    kit_memory_initialize(false);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");
    /* KIT_ALLOC_SET_LOG(1); */

    conf_loader_init(&loader);
    rrmdir("conf-loader-backup");
    mkdir("conf-loader-backup", 0777);

    filename = create_data("test-file", "line\n");
    ok(conf_loader_open(&loader, filename, "conf-loader-backup", NULL, 0, CONF_LOADER_DEFAULT | CONF_LOADER_CHOMP),
       "Opened a test file");
    is_eq(conf_loader_readline(&loader), "line", "Unexpected line read");

    ok(conf_loader_open(&loader, filename, "conf-loader-backup", NULL, 0, CONF_LOADER_DEFAULT), "Opened the test file again");
    data = conf_loader_readfile_binary(&loader, &len, 5);
    is_eq(data ?: "<NULL>", "line\n", "Unexpected data read with maxsize 5");
    is(len, 5, "All 5 bytes were recorded as read");
    kit_free(data);

    ok(conf_loader_open(&loader, filename, "conf-loader-backup", NULL, 0, CONF_LOADER_DEFAULT), "Opened the test file again");
    data = conf_loader_readfile_binary(&loader, NULL, 4);
    is_eq(data ?: "<NULL>", "<NULL>", "Unexpected data read with maxsize 4");
    kit_free(data);

    unlink(filename);
    conf_loader_fini(&loader);

    /* KIT_ALLOC_SET_LOG(0); */
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");

    return exit_status();
}
