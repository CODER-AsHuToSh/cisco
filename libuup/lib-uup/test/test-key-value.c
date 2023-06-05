#include <kit-alloc.h>
#include <tap.h>

#include "common-test.h"
#include "conf-loader.h"
#include "key-value-config.h"

struct test_config {
    struct conf conf;
};

static const struct key_value_entry config[] = {
};

static struct test_config test_defaults;

static void
test_config_free(struct conf *base)
{
    kit_free((unsigned char *)base - offsetof(struct test_config, conf));
}

static const struct conf_type test_config_conf_type = {
    "test-config",
    NULL,
    test_config_free
};

static void
test_pre(void *dummy)
{
    SXE_UNUSED_PARAMETER(dummy);
}

static bool
test_post(void *dummy, struct conf_loader *loader)
{
    SXE_UNUSED_PARAMETER(dummy);
    SXE_UNUSED_PARAMETER(loader);

    return true;
}

int
main(void)
{
    struct conf_loader loader;
    uint64_t           start_allocations;

    plan_tests(2);
    kit_memory_initialize(false);
    // KIT_ALLOC_SET_LOG(1);    // Turn off when done
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    conf_loader_init(&loader);
    const char *file_name = create_data("test-kvc", " ");
    conf_loader_open(&loader, file_name, NULL, NULL, 0, CONF_LOADER_DEFAULT);
    struct conf *conf = key_value_config_new(&loader, sizeof(struct test_config), offsetof(struct test_config, conf),
                                             &test_defaults, config, 0, &test_config_conf_type, test_pre, test_post);
    (void)conf;
    conf_loader_fini(&loader);
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    return exit_status();
}
