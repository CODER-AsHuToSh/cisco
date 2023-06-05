#include <kit-alloc.h>
#include <mockfail.h>
#include <sys/stat.h>
#include <tap.h>

#include "conf-loader.h"
#include "dns-name.h"
#include "domainlist-private.h"

#include "common-test.h"

int
main(void)
{
    uint8_t sub_opendns_com[DNS_MAXLEN_NAME];
    char cmd[4200], gzfn[PATH_MAX];
    uint64_t start_allocations;
    struct conf_loader cl;
    struct domainlist *dl;
    struct stat st, gzst;
    const uint8_t *got;
    const char *fn;

    plan_tests(9);

    kit_memory_initialize(false);
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    conf_loader_init(&cl);

    fn = create_data("test-domainlist-gz",
                     "Awfulhak.com\n"
                     "opendns.com\n"
                     "Awfulhak.org\n"
                     "foo.net\n"
                     "Awfulhak.net\n"
                     "bar.net\n"
                     "baz.net\n");
    snprintf(gzfn, sizeof(gzfn), "%s.gz", fn);
    snprintf(cmd, sizeof(cmd), "gzip -1c <%s >%s", fn, gzfn);
    ok(system(cmd) == 0, "Compressed test file");
    if (stat(fn, &st) == -1)
        st.st_size = -1;
    if (stat(gzfn, &gzst) == -1)
        gzst.st_size = -1;
    ok(st.st_size > gzst.st_size, "Compressed file size (%zu) is smaller than file size (%zu)", (size_t)gzst.st_size, (size_t)st.st_size);

    conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
    ok(dl = domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED), "Loaded an uncompressed domainlist");
    dns_name_sscan("www.opendns.com", "", sub_opendns_com);
    got = domainlist_match(dl, sub_opendns_com, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "match 1");
    is(got, sub_opendns_com + 4, "Matched www.opendns.com 4 bytes into the passed domain");
    domainlist_refcount_dec(dl);

    MOCKFAIL_START_TESTS(1, CONF_LOADER_REALLOC);
    conf_loader_open(&cl, gzfn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
    ok(!domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED),
       "Cannot create a domainlist from a compressed file when conf_loader_readfile() fails to realloc");
    MOCKFAIL_END_TESTS();

    conf_loader_open(&cl, gzfn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
    ok(dl = domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED), "Created a domainlist from a compressed file");
    dns_name_sscan("dashboard2.opendns.com", "", sub_opendns_com);
    got = domainlist_match(dl, sub_opendns_com, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "match 2");
    is(got, sub_opendns_com + 11, "Matched dashboard2.opendns.com 11 bytes into the passed domain");
    domainlist_refcount_dec(dl);

    unlink(gzfn);
    unlink(fn);

    conf_loader_fini(&cl);
    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
