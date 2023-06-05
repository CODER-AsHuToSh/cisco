#include <kit-alloc.h>
#include <mockfail.h>

#include "oolist.h"

#include "common-test.h"

pref_t pref;
struct preforg org;
struct prefblock blk;
struct prefidentity identity;

static void
init_prefs(void)
{
    org.retention = 0;
    identity.origintypeid = 0;
    blk.identity = &identity;
    pref.type = PREF_INDEX_IDENTITY;
    pref.index = 0;
    pref.blk = &blk;
    pref.org = &org;
}

static bool
oolist_add_wrapper(struct oolist **list, uint32_t orgid, uint32_t origin, uint32_t parentorg, enum origin_src src)
{
    identity.originid = origin;
    org.id = orgid;
    org.parentid = parentorg;
    return oolist_add(list, &pref, src);
}

int
main(void)
{
    uint64_t       start_allocations;
    struct oolist *list;
    char           buf[1024];
    size_t         len;

    plan_tests(35);

    kit_memory_initialize(false);
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    init_prefs();

    list = oolist_new();
    is_eq(oolist_origins_to_buf(list, buf, sizeof(buf)), "-", "oolist_origins_to_buf produces '-' for an empty list");

    ok(!oolist_add_wrapper(&list, 0, 0, 0, ORIGIN_SRC_NO_MATCH), "Adding 0 fails");
    is_eq(oolist_origins_to_buf(list, buf, sizeof(buf)), "-", "Didn't add 0");

    MOCKFAIL_START_TESTS(2, oolist_add);
    ok(!oolist_add_wrapper(&list, 0, 1234, 1, ORIGIN_SRC_NO_MATCH), "Adding 1234 fails when allocations fail");
    is_eq(oolist_origins_to_buf(list, buf, sizeof(buf)), "-", "Didn't add 1234");
    MOCKFAIL_END_TESTS();

    ok(oolist_add_wrapper(&list, 5678, 1234, 1, ORIGIN_SRC_NETWORK), "Added 1234");
    is_eq(oolist_origins_to_buf(list, buf, 16), "1234:0:5678:0:1", "1234 shows up in output");
    is_eq(oolist_origins_to_buf(list, buf, 15), "-", "oolist_origins_to_buf() truncates output as expected");
    is_eq(oolist_origins_to_buf_hex(list, buf, 8), "-", "oolist_origins_to_buf_hex() truncates output as expected");
    is_eq(oolist_to_buf_hex(list, buf, 18), "0000162E:000004D2", "5678:1234 shows up in full hex output");
    is_eq(oolist_to_buf_hex(list, buf, 17), "-", "oolist_to_buf_hex() truncates output as expected");

    oolist_add_wrapper(&list, 0, 56789, 1, ORIGIN_SRC_NETWORK_SWG);
    is_eq(oolist_origins_to_buf(list, buf, sizeof(buf)), "1234:0:5678:0:1,56789:0:0:0:1", "Added 56789");

    oolist_add_wrapper(&list, 0, 0, 0, ORIGIN_SRC_NO_MATCH);
    is_eq(oolist_origins_to_buf(list, buf, sizeof(buf)), "1234:0:5678:0:1,56789:0:0:0:1", "Added 0 - nothing changed");

    oolist_add_wrapper(&list, 0xabcd, 1234, 1, ORIGIN_SRC_SITE);
    is_eq(oolist_origins_to_buf(list, buf, 31), "1234:0:43981:0:1,56789:0:0:0:1", "Added 1234 (again)");
    is_eq(oolist_origins_to_buf(list, buf, 30), "1234:0:43981:0:1", "oolist_origins_to_buf() truncates output as expected");
    is_eq(oolist_to_buf(list, buf, 19, NULL, 0), "43981:1234,0:56789", "The correct org shows up with origin 1234");
    is_eq(oolist_to_buf(list, buf, 18, &len, 0), "43981:1234", "oolist_to_buf() truncates output as expected");
    is(len, 10, "oolist_to_buf() outputs correct length");
    is_eq(oolist_to_buf(list, buf, 9,  NULL, 0), "-", "oolist_to_buf() truncates empty output as expected");

    oolist_add_wrapper(&list, 2, 1, 1, ORIGIN_SRC_DEVICE);
    is_eq(oolist_origins_to_buf(list, buf, sizeof(buf)), "1234:0:43981:0:1,56789:0:0:0:1,1:0:2:0:1", "Added 1");

    oolist_clear(&list);
    is_eq(oolist_origins_to_buf(list, buf, sizeof(buf)), "-", "Cleared the list");

    oolist_add_wrapper(&list, 1, 1, 1,  ORIGIN_SRC_AD_ORG);
    oolist_add_wrapper(&list, 2, 2, 20, ORIGIN_SRC_AD_USER);
    oolist_add_wrapper(&list, 3, 3, 30, ORIGIN_SRC_AD_HOST);
    oolist_add_wrapper(&list, 4, 2, 40, ORIGIN_SRC_AD_ALTUID);
    oolist_add_wrapper(&list, 5, 4, 50, ORIGIN_SRC_AD_VA);
    oolist_add_wrapper(&list, 6, 2, 60, ORIGIN_SRC_NO_MATCH);
    is_eq(oolist_origins_to_buf(list, buf, sizeof(buf)), "1:0:1:0:1,2:0:6:0:60,3:0:3:0:30,4:0:5:0:50", "Added 1, 2, 3 and 4");
    is(oolist_origin2src(&list, 1), ORIGIN_SRC_AD_ORG, "Origin is an AD ORG");
    is(oolist_origin2src(&list, 2), ORIGIN_SRC_NO_MATCH, "Did not match any defined origin sources");
    is(oolist_origin2src(&list, 3), ORIGIN_SRC_AD_HOST, "origin is an AD HOST");
    is(oolist_origin2src(&list, 4), ORIGIN_SRC_AD_VA, "origin is an AD VA");

    oolist_rm(&list, 2);
    is_eq(oolist_origins_to_buf(list, buf, sizeof(buf)), "1:0:1:0:1,3:0:3:0:30,4:0:5:0:50", "Removed 2");

    oolist_rm(&list, 9);
    is_eq(oolist_origins_to_buf(list, buf, sizeof(buf)), "1:0:1:0:1,3:0:3:0:30,4:0:5:0:50", "Removed 9");

    oolist_rm(&list, 1);
    oolist_rm(&list, 4);
    oolist_rm(&list, 3);
    is_eq(oolist_origins_to_buf(list, buf, sizeof(buf)), "-", "Removed 1, 4 and 3");

    oolist_rm(&list, 2);
    is_eq(oolist_origins_to_buf(list, buf, sizeof(buf)), "-", "Removed 2");

    oolist_clear(&list);
    is_eq(oolist_origins_to_buf(list, buf, sizeof(buf)), "-", "Cleared the list");
    oolist_clear(&list);
    is_eq(oolist_origins_to_buf(list, buf, sizeof(buf)), "-", "Cleared the list again");

    list = NULL;
    is(oolist_origin2src(&list, 2), ORIGIN_SRC_NO_MATCH, "A NULL list returns no match");

    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
