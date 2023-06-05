#include <kit-alloc.h>
#include <mockfail.h>
#include <sxe-util.h>
#include <tap.h>

#include "dns-name.h"
#include "domainlist-private.h"
#include "object-hash.h"
#include "uup-counters.h"

#include "common-test.h"

char test_domainlist[] = "12345678.com";

int
main(void)
{
    unsigned expected_overflows, hashval;
    struct object_fingerprint of;
    struct domainlist *unhashed;
    uint64_t start_allocations;
    const void *hextras;
    char fp[9];

    plan_tests(45);

    kit_memory_initialize(false);
    uup_counters_init();
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    of.hash = NULL;
    of.fp = (const uint8_t *)fp;
    of.len = sizeof(fp) - 1;
    unhashed = NULL;
    expected_overflows = 2;

    putenv(SXE_CAST_NOCONST(char *, "SXE_LOG_LEVEL_OPENDNSCACHE_LIB_OPENDNSCACHE=6")); /* Set to 6 to suppress opendnscache domainlist debug logging since this is kind of a stress test */

    diag("Add enough unique rows to create extents");
    {
        unsigned unique_domainlists_to_add = 197;
        struct domainlist *domainlist_array[unique_domainlists_to_add];
        char unique_domainlist[sizeof test_domainlist];
        unsigned i, allocated;
        int len;

        /* We don't want ot spend ages allocating millions of things to see a collision, so make the hash smaller */
        of.hash = object_hash_new(32, 32, 8);

        for (allocated = i = 0; i < unique_domainlists_to_add; i++) {
            len = snprintf(unique_domainlist, sizeof(unique_domainlist), "%08u.com", i);
            snprintf(fp, sizeof(fp), "%08x", hashval = i);

            if ((sizeof(long) == 8 && i == 160) || (sizeof(long) == 4 && i == 167)) {    /* Yeah, magic! - See the SXEL1() below for help */
                MOCKFAIL_START_TESTS(3, object_hash_add);
                unsigned hentries;

                /* We expect this pointer to fail to hash */
                hentries = object_hash_entries(of.hash);
                unhashed = domainlist_new_from_buffer(unique_domainlist, len, &of, LOADFLAGS_NONE);
                ok(unhashed, "Allocated a 'special' domainlist object");
                ok(unhashed->oh == NULL, "The 'special' object was unhashed - object-hash overflow allocation failed");
                ok(object_hash_entries(of.hash) == hentries, "The hash wasn't updated");
                expected_overflows++;
                MOCKFAIL_END_TESTS();
            }

            hextras = object_hash_extras(of.hash);
            domainlist_array[i] = domainlist_new_from_buffer(unique_domainlist, len, &of, LOADFLAGS_NONE);
            if (object_hash_extras(of.hash) != hextras)
                SXEL1("A 'special' %zubit number (that extends the hash table) is %u", sizeof(long) * 8, i);
            allocated += !!domainlist_array[i];
        }
        is(allocated, i, "Allocated %u domainlists", i);
        is(object_hash_entries(of.hash), unique_domainlists_to_add, "All domainlists were added to the hash");

        for (i = 0; i < unique_domainlists_to_add; i++)
            domainlist_refcount_dec(domainlist_array[i]);
    }

    diag("Add one HUGE row... greater than 65536 characters so that the offsets are forced to 4 bytes");
    {
        char name_bundle[UINT16_MAX + 100], passtext[DNS_MAXLEN_STRING + 1], failtext[DNS_MAXLEN_STRING + 1];
        uint8_t passname[DNS_MAXLEN_NAME], failname[DNS_MAXLEN_NAME];
        struct domainlist *domainlist;
        unsigned got[4], expect;
        int i, n;

        for (i = n = 0; i <= UINT16_MAX; n++)
            i += snprintf(name_bundle + i, sizeof(name_bundle) - i, "a%08d.com ", i);

        snprintf(fp, sizeof(fp), "%08x", ++hashval);
        domainlist = domainlist_new_from_buffer(name_bundle, i, &of, LOADFLAGS_NONE);
        ok(domainlist, "Allocated a huge domainlist (%d elements)", n);

        memset(got, '\0', sizeof got);
        for (i = expect = 0; i <= UINT16_MAX; i += 14) {
            expect++;
            snprintf(passtext, sizeof(passtext), "www.a%08u.com", i    );
            snprintf(failtext, sizeof(failtext), "www.a%08u.com", i + 1);

            dns_name_sscan(passtext, "", passname);
            dns_name_sscan(failtext, "", failname);

            got[0] += !!domainlist_match(domainlist, passname, DOMAINLIST_MATCH_SUBDOMAIN, NULL, NULL);
            got[1] += !!domainlist_match(domainlist, passname + 4, DOMAINLIST_MATCH_EXACT, NULL, NULL);
            got[2] +=  !domainlist_match(domainlist, failname, DOMAINLIST_MATCH_SUBDOMAIN, NULL, NULL);
            got[3] +=  !domainlist_match(domainlist, failname + 4, DOMAINLIST_MATCH_EXACT, NULL, NULL);
        }
        is(got[0], expect, "Found the expected %d matches",              expect);
        is(got[1], expect, "Found the expected %d exact matches",        expect);
        is(got[2], expect, "Found the expected %d match failures",       expect);
        is(got[3], expect, "Found the expected %d exact match failures", expect);

        domainlist_refcount_dec(domainlist);
    }

    diag("Make sure allocations are being optimized out");
    {
        const char *data = "first.domain second.domain third.domain";
        struct domainlist *dl1, *dl2;

        /* Switch to an un-fingerprinted hash */
        object_hash_free(of.hash);
        of.hash = NULL;
        of.fp = NULL;
        of.len = 0;

        dl1 = domainlist_new_from_buffer(data, strlen(data), &of, LOADFLAGS_NONE);
        ok(dl1, "Allocated a domainlist");
        is(dl1->conf.refcount, 1, "The refcount is 1");

        dl2 = domainlist_new_from_buffer(data, strlen(data), &of, LOADFLAGS_NONE);
        ok(dl2, "Allocated a second domainlist");
        is(dl2->conf.refcount, 2, "The refcount is 2");

        ok(dl1 == dl2, "The pointers are the same");

        domainlist_refcount_dec(dl1);
        domainlist_refcount_dec(dl2);

        /* Switch back to a fingerprinted hash */
        object_hash_free(of.hash);
        of.hash = NULL;
        of.fp = (const uint8_t *)fp;
        of.len = sizeof(fp) - 1;

        snprintf(fp, sizeof(fp), "abcd1234");

        dl1 = domainlist_new_from_buffer(data, strlen(data), &of, LOADFLAGS_NONE);
        ok(dl1, "Allocated a domainlist");
        is(dl1->conf.refcount, 1, "The refcount is 1");

        dl2 = domainlist_new_from_buffer(data, strlen(data), &of, LOADFLAGS_NONE);
        ok(dl2, "Allocated a second domainlist");
        is(dl2->conf.refcount, 2, "The refcount is 2");

        ok(dl1 == dl2, "The pointers are the same");

        domainlist_refcount_dec(dl1);
        domainlist_refcount_dec(dl2);
    }

    diag("A little coverage testing");
    {
        const char *dltxt = "d0 d1 d2 d3 d4 d5 d6 d7 d8 d9";
        struct domainlist *dl[10];
        unsigned dllen, i;

        domainlist_sscan(" :some-other-data", ":", LOADFLAGS_NONE, dl);
        is(dl[0], NULL, "Coverage: As expected, domainlist_sscan(\" :some-other-data\", \":\", dl) returns dl[0]==NULL");
        domainlist_sscan("", " ", LOADFLAGS_NONE, dl);
        is(dl[0], NULL, "Coverage: As expected, domainlist_sscan(\"\", \" \", dl) returns dl[0]==NULL");

        snprintf(fp, sizeof(fp), "%08x", ++hashval);
        is(domainlist_new_from_buffer("", 0, &of, LOADFLAGS_NONE), NULL, "Coverage: As expected, domainlist_new_from_buffer(\"\", 0) returns NULL");

        object_hash_free(of.hash);
        ok(of.hash = object_hash_new(1, 0, 0), "Created a tiny un-fingerprinted domainlist hash");
        of.fp = NULL;
        of.len = 0;

        /* There's only one hash entry - so we'll collide with a domainlist of a different length 8 times, estending once and writing twice to the extent  */
        for (dllen = 2, i = 0; i < 9; dllen += 3, i++) {
            dl[i] = domainlist_new_from_buffer(dltxt, dllen, &of, LOADFLAGS_NONE);
            ok(dl[i], "Allocated domainlist %u", i);
            is(dl[i]->conf.refcount, 1, "The refcount is 1");
        }

        for (i = 0; i < 9; i++)
            domainlist_refcount_dec(dl[i]);
    }

    object_hash_free(of.hash);
    domainlist_refcount_dec(unhashed);

    is(kit_counter_get(COUNTER_UUP_OBJECT_HASH_OVERFLOWS), expected_overflows, "Recorded %u object-hash overflow%s",
       expected_overflows, expected_overflows == 1 ? "" : "s");

    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
