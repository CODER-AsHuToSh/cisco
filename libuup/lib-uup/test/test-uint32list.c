#include <kit-alloc.h>
#include <mockfail.h>
#include <openssl/sha.h>
#include <string.h>
#include <tap.h>

#include "object-hash.h"
#include "uint32list.h"
#include "uup-counters.h"

#include "common-test.h"

int
main(void)
{
    uint64_t start_allocations;

    plan_tests(12);

    kit_memory_initialize(false);
    uup_counters_init();
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    diag("Verify that uint32list object hashing works");
    {
        const char *data1 = "324 11992 65123 71011";
        const char *data2 = "11992 65123 71011";
        uint8_t hashfp[SHA_DIGEST_LENGTH];
        struct uint32list *u1, *u2, *u3;
        struct object_fingerprint of;
        SHA_CTX sha1;

        /* Create a tiny hash so that we can get better coverage */
        of.hash = object_hash_new(1, 0, sizeof(hashfp));
        of.fp = hashfp;
        of.len = sizeof(hashfp);

        SHA1_Init(&sha1);
        SHA1_Update(&sha1, data1, strlen(data1));
        SHA1_Final(hashfp, &sha1);

        u1 = uint32list_new(data1, &of);
        ok(u1, "Generated a uint32list from data1");
        u2 = uint32list_new(data1, &of);
        ok(u2, "Generated another uint32list from data1");
        ok(u1 == u2, "Generating the same uint32list with fingerprints twice yields the same data");
        is(u1->refcount, 2, "The refcount is 2");

        SHA1_Init(&sha1);
        SHA1_Update(&sha1, data2, strlen(data2));
        SHA1_Final(hashfp, &sha1);
        u3 = uint32list_new(data2, &of);

        ok(u3, "Generated a uint32list from data2");
        ok(u1 != u3, "Generating a different uint32list with fingerprints yields different data");

        uint32list_refcount_dec(u1);
        uint32list_refcount_dec(u2);
        uint32list_refcount_dec(u3);

        object_hash_free(of.hash);
    }

    diag("Verify some uint32list object hashing negative cases");
    {
        unsigned allocated, expected_overflows;
        struct uint32list *u[14], *unhashed;
        uint8_t hashfp[SHA_DIGEST_LENGTH];
        const char *data1 = "626 929";
        struct object_fingerprint of;
        char ascii[1024];
        SHA_CTX sha1;
        unsigned i;

        /* Create a bogus hash */
        of.hash = object_hash_new(1, 0, sizeof(hashfp) * 2);
        of.fp = hashfp;
        of.len = sizeof(hashfp);

        SHA1_Init(&sha1);
        SHA1_Update(&sha1, data1, strlen(data1));
        SHA1_Final(hashfp, &sha1);

        u[0] = uint32list_new(data1, &of);
        ok(!u[0], "Failed to create a uint32list with a bogus fingerprint");
        object_hash_free(of.hash);

        unhashed = NULL;
        expected_overflows = 1;
        /* Create a tiny hash so that we can test allocation failures */
        of.hash = object_hash_new(1, 0, sizeof(hashfp));
        for (allocated = i = 0; i < 14; i++) {
            if (i == 7) {
                MOCKFAIL_START_TESTS(1, object_hash_add);
                /* This pointer will fail to hash */
                snprintf(ascii, sizeof(ascii), "112 520 552 900");
                SHA1_Init(&sha1);
                SHA1_Update(&sha1, ascii, strlen(ascii));
                SHA1_Final(hashfp, &sha1);
                unhashed = uint32list_new(ascii, &of);
                ok(unhashed, "Allocated an unhashed uint32list object - object-hash overflow allocation failed");
                expected_overflows++;
                MOCKFAIL_END_TESTS();
            }
            snprintf(ascii, sizeof(ascii), "112 520 552 900%u", i);
            SHA1_Init(&sha1);
            SHA1_Update(&sha1, ascii, strlen(ascii));
            SHA1_Final(hashfp, &sha1);
            u[i] = uint32list_new(ascii, &of);
            allocated += !!u[i];
        }
        is(allocated, 14, "Allocated 14 uint32list objects");
        is(kit_counter_get(COUNTER_UUP_OBJECT_HASH_OVERFLOWS), expected_overflows, "Recorded %u object-hash overflow%s",
           expected_overflows, expected_overflows == 1 ? "" : "s");

        for (i = 0; i < 14; i++)
            uint32list_refcount_dec(u[i]);
        object_hash_free(of.hash);
        uint32list_refcount_dec(unhashed);
    }

    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
