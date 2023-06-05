#include <kit-alloc.h>
#include <string.h>
#include <tap.h>

#include "prefixtree.h"

#include "common-test.h"

static unsigned keycount;
static bool
keyvalidator(const uint8_t *key, uint8_t key_len, void *v, void *ptr)
{
    if (v) {
        if (key_len != 3) {
            SXEL3("Got unexpected key length %u", key_len);
            return false;
        }
        if (key[2] != keycount) {
            SXEL3("Got unexpected key value ending %u, not %u", key[2], keycount);
            return false;
        }
        if ((uintptr_t)v != keycount + 1) {
            SXEL3("Got unexpected key node pointer %lu, not %u", (unsigned long)(uintptr_t)v, keycount + 1);
            return false;
        }
        if (ptr != NULL) {
            SXEL3("Got unexpected pointer value");
            return false;
       }
        keycount++;
    }

    return true;
}

static const void *test_value = "zork";

static void
test_callback(void *value)
{
    test_value = value;
}

int
main(void)
{
    uint64_t           start_allocations;
    struct prefixtree *pt;

    plan_tests(277);

    kit_memory_initialize(false);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    diag("Prove that we can insert 256 child nodes into a prefixtree");
    {
        ok(pt = prefixtree_new(), "Created a prefixtree");
        skip_if(!pt, 260, "Cannot run tests without a prefixtree") {
            unsigned klen;
            uint8_t k[16];
            unsigned i;
            void **v;
            int len;

            memcpy(k, "\0\1", 2);

            for (i = 0; i < 256; i++) {
                k[2] = i;
                ok(v = prefixtree_put(pt, k, 3), "Inserted node %u", i);

                if (v)
                    *v = (void *)(intptr_t)(i + 1);
            }

            is(prefixtree_get(pt, (const uint8_t *)"\0\1\177", 3), 0200, "Found expected value for \\0\\1\\177");
            ok(v = prefixtree_put(pt, (const uint8_t *)"\0\003com\005cisco", 12), "Put cisco.com in the tree");
            *v = (void *)(uintptr_t)"cisco.com";
            is(prefixtree_put(pt, (const uint8_t *)"\0\003com\005cisco", 12), v, "Duplicate put returns the same node");
            ok(prefixtree_contains_subtree(pt, (const uint8_t *)"\0\003com", 5),  "Subtree 'com' found");
            ok(!prefixtree_contains_subtree(pt, (const uint8_t *)"\0\003org", 5), "Subtree 'org' not found (as expected)");

            keycount = 0;
            klen = 0;
            prefixtree_walk(pt, keyvalidator, k, &klen, NULL);
            is(keycount, 256, "Successfully walked 256 prefixtree nodes");    // the cisco.com node is not counted

            memcpy(k, "\0\2\4", 3);
            ok(v = prefixtree_put(pt, k, 2), "Inserted another node (\\0\\2)");
            if (v)
                *v = (void *)(intptr_t)(1000);
            ok(v = prefixtree_put(pt, k, 3), "Inserted one more node (\\0\\2\\4)");
            if (v)
                *v = (void *)(intptr_t)(2000);

            is(prefixtree_get(pt, (const uint8_t *)"\0\2", 2), 1000, "Found expected value for \\0\\2");
            len = 2;
            is(prefixtree_prefix_get(pt, (const uint8_t *)"\0\2", &len), 1000, "Found expected prefix for \\0\\2");
            is(len, 2, "The found prefix had len 2");

            is(prefixtree_get(pt, (const uint8_t *)"\0\2\4", 3), 2000, "Found expected value for \\0\\2\\4");
            len = 3;
            is(prefixtree_prefix_get(pt, (const uint8_t *)"\0\2\4", &len), 2000, "Found expected prefix for \\0\\2\\4");
            is(len, 3, "The found prefix had len 3");

            len = 3;
            is(prefixtree_prefix_get(pt, (const uint8_t *)"\0\2\5", &len), 1000, "Found expected prefix for \\0\\2\\5");
            is(len, 2, "The found prefix had len 2");

            len = 3;
            ok(!prefixtree_prefix_get(NULL, (const uint8_t *)"\0\2\5", &len), "Found no prefix when no prefixtree is given");

            prefixtree_delete(pt, test_callback);
            is_eq(test_value, "cisco.com", "Delete callback was called with the value 'cisco.com'");
        }
    }

    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    return exit_status();
}
