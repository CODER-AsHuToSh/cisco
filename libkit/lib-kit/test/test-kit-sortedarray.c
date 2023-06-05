#include <mockfail.h>
#include <stdlib.h>
#include <tap.h>

#include "kit.h"

static int
unsigned_cmp(const void *lhs, const void *rhs)
{
    return *(const unsigned *)lhs == *(const unsigned *)rhs ? 0 : *(const unsigned *)lhs < *(const unsigned *)rhs ? -1 : 1;
}

static const char *
unsigned_fmt(const void *u)
{
    static __thread char     string[4][12];
    static __thread unsigned next = 0;

    sprintf(string[next = (next + 1) % 4], "%u", *(const unsigned *)u);
    return string[next];
}

static const struct kit_sortedelement_class testclass = { sizeof(unsigned), 0, unsigned_cmp, unsigned_fmt};
static const unsigned u[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24};

int
main(void)
{
    unsigned *array = NULL;
    unsigned  count = 0;
    unsigned  alloc = 7;
    unsigned  value = 2;
    bool      match;

    plan_tests(40);

    MOCKFAIL_START_TESTS(1, kit_sortedarray_add);
    ok(!kit_sortedarray_add(&testclass, (void **)&array, &count, &alloc, &value, 0), "Failed to add 2 (realloc failed)");
    MOCKFAIL_END_TESTS();

    ok(kit_sortedarray_add(&testclass, (void **)&array, &count, &alloc, &value, 0),  "Added 2 (first element)");
    ok(array,                                                                        "Array was allocated");
    is(count, 1,                                                                     "Array has one element");
    ok(!kit_sortedarray_add(&testclass, (void **)&array, &count, &alloc, &value, 0), "Failed to add a second 2");
    value = 3;
    ok(kit_sortedarray_add(&testclass, (void **)&array, &count, &alloc, &value, 0),  "Added 3 (second element)");
    value = 1;
    ok(!kit_sortedarray_add(&testclass, (void **)&array, &count, &alloc, &value, 0), "Failed to added 1 out of order");
    is(count, 2,                                                                     "Array has two elements");
    value = 7;
    ok(kit_sortedarray_add(&testclass, (void **)&array, &count, &alloc, &value, 0),  "Added 7 (third element)");
    value = 13;
    ok(kit_sortedarray_add(&testclass, (void **)&array, &count, &alloc, &value, 0),  "Added 13 (fourth element)");
    value = 17;
    ok(kit_sortedarray_add(&testclass, (void **)&array, &count, &alloc, &value, 0),  "Added 17 (fifth element)");
    value = 23;
    ok(kit_sortedarray_add(&testclass, (void **)&array, &count, &alloc, &value, 0),  "Added 23 (sixth element)");

    value = 7;
    ok(!kit_sortedarray_add(&testclass, (void **)&array, &count, &alloc, &value, KIT_SORTEDARRAY_ALLOW_INSERTS),
       "Failed to inserted 7 (duplicate element)");
    value = 5;
    ok(kit_sortedarray_add(&testclass, (void **)&array, &count, &alloc, &value, KIT_SORTEDARRAY_ALLOW_INSERTS),
       "Inserted 5 (third element)");
    is(count, 7, "Array now has seven elements");

    value = 29;
    ok(!kit_sortedarray_add(&testclass, (void **)&array, &count, &alloc, &value, KIT_SORTEDARRAY_DEFAULT), \
       "Failed to add 29 (full)");

    is(array[0], 2,  "Element 0 is 2");
    is(array[0], 2,  "Element 1 is 3");
    is(array[2], 5,  "Element 2 is 5");
    is(array[2], 5,  "Element 3 is 7");
    is(array[6], 23, "Element 6 is 23");

    is(kit_sortedarray_find(&testclass, array, count, &u[1],  &match), 0, "Correct insertion point for 1");
    ok(!match,                                                            "1 is not an exact match");
    is(kit_sortedarray_find(&testclass, array, count, &u[2],  &match), 0, "Found 2");
    ok(match,                                                             "2 is an exact match");
    is(kit_sortedarray_find(&testclass, array, count, &u[6],  &match), 3, "Correct insertion point for 6");
    is(kit_sortedarray_find(&testclass, array, count, &u[7],  &match), 3, "Found 7");
    is(kit_sortedarray_find(&testclass, array, count, &u[20], &match), 6, "Correct insertion point for 20");
    is(kit_sortedarray_find(&testclass, array, count, &u[23], &match), 6, "Found 23");
    is(kit_sortedarray_find(&testclass, array, count, &u[24], &match), 7, "Correct insertion point for 24");
    ok(!match,                                                            "24 is not an exact match");

    ok(!kit_sortedarray_get(&testclass, array, count, &u[1]),  "Couldn't get 1");
    ok(!kit_sortedarray_get(&testclass, array, count, &u[6]),  "Couldn't get 6");
    ok(!kit_sortedarray_get(&testclass, array, count, &u[20]), "Couldn't get 20");
    ok(!kit_sortedarray_get(&testclass, array, count, &u[24]), "Couldn't get 24");

    const unsigned *g;
    ok((g = (const unsigned *)kit_sortedarray_get(&testclass, array, count, &u[2]))  && *g == 2,  "Got 2");
    ok((g = (const unsigned *)kit_sortedarray_get(&testclass, array, count, &u[7]))  && *g == 7,  "Got 7");
    ok((g = (const unsigned *)kit_sortedarray_get(&testclass, array, count, &u[23])) && *g == 23, "Got 23");

    value = 29;
    ok(kit_sortedarray_add(&testclass, (void **)&array, &count, &alloc, &value,
                           KIT_SORTEDARRAY_ALLOW_GROWTH | KIT_SORTEDARRAY_ZERO_COPY), "Added 29 (full, but growth allowed)");
    ok(array[7] != 29, "Zero copy specified, so added array element was not initialized");

    return exit_status();
}
