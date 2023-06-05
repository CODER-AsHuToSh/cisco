#include <kit-alloc.h>
#include <mockfail.h>
#include <tap.h>

#include "uint16set.h"

#include "common-test.h"

int
main(void)
{
    uint64_t start_allocations;
    struct uint16set *set;
    unsigned consumed;

    plan_tests(33);

    kit_memory_initialize(false);
    start_allocations = memory_allocations();

    MOCKFAIL_START_TESTS(3, uint16set_new);
    ok(!uint16set_new("", NULL),      "Can't create set if allocations fail");    // This was leading to a core dump
    ok(!uint16set_new("", &consumed), "Can't create set if allocations fail, but return consumed");
    is(consumed, 0,                   "No bytes consumed");
    MOCKFAIL_END_TESTS();

    set = uint16set_new("", NULL);
    is(uint16set_count(set), 0, "An empty set is empty");
    is_eq(uint16set_to_str(set), "", "The set emits correctly");
    uint16set_free(set);

    set = uint16set_new("this is not a set", &consumed);
    is(uint16set_count(set), 0, "A garbage set is empty");
    is(consumed, 0, "None of the garbage is consumed");
    uint16set_free(set);

    set = uint16set_new("-this is actually a set", &consumed);
    is(uint16set_count(set), 65536, "A full set is 65536 big");
    is(consumed, 1, "Only the first character of input is consumed");
    ok(uint16set_match(set, 0), "The set contains 0");
    ok(uint16set_match(set, 100), "The set contains 100");
    ok(uint16set_match(set, 65535), "The set contains 65535");
    is_eq(uint16set_to_str(set), "0-65535", "The set emits correctly");
    uint16set_free(set);

    set = uint16set_new("-,-,1,100-200this is actually a set", &consumed);
    is_eq(uint16set_to_str(set), "0-65535", "The set emits correctly");
    is(uint16set_count(set), 65536, "Redundant stuff is reduced ok");
    is(consumed, 13, "13 characters of input were consumed");
    uint16set_free(set);

    set = uint16set_new("12,10,1-5,4-9,-3,20-28,24,22-23,65536", NULL);
    is(uint16set_count(set), 21, "Reduction and ordering works");
    ok(uint16set_match(set, 0), "The set contains 0");
    ok(uint16set_match(set, 3), "The set contains 3");
    ok(uint16set_match(set, 6), "The set contains 6");
    ok(uint16set_match(set, 10), "The set contains 10");
    ok(!uint16set_match(set, 11), "The set doesn't contain 11");
    ok(uint16set_match(set, 12), "The set contains 12");
    ok(!uint16set_match(set, 13), "The set doesn't contain 13");
    ok(!uint16set_match(set, 19), "The set doesn't contain 19");
    ok(uint16set_match(set, 20), "The set contains 20");
    ok(uint16set_match(set, 28), "The set contains 28");
    ok(!uint16set_match(set, 29), "The set doesn't contain 29");
    uint16set_to_str(NULL);
    MOCKFAIL_START_TESTS(1, uint16set_to_str);
    is_eq(uint16set_to_str(set), "<uint16set-allocation-failure>", "The set emits an error when allocations fail");
    MOCKFAIL_END_TESTS();
    is_eq(uint16set_to_str(set), "0-10,12,20-28", "The set emits correctly");
    uint16set_free(set);

    ok(memory_allocations() != start_allocations, "We have outstanding memory allocations (%llu)",
        (unsigned long long)(memory_allocations() - start_allocations));
    ok(uint16set_to_str(NULL) == NULL, "Cleared up the internal set buffer");
    is(memory_allocations(), start_allocations, "All memory allocations were freed");

    return exit_status();
}
