#include <kit-alloc.h>
#include <tap.h>

#include "common-test.h"
#include "pref-categories.h"

int
main(void)
{
    pref_categories_t left, right, override, usable;
    uint64_t          start_allocations;

    plan_tests(4);
    kit_memory_initialize(false);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    pref_categories_setnone(&left);
    pref_categories_setall(&right);
    ok(!pref_categories_equal(&left, &right), "All bits set != no bits set");

    pref_categories_sscan(&left,    "55");    // 01010101
    pref_categories_sscan(&right,   "5a");    // 01011010; ^ = 00001111
    pref_categories_sscan(&override,"33");    // 00110011; & = 00000011
    pref_categories_usable(&usable, &left, &right, &override);    // usable = ((left ^ right) & usable ) ^ left
    is_eq(pref_categories_idstr(&usable), "56", "Usable is as expected");    // 01010101 ^ 00000011 = 01010110 = 0x56

    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    return exit_status();
}
