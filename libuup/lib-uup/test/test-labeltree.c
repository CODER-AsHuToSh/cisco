#include <mockfail.h>
#include <sxe-log.h>
#include <tap.h>

#include "labeltree.h"

unsigned counted_nodes, counted_values;

static bool
counter(const uint8_t *key, void *value, void *userdata)
{
    SXE_UNUSED_PARAMETER(userdata);

    if (key)
        SXEL1("Visited %s, value %zu", dns_name_to_str1(key), (uintptr_t)value);

    counted_nodes++;

    if (value)
        counted_values++;

    return true;
}

static bool
find_wildcard(const uint8_t *key, void *value, void *userdata)
{
    void **ret = userdata;

    SXEL1("Is %s (value %zu) a wildcard name?", dns_name_to_str1(key), (uintptr_t)value);

    if (key[0] == 1 && key[1] == '*') {
        if (ret)
            *ret = value;
        return false;
    }

    return true;
}

static bool
visit_failure(const uint8_t *name, void *value, void *userdata)
{
    return value == NULL || !dns_name_equal(name, userdata);
}

static uintptr_t test_value = 0;

static void
test_callback(void *value)
{
    if ((uintptr_t)value == test_value + 1)
        test_value++;
}

int
main(void)
{
    uint8_t name[DNS_MAXLEN_NAME], item[DNS_MAXLEN_NAME];
    struct labeltree *lt;
    const uint8_t *v;
    void *value;

    plan_tests(96);

    diag("A missing tree");
    {
        dns_name_sscan(".", "", name);
        ok(!labeltree_suffix_get(NULL, name, LABELTREE_FLAG_NONE), "labeltree_suffix_get(NULL) fails as expected");
        ok(!labeltree_get(NULL, name, LABELTREE_FLAG_NONE), "labeltree_get(NULL) fails as expected");
    }

    diag("An empty tree");
    {
        MOCKFAIL_START_TESTS(1, LABELTREE_NEW_INTERNAL);
        ok(!labeltree_new(), "Cannot create a labeltree when labeltree_new_internal() fails");
        MOCKFAIL_END_TESTS();

        lt = labeltree_new();
        ok(lt, "Created an empty labeltree");
        dns_name_sscan(".", "", name);
        ok(!labeltree_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_get('.') fails as expected");
        labeltree_put(lt, name, (void *)1);
        ok(labeltree_get(lt, name, LABELTREE_FLAG_NONE), "Updated the value for the root node, labeltree_get('.') now succeeds");

        dns_name_sscan("one.node.tree", "", name);
        MOCKFAIL_START_TESTS(1, LABELTREE_NEW_INTERNAL);
        ok(!labeltree_put(lt, name, LABELTREE_VALUE_SET), "Cannot create a labeltree node when labeltree_new_internal() fails");
        MOCKFAIL_END_TESTS();
        MOCKFAIL_START_TESTS(1, LABELTREE_NEW_INTERNAL);
        MOCKFAIL_SET_FREQ(2);
        ok(!labeltree_put(lt, name, LABELTREE_VALUE_SET), "Cannot add internal node when labeltree_new_internal() fails");
        MOCKFAIL_END_TESTS();
        MOCKFAIL_START_TESTS(1, LABELTREE_PUT_MALLOC);
        ok(!labeltree_put(lt, name, LABELTREE_VALUE_SET), "Cannot create a labeltree node when labeltree_put() fails malloc()");
        MOCKFAIL_END_TESTS();
        ok(labeltree_put(lt, name, (void *)2), "Created a labeltree node");

        dns_name_sscan("two.node.tree", "", name);
        MOCKFAIL_START_TESTS(1, LABELTREE_PUT_REALLOC);
        ok(!labeltree_put(lt, name, LABELTREE_VALUE_SET), "Cannot create a second labeltree node when labeltree_put() fails realloc()");
        MOCKFAIL_END_TESTS();
        ok(labeltree_put(lt, name, (void *)3), "Created a second labeltree node");

        dns_name_sscan("one.node.tree", "", name);
        ok(labeltree_get(lt, name, LABELTREE_FLAG_NONE), "The first node is get()able");
        dns_name_sscan("two.node.tree", "", name);
        ok(labeltree_get(lt, name, LABELTREE_FLAG_NONE), "The second node is get()able");

        labeltree_delete(lt, test_callback);
        is(test_value, 3, "Got expected sequence of values in delete callbacks (1, 2, 3)");
        labeltree_free(NULL);
    }

    diag("A single domain in a tree");
    {
        lt = labeltree_new();
        ok(lt, "Created an empty labeltree");
        dns_name_sscan("something.or.other.net", "", name);
        labeltree_put(lt, name, LABELTREE_VALUE_SET);

        ok(labeltree_get(lt, name, LABELTREE_FLAG_NONE), "Inserted a labeltree node, found it again");

        labeltree_put(lt, name, LABELTREE_VALUE_SET);
        ok(labeltree_get(lt, name, LABELTREE_FLAG_NONE), "Inserted the same labeltree node, found it again");

        counted_nodes = counted_values = 0;
        labeltree_walk(lt, counter, item, NULL);
        is(counted_nodes, 5, "Counted 5 nodes");
        is(counted_values, 1, "Counted 1 value");

        ok(labeltree_walk(lt, find_wildcard, item, NULL), "No wildcards in the tree");

        ok(labeltree_suffix_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_suffix_get('same key') succeeds");
        dns_name_sscan("deeper.than.something.or.other.net", "", name);
        ok(labeltree_suffix_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_suffix_get('something deeper') succeeds");
        dns_name_sscan("or.other.net", "", name);
        ok(!labeltree_suffix_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_suffix_get('something shallower') fails");

        labeltree_free(lt);
    }

    diag("Multiple domains in a tree");
    {
        const char *names[] = {
            "net",
            "something.or.other.net",
            "Awfulhak.net",
            "opendns.net",
            "zone.net",
            "an.other.net",
            "awfulhak.org",
            "x.y.awfulhak.org",
            "x.*.awfulhak.org",
            "*.org",
            "*.*.*.org",
        };
        unsigned i;

        lt = labeltree_new();

        for (i = 0; i < sizeof(names) / sizeof(*names); i++) {
            dns_name_sscan(names[i], "", name);
            labeltree_put(lt, name, (void *)(uintptr_t)names[i]);    // Use the domain name strings as the values
        }

        counted_nodes = counted_values = 0;
        labeltree_walk(lt, counter, item, NULL);
        is(counted_nodes, 18, "Counted 18 nodes");
        is(counted_values, 11, "Counted 11 values");

        ok(!labeltree_walk(lt, find_wildcard, item, &v), "Wildcard found in the tree");
        is_eq(v, "*.org", "Found expected wildcard name");

        for (i = 0; i < sizeof(names) / sizeof(*names); i++) {
            dns_name_sscan(names[i], "", name);
            ok(labeltree_get(lt, name, LABELTREE_FLAG_NONE), "Found node '%s'", names[i]);
        }

        dns_name_sscan("y.Awfulhak.org", "", name);
        ok(!labeltree_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_get('y.Awfulhak.org') fails");

        dns_name_sscan("x.Y.Awfulhak.ORG", "", name);
        ok(labeltree_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_get('x.Y.Awfulhak.ORG') succeeds");

        dns_name_sscan("www.Awfulhak.org", "", name);
        ok(!labeltree_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_get('www.Awfulhak.org') fails");

        dns_name_sscan("x.www.Awfulhak.ORG", "", name);
        ok(!labeltree_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_get('x.www.Awfulhak.ORG') fails (no internal wildcards)");

        dns_name_sscan("x.*.Awfulhak.ORG", "", name);
        ok(v = labeltree_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_get('x.*.Awfulhak.ORG') succeeds (exact match)");
        is_eq(v, "x.*.awfulhak.org", "x.*.Awfulhak.ORG matched x.*.awfulhak.org");

        dns_name_sscan("Anything.Org", "", name);
        ok(labeltree_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_get('Anything.Org') succeeds");

        dns_name_sscan("two-deep.Anything.Org", "", name);
        ok(v = labeltree_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_get('two-deep.Anything.Org') succeeds");
        is_eq(v, "*.org", "two-deep.Anything.Org matched *.org (wildcard domain name)");

        dns_name_sscan("three.deep.domain.org", "", name);
        ok(v = labeltree_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_get('three.deep.domain.org') succeeds");
        is_eq(v, "*.org", "three.deep.domain.org matched *.org (wildcard domain name)");

        dns_name_sscan("three.*.*.org", "", name);
        ok(v = labeltree_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_get('three.*.*.org') succeeds");
        is_eq(v, "*.*.*.org", "three.*.*.org matched *.*.*.org (longer match overrides shorter wildcard domain name)");

        dns_name_sscan("deeper.than.Something.or.other.net", "", name);
        ok(v = labeltree_suffix_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_suffix_get('something deeper') succeeds");
        is_strncmp(dns_name_to_str1(v), "Something.or.other.net", strlen("Something.or.other.net"), "Found the correct (longest) node");

        dns_name_sscan("than.something.or.other.net", "", name);
        ok(v = labeltree_suffix_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_suffix_get('slightly deeper') succeeds");
        is_strncmp(dns_name_to_str1(v), "something.or.other.net", strlen("something.or.other.net"), "Found the correct (longest) node");

        dns_name_sscan("something.or.other.net", "", name);
        ok(v = labeltree_suffix_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_suffix_get('same') succeeds");
        is_strncmp(dns_name_to_str1(v), "something.or.other.net", strlen("something.or.other.net"), "Found the correct (longest) node");

        dns_name_sscan("or.other.net", "", name);
        ok(v = labeltree_suffix_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_suffix_get('something shallower') succeeds");
        is_strncmp(dns_name_to_str1(v), "net", strlen("net"), "Found the correct (longest) node");

        dns_name_sscan(".", "", name);
        ok(!labeltree_suffix_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_suffix_get('.') fails (as expected)");
    }

    diag("Search for paths to the greatest node less than a name");
    {
        // lt = {
        //   "net",
        //   "Awfulhak.net",
        //   "opendns.net",
        //   "an.other.net",
        //   "something.or.other.net",
        //   "zone.net",
        //   "*.org",
        //   "*.*.*.org",
        //   "awfulhak.org",
        //   "x.*.awfulhak.org",
        //   "x.y.awfulhak.org"
        // }

        struct labeltree_iter iter;

        dns_name_sscan("zone.net", "", name);
        is_eq(labeltree_search_iter(lt, name, &iter), "zone.net",               "labeltree_search_iter('zone.net') returns 'zone.net");
        is_eq(labeltree_iter_parent(&iter),           "net",                    "parent value is 'net'");
        is_eq(labeltree_iter_previous(&iter),         "something.or.other.net", "previous value is 'something.or.other.net'");
        is(labeltree_iter_get_name(&iter, name),      name,                     "got the iterator DNS name");
        is_eq(dns_name_to_str1(name),                 "something.or.other.net", "iterator name is 'something.or.other.net'");

        dns_name_sscan("awfulhak.net", "", name);
        is_eq(labeltree_search_iter(lt, name, &iter), "Awfulhak.net", "labeltree_search_iter('awfulhak.net') returns 'Awfulhak.net'");
        is_eq(labeltree_iter_parent(&iter),           "net",          "parent value is 'net'");
        is_eq(labeltree_iter_previous(&iter),         "net",          "previous value is 'net'");

        dns_name_sscan("before", "", name);
        ok(!labeltree_search_iter(lt, name, &iter), "labeltree_search_iter('before') returns NULL");
        ok(!labeltree_iter_parent(&iter),           "parent (.) has no value");
        ok(!labeltree_iter_previous(&iter),         "No previous value");

        // Insert a value at the root
        dns_name_sscan(".", "", name);
        labeltree_put(lt, name, (void *)(uintptr_t)".");

        dns_name_sscan("before", "", name);
        ok(!labeltree_search_iter(lt, name, &iter), "labeltree_search_iter('before') returns NULL");
        is_eq(labeltree_iter_parent(&iter), ".",    "parent value is '.'");

        dns_name_sscan("before.any.net", "", name);
        ok(!labeltree_search_iter(lt, name, &iter),  "labeltree_search_iter('before.any.net') returns NULL");
        ok(!labeltree_iter_parent(&iter),            "parent (any.net) has no value");
        is_eq(labeltree_iter_previous(&iter), "net", "previous value is 'net'");

        dns_name_sscan("between.net", "", name);
        ok(!labeltree_search_iter(lt, name, &iter),           "labeltree_search_iter('between.net') returns NULL");
        is_eq(labeltree_iter_parent(&iter), "net",            "parent value is 'net'");
        is_eq(labeltree_iter_previous(&iter), "Awfulhak.net", "previous value is 'Awfulhak.net'");

        dns_name_sscan("expand.*.*.org", "", name);
        dns_name_sscan("nomatch", "", item);
        ok(labeltree_search(lt, name, 0, &value, visit_failure, item), "Searching is successful with no failing visitor");
        ok(value, "A value was returned");

        dns_name_sscan("org", "", item);
        ok(labeltree_search(lt, name, 0, &value, visit_failure, item), "Searching can't be blocked at .org (no value)");
        ok(value, "A value was returned");

        dns_name_sscan("*.org", "", item);
        ok(!labeltree_search(lt, name, 0, &value, visit_failure, item), "Searching can be blocked at *.org");
        ok(!value, "A value was not returned");

        dns_name_sscan("expand.*.*.org", "", item);
        ok(!labeltree_search(lt, name, 0, &value, visit_failure, item), "Searching can be blocked at expand.*.*.org (the actual wildcard)");
        ok(!value, "A value was not returned");

        labeltree_free(lt);
    }

    diag("When we process the public-suffix list we do it slightly differently");
    {
        const char *names[] = {
            "a.b.c.d.e",
            "b.b.c.*.e",
            "c.b.*.d.e",
            "c.b.*.*.*",
            "d.*.*.*.*",
        };
        unsigned i;

        lt = labeltree_new();

        for (i = 0; i < sizeof(names) / sizeof(*names); i++) {
            dns_name_sscan(names[i], "", name);
            labeltree_put(lt, name, LABELTREE_VALUE_SET);
        }

        dns_name_sscan("a.b.c.d.e", "", name);
        ok(labeltree_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_suffix_get('a.b.c.d.e') succeeds");
        ok(labeltree_get(lt, name, LABELTREE_FLAG_NO_WILDCARD_WHITEOUT), "labeltree_suffix_get('a.b.c.d.e') succeeds with no wildcard whiteout");

        dns_name_sscan("b.b.c.d.e", "", name);
        ok(!labeltree_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_suffix_get('b.b.c.d.e') fails");
        ok(labeltree_get(lt, name, LABELTREE_FLAG_NO_WILDCARD_WHITEOUT), "labeltree_suffix_get('b.b.c.d.e') succeeds with no wildcard whiteout");

        dns_name_sscan("c.b.c.d.e", "", name);
        ok(!labeltree_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_suffix_get('c.b.c.d.e') fails");
        ok(labeltree_get(lt, name, LABELTREE_FLAG_NO_WILDCARD_WHITEOUT), "labeltree_suffix_get('c.b.c.d.e') succeeds with no wildcard whiteout");

        dns_name_sscan("d.b.c.d.e", "", name);
        ok(!labeltree_get(lt, name, LABELTREE_FLAG_NONE), "labeltree_suffix_get('d.b.c.d.e') fails");
        ok(labeltree_get(lt, name, LABELTREE_FLAG_NO_WILDCARD_WHITEOUT), "labeltree_suffix_get('d.b.c.d.e') succeeds with no wildcard whiteout");
    }

    return exit_status();
}
