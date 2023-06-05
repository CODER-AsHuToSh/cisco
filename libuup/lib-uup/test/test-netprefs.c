#include <kit-alloc.h>
#include <mockfail.h>
#include <tap.h>

#include "cidr-ipv4.h"
#include "cidr-ipv6.h"
#include "conf-loader.h"
#include "labeltree.c"
#include "netprefs-private.h"
#include "radixtree128.h"
#include "radixtree32.h"

#include "common-test.h"

#define CIDR_STR_SZ 45
#define LOADFLAGS_NETPREFS \
            (LOADFLAGS_FP_ALLOW_OTHER_TYPES| LOADFLAGS_FP_ELEMENTTYPE_DOMAIN | LOADFLAGS_FP_ELEMENTTYPE_APPLICATION)

/*
 * Returns a string with 'count' 45 byte values
 */
static char *
great_expectations(const char *txt, unsigned *count)
{
    struct cidr_ipv4 cidr4;
    struct cidr_ipv6 cidr6;
    const char *p;
    unsigned n;
    char *ret;

    p = txt;
    *count = 0;
    while (p && *p) {
        ++*count;
        if ((p = strchr(p, '\n')) != NULL)
            p++;
    }
    SXEA1(ret = kit_calloc(*count, CIDR_STR_SZ), "Oops, kit_calloc(%u, %u) failed", *count, CIDR_STR_SZ);

    p = txt;
    n = 0;
    while (p && *p) {
        if (cidr_ipv4_sscan(&cidr4, p, PARSE_CIDR_ONLY))
            strncpy(ret + n, cidr_ipv4_to_str(&cidr4, 0), CIDR_STR_SZ);
        else if (cidr_ipv6_sscan(&cidr6, p, PARSE_CIDR_ONLY))
            strncpy(ret + n, cidr_ipv6_to_str(&cidr6, 0), CIDR_STR_SZ);
        else
            ret[n] = '\0';
        ret[n + CIDR_STR_SZ - 1] = '\0';
        n += CIDR_STR_SZ;
        if ((p = strchr(p, '\n')) != NULL)
            p++;
    }
    return ret;
}

static char *walk32data;
static unsigned walk32count;
static void
walk32(struct cidr_ipv4 *cidr)
{
    char got[CIDR_STR_SZ];
    unsigned i;

    memcpy(got, cidr_ipv4_to_str(cidr, 0), CIDR_STR_SZ);
    got[CIDR_STR_SZ - 1] = '\0';
    for (i = 0; i < walk32count; i++)
        if (strcmp(walk32data + i * CIDR_STR_SZ, got) == 0) {
            pass("Walk32 got expected cidr %s", got);
            walk32data[i * CIDR_STR_SZ] = '\0';
            return;
        }
    fail("walk32: %s: Got unexpected CIDR", got);
}

static void
verify_walk_32(struct radixtree32 *tree, const char *data)
{
    unsigned err, i;

    walk32data = great_expectations(data, &walk32count);
    radixtree32_walk(tree, walk32);

    for (err = i = 0; i < walk32count; i++)
        if (walk32data[i * CIDR_STR_SZ]) {
            diag("Remaining expectation: %s", walk32data + i * CIDR_STR_SZ);
            err++;
        }
    is(err, 0, "Zero nodes were missed by the walk32");
}

static char *walk128data;
static unsigned walk128count;
static void
walk128(struct cidr_ipv6 *cidr)
{
    char got[CIDR_STR_SZ];
    unsigned i;

    memcpy(got, cidr_ipv6_to_str(cidr, 0), CIDR_STR_SZ);
    got[CIDR_STR_SZ - 1] = '\0';
    for (i = 0; i < walk128count; i++)
        if (strcmp(walk128data + i * CIDR_STR_SZ, got) == 0) {
            pass("Walk128 got expected cidr %s", got);
            walk128data[i * CIDR_STR_SZ] = '\0';
            return;
        }
    fail("walk128: %s: Got unexpected CIDR", got);
}

static void
verify_walk_128(struct radixtree128 *tree, const char *data)
{
    unsigned err, i;

    walk128data = great_expectations(data, &walk128count);
    radixtree128_walk(tree, walk128);

    for (err = i = 0; i < walk128count; i++)
        if (walk128data[i * CIDR_STR_SZ]) {
            diag("Remaining expectation: %s", walk128data + i * CIDR_STR_SZ);
            err++;
        }

    is(err, 0, "Zero nodes were missed by the walk128");
}

int
main(void)
{
    pref_categories_t expected_categories;
    uint64_t start_allocations;
    struct prefidentity *ident;
    struct prefbundle *bundle;
    const struct preforg *org;
    struct conf_info *info;
    struct conf_loader cl;
    struct netaddr addr;
    struct netprefs *np;
    const char *fn;
    unsigned i, z;
    pref_t pr;

    plan_tests(246);

    conf_initialize(".", ".", false, NULL);
    kit_memory_initialize(false);
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */

    conf_loader_init(&cl);

    diag("Test integration with the conf subsystem");
    {
        netprefs_register(&CONF_NETPREFS, "netprefs", "netprefs", true);
        ok(!netprefs_conf_get(NULL, CONF_NETPREFS), "Failed to get netprefs from a NULL confset");
        conf_unregister(CONF_NETPREFS);
    }

    diag("Test missing file load");
    {
        info = conf_info_new(NULL, "noname", "nopath", NULL, LOADFLAGS_NONE, NULL, 0);
        info->updates++;

        conf_loader_open(&cl, "/tmp/not-really-there", NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        ok(!np, "Failed to read non-existent file");
        OK_SXEL_ERROR("/tmp/not-really-there could not be opened: No such file or directory");
        OK_SXEL_ERROR(NULL);

        conf_loader_done(&cl, info);
        is(info->updates, 1, "conf_loader_done() didn't bump 'updates'");
        is(info->st.dev, 0, "Loading a non-existent file gives a clear stat");
        for (z = 0; z < sizeof(info->digest); z++)
            if (info->digest[z])
                break;
        is(z, sizeof(info->digest), "The digest of an empty file has %zu zeros", sizeof(info->digest));
        conf_info_free(info);
    }

    diag("Test garbage file");
    {
        fn = create_data("test-netprefs", "This is not the correct format\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read garbage file");
        OK_SXEL_ERROR(": 1: Invalid header; must contain 'netprefs'");
    }

    diag("Test V%d data load", NETPREFS_VERSION - 1);
    {
        fn = create_data("test-netprefs", "netprefs %d\ncount 1\nunread-data\n", NETPREFS_VERSION - 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data", NETPREFS_VERSION - 1);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [%d]", NETPREFS_VERSION);
    }

    diag("Test V%d data load", NETPREFS_VERSION + 1);
    {
        fn = create_data("test-netprefs", "netprefs %d\ncount 0\nunread-data\n", NETPREFS_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data", NETPREFS_VERSION + 1);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [%d]", NETPREFS_VERSION);
    }

    diag("Test empty data load");
    {
        fn = create_data("test-netprefs", "# Nothing to see here\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read an empty file");
        OK_SXEL_ERROR("No content found");
    }

    diag("Test V%d empty data load", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs", "netprefs %d\ncount 0\n", NETPREFS_VERSION);

        MOCKFAIL_START_TESTS(2, fileprefs_new);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        ok(!np, "netprefs_new() of empty V%u data fails when fileprefs_new() fails", NETPREFS_VERSION);
        OK_SXEL_ERROR("Cannot allocate");
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        conf_loader_done(&cl, NULL);
        unlink(fn);
        ok(np, "Constructed struct netprefs from empty V%d data", NETPREFS_VERSION);
        skip_if(!np, 4, "Cannot test NULL np") {
            is(PREFS_COUNT(np, identities), 0, "V%d data has a count of zero", NETPREFS_VERSION);
            is(np->conf.refcount, 1, "V%d data has a refcount of 1", NETPREFS_VERSION);
            netprefs_refcount_inc(np);
            is(np->conf.refcount, 2, "V%u data can bump its refcount", NETPREFS_VERSION);
            netprefs_refcount_dec(np);
            is(np->conf.refcount, 1, "V%u data can drop its refcount", NETPREFS_VERSION);
            netprefs_refcount_dec(np);
        }
    }

    diag("Test V%d data load with additional invalid versions", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs", "netprefs %d xx\ncount 0\n[lists:0]\n[bundles:0]\n[orgs:0]\n[identities:0]\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with version 'xx' also specified", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 1: Invalid header version(s); must be numeric");

        fn = create_data("test-netprefs", "netprefs %d %d\ncount 0\n[bundles:0:%d %d]\n",
                                          NETPREFS_VERSION, NETPREFS_VERSION + 1,
                                          NETPREFS_VERSION, NETPREFS_VERSION + 1);  /* Valid + invalid versions */
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(np, "Read version %d data with version %d also specified", NETPREFS_VERSION, NETPREFS_VERSION + 1);
        netprefs_refcount_dec(np);

        fn = create_data("test-netprefs", "netprefs %d %d\ncount 0\n[bundles:0:%d %d]\n",
                                          NETPREFS_VERSION, NETPREFS_VERSION + 1,   /* Valid + invalid versions */
                                          NETPREFS_VERSION, NETPREFS_VERSION - 1);  /* Not the same versions */
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with version '%d' not matching the header", NETPREFS_VERSION, NETPREFS_VERSION - 1);
        OK_SXEL_ERROR(": 3: Section header version %d not specified in file header", NETPREFS_VERSION - 1);

        fn = create_data("test-netprefs", "netprefs %d %d\ncount 0\n[bundles:0:%d xx]\n",
                                          NETPREFS_VERSION, NETPREFS_VERSION + 1,   /* Valid versions */
                                          NETPREFS_VERSION);                        /* Not the same versions - not even a number*/
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with version 'xx' not even numeric", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 3: Invalid section header version(s)");
    }

    diag("Test V%d data load with missing lines", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs", "netprefs %d\ncount 1\n[lists:0]\n[bundles:0]\n[orgs:0]\n[identities:0]\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with missing lines", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 6: Incorrect total count 1 - read 0 data lines");
    }

    diag("Test V%d data load with invalid headers", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs", "netprefs %d\ncount 0\n[lists]\n[bundles]\n[orgs]\n[identities]\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with old-style 'version' header", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 3: Expected section header");

        fn = create_data("test-netprefs", "netprefs %d\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with EOF before 'count' header", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 1: No count line found");

        fn = create_data("test-netprefs", "netprefs %d\ncount X\n[lists:0]\n[bundles:0]\n[orgs:0]\n[identities:0]\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with invalid 'count' header", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 2: Invalid count; must be a numeric value");
    }

    diag("Test %d1 data load with extra lines", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs", "netprefs %d\ncount 0\n[lists:0]\n[bundles:0]\n[orgs:0]\n[identities:0]\nextra-garbage\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with extra garbage", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 7: Unexpected [identities] line - wanted only 0 items");
    }

    diag("Test V%d data load with and without duplicate discarded lists", NETPREFS_VERSION);
    {
        const char discard_list[]     = "9:1:cidr:72:e30088c5bb3b44ce3e44ac1060c5ad1efb882c85:127.0.0.0/24\n";
        const char application_list[] = "19:1:application:72:0430968c125eff39b25f22fa804baabe92c4a648:123 456\n";
        const char content_format[]   = "netprefs %d\n"
                                        "count %d\n"
                                        "[lists:%d]\n%s%s"
                                        "[bundles:0]\n"
                                        "[identities:0]\n";
        fn = create_data("test-netprefs", content_format, NETPREFS_VERSION, 1, 1, discard_list, "");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(np, "Read version %d data with single discarded CIDR list", NETPREFS_VERSION);
        netprefs_refcount_dec(np);

        fn = create_data("test-netprefs", content_format, NETPREFS_VERSION, 2, 2, discard_list, discard_list);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with duplicate discarded CIDR list", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 5: Cannot mark preflist 09:1:cidr as discarded");

        fn = create_data("test-netprefs", content_format, NETPREFS_VERSION, 1, 1, application_list, "");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(np, "Read version %d data with application list", NETPREFS_VERSION);
        netprefs_refcount_dec(np);
    }

    diag("Test V%d data load with invalid CIDR", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs",   "netprefs %d\n"
                                            "count 3\n"
                                            "[lists:1]\n"
                                            "9:1:domain:72:ea30235cf4a6e3540284842ace8291c8504c6ede:mylookup1\n"
                                            "[bundles:1]\n"
                                            "1:1:0:0:0::::1:::::::\n"
                                            "[identities:1]\n"
                                            "127.0.0/32:100000:1:0:1:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with invalid format", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 8: Unrecognised line (invalid CIDR)");
    }

    diag("Test V%d data load with missing fingerprint and domainlist fields", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs",   "netprefs %d\n"
                                            "count 3\n"
                                            "[lists:1]\n"
                                            "9:1:domain:72\n"
                                            "[bundles:1]\n"
                                            "1:1:0:0:0::::1:::::\n"
                                            "[identities:1]\n"
                                            "127.0.0.1/32:100000:1:0:1:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with missing fingerprint & domainlist", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 4: Unrecognised bit for list type 08");
    }

    diag("Test V%d data load with missing domainlist field", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs",   "netprefs %d\n"
                                            "count 3\n"
                                            "[lists:1]\n"
                                            "9:1:domain:72:adc83b19e793491b1c6ea0fd8b46cd9f32e592fc\n"
                                            "[bundles:1]\n"
                                            "1:1:0:0:0::::1:::::::\n"
                                            "[identities:1]\n"
                                            "127.0.0.1/32:100000:1:0:1:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with invalid domainlist", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 4: List type 08 name domain must have a fingerprint (even number of hex digits)");
    }

    diag("Test V%d data load with invalid flags field", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs",   "netprefs %d\n"
                                            "count 3\n"
                                            "[lists:1]\n"
                                            "9:1:domain:72:ea30235cf4a6e3540284842ace8291c8504c6ede:mylookup1\n"
                                            "[bundles:1]\n"
                                            "1:1:0:W:0::::1:::::::\n"
                                            "[identities:1]\n"
                                            "127.0.0.1/32:100000:1:0:1:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with invalid flags", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 6: Unrecognised bundle line (invalid actype:bundleid:priority:flags:)");
    }

    diag("Test V%d data load with invalid priority field", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs",   "netprefs %d\n"
                                            "count 3\n"
                                            "[lists:1]\n"
                                            "9:1:domain:72:ea30235cf4a6e3540284842ace8291c8504c6ede:mylookup1\n"
                                            "[bundles:1]\n"
                                            "1:1:W:0:0::::1:::::::\n"
                                            "[identities:1]\n"
                                            "127.0.0.1/32:100000:1:0:1:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with invalid priority", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 6: Unrecognised bundle line (invalid actype:bundleid:priority:flags:)");
    }

    diag("Test V%d data load with invalid categories", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs", "netprefs %d\n"
                                            "count 3\n"
                                            "[lists:1]\n"
                                            "9:1:domain:72:ea30235cf4a6e3540284842ace8291c8504c6ede:mylookup1\n"
                                            "[bundles:1]\n"
                                            "1:1:0:0:g::::1:::::::\n"
                                            "[identities:1]\n"
                                            "127.0.0.1/32:100000:1:0:1:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with invalid categories (not hex)", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 6: Unrecognised bundle line (invalid categories)");
    }

    diag("Test V%d data load with invalid list", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs", "netprefs %d\ncount 5\n"
                         "[lists:2]\n"
                         "4:1:domain::e04a31185d147edd80f03146e151604ac707631c:except.com\n"
                         "30:1:domain::e04a31185d147edd80f03146e151604ac707631c:except.com\n"
                         "[bundles:1]\n"
                         "0:1:0:0:0:::1::::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:0:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(np, "Read version %d data with an invalid ltype", NETPREFS_VERSION);
        netprefs_refcount_dec(np);

        fn = create_data("test-netprefs", "netprefs %d\ncount 4\n"
                         "[lists:1]\n"
                         "0:1:domain::adc83b19e793491b1c6ea0fd8b46cd9f32e592fc:except.com\n"
                         "[bundles:1]\n"
                         "0:1:0:0:0:::1::::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:0:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with no list bit", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 4: Invalid category bit field for list type 0");

        fn = create_data("test-netprefs", "netprefs %d\ncount 4\n"
                         "[lists:1]\n"
                         "0:1:domain:X:e04a31185d147edd80f03146e151604ac707631c:except.com\n"
                         "[bundles:1]\n"
                         "0:1:0:0:0:::1::::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:0:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with an invalid list bit", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 4: Unrecognised bit for list type 0");

        fn = create_data("test-netprefs", "netprefs %d\ncount 4\n"
                         "[lists:1]\n"
                         "4:1:domain:0:e04a31185d147edd80f03146e151604ac707631c:except.com\n"
                         "[bundles:1]\n"
                         "0:1:0:0:0:::1::::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:0:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with an invalid list bit for AT_LIST_EXCEPT list type", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 4: Invalid category bit field for list type 04");

        fn = create_data("test-netprefs", "netprefs %d\ncount 4\n"
                         "[lists:1]\n"
                         "c:1:url_proxyt:0:754c0cca85ec19b66c33f8324d8b2ad0e880c910:url_proxy\n"
                         "[bundles:1]\n"
                         "0:1:0:0:0:::1::::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:0:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with an invalid list bit for AT_LIST_URL_PROXY_HTTPS list type", NETPREFS_VERSION);
        OK_SXEL_ERROR("prefbuilder_attach: Except list 04:1:* doesn't exist");
        OK_SXEL_ERROR(": 6: Cannot attach bundle 0:1 to list 04:1 (list pos 1)");

        fn = create_data("test-netprefs", "netprefs %d\ncount 4\n"
                         "[lists:1]\n"
                         "0:1:domain:0:76b7bde840799a623101a1e255807208c4bb754c:block1\n"
                         "[bundles:1]\n"
                         "0:1:0:0:0:::1::::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:0:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with an invalid list bit of 0 for AT_LIST_BLOCK list type", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 4: Unrecognised bit for list type 0");

        fn = create_data("test-netprefs", "netprefs %d\ncount 4\n"
                         "[lists:1]\n"
                         "0:1:::e04a31185d147edd80f03146e151604ac707631c:except.com\n"
                         "[bundles:1]\n"
                         "0:1:0:0:0:::1::::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:0:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with an empty name field", NETPREFS_VERSION);
        OK_SXEL_ERROR("prefbuilder_attach: Except list 04:1:* doesn't exist");
        OK_SXEL_ERROR(": 6: Cannot attach bundle 0:1 to list 04:1 (list pos 1)");

        fn = create_data("test-netprefs", "netprefs %d\ncount 4\n"
                         "[lists:1]\n"
                         "0:1:name\n"
                         "[bundles:1]\n"
                         "0:1:0:0:0:::1::::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:0:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with an unterminated name", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 4: Unrecognised list line (no elementtype terminator)");
    }

    diag("Test V%d data load with trailing identity junk", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs", "netprefs %d\ncount 3\n"
                         "[bundles:1]\n"
                         "0:1:0:0:0:::::::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:0:1trailing junk\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with trailing identity junk", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 8: Unrecognised identity line (trailing junk)");
    }

    diag("Test V%d data load with invalid actype", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs", "netprefs %d\ncount 3\n"
                         "[bundles:1]\n"
                         "5:1:0:0:0:::::::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:1:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with invalid bundle actype", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 4: Unrecognised bundle line (invalid actype)");

        fn = create_data("test-netprefs", "netprefs %d\ncount 3\n"
                         "[bundles:1]\n"
                         "1:1:0:0:0:::::::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:5:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with invalid identity actype", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 8: Unrecognised list line (invalid actype)");
    }

    diag("Test V%d data load with invalid bundle", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs", "netprefs %d\ncount 3\n"
                         "[lists:0]\n"
                         "[bundles:1]\n"
                         "0:1:0:0:0:::::1::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:0:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(np, "Read version %d data with invalid (external) list reference", NETPREFS_VERSION);
        netprefs_refcount_dec(np);

        fn = create_data("test-netprefs", "netprefs %d\ncount 4\n"
                         "[bundles:2]\n"
                         "0:1:0:0:0:::::::::::\n"
                         "0:1:0:0:0:::::::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:0:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with duplicate bundle", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 5: Cannot create bundle 0:1");

        fn = create_data("test-netprefs", "netprefs %d\ncount 3\n"
                         "[bundles:1]\n"
                         "1:1:0:0:0:::::::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:0:2\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        ok(np, "Read version %d data with ident referring to an invalid bundle", NETPREFS_VERSION);
        netprefs_refcount_dec(np);

        fileprefs_set_strict(1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with ident referring to an invalid bundle - strict mode!", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 8: Cannot add identity; invalid bundleid or orgid");

        fn = create_data("test-netprefs", "netprefs %d\n"
                         "count 3\n"
                         "[bundles:1]\n"
                         "0:1:0:0::::::::::::\n"
                         "[orgs:1]\n"
                         "2:0:0:365:0:1002:0\n"
                         "[identities:1]\n"
                         "::1/128:42:1:2:0:1\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(!np, "Failed to read version %d data with an empty categories field", NETPREFS_VERSION);
        OK_SXEL_ERROR(": 4: Unrecognised bundle line (invalid categories)");
    }

    diag("Test V%d data load with memory failures", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs",
                            "netprefs %d\n"
                            "count 8\n"
                            "[bundles:2]\n"
                            "1:1:9:72:350000002000001483:::::::::::\n"
                            "1:2:256:50:350000002000001483:::::::::::\n"
                            "[orgs:2]\n"
                            "1:0:0:365:0:1001:0\n"
                            "2:0:0:365:0:1002:0\n"
                            "[identities:4]\n"
                            "1.2.3.0/24:123456:1:1:1:1\n"
                            "1.2.4.0/24:123456:1:1:1:1\n"
                            "1:2::/32:789012:1:2:1:2\n"
                            "1:3::/32:789012:1:2:1:2\n", NETPREFS_VERSION);

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(np = netprefs_new(&cl, LOADFLAGS_NETPREFS), "Loaded netprefs v%u with 4 identities", NETPREFS_VERSION);
        skip_if(!np, 2, "Cannot test NULL np") {
            is(PREFS_COUNT(np, identities), 4, "V%d data has a count of four", NETPREFS_VERSION);
            is(np->conf.refcount, 1, "V%d data has a refcount of 1", NETPREFS_VERSION);
            netprefs_refcount_dec(np);
        }

        MOCKFAIL_START_TESTS(4, radixtree32_new);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!netprefs_new(&cl, LOADFLAGS_NETPREFS), "Failed to load netprefs when radixtree32_new() fails");
        OK_SXEL_ERROR("Couldn't allocate");
        MOCKFAIL_SET_FREQ(2);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!netprefs_new(&cl, LOADFLAGS_NETPREFS), "Failed to load netprefs when radixtree32_put() fails");
        OK_SXEL_ERROR("Not enough memory to allocate a radixtree32");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(8, radixtree128_new);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!netprefs_new(&cl, LOADFLAGS_NETPREFS), "Failed to load netprefs when radixtree128_new() fails");
        OK_SXEL_ERROR("Couldn't allocate");
        MOCKFAIL_SET_FREQ(2);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!netprefs_new(&cl, LOADFLAGS_NETPREFS), "Failed to load netprefs when radixtree128_put() fails");
        OK_SXEL_ERROR("Failed to insert a new radixtree32 node");
        OK_SXEL_ERROR("Couldn't allocate");
        OK_SXEL_ERROR("Not enough memory to allocate a radixtree128");
        OK_SXEL_ERROR("Couldn't allocate");
        OK_SXEL_ERROR("Failed to insert a new radixtree128 node");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(2, fileprefs_load_fileheader);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!netprefs_new(&cl, LOADFLAGS_NETPREFS), "Failed to load netprefs when version allocation fails");
        OK_SXEL_ERROR("Couldn't allocate 5*4 version bytes");
        MOCKFAIL_END_TESTS();

        unlink(fn);
    }

    diag("Test V%d data handling", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs",
                            "netprefs %d\n"
                            "count 11\n"
                            "[lists:3]\n"
                            "1:1:domain:71:2cdf6da64d5f453dc5c74553e18c04e78b7ad44d:blocked.1 blocked.2\n"
                            "1:2:domain:71:01f7a1505e520a10af542eb5b4ca988eb1c1120e:blocked.3\n"
                            "1:3:domain:71:b07129a65fd3f0cfac9a77e1fba5e028202572f0:blocked.4\n"
                            "[bundles:4]\n"
                            "1:1:9:72:350000002000001483:::::::::::\n"
                            "1:2:256:50:350000002000001483::1:::::::::\n"
                            "1:3:42:1800:BADC0DE00000000DEADBEEF::2:::::::::\n"
                            "1:4:19:1:FEDCBA9876543210::3:::::::::\n"
                            "[identities:4]\n"
                            "9.0.2.0/24:123456:1:0:1:1\n"
                            "9.0.3.4/32:789012:1:0:1:2\n"
                            "9.0.4.0/24:345678:1:0:1:3\n"
                            "9.0.5.0/24:2:1:0:1:4\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(np, "Constructed struct netprefs from V%d data", NETPREFS_VERSION);
        skip_if(!np, 29, "Cannot test NULL np") {
            is(PREFS_COUNT(np, identities), 4, "V%d data has a count of four", NETPREFS_VERSION);
            is(np->conf.refcount, 1, "V%d data has a refcount of 1", NETPREFS_VERSION);

            diag("    V%d failed lookup", NETPREFS_VERSION);
            {
                netaddr_from_str(&addr, "9.0.3.3", AF_INET);
                is(netprefs_get(&pr, np, "netprefs", &addr, NULL, "a test IP"), -1, "Got no prefs for IP 9.0.3.3");
            }

            diag("    V%d exact lookup", NETPREFS_VERSION);
            {
                netaddr_from_str(&addr, "9.0.3.4", AF_INET);
                ok(netprefs_get(&pr, np, "netprefs", &addr, NULL, "a test IP") != -1, "Got prefs for IP 9.0.3.4 (exact lookup)");
                skip_if(!PREF_VALID(&pr), 8, "Cannot run exact lookup tests without prefs") {
                    bundle = PREF_BUNDLE(&pr);
                    org = PREF_ORG(&pr);
                    ident = PREF_IDENT(&pr);
                    is(bundle->bundleflags, PREF_BUNDLEFLAGS_EXPIRED_RRS | PREF_BUNDLEFLAGS_TYPO_CORRECTION,
                       "Got the correct flags for IP 9.0.3.4");
                    is(ident->originid, 789012, "Got the correct origin_id for IP 9.0.3.4");
                    is(ident->origintypeid, 1, "The origintypeid was populated");
                    pref_categories_sscan(&expected_categories, "350000002000001483");
                    ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                       "Unexpected categories %s (expected 350000002000001483)",  pref_categories_idstr(&bundle->base_blocked_categories));
                    is(bundle->priority, 256, "Got the correct priority for IP 9.0.3.4");
                    is(org ? org->id : 0, 0, "Got the correct org ID for IP 9.0.3.4");
                    is(bundle->id, 2, "Got the correct bundle ID for IP 9.0.3.4");
                }
            }

            diag("    V%d contained lookup", NETPREFS_VERSION);
            {
                netaddr_from_str(&addr, "9.0.4.1", AF_INET);
                ok(netprefs_get(&pr, np, "netprefs", &addr, NULL, "a test IP") != -1, "Got prefs for IP 9.0.4.1 (contained lookup)");
                skip_if(!PREF_VALID(&pr), 8, "Cannot run contained lookup tests without prefs") {
                    bundle = PREF_BUNDLE(&pr);
                    org = PREF_ORG(&pr);
                    ident = PREF_IDENT(&pr);
                    is(bundle->bundleflags, PREF_BUNDLEFLAGS_BPB | PREF_BUNDLEFLAGS_ALLOWLIST_ONLY,
                       "Got the correct flags for IP 9.0.4.1");
                    is(ident->originid, 345678, "Got the correct origin_id for IP 9.0.4.1");
                    is(ident->origintypeid, 1, "The origintypeid was populated");
                    pref_categories_sscan(&expected_categories, "badc0de00000000deadbeef");
                    ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                       "Unexpected categories %s (expected BADC0DE00000000DEADBEEF)",  pref_categories_idstr(&bundle->base_blocked_categories));
                    is(bundle->priority, 42, "Got the correct priority for IP 9.0.4.1");
                    is(org ? org->id : 0, 0, "Got the correct org ID for IP 9.0.4.1");
                    is(bundle->id, 3, "Got the correct bundle ID for IP 9.0.4.1");
                }
            }

            diag("    V%d contained lookup of a closed network", NETPREFS_VERSION);
            {
                netaddr_from_str(&addr, "9.0.5.1", AF_INET);
                ok(netprefs_get(&pr, np, "netprefs", &addr, NULL, "a test IP") != -1, "Got prefs for IP 9.0.5.1 (closed lookup)");
                skip_if(!PREF_VALID(&pr), 6, "Cannot run closed lookup tests without prefs") {
                    bundle = PREF_BUNDLE(&pr);
                    ident = PREF_IDENT(&pr);
                    is(bundle->bundleflags, PREF_BUNDLEFLAGS_CLOSED_NETWORK, "Got the correct flags for IP 9.0.5.1");
                    is(ident->originid, 2, "Got the correct origin_id for IP 9.0.5.1");
                    is(ident->origintypeid, 1, "The origintypeid was populated");
                    pref_categories_sscan(&expected_categories, "fedcba9876543210");
                    ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                       "Unexpected categories %s (expected fedcba9876543210)",  pref_categories_idstr(&bundle->base_blocked_categories));
                    is(bundle->priority, 0x13, "Got the correct priority for IP 9.0.5.1");
                }
            }

            diag("    V%u key_to_str returns identity key as a cidr", NETPREFS_VERSION);
            {
                is_eq((*np->fp.ops->key_to_str)(&np->fp, 0), "9.0.2.0/24", "Got the correct first key");
            }

            netprefs_refcount_dec(np);
        }
    }

    diag("Test V%d IPv6 data handling", NETPREFS_VERSION);
    {
        fn = create_data("test-netprefs",
                            "netprefs %d\n"
                            "count 25\n"
                            "[lists:6]\n"
                            "1:1:domain:71:740f05909a2971cb969365289a152b0ba628783a:blocked.4\n"
                            "1:2:domain:71:668073dce9a3e3e429151e6d6f9490a09d9c1964:blocked.1 blocked.2\n"
                            "1:3:domain:71:2fa812d29671b533b08a26c04e6a9225463ef3d2:blocked.3\n"
                            "1:4:domain:71:2fa812d29671b533b08a26c04e6a9225463ef3d2:blocked.3\n"
                            "1:5:domain:71:740f05909a2971cb969365289a152b0ba628783a:blocked.4\n"
                            "1:6:domain:71:668073dce9a3e3e429151e6d6f9490a09d9c1964:blocked.1 blocked.2\n"
                            "[bundles:8]\n"
                            "1:1:19:1:FEDCBA9876543210::1:::::::::\n"
                            "1:2:9:10000072:350000002000001483:::::::::::\n"
                            "1:3:256:10000070:350000002000001483::2:::::::::\n"
                            "1:4:42:1800:BADC0DE00000000DEADBEEF::3:::::::::\n"
                            "1:5:42:10001800:BADC0DE00000000DEADBEEF::4:::::::::\n"
                            "1:6:19:10000001:FEDCBA9876543210::5:::::::::\n"
                            "1:7:9:72:350000002000001483:::::::::::\n"
                            "1:8:256:50:350000002000001483::6:::::::::\n"
                            "[orgs:3]\n"
                            "2:0:2000000000000000000000:366:10:1002:0\n"
                            "100:ff:0:366:20:100100:0\n"
                            "300:100:0:365:30:100300:0\n"
                            "[identities:8]\n"
                            "[::9:0:5:0]/112:2:1:100:1:1\n"
                            "9.0.2.0/24:123456:1:2:1:2\n"
                            "9.0.3.4/32:789012:1:2:1:3\n"
                            "[::9:0:4:0]/112:345678:1:2:1:4\n"
                            "9.0.4.0/24:345678:1:0:1:5\n"
                            "9.0.5.0/24:2:1:0:1:6\n"
                            "[::9:0:2:0]/112:123456:1:0:1:7\n"
                            "[::9:0:3:4]/128:789012:1:300:1:8\n", NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(np, "Constructed struct netprefs from V%d data", NETPREFS_VERSION);
        skip_if(!np, 33, "Cannot test NULL np") {
            is(PREFS_COUNT(np, identities), 8, "V%d data has a count of eight", NETPREFS_VERSION);
            is(np->conf.refcount, 1, "V%d data has a refcount of 1", NETPREFS_VERSION);

            diag("    V%d failed lookup", NETPREFS_VERSION);
            {
                netaddr_from_str(&addr, "::9:0:3:3", AF_INET6);
                is(netprefs_get(&pr, np, "netprefs", &addr, NULL, "a test IP"), -1, "Got no prefs for IP ::9:0:3:3");
            }

            diag("    V%d exact lookup", NETPREFS_VERSION);
            {
                netaddr_from_str(&addr, "::9:0:3:4", AF_INET6);
                ok(netprefs_get(&pr, np, "netprefs", &addr, NULL, "a test IP") != -1, "Got prefs for IP ::9:0:3:4 (exact lookup)");
                skip_if(!PREF_VALID(&pr), 10, "Cannot run exact lookup tests without prefs") {
                    bundle = PREF_BUNDLE(&pr);
                    org = PREF_ORG(&pr);
                    ident = PREF_IDENT(&pr);
                    is(bundle->bundleflags, PREF_BUNDLEFLAGS_EXPIRED_RRS | PREF_BUNDLEFLAGS_TYPO_CORRECTION,
                       "Got the correct flags for IP ::9:0:3:4");
                    is(ident->originid, 789012, "Got the correct origin_id for IP ::9:0:3:4");
                    is(ident->origintypeid, 1, "The origintypeid was populated");
                    pref_categories_sscan(&expected_categories, "350000002000001483");
                    ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                       "Unexpected categories %s (expected 350000002000001483)",  pref_categories_idstr(&bundle->base_blocked_categories));
                    is(bundle->priority,         256,    "Got the correct priority for IP ::9:0:3:4");
                    is(org ? org->id         : 0, 300,    "Got the correct orgid for IP ::9:0:3:4");
                    is(org ? org->orgflags   : 0, 256,    "Got the correct org flags for IP ::9:0:3:4");
                    is(org ? org->retention  : 0, 365,    "Got the correct org retention period for IP ::9:0:3:4");
                    is(org ? org->warnperiod : 0, 30,    "Got the correct org warn period for IP ::9:0:3:4");
                    is(org ? org->originid   : 0, 100300, "Got the correct org originid for IP ::9:0:3:4");
                }
            }

            diag("    V%d contained lookup", NETPREFS_VERSION);
            {
                netaddr_from_str(&addr, "::9:0:4:1", AF_INET6);
                ok(netprefs_get(&pr, np, "netprefs", &addr, NULL, "a test IP") != -1, "Got prefs for IP ::9:0:4:1 (contained lookup)");
                skip_if(!PREF_VALID(&pr), 10, "Cannot run contained lookup tests without prefs") {
                    bundle = PREF_BUNDLE(&pr);
                    org    = PREF_ORG(&pr);
                    ident  = PREF_IDENT(&pr);
                    is(bundle->bundleflags, PREF_BUNDLEFLAGS_BPB | PREF_BUNDLEFLAGS_ALLOWLIST_ONLY,
                       "Got the correct flags for IP ::9:0:4:1");
                    is(ident->originid, 345678, "Got the correct origin_id for IP ::9:0:4:1");
                    is(ident->origintypeid, 1, "The origintypeid was populated");
                    pref_categories_sscan(&expected_categories, "badc0de00000000deadbeef");
                    ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                       "Unexpected categories %s (expected BADC0DE00000000DEADBEEF)",  pref_categories_idstr(&bundle->base_blocked_categories));
                    is(bundle->priority, 42, "Got the correct priority for IP ::9:0:4:1");

                    if (org != NULL) {
                        is(org->id,       2, "Got the correct orgid for IP ::9:0:4:1");
                        is(org->orgflags, 0, "Got the correct org flags for IP ::9:0:4:1");
                        pref_categories_sscan(&expected_categories, "2000000000000000000000");
                        ok(pref_categories_equal(&org->unmasked, &expected_categories),
                            "Unexpected categories %s (expected 2000000000000000000000)",  pref_categories_idstr(&org->unmasked));
                    }
                }
            }

            diag("    V%d contained lookup of a closed network", NETPREFS_VERSION);
            {
                netaddr_from_str(&addr, "::9:0:5:1", AF_INET6);
                ok(netprefs_get(&pr, np, "netprefs", &addr, NULL, "a test IP") != -1, "Got prefs for IP ::9:0:5:1 (closed lookup)");
                skip_if(!PREF_VALID(&pr), 6, "Cannot run closed lookup tests without prefs") {
                    bundle = PREF_BUNDLE(&pr);
                    ident = PREF_IDENT(&pr);
                    is(bundle->bundleflags, PREF_BUNDLEFLAGS_CLOSED_NETWORK, "Got the correct flags for IP ::9:0:5:1");
                    is(ident->originid, 2, "Got the correct origin_id for IP ::9:0:5:1");
                    is(ident->origintypeid, 1, "The origintypeid was populated");
                    pref_categories_sscan(&expected_categories, "fedcba9876543210");
                    ok(pref_categories_equal(&bundle->base_blocked_categories, &expected_categories),
                       "Unexpected categories %s (expected fedcba9876543210)",  pref_categories_idstr(&bundle->base_blocked_categories));
                    is(bundle->priority, 0x13, "Got the correct priority for IP ::9:0:5:1");
                }
            }

            diag("    V%u key_to_str returns identity key as a V6 cidr", NETPREFS_VERSION);
            {
                is_eq((*np->fp.ops->key_to_str)(&np->fp, 0), "[::9:0:5:0]/112", "Got the correct first key");
            }

            netprefs_refcount_dec(np);
        }
    }

    diag("Test radixtree32 insertion code paths");
    {
#define NETPREFS_IPV4_DATA  "[bundles:15]\n" \
                            "1:1:597:72:350000002000001483:::::::::::\n" \
                            "1:2:596:72:350000002000001483:::::::::::\n" \
                            "1:3:595:72:350000002000001483:::::::::::\n" \
                            "1:4:594:72:350000002000001483:::::::::::\n" \
                            "1:5:593:72:350000002000001483:::::::::::\n" \
                            "1:6:592:72:350000002000001483:::::::::::\n" \
                            "1:7:585:72:350000002000001483:::::::::::\n" \
                            "1:8:584:72:350000002000001483:::::::::::\n" \
                            "1:9:583:72:350000002000001483:::::::::::\n" \
                            "1:10:582:72:350000002000001483:::::::::::\n" \
                            "1:11:581:72:350000002000001483:::::::::::\n" \
                            "1:12:580:72:350000002000001483:::::::::::\n" \
                            "1:13:579:72:350000002000001483:::::::::::\n" \
                            "1:14:578:72:350000002000001483:::::::::::\n" \
                            "1:15:577:72:350000002000001483:::::::::::\n" \
                            "[identities:15]\n" \
                            "0.0.0.0/0:1:1:0:1:1\n" \
                            "1.2.2.0/24:2:1:0:1:2\n" \
                            "1.2.3.0/24:3:1:0:1:3\n" \
                            "1.2.4.0/24:4:1:0:1:4\n" \
                            "1.2.5.0/24:5:1:0:1:5\n" \
                            "1.2.6.0/24:6:1:0:1:6\n" \
                            "1.2.6.0/25:7:1:0:1:7\n" \
                            "1.2.6.0/26:8:1:0:1:8\n" \
                            "1.2.6.0/27:9:1:0:1:9\n" \
                            "1.2.6.0/28:10:1:0:1:10\n" \
                            "1.2.7.0/28:11:1:0:1:11\n" \
                            "1.2.7.0/27:12:1:0:1:12\n" \
                            "1.2.7.0/26:13:1:0:1:13\n" \
                            "1.2.7.0/25:14:1:0:1:14\n" \
                            "1.2.7.0/24:15:1:0:1:15\n"
        fn = create_data("test-netprefs", "netprefs %d\ncount 30\n" NETPREFS_IPV4_DATA, NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        unlink(fn);
        ok(np, "Constructed struct netprefs from V%d data", NETPREFS_VERSION);
        skip_if(!np, 30, "Cannot test NULL np") {
            verify_walk_32(np->radixtree32, NETPREFS_IPV4_DATA);  /* plus 15+1 oks */
            is(PREFS_COUNT(np, identities), 15, "Data has a count of fifteen");
            is(np->conf.refcount, 1, "V%d data has a refcount of 1", NETPREFS_VERSION);

            struct {
                const char *addr;
                unsigned origin;
                const char *reason;
            } expect[] = {
                { "1.3.0.0", 1, "IP is matched by 0.0.0.0/0" },
                { "1.2.2.1", 2, "IP is matched by 1.2.2.0/24" },
                { "1.2.6.255", 6, "IP is matched by 1.2.6.0/24" },
                { "1.2.6.0", 0xa, "IP is matched by 1.2.6.0/28" },
                { "1.2.7.4", 0xb, "IP is matched by 1.2.7.0/28 (despite priorities)" },
                { "1.2.7.17", 0xc, "IP is matched by 1.2.7.0/27" },
            };

            for (i = 0; i < sizeof expect / sizeof *expect; i++) {
                netaddr_from_str(&addr, expect[i].addr, AF_INET);
                ok(netprefs_get(&pr, np, "netprefs", &addr, NULL, "a test IP") != -1, "Got prefs for item %d IP %s", i, expect[i].addr);
                skip_if(!PREF_VALID(&pr), 1, "Got nothing for IP %s, cannot verify origin %08x", expect[i].addr, expect[i].origin) {
                    is(PREF_IDENT(&pr)->originid, expect[i].origin, "Got the correct origin_id (%08x) for IP %s: %s", expect[i].origin, expect[i].addr, expect[i].reason);
                }
            }

            netprefs_refcount_dec(np);
        }
    }

    diag("Test radixtree128 insertion code paths");
    {
#define NETPREFS_IPV6_DATA  "[bundles:17]\n" \
                            "1:1:597:72:350000002000001483:::::::::::\n" \
                            "1:2:596:72:350000002000001483:::::::::::\n" \
                            "1:3:595:72:350000002000001483:::::::::::\n" \
                            "1:4:594:72:350000002000001483:::::::::::\n" \
                            "1:5:593:72:350000002000001483:::::::::::\n" \
                            "1:6:592:72:350000002000001483:::::::::::\n" \
                            "1:7:585:72:350000002000001483:::::::::::\n" \
                            "1:8:584:72:350000002000001483:::::::::::\n" \
                            "1:9:583:72:350000002000001483:::::::::::\n" \
                            "1:10:582:72:350000002000001483:::::::::::\n" \
                            "1:11:581:72:350000002000001483:::::::::::\n" \
                            "1:12:580:72:350000002000001483:::::::::::\n" \
                            "1:13:579:72:350000002000001483:::::::::::\n" \
                            "1:14:578:72:350000002000001483:::::::::::\n" \
                            "1:15:577:72:350000002000001483:::::::::::\n" \
                            "1:16:2457:72:350000002000001483:::::::::::\n" \
                            "1:17:2457:72:350000002000001483:::::::::::\n" \
                            "[identities:19]\n" \
                            "[::]/0:1:1:0:1:1\n" \
                            "[1::2:2:0]/112:2:1:0:1:2\n" \
                            "[1::2:3:0]/112:3:1:0:1:3\n" \
                            "[1::2:4:0]/112:4:1:0:1:4\n" \
                            "[1::2:5:0]/112:5:1:0:1:5\n" \
                            "[1::2:6:0]/112:6:1:0:1:6\n" \
                            "[1::2:6:0]/114:7:1:0:1:7\n" \
                            "[1::2:6:0]/116:8:1:0:1:8\n" \
                            "[1::2:6:0]/118:9:1:0:1:9\n" \
                            "[1::2:6:0]/120:10:1:0:1:10\n" \
                            "[1::2:7:0]/120:11:1:0:1:11\n" \
                            "[1::2:7:0]/118:12:1:0:1:12\n" \
                            "[1::2:7:0]/116:13:1:0:1:13\n" \
                            "[1::2:7:0]/114:14:1:0:1:14\n" \
                            "[1::2:7:0]/112:15:1:0:1:15\n" \
                            "[1:0:1::]/112:16:1:0:1:16\n" \
                            "[1:0:2::]/112:17:1:0:1:17\n" \
                            "2601:18c:c501:5d0::/64:17:1:0:1:17\n" \
                            "2601:18c:c501:5d1::/64:17:1:0:1:17\n"

        fn = create_data("test-netprefs", "netprefs %d\ncount 36\n" NETPREFS_IPV6_DATA, NETPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, LOADFLAGS_NETPREFS);
        ok(np, "Constructed struct netprefs from V%d data", NETPREFS_VERSION);
        skip_if(!np, 43, "Cannot test NULL np") {
            verify_walk_128(np->radixtree128, NETPREFS_IPV6_DATA);  /* plus 19+1 oks */
            is(PREFS_COUNT(np, identities), 19, "Data has a count of nineteen");
            is(np->conf.refcount, 1, "V%d data has a refcount of 1", NETPREFS_VERSION);

            struct {
                const char *addr;
                unsigned origin;
                const char *reason;
            } expect[] = {
                { "1::3:0:0", 0x1, "IP is matched by ::/0" },
                { "1::2:2:1", 0x2, "IP is matched by 1::2:2:0/112" },
                { "1::2:6:ffff", 0x6, "IP is matched by 1::2:6:0/112" },
                { "1::2:6:0", 0xa, "IP is matched by 1::2:6:0/120" },
                { "1::2:7:80", 0xb, "IP is matched by 1::2:7:0/120 (despite priorities)" },
                { "1::2:7:201", 0xc, "IP is matched by 1::2:7:0/118" },
                { "1:0:2::1", 0x11, "IP is matched by 1:0:2::/112" },
                { "1:0:3::1", 0x1, "IP is matched by ::/0" },
                { "2601:18c:c501:5d0:24e0:a113:844:ebbf", 0x11, "IP is matched by 2601:18c:c501:5d0::/64" },
                { "2601:18c:c501:5d0::1", 0x11, "IP is matched by 2601:18c:c501:5d0::/64" },
            };

            for (i = 0; i < sizeof expect / sizeof *expect; i++) {
                netaddr_from_str(&addr, expect[i].addr, AF_INET6);
                ok(netprefs_get(&pr, np, "netprefs", &addr, NULL, "a test IP") != -1, "Got prefs for item %d IP %s", i, expect[i].addr);
                skip_if(!PREF_VALID(&pr), 1, "Got nothing for IP %s, cannot verify origin %08x", expect[i].addr, expect[i].origin) {
                    is(PREF_IDENT(&pr)->originid, expect[i].origin, "Got the correct origin_id (%08x) for IP %s: %s", expect[i].origin, expect[i].addr, expect[i].reason);
                }
            }

            ok(netprefs_get_policy(np, &pr, AT_ORIGIN, 42, 17), "Found origin policy 17 with no index");
            netprefs_refcount_dec(np);
        }

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        np = netprefs_new(&cl, 0);
        unlink(fn);
        ok(np, "Constructed struct netprefs from V%d data with a policy index", NETPREFS_VERSION);
        ok(netprefs_get_policy(np, &pr, AT_ORIGIN, 42, 17), "Found origin policy 17 (even though there's no org 42)");
        is(np ? PREF_BUNDLE(&pr)->id : 0, 17, "The id is reported as 17");
        is(np ? PREF_BUNDLE(&pr)->priority : 0, 2457, "The priority is reported as 2457");
        ok(!netprefs_get_policy(np, &pr, AT_ORIGIN, 42, 18), "Cannot find origin policy 17 - doesn't exist");
        ok(!netprefs_org(np, 17), "Cannot find org 17 in netprefs... no index and no org");
        ok(netprefs_get_prefblock(np, 17), "Got prefblock from netprefs (org is ignored)");
        netprefs_refcount_dec(np);
    }

    OK_SXEL_ERROR(NULL);
    test_uncapture_sxel();

    kit_free(walk32data);
    kit_free(walk128data);
    conf_loader_fini(&cl);
    fileprefs_freehashes();
    confset_unload();          // Finalize the conf subsystem
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
