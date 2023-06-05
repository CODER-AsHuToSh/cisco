#include <fcntl.h>
#include <kit-alloc.h>
#include <kit-random.h>
#include <mockfail.h>
#include <tap.h>

#include "ccb.h"
#include "conf-loader.h"
#include "pref.h"

#include "common-test.h"

struct ccb_config {
    const char *name;
    int bit;
    const char *handling;
    unsigned masked : 1;
};

static int
cmp_ccb_config(const void *a, const void *b)
{
    return ((const struct ccb_config *)a)->bit - ((const struct ccb_config *)b)->bit;
}

#define SANE          0x00
#define SANE_NOSORT   0x01
#define SANE_ALLOWDUP 0x02

static struct ccb_config *
sane_ccb_data(unsigned *nconfig, const struct ccb_config *config, unsigned flags)
{
    static struct ccb_config data[100];
    unsigned n, total;

    static struct ccb_config required_data[] = {
        { "botnet", 64, "botnet", 0 },
        { "botnet2", 65, "botnet", 0 },
        { "malware", 66, "malware", 0 },
        { "malware2", 67, "malware", 0 },
        { "phish", 68, "phish", 0 },
        { "suspicious", 69, "suspicious", 0 },
        { "blocked", 71, "blocked", 0 },
        { "whitelisted", 72, "whitelisted", 0 },
        { "global whitelist", 73, "normal", 0 },
        { "sinkhole", 74, "sinkhole", 0 },
        { "application block", 151, "application", 0 },
        { "application allow", 152, "whitelisted", 0 },
    };

#define REQUIRED_COUNT (sizeof(required_data) / sizeof(*required_data))

    total = REQUIRED_COUNT + *nconfig;
    SXEA1(total <= sizeof(data) / sizeof(*data), "Too many config entries - got %u, max %zu", *nconfig, sizeof(data) / sizeof(*data) - REQUIRED_COUNT);

    memcpy(data, required_data, sizeof(required_data));
    memcpy(data + REQUIRED_COUNT, config, *nconfig * sizeof(*config));
    if (!(flags & SANE_NOSORT))
        qsort(data, total, sizeof(*data), cmp_ccb_config);

    if (!(flags & SANE_ALLOWDUP))
        /* Remove dups */
        for (n = 1; n < total; n++)
            if (data[n].bit == data[n - 1].bit) {
                memmove(data + n - 1, data + n, (total - n - 1) * sizeof(*data));
                n--;
                total--;
            }

    *nconfig = total;
    return data;
}

static struct ccb_config *
default_ccb_array(unsigned *count)
{
    *count = 0;
    return sane_ccb_data(count, NULL, SANE);
}

static const char *
ccb2txt(unsigned count, const struct ccb_config *data)
{
    static char content[4096];
    unsigned i, pos;
    int n;

    pos = 0;
    for (i = 0; i < count; i++, pos += n) {
        n = snprintf(content + pos, sizeof(content) - pos, "%s:%d:%s:%u\n", data[i].name, data[i].bit, data[i].handling, data[i].masked);
        SXEA1(pos + n < sizeof(content), "content buffer overflow");
    }

    return content;
}

static const char *
create_ccb_data(const char *name, unsigned count, const struct ccb_config *indata, unsigned flags)
{
    struct ccb_config *data;

    data = sane_ccb_data(&count, indata, flags);

    return create_data(name, "ccb %d\ncount %u\n%s", CCB_VERSION, count, ccb2txt(count, data));
}

int
main(void)
{
    uint64_t start_allocations;
    struct ccb_config *data;
    struct ccb *ccb = NULL;
    struct conf_loader cl;
    pref_categories_t cat;
    const char *fn;
    unsigned count;

    plan_tests(ccb_handling_entries + 68);

    kit_random_init(open("/dev/urandom", O_RDONLY));
    conf_initialize(NULL, ".", false, NULL);

    kit_memory_initialize(false);
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    conf_loader_init(&cl);

    pref_categories_setall(&cat);
    ccb_masked(NULL, &cat);
    ok(pref_categories_isnone(&cat), "ccb_masked() handles a NULL ccb - even though there's always a default ccb");
    pref_categories_setbit(&cat, 85);
    ccb_pref_categories_str(NULL, NULL);
    MOCKFAIL_START_TESTS(1, CCB_PREF_CATEGORIES_STR);
    is_eq(ccb_pref_categories_str(NULL, &cat), "<pref-categories-allocation-error>", "ccb_pref_categories cannot display itself when ccb_pref_categories_str() fails to allocate");
    MOCKFAIL_END_TESTS();
    is_eq(ccb_pref_categories_str(NULL, &cat), "bit85", "pref_categories displays bit 85 correctly");
    ccb_pref_categories_str(NULL, NULL);    // Toss the internally allocated buffer

    diag("Test loading an empty CCB file");
    {
        fn = create_data("test-ccb", "\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load an empty CCB file");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with bad version character");
    {
        data = default_ccb_array(&count);
        fn = create_data("test-ccb", "ccb X\ncount %u\n%s", count, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with bad version");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with an invalid version");
    {
        data = default_ccb_array(&count);
        fn = create_data("test-ccb", "ccb %d\ncount %u\n%s", CCB_VERSION - 1, count, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with invalid version");
        ccb_refcount_dec(ccb);
        unlink(fn);

        fn = create_data("test-ccb", "ccb %d\ncount %u\n%s", CCB_VERSION + 1, count, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with invalid version");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with bad count character");
    {
        data = default_ccb_array(&count);
        fn = create_data("test-ccb", "ccb %d\ncount X\n%s", CCB_VERSION, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with bad count character");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with incorrect low count");
    {
        count = 1;
        data = sane_ccb_data(&count, &(const struct ccb_config){"Alcohol", 1, "domaintagging", 0}, SANE);
        fn = create_data("test-ccb", "ccb %d\ncount %u\n%s", CCB_VERSION, count - 1, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with incorrect low count");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with incorrect high count");
    {
        data = default_ccb_array(&count);
        fn = create_data("test-ccb", "ccb %d\ncount %u\n%s", CCB_VERSION, count + 1, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with incorrect high count");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with bad category bit");
    {
        data = default_ccb_array(&count);
        fn = create_data("test-ccb", "ccb %d\ncount %u\nAdware:X:domaintagging:0\n%s", CCB_VERSION, count + 1, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with bad category bit");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with high category bit");
    {
        fn = create_ccb_data("test-ccb", 1, &(const struct ccb_config){"Alcohol", PREF_CATEGORIES_MAX_BITS, "domaintagging", 0}, SANE);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with high category bit");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with negative category bit");
    {
        fn = create_ccb_data("test-ccb", 1, &(const struct ccb_config){"Alcohol", -1, "domaintagging", 0}, SANE);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with high category bit");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with duplicate category bit");
    {
        fn = create_ccb_data("test-ccb", 2, (const struct ccb_config []){
                                                (const struct ccb_config){"Adware", 0, "domaintagging", 0},
                                                (const struct ccb_config){"Alcohol", 0, "domaintagging", 0}
                                            }, SANE_ALLOWDUP);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with duplicate category bit");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with unsorted category bit");
    {
        fn = create_ccb_data("test-ccb", 2, (const struct ccb_config []){
                                                (const struct ccb_config){"Adware", 1, "domaintagging", 0},
                                                (const struct ccb_config){"Alcohol", 0, "domaintagging", 0}
                                            }, SANE_NOSORT);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with unsorted category bit");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with bad handling");
    {
        fn = create_ccb_data("test-ccb", 2, (const struct ccb_config []){
                                                (const struct ccb_config){"Adware", 0, "domaintaggingX", 0},
                                                (const struct ccb_config){"Alcohol", 1, "domaintagging", 0}
                                            }, SANE);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with bad handling");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with space before handling");
    {
        fn = create_ccb_data("test-ccb", 2, (const struct ccb_config []){
                                                (const struct ccb_config){"Adware", 0, " domaintagging", 0},
                                                (const struct ccb_config){"Alcohol", 1, "domaintagging", 0}
                                            }, SANE);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load a CCB file with space before handling");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with trailing garbage");
    {
        const char *txt;

        count = 2;
        data = sane_ccb_data(&count, (const struct ccb_config []){
                                         (const struct ccb_config){"Adware", 0, "domaintagging", 0},
                                         (const struct ccb_config){"Alcohol", 1, "domaintagging", 0}
                                     }, SANE);
        txt = ccb2txt(count, data);
        fn = create_data("test-ccb", "ccb %d\ncount %u\n%.*s   # Adware is domaintagging\n", CCB_VERSION, count, (int)strlen(txt) - 1, txt);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Can't load a CCB file with a trailing comment");
        unlink(fn);
    }

    diag("Test loading a CCB file with a key that has no bit, handling or masked");
    {
        data = default_ccb_array(&count);
        fn = create_data("test-ccb", "ccb %d\ncount %u\nAdware\n%s", CCB_VERSION, count + 1, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with a key that has no bit or handling");
        ccb_refcount_dec(ccb);
        unlink(fn);

        fn = create_data("test-ccb", "ccb %d\ncount %u\n%sAlcohol", CCB_VERSION, count + 1, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with a key that ends the file");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with a missing key");
    {
        data = default_ccb_array(&count);
        fn = create_data("test-ccb", "ccb %d\ncount %u\n:0:domaintagging:0\n%s", CCB_VERSION, count + 1, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with a missing key");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with missing handling");
    {
        fn = create_ccb_data("test-ccb", 1, &(const struct ccb_config){"Attack", 75, "", 0}, SANE);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(ccb, "Loaded a CCB file with a missing handling");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with empty category line");
    {
        data = default_ccb_array(&count);
        fn = create_data("test-ccb", "ccb %d\ncount %u\n       \n%s", CCB_VERSION, count + 1, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with empty category line");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with a missing masked separator");
    {
        data = default_ccb_array(&count);
        fn = create_data("test-ccb", "ccb %d\ncount %u\nAlcohol:1:domaintagging\n%s", CCB_VERSION, count + 1, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with a missing masked separator");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with a missing masked field");
    {
        data = default_ccb_array(&count);
        fn = create_data("test-ccb", "ccb %d\ncount %u\nAlcohol:1:domaintagging:\n%s", CCB_VERSION, count + 1, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with a missing masked field");
        ccb_refcount_dec(ccb);
        unlink(fn);

        fn = create_data("test-ccb", "ccb %d\ncount %u\n%sAlcohol:1:domaintagging:", CCB_VERSION, count + 1, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with a missing masked field at the end of the file");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test loading a CCB file with an invalid masked field");
    {
        data = default_ccb_array(&count);
        fn = create_data("test-ccb", "ccb %d\ncount %u\nAlcohol:1:domaintagging:2\n%s", CCB_VERSION, count + 1, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Failed to load CCB file with an invalid masked field");
        ccb_refcount_dec(ccb);
        unlink(fn);
    }

    diag("Test the default CCB handling categories");
    {
        const struct ccb *const_ccb = ccb_conf_get(NULL, 0);
        pref_categories_t all, expect, found;
        unsigned hpos;

        pref_categories_setall(&all);
        ok(const_ccb, "Default CCB has been loaded");
        for (hpos = 0; hpos < ccb_handling_entries; hpos++) {
            ccb_handling_pos_intersects(const_ccb, &found, hpos, &all);
            pref_categories_setnone(&expect);

            switch (ccb_pos2handling(hpos)) {
            case QUERY_HANDLING_DOMAINTAGGING:
                pref_categories_setall(&expect);
                pref_categories_unsetbit(&expect, CATEGORY_BIT_ALLOWLIST);
                pref_categories_unsetbit(&expect, CATEGORY_BIT_BLOCKLIST);
                pref_categories_unsetbit(&expect, CATEGORY_BIT_BOTNET);
                pref_categories_unsetbit(&expect, CATEGORY_BIT_BOTNET2);
                pref_categories_unsetbit(&expect, CATEGORY_BIT_MALWARE);
                pref_categories_unsetbit(&expect, CATEGORY_BIT_MALWARE2);
                pref_categories_unsetbit(&expect, CATEGORY_BIT_PHISH);
                pref_categories_unsetbit(&expect, CATEGORY_BIT_SINKHOLE);
                pref_categories_unsetbit(&expect, CATEGORY_BIT_SUSPICIOUS);
                pref_categories_unsetbit(&expect, CATEGORY_BIT_GLOBAL_ALLOWLIST);
                pref_categories_unsetbit(&expect, CATEGORY_BIT_ALLOWAPP);
                pref_categories_unsetbit(&expect, CATEGORY_BIT_BLOCKAPP);
                ok(pref_categories_equal(&found, &expect), "Default domaintagging handling is correct (got %s)", pref_categories_idstr(&found));
                break;
            case QUERY_HANDLING_ALLOWLISTED:
                pref_categories_setbit(&expect, CATEGORY_BIT_ALLOWLIST);
                pref_categories_setbit(&expect, CATEGORY_BIT_ALLOWAPP);
                ok(pref_categories_equal(&found, &expect), "Default whitelist handling is correct (got %s)", pref_categories_idstr(&found));
                break;
            case QUERY_HANDLING_BLOCKED:
                pref_categories_setbit(&expect, CATEGORY_BIT_BLOCKLIST);
                ok(pref_categories_equal(&found, &expect), "Default blocked handling is correct (got %s)", pref_categories_idstr(&found));
                break;
            case QUERY_HANDLING_BOTNET:
                pref_categories_setbit(&expect, CATEGORY_BIT_BOTNET);
                pref_categories_setbit(&expect, CATEGORY_BIT_BOTNET2);
                ok(pref_categories_equal(&found, &expect), "Default botnet handling is correct (got %s)", pref_categories_idstr(&found));
                break;
            case QUERY_HANDLING_MALWARE:
                pref_categories_setbit(&expect, CATEGORY_BIT_MALWARE);
                pref_categories_setbit(&expect, CATEGORY_BIT_MALWARE2);
                ok(pref_categories_equal(&found, &expect), "Default malware handling is correct (got %s)", pref_categories_idstr(&found));
                break;
            case QUERY_HANDLING_PHISH:
                pref_categories_setbit(&expect, CATEGORY_BIT_PHISH);
                ok(pref_categories_equal(&found, &expect), "Default phish handling is correct (got %s)", pref_categories_idstr(&found));
                break;
            case QUERY_HANDLING_SINKHOLE:
                pref_categories_setbit(&expect, CATEGORY_BIT_SINKHOLE);
                ok(pref_categories_equal(&found, &expect), "Default sinkhole handling is correct (got %s)", pref_categories_idstr(&found));
                break;
            case QUERY_HANDLING_SUSPICIOUS:
                pref_categories_setbit(&expect, CATEGORY_BIT_SUSPICIOUS);
                ok(pref_categories_equal(&found, &expect), "Default suspicious handling is correct (got %s)", pref_categories_idstr(&found));
                break;
            case QUERY_HANDLING_APPLICATION:
                pref_categories_setbit(&expect, CATEGORY_BIT_BLOCKAPP);
                ok(pref_categories_equal(&found, &expect), "Default application handling is correct (got %s)", pref_categories_idstr(&found));
                break;
            case QUERY_HANDLING_NORMAL:
                pref_categories_setbit(&expect, CATEGORY_BIT_GLOBAL_ALLOWLIST);
                ok(pref_categories_equal(&found, &expect), "Default normal handling is correct (got %s)", pref_categories_idstr(&found));
                break;
            default:
                ok(pref_categories_isnone(&found), "Default ccb for handling %d is empty (got %s)", ccb_pos2handling(hpos), pref_categories_idstr(&found));
                break;
            }
        }

        is(ccb_version(const_ccb), CCB_VERSION, "The version of CCB must be %d", CCB_VERSION);
        is(ccb_conf(const_ccb)->refcount, 0, "The refcount of the default CCB is 0");
    }

    diag("Test loading a good ccb file without required settings");
    {
        fn = create_data("test-ccb", "ccb %d\ncount 1\nAlcohol:1:domaintagging:0", CCB_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(!ccb, "Can't load a CCB file without required defaults");
        unlink(fn);
    }

    diag("Test loading a good ccb file with required settings");
    {
        unsigned i, nmasked;

        count = 2;
        data = sane_ccb_data(&count, (const struct ccb_config []){
                                         (const struct ccb_config){"Alcohol", 1, "domaintagging", 0},
                                         (const struct ccb_config){"Internet Watch Foundation", 85, "domaintagging", 0}
                                     }, SANE);
        fn = create_data("test-ccb", "ccb %d\ncount %u\n  %s", CCB_VERSION, count, ccb2txt(count, data));
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(ccb, "Loaded a CCB file with %u lines", count);

        skip_if(!ccb, 9, "Cannot test the ccb object") {
            is_eq(ccb_allowlisted_txt(ccb), "whitelisted", "By default, the allowlisted text is 'whitelisted'");
            ccb_masked(ccb, &cat);
            is_eq(pref_categories_idstr(&cat), "0", "By default, no categories are masked");
            pref_categories_setbit(&cat, 85);
            is_eq(ccb_pref_categories_str(ccb, &cat), "Internet Watch Foundation",
                  "ccb_pref_categories_str converts bit 85 correctly");
            is(ccb_conf(ccb)->refcount, 1,     "The refcount of the CCB is 1");
            ccb_refcount_inc(ccb);
            is(ccb_conf(ccb)->refcount, 2, "The refcount of the CCB can be incremented");
            ccb_refcount_dec(ccb);
            is(ccb_conf(ccb)->refcount, 1, "The refcount of the CCB can be decremented");
            is_eq(ccb_label(ccb, 85) ?: "<NULL>", "Internet Watch Foundation", "The IWF bit has the correct label");
            is(ccb_ismasked(ccb, 85), 0, "The IWF bit is not masked");
            for (i = nmasked = 0; i < 128; i++)
                if (ccb_ismasked(ccb, i))
                    nmasked++;
            is(nmasked, 0, "None of the other bits are masked either");

            ccb_refcount_dec(ccb);
        }
        unlink(fn);

        count = 2;
        data = sane_ccb_data(&count, (const struct ccb_config []){
                                         (const struct ccb_config){"Alcohol", 1, "domaintagging", 0},
                                         (const struct ccb_config){"Internet Watch Foundation", 85, "domaintagging", 1}
                                     }, SANE);
        fn = create_data("test-ccb", "ccb %d\ncount %u\n  %s", CCB_VERSION, count, ccb2txt(count, data));

        MOCKFAIL_START_TESTS(1, CCB_CREATE);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!ccb_new(&cl), "Cannot load a ccb file when ccb_create() fails");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(1, CCB_CREATE_BITMAP);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!ccb_new(&cl), "Cannot load a ccb file when ccb_create() fails to allocate a bitmap");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(1, CCB_PARSE_CATEGORY);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!ccb_new(&cl), "Cannot load a ccb file when ccb_parse_category() fails");
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ccb = ccb_new(&cl);
        ok(ccb, "Loaded a CCB file with %u lines", count);
        skip_if(!ccb, 6, "Cannot test the ccb object") {
            is(ccb_conf(ccb)->refcount, 1, "The refcount of the CCB is 1");
            ccb_refcount_inc(ccb);
            is(ccb_conf(ccb)->refcount, 2, "The refcount of the CCB can be incremented");
            ccb_refcount_dec(ccb);
            is(ccb_conf(ccb)->refcount, 1, "The refcount of the CCB can be decremented");
            is_eq(ccb_label(ccb, 85), "Internet Watch Foundation", "The IWF bit has the correct label");
            is(ccb_ismasked(ccb, 85), 1, "The IWF bit is masked");
            for (i = nmasked = 0; i < 128; i++)
                if (ccb_ismasked(ccb, i))
                    nmasked++;
            is(nmasked, 1, "The IWF bit is the only masked bit");
            ccb_refcount_dec(ccb);
        }
        unlink(fn);
    }

    diag("Test registering, de-registering and tidying up");
    {
        const struct ccb *cccb;
        struct confset *set;
        module_conf_t reg;

        count = 2;
        data = sane_ccb_data(&count, (const struct ccb_config []){
                                         (const struct ccb_config){"Alcohol", 1, "domaintagging", 0},
                                         (const struct ccb_config){"Internet Watch Foundation", 85, "domaintagging", 1}
                                     }, SANE);
        create_atomic_file("test-ccb", "ccb %d\ncount %u\n  %s", CCB_VERSION, count, ccb2txt(count, data));
        reg = 0;
        ccb_register(&reg, "ccb", "test-ccb", true);
        ok(reg, "Registered test-ccb as 'ccb'");
        ok(confset_load(NULL), "Noted an update to test-ccb");
        ok(set = confset_acquire(NULL), "Acquired the conf set");
        skip_if(!set, 3, "Cannot look at ccb with no set") {
            ok(cccb = ccb_conf_get(set, reg), "Acquired the ccb");
            is_eq(ccb_label(cccb, 85) ?: "<NULL>", "Internet Watch Foundation", "The IWF bit has the correct label");
            is_eq(ccb_label(cccb, 66) ?: "<NULL>", "malware", "The 'malware' bit has the correct label");
            confset_release(set);
        }

        ok(cccb = ccb_conf_get(NULL, 12345), "Acquired the default ccb");
        ok(ccb_label(cccb, 66) == NULL, "The 'malware' label is NULL, but that's expected");

        conf_unregister(reg);
        confset_unload();
        ccb_deinitialize();    /* Necessary to clean up the default ccb */
        unlink("test-ccb");
    }

    diag("test query_handling_ccb_str()");
    {
        is_eq(ccb_handling_str(CCB_HANDLING_PROXY_ALLOWAPP), "application", "ccb query handling sets allowapp to application");
        is_eq(ccb_handling_str(CCB_HANDLING_PROXY_BLOCKAPP), "application", "ccb query handling sets blockapp to application");
        is_eq(ccb_handling_str(CCB_HANDLING_PROXY_NSD), "nsd", "ccb query handling sets nsd");
        is_eq(ccb_handling_str(CCB_HANDLING_PROXY_URL_PROXY), "http-greylist", "ccb query handling sets http-greylist");
        is_eq(ccb_handling_str(CCB_HANDLING_PROXY_URL_PROXY_HTTPS), "https-greylist", "ccb query handling sets https-greylist");
        is_eq(ccb_handling_str(CCB_HANDLING_PROXY_ORG_BLOCK_GREYLIST), "org-https-greylist", "ccb query handling sets org-https-greylist");
        is_eq(ccb_handling_str(CCB_HANDLING_PROXY_ORG_BLOCK_GREYLIST + 1), "unknown", "ccb query handling return unknown for out of bounds");
    }

    ccb_pref_categories_str(NULL, NULL);    // Finalize the per thread allocated buffer
    conf_loader_fini(&cl);
    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
