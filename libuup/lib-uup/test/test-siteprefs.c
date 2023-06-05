#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <kit-alloc.h>
#include <mockfail.h>

#include "odns.h"
#include "oolist.h"
#include "siteprefs-private.h"
#include "uint32list.h"
#include "xray.h"

#include "common-test.h"

#define LOADFLAGS_SITEPREFS \
            (LOADFLAGS_FP_ALLOW_OTHER_TYPES| LOADFLAGS_FP_ELEMENTTYPE_DOMAIN | LOADFLAGS_FP_ELEMENTTYPE_APPLICATION)

int
main(void)
{
    uint64_t start_allocations;
    const struct preforg *corg;
    struct conf_info *info;
    const struct conf_type *siteprefs_conf_type = NULL;    // Force initialization to shut up gcc in release build
    struct conf_loader cl;
    struct siteprefs *sp;
    struct oolist *ids;
    struct odns odns;
    const char *fn;
    char buf[4096];
    unsigned i;
    pref_t pr;

    plan_tests(216);

    conf_initialize(".", ".", false, NULL);
    kit_memory_initialize(false);
    // KIT_ALLOC_SET_LOG(1);    // Turn off when done
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */

    conf_loader_init(&cl);
    ids = oolist_new();

    diag("Test integration with the conf subsystem");
    {
        siteprefs_register(&CONF_SITEPREFS, "siteprefs", "siteprefs", true);
        ok(!siteprefs_conf_get(NULL, CONF_SITEPREFS), "Failed to get siteprefs from a NULL confset");
        conf_unregister(CONF_SITEPREFS);
    }

    diag("Test missing file load");
    {
        info = conf_info_new(NULL, "noname", "nopath", NULL, LOADFLAGS_NONE, NULL, 0);
        info->updates++;

        conf_loader_open(&cl, "/tmp/not-really-there", NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read non-existent file");
        OK_SXEL_ERROR("not-really-there could not be opened: No such file or directory");
        OK_SXEL_ERROR(NULL);

        conf_loader_done(&cl, info);
        is(info->updates, 1, "conf_loader_done() didn't bump 'updates'");
        is(info->st.dev, 0, "Loading a non-existent file gives a clear stat");
        for (i = 0; i < sizeof(info->digest); i++)
            if (info->digest[i])
                break;
        is(i, sizeof(info->digest), "The digest of an empty file has %zu zeros", sizeof(info->digest));
        conf_info_free(info);
    }

    diag("Test garbage file");
    {
        fn = create_data("test-siteprefs", "This is not the correct format\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        unlink(fn);
        ok(!sp, "Failed to read garbage file");
        OK_SXEL_ERROR(": 1: Invalid header; must contain 'siteprefs'");
    }

    diag("Test V%u data load", SITEPREFS_VERSION - 1);
    {
        fn = create_data("test-siteprefs", "siteprefs %u\ncount 0\n", SITEPREFS_VERSION - 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        unlink(fn);
        ok(!sp, "Failed to read version %u data", SITEPREFS_VERSION - 1);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [");
    }

    diag("Test V%u data load", SITEPREFS_VERSION + 1);
    {
        fn = create_data("test-siteprefs", "siteprefs %u\ncount 0\n", SITEPREFS_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        unlink(fn);
        ok(!sp, "Failed to read version %u data", SITEPREFS_VERSION + 1);
        OK_SXEL_ERROR(": 1: Invalid version(s); must be from the set [");
    }

    diag("Test V%u empty data load", SITEPREFS_VERSION);
    {
        fn = create_data("test-siteprefs", "siteprefs %u\ncount 0\n%s", SITEPREFS_VERSION,
                         "[bundles:0]\n[orgs:0]\n[identities:0]\n");

        MOCKFAIL_START_TESTS(2, fileprefs_new);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "siteprefs_new() of empty V%u data fails when fileprefs_new() fails", SITEPREFS_VERSION);
        OK_SXEL_ERROR("Cannot allocate");
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        conf_loader_done(&cl, NULL);
        unlink(fn);
        ok(sp, "Constructed siteprefs from empty V%u data", SITEPREFS_VERSION);

        skip_if(!sp, 4, "Cannot run these tests without siteprefs") {
            siteprefs_conf_type = sp->conf.type;    // Tricky: extract the type pointer for later use.
            is(PREFS_COUNT(sp, identities), 0, "V%u data has a count of zero", SITEPREFS_VERSION);
            is(sp->conf.refcount, 1, "V%u data has a refcount of 1", SITEPREFS_VERSION);
            siteprefs_refcount_inc(sp);
            is(sp->conf.refcount, 2, "V%u data can bump its refcount", SITEPREFS_VERSION);
            siteprefs_refcount_dec(sp);
            is(sp->conf.refcount, 1, "V%u data can drop its refcount", SITEPREFS_VERSION);
            siteprefs_refcount_dec(sp);
        }
    }

    diag("Test V%u data load with extra lines", SITEPREFS_VERSION);
    {
        fn = create_data("test-siteprefs", "siteprefs %u\ncount 0\n%sextra-garbage\n", SITEPREFS_VERSION,
                 "[lists:0]\n[bundles:0]\n[orgs:0]\n[identities:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        unlink(fn);
        ok(!sp, "Failed to read version %u data with extra garbage", SITEPREFS_VERSION);
        OK_SXEL_ERROR(": 7: Unexpected [identities] line - wanted only 0 items");
    }

    diag("Test V%u data load with inconsistent headers", SITEPREFS_VERSION);
    {
        const char *good[] = {
            "[lists:0]\n",
            "[settinggroup:0]\n",
            "[bundles:0]\n",
            "[orgs:0]\n",
            "[identities:0]\n",
            "[lists:0]\n[bundles:0]\n",
            "[lists:0]\n[bundles:0]\n[orgs:0]\n",
            "[lists:0]\n[bundles:0]\n[orgs:0]\n[identities:0]\n",
            "[lists:0]\n[settinggroup:0]\n[bundles:0]\n[orgs:0]\n[identities:0]\n",
            "[settinggroup:0]\n[bundles:0]\n[orgs:0]\n[identities:0]\n",
        };
        const char *bad[] = {
            "[lists]\n[bundles]\n[orgs]\n[identities]\n",
        };

        for (i = 0; i < sizeof(good) / sizeof(*good); i++) {
            fn = create_data("test-siteprefs", "siteprefs %u\ncount 0\n%s", SITEPREFS_VERSION, good[i]);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
            unlink(fn);
            ok(sp, "Read empty version %u data with valid headers", SITEPREFS_VERSION);
            siteprefs_refcount_dec(sp);
        }

        for (i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
            fn = create_data("test-siteprefs", "siteprefs %u\ncount 0\n%s", SITEPREFS_VERSION, bad[i]);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
            unlink(fn);
            ok(!sp, "Failed to read empty version %u data with invalid headers", SITEPREFS_VERSION);
            OK_SXEL_ERROR(": 3: Expected section header");
        }
    }

    diag("Test V%u data load with invalid assetid (and a bit of rogue padding)", SITEPREFS_VERSION);
    {
        struct conf_info conf_info;
        struct conf     *conf;

        const char *data = "[lists:7]\n"
                           "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                           "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                           "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                           "008:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                           "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                           "0C:5:something::886700e4c2276be2081d435212652438f02b5c9c:some undefined data of type 'something'\n"
                           "40:5:something-else::886700e4c2276be2081d435212652438f02b5c9d:some undefined data of type 'something-else' with a dodgy ltype\n"
                           "[bundles:1]\n"
                           "0:1:1:60:1F0000000000000000::1 4:2:3:5::::::\n"
                           "[orgs:1]\n"
                           "2748:0:0:365:0:1002748:0\n"
                           "[identities:1]\n";
        const char *badident = "1:1x::1.2.3.4/32:2:21:2748:0:1\n";
        const char *goodident = "1:1::1.2.3.4/32:2:21:2748:0:1\n";

        /* Verify a valid load, testing the internal allocate function while we're at it.
         */
        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s", SITEPREFS_VERSION, data, goodident);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        conf_info.loadflags = LOADFLAGS_SITEPREFS;
        conf_info.type      = siteprefs_conf_type;    // Saved above on first valid load
        conf                = conf_info.type->allocate(&conf_info, &cl);
        ok(conf, "Read version %u data with a valid assetid", SITEPREFS_VERSION);
        sp = (struct siteprefs *)((char *)conf - offsetof(struct siteprefs, conf));
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s", SITEPREFS_VERSION, data, badident);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        unlink(fn);
        ok(!sp, "Failed to read version %u data with an invalid assetid", SITEPREFS_VERSION);
        OK_SXEL_ERROR(": 16: Unrecognised line (invalid assetid or orgid)");
    }

    diag("Test V%u data load with invalid CIDR", SITEPREFS_VERSION);
    {
        const char *precidr = "[lists:5]\n"
                              "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                              "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                              "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                              "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                              "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                              "[bundles:1]\n"
                              "0:1:1:60:1F0000000000000000::1 4:2:3:5::::::\n"
                              "[orgs:1]\n"
                              "2748:0:0:365:0:1002748:0\n"
                              "[identities:1]\n";
        const char *idtype1 = "1:1::";
        const char *idtype2 = "2:2748:21:";
        const char *postcidr = ":2:21:2748:0:1\n";
        const char *goodcidr = "1.2.3.4/32";
        const char *badcidr = "1.2.3.4";

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 8\n%s%s%s%s", SITEPREFS_VERSION, precidr, idtype1, goodcidr, postcidr);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Read version %u data with a valid CIDR", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 8\n%s%s%s%s", SITEPREFS_VERSION, precidr, idtype1, badcidr, postcidr);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with an invalid CIDR", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 14: Unrecognised line (invalid CIDR)");

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 8\n%s%s%s%s", SITEPREFS_VERSION, precidr, idtype2, goodcidr, postcidr);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Read version %u data with a valid CIDR", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 8\n%s%s%s%s", SITEPREFS_VERSION, precidr, idtype2, badcidr, postcidr);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with an invalid CIDR", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 14: Unrecognised line (invalid CIDR)");
    }

    diag("Test V%u data load with invalid pref flags", SITEPREFS_VERSION);
    {
        const char *preflag = "[lists:5]\n"
                              "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                              "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                              "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                              "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                              "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                              "[bundles:1]\n"
                              "0:1:1:";
        const char *postflag = ":0::1 4:2:3:5::::::\n"
                               "[orgs:1]\n"
                               "2748:0:0:365:0:1002738:0\n"
                               "[identities:1]\n"
                               "1:1::1.2.3.4/32:2:21:2748:0:1\n";
        const char *goodflag = "60";
        const char *badflag = "60x";

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 8\n%s%s%s", SITEPREFS_VERSION, preflag, goodflag, postflag);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Read version %u data with valid pref flags", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 8\n%s%s%s", SITEPREFS_VERSION, preflag, badflag, postflag);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with invalid pref flags", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 10: Unrecognised bundle line (invalid actype:bundleid:priority:flags:)");
    }

    diag("Test V%u data load with wrong sort order for siteprefs key type %u", SITEPREFS_VERSION, SITEPREFS_KEY_TYPE1);
    {
        const char *preident = "[lists:5]\n"
                               "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                               "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                               "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                               "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                               "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                               "[bundles:1]\n"
                               "0:1:4294967295:60:3F0000780000000000::1 4:2:3:5::::::\n"
                               "[orgs:1]\n"
                               "2748:0:0:365:0:1002748:0\n"
                               "[identities:2]\n";
        const char *v4first = "1:14698509::1.2.3.4/32:14698509:21:2748:0:1\n";
        const char *v4second = "1:14698509::1.2.3.5/32:14698509:21:2748:0:1\n";
        const char *v6first = "1:14698509::202:2::2/128:14698509:21:2748:0:1\n";
        const char *v6second = "1:14698509::300::/8:14698509:21:2748:0:1\n";

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 9\n%s%s%s", SITEPREFS_VERSION, preident, v4first, v4second);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Read version %u data with valid v4 sort order", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 9\n%s%s%s", SITEPREFS_VERSION, preident, v4second, v4first);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with invalid v4 sort order", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 15: Invalid line (out of order)");

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 9\n%s%s%s", SITEPREFS_VERSION, preident, v6first, v4first);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Read version %u data with valid v6/v4 sort order", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 9\n%s%s%s", SITEPREFS_VERSION, preident, v4first, v6first);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with invalid v4/v6 sort order", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 15: Invalid line (out of order - v6 CIDRs must preceed v4 CIDRs)");

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 9\n%s%s%s", SITEPREFS_VERSION, preident, v6first, v6second);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Read version %u data with valid v6 sort order", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 9\n%s%s%s", SITEPREFS_VERSION, preident, v6second, v6first);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with invalid v6 sort order", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 15: Invalid line (out of order)");
    }

    diag("Test V%u data load with wrong sort order for siteprefs key type %u", SITEPREFS_VERSION, SITEPREFS_KEY_TYPE2);
    {
        const char *preident = "[lists:5]\n"
                               "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                               "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                               "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                               "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                               "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                               "[bundles:1]\n"
                               "0:1:4294967295:60:3F0000780000000000::1 4:2:3:5::::::\n"
                               "[orgs:2]\n"
                               "2750:0:0:365:0:1002748:0\n"
                               "2751:0:0:365:0:1002748:0\n"
                               "[identities:2]\n";
        const char *v4first = "2:2750:40:1.2.3.4/32:14698509:21:2750:0:1\n";
        const char *v4second = "2:2750:40:1.2.3.5/32:14698509:21:2750:0:1\n";
        const char *v6first = "2:2750:40:202:2::2/128:14698509:21:2750:0:1\n";
        const char *v6second = "2:2750:40:300::/8:14698509:21:2750:0:1\n";
        const char *type1 = "1:14698509::1.2.3.4/32:14698509:21:2750:0:1\n"; /* Same as v4first but a TYPE1 key */
        const char *orgidsecond = "2:2751:40:1.2.3.4/32:14698509:21:2750:0:1\n"; /* Same as v4first but with orgid key field = 2751 */
        const char *invalid_orgid = "2:ABC:40:1.2.3.4/32:14698509:21:2750:0:1\n";
        const char *invalid_asset_type = "2:2751:ABC:1.2.3.4/32:14698509:21:2750:0:1\n";

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s", SITEPREFS_VERSION, preident, v4first, v4second);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Read version %u data with valid v4 sort order", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s", SITEPREFS_VERSION, preident, v4second, v4first);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with invalid v4 sort order", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 16: Invalid line (out of order)");

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s", SITEPREFS_VERSION, preident, v6first, v4first);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Read version %u data with valid v6/v4 sort order", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s", SITEPREFS_VERSION, preident, v4first, v6first);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with invalid v4/v6 sort order", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 16: Invalid line (out of order - v6 CIDRs must preceed v4 CIDRs)");

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s", SITEPREFS_VERSION, preident, v6first, v6second);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Read version %u data with valid v6 sort order", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s", SITEPREFS_VERSION, preident, v6second, v6first);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with invalid v6 sort order", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 16: Invalid line (out of order)");

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s", SITEPREFS_VERSION, preident, type1, v4first);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Read version %u data with valid key type sort order", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s", SITEPREFS_VERSION, preident, v4first, type1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with invalid key type sort order", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 16: Invalid line (out of order)");

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s", SITEPREFS_VERSION, preident, v4first, orgidsecond);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Read version %u data with valid origid sort order", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s", SITEPREFS_VERSION, preident, orgidsecond, v4first);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with invalid orgid sort order", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 16: Invalid line (out of order)");

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s", SITEPREFS_VERSION, preident, v4first, invalid_orgid);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with invalid orgid", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 16: Unrecognised line (invalid assetid or orgid)");

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s", SITEPREFS_VERSION, preident, v4first, invalid_asset_type);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with invalid asset_type", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 16: Unrecognised line (invalid asset_type)");
    }

    diag("Test V%u data load with same network part and wrong sort order", SITEPREFS_VERSION);
    {
        const char *preident = "[lists:5]\n"
                               "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                               "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                               "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                               "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                               "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                               "[bundles:1]\n"
                               "0:1:4294967295:60:3F0000780000000000::1 4:2:3:5::::::\n"
                               "[orgs:1]\n"
                               "2748:0:0:365:0:1002748:0\n"
                               "[identities:2]\n";
        const char *v4ident1 = "1:14698509::10.0.0.0/8:14698509:21:2748:0:1\n";
        const char *v4ident2 = "1:14698509::10.0.0.0/31:14698509:21:2748:0:1\n";
        const char *v6ident1 = "1:14698509::1:2:3::/48:14698509:21:2748:0:1\n";
        const char *v6ident2 = "1:14698509::1:2:3::/64:14698509:21:2748:0:1\n";

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 9\n%s%s%s", SITEPREFS_VERSION, preident, v4ident1, v4ident2);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Read version %u data with same network part and valid v4 sort order", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 9\n%s%s%s", SITEPREFS_VERSION, preident, v4ident2, v4ident1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with same network part and invalid v4 sort order", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 15: Invalid line (out of order)");

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 9\n%s%s%s", SITEPREFS_VERSION, preident, v4ident1, v4ident1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with same duplicate v4 key", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 15: Invalid line (duplicate)");

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 9\n%s%s%s", SITEPREFS_VERSION, preident, v6ident1, v6ident2);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Read version %u data with same network part and valid v6 sort order", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 9\n%s%s%s", SITEPREFS_VERSION, preident, v6ident2, v6ident1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with same network part and invalid v6 sort order", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 15: Invalid line (out of order)");

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 9\n%s%s%s", SITEPREFS_VERSION, preident, v6ident1, v6ident1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with same duplicate v6 key", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 15: Invalid line (duplicate)");
    }

    diag("Test V%u data load with duplicate org", SITEPREFS_VERSION);
    {
        const char *preorg = "[lists:5]\n"
                             "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                             "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                             "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                             "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                             "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                             "[bundles:1]\n"
                             "0:1:4294967295:60:3F0000780000000000::1 4:2:3:5::::::\n"
                             "[orgs:2]\n";
        const char *postorg = "[identities:1]\n"
                              "1:14698509::10.0.0.0/8:14698509:21:2748:0:1\n";
        const char *org1 = "2748:0:0:365:0:1002748:0\n";
        const char *org2 = "2749:1:2:365:0:1002749:0\n";

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 9\n%s%s%s%s", SITEPREFS_VERSION, preorg, org1, org2, postorg);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Read version %u data with different orgs", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 9\n%s%s%s%s", SITEPREFS_VERSION, preorg, org1, org1, postorg);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Failed to read version %u data with duplicate orgs", SITEPREFS_VERSION);
        unlink(fn);
        OK_SXEL_ERROR(": 13: Cannot create org 2748");
    }

    diag("Test V%u data load with invalid domain list fields", SITEPREFS_VERSION);
    {
        const char *precontent = "[lists:5]\n"
                                 "0:1:url:71:deadbeef:http://black1/path https://black2/?x=1&y=2\n"
                                 "0:4:cidr:70:bad1:1.2.3.0/24 10.0.0.0/8\n"
                                 "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                                 "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                                 "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                                 "[bundles:1]\n"
                                 "0:1:4294967295:60:1F0000000000000000::1 4:2:3:5::::::";
        const char *postcontent = "\n"
                                  "[orgs:1]\n"
                                  "2748:0:0:365:0:1002748:0\n"
                                  "[identities:1]\n"
                                  "1:6789971::1.2.3.4/32:6789971:21:2748:0:1\n";
        const char *withcolon = ":";
        const char *withoutcolon = "";

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 8\n%s%s%s", SITEPREFS_VERSION, precontent, withoutcolon, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        unlink(fn);
        ok(sp, "Loaded version %u data with valid bundle lists", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 8\n%s%s%s", SITEPREFS_VERSION, precontent, withcolon, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        unlink(fn);
        ok(!sp, "Failed to read version %u data with invalid bundle lists", SITEPREFS_VERSION);
        OK_SXEL_ERROR(": 10: Unrecognised bundle line (invalid warn app list ':')");
    }

    diag("Test V%u data load with invalid application lists", SITEPREFS_VERSION);
    {
        const char *precontent = "[lists:7]\n"
                                 "0:1:url:71:deadbeef:http://black1/path https://black2/?x=1&y=2\n"
                                 "0:4:cidr:70:bad1:1.2.3.0/24 10.0.0.0/8\n"
                                 "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                                 "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                                 "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n";
        const char *postcontent = "[bundles:1]\n"
                                  "0:1:4294967295:60:1F0000000000000000::1 4:2:3:5::4::::\n"
                                  "[orgs:1]\n"
                                  "2748:0:0:365:0:1002748:0\n"
                                  "[identities:1]\n"
                                  "1:6789971::1.2.3.4/32:6789971:21:2748:0:1\n";
        const char *goodlist1 = "14:4:application:151:6782bc60f931c88237c2836c3031ef4c717066e1:1\n";
        const char *goodlist2 = "14:6:application:152:6782bc60f931c88237c2836c3031ef4c717066e1:1\n";
        const char *goodlist3 = "14:6:application:148:6782bc60f931c88237c2836c3031ef4c717066e3:1 2 3\n";
        const char *badlist = "14:4:application:148:6782bc60f931c88237c2836c3031ef4c717066e2:x1\n";
        const char *badfp = "14:4:application:148:6782bc60f931c88237c2836c3031ef4c717066:1\n";

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s%s", SITEPREFS_VERSION, precontent, goodlist1, goodlist2, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        unlink(fn);
        ok(sp, "Loaded version %u data with valid duplicate applist data", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s%s", SITEPREFS_VERSION, precontent, goodlist1, goodlist3, postcontent);

        MOCKFAIL_START_TESTS(3, UINT32LIST_NEW);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Cannot load version %u data with valid different applist data when calloc fails", SITEPREFS_VERSION);
        OK_SXEL_ERROR("Failed to allocate uint32list of ");
        OK_SXEL_ERROR(": 9: Unrecognised list line (parsing uint32list failed)");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(3, UINT32LIST_REALLOC);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(!sp, "Cannot load version %u data with valid different applist data when realloc fails", SITEPREFS_VERSION);
        OK_SXEL_ERROR("Failed to reallocate uint32list val to 0 elements");
        OK_SXEL_ERROR(": 9: Unrecognised list line (parsing uint32list failed)");
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Loaded version %u data with valid different applist data", SITEPREFS_VERSION);
        siteprefs_refcount_dec(sp);
        unlink(fn);

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s%s", SITEPREFS_VERSION, precontent, badlist, goodlist2, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        unlink(fn);
        ok(!sp, "Failed to read version %u data with invalid applist data", SITEPREFS_VERSION);
        OK_SXEL_ERROR("Invalid or out-of-range uint32 found in list");
        OK_SXEL_ERROR(": 9: Unrecognised list line (parsing uint32list failed)");

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s%s", SITEPREFS_VERSION, precontent, badfp, goodlist2, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        unlink(fn);
        ok(!sp, "Failed to read version %u data with an invalid applist fingerprint", SITEPREFS_VERSION);
        OK_SXEL_ERROR("Invalid domainlist fingerprint; hex length should be 40, not 38");
        OK_SXEL_ERROR(": 9: Unrecognised list line (parsing uint32list failed)");

        fn = create_data("test-siteprefs", "siteprefs %u\ncount 10\n%s%s%s%s", SITEPREFS_VERSION, precontent, goodlist1, goodlist1, postcontent);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        unlink(fn);
        ok(!sp, "Failed to read version %u data with duplicate applist data", SITEPREFS_VERSION);
        OK_SXEL_ERROR(": 10: Cannot create preflist 14:4:application");
    }

    diag("Test V%u failures with varying fingerprint sizes", SITEPREFS_VERSION);
    {
        struct {
            int result;
            const char *type;
            const char *fp1, *data1;
            const char *fp2, *data2;
            const char *err;
        } data[] = {
            { 1, "domain", "abcd", "x.com y.com",           "1234", "a.com",       ""},
            { 0, "domain", "abcd", "x.com y.com",           "12",   "a.com",       "Invalid domainlist fingerprint; hex length should be 4, not 2"},
            { 1, "cidr",   "abcd", "1.2.3.4/32 2.3.0.0/16", "1234", "1.2.3.0/24",  ""},
            { 0, "cidr",   "abcd", "1.2.3.4/32 2.3.0.0/16", "12",   "1.2.3.0/24",  "Invalid cidrlist fingerprint; length should be 2, not 1"},
            { 1, "url",    "abcd", "a.com/x/y b.com/path",  "1234", "b.com/path",  ""},
            { 0, "url",    "abcd", "a.com/x/y b.com/path",  "12",   "b.com/other", "Invalid urllist fingerprint; length should be 2, not 1"},
        };

        fileprefs_freehashes();

        for (i = 0; i < sizeof(data) / sizeof(*data); i++) {
            fn = create_data("test-siteprefs", "siteprefs %u\n"
                                               "count 5\n"
                                               "[lists:2]\n"
                                               "0:1:%s:71:%s:%s\n"
                                               "0:2:%s:70:%s:%s\n"
                                               "[bundles:1]\n"
                                               "0:1:0:60:1::1 2:::::::::\n"
                                               "[orgs:1]\n"
                                               "2748:0:0:365:0:1002748:0\n"
                                               "[identities:1]\n"
                                               "1:6789971::1.2.3.4/32:6789971:21:2748:0:1\n",
                             SITEPREFS_VERSION, data[i].type, data[i].fp1, data[i].data1, data[i].type, data[i].fp2, data[i].data2);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            sp = siteprefs_new(&cl, LOADFLAGS_FP_ELEMENTTYPE_APPLICATION | LOADFLAGS_FP_ELEMENTTYPE_CIDR
                                    | LOADFLAGS_FP_ELEMENTTYPE_DOMAIN | LOADFLAGS_FP_ELEMENTTYPE_URL);
            unlink(fn);
            ok(!!sp == data[i].result, "%s siteprefs from V%u data set %u", data[i].result ? "Constructed" : "Didn't construct", SITEPREFS_VERSION, i);
            if (strcmp(data[i].err, ""))
                OK_SXEL_ERROR(data[i].err);
            else
                OK_SXEL_ERROR(NULL);
            if (*data[i].err)
                OK_SXEL_ERROR("Unrecognised list line");
            siteprefs_refcount_dec(sp);
        }

        fileprefs_freehashes();
    }

    diag("Test V%u data handling - XXX this should be improved - the assetid and originids are inconsistent", SITEPREFS_VERSION);
    {
        fn = create_data("test-siteprefs", "siteprefs %u\n"
                                           "count 38\n"
                                           "[lists:5]\n"
                                           "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                                           "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                                           "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                                           "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                                           "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                                           "[bundles:6]\n"
                                           "0:1:6:60:1F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:12:5:61:1F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:42:4:62:1F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:43:4:63:1F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:1000:5:60:2F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:1001:6:61:2F0000000000000000::1 4:2:3:5::::::\n"
                                           "[orgs:1]\n"
                                           "2748:40:0:365:10:1002748:123\n"
                                           "[identities:26]\n"
                                           "1:1::[1:2::]/42:9070144:21:2748:0:1\n"
                                           "1:1::[1:2:3::]/48:9070192:21:2748:0:12\n"
                                           "1:1::[1:2:3:4::]/64:9070196:21:2748:0:42\n"
                                           "1:1::1.2.0.0/21:70144:21:2748:0:1\n"
                                           "1:1::1.2.3.0/24:70192:21:2748:0:12\n"
                                           "1:1::1.2.3.4/32:70196:21:2748:0:42\n"
                                           "1:1::10.2.3.0/24:70777:21:2748:0:42\n"
                                           "1:2::[1:2::]/32:9135680:21:2748:0:43\n"
                                           "1:2::[1:2:3::]/48:9135728:40:2748:0:1000\n"
                                           "1:2::[1:2:3:4::]/64:9135732:40:2748:0:1001\n"
                                           "1:2::1.2.0.0/16:135680:21:2748:0:43\n"
                                           "1:2::1.2.3.0/24:135728:40:2748:0:1000\n"
                                           "1:2::1.2.3.4/32:135732:40:2748:0:1001\n"
                                           "2:2748:21:[1:2::]/42:9070150:21:2748:0:1\n"
                                           "2:2748:21:[1:2:3::]/48:9070192:21:2748:0:12\n"
                                           "2:2748:21:[1:2:3:4::]/64:9070196:21:2748:0:43\n"
                                           "2:2748:21:1.2.0.0/21:70144:21:2748:0:1\n"
                                           "2:2748:21:1.2.3.0/24:70192:21:2748:0:12\n"
                                           "2:2748:21:1.2.3.4/32:70196:21:2748:0:42\n"
                                           "2:2748:21:10.2.3.0/30:70777:21:2748:0:42\n"
                                           "2:2748:40:[1:2::]/32:9135680:21:2748:0:1001\n"
                                           "2:2748:40:[1:2:3::]/48:9135728:21:2748:0:1000\n"
                                           "2:2748:40:[1:2:3:4::]/64:9135732:21:2748:0:43\n"
                                           "2:2748:40:1.2.0.0/16:135680:21:2748:0:1001\n"
                                           "2:2748:40:1.2.3.0/24:135728:21:2748:0:1000\n"
                                           "2:2748:40:1.2.3.4/32:135732:21:2748:0:43\n", SITEPREFS_VERSION);

        MOCKFAIL_START_TESTS(2, fileprefs_load_section);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!siteprefs_new(&cl, LOADFLAGS_SITEPREFS), "Failed to load empty v%u siteprefs when keys cannot be allocated", SITEPREFS_VERSION);
        OK_SXEL_ERROR("Couldn't calloc");
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!siteprefs_get(&pr, NULL, &odns, &ids, NULL), "Can't get prefs without siteprefs");
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        ok(sp, "Constructed struct siteprefs from V%u data", SITEPREFS_VERSION);
        ok(!siteprefs_get(&pr, sp, NULL, &ids, NULL), "Can't get prefs without odns");

        skip_if(!sp, 21, "Cannot run these tests without siteprefs") {
            ok(siteprefs_get_prefblock(sp, 666), "Got prefblock");    // Orgid is ignored
            is(PREFS_COUNT(sp, identities), 26, "V%u data has a count of 26", SITEPREFS_VERSION);
            is(sp->conf.refcount, 1, "V%u data has a refcount of 1", SITEPREFS_VERSION);
            odns.fields = 0;
            ok(!siteprefs_get(&pr, sp, &odns, &ids, NULL), "Can't get prefs without odns");

            odns.fields          = ODNS_FIELD_REMOTEIP4 | ODNS_FIELD_VA;
            odns.va_id           = 666;
            odns.remoteip.family = AF_INET;
            inet_aton("1.2.3.5", &odns.remoteip.in_addr);
            oolist_clear(&ids);
            ok(!siteprefs_get(&pr, sp, &odns, &ids, NULL), "No prefs for org 666 IP 1.2.3.5");

            struct xray xray;
            ok(xray_init_for_client(&xray, 4096), "Successfully allocated X-ray buffer");
            odns.va_id           = 2;
            ok(siteprefs_get(&pr, sp, &odns, &ids, &xray), "Got prefs for org 2 IP 1.2.3.5");
            is_eq(oolist_origins_to_buf(ids, buf, sizeof buf),
                  "135728:40:2748:365:123,135680:21:2748:365:123,70192:21:2748:365:123,70144:21:2748:365:123",
                  "Collected other origin IDs: va 2, cidr 1.2.0.0/16 and va 2, cidr 1.2.3.0/24");

            static const char *expected_xray[] = {
            "siteprefs match: found: bundle 0:1000, priority 5, origin 135728 for candidate item 11 with cidr 1.2.3.0/24",
            "siteprefs match: found: bundle 0:43, priority 4, origin 135680 for candidate item 10 with cidr 1.2.0.0/16",
            "siteprefs match: found: bundle 0:12, priority 5, origin 70192 for candidate item 17 with cidr 1.2.3.0/24 (type 2)",
            "siteprefs match: found: bundle 0:1, priority 6, origin 70144 for candidate item 16 with cidr 1.2.0.0/21 (type 2)",
            "siteprefs match: using: bundle 0:43, priority 4, origin 135680"
            };

            const uint8_t *xp = xray.addr;

            for (i = 0; i < sizeof(expected_xray) / sizeof(expected_xray[0]); i++) {
                is(*xp, strlen(expected_xray[i]),                              "Line %u has the expected length", i + 1);
                is_strncmp(xp + 1, expected_xray[i], strlen(expected_xray[i]), "Line %u has correct content",     i + 1);
                xp += 1 + strlen(expected_xray[i]);
            }

            is(*xp, 0, "There is no extra X-ray data");
            xray_fini_for_client(&xray);
            ok(PREF_VALID(&pr), "Got prefs for va 2, cidr 1.2.0.0/16");
            skip_if(!PREF_VALID(&pr), 1, "Cannot run this test without prefs") {
                is(PREF_BUNDLE(&pr)->bundleflags, 0x63, "The selected prefs match va 2, cidr 1.2.0.0/16");
            }

            odns.va_id = 1;
            inet_aton("1.2.3.4", &odns.remoteip.in_addr);
            oolist_clear(&ids);
            siteprefs_get(&pr, sp, &odns, &ids, NULL);

            is_eq(oolist_origins_to_buf(ids, buf, sizeof buf),
                  "70196:21:2748:365:123,70192:21:2748:365:123,70144:21:2748:365:123",
                  "Collected other origin IDs for all org 1 entries");
            ok(PREF_VALID(&pr), "Got prefs for va 1, cidr 1.2.3.0/24");
            skip_if(!PREF_VALID(&pr), 1, "Cannot run this test without prefs") {
                is(PREF_BUNDLE(&pr)->bundleflags, 0x62, "The selected prefs match va 1, cidr 1.2.3.4/32");
            }

            odns.fields = ODNS_FIELD_REMOTEIP6 | ODNS_FIELD_VA;
            odns.va_id = 2;
            odns.remoteip.family = AF_INET6;
            inet_pton(AF_INET6, "1:2:3:5::", &odns.remoteip.in6_addr);
            oolist_clear(&ids);
            siteprefs_get(&pr, sp, &odns, &ids, NULL);

            is_eq(oolist_origins_to_buf(ids, buf, sizeof buf),
                  "9135728:40:2748:365:123,9135680:21:2748:365:123,9070192:21:2748:365:123,9070150:21:2748:365:123",
                  "Collected other origin IDs: va 2, cidr 1:2::/32 and va 2, cidr 1:2:3::/48");
            ok(PREF_VALID(&pr), "Got prefs for va 2, cidr 1:2::/32");
            skip_if(!PREF_VALID(&pr), 1, "Cannot run this test without prefs") {
                is(PREF_BUNDLE(&pr)->bundleflags, 0x63, "The selected prefs match va 2, cidr 1:2::/32");
            }

            odns.va_id = 1;
            inet_pton(AF_INET6, "1:2:3:4::", &odns.remoteip.in6_addr);
            oolist_clear(&ids);
            siteprefs_get(&pr, sp, &odns, &ids, NULL);

            is_eq(oolist_origins_to_buf(ids, buf, sizeof buf),
                  "9070196:21:2748:365:123,9070192:21:2748:365:123,9070144:21:2748:365:123,9070150:21:2748:365:123",
                  "Collected other origin IDs for all org 1 entries");
            ok(PREF_VALID(&pr), "Got prefs for va 1, cidr 1:2:3::/48");
            skip_if(!PREF_VALID(&pr), 1, "Cannot run this test without prefs") {
                is(PREF_BUNDLE(&pr)->bundleflags, 0x62, "The selected prefs match va 1, cidr 1:2:3:4::/64");
            }

            odns.va_id = 2;
            inet_pton(AF_INET6, "1:2:3:4::", &odns.remoteip.in6_addr);
            oolist_clear(&ids);
            siteprefs_get(&pr, sp, &odns, &ids, NULL);

            is_eq(oolist_origins_to_buf(ids, buf, sizeof buf),
                  "9135732:40:2748:365:123,9135728:40:2748:365:123,9135680:21:2748:365:123,9070196:21:2748:365:123,"
                  "9070192:21:2748:365:123,9070150:21:2748:365:123",
                  "Collected other origin IDs for all org 1 entries");
            ok(PREF_VALID(&pr), "Got prefs for va 2, cidr 1:2:3::/48");
            skip_if(!PREF_VALID(&pr), 1, "Cannot run this test without prefs") {
                is(PREF_BUNDLE(&pr)->bundleflags, 0x63, "The selected prefs match va 2, cidr 1:2:3:4::/64");
            }

            is_eq((*sp->fp.ops->key_to_str)(&sp->fp, 0), "1:1::[1:2::]/42", "Got the correct first key");
            is_eq((*sp->fp.ops->key_to_str)(&sp->fp, 25), "2:2748:40:1.2.3.4/32", "Got the correct last key");

            /* Do the same for IPv4
             */
            odns.remoteip.family = AF_INET;
            inet_pton(AF_INET, "1.2.3.5", &odns.remoteip.in_addr);
            oolist_clear(&ids);
            siteprefs_get(&pr, sp, &odns, &ids, NULL);

            is_eq(oolist_origins_to_buf(ids, buf, sizeof buf),
                  "135728:40:2748:365:123,135680:21:2748:365:123,70192:21:2748:365:123,70144:21:2748:365:123",
                  "Collected other origin IDs for all org 1 IPv4 entries");
            ok(PREF_VALID(&pr), "Got prefs for va 2, cidr 1:2:3::/48");

            skip_if(!PREF_VALID(&pr), 1, "Cannot run this test without prefs") {
                is(PREF_BUNDLE(&pr)->bundleflags, 0x63, "The selected prefs match va 2, cidr 1:2:3:4::/64");
            }

            is_eq((*sp->fp.ops->key_to_str)(&sp->fp, 0), "1:1::[1:2::]/42", "Got the correct first key");
            is_eq((*sp->fp.ops->key_to_str)(&sp->fp, 25), "2:2748:40:1.2.3.4/32", "Got the correct last key");

            siteprefs_refcount_dec(sp);
        }

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        unlink(fn);
        ok(sp, "Constructed struct siteprefs from V%u data with a policy index", SITEPREFS_VERSION);
        corg = siteprefs_org(sp, 2748);
        ok(corg, "Found org 2748 with an index");

        skip_if(!corg, 6, "Cannot verify org data without an org") {
            is(corg->orgflags,  0x40,    "org 2748 flags are correct");
            is(corg->retention, 365,     "org 2748 retention period is correct");
            is(corg->warnperiod, 10,     "org 2748 warn period is correct");
            is(corg->originid,  1002748, "org 2748 originid is correct");
            is(corg->parentid,  123,     "org 2748 parentid is correct");
            ok(pref_categories_isnone(&corg->unmasked), "corg->unmasked is %s (expected 0)", pref_categories_idstr(&corg->unmasked));
        }

        siteprefs_refcount_dec(sp);
    }

    diag("Test V%u early-outs - XXX this should be improved - the assetid and originids are inconsistent", SITEPREFS_VERSION);
    {
        fn = create_data("test-siteprefs", "siteprefs %u\n"
                                           "count 20\n"
                                           "[lists:5]\n"
                                           "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                                           "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                                           "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                                           "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                                           "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                                           "[bundles:7]\n"
                                           "0:1:6:60:1F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:12:5:61:1F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:42:4:62:1F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:43:3:63:1F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:1000:2:60:2F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:1001:1:61:2F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:400000:0:62:2F0000000000000000::1 4:2:3:5::::::\n"
                                           "[orgs:1]\n"
                                           "2:0:0:365:0:1002:0\n"
                                           "[identities:7]\n"
                                           "1:305419896::1.2.0.0/21:4608:21:2:0:1\n"
                                           "1:305419896::1.2.3.0/24:4656:21:2:0:12\n"
                                           "1:305419896::1.2.3.4/32:4660:21:2:0:42\n"
                                           "1:305419896::2.0.0.0/8:8192:21:2:0:43\n"
                                           "1:305419896::2.2.0.1/16:8704:21:2:0:1000\n"
                                           "1:305419896::2.2.2.255/24:8736:21:2:0:1001\n"
                                           "1:305419896::2.2.2.2/32:8738:21:2:0:400000\n", SITEPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        unlink(fn);
        ok(sp, "Constructed struct siteprefs from V%u data", SITEPREFS_VERSION);
        OK_SXEL_ERROR(": 24: 2.2.0.1/16: Invalid CIDR - should be 2.2.0.0/16");
        OK_SXEL_ERROR(": 25: 2.2.2.255/24: Invalid CIDR - should be 2.2.2.0/24");

        skip_if(!sp, 5, "Cannot run these tests without siteprefs") {
            is(PREFS_COUNT(sp, identities), 7, "V%u data has a count of 7", SITEPREFS_VERSION);
            is(sp->conf.refcount, 1, "V%u data has a refcount of 1", SITEPREFS_VERSION);

            odns.fields = ODNS_FIELD_REMOTEIP4 | ODNS_FIELD_VA;
            odns.va_id = 305419896;
            odns.remoteip.family = AF_INET;
            inet_aton("2.2.2.1", &odns.remoteip.in_addr);
            oolist_clear(&ids);
            siteprefs_get(&pr, sp, &odns, &ids, NULL);

            is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "8736:21:2:365:0,8704:21:2:365:0,8192:21:2:365:0",
                  "Collected the correct other_originids");
            ok(PREF_VALID(&pr), "Got prefs for 2.2.2.1");

            skip_if(!PREF_VALID(&pr), 1, "Cannot run this test without prefs") {
                is(PREF_BUNDLE(&pr)->bundleflags, 0x61, "The selected prefs match cidr 2.2.2.0/24");
            }

            /* The early-out is only proven by coverage totals */

            siteprefs_refcount_dec(sp);
        }
    }

    diag("Test V%u narrowest choice - XXX this should be improved - the assetid and originids are inconsistent", SITEPREFS_VERSION);
    {
        /* Lands on 1.2.3.0/16 first, so finds 1.2.5.0/24 second */
        fn = create_data("test-siteprefs", "siteprefs %u\n"
                                           "count 19\n"
                                           "[lists:5]\n"
                                           "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                                           "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                                           "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                                           "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                                           "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                                           "[bundles:3]\n"
                                           "0:1:6:60:1F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:12:5:61:1F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:42:4:62:1F0000000000000000::1 4:2:3:5::::::\n"
                                           "[orgs:1]\n"
                                           "2:0:0:365:0:1002:0\n"
                                           "[identities:10]\n"
                                           "1:305419895::1:2::/42:304608:21:2:0:12\n"
                                           "1:305419895::1:2:3::/48:304656:21:2:0:12\n"
                                           "1:305419895::1.2.0.0/21:4608:21:2:0:12\n"
                                           "1:305419895::1.2.3.0/24:4656:21:2:0:12\n"
                                           "1:305419896::1:2:3::/32:304096:21:2:0:12\n"
                                           "1:305419896::1:2:4::/48:308192:21:2:0:12\n"
                                           "1:305419896::1:2:5::/48:312288:21:2:0:12\n"
                                           "1:305419896::1.2.3.0/16:4096:21:2:0:12\n"
                                           "1:305419896::1.2.4.0/24:8192:21:2:0:12\n"
                                           "1:305419896::1.2.5.0/24:12288:21:2:0:12\n", SITEPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        OK_SXEL_ERROR(": 20: 1:2:3::/32: Invalid CIDR - should be [1:2::]/32");
        OK_SXEL_ERROR(": 23: 1.2.3.0/16: Invalid CIDR - should be 1.2.0.0/16");
        unlink(fn);
        ok(sp, "Constructed struct siteprefs from V%u data with 5 entries", SITEPREFS_VERSION);
        skip_if(!sp, 9, "Cannot run these tests without siteprefs") {
            is(PREFS_COUNT(sp, identities), 10, "V%u data has a count of 10", SITEPREFS_VERSION);
            is(sp->conf.refcount, 1, "V%u data has a refcount of 1", SITEPREFS_VERSION);

            odns.fields = ODNS_FIELD_REMOTEIP4 | ODNS_FIELD_VA;
            odns.va_id = 305419896;
            odns.remoteip.family = AF_INET;
            inet_aton("1.2.5.1", &odns.remoteip.in_addr);
            oolist_clear(&ids);
            siteprefs_get(&pr, sp, &odns, &ids, NULL);

            is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "12288:21:2:365:0,4096:21:2:365:0",
                  "Collected the correct v4 other_originids");
            ok(PREF_VALID(&pr), "Got prefs for 1.2.5.0/24");
            skip_if(!PREF_VALID(&pr), 1, "Cannot run this test without prefs") {
                is(PREF_IDENT(&pr)->originid, 12288, "The selected prefs match cidr 1.2.5.0/24, originid 12288 (narrowest match)");
            }

            odns.fields = ODNS_FIELD_REMOTEIP6 | ODNS_FIELD_VA;
            odns.va_id = 305419896;
            odns.remoteip.family = AF_INET6;
            inet_pton(AF_INET6, "1:2:5:1::", &odns.remoteip.in6_addr);
            oolist_clear(&ids);
            siteprefs_get(&pr, sp, &odns, &ids, NULL);

            is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "312288:21:2:365:0,304096:21:2:365:0",
                  "Collected the correct v6 other_originids");
            ok(PREF_VALID(&pr), "Got prefs for 1:2:5::/48");
            skip_if(!PREF_VALID(&pr), 2, "Cannot run this test without prefs") {
                is(PREF_IDENT(&pr)->originid, 0x4c3e0, "The selected prefs match cidr 1:2:5::/48, originid 12288 (narrowest match)");
                is(PREF_IDENT(&pr)->origintypeid, 21, "The origintypeid was populated");
            }

            siteprefs_refcount_dec(sp);
        }

        /* Lands on 1.2.5.0/24 first, so finds 1.2.3.0/16 second */
        fn = create_data("test-siteprefs", "siteprefs %u\n"
                                           "count 30\n"
                                           "[lists:11]\n"
                                           "0:1:domain:71:43c1ddfb8feded68d30102342899d4dabd0cbc82:black1\n"
                                           "0:4:domain:70:66bcd5e16e1f1daab7647dba907b4e4fa047bf7b:fireeye1\n"
                                           "0:20:domain:71:f5e94651f0f19eaa63e46e9b8d3a74d44710f0c5:black2\n"
                                           "0:22:domain:70:b4227d7d29dd9ff2650ac5effb7a72738ff66fc3:fireeye2\n"
                                           "4:2:domain::6782bc60f931c88237c2836c3031ef4c717066e0:typo1\n"
                                           "4:100:domain::8583e823dd7b77813b4db34a0fd458109c19c234:typo1 typo2\n"
                                           "8:3:domain:72:19b4540a40581d828f2d50c18e3decf2490ea827:white1\n"
                                           "8:15:domain:72:b37b8133f1fa5e36345b605e23a102267d63c870:white2\n"
                                           "C:5:domain::886700e4c2276be2081d435212652438f02b5c9b:urlproxy1\n"
                                           "C:90:domain::429941e556c42b9e62d9cd607eaa408be95f47e1:urlproxy1 urlproxy2\n"
                                           "20:123:domain:158:da4017e8921dcb4e2f98bbb408007ee0985a14be:warn1 warn2\n"
                                           "[bundles:9]\n"
                                           "0:1:1:61:F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:12:1:62:F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:42:2:63:F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:43:2:60:1F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:1000:2:61:1F0000000000000000::1 4 20 22:100:3 15:90:::::123:\n"
                                           "0:1001:3:62:1F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:400000:3:63:1F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:400010:3:60:2F0000000000000000::1 4:2:3:5::::::\n"
                                           "0:400101:3:61:2F0000000000000000::1 4:2:3:5::::::\n"
                                           "[orgs:1]\n"
                                           "2:1F:2000000000000000000000:365:0:1002:0\n"
                                           "[identities:9]\n"
                                           "1:305419895::1.2.0.0/21:4608:21:2:0:1\n"
                                           "1:305419895::1.2.3.0/24:4656:21:2:0:12\n"
                                           "1:305419896::1.2.3.0/16:4096:21:2:0:42\n"
                                           "1:305419896::1.2.4.0/24:8192:21:2:0:43\n"
                                           "1:305419896::1.2.5.0/24:12288:21:2:0:1000\n"
                                           "1:305419897::1.2.0.0/16:70144:21:2:0:1001\n"
                                           "1:305419897::1.2.3.0/23:69632:21:2:0:400000\n"
                                           "1:305419897::1.2.3.0/24:70192:21:2:0:400010\n"
                                           "1:305419897::1.2.4.0/24:73728:21:2:0:400101\n", SITEPREFS_VERSION);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS);
        OK_SXEL_ERROR(": 30: 1.2.3.0/16: Invalid CIDR - should be 1.2.0.0/16");
        OK_SXEL_ERROR(": 34: 1.2.3.0/23: Invalid CIDR - should be 1.2.2.0/23");
        unlink(fn);
        ok(sp, "Constructed struct siteprefs from V%u data with 9 entries", SITEPREFS_VERSION);
        skip_if(!sp, 10, "Cannot run these tests without siteprefs") {
            is(PREFS_COUNT(sp, identities), 9, "V%u data has a count of 9", SITEPREFS_VERSION);
            is(sp->conf.refcount, 1, "V%u data has a refcount of 1", SITEPREFS_VERSION);

            odns.fields = ODNS_FIELD_REMOTEIP4 | ODNS_FIELD_VA;
            odns.va_id = 305419896;
            odns.remoteip.family = AF_INET;
            inet_aton("1.2.5.1", &odns.remoteip.in_addr);
            oolist_clear(&ids);
            siteprefs_get(&pr, sp, &odns, &ids, NULL);

            is_eq(oolist_origins_to_buf(ids, buf, sizeof buf), "12288:21:2:365:0,4096:21:2:365:0", "Collected the correct other_originids");
            ok(PREF_VALID(&pr), "Got prefs for 1.2.5.1");
            skip_if(!PREF_VALID(&pr), 7, "Cannot run this test without prefs") {
                is(PREF_IDENT(&pr)->originid, 0x3000, "The selected prefs match cidr 1.2.5.0/24, originid 0x3000 (narrowest match)");
                ok(pref_domainlist_match(&pr, NULL, AT_LIST_DESTBLOCK, (const uint8_t *)"\6black2", DOMAINLIST_MATCH_SUBDOMAIN, NULL), "v%u blocked contains 'black2'", SITEPREFS_VERSION);
                ok(pref_domainlist_match(&pr, NULL, AT_LIST_EXCEPT, (const uint8_t *)"\5typo2", DOMAINLIST_MATCH_SUBDOMAIN, NULL), "v%u typo_exceptions contains 'typo2'", SITEPREFS_VERSION);
                ok(pref_domainlist_match(&pr, NULL, AT_LIST_DESTALLOW, (const uint8_t *)"\6white2", DOMAINLIST_MATCH_SUBDOMAIN, NULL), "v%u whitelist contains 'white2'", SITEPREFS_VERSION);
                ok(pref_domainlist_match(&pr, NULL, AT_LIST_DESTBLOCK, (const uint8_t *)"\10fireeye2", DOMAINLIST_MATCH_SUBDOMAIN, NULL), "v%u fireeye contains 'fireeye2'", SITEPREFS_VERSION);
                ok(pref_domainlist_match(&pr, NULL, AT_LIST_URL_PROXY_HTTPS, (const uint8_t *)"\11urlproxy2", DOMAINLIST_MATCH_SUBDOMAIN, NULL), "v%u urlproxy contains 'urlproxy2'", SITEPREFS_VERSION);
                ok(pref_domainlist_match(&pr, NULL, AT_LIST_DESTWARN, (const uint8_t *)"\5warn1", DOMAINLIST_MATCH_SUBDOMAIN, NULL), "v%u warn contains 'warn1'", SITEPREFS_VERSION);
            }

            siteprefs_refcount_dec(sp);
        }
    }

    /* Based on the pref-priotities.test "netprefs.win + dirprefs/dirprefs.va + siteprefs.win"
     */
    diag("Test error that escaped coverage testing: level 2 should override level 1 if it's priority is a smaller number");
    {
        fn = create_data("test-siteprefs",    // pref-priorities.test/siteprefs.win
                         "siteprefs %u\n"
                         "count 7\n"
                         "[lists:1]\n"
                         "1:1:domain:71:b688ac579e6454703528622d90cd5d81e11565a3:mylookup1 mylookup2 mylookup2.xray.opendns.com\n"
                         "[bundles:2]\n"
                         "1:1:1:40:F0000000000000000::1:::::::::\n"
                         "1:2:0:40:F0000000000000000::1:::::::::\n"
                         "[identities:4]\n"
                         "1:3735928559::1:2::/32:87654321:21:0:1:1\n"
                         "1:3735928559::127.0.0.0/8:87654321:21:0:1:1\n"
                         "2:0:21:1:2::/32:87654321:21:0:1:2\n"
                         "2:0:21:127.0.0.0/8:87654321:21:0:1:2\n", SITEPREFS_VERSION);

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(sp = siteprefs_new(&cl, LOADFLAGS_SITEPREFS), "Constructed struct siteprefs.win from V%u data", SITEPREFS_VERSION);

        skip_if(!sp, 4, "Cannot run these tests without siteprefs") {
            odns.va_id           = 3735928559;    // 0xdeadbeef
            odns.fields          = ODNS_FIELD_REMOTEIP4 | ODNS_FIELD_VA;
            odns.remoteip.family = AF_INET;
            inet_aton("127.0.0.1", &odns.remoteip.in_addr);
            oolist_clear(&ids);
            ok(siteprefs_get(&pr, sp, &odns, &ids, NULL), "Got prefs for org 3735928559 IP 127.0.0.1");
            is(PREF_BUNDLE(&pr)->priority, 0,             "Expected priority 0 (bundle 2)");

            odns.fields          = ODNS_FIELD_REMOTEIP6 | ODNS_FIELD_VA;
            odns.remoteip.family = AF_INET6;
            inet_pton(AF_INET6, "1:2:3::4", &odns.remoteip.in6_addr);
            oolist_clear(&ids);
            ok(siteprefs_get(&pr, sp, &odns, &ids, NULL), "Got prefs for org 3735928559 IP 1:2:3::4");
            is(PREF_BUNDLE(&pr)->priority, 0,             "Expected priority 0 (bundle 2)");
        }

        siteprefs_refcount_dec(sp);
    }

    OK_SXEL_ERROR(NULL);
    test_uncapture_sxel();

    oolist_clear(&ids);
    conf_loader_fini(&cl);
    fileprefs_freehashes();
    confset_unload();          // Finalize the conf subsystem
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
