#include <cjson/cJSON.h>
#include <kit-alloc.h>
#include <mockfail.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tap.h>
#include <unistd.h>

#include "common-test.h"
#include "conf.h"
#include "conf-loader.h"
#include "crl.h"
#include "digest-store.h"
#include "fileprefs.h"
#include "policy-private.h"

module_conf_t CONF_RULES;    // Separate policy for testing user/group based rules

static void
unlink_test_policy_files(void)
{
    unsigned i;
    char     rmfn[32];

    for (i = 0; i <= 10; i++) {
        snprintf(rmfn, sizeof(rmfn), "test-policy-%u", i);
        unlink(rmfn);
        snprintf(rmfn, sizeof(rmfn), "test-policy-%u.last-good", i);
        unlink(rmfn);
    }

    unlink("test-rules-1");
    unlink("test-rules-1.last-good");
}

static void
error_capture(void)
{
    test_capture_sxel();
    test_passthru_sxel(4);    /* Not interested in SXE_LOG_LEVEL=4 or above - pass them through */
}

static void
error_test(const char *error1, const char *error2)
{
    OK_SXEL_ERROR(error1);
    OK_SXEL_ERROR(error2);
    test_uncapture_sxel();
}

/* Visitor function used when testing policy. Stores the last successfully processed rules reason code in the unsigned provided.
 */
static bool
test_action(void *value, const struct crl_value *action, const struct crl_value *attrs, cJSON **error_out, uint32_t org_id,
            unsigned i)
{
    const struct crl_value *reason = crl_attributes_get_value(attrs, "reason");

    SXE_UNUSED_PARAMETER(action);
    SXE_UNUSED_PARAMETER(error_out);
    SXE_UNUSED_PARAMETER(org_id);
    SXE_UNUSED_PARAMETER(i);

    if (!reason || crl_value_get_type(reason) != CRL_TYPE_JSON)    // These shouldn't happen; if they do, return garbage reason
        *(unsigned *)value = ~0U;
    else
        *(unsigned *)value = (unsigned)((cJSON *)reason->pointer)->valuedouble;

    return *(unsigned *)value == 8;    // Don't short circuit until a rule with reason 8 is matched
}

int
main(void)
{
    struct conf_loader   cl;
    module_conf_t        reg;
    const struct policy *policy;
    struct policy_org   *org;
    struct confset      *set;
    const char          *fn;
    uint64_t             start_allocations;
    unsigned             i;
    int                  gen;
    char                 content[4][4096];

    plan_tests(187);

    kit_memory_initialize(false);
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");
    // KIT_ALLOC_SET_LOG(1);    // Turn off when done

    conf_initialize(".", ".", false, NULL);
    conf_loader_init(&cl);
    gen = 0;

    crl_initialize(0, 0);
    unlink_test_policy_files();

    diag("Test missing file load");
    {
        struct conf_info *info = conf_info_new(NULL, "noname", "nopath", NULL, LOADFLAGS_NONE, NULL, 0);
        info->updates++;

        error_capture();
        conf_loader_open(&cl, "/tmp/not-really-there", NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = policy_org_new(1, &cl, info);
        ok(!org, "Failed to read non-existent file");
        error_test("not-really-there could not be opened: No such file or directory", NULL);

        conf_loader_done(&cl, info);
        is(info->updates, 1, "conf_loader_done() didn't bump 'updates'");
        is(info->st.dev, 0, "Loading a non-existent file gives a clear stat");

        for (i = 0; i < sizeof(info->digest); i++)
            if (info->digest[i])
                break;

        is(i, sizeof(info->digest), "The digest of an empty file has %zu zeros", sizeof(info->digest));
        conf_info_free(info);
    }

    struct conf_info info;

    diag("Test empty files");
    {
        fn = create_data("test-policy", "%s", "");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        info.loadflags = LOADFLAGS_NONE;
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(!org, "Failed to read empty file");
        error_test(": No content found", NULL);

        fn = create_data("test-policy", "rules 2\ncount 0\n[rules:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        info.loadflags = LOADFLAGS_POLICY;
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(org, "Read file with empty [rules] section");
        policy_org_refcount_dec(org);

        fn = create_data("test-policy", "rules 2\ncount 0\n# No policy section header\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(org, "Read file with valid file header, missing [rules] section");
        policy_org_refcount_dec(org);

        fn = create_data("test-policy", "rules 2\ncount 0\n[rules:0]\n[identities:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(!org, "Failed to read file empty [rules] section followed by empty [identities]");
        error_test(": 4: Invalid section header 'identities'", NULL);
    }

    diag("Test garbage files");
    {
        fn = create_data("test-policy", "This is not the correct format\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(!org, "Failed to read garbage file");
        error_test(": Invalid header; must contain 'rules'", NULL);

        fn = create_data("test-policy", "rules 2\ncount 1\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(!org, "Failed to read file with EOF before policy are done");
        error_test(": 2: Incorrect total count 1 - read 0 data lines", NULL);

        fn = create_data("test-policy", "rules 2\ncount 2\n[global:2]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(!org, "Failed to read file with more than one global line");
        error_test(": Global section should never have 2 lines", NULL);

        fn = create_data("test-policy", "rules 2\ncount 1\n[rules:1]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(!org, "Failed to read file with EOF before policy are done");
        error_test(": 3: Unexpected EOF - read 0 [rules] items, not 1", NULL);

        fn = create_data("test-policy", "rules 2\ncount 1\n[rules:1]\n[garbage:0]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(!org, "Failed to read file with [garbage] header before policy are done");
        error_test(": 4: Expected end of line after attributes, got '[garbage:0]'", NULL);

        fn = create_data("test-policy", "rules 2\ncount 0\n[rules:1]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(!org, "Failed to read file with count 0 and EOF before lines are done");
        error_test(": 3: Unexpected EOF - read 0 [rules] items, not 1", NULL);

        fn = create_data("test-policy", "rules 2\ncount 1\n[rules:1]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(!org, "Failed to read file with count 1 and EOF before policy are done");
        error_test(": 3: Unexpected EOF - read 0 [rules] items, not 1", NULL);

        fn = create_data("test-policy", "rules 2\ncount 1\n[identities:1]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(!org, "Failed to read file with count 1 and identities before policy");
        error_test(": 3: Invalid section header 'identities'", NULL);

        fn = create_data("test-policy", "rules 2\ncount 1\n[rules:1x]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(!org, "Failed to read file with bad list header count");
        error_test(": 3: Invalid section header count", NULL);

        // The following test used to verify that policy couldn't be skipped. Now, policy can only contain list sections
        fn = create_data("test-policy", "rules 2\ncount 1\n[rules:0]\n[settinggroup:1]\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(!org, "Failed to read file with invalid section");
        error_test(": 4: Invalid section header 'settinggroup'", NULL);

        conf_loader_fini(&cl);
    }

    diag("Test V%u data load", POLICY_VER_MIN - 1);
    {
        fn = create_data("test-policy", "rules %u\ncount 0\n", POLICY_VER_MIN - 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(!org, "Failed to read version %u data", POLICY_VER_MIN - 1);
        error_test(": 1: Invalid header version(s); must be numeric", NULL);    // Only because 0 is not a valid version
    }

    diag("Test V%u data load", POLICY_VERSION + 1);
    {
        fn = create_data("test-policy", "rules %u\ncount 0\n", POLICY_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        error_capture();
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(!org, "Failed to read version %u data", POLICY_VERSION + 1);
        error_test(": 1: Invalid version(s); must be from the set [1 2]", NULL);
    }

    diag("Test V%u data loads with future V%u", POLICY_VERSION, POLICY_VERSION + 1);
    {
        fn = create_data("test-policy", "rules %u %u\ncount 1\n[rules:0:%u]\n[rules:1:%u]\nnew weird format\n[zork:0:%u]\n",
                         POLICY_VERSION, POLICY_VERSION + 1, POLICY_VERSION, POLICY_VERSION + 1, POLICY_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(org, "Read version %u data despite wonky version %u data", POLICY_VERSION, POLICY_VERSION + 1);
        policy_org_refcount_dec(org);

        fn = create_data("test-policy", "rules %u %u\ncount 0\n[rules:0]\n[zork:0:%u]\n", POLICY_VERSION, POLICY_VERSION + 1,
                         POLICY_VERSION + 1);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        org = policy_org_new(0, &cl, &info);
        unlink(fn);
        ok(org, "Read version %u data with unversioned list data despite wonky version %u data", POLICY_VERSION,
           POLICY_VERSION + 1);
        is(org->count, 0, "Org that had only wonky version %u data has no valid rules", POLICY_VERSION + 1);
        policy_org_refcount_dec(org);
    }

    conf_loader_fini(&cl);

    digest_store_set_options("policy-digest-dir", 1, DIGEST_STORE_DEFAULT_MAXIMUM_AGE);    // Set the test digest directory
    policy_register(&CONF_POLICY, "policy", "test-policy-%u", NULL);
    error_capture();

    reg = 0;
    policy_register(&reg, "policy", "test-more-policy-%u", NULL);
    is(reg, 0, "Cannot register policy twice by name");
    error_test("policy: Config name already registered as ./test-policy-%%u", NULL);

    diag("Test V%u empty data load", POLICY_VERSION);
    {
        snprintf(content[0], sizeof(content[0]), "rules %u\ncount 0\n%s", POLICY_VERSION, "[rules:0]\n");
        create_atomic_file("test-policy-1", "%s", content[0]);

        ok(confset_load(NULL), "Noted an update to test-policy-1 item %u", i);
        ok(!confset_load(NULL), "A second confset_load() call results in nothing");
        ok(set = confset_acquire(&gen), "Acquired the new config");

        skip_if(set == NULL, 6, "Cannot check content without acquiring config") {
            policy = policy_conf_get(set, CONF_POLICY);
            ok(policy, "Constructed policy from empty V%u data", POLICY_VERSION);

            skip_if(policy == NULL, 5, "Cannot check content of NULL policy") {
                is(policy->count, 1, "V%u data has a count of 1 list", POLICY_VERSION);
                is(policy->conf.refcount, 2, "V%u data has a refcount of 2", POLICY_VERSION);

                skip_if(!policy->count, 1, "Cannot verify org count")
                    ok(policy->orgs[0]->rules == NULL, "V%u data has NULL rules", POLICY_VERSION);

                ok(org = policy_find_org(policy, 1), "Found org 1 in the list");
                is(org->count, 0,                    "No rules: kick 'em where it counts!");
            }

            confset_release(set);
            is(policy ? policy->conf.refcount : 0, 1, "confset_release() dropped the refcount back to 1");
        }
    }

    error_capture();    // Start capturing errors

    diag("Test V%u data load with extra garbage lines", POLICY_VERSION);
    {
        create_atomic_file("test-policy-1", "rules %u\nextra garbage\ncount 0\n[rules:0]\n", POLICY_VERSION);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with extra garbage", POLICY_VERSION);
        OK_SXEL_ERROR(": Invalid count; must begin with 'count '");

        create_atomic_file("test-policy-1", "rules %u\ncount 0\nextra garbage\n[rules:0]\n", POLICY_VERSION);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with extra garbage", POLICY_VERSION);
        OK_SXEL_ERROR(": Expected section header");

        create_atomic_file("test-policy-1", "rules %u\ncount 0\n[rules:0]\nextra garbage\n", POLICY_VERSION);
        ok(!confset_load(NULL), "Noted no update; Failed to read version %u data with extra garbage", POLICY_VERSION);
        OK_SXEL_ERROR(": Unexpected [rules] line - wanted only 0 items");

        OK_SXEL_ERROR(NULL);
    }

    diag("Test V%u data load with an invalid count line", POLICY_VERSION);
    {
        create_atomic_file("test-policy-2748", "rules %u\nwrong\n", POLICY_VERSION);
        ok(!confset_load(NULL), "Noted no update; Missing version %u count line", POLICY_VERSION);
        OK_SXEL_ERROR("test-policy-2748: 2: Invalid count; must begin with 'count '");
    }

    diag("Test V%u data load with bad rule lines", POLICY_VERSION);
    {
        create_atomic_file("test-policy-2748", "rules %u\ncount 1\n[rules:1]\nnot a valid rule\n", POLICY_VERSION);
        ok(!confset_load(NULL), "Noted no update; Failed to read bad rule line");
        OK_SXEL_ERROR("test-policy-2748: 4: Expected ':=' after 'not', got 'a valid rule'");
        //OK_SXEL_ERROR("test-policy-2748: 4: Unrecognised rule line (invalid id:)");
    }

    diag("Test V%u data load with various memory allocation failures", POLICY_VERSION);
    {
        snprintf(content[0], sizeof(content[0]), "rules %u\ncount 1\n%s", POLICY_VERSION, "[global:1]\nx:=1\n[rules:0]\n");

        MOCKFAIL_START_TESTS(3, POLICY_CLONE);
        create_atomic_file("test-policy-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR("Couldn't allocate a policy structure");
        OK_SXEL_ERROR("Couldn't clone a policy conf object");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(3, POLICY_CLONE_POLICY_ORGS);
        create_atomic_file("test-policy-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR("Couldn't allocate 10 new policy org slots");
        OK_SXEL_ERROR("Couldn't clone a policy conf object");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(2, POLICY_ORG_NEW);
        create_atomic_file("test-policy-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR("Cannot allocate 96 bytes for a policy_org object");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(2, POLICY_DUP_GLOBALLINE);
        create_atomic_file("test-policy-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR("Failed to allocate memory to duplicate the global attribute line");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(4, POLICY_MORE_POLICY_ORGS);
        char filename[32];

        for (i = 1; i <= 10; i++) {
            snprintf(filename, sizeof(filename), "test-policy-%u", i);
            create_atomic_file(filename, "%s", content[0]);
        }

        ok(confset_load(NULL), "Noted an update");
        OK_SXEL_ERROR(NULL);
        create_atomic_file("test-policy-0", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR("Couldn't reallocate 20 policy org slots");
        MOCKFAIL_END_TESTS();

        create_atomic_file("test-policy-0", "%s", content[0]);    // Actually insert out of order to cover this case
        ok(confset_load(NULL), "Noted an update");

        snprintf(content[0], sizeof(content[0]), "rules %u\ncount 1\n%s", POLICY_VERSION,
                 "[rules:1]\nattrs := 1\ntrue:(block)\n");

        create_atomic_file("test-policy-1", "%s", content[0]);
        MOCKFAIL_START_TESTS(2, POLICY_ALLOCRULES);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR("Failed to malloc a rules array");
        MOCKFAIL_END_TESTS();

        create_atomic_file("test-policy-2", "%s", content[0]);
        MOCKFAIL_START_TESTS(2, POLICY_DUP_ATTRLINE);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR("Failed to allocate memory to duplicate an attribute line");
        MOCKFAIL_END_TESTS();

        create_atomic_file("test-policy-3", "%s", content[0]);
        MOCKFAIL_START_TESTS(2, POLICY_DUP_CONDLINE);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR("Failed to allocate memory to duplicate a condition:action line");
        MOCKFAIL_END_TESTS();

        unlink_test_policy_files();
        ok(confset_load(NULL), "Noted an update");
    }

    diag("Test V%u data load with various additional policy_read_rule failure cases", POLICY_VERSION);
    {
        snprintf(content[0], sizeof(content[0]), "rules %u\ncount 1\n%s", POLICY_VERSION, "[rules:1]\nattrs := 1\n");
        create_atomic_file("test-policy-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR(": 4: Failed to read condition:action line after attribute line");

        snprintf(content[0], sizeof(content[0]), "rules %u\ncount 1\n%s", POLICY_VERSION, "[rules:1]\nattrs := 1\n)\n");
        create_atomic_file("test-policy-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR(": 5: Expected JSON");

        snprintf(content[0], sizeof(content[0]), "rules %u\ncount 1\n%s", POLICY_VERSION, "[rules:1]\nx := 1\ntrue (y)\n");
        create_atomic_file("test-policy-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR(": 5: Expected a ':' after condition, got '(y)'");

        snprintf(content[0], sizeof(content[0]), "rules %u\ncount 1\n%s", POLICY_VERSION, "[rules:1]\nx := 1\ntrue: )\n");
        create_atomic_file("test-policy-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR(": 5: Expected JSON");

        snprintf(content[0], sizeof(content[0]), "rules %u\ncount 1\n%s", POLICY_VERSION, "[rules:1]\nx := 1\ntrue: y z\n");
        create_atomic_file("test-policy-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR(": 5: Expected end of line after action, got 'z'");

        snprintf(content[0], sizeof(content[0]), "rules %u\ncount 1\n%s", POLICY_VERSION, "[global:1]\nx=1\n[rules:0]\n");
        create_atomic_file("test-policy-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR(": 4: Expected ':=' after 'x', got '=1");

        snprintf(content[0], sizeof(content[0]), "rules %u\ncount 1\n%s", POLICY_VERSION, "[global:1]\nx:=1;\n[rules:0]\n");
        create_atomic_file("test-policy-1", "%s", content[0]);
        ok(!confset_load(NULL), "Noted no update");
        OK_SXEL_ERROR(": 4: Expected end of line after global attributes, got ';");
    }

    OK_SXEL_ERROR(NULL);
    test_uncapture_sxel();    // Stop capturing errors
    policy_register(&CONF_RULES, "rules", "rules.%u.org", "( umbrella.source.remote_access = True AND ");

    diag("Test rules V1 data handling");    // Should be tested on the latest when version 1 no longer needs to be supported
    {
        // Data taken from https://github.office.opendns.com/gist/bmajersk/e95e2de758ff564169edbb2bc2ac055d
        create_atomic_file("rules.1.org",
            "rules 1\n"
            "count 4\n"
            "[rulesets:2]\n"
            "ruleset_id=4380\n"
            "ruleset_id=4381\n"
            "[rules:2]\n"
            "ruleset_id=4380 rule_id=85519 priority=1\n"
            "( umbrella.bundle_id = 1401874 AND umbrella.source.all_policy_identities = True"
            "  AND ( umbrella.destination.application_list_ids INTERSECT [251] ) ): (block)\n"
            "ruleset_id=43807 rule_id=708 priority=1\n"
            "( umbrella.source.remote_access = True AND ( umbrella.source.identity_ids INTERSECT [1234567890] ) ): (block) \n"       );

        ok(confset_load(NULL), "Noted an update to rules.1.org");
        ok(set = confset_acquire(&gen), "Acquired the config set that includes policy");

        if (set) {
            ok(policy = policy_conf_get(set, CONF_RULES), "Extracted the user/group policy from the confset");

            if (policy) {
                is(policy_find_org(policy, 2), NULL, "Didn't find org 2; there can only be 1");
                ok(org = policy_find_org(policy, 1), "Found org 1 in the list");

                if (org) {
                    is(org->count, 1, "One rule (rulesets ignored, non-remote_access rules ignored)");

                    for (i = 0; i < org->count; i++) {
                        diag("%s", org->rules[i].attr_line);
                    }
                }
            }
        }

        confset_release(set);
    }

    // Should be tested on the latest when version 1 no longer needs to be supported
    diag("Test rules V1 data handling when all rules are filtered out and there's a global section");
    {
        // Data taken from https://github.office.opendns.com/gist/bmajersk/e95e2de758ff564169edbb2bc2ac055d
        create_atomic_file("rules.1.org",
            "rules 1\n"
            "count 6\n"
            "[organization_configuration:1]\n"
            "my_org_config=1\n"
            "[global:1]\n"
            "my_global=\"value\"\n"
            "[rulesets:2]\n"
            "ruleset_id=4380\n"
            "ruleset_id=4381\n"
            "[rules:2]\n"
            "ruleset_id=4380 rule_id=85519 priority=1\n"
            "( umbrella.bundle_id = 1401874 AND umbrella.source.all_policy_identities = True"
            "  AND ( umbrella.destination.application_list_ids INTERSECT [251] ) ): (block)\n"
            "ruleset_id=4380 rule_id=70684 priority=2\n"
            "( umbrella.bundle_id = 1401874 AND umbrella.source.all_policy_identities = True"
            " AND ( umbrella.destination.category_list_ids INTERSECT [1909000] ) ): (block)\n");

        ok(confset_load(NULL), "Noted an update to rules.1.org");
        ok(set = confset_acquire(&gen), "Acquired the config set that includes policy");

        if (set) {
            ok(policy = policy_conf_get(set, CONF_RULES), "Extracted the user/group policy from the confset");

            if (policy) {
                is(policy_find_org(policy, 2), NULL, "Didn't find org 2; there can only be 1");
                ok(org = policy_find_org(policy, 1), "Found org 1 in the list");

                if (org) {
                    is(org->count, 0, "No rules (rulesets ignored, both non-renote_access rules ignored)");

                    for (i = 0; i < org->count; i++) {
                        diag("%s", org->rules[i].attr_line);
                    }
                }
            }
        }

        confset_release(set);
    }

    diag("Test V%u data handling", POLICY_VERSION);
    {
        // Data taken from the latest sample, 'counter' corrected to 'count' and = to := in attribute lines
        create_atomic_file("test-policy-1",
            "rules %u\n"
            "count 4\n"
            "[rules:4]\n"
            "reason:=2\n"
            "NOT (endpoint.os.type IN [\"windows\", \"macos\", \"ios\", \"linux\", \"android\"]): (block)\n"
            "reason:=3\n"
            "(endpoint.os.type = \"windows\" AND NOT (endpoint.os.version IN [\"v123\", \"v234\"])): (block)\n"
            "reason:=4\n"
            "(endpoint.os.type = \"macos\" AND NOT (endpoint.os.version IN [\"10.15\", \"10.15.1.\", \"10.15.2\","
            " \"10.15.3\", \"10.15.4\", \"10.15.5\", \"10.15.6\", \"10.15.7\", \"10.16\", \"10.16.1\", \"11\", \"11.0\","
            " \"11.1\"])): (block)\n"
            "reason:=8, certlist := endpoint.certificates FIND (sha1 = \"1234567890abcdef1234567890abcdef12345678\")\n"
            "NOT (LENGTH certlist = 1 AND certlist[0][\"issuer\"] = \"DigiCert Inc\" "
            " AND certlist[0][\"subject\"] = \"Cisco OpenDNS LLC\"): (block)\n", POLICY_VERSION);

        ok(confset_load(NULL), "Noted an update to test-policy-1");
        ok(set = confset_acquire(&gen), "Acquired the config set that includes urlprefs");

        if (set) {
            ok(policy = policy_conf_get(set, CONF_POLICY), "Extracted the policy from the confset");

            if (policy) {
                is(policy_find_org(policy, 2), NULL, "Didn't find org 2; there can only be 1");
                ok(org = policy_find_org(policy, 1), "Found org 1 in the list");

                if (org) {
                    struct crl_namespace test_posture;
                    cJSON               *object, *array, *inner;

                    // Generate a simulated posture and push it onto the stack of namespaces
                    object = cJSON_CreateObject();
                    cJSON_AddStringToObject(object, "endpoint.os.type",    "windows");
                    cJSON_AddStringToObject(object, "endpoint.os.version", "10");
                    array  = cJSON_AddArrayToObject(object, "endpoint.certificates");
                    inner  = cJSON_CreateObject();
                    cJSON_AddStringToObject(inner, "sha1",    "1234567890abcdef1234567890abcdef12345678");
                    cJSON_AddStringToObject(inner, "issuer",  "DigiCert Inc");
                    cJSON_AddStringToObject(inner, "subject", "Cisco OpenDNS LLC");
                    cJSON_AddItemToArray(array, inner);
                    crl_namespace_push_object(&test_posture, object);
                    is(org->count, 4, "Four rules");

                    for (i = 0; i < org->count; i++) {    // For each of the 4 rules
                        struct crl_namespace    attr_namespace;
                        struct crl_value       *evaled_attrs;
                        const struct crl_value *attr;
                        cJSON                  *reason;
                        bool                    attrs_alloced;
                        bool                    expected_test[]   = { false, true, false, false };
                        unsigned                expected_reason[] = { 2,     3,    4,     8     };

                        ok(evaled_attrs = crl_attributes_eval(org->rules[i].attributes, &attrs_alloced),
                           "Evaluated attributes against posture");
                        crl_namespace_push_attributes(&attr_namespace, evaled_attrs);
                        is(crl_value_test(org->rules[i].condition), expected_test[i],  "Test %u evaluated as expected", i);
                        is_strncmp(org->rules[i].action->string, "block", 5,           "Action is 'block'");
                        ok(attr = crl_attributes_get_value(evaled_attrs, "reason"),    "Got the reason attribute");
                        reason = attr->pointer;
                        is((unsigned)reason->valuedouble, expected_reason[i],          "The reason was as expected");
                        is(crl_namespace_pop(), &attr_namespace,                       "Popped the attributes namespace");

                        if (attrs_alloced)
                            crl_value_free(evaled_attrs);
                    }

                    is(crl_namespace_pop(), &test_posture, "Popped the test posture");
                    cJSON_Delete(object);

                    diag("Test policy_org_apply");
                    {
                        const struct crl_value *action;
                        cJSON                  *error;
                        cJSON                  *facts  = cJSON_CreateObject();
                        unsigned                reason = 0;

                        /* Apply policy with empty facts, which will fail
                         */
                        action = policy_org_apply(org, 2, facts, &error, test_action, &reason);
                        ok(!action,                                                               "Error applying policy");
                        is_eq(cJSON_GetStringValue(error), "Internal error testing org 2 rule 0", "Got the expected error");
                        is(reason, 0,                                                             "No rule was matched");
                        cJSON_Delete(error);

                        /* Add sufficient facts to reach rule 3, which has code in its attributes, and fail to eval them
                         */
                        cJSON_AddStringToObject(facts, "endpoint.os.type",    "windows");
                        cJSON_AddStringToObject(facts, "endpoint.os.version", "10");
                        action = policy_org_apply(org, 2, facts, &error, test_action, &reason);
                        ok(!action,                                                                      "Error applying policy");
                        is_eq(cJSON_GetStringValue(error), "Failed to evaluate org 2 rule 3 attributes", "Got expected error");
                        is(reason, 3,                                                                    "Rule 1 last matched");
                        cJSON_Delete(error);

                        /* Add sufficient facts to pass rule 3
                         */
                        cJSON_AddArrayToObject(object, "endpoint.certificates");    // Empty cert list
                        action = policy_org_apply(org, 2, facts, &error, test_action, &reason);
                        ok(action,                                                   "Succeeded applying policy");
                        is(crl_identifier_equal_str(action, "block"), CRL_TEST_TRUE, "Action of matching rule is 'block'");
                        is(reason, 8,                                                "Rule 3 last matched");

                        cJSON_Delete(facts);
                    }
                }

                // This test covers policy_slotisempty
                is(rrmdir("policy-digest-dir"), 0, "Removed policy-digest-dir with no errors");
                is(mkdir("policy-digest-dir", 0755), 0, "Created policy-digest-dir");
                digest_store_changed(set);
                int lines = showdir("policy-digest-dir", stdout);
                is(lines, 2, "Found 2 line of data (1 policy file, 1 rules file) in policy-digest-dir directory");
            }
        }

        confset_release(set);
        unlink("test-policy-1");
        ok(confset_load(NULL), "Noted an update for the test-policy-1 removal");
    }

    diag("Test a V%u policy with global attributes", POLICY_VERSION);    // See DPT-1212
    {
        // Data taken from the latest sample, 'counter' corrected to 'count' and = to := in attribute lines
        create_atomic_file("test-policy-1",
            "rules %u\n"
            "count 2\n"
            "[global:1]\n"
            "expiry := time.superceded + 1209600, now := TIME(null)\n"
            "[rules:1]\n"
            "reason := 2\n"
            "expiry >= now: allow", POLICY_VERSION);

        ok(confset_load(NULL), "Noted an update to test-policy-1");
        ok(set = confset_acquire(&gen), "Acquired the config set that includes urlprefs");

        if (set) {
            ok(policy = policy_conf_get(set, CONF_POLICY), "Extracted the policy from the confset");

            if (policy) {
                cJSON *facts = cJSON_CreateObject();
                cJSON *error;

                cJSON_AddNumberToObject(facts, "time.superceded", (double)(time(NULL) - 10));
                ok(org = policy_find_org(policy, 1), "Found org 1 in the list");
                ok(policy_org_apply(org, 2, facts, &error, NULL, NULL), "Succeeded applying policy");
                cJSON_Delete(facts);

                ok(!policy_org_apply(org, 2, NULL, &error, NULL, NULL), "Failed to apply policy without the facts");
                is_eq(cJSON_GetStringValue(error), "Failed to evaluate org 2 global attributes", "Got the expected error");
                cJSON_Delete(error);
            }
        }

        confset_release(set);
        unlink("test-policy-1");
        ok(confset_load(NULL), "Noted an update for the test-policy-1 removal");
    }

    diag("Test a V%u policy with JSON only global attributes", POLICY_VERSION);    // Test for bug DPT-1295
    {
        // Data taken from the latest sample, 'counter' corrected to 'count' and = to := in attribute lines
        create_atomic_file("test-policy-1",
            "rules %u\n"
            "count 2\n"
            "[global:1]\n"
            "constant := 1\n"
            "[rules:1]\n"
            "reason := 2\n"
            "constant: (allow)", POLICY_VERSION);

        ok(confset_load(NULL), "Noted an update to test-policy-1");
        ok(set = confset_acquire(&gen), "Acquired the config set that includes urlprefs");

        if (set) {
            ok(policy = policy_conf_get(set, CONF_POLICY), "Extracted the policy from the confset");

            if (policy) {
                cJSON *facts = cJSON_CreateObject();
                cJSON *error;

                cJSON_AddNumberToObject(facts, "time.superceded", (double)(time(NULL) - 10));
                ok(org = policy_find_org(policy, 1), "Found org 1 in the list");
                ok(policy_org_apply(org, 2, facts, &error, NULL, NULL), "Succeeded applying policy");
                cJSON_Delete(facts);
            }
        }

        confset_release(set);
        unlink("test-policy-1");
        ok(confset_load(NULL), "Noted an update for the test-policy-1 removal");
    }

    OK_SXEL_ERROR(NULL);
    crl_parse_finalize_thread();
    crl_finalize();
    fileprefs_freehashes();
    confset_unload();
    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    /* KIT_ALLOC_SET_LOG(0); */

    unlink_test_policy_files();
    return exit_status();
}

