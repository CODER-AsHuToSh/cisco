#include <kit-alloc.h>
#include <mockfail.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "categorization.h"
#include "ccb.h"
#include "domainlist-private.h"
#include "prefbuilder.h"
#include "pref-overloads.h"
#include "uint32list.h"

#include "common-test.h"

#define ORIGINTYPE_NETWORK     1
#define ORIGINTYPE_ADGRP       3
#define ORIGINTYPE_ADHOST      5
#define ORIGINTYPE_ADUSER      7
#define ORIGINTYPE_ERC         9
#define ORIGINTYPE_VPN        11
#define ORIGINTYPE_VA         13
#define ORIGINTYPE_ADDOMAIN   15
#define ORIGINTYPE_ONNETWORK  17
#define ORIGINTYPE_INTNETWORK 19
#define ORIGINTYPE_SITE       21
#define ORIGINTYPE_ORG        22
#define ORIGINTYPE_DEVICE     24
#define ORIGINTYPE_POLICY     26
#define ORIGINTYPE_CONNECTOR  28
#define ORIGINTYPE_DC         30
#define ORIGINTYPE_NETDEV     32
#define ORIGINTYPE_ANYCONNECT 34

#define ELEMENTTYPES_DOMAIN PREF_LIST_ELEMENTTYPE_BIT(PREF_LIST_ELEMENTTYPE_DOMAIN)

int
main(void)
{
    char               buf[PREF_CATEGORIES_MAX_BITS * 8];
    uint64_t           start_allocations;
    list_pointer_t     lp1, lp2, lp3, lp4;
    struct prefbuilder pbuild;
    struct prefblock  *pblk;
    pref_categories_t  cat;
    const char        *dlstr;
    int                bit, i;
    pref_t             pr;

    plan_tests(201 + 3 * ((PREF_CATEGORIES_MAX_BITS + 11) / 12));

    conf_initialize(NULL, ".", false, NULL);
    kit_memory_initialize(false);
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    diag("### Test conversion functions");

    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_BPB),                         "BPB",                    "The BPB flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_CLOSED_NETWORK),              "CLOSED_NETWORK",         "The CLOSED_NETWORK flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_EXPIRED_RRS),                 "EXPIRED_RRS",            "The EXPIRED_RRS flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_URL_PROXY),                   "URL_PROXY",              "The URL_PROXY flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_SUSPICIOUS_RESPONSE),         "SUSPICIOUS_RESPONSE",    "The SUSPICIOUS_RESPONSE flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_TYPO_CORRECTION),             "TYPO_CORRECTION",        "The TYPO_CORRECTION flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_ALLOWLIST_ONLY),              "ALLOWLIST_ONLY",         "The ALLOWLIST_ONLY flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_NO_STATS),                    "NO_STATS",               "The NO_STATS flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_SECURITY_STATS_ONLY),         "SECURITY_STATS_ONLY",    "The SECURITY_STATS_ONLY flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_RATE_NON_CUSTOMER),           "RATE_NON_CUSTOMER",      "The RATE_NON_CUSTOMER flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_RATE_RESTRICTED),             "RATE_RESTRICTED",        "The RATE_RESTRICTED flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_SIG_FILE_INSPECTION),         "SIG_FILE_INSPECTION",    "The SIG_FILE_INSPECTION flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_SIG_AMP_INSPECTION),          "SIG_AMP_INSPECTION",     "The SIG_AMP_INSPECTION flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_SIG_TG_SANDBOX),              "SIG_TG_SANDBOX",         "The SIG_TG_SANDBOX flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_SAFE_SEARCH),                 "SAFE_SEARCH",            "The SAFE_SEARCH flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_SAML),                        "SAML",                   "The SAML flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_SWG_DISPLAY_BLOCK_PAGE),      "SWG_DISPLAY_BLOCK_PAGE", "The SWG_DISPLAY_BLOCK_PAGE flag text is correct");
    is_eq(pref_bundleflags_to_str(PREF_BUNDLEFLAGS_SWG_DISPLAY_BLOCK_PAGE << 1), "bit25",                  "An invalid flag bit shows as bitXX");

    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_PROXY_NEWLY_SEEN_DOMAINS >> 1),              "bit0",                                    "An invalid flag bit shows as bitXX");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_PROXY_NEWLY_SEEN_DOMAINS),                   "PROXY_NEWLY_SEEN_DOMAINS",                "The PROXY_NEWLY_SEEN_DOMAINS flag text is correct");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_INCLUDE_TALOS_CATEGORIES),                   "INCLUDE_TALOS_CATEGORIES",                "The INCLUDE_TALOS_CATEGORIES flag text is correct");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_GDPR_EU),                                    "GDPR_EU",                                 "The GDPR_EU flag text is correct");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_GDPR_US),                                    "GDPR_US",                                 "The GDPR_US flag text is correct");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_SWG_ENABLED),                                "SWG_ENABLED",                             "The SWG_ENABLED flag text is correct");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_REALTIME_DNS_TUNNEL_BLOCKING),               "REALTIME_DNS_TUNNEL_BLOCKING",            "The REALTIME_DNS_TUNNEL_BLOCKING flag text is correct");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_O365_BYPASS),                                "O365_BYPASS",                             "The O365_BYPASS flag text is correct");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_BYPASS_SWG_FROM_TUNNEL),                     "BYPASS_SWG_FROM_TUNNEL",                  "The BYPASS_SWG_FROM_TUNNEL flag text is correct");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_DNSSEC_ENFORCE_ENABLED),                     "DNSSEC_ENFORCE_ENABLED",                  "The DNSSEC_ENFORCE_ENABLED flag text is correct");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_ALL_DOMAINTAGGING),                          "ALL_DOMAINTAGGING",                       "Use domaintagging to categorize");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_HALF_DOMAINTAGGING),                         "HALF_DOMAINTAGGING",                      "Mask some domaintagging bits that overlap talos bits");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_RESEARCH_ALGORITHMS_CATEGORIZE),             "RESEARCH_ALGORITHMS_CATEGORIZE",          "The RESEARCH_ALGORITHMS_CATEGORIZE flag text is correct");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_RESEARCH_ALGORITHMS_BLOCKING),               "RESEARCH_ALGORITHMS_BLOCKING",            "The RESEARCH_ALGORITHMS_BLOCKING flag text is correct");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_AGGREGATE_REPORTING_ONLY),                   "AGGREGATE_REPORTING_ONLY",                "The AGGREGATE_REPORTING_ONLY flag text is correct");
    is_eq(pref_orgflags_to_str(PREF_ORGFLAGS_AGGREGATE_REPORTING_ONLY << 1),              "bit40",                                   "An invalid flag bit shows as bitXX");

    is(sizeof(elementtype_t), 1, "Element type fits in a byte");
    is(pref_list_name_to_elementtype("application"), PREF_LIST_ELEMENTTYPE_APPLICATION, "'application' list name correctly classified");
    is(pref_list_name_to_elementtype("cidr"),        PREF_LIST_ELEMENTTYPE_CIDR,        "'cidr' list name correctly classified");
    is(pref_list_name_to_elementtype("domain"),      PREF_LIST_ELEMENTTYPE_DOMAIN,      "'domain' list name correctly classified");
    is(pref_list_name_to_elementtype("url"),         PREF_LIST_ELEMENTTYPE_URL,         "'url' list name correctly classified");
    is(pref_list_name_to_elementtype("block"),       PREF_LIST_ELEMENTTYPE_INVALID,     "'block' list name classified as INVALID");

    struct preflist left  = {AT_LIST_DESTBLOCK, 0, PREF_LIST_ELEMENTTYPE_APPLICATION, LIST_POINTER_NULL, 0};
    struct preflist right = {AT_LIST_DESTALLOW, 1, PREF_LIST_ELEMENTTYPE_DOMAIN,      LIST_POINTER_NULL, 0};
    ok(preflist_element.cmp(&left, &right) < 0, "BLOCK < ALLOW");
    ok(preflist_element.cmp(&right, &left) > 0, "ALLOW > BLOCK");
    right.ltype = AT_LIST_DESTBLOCK;
    ok(preflist_element.cmp(&left, &right) < 0, "0 < 1");
    ok(preflist_element.cmp(&right, &left) > 0, "1 > 0");
    right.id = 0;
    ok(preflist_element.cmp(&left, &right) < 0, "APPLICATION < DOMAIN");
    ok(preflist_element.cmp(&right, &left) > 0, "DOMAIN > APPLICATION");
    right.elementtype = PREF_LIST_ELEMENTTYPE_APPLICATION;
    ok(preflist_element.cmp(&right, &left) == 0, "List keys are the same");

    struct preflist list_key = {AT_LIST_DESTALLOW, 0, PREF_LIST_ELEMENTTYPE_DOMAIN, LIST_POINTER_NULL, 0};
    is_eq(preflist_element.fmt(&list_key), "8:0:domain",   "List key correctly formatted");

    struct prefsettinggroup settinggroup_key;
    settinggroup_key.idx = 3;
    settinggroup_key.id  = 1;
    is_eq(prefsettinggroup_element.fmt(&settinggroup_key), "3:1", "Settinggroup key correctly formatted");

    struct preforg org_key;
    org_key.id = 10;
    is_eq(preforg_element.fmt(&org_key), "10", "Org key (id) correctly formatted");

    struct prefbundle bundle_key;
    bundle_key.actype = AT_LIST_URL_PROXY_HTTPS;
    bundle_key.id     = ~0U;
    is_eq(prefbundle_element.fmt(&bundle_key), "C:4294967295", "Bundle key correctly formatted");

    diag("### Test categories functions");

    for (bit = 1; bit < PREF_CATEGORIES_MAX_BITS; bit += 12) {
        pref_categories_setnone(&cat);
        pref_categories_setbit(&cat, bit);
        ok(!pref_categories_isnone(&cat), "pref_categories_setbit(cat, %d) makes 'cat' not none", bit);
        is(pref_categories_getbit(&cat, bit), 1, "pref_categories_setbit(cat, 1) set bit 1");
        ok(pref_categories_isnone_ignorebit(&cat, bit), "pref_categories_isnone_ignorebit(cat, bit) bit 1 others none");
        pref_categories_unsetbit(&cat, bit);
        ok(pref_categories_isnone(&cat), "pref_categories_unsetbit(cat, %d) makes 'cat' none", bit);
    }

    pref_categories_setnone(&cat);
    pref_categories_setbit(&cat, PREF_CATEGORIES_MAX_BITS);
    ok(pref_categories_isnone(&cat), "pref_categories_setbit(cat, %u) doesn't do anything", PREF_CATEGORIES_MAX_BITS);

    pref_categories_setall(&cat);
    MOCKFAIL_START_TESTS(1, CCB_PREF_CATEGORIES_STR_EXTEND);
    is_eq(ccb_pref_categories_str(NULL, &cat), "<pref-categories-reallocation-error>",
          "pref_categories cannot display itself when ccb_pref_categories_str() fails to extend allocate");
    MOCKFAIL_END_TESTS();

    for (i = bit = 0; bit < PREF_CATEGORIES_MAX_BITS; bit++) {
        snprintf(buf + i, sizeof(buf) - i, "%sbit%d", i ? ", " : "", bit);
        i += strlen(buf + i);
    }

    is_eq(ccb_pref_categories_str(NULL, &cat), buf, "pref_categories can display itself when the ccb_pref_categories_str() allocation succeeds");
    is(pref_categories_getbit(&cat, PREF_CATEGORIES_MAX_BITS), 0, "Bit %u isn't set after pref_categories_setall(cat)", PREF_CATEGORIES_MAX_BITS);

    diag("### Test prefbuilder");

    prefbuilder_init(&pbuild, PREFBUILDER_FLAG_NONE, NULL, NULL);
    MOCKFAIL_START_TESTS(1, prefbuilder_alloclist);
    ok(!prefbuilder_alloclist(&pbuild, 64), "Cannot allocate lists when realloc fails"); // Do here because lists are no longer dynamic
    MOCKFAIL_END_TESTS();
    ok(prefbuilder_alloclist(&pbuild, 0),  "Allocate no list blocks");
    ok(!prefbuilder_addlist(&pbuild, AT_ORIGIN | AT_LIST_DESTBLOCK, 50, PREF_LIST_ELEMENTTYPE_DOMAIN, LIST_POINTER_NULL, 50),
       "Failed to add list when there are no more list blocks");
    ok(!prefbuilder_disclist(&pbuild, AT_ORIGIN | AT_LIST_DESTBLOCK, 666, PREF_LIST_ELEMENTTYPE_CIDR),
       "Failed to discard a list when there are no more list blocks");
    ok(prefbuilder_alloclist(&pbuild, 64), "Allocate plenty of list blocks (previously, these were dynamic)");

    ok(!prefbuilder_attachlist(&pbuild, 1234, AT_ORIGIN | AT_LIST_DESTBLOCK, 1234, ELEMENTTYPES_DOMAIN), "Cannot attach a list to a non-existent bundle");

    MOCKFAIL_START_TESTS(1, prefbuilder_allocbundle);
    ok(!prefbuilder_allocbundle(&pbuild, 2), "As expected, failed to allocate space for bundles");
    MOCKFAIL_END_TESTS();
    ok(prefbuilder_allocbundle(&pbuild, 2), "Allocated space for 2 bundles");

    uint32_t sgids_111_222[SETTINGGROUP_IDX_COUNT] = {111, 222, 0, 0};
    uint32_t sgids_zero[SETTINGGROUP_IDX_COUNT] = {0, 0, 0, 0};
    ok(prefbuilder_addbundle(&pbuild, AT_ORIGIN, 1234, 0, 0x00, &cat, sgids_111_222), "Added bundle 1234 to prefbuilder");
    ok(!prefbuilder_addbundle(&pbuild, AT_ORIGIN, 1233, 0, 0x00, &cat, sgids_zero), "Cannot add bundle 1233 - bundles must be sorted");
    ok(!prefbuilder_addbundle(&pbuild, AT_ORIGIN, 1234, 0, 0x00, &cat, sgids_zero), "Cannot re-add bundle 1234 - bundles must be unique");

    MOCKFAIL_START_TESTS(1, prefbuilder_attach);
    ok(!prefbuilder_attachlist(&pbuild, 1234, AT_ORIGIN | AT_LIST_DESTBLOCK, 1234, ELEMENTTYPES_DOMAIN), "Failed to attach the bundle on realloc failure");
    MOCKFAIL_END_TESTS();
    ok(prefbuilder_attachlist(&pbuild, 1234, AT_ORIGIN | AT_LIST_DESTBLOCK, 1234, ELEMENTTYPES_DOMAIN), "Attached the bundle to a non-existent list");

    for (i = 0; i < 18; i++) {    // Saturate the chunk that's already been allocated
        prefbuilder_attachlist(&pbuild, 1234, AT_ORIGIN | AT_LIST_DESTBLOCK, 1235 + i, ELEMENTTYPES_DOMAIN);
    }

    MOCKFAIL_START_TESTS(1, prefbuilder_attach);
    ok(!prefbuilder_attachlist(&pbuild, 1234, AT_ORIGIN | AT_LIST_DESTBLOCK, 1235 + 18, ELEMENTTYPES_DOMAIN), "Failed to attach the bundle on realloc failure");
    MOCKFAIL_END_TESTS();

    ok(!prefbuilder_addidentity(&pbuild, 42, ORIGINTYPE_NETWORK, 2, AT_ORIGIN, 1234), "Cannot add an identity when there's no room");
    pref_categories_setnone(&cat);
    MOCKFAIL_START_TESTS(1, prefbuilder_allocorg);
    ok(!prefbuilder_allocorg(&pbuild, 3), "Failed to alloc org when allocorg fails");
    MOCKFAIL_END_TESTS();
    ok(prefbuilder_allocorg(&pbuild, 3), "Allocated space for orgs");
    ok(prefbuilder_addorg(&pbuild, 2, 1234, &cat, 365, 0, 1002, 0), "Added org 2 to prefbuilder");
    ok(prefbuilder_addorg(&pbuild, 3, 5678, &cat, 365, 0, 1003, 0), "Added org 3 to prefbuilder");
    ok(!prefbuilder_addorg(&pbuild, 1, 5678, &cat, 365, 0, 1001, 0), "Failed to add out-of-order org 1 to prefbuilder");
    pref_categories_setbit(&cat, 85);
    ok(!prefbuilder_addorg(&pbuild, 2, 1234, &cat, 365, 0, 1002, 0), "Cannot add org 2 a second time");
    ok(!prefbuilder_addorg(&pbuild, 3, 1234, &cat, 365, 0, 1003, 0), "Cannot add org 3 a second time");
    MOCKFAIL_START_TESTS(1, prefbuilder_allocident);
    ok(!prefbuilder_allocident(&pbuild, 1), "Failed to expand prefbuilder to 1 identity when malloc fails");
    MOCKFAIL_END_TESTS();
    ok(prefbuilder_allocident(&pbuild, 1), "Expanded prefbuilder to 1 identity");
    ok(!prefbuilder_consume(&pbuild),      "Cannot consume an incomplete prefbuilder");
    ok(!prefbuilder_addidentity(&pbuild, 42, ORIGINTYPE_DEVICE, 2, AT_ORIGIN, 999), "Failed to point an identity at a non-existent bundle");

    dlstr = "google.com  cnn.com\tnews.yahoo.com";
    lp1.domainlist = domainlist_new_from_buffer(dlstr, strlen(dlstr), NULL, LOADFLAGS_NONE);
    lp2.applicationlist = uint32list_new("1 2 3 4 5", NULL);

    MOCKFAIL_START_TESTS(1, kit_sortedarray_add);
    ok(!prefbuilder_disclist(&pbuild, AT_LIST_DESTBLOCK, 7157, PREF_LIST_ELEMENTTYPE_CIDR), "Cannot allocate a discard list when realloc fails");
    MOCKFAIL_END_TESTS();

    ok(prefbuilder_addlist(&pbuild, AT_ORIGIN | AT_LIST_DESTBLOCK, 50, PREF_LIST_ELEMENTTYPE_DOMAIN, LIST_POINTER_NULL, 50), "Added NULL list 50 called 'nulllist' using bit 50");
    ok(!prefbuilder_addlist(&pbuild, AT_ORIGIN | AT_LIST_DESTBLOCK, 99, PREF_LIST_ELEMENTTYPE_APPLICATION, lp2, 99), "Cannot add an application list as a destination list");
    ok(!prefbuilder_addlist(&pbuild, AT_ORIGIN | AT_LIST_APPBLOCK, 99, PREF_LIST_ELEMENTTYPE_DOMAIN, lp1, 99), "Cannot add a domain list as an app list");
    ok(prefbuilder_addlist(&pbuild, AT_ORIGIN | AT_LIST_DESTBLOCK, 99, PREF_LIST_ELEMENTTYPE_DOMAIN, lp1, 99), "Added list 99 called 'mylist' using bit 99");
    ok(!prefbuilder_addlist(&pbuild, AT_ORIGIN | AT_LIST_DESTBLOCK, 98, PREF_LIST_ELEMENTTYPE_DOMAIN, lp1, 0), "Cannot add list 98 - lists must be sorted");
    ok(!prefbuilder_addlist(&pbuild, AT_ORIGIN | AT_LIST_DESTBLOCK, 99, PREF_LIST_ELEMENTTYPE_DOMAIN, lp1, 99), "Cannot re-add list 99 - lists must be unique");
    ok(prefbuilder_addlist(&pbuild, AT_ORIGIN | AT_LIST_DESTBLOCK, 100, PREF_LIST_ELEMENTTYPE_DOMAIN, lp1, 0), "Added list 100 called 'nextlist' using no bit");
    ok(prefbuilder_addlist(&pbuild, AT_ORIGIN | AT_LIST_DESTALLOW, 199, PREF_LIST_ELEMENTTYPE_DOMAIN, lp1, 199), "Added list 199 called 'otherlist' using bit 199");
    ok( prefbuilder_attachlist(&pbuild, 1234, AT_ORIGIN | AT_LIST_DESTBLOCK, 99,  ELEMENTTYPES_DOMAIN), "Attached list 99 to bundle 1234");
    ok(!prefbuilder_attachlist(&pbuild, 1234, AT_ORIGIN | AT_LIST_DESTBLOCK, 99,  ELEMENTTYPES_DOMAIN), "Can't list 99 to bundle 1234 a second time");
    ok( prefbuilder_attachlist(&pbuild, 1234, AT_ORIGIN | AT_LIST_DESTALLOW, 199, ELEMENTTYPES_DOMAIN), "Attached list 199 to bundle 1234");
    ok(!prefbuilder_attachlist(&pbuild, 1234, AT_ORIGIN | AT_LIST_DESTBLOCK, 100, ELEMENTTYPES_DOMAIN), "Failed to attach list 100 to bundle 1234 - bundle 1234's blocklist is not the last listref entry");
    ok( prefbuilder_attachlist(&pbuild, 1234, AT_ORIGIN | AT_LIST_DESTALLOW, 200, ELEMENTTYPES_DOMAIN), "Attached external list 666 to bundle 1234");
    ok(!prefbuilder_attachlist(&pbuild, 1234, AT_ORIGIN | AT_LIST_DESTALLOW, 200, ELEMENTTYPES_DOMAIN), "Failed to attach duplicate external list 666 to bundle 1234");
    ok(prefbuilder_disclist(&pbuild, AT_ORIGIN | AT_LIST_DESTBLOCK, 666, PREF_LIST_ELEMENTTYPE_CIDR), "Successfully discarded a list");
    ok(!prefbuilder_disclist(&pbuild, AT_ORIGIN | AT_LIST_DESTBLOCK, 666, PREF_LIST_ELEMENTTYPE_CIDR), "Can't discard the same list twice");
    ok(!prefbuilder_disclist(&pbuild, AT_ORIGIN | AT_LIST_DESTBLOCK, 665, PREF_LIST_ELEMENTTYPE_CIDR), "Can't discard a list out of order");

    /* prefbuilder_free() will domainlist_refcount_dec() every domainlist!  Bump our count by 3 for the other 3 successful adds above! */
    for (i = 0; i < 3; i++)
        domainlist_refcount_inc(lp1.domainlist);

    prefbuilder_fini(&pbuild);
    is(lp1.domainlist->conf.refcount, 1, "prefbuilder_free() consumed 5 domainlist refcounts");

    diag("### Test a pref_t with an empty prefblock");
    {
        prefbuilder_init(&pbuild, 0, NULL, NULL);
        ok(prefbuilder_allocident(&pbuild, 1), "Allocated 1 identity for prefbuilder");         /* Count must be at least 1 */
        ok(prefbuilder_alloclist(&pbuild, 64),      "Allocate plenty of list blocks (previously, these were dynamic)");
        ok(prefbuilder_allocbundle(&pbuild, 1),     "Allocated space for 1 bundle");
        ok(prefbuilder_addbundle(&pbuild, AT_BUNDLE, 0, 0, 0, &cat, sgids_zero), "Added minimal bundle to prefbuilder");
        ok(prefbuilder_addidentityforbundle(&pbuild, 0, ORIGINTYPE_SITE, 0, 0, 0), "Added a minimal identity");
        MOCKFAIL_START_TESTS(1, prefbuilder_consume);
        ok(!prefbuilder_consume(&pbuild), "Cannot consume the prefbuilder if malloc fails");
        MOCKFAIL_END_TESTS();
        ok(pblk = prefbuilder_consume(&pbuild), "Consumed the minimal prefbuilder");             /* Implicitly finis prefbuilder */
        pref_init_byidentity(&pr, pblk, NULL, NULL, 0);
        is_eq(pref_sorted_list(&pr, AT_LIST_DESTBLOCK), "", "Got back an empty list from the minimal pref");
        prefblock_free(pblk);
    }

    diag("### Test prefbuilder that doesn't allow external refs");

    prefbuilder_init(&pbuild, PREFBUILDER_FLAG_NO_EXTERNAL_REFS, NULL, NULL);
    MOCKFAIL_START_TESTS(1, prefbuilder_allocident);
    ok(!prefbuilder_allocident(&pbuild, 1), "Identity allocation fails");
    MOCKFAIL_END_TESTS();

    ccb_pref_categories_str(NULL, NULL);

    ok(prefbuilder_allocident(&pbuild, 1), "Allocated space for 1 identity");
    ok(prefbuilder_alloclist(&pbuild, 64), "Allocated space for exactly 1 list");
    ok(prefbuilder_addlist(&pbuild, AT_BUNDLE | AT_LIST_DESTBLOCK, 98, PREF_LIST_ELEMENTTYPE_DOMAIN, lp1, 71), "Added a block list with id 98 as bit 71");
    ok(prefbuilder_allocbundle(&pbuild, 2), "Allocated space for exactly 2 bundles");
    uint32_t sgids_555[SETTINGGROUP_IDX_COUNT] = {555, 0, 0, 0};
    ok(prefbuilder_addbundle(&pbuild, AT_BUNDLE, 1233, 0, 0x00, &cat, sgids_555), "Added a bundle with a catid - it was actually dangling and was ignored");
    uint32_t sgids_0_555[SETTINGGROUP_IDX_COUNT] = {0, 555, 0, 0};
    ok(prefbuilder_addbundle(&pbuild, AT_BUNDLE, 1234, 0, 0x00, &cat, sgids_0_555), "Added a bundle with a secid - it was actually dangling and was ignored");
    ok(prefbuilder_allocorg(&pbuild, 1), "Allocated space for exactly 1 org");
    ok(prefbuilder_addorg(&pbuild, 1, 0, &cat, 365, 0, 1001, 0), "Added org 1 to prefbuilder");
    ok(prefbuilder_attach(&pbuild, 0, AT_BUNDLE | AT_LIST_DESTBLOCK, 99, ELEMENTTYPES_DOMAIN), "Attached external list 99 to bundle 1233 (index 0) - it was actually dangling and was ignored");
    ok(prefbuilder_attach(&pbuild, 0, AT_BUNDLE | AT_LIST_DESTBLOCK, 98, ELEMENTTYPES_DOMAIN), "Attached internal list 98 to bundle 1233 (index 0)");
    ok(prefbuilder_addidentityforbundle(&pbuild, 42, ORIGINTYPE_VA, 1, AT_BUNDLE, ELEMENTTYPES_DOMAIN), "Added an identity pointing at org 1 and bundle item 0 (1233)");
    ok(pblk = prefbuilder_consume(&pbuild), "Consumed the prefbuilder");

    prefblock_free(pblk);
    is(lp1.domainlist->conf.refcount, 1, "prefblock_free() didn't decerement domainlist refcounts");
    domainlist_refcount_dec(lp1.domainlist);
    uint32list_refcount_dec(lp2.applicationlist);

    diag("Cover external list references and more");
    {
        pref_categories_t  match;
        struct prefblock  *gblk;        // Point to the global org's prefblock (needs to be external to cover extlist code)
        struct prefblock  *blk;         // Point to the end user org's prefblock; msp org's prefblock will be pblk
        unsigned           elementtypes;
        uint32_t           settinggroups_ids[SETTINGGROUP_IDX_COUNT] = {0, 0, 0, 0 ,0};

        pref_set_globalorg(2);
        ok(blk = prefblock_new_empty(1), "Create an empty pref block for coverage only");
        prefblock_free(blk);

        elementtypes = PREF_LIST_ELEMENTTYPE_BIT(PREF_LIST_ELEMENTTYPE_DOMAIN)
                     | PREF_LIST_ELEMENTTYPE_BIT(PREF_LIST_ELEMENTTYPE_APPLICATION);
        ok(lp1.domainlist      = domainlist_new_from_buffer(".", 1, NULL, 0), "Created a domainlist with '.'");
        ok(lp2.applicationlist = uint32list_new("80085", NULL),               "Created a applicationlist with '80085'");
        ok(lp3.applicationlist = uint32list_new("80061",  NULL),              "Created a applicationlist with '80061'");
        ok(lp4.applicationlist = uint32list_new("8020",  NULL),               "Created a applicationlist with '8020'");

        /* Create an external global org with a domainlist and an application list
         */
        pref_categories_setnone(&cat);
        prefbuilder_init(&pbuild, PREFBUILDER_FLAG_NONE, NULL, NULL);
        ok(prefbuilder_alloclist(&pbuild, 2),                                                              "Alloced two lists");
        ok(prefbuilder_addlist(&pbuild, AT_LIST_DESTBLOCK, 666, PREF_LIST_ELEMENTTYPE_DOMAIN, lp1, 1),     "Added domain list");
        ok(prefbuilder_addlist(&pbuild, AT_LIST_APPBLOCK, 667, PREF_LIST_ELEMENTTYPE_APPLICATION, lp2, 2), "Added app list");
        ok(prefbuilder_allocsettinggroup(&pbuild, 1),                                   "Allocated space for one settinggroup");
        ok(prefbuilder_addsettinggroup(&pbuild, 1, 22, 0, &cat, &cat, &cat),            "Added a security setting group");
        ok(prefbuilder_allocbundle(&pbuild, 1),                                         "Allocated space for one bundle");
        ok(prefbuilder_addbundle(&pbuild, AT_BUNDLE, 0, 0, 0, &cat, settinggroups_ids), "Added the bundle");
        ok(prefbuilder_allocorg(&pbuild, 1),                                            "Allocated space for one org");
        ok(prefbuilder_addorg(&pbuild, 2, PREF_ORGFLAGS_PROXY_NEWLY_SEEN_DOMAINS, &cat, 0, 0, 0, 0), "Added the global org");
        ok(gblk = prefbuilder_consume(&pbuild),                                                      "Built the prefblock");

        /* Create an external parent org with an application list
         */
        pref_categories_setnone(&cat);
        prefbuilder_init(&pbuild, PREFBUILDER_FLAG_NONE, NULL, NULL);
        ok(prefbuilder_alloclist(&pbuild, 1),                                                              "Alloced one list");
        ok(prefbuilder_addlist(&pbuild, AT_LIST_APPBLOCK, 668, PREF_LIST_ELEMENTTYPE_APPLICATION, lp3, 3), "Added app list");
        ok(prefbuilder_allocbundle(&pbuild, 1),                                         "Allocated space for one bundle");
        ok(prefbuilder_addbundle(&pbuild, AT_BUNDLE, 0, 0, 0, &cat, settinggroups_ids), "Added the bundle");
        ok(prefbuilder_allocorg(&pbuild, 1),                                            "Allocated space for one org");
        ok(prefbuilder_addorg(&pbuild, 3, PREF_ORGFLAGS_PROXY_NEWLY_SEEN_DOMAINS, &cat, 0, 0, 0, 0), "Added the parent org");
        ok(pblk = prefbuilder_consume(&pbuild),                                                      "Built the prefblock");

        /* Now create the end user org with another application list, and link the external lists
         */
        prefbuilder_init(&pbuild, PREFBUILDER_FLAG_NONE, NULL, NULL);
        ok(prefbuilder_alloclist(&pbuild, 1),                                                              "Alloced one list");
        ok(prefbuilder_addlist(&pbuild, AT_LIST_APPBLOCK, 669, PREF_LIST_ELEMENTTYPE_APPLICATION, lp4, 4), "Added app list");
        ok(prefbuilder_allocbundle(&pbuild, 1),                                         "Allocated space for one bundle");
        settinggroups_ids[1] = 22;
        ok(prefbuilder_addbundle(&pbuild, AT_BUNDLE, 1, 0, 0, &cat, settinggroups_ids), "Added the bundle");
        ok(prefbuilder_attachlist(&pbuild, 1, AT_LIST_DESTBLOCK, 666, elementtypes),
           "Attached the external domain list to the bundle");
        ok(prefbuilder_attachlist(&pbuild, 1, AT_LIST_APPBLOCK, 667, elementtypes),
           "Attached the external application list to the bundle");
        ok(prefbuilder_attachlist(&pbuild, 1, AT_LIST_APPBLOCK, 668, elementtypes),
           "Attached the external application list to the bundle");
        ok(prefbuilder_attachlist(&pbuild, 1, AT_LIST_APPBLOCK, 669, elementtypes),
           "Attached the internal application list to the bundle");
        ok(prefbuilder_allocorg(&pbuild, 1),                                                         "Allocated space for org");
        ok(prefbuilder_addorg(&pbuild, 4, PREF_ORGFLAGS_PROXY_NEWLY_SEEN_DOMAINS, &cat, 0, 0, 2, 3), "Added the org");
        ok(blk = prefbuilder_consume(&pbuild),                                                       "Built the prefblock");

        pref_init_bybundle(&pr, blk, pblk, gblk, 4, 0);
        ok(!pref_proxy_newly_seen_domain(&pr, &cat, (const uint8_t *)"", NULL), ". is not a newly seen domain to be proxied");
        pref_categories_setbit(&cat, CATEGORY_BIT_NEWLY_SEEN_DOMAINS);
        ok(pref_proxy_newly_seen_domain(&pr, &cat, (const uint8_t *)"", NULL),  ". is a newly seen domain to be proxied");

        ok(pref_domainlist_match(&pr, &cat, AT_LIST_DESTBLOCK, (const uint8_t *)"", DOMAINLIST_MATCH_EXACT, NULL),
           ". matched the block list");

        module_conf_t                mod = 0;
        int                          gen = 0;
        struct confset              *set;
        const struct categorization *categ;

        categorization_register(&mod, "cat", "catfile", true);
        ok(mod != 0, "Registered cat/catfile as configuration");
        create_atomic_file("catfile", "categorization 1\napplication:application:application/application.%%u:148::\n");
        mkdir("application", 0777);
        create_atomic_file("application/application.80085",
                           "lists 1\ncount 3\n[meta:1]\nname appy\n[domains:1]\nxxx\n[urls:1]\nwww/index.html");
        create_atomic_file("application/application.80061",
                           "lists 1\ncount 3\n[meta:1]\nname boogi\n[domains:1]\naaa\n[urls:1]\nbbb/index.html");
        create_atomic_file("application/application.8020",
                           "lists 1\ncount 3\n[meta:1]\nname bozo\n[domains:1]\nyyy\n[urls:1]\nzzz/index.html");

        ok(confset_load(NULL),                        "Loaded cat/catfile");
        ok(set   = confset_acquire(&gen),             "Acquired a confset");
        ok(categ = categorization_conf_get(set, mod), "Got categorization from confset");
        pref_categories_setnone(&match);
        pref_categories_setbit(&cat, 148);
        is(pref_applicationlist_domain_match(&pr, &match, AT_LIST_APPBLOCK, (const uint8_t *)"\3xxx", &cat, categ, set, NULL),
           80085, "xxx matched a DNS name in the external global application block list");
        is_eq(pref_categories_idstr(&match), "10000000000000000000000000000000000004", "Expected match");
        is(pref_applicationlist_domain_match(&pr, &match, AT_LIST_APPBLOCK, (const uint8_t *)"\3aaa", &cat, categ, set, NULL),
           80061, "aaa matched a DNS name in the external parent application block list");
        is_eq(pref_categories_idstr(&match), "1000000000000000000000000000000000000C", "Matches are cumulative");
        is(pref_applicationlist_domain_match(&pr, &match, AT_LIST_APPBLOCK, (const uint8_t *)"\3yyy", &cat, categ, set, NULL),
           8020, "yyy matched a DNS name in the internal application block list");
        is_eq(pref_categories_idstr(&match), "1000000000000000000000000000000000001C", "Matches are cumulative");

        is(pref_applicationlist_proxy(&pr, (const uint8_t *)"\3www", AT_LIST_APPBLOCK, categ, set, NULL), 80085,
           "www matched a URL in the external application block list");
        is(pref_applicationlist_proxy(&pr, (const uint8_t *)"\3bbb", AT_LIST_APPBLOCK, categ, set, NULL), 80061,
           "bbb matched a URL in the external application block list");
        is(pref_applicationlist_proxy(&pr,(const uint8_t *)"\3zzz",  AT_LIST_APPBLOCK, categ, set, NULL), 8020,
           "zzz matched a URL the internal application block list");
        pref_unmasked(&pr, &cat);
        is_eq(pref_categories_idstr(&cat), "0", "Unmasked categories");

        confset_release(set);

        diag("Test cooking with overloads");
        {
            pref_t listener_pref;

            pref_overloads_register(&CONF_PREF_OVERLOADS, "pref-overloads", "test-pref-overloads", true);
            create_atomic_file("test-pref-overloads",
                               "pref-overloads %d\n"
                               "country:IT:d:fffffffffffffff2:e:0:f:0\n", PREF_OVERLOADS_VERSION);
            ok(confset_load(NULL),            "Loaded cat/catfile");
            ok(set   = confset_acquire(&gen), "Acquired a confset");
            pref_init_bybundle(&listener_pref, gblk, NULL, NULL, 2, 0);    // Pref block must include an org
            pref_init_bybundle(&pr, pblk, NULL, NULL, 4, 0);
            pref_cook_with_overloads(&pr, &listener_pref, 0, 0, &cat, "IT", 0, set);    // Must not include an org
            is(pr.cooked, PREF_COOK_BOIL, "prefs are fully cooked (country IT)");

            pref_init_bybundle(&pr, pblk, NULL, NULL, 4, 0);
            pref_cook_with_overloads(&pr, &listener_pref, 0, 0, &cat, "IT", 100, set);  // Must not include an org
            is(pr.cooked, PREF_COOK_BOIL, "prefs are fully cooked (region IT-100)");

            pref_init_bybundle(&pr, pblk, NULL, NULL, 4, 0);
            pref_cook_with_overloads(&pr, &listener_pref, 0, 0, &cat, "XX", 0, set);    // Cook without a country
            is(pr.cooked, PREF_COOK_BOIL, "prefs are fully cooked (country XX)");
        }

        domainlist_refcount_dec(lp1.domainlist);
        uint32list_refcount_dec(lp2.applicationlist);
        uint32list_refcount_dec(lp3.applicationlist);
        uint32list_refcount_dec(lp4.applicationlist);
        prefblock_free(gblk);
        prefblock_free(pblk);
        prefblock_free(blk);
        confset_release(set);
        confset_unload();    // Finalize conf subsytem
    }

    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
