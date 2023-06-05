#include <fcntl.h>
#include <kit-alloc.h>
#include <mockfail.h>
#include <openssl/sha.h>
#include <tap.h>

#include "cidrlist.h"
#include "conf-info.h"
#include "conf-loader.h"
#include "uup-counters.h"
#include "kit-random.h"
#include "object-hash.h"

#include "common-test.h"

enum test_type {
    TEST_STRING,
    TEST_FILE
};

#define TEST_TYPE_TXT(type) ((type) == TEST_STRING ? "string" : "file")

struct object_fingerprint of;
uint8_t hashfp[SHA_DIGEST_LENGTH];

static struct cidrlist *
get_cidrlist(enum test_type type, const char *data, enum cidr_parse how, struct conf_loader *cfgl)
{
    const char *consumed;
    struct cidrlist *cl;
    const char *fn;
    SHA_CTX sha;

    if (type == TEST_STRING) {
        SHA1_Init(&sha);
        SHA1_Update(&sha, data, strlen(data));
        SHA1_Final(hashfp, &sha);
        of.fp = hashfp;
        of.len = sizeof(hashfp);
        return cidrlist_new_from_string(data, " \t\n", &consumed, &of, how);
    }

    fn = create_data("test-cidrlist", "%s", data);
    conf_loader_open(cfgl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
    cl = cidrlist_new_from_file(cfgl, how);
    unlink(fn);
    return cl;
}

int
main(void)
{
    enum test_type     all_types[] = { TEST_STRING, TEST_FILE };
    uint64_t           start_allocations;
    struct conf_loader cfgl;
    struct netsock     sock;
    struct cidrlist   *cl;
    struct conf       *conf;
    struct conf_info   conf_info;
    module_conf_t      CONF_CIDRLIST, CONF_IPLIST;
    char               ascii[256];
    unsigned           i;

    plan_tests(213);

    conf_initialize(".", ".", false, NULL);
    kit_memory_initialize(false);
    uup_counters_init();
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    conf_loader_init(&cfgl);
    kit_random_init(open("/dev/urandom", O_RDONLY));

    diag("Test integration with the conf subsystem");
    {
        cidrlist_register(&CONF_CIDRLIST, "cidrlist", "cidrlist", true);
        ok(!cidrlist_conf_get(NULL, CONF_CIDRLIST), "Failed to get cidrlist from a NULL confset");
        conf_unregister(CONF_CIDRLIST);
        iplist_register(&CONF_IPLIST, "iplist", "iplist", true);
        ok(!iplist_conf_get(NULL, CONF_IPLIST), "Failed to get cidrlist from a NULL confset");
        conf_unregister(CONF_IPLIST);
    }

    diag("Test empty file load using the private cidrlist_allocate function");
    {
        conf_loader_open(&cfgl, "/dev/null", NULL, NULL, 0, CONF_LOADER_DEFAULT);
        conf_info.loadflags = LOADFLAGS_CIDRLIST_CIDR | LOADFLAGS_CIDRLIST_IP;
        conf_info.type      = cidrlist_get_real_type_internals(NULL);
        conf                = conf_info.type->allocate(&conf_info, &cfgl);
        ok(conf, "Read an empty file and allocated a cidrlist for it");
        cl = (struct cidrlist *)((char *)conf - offsetof(struct cidrlist, conf));
        is(cl->conf.refcount, 1, "The cidrlist has a refcount of 1");
        cidrlist_refcount_inc(cl);
        is(cl->conf.refcount, 2, "The cidrlist can increment its reference count");
        cidrlist_refcount_dec(cl);
        is(cl->conf.refcount, 1, "The cidrlist can decrement its reference count");
        cidrlist_refcount_dec(cl);
    }

    for (i = 0; i < sizeof all_types / sizeof *all_types; i++) {
        diag("Test garbage %s", TEST_TYPE_TXT(all_types[i]));
        {
            cl = get_cidrlist(all_types[i], "This is not the correct format\n", PARSE_IP_OR_CIDR, &cfgl);
            ok(!cl, "Failed to read garbage %s", TEST_TYPE_TXT(all_types[i]));
        }

        diag("Test IP %s", TEST_TYPE_TXT(all_types[i]));
        {
            const char *data = "1.2.3.4\n5.6.7.8\n::1\n::3\n";
            cl = get_cidrlist(all_types[i], data, PARSE_IP_ONLY, &cfgl);

            ok(cl, "Read a %s containing only IPs using PARSE_IP_ONLY", TEST_TYPE_TXT(all_types[i]));
            netaddr_from_str(&sock.a, "1.2.3.4", AF_INET);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 1.2.3.4 in the resulting list");
            netaddr_from_str(&sock.a, "1.2.3.5", AF_INET);
            ok(!cidrlist_search(cl, &sock.a, NULL, NULL), "Didn't find 1.2.3.5 in the resulting list");
            netaddr_from_str(&sock.a, "5.6.7.8", AF_INET);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 5.6.7.8 in the resulting list");
            netaddr_from_str(&sock.a, "::1", AF_INET6);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found ::1 in the resulting list");
            netaddr_from_str(&sock.a, "::2", AF_INET6);
            ok(!cidrlist_search(cl, &sock.a, NULL, NULL), "Didn't find ::2 in the resulting list");
            netaddr_from_str(&sock.a, "::3", AF_INET6);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found ::3 in the resulting list");
            cidrlist_refcount_dec(cl);

            cl = get_cidrlist(all_types[i], data, PARSE_IP_OR_CIDR, &cfgl);
            ok(cl, "Read a %s containing only IPs using PARSE_IP_OR_CIDR", TEST_TYPE_TXT(all_types[i]));
            cidrlist_refcount_dec(cl);

            MOCKFAIL_START_TESTS(1, cidrlist_new);
            cl = get_cidrlist(all_types[i], data, PARSE_IP_OR_CIDR, &cfgl);
            ok(!cl, "Failed to read a %s containing only IPs using PARSE_IP_OR_CIDR when cidrlist_new_empty() fails", TEST_TYPE_TXT(all_types[i]));
            MOCKFAIL_END_TESTS();

            MOCKFAIL_START_TESTS(1, CIDRLIST_ADD4);
            cl = get_cidrlist(all_types[i], data, PARSE_IP_OR_CIDR, &cfgl);
            ok(!cl, "Failed to read a %s containing only IPs using PARSE_IP_OR_CIDR when cidrlist_add(v4) fails", TEST_TYPE_TXT(all_types[i]));
            MOCKFAIL_END_TESTS();

            MOCKFAIL_START_TESTS(1, CIDRLIST_ADD6);
            cl = get_cidrlist(all_types[i], data, PARSE_IP_OR_CIDR, &cfgl);
            ok(!cl, "Failed to read a %s containing only IPs using PARSE_IP_OR_CIDR when cidrlist_add(v6) fails", TEST_TYPE_TXT(all_types[i]));
            MOCKFAIL_END_TESTS();

            cl = get_cidrlist(all_types[i], data, PARSE_CIDR_ONLY, &cfgl);
            ok(!cl, "Couldn't read a %s containing only IPs using PARSE_CIDR_ONLY", TEST_TYPE_TXT(all_types[i]));
        }

        diag("Test IP %s", TEST_TYPE_TXT(all_types[i]));
        {
            struct cidrlist *excl_all, *excl_some;
            struct netsock got0, got1, got2, tmp;
            const char *data = "1.2.3.4\n"
                               "1.2.3.5\n"
                               "5.6.7.8\n"
                               "2001:470:e83b:9a:240:f4ff:feb1:1c85\n"
                               "2001:470:e83b:9a::1\n"
                               "2001:470:e83b:9a::95:100\n"
                               "2001:470:e83b:a7:20d:61ff:fe45:2c3f\n";
            const char *exclude_all, *exclude_some;

            exclude_some = "1.2.3.0/24\n2001:470:e83b:9a::/64\n";
            excl_some = get_cidrlist(all_types[i], exclude_some, PARSE_CIDR_ONLY, &cfgl);
            ok(excl_some, "Read a %s containing only CIDRs using PARSE_CIDR_ONLY for excluding some cidrs", TEST_TYPE_TXT(all_types[i]));

            exclude_all = "0.0.0.0/0\n::/0\n";
            excl_all = get_cidrlist(all_types[i], exclude_all, PARSE_CIDR_ONLY, &cfgl);
            ok(excl_all, "Read a %s containing only CIDRs using PARSE_CIDR_ONLY for excluding all cidrs", TEST_TYPE_TXT(all_types[i]));

            cl = get_cidrlist(all_types[i], data, PARSE_IP_ONLY, &cfgl);
            ok(cl, "Read a %s containing only IPs using PARSE_IP_ONLY", TEST_TYPE_TXT(all_types[i]));

            struct random_list_index *rli;
            MOCKFAIL_START_TESTS(1, iplist_random);
            ok(!iplist_random(cl, &rli, &got1, excl_some, NULL, "no-list"), "Cannot get a random IP when the rindex allocation fails");
            MOCKFAIL_END_TESTS();

            memset(&got0, 0xF, sizeof(got0));
            memcpy(&tmp, &got0, sizeof(got0));
            ok(!iplist_random(cl, &rli, &got0, excl_all, NULL, "no-list"), "Can't get a random IP when everything's excluded");
            ok(!memcmp(&got0, &tmp, sizeof(got0)), "Failed random IP call should leave sock unchanged");

            ok(iplist_random(cl, &rli, &got1, excl_some, NULL, "no-list"), "Got a random IP with stuff excluded");
            ok(iplist_random(cl, &rli, &got2, excl_some, NULL, "no-list"), "Got a second random IP");
            ok(!netaddr_equal(&got1.a, &got2.a), "The second IP is different from the first");
            ok(iplist_random(cl, &rli, &got2, excl_some, NULL, "no-list"), "Got a third random IP");
            ok(netaddr_equal(&got1.a, &got2.a), "The third IP is the same as the first");

            cidrlist_refcount_dec(cl);
            data = "127.0.0.1\n1.2.3.4\n1.2.3.5\n5.6.7.8\n2001:470:e83b:9a:240:f4ff:feb1:1c85\n2001:470:e83b:9a::1\n"
                   "2001:470:e83b:9a::95:100\n2001:470:e83b:a7:20d:61ff:fe45:2c3f\n";
            cl   = get_cidrlist(all_types[i], data, PARSE_IP_ONLY, &cfgl);
            ok(iplist_random(cl, &rli, &got1, excl_some, NULL, "no-list"), "Got a random IP with stuff excluded");
            is(rli->count, 8,                                              "Index grew to 8 elements");

            ok(!iplist_random(NULL, &rli, &got1, excl_all, NULL, "no-list"), "Random IP returned false with empty input list");

            iplist_random_free(&rli);

            cidrlist_refcount_dec(excl_all);
            cidrlist_refcount_dec(excl_some);

            cidrlist_refcount_dec(cl);
        }

        diag("Test CIDR %s", TEST_TYPE_TXT(all_types[i]));
        {
            const char *data = "1.2.3.4/32\n5.6.7.0/24\n0001:0002:0003:0004::/128\n0005:0006:0007::/48";
            cl = get_cidrlist(all_types[i], data, PARSE_CIDR_ONLY, &cfgl);

            ok(cl, "Read a %s containing only CIDRs using PARSE_CIDR_ONLY", TEST_TYPE_TXT(all_types[i]));
            netaddr_from_str(&sock.a, "1.2.3.4", AF_INET);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 1.2.3.4 in the resulting list");
            netaddr_from_str(&sock.a, "1.2.3.5", AF_INET);
            ok(!cidrlist_search(cl, &sock.a, NULL, NULL), "Didn't find 1.2.3.5 in the resulting list");
            netaddr_from_str(&sock.a, "5.6.7.8", AF_INET);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 5.6.7.8 in the resulting list");
            netaddr_from_str(&sock.a, "0001:0002:0003:0004::", AF_INET6);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 0001:0002:0003:0004:: in the resulting list");
            netaddr_from_str(&sock.a, "0001:0002:0003:0004:0005::", AF_INET6);
            ok(!cidrlist_search(cl, &sock.a, NULL, NULL), "Didn't find 0001:0002:0003:0004:0005:: in the resulting list");
            netaddr_from_str(&sock.a, "0005:0006:0007:0008::", AF_INET6);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 0005:0006:0007:0008:: in the resulting list");
            sock.a.family = AF_INET + AF_INET6 + 1;
            ok(!cidrlist_search(cl, &sock.a, NULL, NULL), "Searching for an invalid address family fails cleanly");
            cidrlist_refcount_dec(cl);

            cl = get_cidrlist(all_types[i], data, PARSE_IP_OR_CIDR, &cfgl);
            ok(cl, "Read a %s containing only CIDRs using PARSE_IP_OR_CIDR", TEST_TYPE_TXT(all_types[i]));
            cidrlist_refcount_dec(cl);

            if (i == TEST_FILE) {
                cl = get_cidrlist(all_types[i], data, PARSE_IP_ONLY, &cfgl);
                ok(!cl, "Couldn't read a %s containing only CIDRs using PARSE_IP_ONLY", TEST_TYPE_TXT(all_types[i]));
            } else {
                cl = get_cidrlist(all_types[i], data, PARSE_IP_ONLY, &cfgl);
                ok(cl, "TEST_STRING - Partial reads of cidrs from a string succeed with data containing only CIDRs using PARSE_IP_ONLY");
                char buf[1024];
                cidrlist_to_buf(cl, buf, sizeof(buf), NULL);
                is_strstr(buf, "1.2.3.4", "Partial read of CIDRs using PARSE_IP_ONLY");
                cidrlist_refcount_dec(cl);
            }
        }

        diag("Test mixed %s", TEST_TYPE_TXT(all_types[i]));
        {
            const char *data = "1.2.3.4\n5.6.7.0/24\n0001:0002:0003:0004::\n0005:0006:0007::/48";
            cl = get_cidrlist(all_types[i], data, PARSE_IP_OR_CIDR, &cfgl);

            ok(cl, "Read a %s containing IPs and CIDRs using PARSE_IP_OR_CIDR", TEST_TYPE_TXT(all_types[i]));
            netaddr_from_str(&sock.a, "1.2.3.4", AF_INET);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 1.2.3.4 in the resulting list");
            netaddr_from_str(&sock.a, "1.2.3.5", AF_INET);
            ok(!cidrlist_search(cl, &sock.a, NULL, NULL), "Didn't find 1.2.3.5 in the resulting list");
            netaddr_from_str(&sock.a, "5.6.7.8", AF_INET);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 5.6.7.8 in the resulting list");
            netaddr_from_str(&sock.a, "0001:0002:0003:0004::", AF_INET6);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 0001:0002:0003:0004:: in the resulting list");
            netaddr_from_str(&sock.a, "0001:0002:0003:0004:0005::", AF_INET6);
            ok(!cidrlist_search(cl, &sock.a, NULL, NULL), "Didn't find 0001:0002:0003:0004:0005:: in the resulting list");
            netaddr_from_str(&sock.a, "0005:0006:0007:0008::", AF_INET6);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 0005:0006:0007:0008:: in the resulting list");
            cidrlist_refcount_dec(cl);

            cl = get_cidrlist(all_types[i], data, PARSE_CIDR_ONLY, &cfgl);
            ok(!cl, "Couldn't read a %s containing IPs and CIDRs using PARSE_CIDR_ONLY", TEST_TYPE_TXT(all_types[i]));

            if (i == TEST_FILE) {
                cl = get_cidrlist(all_types[i], data, PARSE_IP_ONLY, &cfgl);
                ok(!cl, "Couldn't read a %s containing IPs and CIDRs using PARSE_IP_ONLY", TEST_TYPE_TXT(all_types[i]));
            } else {
                cl = get_cidrlist(all_types[i], data, PARSE_IP_ONLY, &cfgl);
                ok(cl, "TEST_STRING - Partial reads of cidrs from a string succeed with data containing IPs and CIDRs using PARSE_IP_ONLY");
                char buf[1024];
                cidrlist_to_buf(cl, buf, sizeof(buf), NULL);
                is_strstr(buf, "1.2.3.4", "Partial read of CIDRs using PARSE_IP_ONLY");
                cidrlist_refcount_dec(cl);
            }
        }

        diag("Test overlapping CIDR %s", TEST_TYPE_TXT(all_types[i]));
        {
            const char *data = "1.2.3.4/32\n1.2.3.0/24\n5.6.7.8/32\n0001:0002:0003:0004:5:06:007:0008/128\n0001:0002:0003:0004::/64\n";
            cl = get_cidrlist(all_types[i], data, PARSE_CIDR_ONLY, &cfgl);

            ok(cl, "Read a %s containing 1.2.3.4/32, 1.2.3.0/24, 5.6.7.8/32, 1:2:3:4:5:6:7:8/128 and 1:2:3:4::/64", TEST_TYPE_TXT(all_types[i]));
            netaddr_from_str(&sock.a, "1.2.3.4", AF_INET);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 1.2.3.4 in the resulting list");
            netaddr_from_str(&sock.a, "1.2.3.5", AF_INET);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 1.2.3.5 in the resulting list");
            netaddr_from_str(&sock.a, "5.6.7.8", AF_INET);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 5.6.7.8 in the resulting list");
            netaddr_from_str(&sock.a, "1:2:3:4:5:6:7:8", AF_INET6);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 1:2:3:4:5:6:7:8 in the resulting list");
            netaddr_from_str(&sock.a, "1:2:3:4:5:6:7:9", AF_INET6);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 1:2:3:4:5:6:7:9 in the resulting list");

            cidrlist_to_buf(cl, ascii, sizeof(ascii), NULL);
            is_eq(ascii, "1.2.3.0/24 5.6.7.8/32 [1:2:3:4::]/64", "cidrlist_to_buf() produces the correct output");
            cidrlist_refcount_dec(cl);

            data = "0001:0002:0003:0004::/64\n0001:0002:0003:0004:5:06:007:0008/128\n5.6.7.8/32\n1.2.3.0/24\n1.2.3.4/32\n";
            cl = get_cidrlist(all_types[i], data, PARSE_CIDR_ONLY, &cfgl);

            ok(cl, "Read a %s containing 1:2:3:4::/64, 1:2:3:4:5:6:7:8/128, 5.6.7.8/32, 1.2.3.0/24 and 1.2.3.4/32 (reverse order)", TEST_TYPE_TXT(all_types[i]));
            netaddr_from_str(&sock.a, "1.2.3.4", AF_INET);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 1.2.3.4 in the resulting list");
            netaddr_from_str(&sock.a, "1.2.3.5", AF_INET);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 1.2.3.5 in the resulting list");
            netaddr_from_str(&sock.a, "5.6.7.8", AF_INET);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 5.6.7.8 in the resulting list");
            netaddr_from_str(&sock.a, "1:2:3:4:5:6:7:8", AF_INET6);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 1:2:3:4:5:6:7:8 in the resulting list");
            netaddr_from_str(&sock.a, "1:2:3:4:5:6:7:9", AF_INET6);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 1:2:3:4:5:6:7:9 in the resulting list");

            cidrlist_to_buf(cl, ascii, sizeof(ascii), NULL);
            is_eq(ascii, "1.2.3.0/24 5.6.7.8/32 [1:2:3:4::]/64", "cidrlist_to_buf() produces the correct output");
            cidrlist_to_buf(cl, ascii, 11, NULL);
            is_eq(ascii, "1.2.3.0/24", "cidrlist_to_buf() trucates correctly");
            cidrlist_refcount_dec(cl);
        }

        diag("Test short IP representations");
        {
            cl = get_cidrlist(all_types[i], "1.2.3\n", PARSE_IP_ONLY, &cfgl);
            ok(!cl, "Cannot load a %s with a three-part IP (1.2.3)", TEST_TYPE_TXT(all_types[i]));

            cl = get_cidrlist(all_types[i], "1.2\n", PARSE_IP_ONLY, &cfgl);
            ok(!cl, "Cannot load a %s with a two-part IP (1.2)", TEST_TYPE_TXT(all_types[i]));

            cl = get_cidrlist(all_types[i], "1\n", PARSE_IP_ONLY, &cfgl);
            ok(!cl, "Cannot load a %s with a one-part IP (1)", TEST_TYPE_TXT(all_types[i]));
        }

        diag("Test IPv6-only CIDR %s", TEST_TYPE_TXT(all_types[i]));
        {
            const char *data = "0001:0002:0003:0004:5:06:007:0008/128\n0001:0002:0003:0004::/64\n2:3::/32\n::1";
            cl = get_cidrlist(all_types[i], data, PARSE_IP_OR_CIDR, &cfgl);

            ok(cl, "Read a %s containing 1:2:3:4:5:6:7:8/128, 1:2:3:4::/64, 2:3::/32 and ::1", TEST_TYPE_TXT(all_types[i]));
            netaddr_from_str(&sock.a, "1:2:3:4:5:6:7:8", AF_INET6);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 1:2:3:4:5:6:7:8 in the resulting list");
            netaddr_from_str(&sock.a, "1:2:3:4:5:6:7:9", AF_INET6);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 1:2:3:4:5:6:7:9 in the resulting list");
            netaddr_from_str(&sock.a, "2:3:4::", AF_INET6);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found 2:3:4:: in the resulting list");
            netaddr_from_str(&sock.a, "::1", AF_INET6);
            ok(cidrlist_search(cl, &sock.a, NULL, NULL), "Found ::1 in the resulting list");

            cidrlist_to_buf(cl, ascii, sizeof(ascii), NULL);
            is_eq(ascii, "::1 [1:2:3:4::]/64 [2:3::]/32", "cidrlist_to_buf() produces the correct output");

            cidrlist_to_buf(cl, ascii, strlen(ascii), NULL);
            is_eq(ascii, "::1 [1:2:3:4::]/64", "cidrlist_to_buf() truncates correctly");
            cidrlist_refcount_dec(cl);
        }
    }

    diag("Verify that cidrlist object hashing works");
    {
        const char *data1 = "1.2.3.4/32\n1.2.3.0/24\n5.6.7.8/32\n0001:0002:0003:0004:5:06:007:0008/128\n0001:0002:0003:0004::/64\n";
        const char *data2 =             "1.2.3.0/24\n5.6.7.8/32\n0001:0002:0003:0004:5:06:007:0008/128\n0001:0002:0003:0004::/64\n";
        struct cidrlist *c1, *c2, *c3;

        /* Create a tiny hash so that we can get better coverage */
        object_hash_free(of.hash);
        of.hash = object_hash_new(1, 0, sizeof(hashfp));

        c1 = get_cidrlist(TEST_STRING, data1, PARSE_CIDR_ONLY, NULL);
        ok(c1, "Generated a cidrlist from data1");
        c2 = get_cidrlist(TEST_STRING, data1, PARSE_CIDR_ONLY, NULL);
        ok(c2, "Generated another cidrlist from data1");
        ok(c1 == c2, "Generating the same cidrlist with fingerprints twice yields the same data");
        is(c1->conf.refcount, 2, "The refcount is 2");

        c3 = get_cidrlist(TEST_STRING, data2, PARSE_CIDR_ONLY, NULL);
        ok(c1, "Generated a cidrlist from data2");
        ok(c1 != c3, "Generating a different cidrlist with fingerprints yields different data");

        cidrlist_refcount_dec(c1);
        cidrlist_refcount_dec(c2);
        cidrlist_refcount_dec(c3);
    }

    diag("Verify some cidrlist object hashing negative cases");
    {
        unsigned allocated, expected_overflows;
        struct cidrlist *c[10], *unhashed;

        /* Create a bogus hash */
        object_hash_free(of.hash);
        of.hash = object_hash_new(1, 0, sizeof(hashfp) * 2);

        cl = get_cidrlist(TEST_STRING, "1.2.3.4/32", PARSE_CIDR_ONLY, NULL);
        ok(!cl, "Failed to create a cidrlist with a bogus fingerprint");

        /* Create a tiny hash so that we can test allocation failures */
        object_hash_free(of.hash);
        of.hash = object_hash_new(1, 0, sizeof(hashfp));

        unhashed = NULL;
        expected_overflows = 1;
        for (allocated = i = 0; i < 10; i++) {
            if (i == 7) {
                MOCKFAIL_START_TESTS(1, object_hash_add);
                /* This pointer will fail to hash */
                unhashed = get_cidrlist(TEST_STRING, "6.6.6.0/24", PARSE_CIDR_ONLY, NULL);
                ok(unhashed, "Allocated an unhashed cidrlist object - object-hash overflow allocation failed");
                expected_overflows++;
                MOCKFAIL_END_TESTS();
            }
            snprintf(ascii, sizeof(ascii), "1.2.3.%u/32", i);
            c[i] = get_cidrlist(TEST_STRING, ascii, PARSE_CIDR_ONLY, NULL);
            allocated += !!c[i];
        }
        is(allocated, 10, "Allocated 10 cidrlist objects");
        is(kit_counter_get(COUNTER_UUP_OBJECT_HASH_OVERFLOWS), expected_overflows, "Recorded %u object-hash overflow%s",
           expected_overflows, expected_overflows == 1 ? "" : "s");

        for (i = 0; i < 10; i++)
            cidrlist_refcount_dec(c[i]);
        object_hash_free(of.hash);
        of.hash = NULL;
        cidrlist_refcount_dec(unhashed);
    }

    diag("Test cidrlist appending, sorting and reducing");
    {
        const struct {
            const char *append;
            const char *expect;
        } data[] = {
            { "1.2.3.4/32 ::1 2001:1234:56::2 1.2.4.0/24 1.2.3.0/24", "1.2.3.0/24 1.2.4.0/24 ::1 2001:1234:56::2" },
            { "1.2.3.4/32 ::1 2001:1234:56::2 1.2.4.0/24 1.2.3.0/24", "1.2.3.0/24 1.2.4.0/24 ::1 2001:1234:56::2" },
            { "1.0.0.0/8 1.2.4.0/24", "1.0.0.0/8 ::1 2001:1234:56::2" },
            { "0.0.0.0/0 2001::/16", "0.0.0.0/0 ::1 [2001::]/16" },
            { "0.0.0.0/0 2001::/16", "0.0.0.0/0 ::1 [2001::]/16" }
        };
        struct cidrlist *xcl;
        const char *consumed;
        char buf[1024];

        ok(cidrlist_append(NULL, NULL), "Appending a NULL cidrlist to a NULL cidrlist works");
        xcl = cidrlist_new_from_string(data[i = 0].append, " ", &consumed, NULL, PARSE_IP_OR_CIDR);
        ok(xcl, "Created a cidrlist from data item %u", i);
        is(*consumed, '\0', "Used the entire input cidrlist string");
        ok(!cidrlist_append(NULL, xcl), "Appending a populated cidrlist to a NULL cidrlist fails");

        cl = cidrlist_new(PARSE_IP_OR_CIDR);
        ok(cidrlist_append(NULL, cl), "Appending an empty cidrlist to a NULL cidrlist works");

        MOCKFAIL_START_TESTS(1, CIDRLIST_APPEND4);
        ok(!cidrlist_append(cl, xcl), "Appending a cidrlist fails when the IPv4 realloc() fails");
        MOCKFAIL_END_TESTS();
        MOCKFAIL_START_TESTS(1, CIDRLIST_APPEND6);
        ok(!cidrlist_append(cl, xcl), "Appending a cidrlist fails when the IPv4 realloc() fails");
        MOCKFAIL_END_TESTS();

        cidrlist_refcount_dec(xcl);

        for (i = 0; i < sizeof(data) / sizeof(*data); i++) {
            xcl = cidrlist_new_from_string(data[i].append, " ", &consumed, NULL, PARSE_IP_OR_CIDR);
            ok(xcl, "Created a cidrlist from data item %u", i);
            is(*consumed, '\0', "Used the entire input cidrlist string");
            ok(cidrlist_append(cl, xcl), "Appended it to he main list");
            cidrlist_refcount_dec(xcl);

            cidrlist_sort(cl);
            cidrlist_to_buf(cl, buf, sizeof(buf), NULL);
            is_eq(buf, data[i].expect, "The sorted & reduced string is correct for iteration %u", i);
        }

        cidrlist_refcount_dec(cl);
    }

    diag("Test cidrlist delimeter options");
    {
        const struct {
            const char *input;
            const char *space_delimiter;
            const char *space_consumed_remaining;
            const char *comma_delimiter;
            const char *comma_consumed_remaining;
        } data[] = {
            { "1.2.3.4 5.6.7.8 9.10.11.12", "1.2.3.4 5.6.7.8 9.10.11.12", "",                    "1.2.3.4",                    " 5.6.7.8 9.10.11.12" },
            { "1.2.3.4,5.6.7.8,9.10.11.12", "1.2.3.4",                    ",5.6.7.8,9.10.11.12", "1.2.3.4 5.6.7.8 9.10.11.12", "" },
            { "1.2.3.4 5.6.7.8,9.10.11.12", "1.2.3.4 5.6.7.8",            ",9.10.11.12",         "1.2.3.4",                    " 5.6.7.8,9.10.11.12" },
            { "1.2.3.4,5.6.7.8 9.10.11.12", "1.2.3.4",                    ",5.6.7.8 9.10.11.12", "1.2.3.4 5.6.7.8",            " 9.10.11.12" }
        };

        struct cidrlist *space_list;
        struct cidrlist *comma_list;
        const char *consumed;
        char buf[1024];

        for (i = 0; i < sizeof(data) / sizeof(*data); i++) {
            space_list = cidrlist_new_from_string(data[i].input, " ", &consumed, NULL, PARSE_IP_OR_CIDR);
            ok(space_list, "Created a space delimeted cidrlist from data item %u", i);
            cidrlist_to_buf(space_list, buf, sizeof(buf), NULL);
            is_strstr(buf, data[i].space_delimiter, "The space delimited string is correct for iteration %u", i);
            is_strstr(consumed, data[i].space_consumed_remaining, "The space delimited consumed string is correct for iteration %u", i);
            cidrlist_refcount_dec(space_list);

            comma_list = cidrlist_new_from_string(data[i].input, ",", &consumed, NULL, PARSE_IP_OR_CIDR);
            ok(comma_list, "Created a comma delimeted cidrlist from data item %u", i);
            cidrlist_to_buf(comma_list, buf, sizeof(buf), NULL);
            is_strstr(buf, data[i].comma_delimiter, "The comma delimited string is correct for iteration %u", i);
            is_strstr(consumed, data[i].comma_consumed_remaining, "The comma delimited consumed string is correct for iteration %u", i);
            cidrlist_refcount_dec(comma_list);
        }
    }

    conf_loader_fini(&cfgl);
    object_hash_free(of.hash);
    confset_unload();             // Finalize the conf subsystem
    is(memory_allocations(), start_allocations, "All memory allocations were freed after conf interaction tests");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
