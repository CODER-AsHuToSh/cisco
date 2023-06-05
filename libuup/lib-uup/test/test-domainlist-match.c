#include <kit-alloc.h>
#include <mockfail.h>
#include <tap.h>

#include "conf-loader.h"
#include "dns-name.h"
#include "domainlist-private.h"

#include "common-test.h"

int
main(int argc, char **argv)
{
    uint8_t domain[DNS_MAXLEN_NAME];
    struct domainlist *domainlist;
    uint64_t start_allocations;
    struct conf_loader cl;
    const uint8_t *got;
    const char *fn;

    SXE_UNUSED_PARAMETER(argc);
    SXE_UNUSED_PARAMETER(argv);

    plan_tests(84);

    kit_memory_initialize(false);
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    conf_loader_init(&cl);

    diag("empty lists are... missing");
    {
        fn = create_data("test-domainlist-empty-file-for-domainlist-new-coverage.txt", "%s", "");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        is(domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED), NULL, "As expected, domainlist_new() returns NULL for empty file");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        is(domainlist_new(&cl, 0, LOADFLAGS_DL_EXACT | LOADFLAGS_DL_LINEFEED_REQUIRED), NULL,
           "As expected, domainlist_new(LOADFLAGS_DL_EXACT) returns NULL for empty file");
        unlink(fn);
    }

    diag("missing lists are... missing");
    {
        fn = create_data("test-domainlist-invalid-file-for-domainlist-new-coverage.txt", "#include doesnt-exist\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        is(domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED), NULL, "As expected, domainlist_new() returns NULL for invalid file");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        is(domainlist_new(&cl, 0, LOADFLAGS_DL_EXACT | LOADFLAGS_DL_LINEFEED_REQUIRED), NULL,
           "As expected, domainlist_new(LOADFLAGS_DL_EXACT) returns NULL for invalid file");
        unlink(fn);
    }

    diag("missing linefeeds are ok");
    {
        fn = create_data("test-domainlist-missing-linefeed.txt", "domain.com");

        MOCKFAIL_START_TESTS(1, DOMAINLIST_PARSE);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED), "Cannot load a domainlist when domainlist_parse() fails");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(1, DOMAINLIST_NEW_INDEX);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED), "Cannot load a domainlist when domainlist_parse() fails to allocate an index");
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        domainlist = domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED);
        ok(domainlist, "domainlist_new() works for a file with a missing trailing linefeed");

        dns_name_sscan("domain.com", "", domain);
        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test no newline");
        ok(got, "Found domain.com as expected in domainlist: %s", fn);
        is(got, domain, "The match was equal to the passed domain");
        domainlist_refcount_dec(domainlist);
        unlink(fn);
    }

    diag("embedded garbage is bad");
    {
        char txt[1024];

        fn = create_binary_data("test-domainlist-embedded-garbage.txt", "domain\0.com\n", 12);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        is(domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED), NULL, "As expected, domainlist_new() returns NULL for a file with an embedded NUL");
        unlink(fn);

        fn = create_binary_data("test-domainlist-embedded-garbage.txt", "domain~.com\n", 12);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        is(domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED), NULL, "As expected, domainlist_new() returns NULL for a file with embedded garbage");
        unlink(fn);

        domainlist = domainlist_new_from_buffer("^ a.com\t0.0.0.0/0 c.com b.com!", 30, NULL, LOADFLAGS_DL_IGNORE_JUNK);
        ok(domainlist, "Created a domainlist, ignoring junk");
        ok(domainlist_to_buf(domainlist, txt, sizeof(txt), NULL), "Converted the list to ascii");
        is_eq(txt, "a.com c.com", "Junk was discarded");
        domainlist_refcount_dec(domainlist);
    }

    diag("subdomain matches find the correct suffix");
    {
        fn = create_data("test-domainlist-match-example-net.txt",
            "example.com\n"
            "example.net\n"
            "static-example.net\n"
            "example.org\n");

        MOCKFAIL_START_TESTS(1, CONF_LOADER_READFILE);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED), "Cannot create a domainlist when conf_loader_readfile() fails");
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        domainlist = domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED);
        dns_name_sscan("www.example.net", "", domain);

        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 1");
        ok(got, "Found name as expected in domainlist: %s", fn);
        is(got, domain + 4, "The match was 4 bytes into the passed domain");
        domainlist_refcount_dec(domainlist);
        unlink(fn);

        fn = create_data("test-domainlist-match-c-d.txt",
            "# The first 7 entries mean that our first match will be the 'd' entry\n"
            "one.record.a\n"
            "two.record.a\n"
            "three.record.a\n"
            "four.record.a\n"
            "five.record.a\n"
            "six.record.a\n"
            "seven.record.a\n"
            "# bsearch() for 'a.bob.c.d' finds the next entry\n"
            "d\n"
            "c.d\n"
            "sortabla.c.d\n"
            "b.c.d\n"
            "bob.c.d\n"
            "egnops.bob.c.d\n"
            "yob.c.d\n"
            "god.c.d\n");

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        domainlist = domainlist_new(&cl, 0, LOADFLAGS_DL_EXACT | LOADFLAGS_DL_LINEFEED_REQUIRED);
        dns_name_sscan("a.bob.c.d", "", domain);

        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test c.d");
        ok(got, "Found a match for a.bob.c.d as expected in domainlist: %s", fn);
        if (!is(got, domain + 2, "The match was 2 bytes into the passed domain"))
            diag("Got: '%s', not '%s'", got ? dns_name_to_str1(got) : "<NULL>", dns_name_to_str2(domain + 2));
        domainlist_refcount_dec(domainlist);
        unlink(fn);
    }

    diag("extra lines are ignored");
    {
        fn = create_data("test-domainlist-match-amazon-extra-line.txt",
            "amazon.com\n"
            "disney.com\n"
            "images-amazon.com\n"
            "linkedin.com\n"
            "\n");

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        domainlist = domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED);
        dns_name_sscan("www.amazon.com", "", domain);

        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 2");
        ok(got, "Found name as expected in domainlist: %s", fn);
        is(got, domain + 4, "The match was 4 bytes into the passed domain");
        domainlist_refcount_dec(domainlist);
        unlink(fn);
    }

    diag("subdomain kissing match");
    {
        fn = create_data("test-domainlist-match-amazon-sub-domain-kissing.txt",
            "amazon.com\n"
            "disney.com\n"
            "images.amazon.com\n"
            /* What does this even mean?  Can anyone elaborate? */
            // without this next line then after sorting images.amazon.com is kissing amazon.com:
            // "images-amazon.com\n"
            "linkedin.com\n");

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        domainlist = domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED);
        dns_name_sscan("www.amazon.com", "", domain);

        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 3");
        ok(got, "Found name as expected in domainlist: %s", fn);
        is(got, domain + 4, "The match was 4 bytes into the passed domain");
        domainlist_refcount_dec(domainlist);
        unlink(fn);
    }

    diag("subdomain not kissing match");
    {
        fn = create_data("test-domainlist-match-amazon-sub-domain-kissing-not.txt",
            "amazon.com\n"
            "disney.com\n"
            "images.amazon.com\n"
            "images-amazon.com\n"
            "linkedin.com\n");

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        domainlist = domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED);
        dns_name_sscan("www.amazon.com", "", domain);

        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 4");
        ok(got, "Found name as expected in domainlist: %s", fn);
        is(got, domain + 4, "The match was 4 bytes into the passed domain");
        domainlist_refcount_dec(domainlist);
        unlink(fn);
    }

    diag("subdomain match");
    {
        fn = create_data("test-domainlist-match-amazon.txt",
            "amazon.com\n"
            "disney.com\n"
            "images-amazon.com\n"
            "linkedin.com\n");

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        domainlist = domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED);
        dns_name_sscan("www.amazon.com", "", domain);

        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 5");
        ok(got, "Found name as expected in domainlist: %s", fn);
        is(got, domain + 4, "The match was 4 bytes into the passed domain");
        domainlist_refcount_dec(domainlist);
        unlink(fn);
    }

    diag("domainlist_match() returns are correct");
    {
        fn = create_data("test-domainlist-match-amazon-www.txt",
            "www.amazon.com\n"
            "disney.com\n"
            "images-amazon.com\n"
            "linkedin.com\n");

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        domainlist = domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED);
        dns_name_sscan("www.amazon.com", "", domain);

        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 6");
        ok(got, "Found name as expected in domainlist: %s", fn);
        is(got, domain, "The match was equal to the passed domain");
        domainlist_refcount_dec(domainlist);
        unlink(fn);
    }

    diag("domainlists are reduced");
    {
        fn = create_data("test-domainlist-remove.txt",
            "amazon.com\n"
            "images-amazon.com\n"
            "images.amazon.com\n");

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        domainlist = domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED);
        is(domainlist->name_amount, 2, "images.amazon.com removed as expected");

        domainlist_refcount_dec(domainlist);
        unlink(fn);
    }

    diag("domainlist output");
    {
        const char *sorted = "a2z.com awfulhak.net Awfulhak.org opendns.com opendns.com.org";
        char txt[1024];

        fn = create_data("test-domainlist-output.txt",
            "opendns.com.org\n"
            "opendns.com\n"
            "www.opendns.com\n"
            "a2z.com\n"
            "Awfulhak.org\n"
            "awfulhak.net\n");

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        domainlist = domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED);

        ok(domainlist_to_buf(domainlist, txt, sizeof(txt), NULL), "Converted the list to un-sorted ascii");
        is_eq(txt, "Awfulhak.org opendns.com.org opendns.com a2z.com awfulhak.net", "un-sorted ascii is correct");

        is(domainlist_to_sorted_ascii(domainlist, txt, strlen(sorted)), -1, "Cannot see sorted output when the buffer's too small");

        ok(domainlist_to_sorted_ascii(domainlist, txt, strlen(sorted) + 1) > 0, "Converted the list to sorted ascii");
        is_eq(txt, sorted, "sorted ascii is correct");

        domainlist_refcount_dec(domainlist);
        unlink(fn);
    }

    diag("whitespace is ignored");
    {
        char domainlist_str[] = " \tgoogle.com\t  cnn.com  \t news.yahoo.com ";

        MOCKFAIL_START_TESTS(1, DOMAINLIST_NEW_FROM_BUFFER);
        ok(!domainlist_new_from_buffer(domainlist_str, strlen(domainlist_str), NULL, LOADFLAGS_NONE), "Cannot allocate a domainlist when domainlist_new_from_buffer() fails");
        MOCKFAIL_END_TESTS();

        domainlist = domainlist_new_from_buffer(domainlist_str, strlen(domainlist_str), NULL, LOADFLAGS_NONE);

        /* Check that a domain on the list does not match */
        dns_name_sscan("yahoo.com", "", domain);
        ok(!domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 7"), "As expected, did not find yahoo.com in domainlist '%s'", domainlist_str);

        /* Check that the names on the list are found */
        dns_name_sscan("reader.google.com", "", domain);
        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 8");
        ok(got, "As expected, did find reader.google.com in domainlist '%s'", domainlist_str);
        is(got, domain + 7, "The match was 7 bytes into the passed domain");
        dns_name_sscan("cnn.com", "", domain);
        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 9");
        ok(got, "As expected, did find cnn.com in domainlist '%s'", domainlist_str);
        is(got, domain, "The match was equal to the passed domain");
        dns_name_sscan("news.yahoo.com", "", domain);
        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 10");
        ok(got, "As expected, did find news.yahoo.com in domainlist '%s'", domainlist_str);
        is(got, domain, "The match was equal to the passed domain");
        domainlist_refcount_dec(domainlist);
    }

    diag("Matching against the freezelist");
    {
        char domainlist_str[] = "hpb.bg\nwww.x.com.cn\nlist.115seo.com\n173uu.com\nwww.888.com\nboxun.com\nwww.boxun.com\nepochtimes.com\ngotpvp.com\nmineplex.com\nfengdun.net\nmediatemple.net\narkhamnetwork.org\ns2w2s.ru\n";
        char nxdomain[DNS_MAXLEN_STRING + 1];
        const char *garbage;
        uint8_t *expect;
        char *tok;
        int glen;

        domainlist = domainlist_new_from_buffer(domainlist_str, strlen(domainlist_str), NULL, LOADFLAGS_NONE);

        garbage = "garbage.is.a.wonderful.thing";
        glen = 15;
        for (tok = strtok(domainlist_str, "\n"); tok; tok = strtok(NULL, "\n")) {
            dns_name_sscan(tok, "", domain);
            got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 11");
            expect = strcmp(tok, "www.boxun.com") ? domain : domain + 4;
            is(got, expect, "Found '%s' in domainlist", tok);

            glen++;
            while (garbage[glen - 1] == '.')
                glen++;
            snprintf(nxdomain, sizeof(nxdomain), "%.*s.%s", glen, garbage, tok);
            dns_name_sscan(nxdomain, "", domain);
            got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 12");
            expect = domain + strlen(nxdomain) - strlen(tok);
            if (strcmp(tok, "www.boxun.com") == 0)
                expect += 4;
            is(got, expect, "Found '%s' in domainlist (as %s)", nxdomain, dns_name_to_str1(expect));
        }

        dns_name_sscan("com", "", domain);
        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 13");
        ok(!got, "Didn't find '%s' in domainlist", dns_name_to_str1(domain));

        dns_name_sscan(".", "", domain);
        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 14");
        ok(!got, "Didn't find '%s' in domainlist", dns_name_to_str1(domain));

        dns_name_sscan("something.Xmediatemple.net", "", domain);
        domain[11] = '.';    /* A *real* '.' embedded in the qname */
        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 15");
        ok(!got, "Didn't find '%s' in domainlist", dns_name_to_str1(domain));

        domainlist_refcount_dec(domainlist);
    }

    diag("Matching against a domainlist containing '.'");
    {
        char domainlist_str[] = ".\n";

        domainlist = domainlist_new_from_buffer(domainlist_str, strlen(domainlist_str), NULL, LOADFLAGS_NONE);

        dns_name_sscan("something", "", domain);
        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 16");
        is(got, domain + 10, "Found 'something' in domainlist (match is '%s')", dns_name_to_str1(got));

        dns_name_sscan("something.else", "", domain);
        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 17");
        is(got, domain + 15, "Found 'something.else' in domainlist (match is '%s')", dns_name_to_str1(got));

        dns_name_sscan(".", "", domain);
        got = domainlist_match(domainlist, domain, DOMAINLIST_MATCH_SUBDOMAIN, NULL, "test 18");
        is(got, domain, "Found '.' in domainlist (match is '%s')", dns_name_to_str1(got));

        domainlist_refcount_dec(domainlist);
    }

    diag("Force line allocations from domainlists packed onto one line");
    {
        char data[2048], *ptr;
        int i;

        for (i = 0; i < 2048 - 15; i += strlen(data + i))
            snprintf(data + i, sizeof(data) - i, "domain%04d.com ", i);
        fn = create_data("test-domainlist-output.txt", "%s", data);

        MOCKFAIL_START_TESTS(1, CONF_LOADER_RAW_GETLINE);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED), "Cannot create a domainlist from a 2k line when conf_loader_raw_getline() fails");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(1, CONF_LOADER_GZREAD);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED), "Cannot create a domainlist from a 2k line when conf-loader fails with a gzread() error");
        MOCKFAIL_END_TESTS();

        MOCKFAIL_START_TESTS(1, CONF_LOADER_TOOMUCHDATA);
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED), "Cannot create a domainlist from a 2k line when conf-loader fails with an overflow error");
        MOCKFAIL_END_TESTS();

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        domainlist = domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED);
        ok(!domainlist, "Cannot create a domainlist from a 2k line with embedded spaces");

        for (ptr = strchr(data, ' '); ptr; ptr = strchr(ptr + 1, ' '))
            *ptr = '\n';
        unlink(fn);
        fn = create_data("test-domainlist-output.txt", "%s", data);

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        domainlist = domainlist_new(&cl, 0, LOADFLAGS_DL_LINEFEED_REQUIRED);
        ok(domainlist, "Created a domainlist from a 2k file");

        domainlist_refcount_dec(domainlist);
        unlink(fn);
    }

    conf_loader_fini(&cl);
    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
