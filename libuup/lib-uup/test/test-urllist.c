#include <kit-alloc.h>
#include <mockfail.h>
#include <openssl/sha.h>
#include <tap.h>

#include "conf-loader.h"
#include "object-hash.h"
#include "url-normalize.h"
#include "urllist-private.h"
#include "uup-counters.h"

#include "common-test.h"

#define STR_AND_LEN(str) str, strlen(str)

static void
test_urllist_match(struct urllist *ul, const char *url, int url_len, int match_expected, int line)
{
    char norm_buf[4096];
    unsigned norm_buf_len = sizeof(norm_buf);
    url_normalize(url, url_len, norm_buf, &norm_buf_len);
    is(urllist_match(ul, norm_buf, norm_buf_len), match_expected, "match line number: %d", line);
}

int
main(void)
{
    struct conf_loader cl;
    struct urllist    *urllist;
    const char        *fn;
    uint64_t           start_allocations;
    size_t             len;
    int                got;

    plan_tests(123);

    kit_memory_initialize(false);
    uup_counters_init();
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    conf_loader_init(&cl);

    diag("empty lists are fine");
    {
        fn = create_data("test-urllist-empty-file-for-urllist-new-coverage.txt", "%s", "");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        urllist = urllist_new(&cl);
        ok(urllist != NULL, "As expected, urllist_new() doesn't return NULL for empty file");
        got = urllist_match(urllist, STR_AND_LEN("foo.com/abc"));
        is(got, 0, "Calling match on an empty list is fine");
        urllist_refcount_dec(urllist);
        unlink(fn);
    }

    diag("just whitespace lists are fine too");
    {
        fn = create_data("test-urllist-just-whitespace.txt", " ");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        urllist = urllist_new(&cl);
        ok(urllist != NULL, "As expected, urllist_new() doesn't return NULL for empty file");
        urllist_refcount_dec(urllist);
        unlink(fn);
    }

    diag("missing lists are fine");
    {
        fn = create_data("test-urllist-invalid-include.txt", "#include doesnt-exist\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        urllist = urllist_new(&cl);
        ok(urllist != NULL, "As expected, urllist_new() doesn't return NULL on no data");
        got = urllist_match(urllist, STR_AND_LEN("foo.com/abc"));
        is(got, 0, "Calling match on an empty list is fine");
        urllist_refcount_dec(urllist);

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!urllist_new_strict(&cl, 0), "As expected, urllist_new_strict() returns NULL on no data");

        unlink(fn);
    }

    diag("memory allocation fails hashtable create");
    {
        fn = create_data("test-urllist-alloc-fails.txt", "foo.com/abc");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        MOCKFAIL_START_TESTS(1, URLLIST_HASHTABLE_CREATE);
        is(urllist_new(&cl), NULL, "As expected, urllist_new() returns NULL on alloc fail");
        MOCKFAIL_END_TESTS();
        unlink(fn);
    }

    diag("memory allocation fails hashtable add");
    {
        fn = create_data("test-urllist-alloc-fails.txt", "foo.com/abc");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        MOCKFAIL_START_TESTS(1, URLLIST_HASHTABLE_ADD);
        is(urllist_new(&cl), NULL, "As expected, urllist_new() returns NULL on alloc fail");
        MOCKFAIL_END_TESTS();
        unlink(fn);
    }

    diag("memory allocation fails parse urllist");
    {
        fn = create_data("test-urllist-alloc-fails.txt", "foo.com/abc");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        MOCKFAIL_START_TESTS(1, URLLIST_PARSE_URLLIST);
        is(urllist_new(&cl), NULL, "As expected, urllist_new() returns NULL on alloc fail");
        MOCKFAIL_END_TESTS();
        unlink(fn);
    }

    diag("strict match case");
    {
        const char *line;

        fn = create_data("test-urllist-strict-fails.txt", "\nfoo.com/abc\n\nbar.com/def\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(urllist = urllist_new(&cl), "urllist_new() works fine");
        urllist_refcount_dec(urllist);

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!urllist_new_strict(&cl, 3), "urllist_new_strict(cl, 3) doesn't");

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(urllist = urllist_new_strict(&cl, 2), "urllist_new_strict(cl, 2) does");
        urllist_refcount_dec(urllist);

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(urllist = urllist_new_strict(&cl, 1), "urllist_new_strict(cl, 1) does too");
        urllist_refcount_dec(urllist);

        line = conf_loader_readline(&cl);
        is_eq(line, "bar.com/def\n", "urllist_new_strict(cl, 1) didn't touch the second url");

        unlink(fn);

        fn = create_data("test-urllist-strict-fails.txt", "\nfoo.com/abc  bar.com/def\n");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(urllist = urllist_new(&cl), "urllist_new() works fine with embedded spaces");
        ok(urllist_match(urllist, STR_AND_LEN("foo.com/abc")), "Found foo.com/abc");
        ok(urllist_match(urllist, STR_AND_LEN("bar.com/def")), "Found bar.com/def");
        urllist_refcount_dec(urllist);

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!urllist_new_strict(&cl, 0), "urllist_new_strict() doesn't like the embedded space");

        unlink(fn);
    }

    diag("simple match case");
    {
        fn = create_data("test-urllist.txt", "foo.com/abc");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        urllist = urllist_new(&cl);
        ok(urllist, "urllist_new() works for a file with a missing trailing linefeed");
        got = urllist_match(urllist, STR_AND_LEN("foo.com/abc"));
        ok(got, "Found foo.com/abc as expected in urllist: %s", fn);
        urllist_refcount_dec(urllist);
        unlink(fn);
    }

    diag("test whitespace and stuff");
    {
        const char *list_of_lists[][2] = {
            {"foo.com/abc", "No whitespace"},
            {" foo.com/abc", "Leading whitespace"},
            {" foo.com/abc ", "Whitespace all around"},
            {"\nfoo.com/abc", "Leading newlines"},
            {"foo.com/abc\n", "ending newlines"},
            {"\nfoo.com/abc\n", "newlines all around"},
            {"\n \n foo.com/abc\n \n\n  \n", "whitespaces and stuff all around"},
            {"\t\nfoo.com/abc\t", "and some tabs"},
            {"abc.com/foo\nfoo.com/abc", "newline as a seperateor"},
            {"abc.com/foo foo.com/abc", "space as a seperateor"},
            {"foo.com/abc\nabc.com/foo", "newline as a seperateor 2"},
            {"foo.com/abc abc.com/foo", "space as a seperateor 2"},
            {"\nfoo.com/abc\nabc.com/foo", "newline as a seperateor 3"},
            {" foo.com/abc abc.com/foo", "space as a seperateor 3"},
            {"\nfoo.com/abc\nabc.com/foo\n", "newline as a seperateor 4"},
            {" foo.com/abc abc.com/foo ", "space as a seperateor 4"},
        };

        unsigned x;
        for (x = 0; x < ((sizeof(list_of_lists)/2) / sizeof(char *)); x++) {
            diag("%s", list_of_lists[x][1]);
            fn = create_data("test-urllist-whitespace-is-alright.txt", "%s", list_of_lists[x][0]);
            conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
            urllist = urllist_new(&cl);
            ok(urllist, "urllist_new() loads correctly");
            got = urllist_match(urllist, STR_AND_LEN("foo.com/abc"));
            ok(got, "Found foo.com/abc as expected in urllist: %s", fn);
            urllist_refcount_dec(urllist);
            unlink(fn);
        }
    }

    diag("A bunch of match cases");
    {
        fn = create_data("test-urllist-missing-linefeed.txt", "a.ca/a b.ca b.ca/more c.com:80/?c=d&a=b");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);

        ok(urllist = urllist_new(&cl), "urllist_new() loads fine");
        is(urllist_match(urllist, STR_AND_LEN("foo.com/abc")),    0,                        "foo.com/abc is not found");
        is(urllist_match(urllist, STR_AND_LEN("a.ca/a")),         strlen("a.ca/a"),         "Matched a.ca/a");
        is(urllist_match(urllist, STR_AND_LEN("b.ca/")),          strlen("b.ca/"),          "Matched b.ca/");
        is(urllist_match(urllist, STR_AND_LEN("c.com/?a=b&c=d")), strlen("c.com/?a=b&c=d"), "Matched c.com/?a=b&c=d");

        urllist_refcount_dec(urllist);
        unlink(fn);
    }

    diag("More match logic");
    {
        fn = create_data("test-urllist-missing-linefeed.txt",
          "http://a.co/cx/15195/100/setup_1848x19m.exe?z=z&super=bad&test=yes "
          "http://c.co/cx/15195/100/ "
          "http://d.co/cx/15195/100 "
          "http://g.com/a/d "
          "http://h.com/a/ "
          "http://i.com/a "
        );

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        urllist = urllist_new(&cl);
        ok(urllist, "urllist_new() loads fine");

        // http://a.co/cx/15195/100/setup_1848x19m.exe?z=z&super=bad&test=yes
        len = strlen("a.co/cx/15195/100/setup_1848x19m.exe?z=z&super=bad&test=yes");
        test_urllist_match(urllist, STR_AND_LEN("a.co/cx/15195/100/setup_1848x19m.exe?super=bad&test=yes&z=z"), len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("a.co/cx/15195/100/setup_1848x19m.exe?super=bad&test=yes"),     0,   __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("a.co/cx/15195/100/setup_1848x19m.exe?"),                       0,   __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("a.co/cx/15195/100/setup_1848x19m.exe"),                        0,   __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("a.co/cx/15195/100/"),                                          0,   __LINE__);

        // http://c.co/cx/15195/100/
        len = strlen("c.co/cx/15195/100");
        test_urllist_match(urllist, STR_AND_LEN("c.co/cx/15195/100/setup_1848x19m.exe?super=bad&test=yes&z=z"), len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("c.co/cx/15195/100/setup_1848x19m.exe?"),                       len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("c.co/cx/15195/100/setup_1848x19m.exe"),                        len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("c.co/cx/15195/100/"),                                          len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("c.co/cx/15195/100"),                                           len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("c.co/cx/15195/10"),                                            0,   __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("c.co/cx/15195/1000"),                                          0,   __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("c.co/cx/15195/"),                                              0,   __LINE__);

        // http://d.co/cx/15195/100
        len = strlen("d.co/cx/15195/100");
        test_urllist_match(urllist, STR_AND_LEN("d.co/cx/15195/100/?awesome=yes"), len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("d.co/cx/15195/100/?"),            len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("d.co/cx/15195/100/"),             len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("d.co/cx/15195/100"),              len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("d.co/cx/15195/10"),               0,   __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("d.co/cx/15195/1000"),             0,   __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("d.co/cx/15195/"),                 0,   __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("d.co/cx/15195"),                  0,   __LINE__);

        // http://g.com/a/d
        len = strlen("g.com/a/d");
        test_urllist_match(urllist, STR_AND_LEN("g.com/a/d?g"), len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("g.com/a/d?"),  len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("g.com/a/d"),   len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("g.com/a/"),    0,   __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("g.com/a/?a"),  0,   __LINE__);

        // http://h.com/a/
        len = strlen("h.com/a");
        test_urllist_match(urllist, STR_AND_LEN("h.com/a/d?g"), len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("h.com/a/d"),   len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("h.com/a/?g"),  len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("h.com/a/"),    len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("h.com/a?g"),   len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("h.com/a"),     len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("h.com/"),      0,   __LINE__);

        // http://i.com/a
        len = strlen("i.com/a");
        test_urllist_match(urllist, STR_AND_LEN("i.com/a/d?g"), len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("i.com/a/d"),   len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("i.com/a/?g"),  len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("i.com/a/"),    len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("i.com/a?g"),   len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("i.com/a"),     len, __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("i.com/"),      0,   __LINE__);
        test_urllist_match(urllist, STR_AND_LEN("i.com"),       0,   __LINE__);

        urllist_refcount_dec(urllist);
        unlink(fn);
    }

    diag("Buffer fails on no data");
    {
        is(urllist_new_from_buffer(NULL,   0, NULL, LOADFLAGS_NONE), NULL, "Successfully didn't load");
        is(urllist_new_from_buffer("",     0, NULL, LOADFLAGS_NONE), NULL, "Successfully didn't load");
        is(urllist_new_from_buffer(" ",    1, NULL, LOADFLAGS_NONE), NULL, "Successfully didn't load");
        is(urllist_new_from_buffer("  ",   2, NULL, LOADFLAGS_NONE), NULL, "Successfully didn't load");
        is(urllist_new_from_buffer("\t",   1, NULL, LOADFLAGS_NONE), NULL, "Successfully didn't load");
        is(urllist_new_from_buffer(" \t ", 3, NULL, LOADFLAGS_NONE), NULL, "Successfully didn't load");
    }

    diag("new from buffer can match");
    {
        urllist = urllist_new_from_buffer(STR_AND_LEN("foo.com/abc"), NULL, LOADFLAGS_NONE);
        ok(urllist, "urllist_new_from_buffer() works");
        got = urllist_match(urllist, STR_AND_LEN("foo.com/abc"));
        ok(got, "Found foo.com/abc as expected in urllist: %s", fn);
        urllist_refcount_dec(urllist);
    }

    diag("simple match case");
    {
        fn = create_data("test-urllist.txt", "foo.com/abc");
        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        urllist = urllist_new(&cl);
        ok(urllist, "urllist_new() works for a file with a missing trailing linefeed");
        got = urllist_match(urllist, STR_AND_LEN("foo.com/abc"));
        ok(got, "Found foo.com/abc as expected in urllist: %s", fn);
        urllist_refcount_dec(urllist);
        unlink(fn);
    }

#define HUNDRED_CHARS "0000000000111111111122222222223333333333444444444455555555556666666666777777777788888888889999999999"
#define THOUSAND_CHARS HUNDRED_CHARS HUNDRED_CHARS HUNDRED_CHARS HUNDRED_CHARS HUNDRED_CHARS HUNDRED_CHARS HUNDRED_CHARS HUNDRED_CHARS HUNDRED_CHARS HUNDRED_CHARS
#define FIVE_THOUSAND_CHARS THOUSAND_CHARS THOUSAND_CHARS THOUSAND_CHARS THOUSAND_CHARS THOUSAND_CHARS
    diag("A URL gets truncated");
    {
        fn = create_data("test-urllist.txt", "http://awesome/" FIVE_THOUSAND_CHARS);

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(urllist = urllist_new(&cl), "urllist_new() works for truncated URLs");
        urllist_refcount_dec(urllist);

        conf_loader_open(&cl, fn, NULL, NULL, 0, CONF_LOADER_DEFAULT);
        ok(!urllist_new_strict(&cl, 0), "urllist_new_strict() doesn't work for truncated URLs");

        unlink(fn);
    }

    diag("Verify that urllist object hashing works");
    {
        const char *data1 = "url1.com/url1 url2.com/url2 url3.com/url3";
        const char *data2 =               "url2.com/url2 url3.com/url3";
        uint8_t hashfp[SHA_DIGEST_LENGTH];
        struct object_fingerprint of;
        struct urllist *u1, *u2, *u3;
        SHA_CTX sha1;

        /* Create a tiny hash so that we can get better coverage */
        of.hash = object_hash_new(1, 0, sizeof(hashfp));
        of.fp = hashfp;
        of.len = sizeof(hashfp);

        SHA1_Init(&sha1);
        SHA1_Update(&sha1, data1, strlen(data1));
        SHA1_Final(hashfp, &sha1);

        u1 = urllist_new_from_buffer(data1, strlen(data1), &of, LOADFLAGS_NONE);
        ok(u1, "Generated a urllist from data1");
        u2 = urllist_new_from_buffer(data1, strlen(data1), &of, LOADFLAGS_NONE);
        ok(u2, "Generated another urllist from data1");
        ok(u1 == u2, "Generating the same urllist with fingerprints twice yields the same data");
        is(u1->conf.refcount, 2, "The refcount is 2");

        SHA1_Init(&sha1);
        SHA1_Update(&sha1, data2, strlen(data2));
        SHA1_Final(hashfp, &sha1);
        u3 = urllist_new_from_buffer(data2, strlen(data2), &of, LOADFLAGS_NONE);

        ok(u3, "Generated a urllist from data2");
        ok(u1 != u3, "Generating a different urllist with fingerprints yields different data");

        urllist_refcount_dec(u1);
        urllist_refcount_dec(u2);
        urllist_refcount_dec(u3);

        object_hash_free(of.hash);
    }

    diag("Verify some urllist object hashing negative cases");
    {
        unsigned allocated, expected_overflows;
        uint8_t hashfp[SHA_DIGEST_LENGTH];
        struct urllist *u[10], *unhashed;
        const char *data1 = "x.com/y/z";
        struct object_fingerprint of;
        char ascii[1024];
        SHA_CTX sha1;
        unsigned i;

        /* Create a bogus hash */
        of.hash = object_hash_new(1, 0, sizeof(hashfp) * 2);
        of.fp = hashfp;
        of.len = sizeof(hashfp);

        SHA1_Init(&sha1);
        SHA1_Update(&sha1, data1, strlen(data1));
        SHA1_Final(hashfp, &sha1);

        u[0] = urllist_new_from_buffer(data1, strlen(data1), &of, LOADFLAGS_NONE);
        ok(!u[0], "Failed to create a urllist with a bogus fingerprint");
        object_hash_free(of.hash);

        unhashed = NULL;
        expected_overflows = 1;
        /* Create a tiny hash so that we can test allocation failures */
        of.hash = object_hash_new(1, 0, sizeof(hashfp));
        for (allocated = i = 0; i < 10; i++) {
            if (i == 7) {
                MOCKFAIL_START_TESTS(1, object_hash_add);
                /* This pointer will fail to hash */
                snprintf(ascii, sizeof(ascii), "unhashed.domain/cant/find/me");
                SHA1_Init(&sha1);
                SHA1_Update(&sha1, ascii, strlen(ascii));
                SHA1_Final(hashfp, &sha1);
                unhashed = urllist_new_from_buffer(ascii, strlen(ascii), &of, LOADFLAGS_NONE);
                ok(unhashed, "Allocated an unhashed urllist object - object-hash overflow allocation failed");
                expected_overflows++;
                MOCKFAIL_END_TESTS();
            }
            snprintf(ascii, sizeof(ascii), "some.domain/a/%u/c", i);
            SHA1_Init(&sha1);
            SHA1_Update(&sha1, ascii, strlen(ascii));
            SHA1_Final(hashfp, &sha1);
            u[i] = urllist_new_from_buffer(ascii, strlen(ascii), &of, LOADFLAGS_NONE);
            allocated += !!u[i];
        }
        is(allocated, 10, "Allocated 10 urllist objects");
        is(kit_counter_get(COUNTER_UUP_OBJECT_HASH_OVERFLOWS), expected_overflows, "Recorded %u object-hash overflow%s",
           expected_overflows, expected_overflows == 1 ? "" : "s");

        for (i = 0; i < 10; i++)
            urllist_refcount_dec(u[i]);
        object_hash_free(of.hash);
        urllist_refcount_dec(unhashed);
    }

    conf_loader_fini(&cl);

    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
