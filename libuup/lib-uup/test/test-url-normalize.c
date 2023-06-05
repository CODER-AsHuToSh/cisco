#include <string.h>
#include <sxe-log.h>
#include <tap.h>

#include "url-normalize.h"

static void
normalize_check(const char *url_in, const char *url_out_expected, unsigned buf_size, int return_val, int line)
{
    printf("\nTest line %d - %s => (%u) %s\n", line, url_in, buf_size, url_out_expected);

    char url_out[buf_size + 2];
    unsigned url_out_len = buf_size;

    // Guard bytes
    url_out[buf_size + 0] = 0xA;
    url_out[buf_size + 1] = 0x9;

    if (return_val == URL_NORM_FAILED) {
        is(url_normalize(url_in, strlen(url_in), url_out, &url_out_len), return_val, "url_normalize(...) returns failure");
        goto DONE;
    } else if (return_val == URL_NORM_TRUNCATED) {
        is(url_normalize(url_in, strlen(url_in), url_out, &url_out_len), return_val, "url_normalize(...) returns truncated");
    } else {
        is(url_normalize(url_in, strlen(url_in), url_out, &url_out_len), return_val, "url_normalize(...) succeeded");
    }

    if ((url_out[buf_size + 0] != 0xA) ||
        (url_out[buf_size + 1] != 0x9))
    {
        ok(0, "Overwritten guard byte!");
    }

    if (url_out_len == strlen(url_out_expected)) {
        is(url_out_len, strlen(url_out_expected), "Expected normalized URL is the correct length");
    } else {
        ok(0, "Expected normalized URL is not the correct length");
        goto FAILED_AND_PRINT;
    }

    unsigned x;
    for (x = 0; x < url_out_len; x++) {
        if (url_out[x] != url_out_expected[x]) {
            ok(0, "Expected normalized URL does not match");
            goto FAILED_AND_PRINT;
        }
    }
    ok(1, "Epected normalized URL matches");
    goto DONE;

FAILED_AND_PRINT:
    printf("Input:      %s\n", url_in);
    printf("Expected:   %s\n", url_out_expected);
    printf("Normalized: %.*s\n", url_out_len, url_out);

DONE:
    // Stop on first failure
    if (exit_status()) {
        exit(exit_status());
    }
    return;
}

int
main(void)
{
    plan_no_plan();

    ok(1, "Ok, we've started the tests!");

    {
        // Sanity
        normalize_check("a.co",        "a.co/", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("foo.com/", "foo.com/", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("bar.com",  "bar.com/", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("bar.com/super/awesome", "bar.com/super/awesome", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("bar.com/super/awesome?a=b", "bar.com/super/awesome?a=b", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("bar.com/super/awesome?a=b&c=d", "bar.com/super/awesome?a=b&c=d", 128, URL_NORM_SUCCESS, __LINE__);

        // Failures
        normalize_check("bar.com", "",     0, URL_NORM_FAILED, __LINE__);
        normalize_check("",        "",   128, URL_NORM_FAILED, __LINE__);
        normalize_check("",        " ",  128, URL_NORM_FAILED, __LINE__);
        normalize_check("",        "  ", 128, URL_NORM_FAILED, __LINE__);
        normalize_check(" ",       "",   128, URL_NORM_FAILED, __LINE__);
        normalize_check("  ",      "",   128, URL_NORM_FAILED, __LINE__);
        normalize_check(" ",       " ",  128, URL_NORM_FAILED, __LINE__);
        normalize_check("  ",      "  ", 128, URL_NORM_FAILED, __LINE__);
        normalize_check("=",       "  ", 128, URL_NORM_FAILED, __LINE__);
        normalize_check("@",       "  ", 128, URL_NORM_FAILED, __LINE__);
        normalize_check("/",       "",   128, URL_NORM_FAILED, __LINE__);
        normalize_check("/a",      "",   128, URL_NORM_FAILED, __LINE__);

        // Domain Failures
        normalize_check("a!b.com/",      "",   128, URL_NORM_FAILED, __LINE__);
        normalize_check("a!b.com/",      "",   128, URL_NORM_FAILED, __LINE__);
        normalize_check("a[]b.com/",     "",   128, URL_NORM_FAILED, __LINE__);
        normalize_check("a|b.com/",      "",   128, URL_NORM_FAILED, __LINE__);

        // Valid domain characters
        normalize_check("abcdef123_._.-_-._-_.com/", "abcdef123_._.-_-._-_.com/",   128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("-.ca/",                     "-.ca/",   128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("_.ru",                      "_.ru/",   128, URL_NORM_SUCCESS, __LINE__);

        // leading whitespace
        normalize_check(" BaR.cOm",  "bar.com/", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("  BaR.cOm", "bar.com/", 128, URL_NORM_SUCCESS, __LINE__);

        // Lower Case
        normalize_check("BaR.cOm",             "bar.com/",            128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("BaR.cOm/AbC",         "bar.com/abc",         128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("BaR.cOm/AbC?D=E&F=G", "bar.com/abc?d=e&f=g", 128, URL_NORM_SUCCESS, __LINE__);

        // Truncation
        normalize_check("bar.co", "",        1, URL_NORM_FAILED, __LINE__);
        normalize_check("bar.co", "",        2, URL_NORM_FAILED, __LINE__);
        normalize_check("bar.co", "",        3, URL_NORM_FAILED, __LINE__);
        normalize_check("bar.co", "",        4, URL_NORM_FAILED, __LINE__);
        normalize_check("bar.co", "",        5, URL_NORM_FAILED, __LINE__);
        normalize_check("bar.co", "",        6, URL_NORM_FAILED, __LINE__);
        normalize_check("bar.co", "bar.co/", 7, URL_NORM_SUCCESS, __LINE__);

        // Scheme Removal
        normalize_check("http://BaR.cOm",   "bar.com/", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("http://BaR.cOm/",  "bar.com/", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("https://BaR.cOm",  "bar.com/", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("https://BaR.cOm/", "bar.com/", 128, URL_NORM_SUCCESS, __LINE__);

        // User Pass Port
        normalize_check("https://a:b@c.com:80/",   "c.com/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("https://aa:ba@c.com:80/", "c.com/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("https://@c.com/",         "c.com/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("https://b@c.com/",        "c.com/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("https://bb@c.com/",       "c.com/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("https://@@c.com/",        "c.com/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("https://:@c.com/",        "c.com/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("https://:b@c.com/",       "c.com/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("https://:bb@c.com/",      "c.com/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("https://c.com:/",         "c.com/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("https://c.com:1/",        "c.com/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("https://c.com:12/",       "c.com/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("https://c.com:999999/",   "c.com/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("http://a9a:b8b@c7c.co/",  "c7c.co/", 128, URL_NORM_SUCCESS, __LINE__);

        normalize_check("https://::c.com/", "", 128, URL_NORM_FAILED,  __LINE__);
        normalize_check("https://@:c.com/", "", 128, URL_NORM_FAILED,  __LINE__);
        normalize_check("c.co:",            "", 128, URL_NORM_FAILED,  __LINE__);
        normalize_check("c.co:d9",          "", 128, URL_NORM_FAILED,  __LINE__);

        // Short and Long Domain Names
        normalize_check("c.c", "", 1024, URL_NORM_FAILED,  __LINE__);
        normalize_check("A12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678.com",
                        "a12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678.com/",
                        1024, URL_NORM_SUCCESS,  __LINE__);
        normalize_check("A123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789.com",
                        "", 1024, URL_NORM_FAILED,  __LINE__);

        // Pathless URLs with query args
        normalize_check("c.co/?a=b",    "c.co/?a=b",     128, URL_NORM_SUCCESS,  __LINE__);
        normalize_check("c.co?a=b",     "c.co/?a=b",     128, URL_NORM_SUCCESS,  __LINE__);
        normalize_check("c.co?c=d&a=b", "c.co/?a=b&c=d", 128, URL_NORM_SUCCESS,  __LINE__);
        normalize_check("c.co:?a=b",    "c.co/?a=b",     128, URL_NORM_SUCCESS,  __LINE__);
        normalize_check("c.co:1?a=b",   "c.co/?a=b",     128, URL_NORM_SUCCESS,  __LINE__);
        normalize_check("c.co:12?a=b",  "c.co/?a=b",     128, URL_NORM_SUCCESS,  __LINE__);

        // Path Truncation
        normalize_check("https://a:b@c.com:80/superawesome", "c.com/superawesome", 19, URL_NORM_SUCCESS,   __LINE__);
        normalize_check("https://a:b@c.com:80/superawesome", "c.com/superawesome", 18, URL_NORM_SUCCESS,   __LINE__);
        normalize_check("https://a:b@c.com:80/superawesome", "c.com/superawesom",  17, URL_NORM_TRUNCATED, __LINE__);

        // Remove Duplicate path slashes
        normalize_check("a.com/a/b/",    "a.com/a/b", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com///a//b/", "a.com/a/b", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a////b",  "a.com/a/b", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/b//",   "a.com/a/b", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/b///",  "a.com/a/b", 128, URL_NORM_SUCCESS, __LINE__);

        // Remove dot-segments from paths
        normalize_check("a.com/.",       "a.com/.",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/./",    "a.com/a",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/./",      "a.com/",       128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/./a",     "a.com/a",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/.b",      "a.com/.b",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/.b/",     "a.com/.b",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/.b/a",    "a.com/.b/a",   128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/b./",     "a.com/b.",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/b./a",    "a.com/b./a",   128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/c/.",     "a.com/c/.",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/c/./",    "a.com/c",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/c/./a",   "a.com/c/a",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/c/.b",    "a.com/c/.b",   128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/c/.b/",   "a.com/c/.b" ,  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/c/.b/a",  "a.com/c/.b/a", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/c/b./",   "a.com/c/b.",   128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/c/b./a",  "a.com/c/b./a", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/./.",     "a.com/.",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/././",    "a.com/",       128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/././a",   "a.com/a",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/.?",      "a.com/.",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/./?",     "a.com/",       128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/..?",     "a.com/..",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/../?",    "a.com/",       128, URL_NORM_SUCCESS, __LINE__);

        // Remove double dot-segments from paths
        normalize_check("a.com/..",               "a.com/..",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a..",              "a.com/a..",   128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a../",             "a.com/a..",   128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a../b",            "a.com/a../b", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/../",              "a.com/",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/../a",             "a.com/a",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/../.",             "a.com/.",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/../a.",            "a.com/a.",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/../.a",            "a.com/.a",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/./..",             "a.com/..",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/..",             "a.com/a/..",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com//..",              "a.com/..",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/../",              "a.com/",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com//../",             "a.com/",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/../",            "a.com/",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/./../",            "a.com/",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/../../",           "a.com/",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/../",            "a.com/",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/../b",           "a.com/b",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/aaa/../b",         "a.com/b",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/.aaa/../b",        "a.com/b",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/.a./../b",         "a.com/b",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/../b/..",        "a.com/b/..",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/../b/../",       "a.com/",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/../b/../c",      "a.com/c",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/b/../c",         "a.com/a/c",   128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/b/c/../",        "a.com/a/b",   128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/b/c/../../",     "a.com/a",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/b/c/../../../",  "a.com/",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/b/c/../../../d", "a.com/d",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/b/../c/d/../",   "a.com/a/c",   128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a/b/../c/d/../../../../../../../../", "a.com/", 128, URL_NORM_SUCCESS, __LINE__);

        // decode percent-encoded characters that were never supposed to be percent-encoded
        normalize_check("a.com/\%",         "a.com/\%",       128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%/",        "a.com/\%",       128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%\%",       "a.com/\%\%",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%\%/",      "a.com/\%\%",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%4",        "a.com/\%4",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%4!",       "a.com/\%4\%21",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%4!/",      "a.com/\%4\%21",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%4;",       "a.com/\%4\%3b",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%4^",       "a.com/\%4\%5e",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%4^/",      "a.com/\%4\%5e",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%4/",       "a.com/\%4",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%41",       "a.com/a",        128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%41/",      "a.com/a",        128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%61",       "a.com/a",        128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%2C",       "a.com/\%2c",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%2F",       "a.com/\%2f",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%40",       "a.com/\%40",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%5B",       "a.com/\%5b",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%60",       "a.com/\%60",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%7b",       "a.com/\%7b",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%7f",       "a.com/\%7f",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%5c",       "a.com/\%5c",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%61/",      "a.com/a",        128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/abc/\%61",   "a.com/abc/a",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/b/\%61/.",   "a.com/b/a/.",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/b/\%61/./",  "a.com/b/a",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/b/\%61/../", "a.com/b",        128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/\%61/../",   "a.com/",         128, URL_NORM_SUCCESS, __LINE__);
        // 0x30                                 0x39   0x2D  0x5F  0x2E  0x7E
        // 0    1   2   3   4   5   6   7   8   9      -     _     .     ~
        // 0x41                                                                                                 0x5A
        // A    B   C   D   E   F   G   H   I   J   K   L   M   N   O   P   Q   R   S   T   U   V   W   X   Y   Z
        // 0x61                                                                                                 0x7A
        // a    b   c   d   e   f   g   h   i   j   k   l   m   n   o   p   q   r   s   t   u   v   w   x   y   z
        // lower-case the letters in percent-encoded letter sequences
        normalize_check("a.co/\%2D\%2E\%30\%31\%32\%33\%34\%35\%36\%37\%38\%39\%5F\%7E",
                        "a.co/-.0123456789_~", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.co/\%2d\%2e\%30\%31\%32\%33\%34\%35\%36\%37\%38\%39\%5f\%7e",
                        "a.co/-.0123456789_~", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.co/\%41\%42\%43\%44\%45\%46\%47\%48\%49\%4A\%4B\%4C\%4D\%4E\%4F\%50\%51\%52\%53\%54\%55\%56\%57\%58\%59\%5A",
                        "a.co/abcdefghijklmnopqrstuvwxyz", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.co/\%61\%62\%63\%64\%65\%66\%67\%68\%69\%6A\%6B\%6C\%6D\%6E\%6F\%70\%71\%72\%73\%74\%75\%76\%77\%78\%79\%7A",
                        "a.co/abcdefghijklmnopqrstuvwxyz", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.co/\%41\%42\%43\%44\%45\%46\%47\%48\%49\%4a\%4b\%4c\%4d\%4e\%4f\%50\%51\%52\%53\%54\%55\%56\%57\%58\%59\%5a",
                        "a.co/abcdefghijklmnopqrstuvwxyz", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.co/\%61\%62\%63\%64\%65\%66\%67\%68\%69\%6a\%6b\%6c\%6d\%6e\%6f\%70\%71\%72\%73\%74\%75\%76\%77\%78\%79\%7a",
                        "a.co/abcdefghijklmnopqrstuvwxyz", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.co/\%00\%01\%02\%03\%04\%05\%06\%07\%08\%09\%0a\%0b\%0c\%0d\%0e\%0f\%10\%11\%12\%13\%14\%15\%16\%17\%18\%19\%1a\%1b\%1c\%1d\%1e\%1f\%20\%21\%22\%23\%24\%25\%26\%27\%28\%29\%2a\%2b\%2c\%2d\%2e\%2f\%30\%31\%32\%33\%34\%35\%36\%37\%38\%39\%3a\%3b\%3c\%3d\%3e\%3f\%40\%41\%42\%43\%44\%45\%46\%47\%48\%49\%4a\%4b\%4c\%4d\%4e\%4f\%50\%51\%52\%53\%54\%55\%56\%57\%58\%59\%5a\%5b\%5c\%5d\%5e\%5f\%60\%61\%62\%63\%64\%65\%66\%67\%68\%69\%6a\%6b\%6c\%6d\%6e\%6f\%70\%71\%72\%73\%74\%75\%76\%77\%78\%79\%7a\%7b\%7c\%7d\%7e\%7f\%80\%81\%82\%83\%84\%85\%86\%87\%88\%89\%8a\%8b\%8c\%8d\%8e\%8f\%90\%91\%92\%93\%94\%95\%96\%97\%98\%99\%9a\%9b\%9c\%9d\%9e\%9f\%a0\%a1\%a2\%a3\%a4\%a5\%a6\%a7\%a8\%a9\%aa\%ab\%ac\%ad\%ae\%af\%b0\%b1\%b2\%b3\%b4\%b5\%b6\%b7\%b8\%b9\%ba\%bb\%bc\%bd\%be\%bf\%c0\%c1\%c2\%c3\%c4\%c5\%c6\%c7\%c8\%c9\%ca\%cb\%cc\%cd\%ce\%cf\%d0\%d1\%d2\%d3\%d4\%d5\%d6\%d7\%d8\%d9\%da\%db\%dc\%dd\%de\%df\%e0\%e1\%e2\%e3\%e4\%e5\%e6\%e7\%e8\%e9\%ea\%eb\%ec\%ed\%ee\%ef\%f0\%f1\%f2\%f3\%f4\%f5\%f6\%f7\%f8\%f9\%fa\%fb\%fc\%fd\%fe\%ff",
                        "a.co/\%00\%01\%02\%03\%04\%05\%06\%07\%08\%09\%0a\%0b\%0c\%0d\%0e\%0f\%10\%11\%12\%13\%14\%15\%16\%17\%18\%19\%1a\%1b\%1c\%1d\%1e\%1f\%20\%21\%22\%23\%24\%25&\%27\%28\%29\%2a\%2b\%2c-.\%2f0123456789\%3a\%3b\%3c=\%3e?\%40abcdefghijklmnopqrstuvwxyz\%5b\%5c\%5d\%5e_\%60abcdefghijklmnopqrstuvwxyz\%7b\%7c\%7d~\%7f\%80\%81\%82\%83\%84\%85\%86\%87\%88\%89\%8a\%8b\%8c\%8d\%8e\%8f\%90\%91\%92\%93\%94\%95\%96\%97\%98\%99\%9a\%9b\%9c\%9d\%9e\%9f\%a0\%a1\%a2\%a3\%a4\%a5\%a6\%a7\%a8\%a9\%aa\%ab\%ac\%ad\%ae\%af\%b0\%b1\%b2\%b3\%b4\%b5\%b6\%b7\%b8\%b9\%ba\%bb\%bc\%bd\%be\%bf\%c0\%c1\%c2\%c3\%c4\%c5\%c6\%c7\%c8\%c9\%ca\%cb\%cc\%cd\%ce\%cf\%d0\%d1\%d2\%d3\%d4\%d5\%d6\%d7\%d8\%d9\%da\%db\%dc\%dd\%de\%df\%e0\%e1\%e2\%e3\%e4\%e5\%e6\%e7\%e8\%e9\%ea\%eb\%ec\%ed\%ee\%ef\%f0\%f1\%f2\%f3\%f4\%f5\%f6\%f7\%f8\%f9\%fa\%fb\%fc\%fd\%fe\%ff",
                        2048, URL_NORM_SUCCESS, __LINE__);

        // percent-encode reserved characters that were supposed to be percent-encode already
        normalize_check("a.com/!@$%^&*()_-=,.'", "a.com/%21%40%24%%5e&%2a%28%29_-=%2c.%27",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/!", "a.com/",    6, URL_NORM_TRUNCATED, __LINE__);
        normalize_check("a.com/!", "a.com/%",   7, URL_NORM_TRUNCATED, __LINE__);
        normalize_check("a.com/!", "a.com/%2",  8, URL_NORM_TRUNCATED, __LINE__);
        normalize_check("a.com/!", "a.com/%21", 9, URL_NORM_SUCCESS,   __LINE__);

        // remove '?' if there are no URL query parameters
        normalize_check("a.com/?",      "a.com/",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a?",     "a.com/a",     128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com//?",     "a.com/",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??",     "a.com/",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/???",    "a.com/",      128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?a=b",   "a.com/?a=b",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?a?=b",  "a.com/?a?=b", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??a?=b", "a.com/?a?=b", 128, URL_NORM_SUCCESS, __LINE__);

        // remove URL fragments
        // remove trailing whitespace
        normalize_check("a.com/#",      "a.com/",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/#a",     "a.com/",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/#a",     "a.com/",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/b#a",    "a.com/b",   128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/b/#a",   "a.com/b/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/b/c#a",  "a.com/b/c", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/ ",      "a.com/",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/  ",     "a.com/",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/a  ",    "a.com/a",   128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/ab  ",   "a.com/ab",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/# ",     "a.com/",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/#a ",    "a.com/",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/#a ",    "a.com/",    128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/b#a ",   "a.com/b",   128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/b/#a ",  "a.com/b/",  128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/b/c#a ", "a.com/b/c", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/b/c#a!@#$%^1234ABC DEF   ", "a.com/b/c", 128, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/b/c #a!@#$%^1234A", "a.com/b/c%20", 128, URL_NORM_SUCCESS, __LINE__);

        // remove redundant query parameter separators "&"
        // sort URL query parameters
        normalize_check("a.com/?a=b",                  "a.com/?a=b",                      1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?a=b&c=d",              "a.com/?a=b&c=d",                  1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?a=b&&c=d",             "a.com/?a=b&c=d",                  1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?c=d&&a=b",             "a.com/?a=b&c=d",                  1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??c=d&&a=b&e",          "a.com/?a=b&c=d&e",                1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??c=d&&a=b&e=",         "a.com/?a=b&c=d&e=",               1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??c=d&a=b&&e=",         "a.com/?a=b&c=d&e=",               1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??c=d&a=b&&g=h&e=f",    "a.com/?a=b&c=d&e=f&g=h",          1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??c^=d!&&g=h&e=f",      "a.com/?c\%5e=d\%21&e=f&g=h",      1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??z^=/./&&g=h&e=f",     "a.com/?e=f&g=h&z\%5e=\%2f.\%2f",  1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??z^=/../&&g=h&e=f",    "a.com/?e=f&g=h&z\%5e=\%2f..\%2f", 1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??z^=?&&g=h&e=f",       "a.com/?e=f&g=h&z\%5e=?",          1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??z^=?&&%20=h&%41=%42", "a.com/?%20=h&a=b&z\%5e=?",        1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??z^=?&&%20=&%41=%42",  "a.com/?%20=&a=b&z%5e=?",          1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?z=",                   "a.com/?z=",                       1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?z=&q=",                "a.com/?q=&z=",                    1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?ef=gh&ij=k&abc=d",     "a.com/?abc=d&ef=gh&ij=k",         1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?&&&&",                 "a.com/",                          1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?a=",                   "a.com/?a=",                       1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?a&",                   "a.com/?a",                        1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?a=&",                  "a.com/?a=",                       1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?a=&&",                 "a.com/?a=",                       1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??a=",                  "a.com/?a=",                       1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??a&",                  "a.com/?a",                        1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??a=&",                 "a.com/?a=",                       1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/??a=&&",                "a.com/?a=",                       1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?&c=d&a=b",             "a.com/?a=b&c=d",                  1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?&c=d&&a=b",            "a.com/?a=b&c=d",                  1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?&c=d&&a=b&",           "a.com/?a=b&c=d",                  1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?&c=d&&a=b&&",          "a.com/?a=b&c=d",                  1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?a=b&=",                "a.com/?a=b",                      1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?a",                    "a.com/?a",                        1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?a&",                   "a.com/?a",                        1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?b&a",                  "a.com/?a&b",                      1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?b&a&",                 "a.com/?a&b",                      1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?c&b&a",                "a.com/?a&b&c",                    1024, URL_NORM_SUCCESS, __LINE__);

        // Changing &amp; to & in query args
        normalize_check("a.com/&amp;/abc",              "a.com/&amp\%3b/abc",             1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?&amp",                  "a.com/?amp",                     1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?&amp;",                 "a.com/",                         1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?&amp;a",                "a.com/?a",                       1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?1=2&amp;3=4",           "a.com/?1=2&3=4",                 1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("a.com/?&amp;1=2&3=4&amp;",     "a.com/?1=2&3=4",                 1024, URL_NORM_SUCCESS, __LINE__);

        // Some fun random URLs and edge cases
        normalize_check("www.paypsl-ltd.co:443", "www.paypsl-ltd.co/", 1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("sc.hitz247.com:8000", "sc.hitz247.com/", 1024, URL_NORM_SUCCESS, __LINE__);
        normalize_check("http://cdd.net.ua/apothecary/products_new.php/?language=en&?p?=39&page=1", // not sure what should happen here...
                        "cdd.net.ua/apothecary/products_new.php??p?=39&language=en&page=1",
                        2048, URL_NORM_SUCCESS, __LINE__);
        normalize_check("http://gumblar.cn/düsseldorf", "gumblar.cn/d%c3%bcsseldorf", 1024, URL_NORM_SUCCESS, __LINE__);
    }

    {
        printf("\nTest line %d - NULL escaped\n", __LINE__);
        char url_out[1024];
        unsigned url_out_len = sizeof(url_out);
        is(url_normalize("abc.com/abc\0", 12, url_out, &url_out_len), URL_NORM_SUCCESS, "url_normalize() returns SUCCESS");
        SXED6("abc.com/abc\%00", url_out_len);
        SXED6(url_out, url_out_len);
        is(memcmp("abc.com/abc\%00", url_out, url_out_len), 0, "NULL's are escaped correctly");
    }

    return exit_status();
}
