#include <kit-alloc.h>
#include <mockfail.h>
#include <string.h>
#include <tap.h>

#include "parseline.h"

int
main(void)
{
    const char *key, *value;
    char buf[1024], *p;
    size_t klen, vlen;
    int n;

    plan_tests(36);

    diag("Comments at the end of lines are removed");
    {
        strcpy(buf, "hello world # comment");
        n = parseline_spaces(buf, &key, &klen, &value, &vlen);
        is(n, 2, "parseline with a comment gets multiple tokens");
        ok(word_match("hello", key, klen), "The key is correct");
        ok(word_match("world", value, vlen), "The value is trimmed correctly");
        p = word_dup(value, vlen);
        is_eq(p, "world", "word_dup works ok");
        kit_free(p);
    }

    diag("Leading whitespace is ignored");
    {
        strcpy(buf, " \t\n\rhello world");
        n = parseline_spaces(buf, &key, &klen, &value, &vlen);
        is(n, 2, "parseline with leading spaces gets multiple tokens");
        ok(word_match("hello", key, klen), "The key is correct");
        ok(word_match("world", value, vlen), "The value is correct");
    }

    diag("Empty lines are identified");
    {
        strcpy(buf, " \t\n\r");
        n = parseline_spaces(buf, &key, &klen, &value, &vlen);
        is(n, 0, "parseline with only whitespace returns zero");
    }

    diag("Lines with only one token are identified");
    {
        strcpy(buf, " \t\n\rwhat ");
        n = parseline_spaces(buf, &key, &klen, &value, &vlen);
        is(n, 1, "parseline with only one token returns one");
        ok(word_match("what", key, klen), "The token was trimmed correctly");
        p = word_dup(key, klen);
        is_eq(p, "what", "word_dup works ok");
        kit_free(p);
    }

    diag("A CSV-style line can be parsed");
    {
        strcpy(buf, ",field2,field3,,field5,");
        n = parseline(buf, &key, &klen, &value, &vlen, ",", false);
        is(n, 2, "parseline with multiple tokens gives a result of 2");
        ok(word_match("", key, klen), "The first token is empty");
        ok(word_match("field2,field3,,field5,", value, vlen), "The second token is the remainder");

        n = parseline(value, &key, &klen, &value, &vlen, ",", false);
        is(n, 2, "parseline again gives a result of 2");
        ok(word_match("field2", key, klen), "The first token is 'field2'");
        ok(word_match("field3,,field5,", value, vlen), "The second token is the remainder");

        n = parseline(value, &key, &klen, &value, &vlen, ",", false);
        is(n, 2, "parseline again gives a result of 2");
        ok(word_match("field3", key, klen), "The first token is 'field3'");
        ok(word_match(",field5,", value, vlen), "The second token is the remainder");

        n = parseline(value, &key, &klen, &value, &vlen, ",", false);
        is(n, 2, "parseline again gives a result of 2");
        ok(word_match("", key, klen), "The first token is empty");
        ok(word_match("field5,", value, vlen), "The second token is the remainder");

        n = parseline(value, &key, &klen, &value, &vlen, ",", false);
        is(n, 2, "parseline again gives a result of 2");
        ok(word_match("field5", key, klen), "The first token is 'field5'");
        ok(word_match("", value, vlen), "The second token is empty");

        n = parseline(value, &key, &klen, &value, &vlen, ",", false);
        is(n, 0, "parseline again gives a result of 0");
    }

    diag("Using the same data but with multi=true gives different behaviour");
    {
        strcpy(buf, ",field2,field3,,field5,");
        n = parseline(buf, &key, &klen, &value, &vlen, ",", true);
        is(n, 2, "parseline with multiple tokens gives a result of 2");
        ok(word_match("field2", key, klen), "The first token is 'field2'");
        ok(word_match("field3,,field5", value, vlen), "The second token is the remainder and excludes trailing separators");

        n = parseline(value, &key, &klen, &value, &vlen, ",", true);
        is(n, 2, "parseline again gives a result of 2");
        ok(word_match("field3", key, klen), "The first token is 'field3'");
        ok(word_match("field5", value, vlen), "The second token is the remainder");

        n = parseline(value, &key, &klen, &value, &vlen, ",", true);
        is(n, 1, "parseline again gives a result of 2");
        ok(word_match("field5", key, klen), "The first token is 'field5'");
    }

    diag("Test allocation failure");
    {
        MOCKFAIL_START_TESTS(1, word_dup);
        ok(!word_dup("word", 4), "Cannot duplicate a word if malloc fails");
        MOCKFAIL_END_TESTS();
    }

    return exit_status();
}
