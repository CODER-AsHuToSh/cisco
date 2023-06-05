#include <kit-alloc.h>
#include <sxe-util.h>
#include <tap.h>

#include "cidrlist.h"
#include "domainlist-private.h"
#include "object-hash.h"
#include "uint32list.h"
#include "urllist-private.h"

#include "common-test.h"

extern void (*uint32list_free_hook)(struct uint32list *me);
static void (*real_uint32list_free)(struct uint32list *me);
static struct conf_type real_type;
struct {
    struct object_fingerprint *fp;

    const char *new_applicationlist_content;
    struct uint32list *created_al;

    const char *new_domainlist_content;
    struct domainlist *created_dl;

    const char *new_urllist_content;
    struct urllist *created_ul;

    const char *new_cidrlist_content;
    struct cidrlist *created_cl;
} sneaky;

static void
uint32list_free_overload(struct uint32list *al)
{
    if (sneaky.new_applicationlist_content) {
        sneaky.created_al = uint32list_new(sneaky.new_applicationlist_content, sneaky.fp);
        sneaky.new_applicationlist_content = NULL;
        sneaky.fp = NULL;
    }
    real_uint32list_free(al);
}

static void
hijacked_object_free(struct conf *base)
{
    size_t len;
    const char *consumed;
    /*
     * The hijacked *list_free function allocates a new *list object at a
     * critical point - just before the object is actually freed.  The
     * expected behaviour is that the real *list_free() function notices
     * this and doesn't actually destroy the object internals, leaving the
     * object-hash referring to a still-intact object.
     */

    if (sneaky.new_domainlist_content) {
        len = strlen(sneaky.new_domainlist_content);
        sneaky.created_dl = domainlist_new_from_buffer(sneaky.new_domainlist_content, len, sneaky.fp, LOADFLAGS_NONE);
        sneaky.new_domainlist_content = NULL;
        sneaky.fp = NULL;
    } else if (sneaky.new_urllist_content) {
        len = strlen(sneaky.new_urllist_content);
        sneaky.created_ul = urllist_new_from_buffer(sneaky.new_urllist_content, len, sneaky.fp, LOADFLAGS_NONE);
        sneaky.new_urllist_content = NULL;
        sneaky.fp = NULL;
    } else if (sneaky.new_cidrlist_content) {
        sneaky.created_cl = cidrlist_new_from_string(sneaky.new_cidrlist_content, " ", &consumed, sneaky.fp, PARSE_IP_OR_CIDR);
        sneaky.new_cidrlist_content = NULL;
        sneaky.fp = NULL;
    }
    real_type.free(base);
}

int
main(int argc, char **argv)
{
    struct object_fingerprint of;
    uint64_t start_allocations;
    struct conf_type fake_type;
    char fp[9];

    SXE_UNUSED_PARAMETER(argc);
    SXE_UNUSED_PARAMETER(argv);

    plan_tests(34);

    kit_memory_initialize(false);
    /* KIT_ALLOC_SET_LOG(1); */
    ok(start_allocations = memory_allocations(), "Clocked the initial # memory allocations");

    of.hash = NULL;
    of.fp = (const uint8_t *)fp;
    of.len = sizeof(fp) - 1;

    /* Set to 6 to suppress opendnscache domainlist debug logging since this is kind of a stress test */
    putenv(SXE_CAST_NOCONST(char *, "SXE_LOG_LEVEL_OPENDNSCACHE_LIB_OPENDNSCACHE=6"));

    diag("Test that applicationlist races behave");
    {
        struct uint32list *al;
        const char *content;

        content = "46670 46684 46826 600 733592 915 986256";

        of.hash = object_hash_new(32, 32, 8);
        al = uint32list_new(content, &of);
        ok(al, "Created an applicationlist with seven ids");
        uint32list_refcount_dec(al);
        object_hash_free(of.hash);
        of.hash = NULL;
        is(memory_allocations(), start_allocations, "Memory was freed after the applicationlist was freed");

        /* Now hijack the uint32list_free() function */
        real_uint32list_free = uint32list_free_hook;
        uint32list_free_hook = uint32list_free_overload;
        memset(&sneaky, '\0', sizeof(sneaky));
        sneaky.new_applicationlist_content = content;
        sneaky.fp = &of;

        /* And create the applicationlist - racing a uint32list_new() against the last refcount_dec() */
        of.hash = object_hash_new(32, 32, 8);
        al = uint32list_new(content, &of);
        ok(al, "Created a hijacked applicationlist with seven ids");
        ok(!sneaky.created_al, "No sneaky created applicationlist yet");
        uint32list_refcount_dec(al);
        ok(sneaky.created_al, "The uint32list_refcont_dec() populated the sneaky applicationlist");
        is(sneaky.created_al, al, "The sneaky applicationlist is the same pointer");
        is(sneaky.created_al->refcount, 1, "The sneaky applicationlist has a refcount of 1");
        uint32list_refcount_dec(sneaky.created_al);
        object_hash_free(of.hash);
        of.hash = NULL;

        /* Restore the uint32list_free() function */
        uint32list_free_hook = real_uint32list_free;

        is(memory_allocations(), start_allocations, "Memory was freed after the domainlist was freed");
    }

    diag("Test that domainlist races behave");
    {
        struct domainlist *dl;
        const char *content;
        size_t clen;

        content = "a.com b.com c.com";
        clen = strlen(content);

        of.hash = object_hash_new(32, 32, 8);
        dl = domainlist_new_from_buffer(content, clen, &of, LOADFLAGS_NONE);
        ok(dl, "Created a domainlist with three domains");
        domainlist_refcount_dec(dl);
        object_hash_free(of.hash);
        of.hash = NULL;
        is(memory_allocations(), start_allocations, "Memory was freed after the domainlist was freed");

        /* Now hijack the domainlist_free() function */
        domainlist_get_real_type_internals(&real_type);
        fake_type.name = "fake-domainlist";
        fake_type.allocate = real_type.allocate;
        fake_type.free = hijacked_object_free;
        memset(&sneaky, '\0', sizeof(sneaky));
        sneaky.new_domainlist_content = content;
        sneaky.fp = &of;
        domainlist_set_type_internals(&fake_type);

        /* And create the domainlist - racing a domainlist_new() against the last refcount_dec() */
        of.hash = object_hash_new(32, 32, 8);
        dl = domainlist_new_from_buffer(content, clen, &of, LOADFLAGS_NONE);
        ok(dl, "Created a hijacked domainlist with three domains");
        ok(!sneaky.created_dl, "No sneaky created domainlist yet");
        domainlist_refcount_dec(dl);
        ok(sneaky.created_dl, "The domainlist_refcont_dec() populated the sneaky domainlist");
        is(sneaky.created_dl, dl, "The sneaky domainlist is the same pointer");
        is(sneaky.created_dl->conf.refcount, 1, "The sneaky domainlist has a refcount of 1");
        domainlist_refcount_dec(sneaky.created_dl);
        object_hash_free(of.hash);
        of.hash = NULL;

        /* Restore the domainlist type internals */
        domainlist_set_type_internals(NULL);

        is(memory_allocations(), start_allocations, "Memory was freed after the domainlist was freed");
    }

    diag("Test that urllist races behave");
    {
        const char *content;
        struct urllist *ul;
        size_t clen;

        content = "http://a.co/cx/15195/100/setup_1848x19m.exe?z=z&super=bad&test=yes "
                  "http://c.co/cx/15195/100/ "
                  "http://d.co/cx/15195/100 "
                  "http://g.com/a/d "
                  "http://h.com/a/ "
                  "http://i.com/a ";
        clen = strlen(content);

        of.hash = object_hash_new(32, 32, 8);
        ul = urllist_new_from_buffer(content, clen, &of, LOADFLAGS_NONE);
        ok(ul, "Created a urllist with six urls");
        urllist_refcount_dec(ul);
        object_hash_free(of.hash);
        of.hash = NULL;
        is(memory_allocations(), start_allocations, "Memory was freed after the urllist was freed");

        /* Now hijack the urllist_free() function */
        urllist_get_real_type_internals(&real_type);
        fake_type.name = "fake-urllist";
        fake_type.allocate = real_type.allocate;
        fake_type.free = hijacked_object_free;
        memset(&sneaky, '\0', sizeof(sneaky));
        sneaky.new_urllist_content = content;
        sneaky.fp = &of;
        urllist_set_type_internals(&fake_type);

        /* And create the urllist - racing a urllist_new() against the last refcount_dec() */
        of.hash = object_hash_new(32, 32, 8);
        ul = urllist_new_from_buffer(content, clen, &of, LOADFLAGS_NONE);
        ok(ul, "Created a hijacked urllist with six urls");
        ok(!sneaky.created_ul, "No sneaky created urllist yet");
        urllist_refcount_dec(ul);
        ok(sneaky.created_ul, "The urllist_refcont_dec() populated the sneaky urllist");
        is(sneaky.created_ul, ul, "The sneaky urllist is the same pointer");
        is(sneaky.created_ul->conf.refcount, 1, "The sneaky urllist has a refcount of 1");
        urllist_refcount_dec(sneaky.created_ul);
        object_hash_free(of.hash);
        of.hash = NULL;

        /* Restore the urllist type internals */
        urllist_set_type_internals(NULL);

        is(memory_allocations(), start_allocations, "Memory was freed after the urllist was freed");
    }

    diag("Test that cidrlist races behave");
    {
        const char *consumed;
        const char *content;
        struct cidrlist *cl;

        content = "10.0.0.0/8 208.67.222.0/24 ::1/128 2001:470:e83b:a7::/64 172.16.0.0/12";

        of.hash = object_hash_new(32, 32, 8);
        cl = cidrlist_new_from_string(content, " ", &consumed, &of, PARSE_IP_OR_CIDR);
        ok(cl, "Created a cidrlist with five cidrs");
        cidrlist_refcount_dec(cl);
        object_hash_free(of.hash);
        of.hash = NULL;
        is(memory_allocations(), start_allocations, "Memory was freed after the cidrlist was freed");

        /* Now hijack the cidrlist_free() function */
        cidrlist_get_real_type_internals(&real_type);
        fake_type.name = "fake-cidrlist";
        fake_type.allocate = real_type.allocate;
        fake_type.free = hijacked_object_free;
        memset(&sneaky, '\0', sizeof(sneaky));
        sneaky.new_cidrlist_content = content;
        sneaky.fp = &of;
        cidrlist_set_type_internals(&fake_type);

        /* And create the cidrlist - racing a cidrlist_new() against the last refcount_dec() */
        of.hash = object_hash_new(32, 32, 8);
        cl = cidrlist_new_from_string(content, " ", &consumed, &of, PARSE_IP_OR_CIDR);
        ok(cl, "Created a hijacked cidrlist with five cidrs");
        ok(!sneaky.created_cl, "No sneaky created cidrlist yet");
        cidrlist_refcount_dec(cl);
        ok(sneaky.created_cl, "The cidrlist_refcont_dec() populated the sneaky cidrlist");
        is(sneaky.created_cl, cl, "The sneaky cidrlist is the same pointer");
        is(sneaky.created_cl->conf.refcount, 1, "The sneaky cidrlist has a refcount of 1");
        cidrlist_refcount_dec(sneaky.created_cl);
        object_hash_free(of.hash);
        of.hash = NULL;

        /* Restore the cidrlist type internals */
        cidrlist_set_type_internals(NULL);

        is(memory_allocations(), start_allocations, "Memory was freed after the cidrlist was freed");
    }

    is(memory_allocations(), start_allocations, "All memory allocations were freed");
    /* KIT_ALLOC_SET_LOG(0); */

    return exit_status();
}
