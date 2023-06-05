/*
 * A url list is a hash-table of urls
 */

#include <ctype.h>
#include <errno.h>
#include <kit-alloc.h>
#include <mockfail.h>

#include "conf-loader.h"
#include "object-hash.h"
#include "url-normalize.h"
#include "urllist-private.h"
#include "urllist.h"
#include "uup-counters.h"

#define CONSTCONF2UL(confp) (const struct urllist *)((confp) ? (const char *)(confp) - offsetof(struct urllist, conf) : NULL)
#define CONF2UL(confp)      (struct urllist *)((confp) ? (char *)(confp) - offsetof(struct urllist, conf) : NULL)

#define URLLIST_OBJECT_HASH_ROWS  (1 << 14)    /* 16,384 rows with 7 usable cells per row = 114,688 cells and 1MB RAM */
#define URLLIST_OBJECT_HASH_LOCKS 32

static struct conf *urllist_allocate(const struct conf_info *info, struct conf_loader *cl);
static void urllist_free_base(struct conf *base);
static void urllist_free(struct urllist *ul);

static const struct conf_type ulct = {
    "urllist",
    urllist_allocate,
    urllist_free_base,
};
static const struct conf_type *ulctp = &ulct;

void
urllist_get_real_type_internals(struct conf_type *copy)
{
    /* Only used by tests - to get the original urllist type contents */
    *copy = ulct;
}

void
urllist_set_type_internals(const struct conf_type *replacement)
{
    /* Only used by tests - to hijack the original urllist type contents */
    ulctp = replacement ?: &ulct;
}

void
urllist_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(ulctp, NULL, name, fn, loadable, LOADFLAGS_UL_ALLOW_EMPTY_LISTS, NULL, 0);
}

const struct urllist *
urllist_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == ulctp, "urllist_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2UL(base);
}

static uint32_t
fnv04(char const *buf, int len)
{
   uint32_t hash = 0x811C9DC5;

   for (; --len >= 0; ++buf) {
       hash = (hash ^ *(uint8_t const *)buf) * 0x01000193;
   }

   hash += hash << 13;
   hash ^= hash >> 7;
   hash += hash << 3;
   hash ^= hash >> 17;
   hash += hash << 5;
   return hash;
}

static struct urllist_hash_bucket *
urllist_hash_find(const struct urllist *ul, const char *url, unsigned url_len)
{
    struct urllist_hash_bucket *bucket, **slot;
    uint32_t key;

    key = fnv04(url, url_len);
    slot = &ul->hash[key % ul->hash_size];
    for (bucket = *slot; bucket; bucket = bucket->next)
        if (bucket->hash_key == key && bucket->url_len == url_len && memcmp(bucket->url, url, url_len) == 0)
            break;

    SXEL6("%s(ul=?, url='%.*s', url_len=%u) {} // key=%u, %s", __FUNCTION__, url_len, url, url_len, key, bucket ? "matched" : "no match");

    return bucket;
}

/**
 * Search for a matching URL in a URL list. Partial URLs are matched
 *
 * @param ul      urllist to search in
 * @param url     URL to search for, which MUST be in normal form
 * @param url_len length of the URL
 *
 * @return 0 if no match or the length of the matching URL
 */
unsigned
urllist_match(const struct urllist *ul, const char *url, unsigned url_len)
{
    int      first_slash = 1;
    unsigned match_len;

    SXEE6("(ul=%p, url=%.*s, url_len=%u)", ul, url_len, url, url_len);

    if (ul) {
        for (match_len = 0; match_len < url_len; match_len++) {
            if (url[match_len] == '/') {
                if (urllist_hash_find(ul, url, match_len + first_slash)) {
                    match_len += first_slash;
                    goto DONE;
                }

                first_slash = 0;
            }

            if (url[match_len] == '?') {
                if (urllist_hash_find(ul, url, match_len))
                    goto DONE;

                break;
            }
        }

        if (urllist_hash_find(ul, url, url_len)) {
            match_len = url_len;
            goto DONE;
        }
    }

    match_len = 0;

DONE:
    SXER6("return %u", match_len);
    return match_len;
}

/* Returns -1 on fail, 0 on already in hashtable, or the depth of the bucket list */
static int
urllist_hash_add(struct urllist *ul, const char *url, unsigned url_len)
{
    int depth = 1;

    SXEE6("(ul=%p,url=%.*s,url_len=%u)", ul, url_len, url, url_len);

    if (urllist_match(ul, url, url_len)) {
        SXEL6("urllist_hash_add - discarding URL, match found");
        depth = 0;
        goto DONE;
    }

    uint32_t key = fnv04(url, url_len);
    struct urllist_hash_bucket **slot = &(ul->hash[key % ul->hash_size]);
    struct urllist_hash_bucket *new_bucket;

    if ((new_bucket = MOCKFAIL(URLLIST_HASHTABLE_ADD, NULL,
                               kit_malloc(sizeof(struct urllist_hash_bucket) + sizeof(char) * url_len))) == NULL) {
        SXEL2("Failed to allocate %zu bytes for urllist hashtable bucket", sizeof(struct urllist_hash_bucket) + sizeof(char) * url_len);
        depth = -1;
        goto DONE;
    }

    new_bucket->next = NULL; /* Always add to the end */
    new_bucket->hash_key = key;
    new_bucket->url_len = url_len;
    memcpy(new_bucket->url, url, url_len);

    if (*slot == NULL) {
        *slot = new_bucket;
    } else {
        struct urllist_hash_bucket *bucket = *slot;

        depth++;
        while (bucket->next != NULL) {
            bucket = bucket->next;
            depth++;
        }

        bucket->next = new_bucket;
    }

DONE:
    SXER6("return depth=%d", depth);
    return depth;
}

/* URLs are separated by a single separator character. */
static struct urllist *
urllist_parse(const char *list, int list_len, struct object_fingerprint *of, uint32_t loadflags)
{
    char normalized_url_buf[MAX_URL_LENGTH];
    unsigned normalized_url_buf_len;
    struct urllist *ul = NULL;
    int max_depth = 0;
    bool lf;

    SXEE6("(list=%p, list_len=%d, of=%p, loadflags=0x%" PRIX32 ")", list, list_len, of, loadflags);

    if (list_len == 0 && !(loadflags & LOADFLAGS_UL_ALLOW_EMPTY_LISTS)) {
        goto DONE;
    }

    if ((ul = MOCKFAIL(URLLIST_PARSE_URLLIST, NULL, kit_calloc(1, sizeof(struct urllist) + (of && of->hash ? of->len : 0)))) == NULL) {
        SXEL2("Failed to allocate %zu bytes for urllist list", sizeof(struct urllist));
        goto DONE;
    }

    unsigned hash_size = list_len / AVERAGE_URL_LENGTH;
    hash_size = hash_size ? hash_size : 1;
    SXEL6("URL list length '%d' means a hash size of '%u'", list_len, hash_size);
    ul->hash_size = hash_size;

    if ((ul->hash = MOCKFAIL(URLLIST_HASHTABLE_CREATE, NULL, kit_calloc(hash_size, sizeof(struct urllist_hash_bucket *)))) == NULL) {
        SXEL2("Failed to allocate %zu bytes for urllist hashtable", hash_size * sizeof(struct urllist_hash_bucket *));
        goto ERROR_OUT;
    }

    const char *reader = list;
    int reader_len = 0;

    lf = true;
    while (reader_len || reader < list + list_len) {
        if (reader + reader_len == list + list_len || isspace(reader[reader_len])) {
            /* end of input or end of a URL */
            if (reader_len) {
                /* process the URL */
                normalized_url_buf_len = sizeof(normalized_url_buf);
                URL_NORM_RETURN res = url_normalize(reader, reader_len, normalized_url_buf, &normalized_url_buf_len);

                if (res == URL_NORM_TRUNCATED) {
                    SXEL3("Offset %zd: URL was truncated during normalization: '%.*s'", reader - list, reader_len, reader);
                    if (loadflags & LOADFLAGS_UL_STRICT)
                        goto ERROR_OUT;
                }

                if (res == URL_NORM_FAILED) {
                    SXEL3("Offset %zd: URL failed to normalize: '%.*s'", reader - list, reader_len, reader);
                    if (loadflags & LOADFLAGS_UL_STRICT)
                        goto ERROR_OUT;
                } else {
                    int depth = urllist_hash_add(ul, normalized_url_buf, normalized_url_buf_len);

                    if (depth < 0)
                        goto ERROR_OUT;
                    if (depth > max_depth)
                        max_depth = depth;
                }
                reader += reader_len;
                reader_len = 0;
                lf = false;
            }

            if (reader < list + list_len && *reader++ == '\n')
                lf = true;
        } else if (!reader_len++ && !lf && loadflags & LOADFLAGS_UL_LINEFEED_REQUIRED) {
            SXEL2("Offset %zd: Only one url may be present per line", reader - list);
            goto ERROR_OUT;
        }
    }

    SXEL6("Max URL list hash depth is %u", max_depth);
    if (max_depth != 0 || (loadflags & LOADFLAGS_UL_ALLOW_EMPTY_LISTS)) {
        if (of && of->hash) {
            ul->oh = of->hash;
            memcpy(ul->fingerprint, of->fp, of->len);

            if (object_hash_add(ul->oh, ul, of->fp, of->len) == NULL) {
                SXEL2("Failed to hash urllist object; memory exhaustion?");
                ul->oh = NULL;
            }
        }

        goto DONE;
    }

ERROR_OUT:
    urllist_free(ul);
    ul = NULL;

DONE:
    SXER6("return ul=%p", ul);
    return ul;
}

static bool
urllist_hash_use(void *v, void **vp)
{
    struct object_fingerprint *of = v;
    struct urllist *candidate = *vp;

    if (memcmp(candidate->fingerprint, of->fp, of->len) == 0) {
        urllist_refcount_inc(candidate);
        return true;
    }

    return false;
}

struct urllist *
urllist_new_from_buffer(const char *buf, int len, struct object_fingerprint *of, uint32_t loadflags)
{
    struct urllist *result = NULL;
    unsigned magic;

    SXEE7("(buf=%p, len=%d, of=%p, loadflags=0x%" PRIX32 ")", buf, len, of, loadflags);

    if (of) {
        if (of->hash == NULL)
            of->hash = object_hash_new(URLLIST_OBJECT_HASH_ROWS, URLLIST_OBJECT_HASH_LOCKS, of->len);
        else if ((magic = object_hash_magic(of->hash)) != of->len) {
            SXEL2("Invalid urllist fingerprint; length should be %u, not %u", magic, of->len);
            goto DONE;
        } else
            result = object_hash_action(of->hash, of->fp, of->len, urllist_hash_use, of);

        kit_counter_incr(result ? COUNTER_UUP_OBJECT_HASH_HIT : COUNTER_UUP_OBJECT_HASH_MISS);
    }

    if (result == NULL && (result = urllist_parse(buf, len, of, loadflags)) != NULL)
        conf_setup(&result->conf, ulctp);

DONE:
    SXER7("return %p", result);
    return result;
}

static struct urllist *
urllist_new_from_file(struct conf_loader *cl, unsigned maxlines, uint32_t loadflags)
{
    struct urllist *result = NULL;
    size_t buf_len;
    char *buf;

    SXEE7("(cl=%p, maxlines=%u, loadflags=0x%" PRIX32 ") // path=%s", cl, maxlines, loadflags, conf_loader_path(cl));

    if ((buf = conf_loader_readfile(cl, &buf_len, maxlines)) != NULL) {
        result = urllist_parse(buf, buf_len, NULL, loadflags);
        kit_free(buf);
    }

    if (result != NULL)
        conf_setup(&result->conf, ulctp);

    SXER7("return %p", result);

    if (result == NULL)
        errno = EINVAL;

    return result;
}

struct urllist *
urllist_new(struct conf_loader *cl)
{
    return urllist_new_from_file(cl, 0, LOADFLAGS_UL_ALLOW_EMPTY_LISTS);
}

struct urllist *
urllist_new_strict(struct conf_loader *cl, unsigned maxlines)
{
    return urllist_new_from_file(cl, maxlines, LOADFLAGS_UL_LINEFEED_REQUIRED | LOADFLAGS_UL_STRICT);
}

static struct conf *
urllist_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct urllist *me;

    SXEA6(info->type == ulctp, "%s() with unexpected conf_type %s", __FUNCTION__, info->type->name);
    me = urllist_new_from_file(cl, 0, info->loadflags);

    return me ? &me->conf : NULL;
}

static bool
urllist_hash_remove(void *v, void **vp)
{
    struct urllist *candidate = *vp;
    struct urllist *me = v;

    if (me == candidate && me->conf.refcount == 0) {
        *vp = NULL;
        return true;
    }
    return false;
}

static void
urllist_free(struct urllist *ul)
{
    struct urllist_hash_bucket *bk, *bk_next;
    unsigned i;

    SXEL7("urllist_free(ul=%p) {}", ul);

    if (ul->oh && !object_hash_action(ul->oh, ul->fingerprint, object_hash_magic(ul->oh), urllist_hash_remove, ul)) {
        /*-
         * XXX: It's unusal to get here...
         *      1. This thread gets into urllist_free()
         *      2. Other thread gets a reference to me through the object-hash
         *      3. This thread fails the object_hash_action(..., urllist_hash_remove, ...)
         *      4. Other thread releases its reference
         * When we get to this point, the other thread will delete (or already has deleted) the object internals,
         * so in fact, the object_hash_action() failure implies that the object is now somebody else's problem.
         */
        SXEL6("Failed to remove urllist from its hash (refcount %d); another thread raced to get a reference", ul->conf.refcount);
    } else {
        if (ul->hash != NULL) {
            for (i = 0; i < ul->hash_size; i++)
                for (bk = ul->hash[i]; bk; bk = bk_next) {
                    bk_next = bk->next;
                    kit_free(bk);
                }
            kit_free(ul->hash);
        }
        kit_free(ul);
    }
}

static void
urllist_free_base(struct conf *base)
{
    struct urllist *ul = CONF2UL(base);

    SXEA6(base->type == ulctp, "urllist_free() with unexpected conf_type %s", base->type->name);
    urllist_free(ul);
}

void
urllist_refcount_inc(struct urllist *me)
{
    CONF_REFCOUNT_INC(me);
}

void
urllist_refcount_dec(struct urllist *me)
{
    CONF_REFCOUNT_DEC(me);
}
