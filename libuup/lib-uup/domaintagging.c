#include <errno.h>
#include <kit-alloc.h>
#include <mockfail.h>

#include "conf-loader.h"
#include "domaintagging-private.h"
#include "prefixtree.h"
#include "xray.h"

#define CONSTCONF2DT(confp) (const struct domaintagging *)((confp) ? (const char *)(confp) - offsetof(struct domaintagging, conf) : NULL)
#define CONF2DT(confp)      (struct domaintagging *)((confp) ? (char *)(confp) - offsetof(struct domaintagging, conf) : NULL)

/*
 * We know that pref_categories_{un,}pack() uses bit 0 to indicate that
 * something's packed.
 *
 * Here, we work in terms of "offset pointers" by taking our value as an
 * offset count from me->pool_value, adding 1 and shifting it left one.
 *
 * These "offset pointers" are stored as our prefixtree values and allow
 * us to realloc me->pool_value without invalidating those prefixtree values.
 */
#define VALUE_AS_OFFSETPTR(me, value) ((void *)((uintptr_t)((value) - (me)->value_pool + 1) << 1))
#define OFFSETPTR_AS_VALUE(me, found) ((me)->value_pool + (((uintptr_t)(found)) >> 1) - 1)

static struct conf *domaintagging_allocate(const struct conf_info *info, struct conf_loader *cl);
static void domaintagging_free(struct conf *base);

static const struct conf_type dtct = {
    "domaintagging",
    domaintagging_allocate,
    domaintagging_free,
};

void
domaintagging_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(&dtct, NULL, name, fn, loadable, LOADFLAGS_NONE, NULL, 0);
}

const struct domaintagging *
domaintagging_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &dtct, "domaintagging_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2DT(base);
}

bool
domaintagging_match(const struct domaintagging *me, pref_categories_t *all_categories, const uint8_t *name, struct xray *x, const char *listname)
{
    pref_categories_t cat, *found;
    uint8_t key[DNS_MAXLEN_NAME];
    bool result = false;
    int name_len;

    if (me != NULL) {
        name_len = dns_name_len(name);
        dns_name_prefixtreekey(key, name, name_len);
        if (memcmp(me->first, key, name_len) > 0 || memcmp(me->last, key, name_len) < 0) {
            SXEL7("%s: %s: Outside of the domaintagging key range - no match", __FUNCTION__, dns_name_to_str1(name));
            result = false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        } else if ((found = prefixtree_prefix_get(me->prefixtree, key, &name_len)) != NULL) {
            found = pref_categories_unpack(&cat, found) ? &cat : OFFSETPTR_AS_VALUE(me, found);    /* recover the *real* categories! */
            XRAY6(x, "%s match: bits %s", listname, pref_categories_idstr(found));
            pref_categories_union(all_categories, all_categories, found);
            result = true;
        }
    }

    return result;
}

static bool
prefixtree_first(const uint8_t *key, uint8_t key_len, void *v, void *userdata)
{
    SXE_UNUSED_PARAMETER(key);
    SXE_UNUSED_PARAMETER(key_len);
    SXE_UNUSED_PARAMETER(userdata);

    return v == NULL;
}

struct domaintagging *
domaintagging_new(struct conf_loader *cl)
{
    uint8_t key[DNS_MAXLEN_NAME], name[DNS_MAXLEN_NAME];
    pref_categories_t cat, *value;
    struct domaintagging *me = NULL;
    int consumed;
    const char *line, *p;
    unsigned version, name_len;
    void **value_ptr;
    size_t count, n;

    if ((line = conf_loader_readline(cl)) == NULL || sscanf(line, "domaintagging %u\n", &version) != 1 || version != DOMAINTAGGING_VERSION) {
        SXEL2("%s: Unrecognized header line, expected 'domaintagging %u'", conf_loader_path(cl), DOMAINTAGGING_VERSION);
        goto ERROR;
    }

    if ((me = MOCKFAIL(DOMAINTAGGING_NEW, NULL, kit_malloc(sizeof(*me)))) == NULL) {
        SXEL2("%s: Couldn't allocate %zu bytes", conf_loader_path(cl), sizeof(*me));
        goto ERROR;
    }

    conf_setup(&me->conf, &dtct);
    me->value_pool = NULL;
    me->version = version;

    if ((me->prefixtree = prefixtree_new()) == NULL)
        goto ERROR;

    if ((line = conf_loader_readline(cl)) == NULL || sscanf(line, "count %zu\n", &count) != 1) {
        SXEL2("%s: %u: Unrecognized count line, expected 'count N'", conf_loader_path(cl), conf_loader_line(cl));
        goto ERROR;
    }

    value = &cat;

    for (n = 0; (line = conf_loader_readline(cl)) != NULL; n++) {
        if (n == count) {
            SXEL2("%s: %u: unexpected line (exceeds count)", conf_loader_path(cl), conf_loader_line(cl));
            goto ERROR;
        }

        name_len = sizeof(name);
        if ((p = dns_name_sscan_len(line, ":", name, &name_len)) == NULL) {
            SXEL2("%s: %u: Invalid domain name", conf_loader_path(cl), conf_loader_line(cl));
            goto ERROR;
        }

        if (*p++ != ':') {
            SXEL2("%s: %u: Missing colon separator", conf_loader_path(cl), conf_loader_line(cl));
            goto ERROR;
        }

        dns_name_prefixtreekey(key, name, name_len);

        if ((value_ptr = prefixtree_put(me->prefixtree, key, name_len)) == NULL)
            goto ERROR;

        if ((consumed = pref_categories_sscan(value, p)) == 0 || (p[consumed] != '\n' && p[consumed] != 0)) {
            SXEL2("%s: %u: Invalid categories", conf_loader_path(cl), conf_loader_line(cl));
            goto ERROR;
        }

        if (!n || memcmp(me->last, key, name_len) < 0) {
            memcpy(me->last, key, name_len);
            memset(me->last + name_len, '\255', sizeof(me->last) - name_len);
        }

        if ((*value_ptr = pref_categories_pack(value)) == NULL) {
            if (me->value_pool == NULL) {
                if ((me->value_pool = MOCKFAIL(DOMAINTAGGING_NEW_POOL, NULL, kit_malloc((count - n) * sizeof(*me->value_pool)))) == NULL) {
                    SXEL2("%s: Couldn't allocate %zu bytes for categories", conf_loader_path(cl), (count - n) * sizeof(*me->value_pool));
                    goto ERROR;
                }
                value = me->value_pool;
                *value = cat;
            }
            /* We store the value_pool "offset pointer" rather than the real pointer */
            *value_ptr = VALUE_AS_OFFSETPTR(me, value);
            value++;
        } else
            SXEA6((intptr_t)*value_ptr & 1, "pref_categories_pack() didn't set bit 0");
    }
    if (!conf_loader_eof(cl) || n != count) {
        SXEL2("%s: %u: unexpected end of file at record %zu (less than count %zu)", conf_loader_path(cl), conf_loader_line(cl), n, count);
        goto ERROR;
    }
    if (me->value_pool)
        me->value_pool = kit_reduce(me->value_pool, (uint8_t *)value - (uint8_t *)me->value_pool);

    if (count) {
        name_len = 0;
        prefixtree_walk(me->prefixtree, prefixtree_first, me->first, &name_len, NULL);
        memset(me->first + name_len, '\0', sizeof(me->first) - name_len);
    }

    SXEL6("%s(cl=?) {} // %zu entries", __FUNCTION__, count);
    return me;

ERROR:
    CONF_REFCOUNT_DEC(me);
    SXEL6("%s(cl=?) {} // return NULL", __FUNCTION__);
    errno = EINVAL;

    return NULL;
}

static struct conf *
domaintagging_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct domaintagging *me;

    SXE_UNUSED_PARAMETER(info);
    SXEA6(info->type == &dtct, "%s() with unexpected conf_type %s", __FUNCTION__, info->type->name);
    if ((me = domaintagging_new(cl)) != NULL)
        conf_report_load(info->type->name, me->version);
    return me ? &me->conf : NULL;
}

static void
domaintagging_free(struct conf *base)
{
    struct domaintagging *me = CONF2DT(base);

    prefixtree_delete(me->prefixtree, NULL);
    kit_free(me->value_pool);
    kit_free(me);
}
