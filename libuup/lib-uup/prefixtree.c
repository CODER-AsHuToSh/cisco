/* PATRICIA trees. */

#include <kit-alloc.h>
#include <mockfail.h>
#include <string.h>

#include "prefixtree.h"

struct prefixtree {
    struct prefixtree **children;
    void *value;
    uint8_t children_len;    /* See NUMCHILDREN() - 0 may actually mean 256! */
    uint8_t label_len;
    uint8_t label[];
} __attribute__((__packed__));

#define NUMCHILDREN(pt) (int)((pt)->children_len ?: (pt)->children ? 256 : 0)

static int
prefixtree_find(struct prefixtree *me, uint8_t ch)
{
    int cmp, i, lim, pos;

    for (pos = 0, lim = NUMCHILDREN(me); lim; lim >>= 1) {
        i = pos + (lim >> 1);
        if ((cmp = (int)ch - (int)*me->children[i]->label) == 0) {
            pos = i;
            break;
        } else if (cmp > 0) {
            pos = i + 1;
            lim--;
        }
    }

    return pos;
}

static struct prefixtree *
prefixtree_child_get(struct prefixtree *me, const uint8_t *key, int len)
{
    int i;

    if ((i = prefixtree_find(me, *key)) < NUMCHILDREN(me)
     && me->children[i]->label_len <= len
     && memcmp(key, me->children[i]->label, me->children[i]->label_len) == 0)
        return me->children[i];

    return NULL;
}

static bool
prefixtree_child_put(struct prefixtree *me, struct prefixtree *child)
{
    struct prefixtree **tmp;
    int i, nalloc;

    SXEA1(NUMCHILDREN(me) <= UINT8_MAX, "Child node overflow... not possible");
    i = prefixtree_find(me, *child->label);
    SXEA6(i == NUMCHILDREN(me) || me->children[i]->label[0] != *child->label, "Unexpectedly found the thing I'm supposed to insert");
    if (!NUMCHILDREN(me) || (NUMCHILDREN(me) & (NUMCHILDREN(me) - 1)) == 0) {
        nalloc = NUMCHILDREN(me) ? NUMCHILDREN(me) << 1 : 1;
        if ((tmp = MOCKFAIL(prefixtree_put, NULL, kit_realloc(me->children, nalloc * sizeof(*me->children)))) == NULL) {
            SXEL2("Failed to realloc space for %u prefixtree child%s", nalloc, nalloc == 1 ? "" : "ren");
            return false;
        }
        me->children = tmp;
    }
    if (me->children_len)    /* NOTE: NUMCHILDREN() is broken when me->children_len == 0 'till we update it to 1 */
        memmove(me->children + i + 1, me->children + i, (NUMCHILDREN(me) - i) * sizeof(*me->children));
    me->children[i] = child;
    me->children_len++;

    return true;
}

bool
prefixtree_walk(struct prefixtree *me, bool (*callback)(const uint8_t *, uint8_t, void *, void *), uint8_t *key,
                unsigned *key_len, void *userdata)
{
    int i;

    if (me != NULL) {
        memcpy(key + *key_len, me->label, me->label_len);
        *key_len += me->label_len;

        if (!callback(key, *key_len, me->value, userdata))
            return false;

        for (i = 0; i < NUMCHILDREN(me); i++)
            if (!prefixtree_walk(me->children[i], callback, key, key_len, userdata))
                return false;

        *key_len -= me->label_len;
    }

    return true;
}

void
prefixtree_delete(struct prefixtree *me, void (*callback)(void *))
{
    int i;

    if (me) {
        if (callback != NULL)
            callback(me->value);
        for (i = 0; i < NUMCHILDREN(me); i++)
            prefixtree_delete(me->children[i], callback);
        kit_free(me->children);
        kit_free(me);
    }
}

void *
prefixtree_get(struct prefixtree *me, const uint8_t *key, int len)
{
    int i = 0;

    if (me)
        while (i < len && (me = prefixtree_child_get(me, &key[i], len - i)) != NULL)
            i += me->label_len;

    return me == NULL ? NULL : me->value;
}

static struct prefixtree *
prefixtree_new_internal(const uint8_t *key, int len)
{
    struct prefixtree *me;

    if ((me = MOCKFAIL(prefixtree_new, NULL, kit_malloc(sizeof(*me) + len))) == NULL)
        SXEL2("Couldn't allocate a new prefixtree");
    else {
        me->children_len = 0;
        me->children = NULL;
        me->value = NULL;
        me->label_len = len;
        memcpy(me->label, key, len);
    }

    return me;
}

struct prefixtree *
prefixtree_new(void)
{
    return prefixtree_new_internal(NULL, 0);
}

void **
prefixtree_put(struct prefixtree *me, const uint8_t *key, int len)
{
    int i = 0, j, prefix_len, prefix_len_limit;
    struct prefixtree *tmp, *tmp2;

    /*
     * A full domain name may not exceed a total length of 253 characters in
     * its external dotted-label specification. In the internal binary
     * representation of the DNS the maximum length requires 255 octets of
     * storage (RFC 1034).
     */
    SXEA1(len <= UINT8_MAX, "prefixtree_put: len %d is too large", len);

    while ((tmp = prefixtree_child_get(me, &key[i], len - i)) != NULL) {
        me = tmp;
        i += me->label_len;
    }
    if (i >= len)
        return &me->value;

    /* Do KEY and an existing child share a common prefix? */
    if ((j = prefixtree_find(me, key[i])) < NUMCHILDREN(me) && me->children[j]->label[0] == key[i]) {
        /*-
         * Find the longest common prefix.
         * NOTE, the common prefix doesn't have to lie on any particular
         *       boundary.  Specifically, if our key is a reversed dns_name,
         *       (from dns_name_prefixtreekey), a split
         *       key might be completely unreadable unless concatenated with
         *       all parent keys.
         */
        prefix_len_limit = (len - i < me->children[j]->label_len ? len - i : me->children[j]->label_len);
        for (prefix_len = 1; prefix_len < prefix_len_limit; prefix_len++)
            if (key[i + prefix_len] != me->children[j]->label[prefix_len])
                break;
        /* Create a new node labeled with the prefix. */
        if ((tmp = prefixtree_new_internal(me->children[j]->label, prefix_len)) == NULL)
            return NULL;
        /* Create a second node labeled with the remainder of the existing child's label, and make it a child of the first. */
        if ((tmp2 = prefixtree_new_internal(me->children[j]->label + prefix_len, me->children[j]->label_len - prefix_len)) == NULL) {
            kit_free(tmp);
            return NULL;
        }
        if (!prefixtree_child_put(tmp, tmp2)) {
            kit_free(tmp);
            kit_free(tmp2);
            return NULL;
        }
        /* Substitute the two new nodes for the single existing child. */
        tmp2->children_len = me->children[j]->children_len;
        tmp2->children = me->children[j]->children;
        tmp2->value = me->children[j]->value;
        kit_free(me->children[j]);
        me->children[j] = tmp;
        me = tmp;
        i += prefix_len;
    }

    if (i < len) {
        if ((tmp = prefixtree_new_internal(&key[i], len - i)) == NULL)
            return NULL;
        if (!prefixtree_child_put(me, tmp)) {
            kit_free(tmp);
            return NULL;
        }
    }

    return &tmp->value;
}

void *
prefixtree_prefix_choose(struct prefixtree *me, const uint8_t *key, int *len, void *(*choose)(void *, void *), void *userdata)
{
    void *nvalue, *value;
    int i, nlen;

    nlen = 0;
    if (me) {
        i = 0;
        value = choose && me->value ? choose(me->value, userdata) : me->value;
        while ((me = prefixtree_child_get(me, key + i, *len - i)) != NULL) {
            i += me->label_len;
            nvalue = choose && me->value ? choose(me->value, userdata) : me->value;
            if (nvalue != NULL) {
                value = nvalue;
                nlen = i;
            }
        }
    } else
        value = NULL;

    SXEL6("%s(me=?, key=%.*s, len=?, choose=?, userdata=?) {} // return value=%p, *len=%u", __FUNCTION__, *len, key, value, nlen);
    *len = nlen;

    return value;
}

bool
prefixtree_contains_subtree(struct prefixtree *me, const uint8_t *key, int len)
{
    int i;

    while (me) {
        for (i = 0; i < NUMCHILDREN(me); i++)
            if (me->children[i]->label_len >= len && memcmp(key, me->children[i]->label, len) == 0)
                return true;
        if ((me = prefixtree_child_get(me, key, len)) != NULL) {
            key += me->label_len;
            len -= me->label_len;
        }
    }

    return false;
}
