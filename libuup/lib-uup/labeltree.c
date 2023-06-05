#include <kit-alloc.h>
#include <mockfail.h>

#include "labeltree.h"

#define ISDEFAULTKEY(k) ((k)[0] == 1 && (k)[1] == '*')

struct labeltree {
    struct labeltree **child;
    void              *value;
    struct labeltree  *defchild;    /* duplicate of a child[] value */
    unsigned           nchild;
    uint8_t            label[1];
} __attribute__((__packed__));

/**
 * Get the array of offsets to the labels in a DNS name in reverse order (therefore, always 0 terminated)
 */
static const uint8_t *
gather_offsets(uint8_t offsets[DNS_MAX_LABEL_CNT], const uint8_t *name, uint8_t *depth_out)
{
    unsigned i, d, pos;

    i   = DNS_MAX_LABEL_CNT;
    pos = 0;
    d   = 0;

    while (i) {
        d++;
        offsets[--i] = pos;

        if (!name[pos])
            break;

        pos += name[pos] + 1;
    }

    if (depth_out)
        *depth_out = d;

    return offsets + i;    // First populated offset
}

/**
 * Search for a label (key) in a node, returning the matching child index (slot) or the next child index (possibly nchild)
 *
 * @param cmpp Points to an integer set to 0 on match, non-zero on failure.
 */
static unsigned
labeltree_child_slot(const struct labeltree *me, const uint8_t *key, int *cmpp)
{
    unsigned i, len, lim, pos;
    int cmp;

    /* bsearch */
    for (pos = 0, cmp = 1, lim = me->nchild; lim; lim >>= 1) {
        i = pos + (lim >> 1);

        for (len = 1; len <= *key && len <= *me->child[i]->label; len++)
            if ((cmp = (int)dns_tolower[key[len]] - (int)dns_tolower[me->child[i]->label[len]]) != 0)
                break;

        if (cmp == 0)
            cmp = (int)*key - (int)*me->child[i]->label;

        if (cmp == 0) {
            pos = i;
            break;
        }
        else if (cmp > 0) {
            pos = i + 1;
            lim--;
        }
    }

    SXEL7("%s(me->label='%.*s', key='%.*s', cmpp=?) {} // return %u, val '%.*s', prev '%.*s', next '%.*s', *cmpp %d",
          __FUNCTION__, *me->label, me->label + 1, *key, key + 1, pos,
          pos < me->nchild ? *me->child[pos]->label : 6, pos < me->nchild ? (const char *)me->child[pos]->label + 1 : "<null>",
          pos ? *me->child[pos - 1]->label : 6, pos ? (const char *)me->child[pos - 1]->label + 1 : "<null>",
          pos + 1 < me->nchild ? *me->child[pos + 1]->label : 6,
          pos + 1 < me->nchild ? (const char *)me->child[pos + 1]->label + 1 : "<null>",
          cmp);

    if (cmpp)
        *cmpp = cmp;

    return pos;
}

static struct labeltree *
labeltree_child(struct labeltree *me, const uint8_t *key)
{
    unsigned i;
    int cmp;

    return (i = labeltree_child_slot(me, key, &cmp)) < me->nchild && !cmp ? me->child[i] : NULL;
}

static bool
labeltree_walk_recursive(struct labeltree *me, labeltree_walk_t visit, uint8_t *key, uint8_t *pos, void *userdata)
{
    unsigned i;

    SXEA6(me == NULL || *me->label < *pos, "Cannot walk tree - too deep");

    if (me != NULL && *me->label < *pos) {
        *pos -= *me->label + 1;

        if (key)
            memcpy(key + *pos, me->label, *me->label + 1);

        if (!visit(key ? key + *pos : NULL, me->value, userdata))
            return false;

        for (i = 0; i < me->nchild; i++)
            if (!labeltree_walk_recursive(me->child[i], visit, key, pos, userdata))
                return false;

        *pos += *me->label + 1;
    }

    return true;
}

/**
 * Walk a labeltree, calling the callback on every node.
 *
 * @return true if the entire tree was walked
 */
bool
labeltree_walk(struct labeltree *me, labeltree_walk_t visit, uint8_t *key, void *userdata)
{
    uint8_t pos;

    pos = DNS_MAXLEN_NAME;    // Room for the biggest name

    if (key)
        key[pos - 1] = 0;

    return labeltree_walk_recursive(me, visit, key, &pos, userdata);
}

static struct labeltree *
labeltree_new_internal(const uint8_t *key)
{
    struct labeltree *me;

    if ((me = MOCKFAIL(LABELTREE_NEW_INTERNAL, NULL, kit_malloc(sizeof(*me) + *key))) == NULL)
        SXEL2("Couldn't allocate a new labeltree");
    else {
        me->nchild   = 0;
        me->child    = NULL;
        me->defchild = NULL;
        me->value    = NULL;
        memcpy(me->label, key, *key + 1);
    }

    SXEL7("%s(key='%.*s') {} // return %p", __FUNCTION__, *key, key + 1, me);
    return me;
}

struct labeltree *
labeltree_new(void)
{
    return labeltree_new_internal(DNS_NAME_ROOT);
}

void
labeltree_delete(struct labeltree *me, void (*callback)(void *))
{
    unsigned i;

    if (me) {
        if (callback != NULL)
            callback(me->value);

        for (i = 0; i < me->nchild; i++)
            labeltree_delete(me->child[i], callback);

        kit_free(me->child);
        kit_free(me);
    }
}

void
labeltree_free(struct labeltree *me)
{
    labeltree_delete(me, NULL);
}

/**
 * Insert a name to the label tree if not already present
 *
 * @return Pointer to the value (possibly already set if the name was already present) or NULL on error.
 */
void **
labeltree_insert(struct labeltree *me, const uint8_t *key)
{
    struct labeltree *child, **newborn;
    uint8_t           depth, offsets_max[DNS_MAX_LABEL_CNT];
    const uint8_t    *offsets;
    unsigned          i;
    int               cmp;

    if (me) {
        if (*key) {
            offsets = gather_offsets(offsets_max, key, &depth);    /* For "\001a\002bc\003com", offsets = { 9, 5, 2, 0 } */

            while ((i = labeltree_child_slot(me, key + *++offsets, &cmp)) < me->nchild && !cmp) {
                me = me->child[i];

                if (!*offsets)   // Name is already in the tree
                    return &me->value;
            }

            if ((child = labeltree_new_internal(key + *offsets)) == NULL)
                return NULL;

            /* Update this node */
            if ((newborn = MOCKFAIL(LABELTREE_PUT_REALLOC, NULL, kit_realloc(me->child, (me->nchild + 1) * sizeof(*me->child)))) == NULL) {
                SXEL2("Failed to realloc space for %u child labeltree node%s", me->nchild + 1, me->nchild ? "s" : "");
                kit_free(child);
                return NULL;
            }

            me->child = newborn;

            if (me->nchild > i)
                memmove(me->child + i + 1, me->child + i, (me->nchild - i) * sizeof(*me->child));

            me->child[i] = child;
            me->nchild++;

            if (ISDEFAULTKEY(key + *offsets))
                me->defchild = me->child[i];

            me = me->child[i];

            /* Create additional subnodes for each remaining label */
            while (*offsets++) {
                if ((child = labeltree_new_internal(key + *offsets)) == NULL)
                    return NULL;

                if ((me->child = MOCKFAIL(LABELTREE_PUT_MALLOC, NULL, kit_malloc(sizeof(*me->child)))) == NULL) {
                    SXEL2("Failed to malloc space for a child labeltree node");
                    kit_free(child);
                    return NULL;
                }

                me->child[0] = child;
                me->nchild = 1;

                if (ISDEFAULTKEY(key + *offsets))
                    me->defchild = me->child[0];

                me = me->child[0];
            }
        }
    }

    return me ? &me->value : NULL;
}

/**
 * Put a name in the label tree, overwriting the value if the name already exists
 *
 * @return Added value on new name, previous value if name was already in the tree, or NULL on error.
 */
void *
labeltree_put(struct labeltree *me, const uint8_t *key, void *value)
{
    void **value_ptr;

    SXEA1(value, "Attempt to put a NULL value in labeltree for key %s", dns_name_to_str1(key));

    if ((value_ptr = labeltree_insert(me, key))== NULL)
        return NULL;

    void *previous_value = *value_ptr;
    *value_ptr           = value;
    return previous_value ?: value;
}

/* Find the depth of the deepest match, returning 0 if there are no matching leaf nodes
 */
static uint8_t
labeltree_deepest(struct labeltree *me, const uint8_t *key, const uint8_t *offsets, uint8_t depth, void **value_out)
{
    struct labeltree *child;
    void             *value_wild = NULL;
    uint8_t           newdepth = 0, altdepth;
    unsigned          i;
    int               cmp;

    if (offsets[depth]) {    // Not the trailing 0
        child    = (i = labeltree_child_slot(me, key + offsets[depth + 1], &cmp)) < me->nchild && !cmp ? me->child[i] : NULL;
        altdepth = me->defchild ? labeltree_deepest(me->defchild, key, offsets, depth + 1, &value_wild) : 0;
        newdepth = child ? labeltree_deepest(child, key, offsets, depth + 1, value_out) : 0;

        if (newdepth < altdepth) {
            newdepth   = altdepth;
            *value_out = value_wild;
        }
    }

    if (newdepth == 0 && me->value) {
        newdepth   = depth + 1;
        *value_out = me->value;
    }

    SXEA6(newdepth || me->value == NULL, "Value %zu but not match", (uintptr_t)me->value);
    return newdepth;
}

#define ASTERISK_LABEL ((const uint8_t *)"\1*")    // See RFC 4592 section 2.1.1

const uint8_t *
labeltree_search(struct labeltree *me, const uint8_t *key, unsigned flags, void **value_out, labeltree_walk_t visit, void *userdata)
{
    const uint8_t    *offsets, *suffix = NULL;
    uint8_t           depth, offsets_max[DNS_MAX_LABEL_CNT];
    struct labeltree *child;

    SXEE6("(me=%p, key=%s, flags=0x%02x)", me, key ? dns_name_to_str1(key) : "NULL", flags);

    if (me) {
        offsets = gather_offsets(offsets_max, key, NULL);    /* For "\001a\002bc\003com", offsets = { 9, 5, 2, 0 } */

        if (flags & LABELTREE_FLAG_NO_WILDCARD_WHITEOUT) {
            depth = labeltree_deepest(me, key, offsets, 0, value_out);
            suffix = depth ? key + offsets[depth - 1] : NULL;
        }
        else {    // Ignore wildcards, treating them as plain text labels
            if (me->value) {    // There is a value at the root (.)
                *value_out = me->value;
                suffix = key + offsets[0];
            }

            for (depth = 0; offsets[depth] != 0 && (child = labeltree_child(me, key + offsets[depth + 1])); ) {
                depth++;
                me = child;

                if (me->value) {
                    if (visit && !visit(key + offsets[depth], me->value, userdata)) {
                        *value_out = NULL;
                        suffix = NULL;
                        goto OUT;
                    }
                    *value_out = me->value;
                    suffix = key + offsets[depth];
                }
            }

            /* If the name was not found, check the parent for a matching wildcard domain name
             */
            if (offsets[depth] != 0 && (child = labeltree_child(me, ASTERISK_LABEL)) && child->value) {
                if (visit && !visit(key, child->value, userdata)) {
                    *value_out = NULL;
                    suffix = NULL;
                } else {
                    *value_out = child->value;
                    suffix = key;
                }
            }
        }
    }

OUT:
    SXER6("return suffix=%s; // *value_out=%p", suffix ? dns_name_to_str1(suffix) : "NULL", *value_out);
    return suffix;
}

const uint8_t *
labeltree_suffix_get(struct labeltree *me, const uint8_t *key, unsigned flags)
{
    void *value_dummy;

    return labeltree_search(me, key, flags, &value_dummy, NULL, NULL);
}

void *
labeltree_get_walk(struct labeltree *me, const uint8_t *key, unsigned flags, labeltree_walk_t visit, void *userdata)
{
    void          *value  = NULL;
    const uint8_t *suffix = labeltree_search(me, key, flags, &value, visit, userdata);

    if (suffix == key) {
        SXEA6(value != NULL || key[0] == 0, "NULL value on perfect match!");
        return value;
    }

    return NULL;
}

/**
 * Search for a key in a labeltree, recording the path in a labeltree iterator
 *
 * @return The value if key was found, or NULL if there was no exact match
 */
const void *
labeltree_search_iter(struct labeltree *me,  const uint8_t *key, struct labeltree_iter *iter_out)
{
    struct labeltree *parent = NULL;
    const uint8_t    *offsets;
    unsigned          i;
    uint8_t           offsets_max[DNS_MAX_LABEL_CNT];

    SXEA6(me,  "me must point to the root of a labeltree");
    SXEA6(key, "key must point to the lower case name to search for");
    SXEE6("(me=%p, key=%s, iter_out=?)", me, dns_name_to_str1(key));

    offsets           = gather_offsets(offsets_max, key, NULL);    /* For "\001a\002bc\003com", offsets = { 9, 5, 2, 0 } */
    iter_out->path[0] = me;
    iter_out->parent  = NULL;
    iter_out->cmp     = 0;

    for (iter_out->depth = 0; offsets[iter_out->depth] != 0; ) {
        parent = iter_out->path[(iter_out->depth)++];
        i      = labeltree_child_slot(parent, key + offsets[iter_out->depth], &iter_out->cmp);
        iter_out->i[iter_out->depth] = i;
        SXEA6(iter_out->i[iter_out->depth] <= parent->nchild, "WAT? Child index out of range");

        if (iter_out->cmp)    // key not found
            break;

        SXEA6(i < parent->nchild, "Found an exact match, but index is out of range");
        iter_out->path[iter_out->depth] = parent->child[i];
    }

    if (offsets[iter_out->depth] == 0)
        iter_out->parent = parent;

    SXER6("return value=%p; // iter_out->depth=%u",
          iter_out->cmp ? NULL : iter_out->path[iter_out->depth]->value, iter_out->depth);
    return iter_out->cmp ? NULL : iter_out->path[iter_out->depth]->value;
}

/**
 * @return The value of the parent if found, or NULL if the parent was not matched in the last search
 */
const void *
labeltree_iter_parent(struct labeltree_iter *me)
{
    return me->parent ? me->parent->value : NULL;
}

/**
 * @return The value of the previous non-NULL entry if found, or NULL if there is no previous entry
 */
const void *
labeltree_iter_previous(struct labeltree_iter *me)
{
    while (me->depth > 0) {    // If we're not already at the root

        if (me->i[me->depth] == 0) {               // If already in the first slot
            if (me->path[--me->depth]->value) {    // Parent has a value, so it's the previous node
                me->parent = me->depth ? me->path[me->depth - 1] : NULL;
                return me->path[me->depth]->value;
            }

            continue;
        }

        me->parent          = me->path[me->depth - 1];
        me->path[me->depth] = me->parent->child[--me->i[me->depth]];    // Point to the previous node

        while (me->path[me->depth]->nchild > 0) {   // While it has children, find the greatest of them
            me->parent          = me->path[me->depth++];
            me->i[me->depth]    = me->parent->nchild - 1;
            me->path[me->depth] = me->parent->child[me->parent->nchild - 1];
        }

        return me->path[me->depth]->value;
    }

    me->parent = NULL;
    return NULL;
}

/**
 * Copy the DNS name stored in the iterator's path into *name_out
 */
uint8_t *
labeltree_iter_get_name(struct labeltree_iter *me, uint8_t *name_out)
{
    uint8_t *name = name_out;
    unsigned i;

    for (i = me->depth; i > 0; i--) {    // If we're not already at the root, copy the next label
        *name = me->path[i]->label[0];
        memcpy(name + 1, me->path[i]->label + 1, *name);
        name += 1 + *name;
    }

    *name = 0;
    return name_out;
}
