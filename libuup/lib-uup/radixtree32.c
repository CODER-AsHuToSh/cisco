#include <kit-alloc.h>
#include <mockfail.h>

#include "cidr-ipv4.h"
#include "radixtree32.h"

#define CHILD_INDEX(addr, mask) ((addr & (~mask ^ (~mask >> 1))) != 0)

struct radixtree32 {
    struct cidr_ipv4 cidr;
    struct cidr_ipv4 *value;
    union {
        struct cidr_ipv4 *child_as_leaf[2];
        struct radixtree32 *child[2];
    } c;
    uint8_t child_is_leaf[2];
};

void
radixtree32_delete(struct radixtree32 *me)
{
    struct radixtree32 *child;

    if (me != NULL) {
        if (!me->child_is_leaf[0]) {
            if (!me->child_is_leaf[1])
                radixtree32_delete(me->c.child[1]);
            child = me->c.child[0];
        } else
            child = me->child_is_leaf[1] ? NULL : me->c.child[1];
        kit_free(me);
        radixtree32_delete(child);    /* tail call: should be kept at the end of the function in order to avoid recursion */
    }
}

struct radixtree32 *
radixtree32_new(void)
{
    struct radixtree32 *me;

    if ((me = MOCKFAIL(radixtree32_new, NULL, kit_calloc(1, sizeof(*me)))) == NULL)
        SXEL2("Couldn't allocate %zu bytes", sizeof(*me));
    return me;
}

static uint32_t
longest_common_mask(const struct cidr_ipv4 *cb1, const struct cidr_ipv4 *cb2)
{
    uint32_t mask = cb1->mask & cb2->mask;
    uint32_t xor = cb1->addr ^ cb2->addr;

    while (xor & mask)
        mask <<= 1;

    return mask;
}

/*-
 * Inserting a struct cidr_ipv4 B into a tree rooted at a node N:
 *   While a non-leaf child of N contains B, set N to that child.
 *   (Now we're at a node N that contains B,
 *     and B won't be inserted into a subtree of N,
 *     because no non-leaf child of N contains B.)
 *   If B matches N,
 *     install B as N's value and return.
 *   If N's child field for B is empty,
 *     install B in it and return.
 *   If N's leaf field for B is not empty,
 *     create a new node N' whose struct cidr_ipv4 is the longest one containing
 *     both B and the leaf.  Insert B and the leaf into the
 *     appropriate fields, set N's child field for B to N', and clear
 *     N's leaf field.
 *   If N's child field for B is not empty,
 *     create a new node N' whose struct cidr_ipv4 is the longest one containing
 *     both B and the child.  Insert B and the child into the
 *     appropriate fields, and set N's child field for B to N'.
 */
bool
radixtree32_put(struct radixtree32 *me, struct cidr_ipv4 *cidr)
{
    struct radixtree32 *new_node;
    int i, new_i;
    uint32_t mask;

    for (;;) {
        i = CHILD_INDEX(cidr->addr, me->cidr.mask);
        if (me->child_is_leaf[i] || me->c.child[i] == NULL || !CIDR_IPV4_CONTAINS_NET(&me->c.child[i]->cidr, cidr))
            break;
        me = me->c.child[i];
    }

    if (me->cidr.mask == cidr->mask)
        me->value = cidr;
    else if (me->c.child[i] == NULL) {
        me->c.child_as_leaf[i] = cidr;
        me->child_is_leaf[i] = 1;
    } else {
        if ((new_node = radixtree32_new()) == NULL)
            return false;
        mask = longest_common_mask(cidr, &me->c.child[i]->cidr);
        new_node->cidr.addr = cidr->addr & mask;
        new_node->cidr.mask = mask;

        if (mask == cidr->mask)
            new_node->value = cidr;
        else {
            new_i = CHILD_INDEX(cidr->addr, mask);
            new_node->c.child_as_leaf[new_i] = cidr;
            new_node->child_is_leaf[new_i] = 1;
        }

        if (me->child_is_leaf[i] && mask == me->c.child[i]->cidr.mask)
            new_node->value = me->c.child_as_leaf[i];
        else {
            new_i = CHILD_INDEX(me->c.child[i]->cidr.addr, mask);
            new_node->c.child[new_i] = me->c.child[i];
            new_node->child_is_leaf[new_i] = me->child_is_leaf[i];
        }

        me->c.child[i] = new_node;
        me->child_is_leaf[i] = 0;
    }

    return true;
}

struct cidr_ipv4 *
radixtree32_get(struct radixtree32 *me, struct in_addr addr)
{
    struct cidr_ipv4 *value = NULL;
    int i;

    while (me != NULL && CIDR_IPV4_CONTAINS_ADDR(&me->cidr, addr)) {
        if (me->value != NULL)
            value = me->value;
        i = CHILD_INDEX(ntohl(addr.s_addr), me->cidr.mask);
        if (me->child_is_leaf[i]) {
            if (CIDR_IPV4_CONTAINS_ADDR(me->c.child_as_leaf[i], addr))
                return me->c.child_as_leaf[i];
            else
                return value;
        }
        me = me->c.child[i];
    }
    return value;
}

void
radixtree32_walk(struct radixtree32 *me, void (*callback)(struct cidr_ipv4 *cidr))
{
    if (me) {
        if (me->value != NULL)
            callback(me->value);

        if (me->c.child[0] != NULL) {
            if (me->child_is_leaf[0])
                callback(me->c.child_as_leaf[0]);
            else
                radixtree32_walk(me->c.child[0], callback);
        }

        if (me->c.child[1] != NULL) {
            if (me->child_is_leaf[1])
                callback(me->c.child_as_leaf[1]);
            else
                radixtree32_walk(me->c.child[1], callback); /* tail call: should be kept at the end of the function in order to avoid recursion */
        }
    }
}
