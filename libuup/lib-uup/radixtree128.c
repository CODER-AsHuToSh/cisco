#include <kit-alloc.h>
#include <mockfail.h>

#include "cidr-ipv6.h"
#include "radixtree128.h"

#define CHILD_INDEX(cidr, maskbits) (!!(CIDRV6_DWORD(cidr, (maskbits) / 32) & htonl(1 << (31 - ((maskbits) % 32)))))

struct radixtree128 {
    struct cidr_ipv6 cidr;
    struct cidr_ipv6 *value;
    union {
        /*
         * Note, &me->c.child[i]->cidr and me->c.child_as_leaf[i] are synonomous!!
         * It's not obvious, but the code depends on this!!
         */
        struct cidr_ipv6 *child_as_leaf[2];
        struct radixtree128 *child[2];
    } c;
    uint8_t child_is_leaf[2];
};

void
radixtree128_delete(struct radixtree128 *me)
{
    struct radixtree128 *child;

    if (me != NULL) {
        if (!me->child_is_leaf[0]) {
            if (!me->child_is_leaf[1])
                radixtree128_delete(me->c.child[1]);
            child = me->c.child[0];
        } else
            child = me->child_is_leaf[1] ? NULL : me->c.child[1];

        kit_free(me);
        radixtree128_delete(child);    /* tail call: should be kept at the end of the function in order to avoid recursion */
    }
}

struct radixtree128 *
radixtree128_new(void)
{
    struct radixtree128 *me;

    if ((me = MOCKFAIL(radixtree128_new, NULL, kit_calloc(1, sizeof(*me)))) == NULL)
        SXEL2("Couldn't allocate %zu bytes", sizeof(*me));
    return me;
}

static uint8_t
longest_common_maskbits(const struct cidr_ipv6 *a, const struct cidr_ipv6 *b)
{
    in_addr_t mask;
    uint32_t hmask, xor;
    int bits, q;

    bits = a->maskbits < b->maskbits ? a->maskbits : b->maskbits;
    for (q = 3; q >= 0; q--) {
        mask = bits2mask(bits - q * 32);
        xor = CIDRV6_DWORD(*a, q) ^ CIDRV6_DWORD(*b, q);
        while (xor & mask) {
            hmask = ntohl(mask) << 1;
            mask = htonl(hmask);
            if (bits > (q + 1) * 32)
                bits = (q + 1) * 32;
            bits--;
        }
    }

    return bits;
}

/*-
 * Inserting a struct cidr_ipv6 B into a tree rooted at a node N:
 *   While a non-leaf child of N contains B, set N to that child.
 *   (Now we're at a node N that contains B,
 *     and B won't be inserted into a subtree of N,
 *     because no non-leaf child of N contains B.)
 *   If B matches N,
 *     install B as N's value and return.
 *   If N's child field for B is empty,
 *     install B in it and return.
 *   If N's leaf field for B is not empty,
 *     create a new node N' whose struct cidr_ipv6 is the longest one containing
 *     both B and the leaf.  Insert B and the leaf into the
 *     appropriate fields, set N's child field for B to N', and clear
 *     N's leaf field.
 *   If N's child field for B is not empty,
 *     create a new node N' whose struct cidr_ipv6 is the longest one containing
 *     both B and the child.  Insert B and the child into the
 *     appropriate fields, and set N's child field for B to N'.
 */
bool
radixtree128_put(struct radixtree128 *me, struct cidr_ipv6 *cidr)
{
    struct radixtree128 *new_node;
    int i, new_i;
    int maskbits;

    for (;;) {
        i = CHILD_INDEX(*cidr, me->cidr.maskbits);
        if (me->child_is_leaf[i] || me->c.child[i] == NULL || !cidr_ipv6_contains_net(&me->c.child[i]->cidr, cidr))
            break;
        me = me->c.child[i];
    }

    if (me->cidr.maskbits == cidr->maskbits)
        me->value = cidr;
    else if (me->c.child[i] == NULL) {
        me->c.child_as_leaf[i] = cidr;
        me->child_is_leaf[i] = 1;
    } else {
        if ((new_node = radixtree128_new()) == NULL)
            return false;
        maskbits = longest_common_maskbits(cidr, &me->c.child[i]->cidr);
        new_node->cidr.addr = cidr->addr;
        new_node->cidr.maskbits = maskbits;
        cidr_ipv6_apply_mask(&new_node->cidr);

        if (maskbits == cidr->maskbits)
            new_node->value = cidr;
        else {
            new_i = CHILD_INDEX(*cidr, maskbits);
            new_node->c.child_as_leaf[new_i] = cidr;
            new_node->child_is_leaf[new_i] = 1;
        }

        if (me->child_is_leaf[i] && maskbits == me->c.child[i]->cidr.maskbits)
            new_node->value = me->c.child_as_leaf[i];
        else {
            new_i = CHILD_INDEX(me->c.child[i]->cidr, maskbits);
            new_node->c.child[new_i] = me->c.child[i];
            new_node->child_is_leaf[new_i] = me->child_is_leaf[i];
        }

        me->c.child[i] = new_node;
        me->child_is_leaf[i] = 0;
    }

    return true;
}

struct cidr_ipv6 *
radixtree128_get(struct radixtree128 *me, const struct in6_addr *ip6addr)
{
    struct cidr_ipv6 addr = { *ip6addr, 128 };
    struct cidr_ipv6 *value = NULL;
    int i;

    while (me != NULL && cidr_ipv6_contains_net(&me->cidr, &addr)) {
        if (me->value != NULL)
            value = me->value;
        i = CHILD_INDEX(addr, me->cidr.maskbits);
        if (me->child_is_leaf[i]) {
            if (cidr_ipv6_contains_net(me->c.child_as_leaf[i], &addr))
                return me->c.child_as_leaf[i];
            else
                return value;
        }
        me = me->c.child[i];
    }
    return value;
}

void
radixtree128_walk(struct radixtree128 *me, void (*callback)(struct cidr_ipv6 *cidr))
{
    if (me) {
        if (me->value != NULL)
            callback(me->value);

        if (me->c.child[0] != NULL) {
            if (me->child_is_leaf[0])
                callback(me->c.child_as_leaf[0]);
            else
                radixtree128_walk(me->c.child[0], callback);
        }

        if (me->c.child[1] != NULL) {
            if (me->child_is_leaf[1])
                callback(me->c.child_as_leaf[1]);
            else
                radixtree128_walk(me->c.child[1], callback); /* tail call: should be kept at the end of the function in order to avoid recursion */
        }
    }
}
