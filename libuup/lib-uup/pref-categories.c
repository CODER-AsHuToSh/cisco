#include <inttypes.h>
#include <kit.h>
#include <stdio.h>
#include <string.h>
#include <sxe-log.h>

#include "pref-categories.h"

#define NIBBLES_PER_WORD (PREF_CATEGORIES_WORD_BITS / 4)

const char *
pref_categories_to_buf(const pref_categories_t *cat, unsigned size, char *buf)
{
    char *p;

    SXEA1(size >= PREF_CATEGORIES_IDSTR_MAX_LEN + 1,
          "%s: Size of buffer %u is less than minimum %u", __func__, size, PREF_CATEGORIES_IDSTR_MAX_LEN + 1);

    for (unsigned i = 0; i < PREF_CATEGORIES_WORDS; i++)
        snprintf(&buf[i * NIBBLES_PER_WORD], NIBBLES_PER_WORD + 1, "%016" PRIX64, cat->words[PREF_CATEGORIES_WORDS - i - 1]);

    p = &buf[strspn(buf, "0")];
    return *p != '\0' ? p : p - 1;
}

const char *
pref_categories_idstr(const pref_categories_t *cat)
{
    static __thread char buf[PREF_CATEGORIES_IDSTR_MAX_LEN + 1];

    return pref_categories_to_buf(cat, sizeof(buf), buf);
}

size_t
pref_categories_sscan(pref_categories_t *cat, const char *str)
{
    char   buf[PREF_CATEGORIES_IDSTR_MAX_LEN];
    char   word_hex[2 * sizeof(uint64_t) + 1];
    size_t len;

    if ((len = strspn(str, "0123456789abcdefABCDEF")) >= sizeof(buf))
        len = sizeof(buf);
    else
        memset(buf, '0', sizeof(buf) - len);

    memcpy(&buf[sizeof(buf) - len], str, len);
    word_hex[2 * sizeof(uint64_t)] = '\0';

    for (unsigned i = 0; i < PREF_CATEGORIES_WORDS; i++) {
        memcpy(word_hex, &buf[i * NIBBLES_PER_WORD], NIBBLES_PER_WORD);
        cat->words[PREF_CATEGORIES_WORDS - i - 1] = kit_strtoull(word_hex, NULL, 16);
    }

    SXEL7("%s(cat=?, str=\"%.*s\") {} // return %zu", __FUNCTION__, (int)len, str, len);
    return len;
}

void
pref_categories_setall(pref_categories_t *cat)
{
    memset(cat, 0xFF, sizeof(*cat));
}

void
pref_categories_setbit(pref_categories_t *cat, unsigned bit)
{
    if (bit < PREF_CATEGORIES_MAX_BITS)
        cat->words[bit / PREF_CATEGORIES_WORD_BITS] |= 1ULL << (bit % PREF_CATEGORIES_WORD_BITS);
}

void
pref_categories_unsetbit(pref_categories_t *cat, unsigned bit)
{
    if (bit < PREF_CATEGORIES_MAX_BITS)
        cat->words[bit / PREF_CATEGORIES_WORD_BITS] &= ~(1ULL << (bit % PREF_CATEGORIES_WORD_BITS));
}

bool
pref_categories_getbit(const pref_categories_t *cat, unsigned bit)
{
    if (bit < PREF_CATEGORIES_MAX_BITS)
        return cat->words[bit / PREF_CATEGORIES_WORD_BITS] & (1ULL << (bit % PREF_CATEGORIES_WORD_BITS)) ? true : false;

    return false;
}

void
pref_categories_setnone(pref_categories_t *cat)
{
    memset(cat, '\0', sizeof(*cat));
}

bool
pref_categories_equal(const pref_categories_t *left, const pref_categories_t *right)
{
    for (unsigned i = 0; i < PREF_CATEGORIES_WORDS; i++)
        if (left->words[i] != right->words[i])
            return false;

    return true;
}

bool
pref_categories_isnone(const pref_categories_t *cat)
{
    for (unsigned i = 0; i < PREF_CATEGORIES_WORDS; i++)
        if (cat->words[i])
            return false;

    return true;
}

bool
pref_categories_isnone_ignorebit(const pref_categories_t *cat, unsigned bit)
{
    pref_categories_t temp;

    pref_categories_setall(&temp);
    pref_categories_unsetbit(&temp, bit);
    pref_categories_intersect(&temp, &temp, cat);
    return pref_categories_isnone(&temp);
}

bool
pref_categories_intersect(pref_categories_t *cat, const pref_categories_t *cat1, const pref_categories_t *cat2)
{
    bool              clear = true;
    pref_categories_t temp;

    cat = cat != NULL ? cat : &temp;

    for (unsigned i = 0; i < PREF_CATEGORIES_WORDS; i++) {
        cat->words[i] = cat1->words[i] & cat2->words[i];
        clear = cat->words[i] ? false : clear;
    }

    return !clear;
}

bool
pref_categories_union(pref_categories_t *cat, const pref_categories_t *cat1, const pref_categories_t *cat2)
{
    bool              clear = true;
    pref_categories_t temp;

    cat = cat != NULL ? cat : &temp;

    for (unsigned i = 0; i < PREF_CATEGORIES_WORDS; i++) {
        cat->words[i] = cat1->words[i] | cat2->words[i];
        clear = cat->words[i] ? false : clear;
    }

    return !clear;
}

void
pref_categories_clear(pref_categories_t *cat, const pref_categories_t *clear)
{
    for (unsigned i = 0; i < PREF_CATEGORIES_WORDS; i++)
        cat->words[i] &= ~clear->words[i];
}

const pref_categories_t *
pref_categories_usable(pref_categories_t *cat,
                       const pref_categories_t *base_blocked_categories,
                       const pref_categories_t *policy_categories,
                       const pref_categories_t *overridable)
{
    /*
     * XORing 'base_blocked_categories' and 'policy_categories' pulls out what we want to change.
     * ANDing with 'overridable' limits those changes.
     * XORing back into 'base_blocked_categories' applies those sanctioned changes.
     */
    for (unsigned i = 0; i < PREF_CATEGORIES_WORDS; i++)
        cat->words[i] = ((base_blocked_categories->words[i] ^ policy_categories->words[i]) & overridable->words[i])
                      ^ base_blocked_categories->words[i];

    return cat;
}

void *
pref_categories_pack(const pref_categories_t *cat)
{
    uint64_t wbit, word;
    uintptr_t cbit, val;
    unsigned vbits, w;

    for (w = 0, vbits = 1, val = 1; w < PREF_CATEGORIES_WORDS; w++)
        for (cbit = w * PREF_CATEGORIES_WORD_BITS, word = cat->words[w], wbit = 1; word; wbit <<= 1, cbit++)
            if (word & wbit) {
                if (vbits + PREF_CATEGORIES_BITS_PER_BITVAL > 8 * sizeof(void *))
                    return NULL;    /* Doesn't fit in a void * - can't be packed :( */
                val |= (cbit + 1) << vbits;
                vbits += PREF_CATEGORIES_BITS_PER_BITVAL;
                word &= ~wbit;
            }

    return (void *)val;
}

bool
pref_categories_unpack(pref_categories_t *cat, const void *v)
{
    uint64_t val;
    unsigned bit;

    /*
     * Packed values have bit 0 set.
     * NOTE: The domaintagging code "knows" this and uses it to store offsets as the prefixtree value
     */
    if (!((val = (uintptr_t)v) & 1))
        return false;

    memset(cat, '\0', sizeof(*cat));
    for (val >>= 1; val; val >>= PREF_CATEGORIES_BITS_PER_BITVAL)
        if ((bit = (val & ((1 << PREF_CATEGORIES_BITS_PER_BITVAL) - 1)) - 1) < PREF_CATEGORIES_MAX_BITS)
            cat->words[bit / PREF_CATEGORIES_WORD_BITS] |= 1ULL << (bit % PREF_CATEGORIES_WORD_BITS);
    return true;
}
