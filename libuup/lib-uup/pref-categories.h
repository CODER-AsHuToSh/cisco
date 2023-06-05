#ifndef PREF_CATEGORIES_H
#define PREF_CATEGORIES_H

#include <stdbool.h>

#define PREF_CATEGORIES_MAX_BITS        256
#define PREF_CATEGORIES_BITS_PER_BITVAL 8    /* bits required to store bit value (1 - PREF_CATEGORIES_MAX_BITS inclusive) */
#define PREF_CATEGORIES_WORD_BITS       (8 * sizeof(uint64_t))
#define PREF_CATEGORIES_WORDS           ((PREF_CATEGORIES_MAX_BITS + PREF_CATEGORIES_WORD_BITS - 1) / PREF_CATEGORIES_WORD_BITS)
#define PREF_CATEGORIES_IDSTR_MAX_LEN   ((PREF_CATEGORIES_MAX_BITS + 3) / 4)

typedef struct {
    uint64_t words[PREF_CATEGORIES_WORDS];
} pref_categories_t;

#include "pref-categories-proto.h"

#endif
