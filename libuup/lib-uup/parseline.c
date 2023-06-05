#include <ctype.h>
#include <kit-alloc.h>
#include <mockfail.h>
#include <string.h>

#include "parseline.h"

bool
word_match(const char *string, const char *word, size_t word_len)
{
    return strncasecmp(string, word, word_len) == 0 && string[word_len] == '\0';
}

__attribute__((malloc)) char *
word_dup(const char *word, size_t word_len)
{
    char *txt;

    if ((txt = MOCKFAIL(word_dup, NULL, kit_malloc(word_len + 1))) == NULL)
        SXEL2("Failed to allocate space to duplicate '%.*s'", (int)word_len, word);
    else {
        memcpy(txt, word, word_len);
        txt[word_len] = '\0';
    }

    return txt;
}

/*
 * Looks at 'line'.
 * - Positions *key at the first non-separator & sets *key_len to its length
 * - Positions *value at the second word in the line & sets *value_len to its length
 * - Returns 0, 1 or 2 to indicate the number of words
 *   0: The line is empty or contains just separators when 'multi' is true.
 *   1: There is only one 'word' on the line, possibly surrounded with separators if 'multi' is true.
 *   2: There are two or more 'words'.  The first is referenced from *key and *key_len.  All
 *      subsequent words are referenced as a block by *value and *value_len.  Note, *value
 *      can be passed as 'line' into another parseline() call to split further.
 *
 * 'sep' is the list of separator characters to use
 * If 'multi' is true, multiple separator characters are considered as one separator.
 * - for non-zero returns, *key_len will be non-zero
 * If 'multi' is false, every separator is a split point and *key_len may be set to zero.
 */
int
parseline(const char *line, const char **key, size_t *key_len, const char **value, size_t *value_len, const char *sep, bool multi)
{
    const char *end;

    *key = *value = NULL;
    *key_len = *value_len = 0;

    /* Find the start */
    if (multi)
        while (*line && strchr(sep, *line))
            line++;

    /* Find the end */
    if ((end = strchr(line, '#')) == NULL)
        end = line + strlen(line);
    if (multi)
        while (end > line && strchr(sep, end[-1]))
            end--;

    if (line == end)
        return 0;
    *key = line;

    /* Advance to key's end */
    while (line < end && !strchr(sep, *line))
        line++;
    *key_len = line - *key;
    if (line == end)
        return 1;

    /* Advance to value's beginning */
    if (multi)
        while (*line && strchr(sep, *line))
            line++;
    else
        line++;
    *value = line;
    *value_len = end - *value;

    return 2;
}
