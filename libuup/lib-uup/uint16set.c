#include <ctype.h>
#include <kit-alloc.h>
#include <kit.h>
#include <mockfail.h>
#include <string.h>
#include <sxe-util.h>

#include "uint16set.h"

#define MAXVAL 65535

static int
uint16set_compare(const void *a, const void *b)
{
    /* Depends on the first item[] element being 'uint16_t start' */
    return *(const uint16_t *)a - *(const uint16_t *)b;
}

struct uint16set *
uint16set_new(const char *txt, unsigned *consumed)
{
    const char *p, *start;
    struct uint16set *me;
    unsigned commas, i;
    unsigned long val;
    char *end;

    for (commas = 0, p = txt; isdigit(*p) || *p == '-' || *p == ','; p++)
        if (*p == ',')
            commas++;

    if ((me = MOCKFAIL(uint16set_new, NULL, kit_malloc(sizeof *me + commas * sizeof(*me->item)))) == NULL) {
        if (consumed)
            *consumed = 0;

        SXEL2("Couldn't allocate a uint16set with %u blocks", commas + 1);
        return NULL;
    }

    me->count = 0;
    start = txt;
    while (isdigit(*start) || *start == '-') {
        end = strchr(p = start, *start);    /* strchr() to de-const */
        val = *p == '-' ? 0 : kit_strtoul(p, &end, 10);
        if (val > MAXVAL)
            break;
        me->item[me->count].start = val;
        p = end;
        if (*p == '-') {
            p++;
            end = strchr(p, *p);    /* strchr() to de-const */
            val = isdigit(*p) ? kit_strtoul(p, &end, 10) : MAXVAL;
            if (val > MAXVAL || val < me->item[me->count].start)
                break;
            me->item[me->count].end = val;
            p = end;
        } else
            me->item[me->count].end = me->item[me->count].start;
        me->count++;
        start = p;
        if (*start != ',')
            break;
        start++;
    }

    if (consumed)
        *consumed = start - txt;

    qsort(me->item, me->count, sizeof(*me->item), uint16set_compare);

    /* reduce/combine */
    for (i = 1; i < me->count; i++)
        if (me->item[i - 1].end >= me->item[i].start - 1U || !me->item[i].start) {
            if (me->item[i - 1].end < me->item[i].end)
                me->item[i - 1].end = me->item[i].end;
            memmove(me->item + i, me->item + i + 1, (--me->count - i) * sizeof(*me->item));
            i--;
        }

    return me;
}

bool
uint16set_match(const struct uint16set *me, uint16_t val)
{
    unsigned i;

    if (me)
        for (i = 0; i < me->count; i++) {
            if (val < me->item[i].start)
                break;
            else if (val <= me->item[i].end)
                return true;
        }

    return false;
}

const char *
uint16set_to_str(const struct uint16set *me)
{
    static __thread size_t sz;
    static __thread char *buf;
    size_t pos, space;
    char *nbuf;
    unsigned i;

    if (me == NULL) {
        kit_free(buf);
        buf = NULL;
        sz = 0;
    } else if (!me->count)
        return "";
    else
        for (i = 0, pos = 0; i < me->count; i++) {
            space = me->item[i].end == me->item[i].start ? 12 : 24;
            if (pos + space >= sz) {
                if ((nbuf = MOCKFAIL(uint16set_to_str, NULL, kit_realloc(buf, sz + 100))) == NULL) {
                    SXEL2("Couldn't allocate %zu uint16set-str bytes", sz + 100);
                    return "<uint16set-allocation-failure>";
                }
                buf = nbuf;
                sz += 100;
            }
            if (pos)
                buf[pos++] = ',';
            pos += snprintf(buf + pos, sz - pos, "%u", me->item[i].start);
            if (me->item[i].end != me->item[i].start) {
                buf[pos++] = '-';
                pos += snprintf(buf + pos, sz - pos, "%u", me->item[i].end);
            }
        }

    return buf;
}

unsigned
uint16set_count(const struct uint16set *me)
{
    unsigned i, items;

    for (i = items = 0; i < me->count; i++)
        items += me->item[i].end - me->item[i].start + 1;

    return items;
}

void
uint16set_free(struct uint16set *me)
{
    if (me)
        kit_free(me);
}
