#include <kit-alloc.h>
#include <mockfail.h>
#include <sxe-util.h>

#include "oolist.h"

#define CHUNK 10
#define NO_ORG 0

struct oolist {
    size_t used, max;
    uint8_t flags;
    struct oolist_entry item[1];
};

static inline bool
global_parent(uint32_t org)
{
    return org == pref_get_globalorg();

}

static inline bool
no_org(uint32_t org)
{
   return org == NO_ORG;
}

/* A global parent org or no org (i.e., org 0) is considered as not related to any other org. */
static bool
related(uint32_t org1, uint32_t org2)
{
    return (org1 == org2 && !no_org(org1) && !global_parent(org1));
}

/* Multiple orgs scenario is detected when:
 *  - The two orgs are not the same
 *  - Their parents are NOT same
 *  - Either of the two orgs are equal to the global parent org or no org (i.e., org 0)
 *  - Either of the two parent orgs are equal to the global parent org.
 *  - Eihter of the two orgs are orphan orgs i.e., their parent org is 0
 */
static bool
multiple_orgs(uint32_t org1, uint32_t parent_org1, uint32_t org2, uint32_t parent_org2)
{
    return !(related(org1, org2) || related(parent_org1, parent_org2));
}

/*
 * Create an oolist entry from a pref structure
 */
bool
oolist_add(struct oolist **list, pref_t *pref, enum origin_src src)
{
    uint32_t org, origin, origintype, parentorg, retention;
    struct oolist *o, *n;
    size_t max;
    unsigned i;

    origin = PREF_IDENT(pref)->originid;

    if (origin == 0)
        return false;

    if (PREF_ORG(pref) != NULL) {
        org       = PREF_ORG(pref)->id;
        parentorg = PREF_ORG(pref)->parentid;
        retention = PREF_ORG(pref)->retention;
    } else {
        org       = NO_ORG;
        parentorg = NO_ORG;
        retention = 0;
    }
    origintype = PREF_IDENT(pref)->origintypeid;

    o = *list;
    if (o != NULL) {
        for (i = 0; i < o->used; i++)
            if (origin == o->item[i].origin) {
                SXEL7("%s: org %u is replaced by org %u because of same origin %u",
                      __FUNCTION__, o->item[i].org, org, origin);
                o->item[i].org        = org;
                o->item[i].parent     = parentorg;
                o->item[i].src        = src;
                o->item[i].origintype = origintype;
                o->item[i].retention  = retention;
                return true;
            } else if (multiple_orgs(o->item[i].org, o->item[i].parent, org, parentorg)) {
                SXEL7("%s: Multiple orgs (%u & %u) present in oolist", __FUNCTION__, o->item[i].org, org);
                o->flags |= OOLIST_FLAGS_MULTIPLE_ORGS;
            }
        SXEL7("%s: oolist has %zu entr%s in the list. Adding another entry for origin %u",
              __FUNCTION__, o->used, o->used == 1 ? "y" : "ies", origin);
    }

    if (o == NULL || o->used == o->max) {
        max = o ? o->max + CHUNK : CHUNK;
        if ((n = MOCKFAIL(oolist_add, NULL, kit_realloc(o, sizeof(*o) + (max - 1) * sizeof(*o->item)))) == NULL) {
            SXEL2("Couldn't realloc %zu bytes", sizeof(*o) + (max - 1) * sizeof(*o->item));
            return false;
        }
        o = n;
        o->max = max;
        if (!*list) {
            o->used = 0;
            o->flags = OOLIST_FLAGS_NONE;
        }
        *list = o;
    }

    o->item[o->used].origin     = origin;
    o->item[o->used].org        = org;
    o->item[o->used].origintype = origintype;
    o->item[o->used].retention  = retention;
    o->item[o->used].parent     = parentorg;
    o->item[o->used++].src      = src;

    return true;
}

void
oolist_clear(struct oolist **list)
{
    kit_free(*list);
    *list = NULL;
}

void
oolist_rm(struct oolist **list, uint32_t origin)
{
    struct oolist *o;
    unsigned i;

    if (origin == 0)
        return;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    o = *list;
    if (o != NULL)
        for (i = 0; i < o->used; i++)
            if (origin == o->item[i].origin) {
                if (o->used == 1)
                    oolist_clear(list);
                else {
                    for (i++; i < o->used; i++)
                        o->item[i - 1] = o->item[i];
                    o->used--;
                }
                return;
            }
}

enum origin_src
oolist_origin2src(struct oolist **list, uint32_t origin)
{
    struct oolist *o;
    unsigned i;

    if (origin == 0)
        return ORIGIN_SRC_NO_MATCH;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    o = *list;
    if (o != NULL)
        for (i = 0; i < o->used; i++)
            if (origin == o->item[i].origin)
                return o->item[i].src;

    return ORIGIN_SRC_NO_MATCH;
}

const char *
oolist_to_buf(const struct oolist *list, char *buf, size_t bufsz, size_t *len_out, unsigned flags)
{
    size_t      len;
    unsigned    i;
    char       *p;

    SXEA6(bufsz > 1, "Buffer must be big enough for an empty list");

    p = buf;

    if (list)
        for (i = 0; i < list->used; i++) {
            if (flags & OOLIST_COMPLETE) {
                len = snprintf(p, bufsz, flags & OOLIST_IN_HEX ? "%s%08X:%08X:%08X:%08X:%08X" : "%s%u:%u:%u:%u:%u", i ? "," : "",
                               list->item[i].origin, list->item[i].origintype, list->item[i].org, list->item[i].retention, list->item[i].parent);
            } else if (flags & OOLIST_NO_ORGS)
                len = snprintf(p, bufsz, flags & OOLIST_IN_HEX ? "%s%08X" : "%s%u", i ? "," : "", list->item[i].origin);
            else
                len = snprintf(p, bufsz, flags & OOLIST_IN_HEX ? "%s%08X:%08X" : "%s%u:%u", i ? "," : "",
                               list->item[i].org, list->item[i].origin);

            if (len > bufsz - 1) {    // If a partial value was printed, discard it
                *p = '\0';
                break;
            }

            bufsz -= len;
            p     += len;
        }

    if (p == buf)
        snprintf(p++, bufsz, "-");

    if (len_out)
        *len_out = p - buf;

    return buf;
}

const struct oolist_entry *
oolist_entry(const struct oolist *list, size_t n)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    return list && list->used > n ? list->item + n : NULL;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

bool
oolist_check_flags(struct oolist **list, uint8_t flags)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    return *list ? (*list)->flags & flags : false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}
