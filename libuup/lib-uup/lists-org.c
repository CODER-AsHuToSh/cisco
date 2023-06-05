#include <kit-alloc.h>
#include <mockfail.h>

#if SXE_DEBUG
#include "dns-name.h"
#endif

#include "atomic.h"
#include "cidrlist.h"
#include "conf-meta.h"
#include "fileprefs.h"
#include "lists.h"
#include "urllist.h"

void
lists_org_refcount_dec(void *obj)
{
    struct lists_org *me = obj;
    unsigned          i;

    if (me) {
        SXEA1(me->cs.refcount, "Attempt to remove a reference from a list_org that has none");

        if (ATOMIC_DEC_INT_NV(&me->cs.refcount) == 0) {
            for (i = 0; i < me->count; i++)
                preflist_refcount_dec(&me->lists[i]);

            conf_meta_free(me->cm);
            kit_free(me->lists);
            kit_free(me);
        }
    }
}

void
lists_org_refcount_inc(void *obj)
{
    struct lists_org *me = obj;

    if (me)
        ATOMIC_INC_INT(&me->cs.refcount);
}

void *
lists_org_new(uint32_t orgid, struct conf_loader *cl, const struct conf_info *info)
{
    struct fileprefs                file_prefs;
    struct lists_org               *me, *retme;
    struct prefbuilder              pref_builder;
    unsigned                       *ok_vers = NULL;
    const struct fileprefs_section *section = NULL;
    unsigned                        total_count, section_count, i;
    enum fileprefs_section_status   status;

    static struct fileprefs_section lists_section = {
        .name    = "lists",
        .namelen = sizeof("lists") - 1,
        .alloc   = prefbuilder_alloclist,
        .read    = fileprefs_readlist
    };

    static struct fileprefops lists_ops = {
        .type               = "lists",
        .sections           = &lists_section,
        .num_sections       = 1,
        .supported_versions = { LISTS_VERSION, 0 }
    };

    SXEE6("(orgid=%u,cl=?,info=?) // conf_loader_path(cl)=%s, info->loadflags=0x%x", (unsigned)orgid, conf_loader_path(cl),
          (unsigned)info->loadflags);
    retme = NULL;
    prefbuilder_init(&pref_builder, PREFBUILDER_FLAG_NO_EXTERNAL_REFS, cl, NULL);

    if ((me = MOCKFAIL(lists_org_new, NULL, kit_calloc(1, sizeof(*me)))) == NULL) {
        SXEL2("%s: Cannot allocate %zu bytes for a lists_org object", conf_loader_path(cl), sizeof(*me));
        goto SXE_EARLY_OUT;
    }

    me->cs.refcount = 1;
    fileprefs_init(&file_prefs, &lists_ops, info->loadflags);

    if (!fileprefs_load_fileheader(&file_prefs, cl, &total_count, &ok_vers))
        goto SXE_EARLY_OUT;


    for (i = total_count;
         (status = fileprefs_load_section(&file_prefs, cl, &pref_builder, ok_vers, &section, &section_count)) != FILEPREFS_SECTION_NOT_FOUND
         || !conf_loader_eof(cl);
         i -= section_count)

        switch (status) {
        case FILEPREFS_SECTION_NOT_FOUND:
            SXEL2("%s: %u: Unrecognized line, expected section header", conf_loader_path(cl), conf_loader_line(cl));
            goto SXE_EARLY_OUT;

        case FILEPREFS_SECTION_ERROR:
            goto SXE_EARLY_OUT;

        case FILEPREFS_SECTION_LOADED:
            continue;
        }

    if (i) {
        SXEL2("%s: %u: EOF with %u of %u lists remaining", conf_loader_path(cl), conf_loader_line(cl), i, total_count);
        goto SXE_EARLY_OUT;
    }

    if (total_count)
        prefbuilder_consumelists(&pref_builder, &me->lists, &me->count);

    conf_segment_init(&me->cs, orgid, cl, false);
    retme = me;

SXE_EARLY_OUT:
    if (ok_vers)
        kit_free(ok_vers);

    if (retme == NULL)
        lists_org_refcount_dec(me);

    prefbuilder_fini(&pref_builder);
    SXER6("return %s", retme ? "!NULL" : "NULL");
    return retme;
}

/*-
 * Given the subset and the next value, determine the current member index if any and return the current slot.
 *
 * @param subset Sorted array of listids in the subset or NULL to look in all lists
 * @param count  Number of listids in the subset
 * @param next   If subset, a (slot, member) pair, otherwise, just a slot number.
 * @param i_out  Pointer to a subset member index that's populated if subset.
 */
static unsigned
subset_get_member(uint32_t *subset, unsigned count, unsigned next, unsigned *i_out)
{
    if (subset) {
        *i_out = next % count;    // Starting element in the subset
        next  /= count;           // Starting list slot
    }

    return next;
}

/*-
 * Given the lists_org, elementtype, subset, member index, and current list slot, find the next member in the lists.
 *
 * @return List if an element in the subset of listids was found, and if so, next (slot) and i (index) are updated, else NULL.
 */
static struct preflist *
lists_org_find_subset_member(const struct lists_org *me, elementtype_t elementtype, uint32_t *subset, unsigned count,
                             unsigned *next, unsigned *i)
{
    struct preflist *list;

    // If no subset, find the next list with the desired elementtype
    if (!subset) {
        for (; *next < me->count; (*next)++)
            if (me->lists[*next].elementtype == elementtype)
                return &me->lists[*next];

        return NULL;
    }

    // Search the remaining lists for the first of the remaining listids in the subset with the desired elementtype
    for (list = &me->lists[*next]; *i < count; (*i)++) {
        *next += preflist_find(list, me->count - *next, AT_LIST_NONE, subset[*i], elementtype);

        if (*next >= me->count)    // The subset listid is > last lists_org listid
            return NULL;

        list = &me->lists[*next];

        if (preflist_cmp_key(list, AT_LIST_NONE, subset[*i], elementtype) == 0)    // Found a listid
            return list;
    }

    return NULL;
}

/*
 * Determine the next slot (if no subset) or slot/member combination (if subset).
 */
static unsigned
subset_get_next(uint32_t *subset, unsigned count, unsigned next, unsigned i)
{
    return !subset ? next + 1 : (next + 1) * count + i + 1;
}

/**
 * Lookup a DNS name in all the domainlists of a list_org. Partial matches are returned.
 *
 * @param me             Pointer to the list_org to look in
 * @param subset         NULL to look in all lists, or a sorted array of listids
 * @param count          Number of listids in the subset
 * @param next           0 on the first call, or the number returned from the previous call
 * @param name           The DNS name to look for
 * @param listid_matched Pointer to a variable populated with the listid of the list containing name
 * @param name_matched   Pointer to a variable populated with a pointer to the part of name that matched
 * @param bit_out        Pointer to a variable that will be set to the list bit (0 if none), or NULL
 *
 * @return 0 if not found or a positive integer that should be passed as 'next' to continue the lookup
 */
unsigned
lists_org_lookup_domainlist(const struct lists_org *me, uint32_t *subset, unsigned count, unsigned next, const uint8_t *name,
                            uint32_t *listid_matched, const uint8_t **name_matched, uint8_t *bit_out)
{
    struct preflist *list;
    const uint8_t   *match;
    unsigned         i;
    char             listname[32];

    SXEA1(!subset || count, "A subset can't be specified with a 0 count");
    SXEL7("%s(orgid=%u,subset=%s,next=%u,name=%s,...) {}", __func__, me->cs.id, subset ? "yes" : "no", next,
          dns_name_to_str1(name));

    if (me) {
        next = subset_get_member(subset, count, next, &i);

        for (; next < me->count; next++) {
            if (!(list = lists_org_find_subset_member(me, PREF_LIST_ELEMENTTYPE_DOMAIN, subset, count, &next, &i)))
                return 0;

            // The listname is only used in debug (and xray messages, but currently, xray is always NULL)
#if SXE_DEBUG
            snprintf(listname, sizeof(listname), "lists %u:domain", list->id);
#endif

            if ((match = domainlist_match(list->lp.domainlist, name, DOMAINLIST_MATCH_SUBDOMAIN, NULL, listname))) {
                if (bit_out)
                    *bit_out = list->bit;

                *listid_matched = list->id;
                *name_matched   = match;
                return subset_get_next(subset, count, next, i);
            }
        }
    }

    return 0;
}

/**
 * Lookup a URL in all or a subset of the urllists of a list_org. Partial matches are returned.
 *
 * @param me             Pointer to the list_org to look in
 * @param subset         NULL to look in all lists, or a sorted array of listids
 * @param count          Number of listids in the subset
 * @param next           0 on the first call, or the number returned from the previous call
 * @param url            URL to look for
 * @param length         Length of the URL
 * @param listid_matched Pointer to a variable populated with the listid of the list containing name
 * @param length_matched Pointer to a variable populated with the length of the partial URL that matched
 * @param bit_out        Pointer to a variable that will be set to the list bit (0 if none), or NULL
 *
 * @return 0 if not found or a positive integer that should be passed as 'next' to continue the lookup
 */
unsigned
lists_org_lookup_urllist(const struct lists_org *me, uint32_t *subset, unsigned count, unsigned next, const char *url,
                         unsigned length, uint32_t *listid_matched, unsigned *length_matched, uint8_t *bit_out)
{
    struct preflist *list;
    unsigned         i, match;

    SXEA1(!subset || count, "A subset can't be specified with a 0 count");
    SXEL7("%s(orgid=%u,subset=%s,next=%u,name=%.*s,...) {}", __FUNCTION__, me->cs.id, subset ? "yes" : "no", next, length, url);

    if (me) {
        next = subset_get_member(subset, count, next, &i);

        for (; next < me->count; next++) {
            if (!(list = lists_org_find_subset_member(me, PREF_LIST_ELEMENTTYPE_URL, subset, count, &next, &i)))
                return 0;

            if ((match = urllist_match(list->lp.urllist, url, length))) {
                if (bit_out)
                    *bit_out = list->bit;

                *listid_matched = list->id;
                *length_matched = match;
                return subset_get_next(subset, count, next, i);
            }
        }
    }

    return 0;
}

/**
 * Lookup a CIDR in all or a subset of the cidrlists of a list_org. Partial matches are returned.
 *
 * @param me             Pointer to the list_org to look in
 * @param subset         NULL to look in all lists, or a sorted array of listids
 * @param count          Number of listids in the subset
 * @param next           0 on the first call, or the number returned from the previous call
 * @param url            URL to look for
 * @param length         Length of the URL
 * @param listid_matched Pointer to a variable set to the listid of the list containing name
 * @param bits_matched   Pointer to a variable set to the number of bits in the matched CIDR (CIDR_MATCH_ALL for 0.0.0.0/0)
 * @param bit_out        Pointer to a variable that will be set to the list bit (0 if none), or NULL
 *
 * @return 0 if not found or a positive integer that should be passed as 'next' to continue the lookup
 */
unsigned
lists_org_lookup_cidrlist(const struct lists_org *me, uint32_t *subset, unsigned count, unsigned next, struct netaddr *ipaddr,
                          uint32_t *listid_matched, unsigned *bits_matched, uint8_t *bit_out)
{
    struct preflist *list;
    unsigned         i, match;
    char             listname[32];

    SXEA1(!subset || count, "A subset can't be specified with a 0 count");
    SXEL7("%s(orgid=%u,subset=%s,next=%u,ipaddr=%s,...) {}", __FUNCTION__, me->cs.id, subset ? "yes" : "no", next,
          netaddr_to_str(ipaddr));

    if (me) {
        next = subset_get_member(subset, count, next, &i);

        for (; next < me->count; next++) {
            if (!(list = lists_org_find_subset_member(me, PREF_LIST_ELEMENTTYPE_CIDR, subset, count, &next, &i)))
                return 0;

            // The listname is only used in debug (and xray messages, but currently, xray is always NULL)
#if SXE_DEBUG
            snprintf(listname, sizeof(listname), "lists %u:cidr", list->id);
#endif

            if ((match = cidrlist_search(list->lp.cidrlist, ipaddr, NULL, listname))) {
                if (bit_out)
                    *bit_out = list->bit;

                *listid_matched = list->id;
                *bits_matched   = match;
                return subset_get_next(subset, count, next, i);
            }
        }
    }

    return 0;
}
