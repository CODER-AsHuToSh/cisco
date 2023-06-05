#include <kit-alloc.h>
#include <mockfail.h>

#if SXE_DEBUG
#include <kit-bool.h>
#endif

#include "prefbuilder.h"

bool
prefbuilder_allocident(struct prefbuilder *me, unsigned count)
{
    struct prefidentity *nid;

    if (count != me->alloc) {
        SXEA1(count >= me->count, "Attempt to reduce prefbuilder identities to %u elements -- %u of %u already in use", count,
              me->count, me->alloc);

        if ((nid = MOCKFAIL(prefbuilder_allocident, NULL, kit_realloc(me->identity, count * sizeof(*me->identity)))) == NULL) {
            SXEL2("Couldn't %sallocate %zu bytes", me->alloc ? "" : "re", count * sizeof(*me->identity));
            return false;
        }

        me->identity = nid;
        me->alloc    = count;
    }

    return true;
}

void
prefbuilder_init(struct prefbuilder *me, uint32_t flags, struct conf_loader *cl, void *user)
{
    SXEA6(me, "Can't pass a NULL prefbuilder to its constructor");
    memset(me, 0, sizeof(*me));
    me->flags  = flags;
    me->loader = cl;
    me->user   = user;
}

void
prefbuilder_shrink(struct prefbuilder *me)
{
    SXEA1(me->count < me->alloc, "Attempt to shrink a prefbuilder with no free space (%u of %u)", me->count, me->alloc);
    me->identity = kit_realloc(me->identity, --me->alloc * sizeof(*me->identity));
    SXEA1(me->identity || !me->alloc, "Failed to shrink to %u identities", me->alloc);
}

bool
prefbuilder_alloclist(struct prefbuilder *me, unsigned count)
{
    struct preflist *list;

    if (count != me->list.alloc) {
        SXEA1(count >= me->list.count, "Attempt to reduce prefbuilder lists to %u elements -- %u of %u already in use", count,
              me->list.count, me->list.alloc);

        if ((list = MOCKFAIL(prefbuilder_alloclist, NULL, kit_realloc(me->list.block, count * sizeof(*me->list.block)))) == NULL) {
            SXEL2("Failed to realloc prefbuilder list block to %u elements", count);
            return false;
        }

        me->list.block = list;
        me->list.alloc = count;
    }

    return true;
}

/**
 * Add a list to a prefbuilder
 *
 * @param elementtype One of APPLICATION, CIDR, DOMAIN, or URL
 * @param lp          List pointer
 */
bool
prefbuilder_addlist(struct prefbuilder *me, ltype_t ltype, uint32_t listid, elementtype_t elementtype, list_pointer_t lp,
                    uint8_t bit)
{
    if (me->list.count == me->list.alloc) {
        SXEL2("Number of lists exceed count %u in list header", me->list.alloc);
        return false;
    }

    if (!ltype_matches_elementtype(ltype, elementtype)) {
        SXEL2("Cannot add list type %s with ltype %02X", pref_list_elementtype_to_name(elementtype), ltype);
        return false;
    }

    SXEL7("Inserting list %02X:%u:%s at pos %u", ltype, listid, pref_list_elementtype_to_name(elementtype), me->list.count);
    struct preflist list;
    list.ltype       = ltype;
    list.id          = listid;
    list.elementtype = elementtype;
    list.lp          = lp;
    list.bit         = bit;

    return kit_sortedarray_add(&preflist_element, (void **)&me->list.block, &me->list.count, &me->list.alloc, &list,
                               KIT_SORTEDARRAY_DEFAULT);
}

/**
 * Discard a list, recording it so that bundles referring to it can also be discarded.
 *
 * @param me                       Pointer to a prefbuilder
 * @param ltype/listid/elementtype Identify the list to be discarded
 */
bool
prefbuilder_disclist(struct prefbuilder *me, ltype_t ltype, uint32_t listid, elementtype_t elementtype)
{
    // Normally, we don't expect to discard lists. Prepare to allocate the first time we encounter one. Probably vastly
    // overallocate, since we're allocating enough space in case all remaining lists are discarded.
    if (!me->disclists.block)
        me->disclists.alloc = me->list.alloc - me->list.count;

    if (me->disclists.count == me->disclists.alloc) {
        SXEL2("Number of lists exceed count %u in list header", me->list.alloc);    // Yes, this is the implication
        return false;
    }

    SXEL7("Inserting discarded list %02X:%u:%s", ltype, listid, pref_list_elementtype_to_name(elementtype));
    struct preflist key;
    key.ltype       = ltype;
    key.id          = listid;
    key.elementtype = elementtype;

    return kit_sortedarray_add(&preflist_element, (void **)&me->disclists.block, &me->disclists.count, &me->disclists.alloc,
                               &key, KIT_SORTEDARRAY_DEFAULT);
}

bool
prefbuilder_allocsettinggroup(struct prefbuilder *me, unsigned count)
{
    struct prefsettinggroup *psg;

    if (count != me->settinggroup.alloc) {
        SXEA1(count >= me->settinggroup.count,
              "Attempt to reduce prefbuilder settinggroups to %u elements -- %u of %u already in use",
              count, me->settinggroup.count, me->settinggroup.alloc);

        if ((psg = MOCKFAIL(prefbuilder_allocsettinggroup, NULL,
                            kit_realloc(me->settinggroup.block, count * sizeof(*me->settinggroup.block)))) == NULL) {
            SXEL2("Failed to realloc prefbuilder settinggroup block to %u elements", count);
            return false;
        }

        me->settinggroup.block = psg;
        me->settinggroup.alloc = count;
    }

    return true;
}

bool
prefbuilder_addsettinggroup(struct prefbuilder *me, settinggroup_idx_t sgidx, uint32_t sgid, uint32_t flags,
                            const pref_categories_t *blocked_categories, const pref_categories_t *nodecrypt_categories,
                            const pref_categories_t *warn_categories)
{
    struct prefsettinggroup settinggroup;

    SXEL7("Inserting settinggroup %X:%u at pos %u", sgidx, sgid, me->settinggroup.count);

    settinggroup.idx = sgidx;
    settinggroup.id = sgid;
    settinggroup.bundleflags = flags;
    settinggroup.blocked_categories = *blocked_categories;
    settinggroup.nodecrypt_categories = *nodecrypt_categories;
    settinggroup.warn_categories = *warn_categories;

    return kit_sortedarray_add(&prefsettinggroup_element, (void **)&me->settinggroup.block, &me->settinggroup.count,
                               &me->settinggroup.alloc, &settinggroup, KIT_SORTEDARRAY_DEFAULT);
}

bool
prefbuilder_allocorg(struct prefbuilder *me, unsigned count)
{
    struct preforg *org;

    if (count != me->org.alloc) {
        SXEA1(count >= me->org.count, "Attempt to reduce prefbuilder orgs to %u elements -- %u of %u already in use", count,
              me->org.count, me->org.alloc);

        if ((org = MOCKFAIL(prefbuilder_allocorg, NULL, kit_realloc(me->org.block, count * sizeof(*me->org.block)))) == NULL) {
            SXEL2("Failed to realloc prefbuilder org block to %u elements", count);
            return false;
        }

        me->org.block = org;
        me->org.alloc = count;
    }

    return true;
}

bool
prefbuilder_addorg(struct prefbuilder *me, uint32_t id, pref_orgflags_t flags, const pref_categories_t *unmasked,
                   uint32_t retention, uint32_t warnperiod, uint32_t originid, uint32_t parentid)
{
    struct preforg org;

    SXEL7("Inserting org %" PRIu32 " at pos %u", id, me->org.count);
    org.id       = id;
    org.orgflags = flags;
    org.unmasked = *unmasked;
    org.retention= retention;
    org.warnperiod = warnperiod;
    org.originid = originid;
    org.parentid = parentid;

    return kit_sortedarray_add(&preforg_element, (void **)&me->org.block, &me->org.count, &me->org.alloc, &org,
                               KIT_SORTEDARRAY_DEFAULT);
}

bool
prefbuilder_allocbundle(struct prefbuilder *me, unsigned count)
{
    struct prefbundle *b;

    if (count != me->bundle.alloc) {
        SXEA1(count >= me->bundle.count, "Attempt to reduce prefbuilder bundles to %u elements -- %u of %u already in use",
              count, me->bundle.count, me->bundle.alloc);

        if ((b = MOCKFAIL(prefbuilder_allocbundle, NULL, kit_realloc(me->bundle.block, count * sizeof(*me->bundle.block)))) == NULL) {
            SXEL2("Failed to realloc prefbuilder bundle block to %u elements", count);
            return false;
        }

        me->bundle.block = b;
        me->bundle.alloc = count;
    }

    return true;
}

bool
prefbuilder_addbundle(struct prefbuilder *me, actype_t actype, uint32_t bundleid, uint32_t priority, pref_bundleflags_t flags,
                      const pref_categories_t *cat, uint32_t settinggroup_ids[SETTINGGROUP_IDX_COUNT])
{
    const struct prefsettinggroup *sg;
    struct prefbundle bundle, *b;
    unsigned i;

    SXEL7("Inserting bundle %X:%" PRIu32 " at pos %u", actype, bundleid, me->bundle.count);

    bundle.actype = actype;
    bundle.id     = bundleid;

    // Insert now with zero copy to avoid having to copy the whole bundle, which is > 128 bytes
    if (!(b = kit_sortedarray_add(&prefbundle_element, (void **)&me->bundle.block, &me->bundle.count, &me->bundle.alloc,
                                  &bundle, KIT_SORTEDARRAY_ZERO_COPY)))
        return false;

    b->actype = actype;
    b->id = bundleid;
    b->priority = priority;
    b->bundleflags = flags;
    b->base_blocked_categories = *cat;
    pref_categories_setnone(&b->base_nodecrypt_categories);
    pref_categories_setnone(&b->base_warn_categories);
    b->dest_block = b->exceptions = b->dest_allow = b->url_proxy_https = b->dest_nodecrypt = b->dest_warn = PREF_NOLIST;
    b->app_block = b->app_allow = b->app_nodecrypt = b->app_warn = PREF_NOLIST;
    b->ext_dest_block = b->ext_dest_allow = b->ext_url_proxy_https = b->ext_dest_nodecrypt = b->ext_dest_warn = PREF_NOLIST;
    b->ext_app_block = b->ext_app_allow = b->ext_app_nodecrypt = b->ext_app_warn = PREF_NOLIST;

    for (i = 0; i < SETTINGGROUP_IDX_COUNT; i++) {
        b->sgids[i] = 0;

        if (settinggroup_ids[i] == 0)
            continue;

        /*
         * Attempt to resolve external references immediately.  This will optimize the runtime settinggroups lookup for the
         * normal case, only leaving MSP client orgs with external dirprefs references back to the MSP (parentid).
         */
        if ((sg = prefsettinggroup_get(me->settinggroup.block, me->settinggroup.count, i, settinggroup_ids[i])) != NULL) {
            SXEL7("Resolved settinggroup idx:id %u:%" PRIu32 " to settinggroup item %zu", i, settinggroup_ids[i],
                    sg - me->settinggroup.block);
            b->bundleflags |= sg->bundleflags;
            pref_categories_union(&b->base_blocked_categories, &b->base_blocked_categories, &sg->blocked_categories);
            pref_categories_union(&b->base_nodecrypt_categories, &b->base_nodecrypt_categories, &sg->nodecrypt_categories);
            pref_categories_union(&b->base_warn_categories, &b->base_warn_categories, &sg->warn_categories);
        } else {
            b->sgids[i] = settinggroup_ids[i];    /* May be an external reference, so save it */

            if (me->flags & PREFBUILDER_FLAG_NO_EXTERNAL_REFS)
                SXEL4("Cannot resolve settinggroups (settinggroup idx:id=%u:%" PRIu32 ") and external references aren't allowed",
                      i, b->sgids[i]);
        }
    }

    return true;
}

/**
 * Attach a list to a bundle
 *
 * @param elementtypes A bit mask of the elementtypes allowed for this pref type
 */
bool
prefbuilder_attach(struct prefbuilder *me, unsigned bitem, ltype_t ltype, uint32_t listid, unsigned elementtypes)
{
    unsigned *headlistref, *blocklistref, litem, *nblock, ncount;
    struct preflistrefblock *listref;
    const struct preflist *list;
    struct prefbundle *bundle;
    elementtype_t elementtype;
    bool attached, ext;
    int newlistref;

    SXEA6(bitem < me->bundle.count, "prefbuilder_attach() called with bitem %u, but max is %u", bitem, me->bundle.count - 1);

    bundle = me->bundle.block + bitem;
    headlistref = &bundle->dest_block + LTYPE2NUM(ltype);
    listref = &me->listref;
    attached = false;

    /* Find the list we want to reference */
    litem = me->list.count - 1;

    // Repeat for each elementtype that is valid for the pref type
    for (elementtype = 0; elementtype < PREF_LIST_ELEMENTTYPE_COUNT; elementtype++) {
        // If lists have been discarded, even if the elementype isn't supported, it can still validate the bundle reference
        if (!(elementtypes & PREF_LIST_ELEMENTTYPE_BIT(elementtype))) {
            if (preflist_get(me->disclists.block, me->disclists.count, ltype, listid, elementtype)) {
                SXEL7("%s(): Found discarded list %02X:%" PRIu32 ":%s in %u discarded lists", __FUNCTION__, ltype, listid,
                        pref_list_elementtype_to_name(elementtype), me->disclists.count);
                attached = true;
            }

            // If this isn't the last element type, try the next one.
            if (elementtype + 1 < PREF_LIST_ELEMENTTYPE_COUNT)
                continue;
        }

        list = preflist_get(me->list.block, me->list.count, ltype, listid, elementtype);
        ext = !list;
        if (ext) {
            /* An exact match wasn't found */
            if (ltype == AT_LIST_EXCEPT)
                continue;

            // Skip if a list was already found or external references aren't allowed or this is not the last element type
            if (attached || me->flags & PREFBUILDER_FLAG_NO_EXTERNAL_REFS || elementtype + 1 < PREF_LIST_ELEMENTTYPE_COUNT)
                continue;

            litem = listid;
            SXEA6(listid == (uint32_t)litem, "prefbuilder_attach(): External listid (%02X:%" PRIu32 ":%s) overflow", ltype,
                                             listid, pref_list_elementtype_to_name(elementtype));
            headlistref = &bundle->ext_dest_block + LTYPE2NUM(ltype) - (ltype > AT_LIST_EXCEPT ? 1 : 0);
            listref = &me->extlistref;
        } else
            litem = list - me->list.block;

        /*-
         * This is tricky...
         *
         * listref->block is a series of number lists, for example
         *     | 100 | 12 | 13 | PREF_NOLIST | 12 | PREF_NOLIST | 100 | 101 | 105 | PREF_NOLIST |
         * When (ext), each number is a listid.  When (!ext), each number is an offset into me->list.block[]
         *
         * *headlistref is the offset into listref->block where our list-of-lists starts.  It finishes at the next PREF_NOLIST
         * If *headlistref is PREF_NOLIST, then there's no listref (yet!).
         *
         * We use blocklistref as an iterator through the above (listref->block) numbers.
         */

        if (*headlistref == PREF_NOLIST) {
            *headlistref = listref->count;    /* A brand new list-of-lists starting at offset 'me->{ext,}listref.count' */
            newlistref = 1;
        } else {
            /* Find the end of listref->block, dropping out if the list is already present */
            for (blocklistref = listref->block + *headlistref; *blocklistref != PREF_NOLIST; blocklistref++)
                if (ext) {
                    if (*blocklistref == (unsigned)listid) {
                        SXEL2("prefbuilder_attach(): Bundle %u external listid %X:%" PRIu32 ":%s shows up twice", bitem,
                              ltype, listid, pref_list_elementtype_to_name(elementtype));
                        return false;
                    }
                } else if (me->list.block[*blocklistref].ltype == (ltype | AT_LIST_USED)
                        && me->list.block[*blocklistref].id == listid
                        && me->list.block[*blocklistref].elementtype == elementtype) {
                    SXEL2("prefbuilder_attach(): Bundle %u internal listid %02X:%" PRIu32 ":%s shows up twice", bitem,
                          ltype, listid, pref_list_elementtype_to_name(elementtype));
                    return false;
                }

            /* If we're not at the end of listref->block, fail (we can't extend the list-of-lists) - the caller isn't doing it right! */
            if ((unsigned)(blocklistref - listref->block) != listref->count - 1) {
                SXEL2("prefbuilder_attach(): Bundle %u list %u reference ends at %zd, not %u", bitem, litem, blocklistref - listref->block, listref->count - 1);
                return false;
            }

            listref->count--;    /* We'll overwrite the terminating element */
            newlistref = 0;
        }

        if (listref->alloc < listref->count + 2) {
            /* Need space for this entry plus a PREF_NOLIST terminator */
            ncount = listref->alloc + (listref->alloc > 200 ? listref->alloc / 2 : 20);

            if ((nblock = MOCKFAIL(prefbuilder_attach, NULL, kit_realloc(listref->block, ncount * sizeof(*listref->block)))) == NULL) {
                SXEL2("Failed to realloc prefbuilder %spreflist block to %u elements", ext ? "ext" : "", ncount);

                if (newlistref)
                    *headlistref = PREF_NOLIST;    /* Back to having no lists of this type! */
                else
                    listref->count++;              /* Back to including the final PREF_NOLIST element */

                return false;
            }

            listref->block = nblock;
            listref->alloc = ncount;
        }

        SXEL7("Attaching bundle %u to list %02X:%u:%s via %slistref %u (length is now %u)",
            bitem, ltype, litem, pref_list_elementtype_to_name(elementtype), ext ? "ext " : "", *headlistref, listref->count - *headlistref + 1);
        listref->block[listref->count++] = litem;
        listref->block[listref->count++] = PREF_NOLIST;

        if (!ext)
            me->list.block[litem].ltype |= AT_LIST_USED;    /* So that we can mask out unused lists when generating data for dash1 */

        attached = true;
    }

    if (!attached) {
        if (ltype == AT_LIST_EXCEPT) {
            SXEL2("prefbuilder_attach: Except list %02X:%" PRIu32 ":* doesn't exist", ltype, listid);
            return false;
        }

        if (me->flags & PREFBUILDER_FLAG_NO_EXTERNAL_REFS) {
            SXEL4("Cannot resolve list %02X:%" PRIu32 ":* and external references aren't allowed", ltype, listid);
            return true;    /* but that's ok - the next config update will fix this... hopefully */
        }
    }

    return attached;
}

/*-
 * @param elementttypes A bit mask of the elementtypes allowed for this pref type
 */
bool
prefbuilder_attachlist(struct prefbuilder *me, uint32_t bundleid, ltype_t ltype, uint32_t listid, unsigned elementtypes)
{
    const struct prefbundle *bundle;
    bool ret = false;

    SXEE6("(me=%p,bundleid=%u,ltype=%02X,listid=%u,elementtypes=%X)", me, bundleid, ltype, listid, elementtypes);

    if (!(bundle = prefbundle_get(me->bundle.block, me->bundle.count, LTYPE2ACTYPE(ltype), bundleid)))
        SXEL7("prefbuilder_attachlist: Bundle %X:%u doesn't exist", LTYPE2ACTYPE(ltype), bundleid);
    else
        ret = prefbuilder_attach(me, bundle - me->bundle.block, ltype, listid, elementtypes);

    SXER6("return %s", kit_bool_to_str(ret));
    return ret;
}

bool
prefbuilder_addidentityforbundle(struct prefbuilder *me, uint32_t originid, uint32_t origintypeid, uint32_t orgid,
                                 actype_t actype, unsigned bitem)
{
    struct prefidentity *identity;
    pref_categories_t nounmask;
    unsigned ipos, oitem;
    const struct preforg *org;

    if (me->count == me->alloc)
        return false;    /* Not enough added in prefbuilder_allocident() */

    pref_categories_setnone(&nounmask);

    if (!orgid)
        oitem = NO_ORG_ITEM;
    else if ((ipos = me->org.count) > 0) {
        SXEA6(me->org.block, "The org array has elements, but hasn't been allocated");

        if (!(org = preforg_get(me->org.block, me->org.count, orgid)))
            return false;

        oitem = org - me->org.block;
    }
    else
        return false;

    SXEL7("Inserting identity at pos %u referring to bundle at pos %u", me->count, bitem);
    identity               = me->identity + me->count++;
    identity->originid     = originid;
    identity->origintypeid = origintypeid;
    identity->org          = oitem;
    identity->actype       = actype;
    identity->bundle       = bitem;

    return true;
}

bool
prefbuilder_addidentity(struct prefbuilder *me, uint32_t originid, uint32_t origintypeid, uint32_t orgid, actype_t actype,
                        uint32_t bundleid)
{
    const struct prefbundle *bundle = prefbundle_get(me->bundle.block, me->bundle.count, actype, bundleid);

    if (!bundle)
        return false;    /* Doesn't exist */

    return prefbuilder_addidentityforbundle(me, originid, origintypeid, orgid, actype, bundle - me->bundle.block);
}

/**
 * Consume only the lists from a built prefbuilder.
 *
 * @note This is used by the lists-org object.
 */
void
prefbuilder_consumelists(struct prefbuilder *me, struct preflist **lists_out, unsigned *count_out)
{
    unsigned i;

    *lists_out     = kit_reduce(me->list.block, me->list.count * sizeof(*me->list.block));
    *count_out     = me->list.count;
    me->list.block = NULL;
    me->list.count = 0;

    for (i = 0; i < *count_out; i++)
        (*lists_out)[i].ltype = PREFLIST_LTYPE(&(*lists_out)[i]);    // Strip AT_LIST_USED flag
}

/**
 * Consume a prefblock from a prefbuilder
 *
 * @note This function destroys the prefbuilder as a side effect, but it's safe to call prefbuilder_fini after if you want to
 */
struct prefblock *
prefbuilder_consume(struct prefbuilder *me)
{
    struct prefblock *pb;

    if (me->count != me->alloc) {
        SXEL2("%s(): Too early to consume - at count %u of %u", __FUNCTION__, me->count, me->alloc);
        return NULL;    /* You must add all the planned identities */
    }

    if ((pb = MOCKFAIL(prefbuilder_consume, NULL, kit_malloc(sizeof(*pb)))) == NULL) {
        SXEL2("Couldn't allocate a prefblock (%zu bytes)", sizeof(*pb));
        return NULL;
    }

    prefbuilder_consumelists(me, &pb->resource.list, &pb->count.lists);
    pb->resource.listref    = kit_reduce(me->listref.block, me->listref.count * sizeof(*me->listref.block));
    me->listref.block       = NULL;
    pb->resource.extlistref = kit_reduce(me->extlistref.block, me->extlistref.count * sizeof(*me->extlistref.block));
    me->extlistref.block    = NULL;

    kit_free(me->disclists.block);
    me->disclists.block = NULL;

    pb->resource.settinggroup = kit_reduce(me->settinggroup.block, me->settinggroup.count * sizeof(*me->settinggroup.block));
    pb->count.settinggroups   = me->settinggroup.count;
    me->settinggroup.block    = NULL;

    pb->resource.bundle = kit_reduce(me->bundle.block, me->bundle.count * sizeof(*me->bundle.block));
    pb->count.bundles   = me->bundle.count;
    me->bundle.block    = NULL;

    pb->resource.org = kit_reduce(me->org.block, me->org.count * sizeof(*me->org.block));
    pb->count.orgs   = me->org.count;
    me->org.block    = NULL;

    pb->identity         = me->identity;
    pb->count.identities = me->count;
    me->identity         = NULL;

    return pb;
}

void
prefbuilder_fini(struct prefbuilder *me)
{
    unsigned i;

    SXEA6(me, "Can't pass a NULL prefbuilder to its destructor");

    for (i = 0; i < me->list.count; i++)
        preflist_refcount_dec(&me->list.block[i]);

    kit_free(me->list.block);
    kit_free(me->listref.block);
    kit_free(me->extlistref.block);
    kit_free(me->disclists.block);       // Should have been freed in reduce, unless there was an error
    kit_free(me->settinggroup.block);
    kit_free(me->bundle.block);
    kit_free(me->org.block);
    kit_free(me->identity);
}
