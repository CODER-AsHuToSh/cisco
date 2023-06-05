/*
 * A categorization file is a list of other registered files that
 * define the categorization of domains and ips.
 */
#include <errno.h>
#include <kit-alloc.h>
#include <mockfail.h>

#include "application.h"
#include "categorization-private.h"
#include "cidrlist.h"
#include "conf-loader.h"
#include "dns-name.h"
#include "domaintagging.h"

#define CONSTCONF2CAT(confp) (const struct categorization *)((confp) ? (const char *)(confp) - offsetof(struct categorization, conf) : NULL)
#define CONF2CAT(confp)      (struct categorization *)((confp) ? (char *)(confp) - offsetof(struct categorization, conf) : NULL)

static __thread pref_categories_t option_half_domaintagging;    // Categories masked when HALF_DOMAINTAGGING orgflag is set

static const struct typemap {
    enum categorizationtype type;
    const char *name;
    void (*confregister)(module_conf_t *, const char *, const char *, bool);
} typemap[] = {
    { CATTYPE_DOMAINTAGGING, "domaintagging", domaintagging_register },
    { CATTYPE_DOMAINLIST, "domainlist", domainlist_register },
    { CATTYPE_EXACT_DOMAINLIST, "exact-domainlist", domainlist_register_exact },
    { CATTYPE_IPLIST, "iplist", iplist_register },
    { CATTYPE_CIDRLIST, "cidrlist", cidrlist_register },
    { CATTYPE_APPLICATION, "application", application_register_resolver },
};

static struct conf *categorization_allocate(const struct conf_info *info, struct conf_loader *cl);
static void categorization_free(struct conf *base);

static const struct conf_type catct = {
    "categorization",
    categorization_allocate,
    categorization_free,
};

/**
 * Set per thread options.
 *
 * @param half_domaintagging Pointer to categories to be masked when HALF_DOMAINTAGGING orgflag is set
 */
void
categorization_set_thread_options(const pref_categories_t *half_domaintagging)
{
    memcpy(&option_half_domaintagging, half_domaintagging, sizeof(option_half_domaintagging));
}

void
categorization_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(&catct, NULL, name, fn, loadable, LOADFLAGS_NONE, NULL, 0);
}

const struct categorization *
categorization_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &catct, "categorization_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2CAT(base);
}

void
categorization_refcount_inc(struct categorization *me)
{
    CONF_REFCOUNT_INC(me);
}

void
categorization_refcount_dec(struct categorization *me)
{
    CONF_REFCOUNT_DEC(me);
}

static struct conf *
categorization_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct categorization *me;

    SXEA6(info->type == &catct, "%s() with unexpected conf_type %s", __FUNCTION__, info->type->name);
    if ((me = categorization_new(cl)) != NULL)
        conf_report_load(info->type->name, me->version);

    return me ? &me->conf : NULL;
}

static const struct typemap *
categorization_txt2typemap(const char *line, unsigned *consumed)
{
    unsigned i, len;

    for (i = 0; i < sizeof(typemap) / sizeof(*typemap); i++)
        if (strncmp(line, typemap[i].name, len = strlen(typemap[i].name)) == 0) {
            *consumed = len;
            return typemap + i;
        }

    *consumed = 0;
    return NULL;
}

struct categorization *
categorization_new(struct conf_loader *cl)
{
    const char **allnames, *colon, *line, **nnames;
    unsigned bit, consumed, nalloc, namei, version;
    char *end, name[100], path[PATH_MAX];
    struct categorization *me, *retme;
    const struct typemap *tm;
    bool more_bits;
    module_conf_t *nmodule;
    struct catdata *nitem;
    int cmp;

    me = retme = NULL;
    allnames = NULL;

    if ((line = conf_loader_readline(cl)) == NULL || sscanf(line, "categorization %u\n", &version) != 1 || version != CATEGORIZATION_VERSION) {
        SXEL2("%s: Unrecognized header line, expected 'categorization %u'", conf_loader_path(cl), CATEGORIZATION_VERSION);
        goto OUT;
    }

    if ((me = MOCKFAIL(CATEGORIZATION_NEW, NULL, kit_calloc(1, sizeof(*me)))) == NULL) {
        SXEL2("%s: Couldn't allocate %zu bytes", conf_loader_path(cl), sizeof(*me));
        goto OUT;
    }
    conf_registrar_init(&me->registrar);
    conf_setup(&me->conf, &catct);
    me->version = version;

    while ((line = conf_loader_readline(cl)) != NULL) {
        more_bits = false;
        if (me->count == me->alloc) {
            nalloc = me->alloc + 10;
            nitem = NULL;
            nmodule = NULL;
            if ((nitem = MOCKFAIL(CATEGORIZATION_ALLOC_ITEM, NULL, kit_realloc(me->item, nalloc * sizeof(*me->item)))) == NULL
             || (nmodule = MOCKFAIL(CATEGORIZATION_ALLOC_MOD, NULL, kit_realloc(me->module, nalloc * sizeof(*me->module)))) == NULL
             || (nnames = MOCKFAIL(CATEGORIZATION_ALLOC_NAMES, NULL, kit_realloc(allnames, nalloc * sizeof(*allnames)))) == NULL) {
                SXEL2("%s: Couldn't allocate %u categorization items", conf_loader_path(cl), nalloc);
                kit_free(nitem);
                kit_free(nmodule);
                goto OUT;
            }
            me->item = nitem;
            me->module = nmodule;
            allnames = nnames;
            me->alloc = nalloc;
        }
        if ((tm = categorization_txt2typemap(line, &consumed)) == NULL || line[consumed] != ':') {
            SXEL2("%s: %u: Invalid categorization type (field 1)", conf_loader_path(cl), conf_loader_line(cl));
            goto OUT;
        }

        me->item[me->count].type = tm->type;
        line += consumed + 1;

        if ((colon = strchr(line, ':')) == NULL || colon == line || colon - line > (int)sizeof(name) - 1) {
            SXEL2("%s: %u: Invalid categorization name (field 2)", conf_loader_path(cl), conf_loader_line(cl));
            goto OUT;
        }
        memcpy(name, line, colon - line);
        name[colon - line] = '\0';
        line += colon - line + 1;

        if ((colon = strchr(line, ':')) == NULL || colon == line || colon - line > (int)sizeof(path) - 1) {
            SXEL2("%s: %u: Invalid categorization path (field 3)", conf_loader_path(cl), conf_loader_line(cl));
            goto OUT;
        }
        memcpy(path, line, colon - line);
        path[colon - line] = '\0';
        line += colon - line + 1;

        if (me->item[me->count].type == CATTYPE_DOMAINTAGGING) {
            if (*line != ':') {
                SXEL2("%s: %u: Invalid category bit (field 4) - should be empty", conf_loader_path(cl), conf_loader_line(cl));
                goto OUT;
            }
            line++;
        } else {
            me->item[me->count].catbit = kit_strtoul(line, &end, 10);
            if (me->item[me->count].catbit >= PREF_CATEGORIES_MAX_BITS || *end != ':') {
                SXEL2("%s: %u: Invalid category bit (field 4) - must be less than %u", conf_loader_path(cl), conf_loader_line(cl), PREF_CATEGORIES_MAX_BITS);
                goto OUT;
            }
            line = end + 1;
        }

        bit = kit_strtoul(line, &end, 10);
        if (bit > 31 || *end != ':') {
            SXEL2("%s: %u: Invalid policy bit (field 5) - must be less than 32", conf_loader_path(cl), conf_loader_line(cl));
            goto OUT;
        }
        me->item[me->count].polmask = end == line ? 0 : (1 << bit);
        line = end + 1;

        do {
            bit = kit_strtoul(line, &end, 10);
            if (bit >= PREF_ORG_MAX_BITS || (*end && *end != '\n' && *end != ',') || (more_bits && bit == 0 && errno != 0)) {
                SXEL2("%s: %u: Invalid org bit (field 6) - must be less than %zu", conf_loader_path(cl), conf_loader_line(cl), PREF_ORG_MAX_BITS);
                goto OUT;
            }

            if (more_bits)
                me->item[me->count].orgmask |= end == line ? 0 : (1 << bit);
            else
                me->item[me->count].orgmask = end == line ? 0 : (1 << bit);

            more_bits = (*end == ',') ? true : false;
            line = end + 1;

        } while (more_bits);

        for (namei = 0; namei < me->count; namei++)
            if ((cmp = strcmp(name, allnames[namei])) == 0) {
                SXEL2("%s: %u: Invalid name (field 2) - must be unique", conf_loader_path(cl), conf_loader_line(cl));
                goto OUT;
            } else if (cmp > 0)
                break;

        me->module[me->count] = 0;
        tm->confregister(me->module + me->count, name, path, false);
        if (me->module[me->count] == 0)
            goto OUT;

        if (!conf_registrar_add(&me->registrar, me->module[me->count])) {
            conf_unregister(me->module[me->count]);
            goto OUT;
        }
        memmove(allnames + namei + 1, allnames + namei, (me->count - namei) * sizeof(*allnames));
        allnames[namei] = conf_name(NULL, me->module[me->count]);

        me->count++;
    }

    conf_registrar_set_loadable(&me->registrar);
    retme = me;

OUT:
    kit_free(allnames);
    if (retme == NULL)
        CONF_REFCOUNT_DEC(me);

    return retme;
}

static void
categorization_free(struct conf *base)
{
    struct categorization *me = CONF2CAT(base);

    SXEA6(base->type == &catct, "categorization_free() with unexpected conf_type %s", base->type->name);

    conf_registrar_fini(&me->registrar);
    kit_free(me->module);
    kit_free(me->item);
    kit_free(me);
}

const uint8_t *
categorization_match_appid(const struct categorization *me, const struct confset *conf, pref_categories_t *match,
                           uint32_t appid, const uint8_t *name, uint32_t polbits, pref_orgflags_t orgbits,
                           const pref_categories_t *find, struct xray *x)
{
    const uint8_t *result = NULL;
    unsigned       i;

    if (me != NULL)
        for (i = 0; result == NULL && i < me->count; i++)
            if (me->item[i].type == CATTYPE_APPLICATION
             && pref_categories_getbit(find, me->item[i].catbit)
             && !pref_categories_getbit(match, me->item[i].catbit)
             && (!me->item[i].polmask || me->item[i].polmask & polbits)
             && (!me->item[i].orgmask || me->item[i].orgmask & orgbits)) {
                SXEL6("categorization: Lookup %s in appid %u", dns_name_to_str1(name), appid);

                if ((result = application_match_domain_byid(application_conf_get(conf, me->module[i]), appid, name, x)) != NULL)
                    pref_categories_setbit(match, me->item[i].catbit);
            }

    return result;
}

const uint8_t *
categorization_proxy_appid(const struct categorization *me, const struct confset *conf, uint32_t appid, const uint8_t *name,
                           uint32_t polbits, pref_orgflags_t orgbits, struct xray *x)
{
    const uint8_t *result = NULL;
    unsigned       i;

    if (me != NULL)
        for (i = 0; result == NULL && i < me->count; i++)
            if (me->item[i].type == CATTYPE_APPLICATION
             && (!me->item[i].polmask || me->item[i].polmask & polbits)
             && (!me->item[i].orgmask || me->item[i].orgmask & orgbits)) {
                SXEL6("categorization: Lookup %s proxy in appid %u", dns_name_to_str1(name), appid);

                if ((result = application_proxy_byid(application_conf_get(conf, me->module[i]), appid, name, x)) != NULL)
                    break;
            }

    return result;
}

void
categorization_by_domain(const struct categorization *me, const struct confset *conf, pref_categories_t *match,
                         const uint8_t *name, uint32_t polbits, pref_orgflags_t orgbits, struct xray *x)
{
    enum domainlist_match mtype;
    const char *confname;
    bool is_domaintagging;
    unsigned i;

    if (me != NULL)
        for (i = 0; i < me->count; i++)
            if ((!me->item[i].polmask || me->item[i].polmask & polbits) && (!me->item[i].orgmask || me->item[i].orgmask & orgbits))
                switch (me->item[i].type) {
                case CATTYPE_DOMAINTAGGING:
                    confname = conf_name(conf, me->module[i]);
                    is_domaintagging  = (confname && (strcmp(confname, "domaintagging") == 0)) ? true : false;
                    domaintagging_match(domaintagging_conf_get(conf, me->module[i]), match, name, x, conf_name(conf, me->module[i]));

                    if (is_domaintagging && (orgbits & PREF_ORGFLAGS_HALF_DOMAINTAGGING)) {
                        conf_update_thread_options();    // Call the application to update the thread's options if changed
                        SXEL4("Masking %s domaintagging category bits. HALF_DOMAINTAGGING is set",
                              pref_categories_idstr(&option_half_domaintagging));
                        pref_categories_clear(match, &option_half_domaintagging);
                    }

                    SXEL7("After looking for %s in %s, categories are %s",
                          dns_name_to_str1(name), conf_name(conf, me->module[i]) ?: "<not-loaded>", pref_categories_idstr(match));
                    break;
                case CATTYPE_DOMAINLIST:
                case CATTYPE_EXACT_DOMAINLIST:
                    mtype = me->item[i].type == CATTYPE_DOMAINLIST ? DOMAINLIST_MATCH_SUBDOMAIN : DOMAINLIST_MATCH_EXACT;

                    if (domainlist_match(domainlist_conf_get(conf, me->module[i]), name, mtype, x, conf_name(conf, me->module[i])))
                        pref_categories_setbit(match, me->item[i].catbit);

                    SXEL7("After looking for %s in %s, categories are %s",
                          dns_name_to_str1(name), conf_name(conf, me->module[i]) ?: "<not-loaded>", pref_categories_idstr(match));
                    break;
                case CATTYPE_APPLICATION:
                    if (application_match_domain(application_conf_get(conf, me->module[i]), name, x, conf_name(conf, me->module[i])))
                        pref_categories_setbit(match, me->item[i].catbit);

                    SXEL7("After looking for %s in %s, categories are %s",
                          dns_name_to_str1(name), conf_name(conf, me->module[i]) ?: "<not-loaded>", pref_categories_idstr(match));
                    break;
                default:
                    break;
                }
}   /* COVERAGE EXCLUSION: due to a gcov bug */

void
categorization_by_address(const struct categorization *me, const struct confset *conf, pref_categories_t *match,
                          const struct netaddr *addr, uint32_t polbits, pref_orgflags_t orgbits, struct xray *x)
{
    unsigned i;

    if (me != NULL)
        for (i = 0; i < me->count; i++)
            if ((!me->item[i].polmask || me->item[i].polmask & polbits) && (!me->item[i].orgmask || me->item[i].orgmask & orgbits))
                switch (me->item[i].type) {
                case CATTYPE_CIDRLIST:
                case CATTYPE_IPLIST:
                    if (cidrlist_search(cidrlist_conf_get(conf, me->module[i]), addr, x, conf_name(conf, me->module[i])))
                        pref_categories_setbit(match, me->item[i].catbit);

                    SXEL7("After looking for %s in %s, categories are %s",
                          netaddr_to_str(addr), conf_name(conf, me->module[i]) ?: "<not-loaded>", pref_categories_idstr(match));
                    break;
                default:
                    break;
                }
}   /* COVERAGE EXCLUSION: due to a gcov bug */

bool
categorization_might_proxy(const struct categorization *me, const struct confset *conf, const uint8_t *name, uint32_t polbits,
                           pref_orgflags_t orgbits, struct xray *x)
{
    unsigned i;

    if (me != NULL)
        for (i = 0; i < me->count; i++)
            if (me->item[i].type == CATTYPE_APPLICATION)
                if ((!me->item[i].polmask || me->item[i].polmask & polbits) && (!me->item[i].orgmask || me->item[i].orgmask & orgbits))
                    if (application_proxy(application_conf_get(conf, me->module[i]), name, x, conf_name(conf, me->module[i])))
                        return true;

    return false;
}
