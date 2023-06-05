#include <kit-alloc.h>
#include <mockfail.h>

#include "application-lists.h"
#include "atomic.h"
#include "conf-loader.h"
#include "conf-meta.h"
#include "domainlist.h"
#include "urllist.h"

void
application_lists_refcount_dec(void *obj)
{
    struct application_lists *me = obj;

    if (me && ATOMIC_DEC_INT_NV(&me->cs.refcount) == 0) {
        domainlist_refcount_dec(me->dl);
        domainlist_refcount_dec(me->pdl);
        urllist_refcount_dec(me->ul);
        conf_meta_free(me->cm);
        kit_free(me);
    }
}

void
application_lists_refcount_inc(void *obj)
{
    struct application_lists *me = obj;

    if (me)
        ATOMIC_INC_INT(&me->cs.refcount);
}

void *
application_lists_new(uint32_t appid, struct conf_loader *cl, const struct conf_info *info)
{
    size_t count, dcount, i, mcount, ucount;
    bool wantdata, wantdomains, wanturls;
    struct application_lists *me, *retme;
    unsigned start, version;
    const char *line;

    retme = me = NULL;
    wantdata = false;
    wantdomains = wanturls = true;

    if ((line = conf_loader_readline(cl)) == NULL) {
        SXEL2("%s: Missing header line", conf_loader_path(cl));
        goto SXE_EARLY_OUT;
    }

    if (sscanf(line, "lists %u\n", &version) != 1) {
        if (sscanf(line, "domainlist %u\n", &version) != 1) {
            SXEL2("%s: Unrecognized header line, expected 'lists %u' or 'domainlist %u'",
                  conf_loader_path(cl), APPLICATION_VERSION, APPLICATION_VERSION);
            goto SXE_EARLY_OUT;
        }
        wantdata = true;
        wantdomains = wanturls = false;
    }
    if (version != APPLICATION_VERSION) {
        SXEL2("%s: %u: Unrecognized header version, expected %u, not %u",
              conf_loader_path(cl), conf_loader_line(cl), APPLICATION_VERSION, version);
        goto SXE_EARLY_OUT;
    }

    if ((me = MOCKFAIL(application_lists_new, NULL, kit_calloc(1, sizeof(*me)))) == NULL) {
        SXEL2("%s: Cannot allocate %zu bytes for an application-lists object", conf_loader_path(cl), sizeof(*me));
        goto SXE_EARLY_OUT;
    }
    me->cs.refcount = 1;

    if ((line = conf_loader_readline(cl)) == NULL || sscanf(line, "count %zu\n", &count) != 1) {
        SXEL2("%s: %u: Unrecognized count line, expected 'count <N>'", conf_loader_path(cl), conf_loader_line(cl));
        goto SXE_EARLY_OUT;
    }

    mcount = 0;
    if ((line = conf_loader_readline(cl)) != NULL && sscanf(line, "[meta:%zu]\n", &mcount) == 1) {
        if (mcount && (me->cm = conf_meta_new(cl, mcount)) == NULL)
            goto SXE_EARLY_OUT;
        line = conf_loader_readline(cl);
    }

    dcount = 0;
    ucount = 0;
    while (line && (wantdata || wantdomains || wanturls))
        /**
         * XXX: It would be nice to be more clever here, using one allocation for dl and ul/pdl
         *      BUT....
         *      It turns out that for the dl + pdl case, we're not using most of the data from the [urls]
         *      and in the dl + ul case, the urllist can't reference the original data because it needs
         *      to url_normalize() it, potentially creating a string that's larger than the original.
         */
        if ((wantdata && sscanf(line, "[data:%zu]\n", &dcount) == 1) || (wantdomains && sscanf(line, "[domains:%zu]\n", &dcount) == 1)) {
            if (dcount) {
                if (info->loadflags & LOADFLAGS_APPLICATION_IGNORE_DOMAINS) {
                    for (i = 0; i < dcount; i++)
                        if ((line = conf_loader_readline(cl)) == NULL) {
                            SXEL2("%s: %u: Got EOF after ignoring %zu of %zu domain%s",
                                  conf_loader_path(cl), conf_loader_line(cl), i, dcount, dcount == 1 ? "" : "s");
                            goto SXE_EARLY_OUT;
                        } else if (line[0] == '[') {
                            SXEL2("%s: %u: Got section header after ignoring %zu of %zu domain%s",
                                  conf_loader_path(cl), conf_loader_line(cl), i, dcount, dcount == 1 ? "" : "s");
                            goto SXE_EARLY_OUT;
                        }
                } else {
                    start = conf_loader_line(cl);
                    if ((me->dl = domainlist_new(cl, dcount, LOADFLAGS_DL_LINEFEED_REQUIRED)) == NULL) {
                        SXEL2("%s: %u: Failed to load domainlist", conf_loader_path(cl), start);
                        goto SXE_EARLY_OUT;
                    }
                }
            }
            line = conf_loader_readline(cl);
            wantdata = wantdomains = false;
        } else if (wanturls && sscanf(line, "[urls:%zu]\n", &ucount) == 1) {
            if (ucount) {
                if (info->loadflags & LOADFLAGS_APPLICATION_URLS_AS_PROXY) {
                    start = conf_loader_line(cl);
                    if ((me->pdl = domainlist_new(cl, ucount, LOADFLAGS_DL_LINEFEED_REQUIRED | LOADFLAGS_DL_TRIM_URLS | LOADFLAGS_DL_EXACT)) == NULL) {
                        SXEL2("%s: %u: Failed to load domains from URL list", conf_loader_path(cl), start);
                        goto SXE_EARLY_OUT;
                    }
                } else if ((me->ul = urllist_new_strict(cl, ucount)) == NULL)
                    goto SXE_EARLY_OUT;
            }
            line = conf_loader_readline(cl);
            wanturls = false;
        } else
            break;

    if (line) {
        SXEL2("%s: %u: Unexpected line", conf_loader_path(cl), conf_loader_line(cl));
        goto SXE_EARLY_OUT;
    }

    if (count != mcount + dcount + ucount) {
        SXEL2("%s: %u: Headers don't add up; count %zu != meta %zu + domainlist %zu + urllist %zu",
              conf_loader_path(cl), conf_loader_line(cl), count, mcount, dcount, ucount);
        goto SXE_EARLY_OUT;
    }

    conf_segment_init(&me->cs, appid, cl, false);
    retme = me;

SXE_EARLY_OUT:
    if (retme == NULL)
        application_lists_refcount_dec(me);

    return retme;
}
