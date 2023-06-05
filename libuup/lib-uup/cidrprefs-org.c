#include "cidrprefs-org.h"

/* cidrprefs don't have org keys or identities, so there are no functions to parse and convert keys
 */
static struct fileprefops cidrprefs_org_ops = {
    .type               = "cidrprefs",
    .free               = fileprefs_free,
    .supported_versions = { CIDRPREFS_VERSION, 0 }
};

void *
cidrprefs_org_new(uint32_t orgid, struct conf_loader *cl, const struct conf_info *info)
{
    struct prefs_org *cpo;

    if ((cpo = (struct prefs_org *)fileprefs_new(cl, &cidrprefs_org_ops, sizeof(struct prefs_org), info->loadflags))) {
        conf_segment_init(&cpo->cs, orgid, cl, cpo->fp.loadflags & LOADFLAGS_FP_FAILED);

        if (!(cpo->fp.loadflags & LOADFLAGS_FP_FAILED) && !prefs_org_valid(cpo, conf_loader_path(cl)))
            cpo->fp.loadflags |= LOADFLAGS_FP_FAILED;
    }

    return cpo;
}
