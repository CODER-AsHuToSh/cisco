#include "urlprefs-org.h"

/* URL prefs don't have org keys and don't include identities, so there are no function to parse and convert keys
 */
static struct fileprefops urlprefs_org_ops = {
    .type               = "urlprefs",
    .free               = fileprefs_free,
    .supported_versions = { URLPREFS_VERSION, 0 }
};

void *
urlprefs_org_new(uint32_t orgid, struct conf_loader *cl, const struct conf_info *info)
{
    struct prefs_org *upo;

    if ((upo = (struct prefs_org *)fileprefs_new(cl, &urlprefs_org_ops, sizeof(struct prefs_org), info->loadflags))) {
        conf_segment_init(&upo->cs, orgid, cl, upo->fp.loadflags & LOADFLAGS_FP_FAILED);

        if (!(upo->fp.loadflags & LOADFLAGS_FP_FAILED) && !prefs_org_valid(upo, conf_loader_path(cl)))
            upo->fp.loadflags |= LOADFLAGS_FP_FAILED;
    }

    return upo;
}
