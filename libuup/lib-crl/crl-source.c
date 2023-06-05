#include <ctype.h>

#include "crl-source.h"

void
crl_source_init(struct crl_source *source, char *string, const char *file, unsigned line, unsigned version)
{
    source->text    = string;
    source->left    = string;
    source->file    = file;
    source->line    = line;
    source->version = version;
    source->status  = CRL_STATUS_OK;
}

char *
crl_source_skip_char(struct crl_source *source)
{
    source->left++;
    return source->left;
}

char *
crl_source_skip_space(struct crl_source *source)
{
    while (isspace(*source->left))
        source->left++;

    return source->left;
}

bool
crl_source_is_exhausted(struct crl_source *source)
{
    return *crl_source_skip_space(source) ? false : true;
}
