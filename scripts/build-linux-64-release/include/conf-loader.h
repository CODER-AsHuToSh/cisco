#ifndef CONF_LOADER_H
#define CONF_LOADER_H

#include <sys/param.h>
#include <zlib.h>

#if __FreeBSD__
#include <stdio.h>
#endif

#include "conf.h"
#include "pref-segments.h"

struct conf_loader_state {
    gzFile gz;                              /* File reader */
    char rbuf[8192];                        /* Raw buffer */
    char fn[PATH_MAX];                      /* Path name of opened file */
    size_t rbuflen;                         /* Raw buffer used */
    unsigned line;                          /* Last read line number */
    int err;                                /* CONF_LOADER_STATE_* flags */
};

#define CONF_LOADER_SKIP_COMMENTS 0x01
#define CONF_LOADER_SKIP_EMPTY    0x02
#define CONF_LOADER_CHOMP         0x04    // Replace the '\n' at the end of line with a '\0'
#define CONF_LOADER_ALLOW_NUL     0x08    // Internal flag: Allow '\0' bytes in conf_loader_readfile()
#define CONF_LOADER_UNREAD_LINE   0x10    // Internal flag: The current line has been unread so it can be reprocessed.

#define CONF_LOADER_DEFAULT (CONF_LOADER_SKIP_COMMENTS|CONF_LOADER_SKIP_EMPTY)

/*-
 * struct conf_loader
 *
 * This struct is a vehicle used to build a conf file (something
 * containing struct conf).  As conf_loader_readline() is called (or
 * when conf_loader_readfile() is called), a "last-good" temp file will
 * be written.  When conf_loader_done() is called, the conf file is
 * returned and the temp file is moved into place.  If anything fails,
 * the loader can be reused by just calling conf_loader_open() again.
 *
 * The conf_loader ignores comments and blank lines (per flags above).
 */
struct conf_loader {
    struct conf_stat st;                    /* The config file being loaded */
    struct conf_loader_state state;         /* Currently open file details (if state.gz != NULL) */
    uint8_t flags;                          /* CONF_LOADER_* flags used during loading */
    MD5_CTX md5;
    uint64_t base_alloc;                    /* Per-thread bytes allocated at open() time */
    char tempfn[PATH_MAX];                  /* Temporary backup file */
    char backup[PATH_MAX];                  /* Target backup file */
    gzFile backupgz;                        /* Temporary backup file writer */
    FILE *backupfp;                         /* Needed because gzopen(..., "w0") still writes a binary header/footer */
    char *buf;                              /* Line buffer */
    size_t bufsz;                           /* Line buffer size */
};

#include "conf-loader-proto.h"

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define CONF_LOADER_READFILE    ((const char *)conf_loader_readfile + 0)
#   define CONF_LOADER_GZREAD      ((const char *)conf_loader_readfile + 1)
#   define CONF_LOADER_RAW_GETLINE ((const char *)conf_loader_readfile + 2)
#   define CONF_LOADER_TOOMUCHDATA ((const char *)conf_loader_readfile + 3)
#   define CONF_LOADER_REALLOC     ((const char *)conf_loader_readfile + 4)
#endif

#endif
