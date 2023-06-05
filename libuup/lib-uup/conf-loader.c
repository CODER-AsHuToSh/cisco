#include <errno.h>
#include <kit-alloc.h>
#include <kit.h>
#include <mockfail.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "conf-loader.h"
#include "infolog.h"

#if ZLIB_VERNUM >= 0x1280
#define GZBUFFERSZ     (128 * 1024)
#endif
#define GZLINEGROWTHSZ 256

#ifdef __linux__
#define SSTRERROR(errno, err, sz) strerror_r(errno, err, sz)
#else
#define SSTRERROR(errno, err, sz) (strerror_r(errno, err, sz) ? "No Error" : err)
#endif

void
conf_loader_init(struct conf_loader *cl)
{
    memset(&cl->st, '\0', sizeof(cl->st));
    cl->state.gz = NULL;
    *cl->state.fn = '\0';
    cl->state.err = 0;
    cl->flags = CONF_LOADER_DEFAULT;
    cl->backupgz = NULL;
    cl->backupfp = NULL;
    cl->buf = NULL;
    cl->bufsz = 0;
    *cl->backup = *cl->tempfn = '\0';
}

bool
conf_loader_eof(const struct conf_loader *cl)
{
    return !cl->state.gz && (!cl->buf || !*cl->buf);
}

int
conf_loader_err(const struct conf_loader *cl)
{
    return cl->state.err;
}

static void
conf_loader_reset(struct conf_loader *cl)
{
    if (cl->state.gz) {
        gzclose(cl->state.gz);
        cl->state.gz = NULL;
    }

    if (cl->backupgz || cl->backupfp) {
        if (cl->backupgz)
            gzclose(cl->backupgz);
        if (cl->backupfp)
            fclose(cl->backupfp);
        unlink(cl->tempfn);

        cl->backupgz = NULL;
        cl->backupfp = NULL;
        *cl->tempfn = *cl->backup = '\0';
    }
    memset(&cl->st, '\0', sizeof(cl->st));
    *cl->state.fn = '\0';
    cl->state.rbuflen = 0;
    cl->state.err = 0;
    cl->flags = CONF_LOADER_DEFAULT;
}

bool
conf_loader_open(struct conf_loader *cl, const char *fn, const char *backupdir, const char *backupsuffix, int clev, uint8_t flags)
{
    gzFile      gz;
    struct stat st;
    const char *base;
    int         cperrno, fd, flen;
    char        err[256], how[3];

    conf_loader_reset(cl);
    cl->flags = flags;
    flen = snprintf(cl->state.fn, sizeof(cl->state.fn), "%s", fn);
    if ((fd = open(fn, O_RDONLY)) == -1 && flen < (int)sizeof(cl->state.fn) - 3) {
        cperrno = errno;
        if (cperrno == ENOENT) {    /* If file not found, look for a .gz file */
            strcpy(cl->state.fn + flen, ".gz");
            if ((fd = open(cl->state.fn, O_RDONLY)) != -1)
                SXEL6("%s(): Using %s rather than %s [fd %d]", __FUNCTION__, cl->state.fn, fn, fd);
            else if (errno == ENOENT)
                cl->state.fn[flen] = '\0';
            else
                cperrno = errno;    /* COVERAGE EXCLUSION: todo: test failing to open a compressed file */
        }
        if (fd == -1) {
            SXEL2("%s could not be opened: %s", *cl->state.fn ? cl->state.fn : fn, SSTRERROR(cperrno, err, sizeof(err)));
            errno = cl->state.err = cperrno;
            return false;
        }
    }

    if ((gz = gzdopen(fd, "r")) == NULL) {
        cperrno = errno;
        SXEL3("%s: gzdopen: %s", conf_loader_path(cl), SSTRERROR(errno, err, sizeof(err)));
        close(fd);
        memset(&cl->st, '\0', sizeof(cl->st));
        errno = cl->state.err = cperrno;
        return false;    /* COVERAGE EXCLUSION: todo: Figure out how to make gzdopen fail */
    }

    SXEA1(fstat(fd, &st) == 0, "fstat of descriptor for %s failed", conf_loader_path(cl));
    cl->st.dev = st.st_dev;
    cl->st.ino = st.st_ino;
    cl->st.size = st.st_size;
    cl->st.mtime = st.st_mtime;
    cl->st.ctime = st.st_ctime;

#ifdef GZBUFFERSZ
    gzbuffer(gz, GZBUFFERSZ);
#endif
    MD5_Init(&cl->md5);
    cl->base_alloc = kit_thread_allocated_bytes();

    if (backupdir || backupsuffix) {
        base = kit_basename(fn);
        snprintf(cl->tempfn, sizeof(cl->tempfn), "%s%s.%s%s",
                 backupdir ? backupdir : "", backupdir && *backupdir ? "/" : "", base, backupsuffix ? backupsuffix : "");
        snprintf(cl->backup, sizeof(cl->backup), "%s%s%s%s",
                 backupdir ? backupdir : "", backupdir && *backupdir ? "/" : "", base, backupsuffix ? backupsuffix : "");

        fd = open(cl->tempfn, O_CREAT|O_WRONLY, 0644);
        cperrno = fd == -1 ? errno : 0;

        if (!cperrno) {
            if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
                if (ftruncate(fd, 0) == 0) {
                    SXEA1(clev >= 0 && clev <= 9, "Unexpected clev value %d", clev);
                    if (clev) {
                        snprintf(how, sizeof(how), "w%d", clev);
                        SXEL6("Creating %s using compression level %d", cl->backup, clev);
                        cl->backupgz = gzdopen(fd, how);
                    } else
                        cl->backupfp = fdopen(fd, "w");
                }
                cperrno = cl->backupgz || cl->backupfp ? 0 : errno ?: EIO;    /* ftruncate/gzdopen/fdopen failure */
            } else {
                SXEL6("Failed to lock %s - no backup/reject file stored", cl->tempfn);
                close(fd);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            }
        }

        if (cperrno) {
            SXEL2("conf-loader: Cannot create/truncate %s: %s", cl->tempfn, SSTRERROR(cperrno, err, sizeof(err)));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            close(fd);                                /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            gzclose(gz);                              /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            memset(&cl->st, '\0', sizeof(cl->st));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            errno = cl->state.err = cperrno;          /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            return false;                             /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        }
    }

    cl->state.gz = gz;
    cl->state.line = 0;
    cl->state.rbuflen = 0;

    return true;
}

static ssize_t
conf_loader_raw_nextline(struct conf_loader *cl, size_t start)
{
    size_t  pos, rpos;
    ssize_t result;
    char   *nbuf;
    int     errnum;

    pos = start;

    do {
        if (!cl->state.rbuflen && cl->state.gz) {
            /* Try to get some more raw data */
            result = MOCKFAIL(CONF_LOADER_GZREAD, -1, gzread(cl->state.gz, cl->state.rbuf + cl->state.rbuflen, sizeof(cl->state.rbuf) - cl->state.rbuflen));

            if (result > 0)
                cl->state.rbuflen += result;
            else {
                if (result == -1)
                    SXEL2("%s: %u: %s", conf_loader_path(cl), conf_loader_line(cl),
                          MOCKFAIL(CONF_LOADER_GZREAD, "Some gzerror() string", gzerror(cl->state.gz, &errnum)));
                gzclose(cl->state.gz);
                cl->state.gz = NULL;
            }
        }

        if (cl->state.rbuflen) {
            /* Consume the raw data (populating the conf-loader) until we see a linefeed */
            rpos = 0;
            while (rpos < cl->state.rbuflen) {
                if (pos + 1 >= cl->bufsz) {
                    if ((nbuf = MOCKFAIL(CONF_LOADER_RAW_GETLINE, NULL, kit_realloc(cl->buf, cl->bufsz + GZLINEGROWTHSZ))) == NULL) {
                        SXEL2("Couldn't realloc line buffer to %zu bytes", cl->bufsz);
                        if (cl->state.gz) {
                            gzclose(cl->state.gz);
                            cl->state.gz = NULL;
                        }
                        break;
                    }
                    cl->bufsz += GZLINEGROWTHSZ;
                    cl->buf = nbuf;
                }

                cl->buf[pos] = cl->state.rbuf[rpos++];

                if (cl->buf[pos++] == '\n')
                    break;
                else if (!(cl->flags & CONF_LOADER_ALLOW_NUL) && cl->buf[pos - 1] == '\0') {
                    SXEL3("%s: %u: Embedded NUL detected", conf_loader_path(cl), conf_loader_line(cl));
                    return 0;
                }
            }

            if (rpos == cl->state.rbuflen || (pos > start && cl->buf[pos - 1] == '\n')) {
                result = pos - start;
                memmove(cl->state.rbuf, cl->state.rbuf + rpos, cl->state.rbuflen -= rpos);
            } else
                result = -1;
        } else
            result = pos - start;

        if (cl->buf)
            cl->buf[pos] = '\0';
    } while (cl->state.gz && result > 0 && cl->buf[result + start - 1] != '\n');

    if (result > 0)
        cl->state.line++;

    return result;
}

static const char *
conf_loader_nextline(struct conf_loader *cl, size_t start, size_t *lenp)
{
    ssize_t len;
    int     cperrno;
    char    err[256];

    while ((len = conf_loader_raw_nextline(cl, start)) > 0) {
        MD5_Update(&cl->md5, cl->buf + start, len);

        if ((cl->backupgz != NULL && gzputs(cl->backupgz, cl->buf + start) == -1)
         || (cl->backupfp != NULL && fputs(cl->buf + start, cl->backupfp) == EOF)) {
            cperrno = errno ?: EIO;
            SXEL3("%s(): %s: write: %s", __FUNCTION__, cl->tempfn, SSTRERROR(errno, err, sizeof(err)));
            if (cl->backupgz)
                gzclose(cl->backupgz);
            if (cl->backupfp)
                fclose(cl->backupfp);
            cl->backupgz = NULL;
            cl->backupfp = NULL;
            *cl->tempfn = *cl->backup = '\0';
            cl->state.err = cperrno;    /* COVERAGE EXCLUSION: todo: test write failures */
        }

        if (cl->flags & CONF_LOADER_SKIP_EMPTY && (cl->buf[start] == '\0' || strcmp(cl->buf + start, "\n") == 0))
            continue;

        if (cl->flags & CONF_LOADER_SKIP_COMMENTS && cl->buf[start] == '#')
            continue;

        if (cl->flags & CONF_LOADER_CHOMP && cl->buf[start + len - 1] == '\n')
            cl->buf[start + --len] = '\0';

        if (lenp)
            *lenp = len;

        return cl->buf;
    }

    if (lenp)
        *lenp = 0;

    return NULL;
}

const char *
conf_loader_readline(struct conf_loader *cl)
{
    if (cl->flags & CONF_LOADER_UNREAD_LINE) {
        cl->flags &= ~CONF_LOADER_UNREAD_LINE;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return cl->buf;                           /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    return conf_loader_nextline(cl, 0, NULL);
}

const char *
conf_loader_appendline(struct conf_loader *cl)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    return conf_loader_nextline(cl, cl->state.line ? strlen(cl->buf) : 0, NULL);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
conf_loader_unreadline(struct conf_loader *cl)
{
    SXEA1(cl->state.line, "A line must be read before one can be unread");
    SXEA1(!(cl->flags & CONF_LOADER_UNREAD_LINE), "The current line can't be unread twice without rereading it");
    cl->flags |= CONF_LOADER_UNREAD_LINE;
}

__attribute__((malloc)) char *
conf_loader_readfile_binary(struct conf_loader *cl, size_t *len, size_t maxsz)
{
    uint8_t flags = cl->flags;
    char *ret;

    if ((size_t)cl->st.size > maxsz) {
        SXEL2("%s: Max size is 65535", conf_loader_path(cl));
        ret = NULL;
    } else {
        SXEA6(sizeof(flags) == sizeof(cl->flags), "Oops, 'flags' is the wrong variable type");
        cl->flags |= CONF_LOADER_ALLOW_NUL;
        cl->flags &= ~(CONF_LOADER_SKIP_COMMENTS | CONF_LOADER_SKIP_EMPTY | CONF_LOADER_CHOMP);
        ret = conf_loader_readfile(cl, len, 0);
        cl->flags = flags;
    }

    return ret;
}

__attribute__((malloc)) char *
conf_loader_readfile(struct conf_loader *cl, size_t *len, unsigned maxlines)
{
    size_t      llen, csz, remains;
    char       *content, *adjust;
    const char *line;
    unsigned    gzadd, nlines;

    *len = 0;
    csz = cl->st.size + 1 - gzseek(cl->state.gz, 0, SEEK_CUR) + cl->state.rbuflen;
    SXEL6("%s: %u: Setting csz to %zu + 1 - %zu + %zu = %zu", conf_loader_path(cl), conf_loader_line(cl),
          (size_t)cl->st.size, (size_t)cl->st.size + 1 - csz + cl->state.rbuflen, cl->state.rbuflen, csz);
    if ((content = MOCKFAIL(CONF_LOADER_READFILE, NULL, kit_malloc(csz))) == NULL)
        SXEL2("Couldn't allocate %zu bytes for file data", csz);
    else {
        gzadd = 0;
        nlines = 0;
        while ((line = conf_loader_nextline(cl, 0, &llen)) != NULL) {
            remains = MOCKFAIL(CONF_LOADER_TOOMUCHDATA, 0, csz - *len);
            if (remains <= llen) {
                if (conf_loader_iscompressed(cl)) {
                    /* The input is compressed - our buffer being too small doesn't imply that the file has changed! */
                    gzadd = gzadd ? gzadd * 2 : 128;
                    if ((adjust = MOCKFAIL(CONF_LOADER_REALLOC, NULL, kit_realloc(content, csz + gzadd + llen))) == NULL) {
                        SXEL2("%s: %u: Cannot realloc buffer from %zu to %zu bytes",
                              conf_loader_path(cl), conf_loader_line(cl), csz, csz + gzadd + llen);
                        kit_free(content);
                        return NULL;
                    }
                    content = adjust;
                    csz += gzadd + llen;
                } else {
                    SXEL2("%s: %u: Unexpected line length of %zu when only %zu buffer bytes remain (file has changed?)",
                          conf_loader_path(cl), conf_loader_line(cl), llen, remains);
                    kit_free(content);
                    return NULL;
                }
            }
            memcpy(content + *len, line, llen);
            *len += llen;
            if (++nlines == maxlines)    /* maxlines == 0 means no maximum */
                break;
        }

        if (maxlines) {
            if (nlines != maxlines) {
                SXEL2("%s: %u: Cannot load %u line%s, got %u",
                      conf_loader_path(cl), conf_loader_line(cl), maxlines, maxlines == 1 ? "" : "s", nlines);
                kit_free(content);
                content = NULL;
                *len = 0;
            }
        } else if (conf_loader_eof(cl)) {
            content[*len] = '\0';
            content = kit_reduce(content, *len + 1);
        } else {
            kit_free(content);
            content = NULL;
            *len = 0;
        }
    }

    return content;
}

const char *
conf_loader_path(const struct conf_loader *cl)
{
    return cl && *cl->state.fn ? cl->state.fn : "<none>";
}

unsigned
conf_loader_line(const struct conf_loader *cl)
{
    return cl == NULL || cl->state.fn == NULL ? 0 : cl->state.line;
}

void
conf_loader_done(struct conf_loader *cl, struct conf_info *info)
{
    char err[256];

    if (!cl->state.gz && !cl->state.err) {
        if (info) {
            MD5_Final(info->digest, &cl->md5);
            info->alloc = kit_thread_allocated_bytes() - cl->base_alloc;
            info->updates++;
            info->st = cl->st;
        }

        if (cl->backupgz || cl->backupfp) {
            if ((cl->backupgz && gzclose(cl->backupgz) != Z_OK) || (cl->backupfp && fclose(cl->backupfp) == EOF))
                SXEL3("%s(): %s: write: %s", __FUNCTION__, cl->tempfn, SSTRERROR(errno, err, sizeof(err)));               /* COVERAGE EXCLUSION: todo: test write failures */
            else if (rename(cl->tempfn, cl->backup) != 0)
                SXEL3("%s(): %s => %s: %s", __FUNCTION__, cl->tempfn, cl->backup, SSTRERROR(errno, err, sizeof(err)));    /* COVERAGE EXCLUSION: todo: test rename() failures */
            cl->backupgz = NULL;
            cl->backupfp = NULL;
            *cl->tempfn = *cl->backup = '\0';
        }
    } else if (info) {
        memset(info->digest, '\0', sizeof(info->digest));
    }
}

/* @param fn File name relative to the config directory
 */
void
conf_loader_reject(struct conf_loader *cl, const char *fn, const char *rejectdir)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    const char *base;
    char        err[256], reject_fn[PATH_MAX];

    if (cl->backupgz || cl->backupfp) {             /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        while (conf_loader_readline(cl) != NULL)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            ; /* Consume (backup) the remainder of the file */

        base = kit_basename(fn);                                             /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        snprintf(reject_fn, sizeof(reject_fn), "%s/%s", rejectdir, base);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

        if ((cl->backupgz && gzclose(cl->backupgz) != Z_OK) || (cl->backupfp && fclose(cl->backupfp) == EOF))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            SXEL3("%s(): error closing %s: %s", __FUNCTION__, cl->tempfn, SSTRERROR(errno, err, sizeof(err)));    /* COVERAGE EXCLUSION: todo: test write failures */
        else if (rename(cl->tempfn, reject_fn) != 0)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            SXEL2("%s(): error renaming %s to %s: %s", __FUNCTION__, cl->tempfn, reject_fn, SSTRERROR(errno, err, sizeof(err)));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        else {
            INFOLOG(CONF, "Saved %s as %s", fn, reject_fn);     /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            SXEL6("%s(): Saved %s as %s", __FUNCTION__, fn, reject_fn);
        }

        cl->backupgz = NULL;                 /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        cl->backupfp = NULL;                 /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        *cl->tempfn = *cl->backup = '\0';    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    cl->state.err = EINVAL;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

bool
conf_loader_iscompressed(struct conf_loader *cl)
{
    return cl->state.gz && !gzdirect(cl->state.gz);
}

void
conf_loader_fini(struct conf_loader *cl)
{
    conf_loader_reset(cl);

    kit_free(cl->buf);
    conf_loader_init(cl);
}
