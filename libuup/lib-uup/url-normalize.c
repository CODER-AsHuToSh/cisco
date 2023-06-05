#include <ctype.h>
#include <ctype.h>
#include <kit.h>
#include <stdio.h>
#include <string.h>
#include <sxe-log.h>

#include "url-normalize.h"

struct qarg_item {
    const char *val;
    unsigned len;
};

static int
qarg_item_compare(const void *a, const void *b)
{
    const char *a_val = ((const struct qarg_item *)a)->val;
    unsigned    a_len = ((const struct qarg_item *)a)->len;
    const char *b_val = ((const struct qarg_item *)b)->val;
    unsigned    b_len = ((const struct qarg_item *)b)->len;
    return strncmp(a_val, b_val, a_len < b_len ? a_len : b_len);
}

static void
tolower_strncpy(char *dst, const char *src, int len)
{
    int x;
    for (x = 0; x < len; x++) {
        dst[x] = tolower(src[x]);
    }
}

static bool
should_escape(char n)
{
    if (n == 0x26 || n == 0x2D || n == 0x2E || (n >= 0x30 && n <= 0x39) || n == 0x3D || n == 0x3F
     || (n >= 0x41 && n <= 0x5A) || n == 0x5F || (n >= 0x61 && n <= 0x7A) || n == 0x7E)
        return false;

    return true;
}

static bool
domain_characters(const char *buf, int len)
{
    int x;

    for (x = 0; x < len; x++)
        if (!isalnum(buf[x]) && buf[x] != '.' && buf[x] != '-' && buf[x] != '_')
            return true;

    return false;
}

URL_NORM_RETURN
url_normalize(const char *url, unsigned url_len, char *buf, unsigned *buf_len)
{
    URL_NORM_RETURN ret = URL_NORM_SUCCESS;
    const char *reader = url;
    const char *reader_end = url + url_len;
    char *writer = buf;
    char *writer_end = buf + *buf_len;

    SXEL6("url_normalize() // len=%d, '%.*s'", url_len, url_len, url);

    if (writer == writer_end) {
        ret = URL_NORM_FAILED;
        goto DONE;
    }

    // remove any leading whitespace
    while((reader != reader_end) && (isspace(*reader)))
        reader++;

    if (reader == reader_end) {
        ret = URL_NORM_FAILED;
        goto DONE;
    }

    // remove an http:// scheme
    if ((unsigned)(reader_end - reader) > (sizeof("http://") - 1))
        if (strncasecmp("http://", reader, sizeof("http://") - 1) == 0)
            reader += sizeof("http://") - 1;

    // remove an https:// scheme
    if ((unsigned)(reader_end - reader) > (sizeof("https://") - 1))
        if (strncasecmp("https://", reader, sizeof("https://") - 1) == 0)
            reader += sizeof("https://") - 1;

    // find the end of the domain (account for username, password and port)
    const char *domain_start = reader;
    const char *domain_end;
    for (;;reader++) {
        if (reader == reader_end) {
            domain_end = reader;
            goto DOMAIN_END;
        }
        else if (*reader == '?')  {
            domain_end = reader;
            goto DOMAIN_END;
        }
        else if (*reader == '/')  {
            domain_end = reader;
            goto DOMAIN_END;
        }
        else if (*reader == '@')  {
            domain_start = reader + 1;
        }
        else if (*reader == ':')  { // Could be the a user:pass serperator, or the start of a port
            domain_end = reader;
            int is_port = 1; // port until proven otherwise
            for (;;) {
                reader++;
                if (reader == reader_end) {
                    ret = URL_NORM_FAILED;
                    goto DONE;
                }
                else if (isdigit(*reader)) {
                    if ((is_port == 1) && (reader + 1 == reader_end))
                        goto DOMAIN_END;
                    continue;
                }
                if (*reader == '@') {
                    domain_start = reader + 1;
                    break;
                }
                else if (*reader == ':') {
                    ret = URL_NORM_FAILED;
                    goto DONE;
                }
                else if (*reader == '/' || *reader == '?') {
                    if (is_port == 0) {
                        ret = URL_NORM_FAILED;
                        goto DONE;
                    }
                    goto DOMAIN_END;
                } else
                    is_port = 0;
            }
        }
    }

DOMAIN_END: ;
    int domain_len = domain_end - domain_start;

    // smallest valid URL len would 'a.co/'
    if (domain_len < (int)(sizeof("a.co") - 1)
     || domain_len > URL_HOST_LEN_MAX
     || writer + domain_len >= writer_end
     || domain_characters(domain_start, domain_len)) {
        ret = URL_NORM_FAILED;
        goto DONE;
    }

    tolower_strncpy(writer, domain_start, domain_len);
    writer += domain_len;

    *writer++ = '/';
    if (reader == reader_end)
        goto DONE;

    if (writer == writer_end) {
        ret = URL_NORM_TRUNCATED;
        goto DONE;
    }

    // and now the path portion (paths must start with a '/' or '?'
    if (*reader != '?')
        reader++; // '/' already added

    const char *path_start = writer - 1;
    char *qargs_start = NULL;
    char *qargs_end   = NULL;
    int   skip_write  = 0;

    while (reader != reader_end) {
        if (*reader == '/' && qargs_start == NULL) {
            if (reader + 1 == reader_end || reader[1] == '?') {
                while (writer[-1] == '/' && writer - 1 != path_start)
                    writer--;
                skip_write = 1;
            }
            else if (reader[-1] == '/') {
                skip_write = 1;
            }
        }
        else if ((*reader == '.') && (qargs_start == NULL)) {
            if (reader[-1] == '/'
             && reader + 1 != reader_end
             && reader[1] == '/') {
                if (((writer - 1) != path_start) && (reader + 2 == reader_end))
                    writer--;
                reader++;
                skip_write = 1;
            }
            if (reader[-1] == '.'
             && reader[-2] == '/'
             && reader + 1 != reader_end
             && reader[1] == '/') {
                writer -= 2; // back to previous /
                if (writer == path_start) {
                    writer++;
                } else {
                    while (*(writer - 1) != '/')
                        writer--;
                    if (((writer - 1) != path_start) && (reader + 2 == reader_end))
                        writer--;
                }
                reader++;
                skip_write = 1;
            }
        }
        else if (*reader == '%') {
            if (reader + 2 < reader_end
             && isalnum(reader[1])
             && isalnum(reader[2])) {
                char e_buf[3];
                e_buf[0] = reader[1];
                e_buf[1] = reader[2];
                e_buf[2] = '\0';

                char n = (char)kit_strtol(e_buf, NULL, 16);
                if (should_escape(n) == 0) {
                    reader += 2;
                    *writer++ = tolower(n);
                    skip_write = 1;
                }
            }
        }
        else if (*reader == '?') {
            if (qargs_start == NULL) {
                for (;;) {
                    if (reader + 1 == reader_end)
                        goto DONE;
                    if (reader[1] != '?')
                        break;
                    reader++;
                }
                qargs_start = writer;
            }
        }
        else if (*reader == '#') {
            break;
        }
        else if (*reader == '&') {
            if (qargs_start != NULL
             && reader + 4 <= reader_end
             && memcmp(reader, "&amp;", 5) == 0) {
                *writer++ = '&';
                reader += 4;
                skip_write = 1;
            }
        }
        else if (should_escape(*reader)) {
            const char *tmp_reader = reader;

            while (isspace(*tmp_reader)) {
                tmp_reader++;
                if (tmp_reader == reader_end)
                    goto QARGS;
            }

            char escaped[3];
            snprintf(escaped, sizeof(escaped), "%02x", (unsigned char)*reader);
            *writer++ = '%';
            if (writer == writer_end) {
                ret = URL_NORM_TRUNCATED;
                goto DONE;
            }
            *writer++ = escaped[0];
            if (writer == writer_end) {
                ret = URL_NORM_TRUNCATED;
                goto DONE;
            }
            *writer++ = escaped[1];
            skip_write = 1;
        }

        if (skip_write == 0)
            *writer++ = tolower(*reader);
        else
            skip_write = 0;

        reader++;

        if (writer == writer_end && reader != reader_end) {
            ret = URL_NORM_TRUNCATED;
            goto DONE;
        }
    }

QARGS:
    if (qargs_start == NULL)
        goto DONE;

    /*
     * The query args have been properly (un)escaped and written to writer buf.
     * We need to alloc a buffer where we can write the sorted args
     * and then copy the data back to the writer buf
     */
    qargs_start++;
    qargs_end = writer;
    unsigned qargs_len = qargs_end - qargs_start;

    SXEA6(qargs_len, "url_normalize() - qargs_len is zero!");
    {
        char qargs_buf[qargs_len];
        memcpy(qargs_buf, qargs_start, qargs_len);

        // The smallest query arg would be a& (so divided len by 2)
        struct qarg_item qarg_list[(qargs_len / 2) + 1];
        unsigned qarg_list_count = 0;
        unsigned x;
        char *cur_qarg_start = qargs_buf;

        for (x = 0; x < qargs_len; x++) {
            if (qargs_buf[x] == '&') {
                if (qargs_buf + x != cur_qarg_start) {
                    qarg_list[qarg_list_count].val = cur_qarg_start;
                    qarg_list[qarg_list_count].len = qargs_buf + x - cur_qarg_start;
                    qarg_list_count++;
                }
                cur_qarg_start = qargs_buf + x + 1;
            }
        }

        if (cur_qarg_start != qargs_buf + x) {
            qarg_list[qarg_list_count].val = cur_qarg_start;
            qarg_list[qarg_list_count].len = qargs_buf + x - cur_qarg_start;
            qarg_list_count++;
        }

        if (qarg_list_count == 0) {
            writer = qargs_start - 1; // remove the '?' too
            goto DONE;
        } else {
            writer = qargs_start;
        }

        qsort(qarg_list, qarg_list_count, sizeof(struct qarg_item), qarg_item_compare);

        int first_arg = 1;
        for (x = 0; x < qarg_list_count; x++) {
            if (qarg_list[x].len == 1 && *qarg_list[x].val == '=')
                continue;
            if (first_arg != 1)
                *writer++ = '&';
            else
                first_arg = 0;
            memcpy(writer, qarg_list[x].val, qarg_list[x].len);
            writer += qarg_list[x].len;
        }
    }

DONE:
    *buf_len = writer - buf;
    return ret;
}
