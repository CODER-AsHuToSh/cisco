/*    $OpenBSD: arc4random.c,v 1.25 2013/10/01 18:34:57 markus Exp $    */

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus at openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * ChaCha based random number generator for OpenBSD.
 *
 * __FBSDID("$FreeBSD: head/lib/libc/gen/arc4random.c 298226 2016-04-18 21:05:15Z avos $");
 */

#include <string.h>
#include <sys/param.h>
#include <pthread.h>
#include <sxe-util.h>

#include "kit-arc4random.h"
#include "kit-safe-rw.h"
#include "kit-chacha-private.h"

static int random_data_source_fd = -1;

#define    KEYSZ        32
#define    IVSZ         8
#define    BLOCKSZ      64
#define    RSBUFSZ      (16*BLOCKSZ)

static __thread bool rs_initialized;
static __thread chacha_ctx rs;            /* chacha context for random keystream */
static __thread uint8_t rs_buf[RSBUFSZ];  /* keystream blocks */
static __thread size_t rs_have;           /* valid bytes at end of rs_buf */
static __thread size_t rs_count;          /* bytes till reseed */

static inline void
_rs_init(uint8_t *buf, size_t n)
{
    if (n >= KEYSZ + IVSZ) {
        chacha_keysetup(&rs, buf, KEYSZ * 8, 0);
        chacha_ivsetup(&rs, buf + KEYSZ);
    }
}

static inline void
_rs_rekey(uint8_t *dat, size_t datlen)
{
    /* fill rs_buf with the keystream */
    chacha_encrypt_bytes(&rs, rs_buf, rs_buf, RSBUFSZ);

    /* mix in optional user provided data */
    if (dat) {
        size_t i, m;

        m = MIN(datlen, KEYSZ + IVSZ);
        for (i = 0; i < m; i++)
            rs_buf[i] ^= dat[i];
    }

    /* immediately reinit for backtracking resistance */
    _rs_init(rs_buf, KEYSZ + IVSZ);
    memset(rs_buf, '\0', KEYSZ + IVSZ);
    rs_have = RSBUFSZ - KEYSZ - IVSZ;
}

void
kit_arc4random_stir(void)
{
    uint8_t rdat[KEYSZ + IVSZ];
    ssize_t ret;

    ret = kit_safe_read(random_data_source_fd, &rdat, KEYSZ + IVSZ);
    SXEA1(ret == KEYSZ + IVSZ, "kit_safe_read() cannot fail unless we aren't initialized (got %zd from fd %d, not %d)",
          ret, random_data_source_fd, KEYSZ + IVSZ);

    if (!rs_initialized) {
        _rs_init(rdat, KEYSZ + IVSZ);
        rs_initialized = true;
    } else
        _rs_rekey(rdat, KEYSZ + IVSZ);
    memset(rdat, '\0', sizeof(rdat));

    /* invalidate rs_buf */
    rs_have = 0;
    memset(rs_buf, '\0', RSBUFSZ);

    rs_count = 1600000;
}

static inline void
_rs_stir_if_needed(size_t len)
{
    if (rs_count <= len || !rs_initialized)
        kit_arc4random_stir();
    else
        rs_count -= len;
}

void
kit_arc4random_buf(void *v, size_t n)
{
    uint8_t *buf = v;
    size_t m;

    _rs_stir_if_needed(n);
    while (n) {
        if (rs_have > 0) {
            m = MIN(n, rs_have);
            memcpy(buf, rs_buf + RSBUFSZ - rs_have, m);
            memset(rs_buf + RSBUFSZ - rs_have, '\0', m);
            buf += m;
            n -= m;
            rs_have -= m;
        }
        if (rs_have == 0)
            _rs_rekey(NULL, 0);
    }
}

uint32_t
kit_arc4random(void)
{
    uint32_t val;

    _rs_stir_if_needed(sizeof(val));
    if (rs_have < sizeof(val))
        _rs_rekey(NULL, 0);
    memcpy(&val, rs_buf + RSBUFSZ - rs_have, sizeof(val));
    memset(rs_buf + RSBUFSZ - rs_have, '\0', sizeof(val));
    rs_have -= sizeof(val);

    return val;
}

/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**32 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
uint32_t
kit_arc4random_uniform(uint32_t upper_bound)
{
    uint32_t r, min;

    SXEA1(upper_bound >= 2, "Invalid upper_bound value %u", upper_bound);

    /* 2**32 % x == (2**32 - x) % x */
    min = -upper_bound % upper_bound;

    /*
     * This could theoretically loop forever but each retry has
     * p > 0.5 (worst case, usually far better) of selecting a
     * number inside the range we need, so it should rarely need
     * to re-roll.
     */
    do
        r = kit_arc4random();
    while (r < min);

    return r % upper_bound;
}

static void
_rs_need_init(void)
{
    rs_initialized = false;
}

bool
kit_arc4random_internals_initialized(void)
{
    return rs_initialized;    /* for testing that _rs_need_init() is called */
}

void
kit_arc4random_init(int fd)
{
    SXEA1(random_data_source_fd == -1, "kit_arc4random is already initialized");
    SXEA1(fd != -1, "Unexpected kit_arc4random initialization descriptor");

    random_data_source_fd = fd;
    pthread_atfork(NULL, NULL, _rs_need_init);
}
