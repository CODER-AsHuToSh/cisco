#if __FreeBSD__
#include <sys/types.h>
#endif

#include "kit.h"
#include <sxe-util.h>

#if SXE_DEBUG
#include <string.h>
#endif

// Each ASCII character is matched to a number (0-63) or one of the following special values.
//
#define WS 64    // Whitespace character
#define EQ 65    // Equals sign (padding indicator)
#define IN 66    // Invalid in the encoding

struct basecfg {
    unsigned bits;
    unsigned wantpadding : 1;
    const uint8_t *txtmap;
    const char *binmap;
};

static const uint8_t base16txtmap[256] = {                             // ASCII characters
    IN, IN, IN, IN, IN, IN, IN, IN, IN, WS, WS, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    WS, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, IN, IN, IN, EQ, IN, IN,    // 0 1 2 3 4 5 6 7 8 9 . . . = . .
    IN, 10, 11, 12, 13, 14, 15, IN, IN, IN, IN, IN, IN, IN, IN, IN,    // @ A B C D E F G H I J K L M N O
    15, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,    // P Q R S T U V W X Y Z . . . . . .
    IN, 10, 11, 12, 13, 14, 15, IN, IN, IN, IN, IN, IN, IN, IN, IN,    // ` a b c d e f g h i j k l m n o
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN
};

static struct basecfg base16cfg = {
    .bits = 16,
    .wantpadding = 0,
    .txtmap = base16txtmap,
    .binmap = "0123456789abcdef",
};

static struct basecfg BASE16CFG = {
    .bits = 16,
    .wantpadding = 0,
    .txtmap = base16txtmap,
    .binmap = "0123456789ABCDEF",
};

static const uint8_t base32txtmap[256] = {
    IN, IN, IN, IN, IN, IN, IN, IN, IN, WS, WS, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    WS, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, 26, 27, 28, 29, 30, 31, IN, IN, IN, IN, IN, EQ, IN, IN,    // 0 1 2 3 4 5 6 7 8 9 . . . = . .
    IN,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,    // @ A B C D E F G H I J K L M N O
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, IN, IN, IN, IN, IN,    // P Q R S T U V W X Y Z . . . . .
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN
};

static struct basecfg base32cfg = {
    /* RFC-4648 */
    .bits = 32,
    .wantpadding = 0,
    .txtmap = base32txtmap,
    .binmap = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
};

static const uint8_t base32hextxtmap[256] = {
    IN, IN, IN, IN, IN, IN, IN, IN, IN, WS, WS, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    WS, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, IN, IN, IN, EQ, IN, IN,    // 0 1 2 3 4 5 6 7 8 9 . . . = . .
    IN, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,    // @ A B C D E F G H I J K L M N O
    25, 26, 27, 28, 29, 30, 31, IN, IN, IN, IN, IN, IN, IN, IN, IN,    // P Q R S T U V W X Y Z . . . . .
    IN, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,    // ` a b c d e f g h i j k l m n o
    25, 26, 27, 28, 29, 30, 31, IN, IN, IN, IN, IN, IN, IN, IN, IN,    // p q r s t u v w x y z . . . . .
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN
};

static struct basecfg base32hexcfg = {
    /* RFC 2938 */
    .bits = 32,
    .wantpadding = 0,
    .txtmap = base32hextxtmap,
    .binmap = "0123456789ABCDEFGHIJKLMNOPQRSTUV",
};

static const uint8_t base64txtmap[256] = {
    IN, IN, IN, IN, IN, IN, IN, IN, IN, WS, WS, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    WS, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, 62, IN, IN, IN, 63,    //   . . . . . . . . . . + . . . /
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, IN, IN, IN, EQ, IN, IN,    // 0 1 2 3 4 5 6 7 8 9 . . . = . .
    IN,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,    // @ A B C D E F G H I J K L M N O
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, IN, IN, IN, IN, IN,    // P Q R S T U V W X Y Z . . . . .
    IN, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,    // ` a b c d e f g h i j k l m n o
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, IN, IN, IN, IN, IN,    // p q r s t u v w x y z . . . . .
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN
};

static struct basecfg base64cfg = {
    /* RFC 3548 section 3 */
    .bits = 64,
    .wantpadding = 1,
    .txtmap = base64txtmap,
    .binmap = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
};

static const uint8_t base64urltxtmap[256] = {
    IN, IN, IN, IN, IN, IN, IN, IN, IN, WS, WS, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    WS, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, 62, IN, IN,    //   . . . . . . . . . . . . - . .
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, IN, IN, IN, EQ, IN, IN,    // 0 1 2 3 4 5 6 7 8 9 . . . = . .
    IN,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,    // @ A B C D E F G H I J K L M N O
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, IN, IN, IN, IN, 63,    // P Q R S T U V W X Y Z . . . . _
    IN, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,    // ` a b c d e f g h i j k l m n o
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, IN, IN, IN, IN, IN,    // p q r s t u v w x y z . . . . .
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
    IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN
};

static struct basecfg base64urlcfg = {
    /* RFC 3548 section 4 */
    .bits = 64,
    .wantpadding = 0,
    .txtmap = base64urltxtmap,
    .binmap = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
};

static const char *
encode(char *out, size_t *olen, const uint8_t *in, size_t *ilen, const struct basecfg *cfg)
{
    size_t maxilen, maxolen;
    unsigned bits, shval;
    uint32_t buf;

    for (shval = 1; shval < 8U && 1U << shval != cfg->bits; shval++)
        ;
    SXEA6(shval < 8, "Cannot find a shift value for %u bits", cfg->bits);
    SXEA6(strlen(cfg->binmap) == cfg->bits, "Invalid configured base%u binmap", cfg->bits);

    if (!*olen)
        return "Output overflow";

    if (!*ilen) {
        /* Early escape for zero-length input */
        out[0]='\0';
        *olen = 0;
        return NULL;
    }

    maxilen = *ilen;
    *ilen = 0;
    maxolen = *olen;
    *olen = 0;
    bits = 0;
    buf = 0;
    while (*ilen < maxilen) {
        buf <<= 8;
        buf |= in[(*ilen)++];
        bits += 8;

        while (bits >= shval) {
            if (*olen >= maxolen - 1)
                return "Output overflow";
            out[(*olen)++] = cfg->binmap[(buf >> (bits - shval)) & (cfg->bits - 1)];
            out[*olen] = '\0';
            bits -= shval;
        }
    }

    if (bits) {
        /* Push the remaining bits as high bits of an output char */
        if (*olen >= maxolen - 1)
            return "Output overflow";
        out[(*olen)++] = cfg->binmap[(buf << (shval - bits)) & (cfg->bits - 1)];
        out[*olen] = '\0';
        bits += 8 - shval;  /* emulate a read/write cycle */
    }

    if (cfg->wantpadding)
        while ((bits % 8) != 0) {
            if (*olen >= maxolen - 1)
                return "Output overflow";
            out[(*olen)++] = '=';
            out[*olen] = '\0';
            bits += 8 - shval;  /* emulate a read/write cycle */
        }

    return NULL;
}

static const char *
decode(uint8_t *out, size_t *olen, const char *in, size_t *ilen, unsigned flags, const struct basecfg *cfg)
{
    unsigned bits, done, padding, shval;
    size_t maxilen, maxolen;
    uint32_t buf;
    uint8_t c;

    for (shval = 1; shval < 8U && 1U << shval != cfg->bits; shval++)
        ;
    SXEA6(shval < 8, "Cannot find a shift value for %u bits", cfg->bits);

    bits = done = padding = 0;
    maxilen = *ilen;
    *ilen = 0;
    maxolen = *olen;
    *olen = 0;
    buf = 0;
    while (!done && *ilen < maxilen)
        switch (c = cfg->txtmap[(int)in[*ilen]]) {
        case WS:
            if (flags & KIT_BASE_DECODE_SKIP_WHITESPACE) {
                (*ilen)++;
                continue;
            }
            /* FALLTHRU */

        case IN:
            done = 1;
            break;

        case EQ:
            if (cfg->wantpadding) {
                if ((bits + padding) % 8 != 0) {
                    if (!padding && bits >= shval && bits < 8) {
                        done = 1;
                        break;
                    }
                    (*ilen)++;
                    padding += shval;
                }
                if ((bits + padding) % 8 == 0)
                    done = 1;
            } else
                done = 1;
            break;

        default:
            if (padding)
                done = 1;
            else {
                bits += shval;
                buf = (buf << shval) | c;
                (*ilen)++;
                if (bits >= 8) {
                    if (*olen >= maxolen)
                        return "Output overflow";
                    out[(*olen)++] = (buf >> (bits - 8)) & 255;
                    bits -= 8;
                }
            }
            break;
        }

    if ((bits + padding) % 8 != 0) {
        if (cfg->wantpadding)
            return "Padding characters missing";
        if (!padding && bits >= shval && bits < 8)
            (*ilen)--;    /* unshift that last worthless byte */
    }

    return NULL;    /* success (no error string) */
}

/* base16 conversion functions */

const char *
kit_base16encode(char *out, size_t *olen, const uint8_t *in, size_t *ilen)
{
    return encode(out, olen, in, ilen, &BASE16CFG);
}

const char *
kit_base16decode(uint8_t *out, size_t *olen, const char *in, size_t *ilen, unsigned flags)
{
    return decode(out, olen, in, ilen, flags, &base16cfg);
}

/* Because we don't have padding or skip white-space, provide an easier-to-use "hex' API */

size_t
kit_bin2hex(char *ohex, const uint8_t *ibin, size_t ilen, enum kit_bin2hex_fmt fmt)
{
    size_t olen;

    olen = ilen * 2 + 1;
    encode(ohex, &olen, ibin, &ilen, fmt == KIT_BIN2HEX_UPPER ? &BASE16CFG : &base16cfg);

    return olen;
}

size_t
kit_hex2bin(uint8_t *obin, const char *ihex, size_t ilen)
{
    size_t olen;

    olen = (ilen + 1) / 2;
    decode(obin, &olen, ihex, &ilen, KIT_BASE_DECODE_DEFAULT, &base16cfg);

    return olen;
}

/* base32 conversion functions */

const char *
kit_base32encode(char *out, size_t *olen, const uint8_t *in, size_t *ilen)
{
    return encode(out, olen, in, ilen, &base32cfg);
}

const char *
kit_base32decode(uint8_t *out, size_t *olen, const char *in, size_t *ilen, unsigned flags)
{
    return decode(out, olen, in, ilen, flags, &base32cfg);
}

/* base32hex conversion functions */

const char *
kit_base32hexencode(char *out, size_t *olen, const uint8_t *in, size_t *ilen)
{
    return encode(out, olen, in, ilen, &base32hexcfg);
}

const char *
kit_base32hexdecode(uint8_t *out, size_t *olen, const char *in, size_t *ilen, unsigned flags)
{
    return decode(out, olen, in, ilen, flags, &base32hexcfg);
}

/* base64 conversion functions */

const char *
kit_base64encode(char *out, size_t *olen, const uint8_t *in, size_t *ilen)
{
    return encode(out, olen, in, ilen, &base64cfg);
}

const char *
kit_base64decode(uint8_t *out, size_t *olen, const char *in, size_t *ilen, unsigned flags)
{
    return decode(out, olen, in, ilen, flags, &base64cfg);
}

const char *
kit_base64urlencode(char *out, size_t *olen, const uint8_t *in, size_t *ilen)
{
    return encode(out, olen, in, ilen, &base64urlcfg);
}

const char *
kit_base64urldecode(uint8_t *out, size_t *olen, const char *in, size_t *ilen)
{
    return decode(out, olen, in, ilen, KIT_BASE_DECODE_DEFAULT, &base64urlcfg);
}
