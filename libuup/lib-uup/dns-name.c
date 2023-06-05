#include <ctype.h>
#include <kit-alloc.h>
#include <murmurhash3.h>
#include <sxe-util.h>
#include <sys/param.h>

#include "dns-name.h"

const uint8_t dns_tolower[256] = {
      0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
     10,  11,  12,  13,  14,  15,  16,  17,  18,  19,
     20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
     30,  31,  32,  33,  34,  35,  36,  37,  38,  39,
     40,  41,  42,  43,  44,  45,  46,  47,  48,  49,
     50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
     60,  61,  62,  63,  64, 'a', 'b', 'c', 'd', 'e',
    'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
    'z',  91,  92,  93,  94,  95,  96,  97,  98,  99,
    100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
    110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
    120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
    130, 131, 132, 133, 134, 135, 136, 137, 138, 139,
    140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
    150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
    160, 161, 162, 163, 164, 165, 166, 167, 168, 169,
    170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
    180, 181, 182, 183, 184, 185, 186, 187, 188, 189,
    190, 191, 192, 193, 194, 195, 196, 197, 198, 199,
    200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
    210, 211, 212, 213, 214, 215, 216, 217, 218, 219,
    220, 221, 222, 223, 224, 225, 226, 227, 228, 229,
    230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249,
    250, 251, 252, 253, 254, 255
};

const uint8_t dns_tohost[256] = {
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0, '-', '.',   0, '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9',   0,   0,
      0,   0,   0,   0,   0, 'a', 'b', 'c', 'd', 'e',
    'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
    'z',   0,   0,   0,   0, '_',   0, 'a', 'b', 'c',
    'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z',   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0
};

static int
dns_label_cmp(const uint8_t *name1, const uint8_t *name2)
{
    /* Record the label lengths to use as the last comparison */
    int len1 = *name1++;
    int len2 = *name2++;
    int result;

    /* Now actually compare the labels themselves, uchar by uchar */
    for (int label_len = MIN(len1, len2); label_len > 0; label_len--)
        if ((result = dns_tolower[*name1++] - dns_tolower[*name2++]) != 0)
            return result;

    /* If we got here we had labels matching, verify that we don't have a substring match */
    return len1 - len2;
}

int
dns_name_cmp(const uint8_t *name1, const uint8_t *name2)
{
    int label_len = 0;

    while (dns_tolower[*name1] == dns_tolower[*name2]) {
        if (label_len-- == 0 && (label_len = *name1) == 0)
            break;
        name1++;
        name2++;
    }

    return dns_tolower[*name1] - dns_tolower[*name2];
}

/**
 * @return true if name1 equals name2, using a fast case flattened but non-canonical comparison
 */
bool
dns_name_equal(const uint8_t *dn1, const uint8_t *dn2)
{
    return !dns_name_cmp(dn1, dn2);
}

int
dns_name_canoncmp(const uint8_t *name0, const uint8_t *name1)
{
    struct {
        uint16_t pos[DNS_MAX_LABEL_CNT];
        int idx;
    } lab[2];
    const uint8_t *name;
    int i, pos, result;

    /* Get label offsets */
    for (i = 0; i < 2; i++) {
        name = i ? name1 : name0;
        for (pos = lab[i].idx = 0; name[pos] && lab[i].idx < DNS_MAX_LABEL_CNT; pos += 1 + name[pos])
            lab[i].pos[lab[i].idx++] = pos;
    }

    /* Compare the labels from the end to the start */
    for (result = 0; lab[0].idx && lab[1].idx; )
        if ((result = dns_label_cmp(name0 + lab[0].pos[--lab[0].idx], name1 + lab[1].pos[--lab[1].idx])))
            return result;

    return lab[0].idx - lab[1].idx;
}

bool
dns_name_has_prefix(const uint8_t *name, const uint8_t *prefix)
{
    int label_len;

    for (label_len = 0; dns_tolower[*name] == dns_tolower[*prefix]; name++, prefix++)
        if (label_len-- == 0 && (label_len = *prefix) == 0)
            return true;
    return label_len == 0 && *prefix == 0;
}

uint8_t *
dns_name_dup(const uint8_t *name)
{
    int len = dns_name_len(name);
    uint8_t *name_dup;

    SXEA1(name_dup = kit_malloc(len), "Failed to allocate %d bytes for DNS name", len);
    memcpy(name_dup, name, len);
    return name_dup;
}

const uint8_t *
dns_name_label(const uint8_t *name, unsigned labels_to_skip)
{
    while (labels_to_skip-- > 0 && *name != 0)
        name += *name + 1;
    return name;
}

unsigned
dns_name_len(const uint8_t *name)
{
    unsigned i = 0;

    while (name[i] != 0)
        i += name[i] + 1;

    SXEA6(i < DNS_MAXLEN_NAME, "Got dns_name_len() %u", i + 1);
    return i + 1;
}

int
dns_name_to_lower(uint8_t *dst, const uint8_t *name)
{
    uint8_t i, *p;

    p = dst;
    while ((i = *p++ = *name++))
        for (; i--; p++, name++)
            *p = dns_tolower[*name];

    return p - dst;
}

/* Maps "\1x\7opendns\3com\0" to "\0com\3opendns\7x\1" */
void
dns_name_prefixtreekey(uint8_t *dst, const uint8_t *name, int len)
{
    uint8_t *p;
    int i;

    SXEA6((i = dns_name_len(name)) == len, "Bogus len, got %d not %d", len, i);
    p = dst + len - 1;
    while ((*p = *name)) {
        p -= *name + 1;
        for (i = 1; i <= *name; i++)
            p[i] = dns_tolower[name[i]];
        name += *name + 1;
    }
    SXEA6(p == dst, "Oops, botched key generation - out by %zd", dst - p);
}

/*-
 * Maps "\0com\3opendns\7x\1" to "x.opendns.com"
 * Maps "\0" to ""
 */
const char *
prefixtreekey_txt(const uint8_t *key, int len)
{
    static __thread char txt[DNS_MAXLEN_STRING + 1];
    char *dst;
    int llen;

    SXEA6(len < (int)sizeof(txt), "prefixtreekey too long");
    SXEA6(len > 0, "prefixtreekey too short");
    SXEA6(len != 2, "prefixtreekey length 2 is unexpected");
    SXEA6(!*key, "prefixtree key must always begin with \\0");
    for (dst = txt; len; dst += llen) {
        llen = key[--len];
        len -= llen;
        if (llen) {
            if (dst != txt)
                *dst++ = '.';
            memcpy(dst, key + len, llen);
        }
    }
    *dst = '\0';

    return txt;
}

/**
 * Prepend a numeric label to a DNS name if the number is non-zero
 *
 * @return The original name if number is 0, the buffer containing the prefixed name, or NULL on buffer overflow.
 */
const uint8_t *
dns_name_prefix_unsigned(const uint8_t *name, unsigned number, uint8_t buffer[DNS_MAXLEN_NAME])
{
    if (number == 0)
        return name;

    buffer[0]         = snprintf((char *)buffer + 1, DNS_MAXLEN_NAME - 1, "%u", number);
    unsigned name_len = dns_name_len(name);

    if (buffer[0] + name_len < DNS_MAXLEN_NAME) {
        memcpy(buffer + buffer[0] + 1, name, name_len);
        return buffer;
    }

    return NULL;
}

/**
 * Convert a DNS name to a string, returning the buffer pointer or NULL if the DNS name is invalid.
 *
 * @param len_out If not NULL, points to a size_t set to the length of the string representation of name excluding '\0'
 */
char *
dns_name_to_buf(const uint8_t *name, char *buf, size_t size, size_t *len_out, unsigned flags)
{
    int label_len;
    char *p;

    SXE_UNUSED_PARAMETER(size);
    SXEA6(name != NULL, "The printed name must be non-NULL");
    SXEA6(size > DNS_MAXLEN_STRING, "The buffer must be big enough for the worst case");

    for (p = buf; *name;) {
        label_len = *name++;

        if (p != buf)
            *p++ = '.';

        if (p + label_len + 1 - buf >= DNS_MAXLEN_NAME) {
            strcpy(buf, "?");
            return NULL;
        }

        for (; label_len--; p++, name++)
            *p = (flags & DNS_NAME_TOLOWER) && *name >= 'A' && *name <= 'Z' ? *name + 'a' - 'A' :
                 *name == '.' || *name <= ' ' || *name >= '~' ? '?' : *name;
    }

    if (p == buf)
        *p++ = '.';

    if (len_out)
        *len_out = p - buf;

    *p = '\0';
    SXEA6(p - buf <= DNS_MAXLEN_STRING, "Return %zu - too big", p - buf);
    return buf;
}

const char *
dns_name_to_str1(const uint8_t *name)
{
    static __thread char buf[DNS_MAXLEN_STRING + 1];

    dns_name_to_buf(name, buf, sizeof(buf), NULL, DNS_NAME_DEFAULT);
    return buf;
}

const char *
dns_name_to_str2(const uint8_t *name)
{
    static __thread char buf[DNS_MAXLEN_STRING + 1];

    dns_name_to_buf(name, buf, sizeof(buf), NULL, DNS_NAME_DEFAULT);
    return buf;
}

const char *
dns_name_sscan_len(const char *str, const char *delim, uint8_t *name, unsigned *name_len)
{
    unsigned namesz = *name_len < DNS_MAXLEN_NAME ? *name_len : DNS_MAXLEN_NAME;
    int dch, i, label_len;
    uint8_t *label;

    label = name;
    for (*name_len = 0, label_len = i = 0; str[i] != 0 && strchr(delim, str[i]) == NULL; i++) {
        if (++*name_len > namesz)
            return NULL;

        if (str[i] == '.') {
            if (i) {
                if (!label_len)
                    return NULL;
                label[0] = label_len;
                label += 1 + label_len;
                label_len = 0;
            } else if (str[1] && strchr(delim, str[1]) == NULL)
                return NULL;
        } else if (++label_len > DNS_MAXLEN_LABEL)
            return NULL;
        else if (!i && ++*name_len > namesz)
            return NULL;
        else if (str[i] == '\\') {
            if (isdigit(str[i+1]) && isdigit(str[i+2]) && isdigit(str[i+3])
             && (dch = (int)(str[i + 1] - '0') * 100 + (int)(str[i + 2] - '0') * 10 + str[i + 3] - '0') <= 255) {
                label[label_len] = dch;
                i += 3;
            } else
                label[label_len] = str[++i];
        } else
            label[label_len] = str[i];
    }

    if (!*name_len)
        return NULL;

    label[0] = label_len;
    if (label_len) {
        if (*name_len + 1 > namesz)
            return NULL;

        name[(*name_len)++] = 0;
    }

    return str + i;
}

/*
 * Returns a pointer into NAME to the Nth subdomain of SUPER, or NULL
 * if NAME is not a subdomain of SUPER.
 */
const uint8_t *
dns_name_subdomain(const uint8_t *name, const uint8_t *super, unsigned n)
{
    const uint8_t *result = NULL;
    unsigned i, labels_to_skip, name_labels, super_labels;

    SXEE6("(name=%s, super=%s, n=%u)", dns_name_to_str1(name), dns_name_to_str2(super), n);

    name_labels = 1;
    for (i = 0; name[i] != 0; i += name[i] + 1)
        name_labels++;
    super_labels = 1;
    for (i = 0; super[i] != 0; i += super[i] + 1)
        super_labels++;
    if (name_labels < super_labels
     || (labels_to_skip = name_labels - super_labels) < n
     || !dns_name_equal(dns_name_label(name, labels_to_skip), super))
        goto SXE_EARLY_OUT;

    result = dns_name_label(name, labels_to_skip - n);

SXE_EARLY_OUT:
    SXER6("return %.*s%s", result ? result[0] : 4, result ? (const char *)result + 1 : "NULL", result ? "" : " // not a subdomain");
    return result;
}

bool
dns_name_suffix(const uint8_t *name, const uint8_t *suffix)
{
    int i = 0;
    int name_len = dns_name_len(name);
    int suffix_len = dns_name_len(suffix);

    /* Trim labels from NAME until its length is no greater than that of SUFFIX */
    while (name_len - i > suffix_len)
        i += name[i] + 1;
    return dns_name_equal(&name[i], suffix);
}

/**
 * Add an additional label to a domain name.
 *
 * @param name      Full domain
 * @param ancestor  Ancestor or 'name' to add a label to
 * @return          Subdomain of 'ancestor' with one additional label from 'name'
 *                  added to 'ancestor', or NULL if 'parent' matches 'name'.
 */
const uint8_t *
dns_name_ancestor_subdomain(const uint8_t *name, const uint8_t *ancestor)
{
    const uint8_t *prev;

    SXEA6(((ancestor >= name) && (ancestor + dns_name_len(ancestor) == name + dns_name_len(name))) || !*ancestor,
          "dns_name_ancestor_subdomain was called with ancestor that is not a part of name");

    /* In case ancestor is DNS_NAME_ROOT (see query_set_control()), the last label should be returned */
    for (prev = NULL; (*name != 0) && (!*ancestor || name < ancestor); name += 1 + *name) {
        prev = name;
    }

    return prev;
}

/*-
 * @return offset of suffix 'little' in 'big' or -1 if it isn't a suffix of 'big'
 */
int
dns_name_endswith(const uint8_t *big, const uint8_t *little)
{
    const uint8_t *orig = big;
    uint8_t c;

    for (;;) {
        if (dns_name_equal(big, little))
            return (int)(big - orig);
        c = *big++;
        if (!c)
            return -1;
        big += c;
    }
}

unsigned
dns_label_count(const uint8_t *name, uint8_t *longest)
{
    unsigned count, i;

    if (longest)
        *longest = 0;

    for (count = i = 0; name[i]; i += name[i] + 1, count++)
        if (longest && *longest < name[i])
            *longest = name[i];

    return count;
}

uint32_t
dns_name_hash32(const uint8_t *name)
{
    const uint32_t seed = 91099104;
    return murmur3_32(name, dns_name_len(name), seed);
}

uint32_t
dns_label_hash32(const uint8_t *label)
{
    const uint32_t seed = 91138730;
    return murmur3_32(label + 1, *label, seed);
}

uint32_t
dns_name_fingerprint_bit(const uint8_t *name)
{
    return (uint8_t)1 << (dns_name_hash32(name) % 32);
}

uint8_t
dns_label_fingerprint_bit7(const uint8_t *label)
{
    return (uint8_t)1 << (dns_label_hash32(label) % 7);
}
