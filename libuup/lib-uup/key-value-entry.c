#include <arpa/inet.h>
#include <errno.h>
#include <kit-alloc.h>
#include <stdio.h>

#if __FreeBSD__
#include <sys/socket.h>
#endif

#include "cidrlist.h"
#include "dns-name.h"
#include "domainlist.h"
#include "key-value-entry.h"
#include "odns.h"
#include "parseline.h"
#include "pref-categories.h"

// This helper function is global because it's used by opendnscache specific optcfg functions
bool
key_value_text_to_longlong(struct key_value_source *ctx, void *var, const char *value, size_t value_len,    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                           const struct key_value_attrs *params, int base)
{
    char *end;

    *(long long *)var = kit_strtoll(value, &end, base);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    if (end != value + value_len || errno != 0) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL2("%s: %u: %s: Invalid value, must be %s", ctx->fn, ctx->lineno, ctx->key, base == 16 ? "hex" : base == 8 ? "octal" : "numeric");    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }
    if (*(long long *)var < params->arg1 || *(long long *)var > params->arg2) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL2("%s: %u: %s: Invalid value (%lld), must be between %lld and %lld", ctx->fn, ctx->lineno, ctx->key, *(long long *)var, params->arg1, params->arg2);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    return true;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

bool
key_value_text_to_uint8(struct key_value_source *ctx, void *var, const char *value, size_t value_len,    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                        const struct key_value_attrs *params)
{
    long long llvar;

    SXEA6(params->arg1 >= 0, "Cannot configure a negative minimum uint8 value");
    SXEA6(params->arg2 < 65536, "Cannot configure a maximum uint8 value >255");
    return key_value_text_to_longlong(ctx, &llvar, value, value_len, params, 0) ? (*(uint8_t *)var = llvar), true : false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_uint8_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v,    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                       const char *fmt, ...))
{
    cb(key, v, "%u", (unsigned)*(const uint8_t *)val);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

bool
key_value_text_to_unsigned(struct key_value_source *ctx, void *var, const char *value, size_t value_len, const struct key_value_attrs *params)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    long long llvar;

    SXEA6(params->arg1 >= 0, "Cannot configure a negative minimum unsigned value");
    SXEA6(params->arg2 > params->arg1, "Cannot configure a maximum unsigned value <minval");
    return key_value_text_to_longlong(ctx, &llvar, value, value_len, params, 0) ? (*(unsigned *)var = llvar), true : false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_unsigned_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    cb(key, v, "%u", *(const unsigned *)val);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

bool
key_value_text_to_uint16(struct key_value_source *ctx, void *var, const char *value, size_t value_len, const struct key_value_attrs *params)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    long long llvar;

    SXEA6(params->arg1 >= 0, "Cannot configure a negative minimum uint16 value");
    SXEA6(params->arg2 <= UINT16_MAX, "Cannot configure a maximum uint16 value >65535");
    return key_value_text_to_longlong(ctx, &llvar, value, value_len, params, 0) ? (*(uint16_t *)var = llvar), true : false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_uint16_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    cb(key, v, "%u", (unsigned)*(const uint16_t *)val);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

bool
key_value_text_to_uint32(struct key_value_source *ctx, void *var, const char *value, size_t value_len, const struct key_value_attrs *params)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    long long llvar;

    SXEA6(params->arg1 >= 0, "Cannot configure a negative minimum uint32 value");
    SXEA6((unsigned long)params->arg2 <= UINT32_MAX, "Cannot configure a maximum uint32 value >2^32");
    return key_value_text_to_longlong(ctx, &llvar, value, value_len, params, 0) ? (*(uint32_t *)var = llvar), true : false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_uint32_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    cb(key, v, "%lu", (unsigned long)*(const uint32_t *)val);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

bool
key_value_text_to_int(struct key_value_source *ctx, void *var, const char *value, size_t value_len, const struct key_value_attrs *params)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    long long llvar;

    return key_value_text_to_longlong(ctx, &llvar, value, value_len, params, 0) ? (*(int *)var = llvar), true : false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_int_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    cb(key, v, "%d", *(const int *)val);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

bool
key_value_text_to_hex(struct key_value_source *ctx, void *var, const char *value, size_t value_len, const struct key_value_attrs *params)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    long long llvar;

    if (value_len <= 2 || strncasecmp(value, "0x", 2) != 0) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL2("%s: %u: %s: Invalid value, must begin with '0x'", ctx->fn, ctx->lineno, ctx->key);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    return key_value_text_to_longlong(ctx, &llvar, value, value_len, params, 16) ? (*(unsigned *)var = llvar), true : false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_hex_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    cb(key, v, "0x%x", *(const unsigned *)val);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

bool
key_value_text_to_dnsname(struct key_value_source *ctx, void *var, const char *value, size_t value_len, const struct key_value_attrs *params)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    uint8_t dnsname[DNS_MAXLEN_NAME];

    SXE_UNUSED_PARAMETER(value_len);

    if (dns_name_sscan(value, WHITESPACE, dnsname) == NULL) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL2("%s: %u: %s: Invalid value, name too long", ctx->fn, ctx->lineno, ctx->key);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }
    if (*(uint8_t **)var != params->arg3)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        kit_free(*(uint8_t **)var);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    *(uint8_t **)var = dns_name_dup(dnsname);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    return true;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_dnsname_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    const uint8_t *name = *(const uint8_t *const *)val;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    char dnsname[DNS_MAXLEN_STRING + 1];    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    cb(key, v, "%s", name ? dns_name_to_buf(name, dnsname, sizeof(dnsname), NULL, DNS_NAME_DEFAULT) : "");    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

bool
key_value_text_to_ip(struct key_value_source *ctx, void *var, const char *value, size_t value_len, const struct key_value_attrs *params)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    char ipbuf[INET6_ADDRSTRLEN];

    SXEA6(params->arg1 == AF_INET || params->arg1 == AF_INET6, "Invalid arg1 param");
    snprintf(ipbuf, sizeof(ipbuf), "%.*s", (int)value_len, value);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    if (inet_pton(params->arg1, ipbuf, var) <= 0) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL2("%s: %u: %s: Invalid value", ctx->fn, ctx->lineno, ctx->key);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    return true;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_ip4_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    char ipbuf[INET_ADDRSTRLEN];

    cb(key, v, "%s", inet_ntop(AF_INET, val, ipbuf, sizeof(ipbuf)));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_ip6_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    char ipbuf[INET6_ADDRSTRLEN];

    cb(key, v, "%s", inet_ntop(AF_INET6, val, ipbuf, sizeof(ipbuf)));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

bool
key_value_text_to_encapip(struct key_value_source *ctx, void *var, const char *value, size_t value_len, const struct key_value_attrs *params)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    char ipbuf[INET6_ADDRSTRLEN];
    struct netaddr *a = var;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    bool result = true;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    /*-
     * params->arg1 is the allowable mode for this option.
     * params->arg3 is a pointer to the running program 'mode'.
     */
    if (*params->arg3 != params->arg1) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL2("%s: %u: %s: Not available in this mode", ctx->fn, ctx->lineno, ctx->key);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        result = false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    } else if (strncasecmp(value, "SOURCEIP", value_len) == 0) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        a->family = ODNS_AF_ENCAP_SOURCEIP;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEA6(a->family && a->family != AF_INET && a->family != AF_INET6, "Bad definition of ENCAP_SOURCEIP_AF (%d)", (int)a->family);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    } else {
        snprintf(ipbuf, sizeof(ipbuf), "%.*s", (int)value_len, value);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        result = netaddr_from_str(a, ipbuf, AF_INET) || netaddr_from_str(a, ipbuf, AF_INET6);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        if (!result)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            SXEL2("%s: %u: %s: Invalid value, Must be 'SOURCEIP' or a valid IP address", ctx->fn, ctx->lineno, ctx->key);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    return result;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_encapip_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    const struct netaddr *a = val;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    /*
     * For the non-encapsulating forwarder we don't want to show anything
     * when a->family is zero.
     *
     * For the encapsulating forwarder, we should really show an empty
     * string when a->family is zero.  That only happens if 'encapip' is
     * missing and was never in the options file... so this behaviour will
     * do for now - we don't have access to 'params', so we can't do it
     * properly!
     */
    if (a->family)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        cb(key, v, "%s", a->family == AF_INET6 + AF_INET ? "SOURCEIP" : netaddr_to_str(a));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

bool
key_value_text_to_ipport(struct key_value_source *ctx, void *var, const char *value, size_t value_len, const struct key_value_attrs *params)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    char ipbuf[INET6_ADDRSTRLEN + sizeof("[]:65535") - 1], *colon, *dot, *end;
    const char *ipstr, *portstr;
    sa_family_t family;
    unsigned long port;

    SXE_UNUSED_PARAMETER(params);

    if (value_len == 1 && *value == '-') {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        ((struct netsock *)var)->a.family = AF_UNSPEC;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return true;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    portstr = NULL;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    ipstr = ipbuf;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    snprintf(ipbuf, sizeof(ipbuf), "%.*s", (int)value_len, value);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    if (*ipbuf == '[' && (end = strchr(ipbuf, ']')) != NULL) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        family = AF_INET6;     /* IPv6 with [] */    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        ipstr++;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        *end = '\0';    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        if (end[1] == ':')    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            portstr = end + 2;    /* IPv6 with [] and port */    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    } else if ((colon = strchr(ipbuf, ':')) == NULL)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        family = AF_INET;     /* IPv4 */    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    else if ((dot = strchr(ipbuf, '.')) != NULL && dot < colon) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        family = AF_INET;     /* IPv4 + port */    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        *colon = '\0';    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        portstr = colon + 1;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    } else
        family = AF_INET6;    /* IPv6 */    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    if (inet_pton(family, ipstr, &((struct netsock *)var)->a.addr) <= 0) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL2("%s: %u: %s: Invalid address value", ctx->fn, ctx->lineno, ctx->key);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    if (portstr == NULL)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        port = 53;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    else if ((port = kit_strtoul(portstr, &end, 10)) == 0 || port > 65535 || end == portstr || *end || errno != 0) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL2("%s: %u: %s: Invalid port value", ctx->fn, ctx->lineno, ctx->key);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }
    ((struct netsock *)var)->port = htons(port);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    ((struct netsock *)var)->a.family = family;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    return true;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_ipport_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    char ipbuf[INET6_ADDRSTRLEN], pbuf[7];
    const struct netsock *n = val;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    cb(key, v, "%s%s%s%s",    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
       n->a.family == AF_INET6 ? "[" : "",    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
       n->a.family ? inet_ntop(n->a.family, &n->a.addr, ipbuf, sizeof(ipbuf)) : "",    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
       n->a.family == AF_INET6 ? "]" : "",    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
       n->a.family && ntohs(n->port) != 53 ? (snprintf(pbuf, sizeof(pbuf), ":%u", ntohs(n->port)), pbuf) : "");    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

bool
key_value_text_to_string(struct key_value_source *ctx, void *var, const char *value, size_t value_len, const struct key_value_attrs *params)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    char *word;

    SXEA6(params->arg1 >= 0, "Configured minlen must be >= 0");
    SXEA6(!params->arg2 || params->arg2 >= params->arg1, "Configured maxlen must be >= minlen");
    if (value_len < (size_t)params->arg1) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL3("%s: %u: %s: Must be at least %lld characters long", ctx->fn, ctx->lineno, ctx->key, params->arg1);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }
    if (params->arg2 && value_len > (size_t)params->arg2) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL3("%s: %u: %s: Must be at most %lld characters long", ctx->fn, ctx->lineno, ctx->key, params->arg2);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }
    if ((word = word_dup(value, value_len)) == NULL)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    if (*(const char **)var != params->arg4)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        kit_free(*(char **)var);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    *(char **)var = word;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    return true;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_string_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    cb(key, v, "%s", *(const char *const *)val ?: "");    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

bool
key_value_text_to_domainlist(struct key_value_source *ctx, void *var, const char *value, size_t value_len, const struct key_value_attrs *params)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    struct domainlist *dl;

    if (domainlist_sscan(value, "", params->arg1, &dl) < value + value_len) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL3("%s: %u: %s: Invalid domainlist", ctx->fn, ctx->lineno, ctx->key);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }
    domainlist_refcount_dec(*(struct domainlist **)var);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    *(struct domainlist **)var = dl;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    return true;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_domainlist_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    const char *end;
    char work[256];

    end = domainlist_to_buf(*(const struct domainlist *const *)val, work, sizeof(work) - strlen(key) - 5, NULL) ? "" : "...";    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    cb(key, v, "%s%s", work, end);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

bool
key_value_text_to_cidrlist(struct key_value_source *ctx, void *var, const char *value, size_t value_len, const struct key_value_attrs *params)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    enum cidr_parse how;
    const char     *consumed;

    SXE_UNUSED_PARAMETER(value_len);

    how = params->arg1 ? PARSE_IP_ONLY : PARSE_IP_OR_CIDR;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    cidrlist_refcount_dec(*(struct cidrlist **)var);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    if ((*(struct cidrlist **)var = cidrlist_new_from_string(value, ", \t\n", &consumed, NULL, how)) == NULL || (*consumed != '\0')) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL3("%s: %u: %s: trusted_networks_report_exclusions: Cannot parse %s data", ctx->fn, ctx->lineno, ctx->key, CIDR_PARSE_TXT(how));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    return true;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_cidrlist_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    char *cidrtxt;
    size_t sz;

    cidrtxt = alloca(sz = cidrlist_buf_size(*(const struct cidrlist *const *)val));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    cidrlist_to_buf(*(const struct cidrlist *const *)val, cidrtxt, sz, NULL);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    cb(key, v, "%s", cidrtxt);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

bool
key_value_text_to_categories(struct key_value_source *ctx, void *var, const char *value, size_t value_len, const struct key_value_attrs *params)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    pref_categories_t *cat = var;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    SXE_UNUSED_PARAMETER(params);

    if (pref_categories_sscan(cat, value) != value_len) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        SXEL2("%s: %u: %s: Invalid pref_categories value", ctx->fn, ctx->lineno, ctx->key);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return false;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    return true;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

void
key_value_categories_format(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    const pref_categories_t *const cat = val;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    cb(key, v, "%s", pref_categories_idstr(cat));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}
