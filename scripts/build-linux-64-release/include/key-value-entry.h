#ifndef KEY_VALUE_ENTRY_H
#define KEY_VALUE_ENTRY_H

#include <sxe-log.h>

#if __FreeBSD__
#include <inttypes.h>
#endif

// The source and key of an entry value being parsed
//
struct key_value_source {
    const char *fn;
    unsigned lineno;
    const char *key;
};

// Attributes of the entry value. These are type dependent and include things like maxima, minima, and default values.
//
struct key_value_attrs {
    long long arg1;
    long long arg2;
    uint8_t *arg3;
    char *arg4;
};

// Name and offset of the entry in the config, as well as functions to convert to and from its string format.
//
struct key_value_entry {
    const char *name;
    size_t offset;
    bool (*text_to_entry)(struct key_value_source *, void *, const char *, size_t, const struct key_value_attrs *);
    void (*entry_format)(const char *, const void *, void *, size_t (*)(const char *, void *, const char *, ...));
    const struct key_value_attrs params;
};

/*
 * Get the offset of a field within a struct options, asserting it's of the
 * given type.  Note, because C demotes arrays to pointers when they are
 * used in expressions or as args, we need to handle arrays specially :(
 */
#define TYPEDOFFSET(field, type, opttype) (&((opttype *)0)->field == ((type *)0 - 1) ? 0 : offsetof(opttype, field))
/* #define TYPEDARRAYOFFSET(field, type) (((struct options *)0)->field == ((type *)0 - 1) ? -1 : offsetof(struct options, field)) */

/*
 * These KEY_VALUE_ENTRY_*() macros are used to create struct key_value_entry initializers.
 *
 * The two functions in the macro are:
 * 1) Convert the text from options file and to config
 *     bool key_value_text_to_*(struct key_value_source *ctx, void *var, const char *value, size_t value_len, const struct key_value_attrs *params)
 * 2) Convert config back to text by calling a provided printf-like format function
 *     void key_value_*_to_str(const char *key, const void *val, void *v, __printflike(3, 4) size_t (*cb)(const char *key, void *v, const char *fmt, ...))
 */

#define KEY_VALUE_ENTRY_UINT8(type, field, minval, maxval) \
    { #field, TYPEDOFFSET(field, uint8_t, type), key_value_text_to_uint8, key_value_uint8_format, { minval, maxval, NULL, NULL } }
#define KEY_VALUE_ENTRY_UNSIGNED(type, field, minval, maxval) \
    { #field, TYPEDOFFSET(field, unsigned, type), key_value_text_to_unsigned, key_value_unsigned_format, { minval, maxval, NULL, NULL } }
#define KEY_VALUE_ENTRY_UINT16(type, field, minval, maxval) \
    { #field, TYPEDOFFSET(field, uint16_t, type), key_value_text_to_uint16, key_value_uint16_format, { minval, maxval, NULL, NULL } }
#define KEY_VALUE_ENTRY_UINT32(type, field, minval, maxval) \
    { #field, TYPEDOFFSET(field, uint32_t, type), key_value_text_to_uint32, key_value_uint32_format, { minval, maxval, NULL, NULL } }
#define KEY_VALUE_ENTRY_INT(type, field, minval, maxval) \
    { #field, TYPEDOFFSET(field, int, type), key_value_text_to_int, key_value_int_format, { minval, maxval, NULL, NULL } }
#define KEY_VALUE_ENTRY_UINT32_HEX(type, field, minval, maxval) \
    { #field, TYPEDOFFSET(field, uint32_t, type), key_value_text_to_hex, key_value_hex_format, { minval, maxval, NULL, NULL } }
#define KEY_VALUE_ENTRY_UINT64_HEX(type, field, minval, maxval) \
    { #field, TYPEDOFFSET(field, uint64_t, type), key_value_text_to_hex, key_value_hex_format, { minval, maxval, NULL, NULL } }
#define KEY_VALUE_ENTRY_DNSNAME(type, field, defname) \
    { #field, TYPEDOFFSET(field, uint8_t *, type), key_value_text_to_dnsname, key_value_dnsname_format, { 0, 0, defname, NULL } }
#define KEY_VALUE_ENTRY_IPV4(type, field) \
    { #field, TYPEDOFFSET(field, struct in_addr, type), key_value_text_to_ip, key_value_ip4_format, { AF_INET, 0, NULL, NULL } }
#define KEY_VALUE_ENTRY_IPV6(type, field) \
    { #field, TYPEDOFFSET(field, struct in6_addr, type), key_value_text_to_ip, key_value_ip6_format, { AF_INET6, 0, NULL, NULL } }
#define KEY_VALUE_ENTRY_ENCAPIP(type, field, okval, modeptr) \
    { #field, TYPEDOFFSET(field, struct netaddr, type), key_value_text_to_encapip, key_value_encapip_format, { (okval), 0, (modeptr), NULL } }
#define KEY_VALUE_ENTRY_IPPORT(type, field) \
    { #field, TYPEDOFFSET(field, struct netsock, type), key_value_text_to_ipport, key_value_ipport_format, { 0, 0, NULL, NULL } }
#define KEY_VALUE_ENTRY_STRING(type, field, defname) \
    { #field, TYPEDOFFSET(field, char *, type), key_value_text_to_string, key_value_string_format, { 0, 0, NULL, defname } }
#define KEY_VALUE_ENTRY_LIMITED_STRING(type, field, minlen, maxlen, defname) \
    { #field, TYPEDOFFSET(field, char *, type), key_value_text_to_string, key_value_string_format, { minlen, maxlen, NULL, defname } }
#define KEY_VALUE_ENTRY_DOMAINLIST(type, field) \
    { #field, TYPEDOFFSET(field, struct domainlist *, type), key_value_text_to_domainlist, key_value_domainlist_format, { LOADFLAGS_NONE, 0, NULL, NULL } }
#define KEY_VALUE_ENTRY_EXACT_DOMAINLIST(type, field) \
    { #field, TYPEDOFFSET(field, struct domainlist *, type), key_value_text_to_domainlist, key_value_domainlist_format, { LOADFLAGS_DL_EXACT, 0, NULL, NULL } }
#define KEY_VALUE_ENTRY_IPLIST(type, field) \
    { #field, TYPEDOFFSET(field, struct cidrlist *, type), key_value_text_to_cidrlist, key_value_cidrlist_format, { 1, 0, NULL, NULL } }
#define KEY_VALUE_ENTRY_CIDRLIST(type, field) \
    { #field, TYPEDOFFSET(field, struct cidrlist *, type), key_value_text_to_cidrlist, key_value_cidrlist_format, { 0, 0, NULL, NULL } }
#define KEY_VALUE_ENTRY_CATEGORIES(type, field) \
    { #field, TYPEDOFFSET(field, pref_categories_t, type), key_value_text_to_categories, key_value_categories_format, { 0, 0, NULL, NULL } }

#include "key-value-entry-proto.h"

#endif
