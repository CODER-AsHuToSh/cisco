#include <arpa/inet.h>
#include <kit-alloc.h>
#include <stdio.h>

#if __FreeBSD__
#include <sys/socket.h>
#include <sys/types.h>
#endif

#include "odns.h"
#include "unaligned.h"

/* Fixed EDNS data */
static const struct odns_hdr default_odns_hdr  = {
    .magic   = ODNS_MAGIC,
    .version = ODNS_VERSION_1BYTE_FIELDTYPE,
    .flags   = 0
};

const char *
odns_host_id_to_str(struct odns *odns)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    static __thread char str[KIT_GUID_STR_LEN + 1];

    return kit_guid_to_buf(&odns->host_id, str, sizeof(str));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

const char *
odns_user_id_to_str(struct odns *odns)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    static __thread char str[KIT_GUID_STR_LEN + 1];

    return kit_guid_to_buf(&odns->user_id, str, sizeof(str));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

const char *
odns_device_id_to_str(struct odns *odns)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    static __thread char str[KIT_DEVICEID_STR_LEN + 1];

    if (odns->fields & ODNS_FIELD_DEVICE)                                  /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return kit_deviceid_to_buf(&odns->device_id, str, sizeof(str));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    else
        return "-";    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

const char *
odns_content(struct odns *odns)
{
    static __thread char buf[512];
    char ipbuf[INET6_ADDRSTRLEN];
    int avail, blen, got;

#define APPEND(flag, fmt, ...)                                                                               \
    if (odns->fields & (flag) && (got = snprintf(buf + blen, avail, fmt, __VA_ARGS__)) < avail && got > 0) { \
        blen += got;                                                                                         \
        avail -= got;                                                                                        \
    }

    blen = 0;

    if (odns->fields) {
        avail = sizeof(buf);
        APPEND(odns->fields, "flags=0x%x fields=0x%x", odns->flags, odns->fields);
        APPEND(ODNS_FIELD_ORG, " org=%" PRIu32, odns->org_id);
        APPEND(ODNS_FIELD_VA, " va=%" PRIu32, odns->va_id);
        APPEND(ODNS_FIELD_HOST, " host=%s", kit_guid_to_str(&odns->host_id));
        APPEND(ODNS_FIELD_USER, " user=%s", kit_guid_to_str(&odns->user_id));
        if (odns->alt_user_id_type == 'H')
            APPEND(ODNS_FIELD_ALT_UID, " altuid=%s", kit_md5_to_str(&odns->alt_user_id));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        APPEND(ODNS_FIELD_REMOTEIP, " remoteip=%s", inet_ntop(odns->remoteip.family, &odns->remoteip.addr, ipbuf, sizeof(ipbuf)));
        APPEND(ODNS_FIELD_CLIENTIP, " clientip=%s", inet_ntop(odns->clientip.family, &odns->clientip.addr, ipbuf, sizeof(ipbuf)));
        APPEND(ODNS_FIELD_POLICYTYPE, " policytype=%s", odns->policytype == ODNS_POLICYTYPE_SWG ? "SWG" : "DNS");
        APPEND(ODNS_FIELD_DEVICE, " device=%s", kit_deviceid_to_str(&odns->device_id));
        APPEND(ODNS_FIELD_CLIENTREPORTINGID, " client-reporting-id=%s", odns_client_reporting_id_to_str(odns, false));
        APPEND(ODNS_FIELD_ORIGIN, " origin=%" PRIu32, odns->origin_id);
        APPEND(ODNS_FIELD_ENCAP_PACKET, " %s", "ENCAP");
    }

    buf[blen] = '\0';
    return buf;
}

/*
 * Initialize the ODNS structure for an active directory (AD) request
 *
 * @param me           ODNS structure to initialize
 * @param clientaddr   Address of the client that sent the message
 * @param org_id       Org id or 0 if none
 * @param asset_id     Asset id or 0 if none
 * @param ad_user_id   Pointer to the active directory user GUID or NULL if there is none
 * @param ad_host_id   Pointer to the active directory host GUID or NULL if there is none
 * @param ad_device_id Pointer to the active directory device id or NULL if there is none
 */
void
odns_init(struct odns *me, const struct netaddr *clientaddr, uint32_t org_id, uint32_t asset_id,
          const struct kit_guid *ad_user_id, const struct kit_guid *ad_host_id, const struct kit_deviceid *ad_device_id)
{
    char buf[KIT_GUID_STR_LEN + 1];

    SXEE7("(me=%p, clientaddr=%s)", me, netaddr_to_str(clientaddr));

    /* Set the forwarder fields that are available */

    if (org_id) {
        me->fields |= ODNS_FIELD_ORG;
        me->org_id = org_id;
    }

    if (asset_id) {
        me->fields |= ODNS_FIELD_VA;
        me->va_id = asset_id;
    }

    if (ad_host_id) {
        me->fields |= ODNS_FIELD_HOST;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        me->host_id = *ad_host_id;        /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    if (ad_user_id) {
        me->fields |= ODNS_FIELD_USER;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        me->user_id = *ad_user_id;        /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }
    else
        me->internal_flags |= ODNS_INTERNAL_FLAG_GUEST;

    if (ad_device_id) {
        me->fields |= ODNS_FIELD_DEVICE;                                    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        unaligned_memcpy(&me->device_id, ad_device_id, ODNS_LEN_DEVICE);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    me->remoteip.family = AF_UNSPEC;

    switch (clientaddr->family) {
    case AF_INET:
        me->fields |= ODNS_FIELD_REMOTEIP4;
        me->fields &= ~ODNS_FIELD_REMOTEIP6;
        me->remoteip.family = AF_INET;
        me->remoteip.in_addr = clientaddr->in_addr;
        break;

    case AF_INET6:                                        /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        me->fields |= ODNS_FIELD_REMOTEIP6;               /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        me->fields &= ~ODNS_FIELD_REMOTEIP4;              /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        me->remoteip.family = AF_INET6;                   /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        me->remoteip.in6_addr = clientaddr->in6_addr;     /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        break;                                            /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    snprintf(buf, sizeof(buf), "%s", ad_host_id ? kit_guid_to_str(ad_host_id) : "none");
    SXER7("return, org_id=0x%x va_id=0x%x host_id=%s user_id=%s remoteip=%s",
          org_id, asset_id, buf, ad_user_id ? kit_guid_to_str(ad_user_id) : "none",
          me->fields & ODNS_FIELD_REMOTEIP ? netaddr_to_str(clientaddr) : "none");
}

uint16_t
odns_get_formatted_size(struct odns *odns)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    uint16_t opt_length;

    /* Calculate the total EDNS data size */
    opt_length = sizeof(default_odns_hdr);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    if (odns->fields & ODNS_FIELD_ORG)             /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_length += 1 + sizeof(odns->org_id);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    if (odns->fields & ODNS_FIELD_VA)             /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_length += 1 + sizeof(odns->va_id);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    if (odns->fields & ODNS_FIELD_HOST)     /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_length += 1 + ODNS_LEN_HOST;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    if (odns->fields & ODNS_FIELD_USER)     /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_length += 1 + ODNS_LEN_USER;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    if (odns->fields & ODNS_FIELD_REMOTEIP4)     /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_length += 1 + ODNS_LEN_REMOTEIP4;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    if (odns->fields & ODNS_FIELD_REMOTEIP6)     /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_length += 1 + ODNS_LEN_REMOTEIP6;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    if (odns->fields & ODNS_FIELD_DEVICE)     /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_length += 1 + ODNS_LEN_DEVICE;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    SXEA6(opt_length <= ODNS_MAX_LEN, "opt_length (%u) is greater than the maximum (%zu)", opt_length, ODNS_MAX_LEN);
    return opt_length;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

/*
 * Add the ODNS to a forwarder's EDNS message to a query, using 'default_odns_hdr' and the fields set in the odns structure.
 */
uint8_t *
odns_format(struct odns *odns, uint16_t opt_length, uint8_t *opt_out)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    uint8_t *opt_ptr = opt_out;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    SXE_UNUSED_PARAMETER(opt_length);    // Only used in debug build

    SXEE7("(odns=%p, opt_length=%hu, opt_out=%p) // odns->fields=0x%x", odns, opt_length, opt_out, odns->fields);
    memcpy(opt_ptr, &default_odns_hdr, sizeof(default_odns_hdr));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    opt_ptr += sizeof(default_odns_hdr);                             /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    /* Add all available IDs */
    if (odns->fields & ODNS_FIELD_ORG) {                         /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr[0] = ODNS_FIELD_ORG;                             /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr = unaligned_htonl(opt_ptr + 1, odns->org_id);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    if (odns->fields & ODNS_FIELD_VA) {                         /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr[0] = ODNS_FIELD_VA;                             /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr = unaligned_htonl(opt_ptr + 1, odns->va_id);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    if (odns->fields & ODNS_FIELD_HOST) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr[0] = ODNS_FIELD_HOST;        /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr = unaligned_memcpy(&opt_ptr[1], &odns->host_id, ODNS_LEN_HOST);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    if (odns->fields & ODNS_FIELD_USER) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr[0] = ODNS_FIELD_USER;        /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr = unaligned_memcpy(&opt_ptr[1], &odns->user_id, ODNS_LEN_USER);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    if (odns->fields & ODNS_FIELD_REMOTEIP4) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr[0] = ODNS_FIELD_REMOTEIP4;        /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr = unaligned_memcpy(&opt_ptr[1], &odns->remoteip.in_addr, ODNS_LEN_REMOTEIP4);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    if (odns->fields & ODNS_FIELD_REMOTEIP6) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr[0] = ODNS_FIELD_REMOTEIP6;        /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr = unaligned_memcpy(&opt_ptr[1], &odns->remoteip.in6_addr, ODNS_LEN_REMOTEIP6);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    if (odns->fields & ODNS_FIELD_DEVICE) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr[0] = ODNS_FIELD_DEVICE;        /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr = unaligned_memcpy(&opt_ptr[1], &odns->device_id, ODNS_LEN_DEVICE);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    SXEA6(opt_ptr - opt_out <= opt_length, "Build message length %zu exceeds buffer length %hu", (size_t)(opt_ptr - opt_out),
          opt_length);

    SXER7("return %p; // opt_len=%zu", opt_ptr, (size_t)(opt_ptr - opt_out));
    return opt_ptr;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

uint8_t *
odns_serialize(const struct odns *me, uint8_t *opt_ptr)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    struct odns_hdr *hdr = (struct odns_hdr *)opt_ptr;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    memcpy(hdr, &default_odns_hdr, sizeof(default_odns_hdr));    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    hdr->version = ODNS_VERSION_2BYTE_FIELDTYPE;                 /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    opt_ptr += sizeof(default_odns_hdr);                         /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    /* Add the Encapsulation IP's */
    if (me->fields & ODNS_FIELD_CLIENTIP4) {                         /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr = unaligned_htons(opt_ptr, ODNS_FIELD_CLIENTIP4);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr = unaligned_memcpy(opt_ptr, &me->clientip.in_addr, ODNS_LEN_CLIENTIP4);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    if (me->fields & ODNS_FIELD_CLIENTIP6) {                         /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr = unaligned_htons(opt_ptr, ODNS_FIELD_CLIENTIP6);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        opt_ptr = unaligned_memcpy(opt_ptr, &me->clientip.in6_addr, ODNS_LEN_CLIENTIP6);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    opt_ptr = unaligned_htons(opt_ptr, me->fields & ODNS_FIELD_REMOTEIP);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    opt_ptr = unaligned_memcpy(opt_ptr, &me->remoteip.addr,                  /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
                               me->fields & ODNS_FIELD_REMOTEIP6 ? ODNS_LEN_REMOTEIP6 : ODNS_LEN_REMOTEIP4);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    return opt_ptr;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}

const char *
odns_client_reporting_id_to_str(struct odns *odns, bool for_querylog)    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
{
    static __thread char str[ODNS_MAXLEN_CLIENTREPORTINGID * 2 + 2];  /* TTTT:<63*2 bytes>\0 */
    uint64_t imsi;
    uint16_t type;
    uint8_t len;

    if (odns == NULL || !(odns->fields & ODNS_FIELD_CLIENTREPORTINGID)) {    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        snprintf(str, sizeof(str), "-");                                     /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
        return str;                                                          /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    SXEA6(odns->clientreportingid != NULL, "Flags say client-reporting-id is there, but it's not!");
    len = *odns->clientreportingid;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    SXEA6(len >= ODNS_MINLEN_CLIENTREPORTINGID - 1 && len < ODNS_MAXLEN_CLIENTREPORTINGID, "Unexpected client-reporting-id len %u", len);
    type = unaligned_ntohs(odns->clientreportingid + 1);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    if (!for_querylog                                                /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
     && type == ODNS_CLIENTREPORTINGID_TYPE_IMSI                     /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
     && len == (2 + sizeof(imsi))) {                                 /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            imsi = unaligned_ntohll(odns->clientreportingid + 3);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            snprintf(str, sizeof(str), "IMSI:%" PRIu64, imsi);       /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
            return str;                                              /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    }

    kit_bin2hex(str, odns->clientreportingid + 1, 2, KIT_BIN2HEX_UPPER);   /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    str[4] = ':';                                                          /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
    kit_bin2hex(str + 5, odns->clientreportingid + 3, len - 2, KIT_BIN2HEX_UPPER);    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */

    return str;    /* COVERAGE EXCLUSION: Was covered by opendnscache tests */
}
