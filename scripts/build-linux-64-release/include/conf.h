#ifndef CONF_H
#define CONF_H

#include <limits.h>
#include <sys/time.h>
#include <time.h>

#include "conf-info.h"
#include "conf-worker.h"

#define CONF_DEFAULT_LASTGOOD_COMPRESSION 3       // By default, last good files are compressed at level 3
#define CONF_DEFAULT_WORKER_COUNT         0       // By default, no worker threads are spawned
#define LOADFLAGS_NONE                    0x00    // Loadflags are type-specific - search LOADFLAGS_ elsewhere

struct conf;
struct conf_loader;
struct conf_segment;

struct conf_type {
    const char *name;
    struct conf *(*allocate)(const struct conf_info *, struct conf_loader *);
    void (*free)(struct conf *);
};

struct conf_segment_ops {
    struct conf *(*clone)(struct conf *obase);
    time_t (*settimeatleast)(struct conf *base, time_t t);
    unsigned (*id2slot)(const struct conf *base, uint32_t id);
    const struct conf_segment *(*slot2segment)(const struct conf *base, unsigned slot);
    bool (*slotisempty)(const struct conf *base, unsigned slot);
    void (*slotfailedload)(struct conf *base, unsigned slot, bool value);
    void (*freeslot)(struct conf *base, unsigned slot);
    void *(*newsegment)(uint32_t id, struct conf_loader *cl, const struct conf_info *info);
    void (*freesegment)(void *seg);
    bool (*usesegment)(struct conf *base, void *seg, unsigned slot, uint64_t *alloc);
    void (*loaded)(struct conf *base);
};

struct conf {                                 /* An abstraction for all config files */
    const struct conf_type *type;             /* Data type associated with this file */
    int refcount;                             /* # references */
};

struct confset;                               /* An in-use conf file set */
typedef unsigned module_conf_t;               /* A confset's conf[] index plus 1 */

enum confset_free_method {
    CONFSET_FREE_DISPATCH,                    /* Dispatch free jobs to conf-workers */
    CONFSET_FREE_IMMEDIATE,                   /* Call free immediately */
};

struct conf_registrar {
    unsigned max, num;
    module_conf_t *m;
};

#define CONF_LOAD_REPORT_ADDR 0xd043dedc      /* 208.67.222.220 */
#define CONF_LOAD_REPORT_PORT 53

#if __FreeBSD__
#define __bswap_constant_32 htonl
#define __bswap_constant_16 htons
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define CONF_DEFAULT_REPORT_SERVER { \
    .a = { .in_addr = { .s_addr = __bswap_constant_32(CONF_LOAD_REPORT_ADDR) }, .family = AF_INET }, \
    .port = __bswap_constant_16(CONF_LOAD_REPORT_PORT) \
}
#else
#define CONF_DEFAULT_REPORT_SERVER { \
    .a = { .in_addr = { .s_addr = CONF_LOAD_REPORT_ADDR }, .family = AF_INET }, \
    .port = CONF_LOAD_REPORT_PORT }, \
}
#endif

#define CONF_REFCOUNT_DEC(super) do { if (super) conf_refcount_dec(&(super)->conf, CONFSET_FREE_IMMEDIATE); } while (0)
#define CONF_REFCOUNT_INC(super) conf_refcount_inc(&(super)->conf)

#define CONF_LOAD_REPORT_SUFFIX  (const uint8_t *)"\4load\4conf\7opendns\3com"

#include "conf-proto.h"

#endif
