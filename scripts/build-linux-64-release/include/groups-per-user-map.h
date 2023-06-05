/* Copied from: https://github.office.opendns.com/cdfw/firewall/blob/multi-tenant/src/groups-per-user-map.h
 */

#ifndef __GROUPS_PER_USER_MAP_H__
#define __GROUPS_PER_USER_MAP_H__

#include "conf-loader.h"
#include "conf-segment.h"
#include "object-hash.h"

typedef struct groups_per_user_t {
    uint32_t  user_id;
    size_t    size;
    size_t    count;
    uint32_t *groups;
    struct    groups_per_user_t *next;
} groups_per_user_t;

typedef struct groups_per_user_map {
    struct conf_segment cs;
    size_t              gpu_width;
    groups_per_user_t **gpu;
} groups_per_user_map_t;

#define LOADFLAGS_UTG_ALLOW_EMPTY_LISTS  0x01  /* Don't return NULL on empty list */

groups_per_user_t     *groups_per_user_map_get_groups(groups_per_user_map_t *gpum, uint32_t user_id);
groups_per_user_map_t *groups_per_user_map_new_from_buffer(const char *buf, int len, struct object_fingerprint *of, uint32_t loadflags);
groups_per_user_map_t *groups_per_user_map_new(struct conf_loader *cl);
groups_per_user_map_t *groups_per_user_map_new_from_file(struct conf_loader *cl, uint32_t loadflags);

void  *groups_per_user_map_new_segment(uint32_t id, struct conf_loader *cl, const struct conf_info *info);
void   groups_per_user_map_debug_log(groups_per_user_map_t *gpum);
size_t groups_per_user_map_count_users(groups_per_user_map_t *gpum);
void   groups_per_user_map_free(groups_per_user_map_t *gpum);
void   groups_per_user_map_refcount_inc(void *obj);
void   groups_per_user_map_refcount_dec(void *obj);

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define GPUM_ALLOC_USERCOUNT ((const char *)groups_per_user_map_new_from_file + 0)
#   define GPUM_ALLOC_GPUMS     ((const char *)groups_per_user_map_new_from_file + 1)
#   define GPUM_ALLOC_GPU       ((const char *)groups_per_user_map_new_from_file + 2)
#endif

#endif /* __GROUPS_PER_USER_MAP_H__ */
