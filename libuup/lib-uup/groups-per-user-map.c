/* Copied from: https://github.office.opendns.com/cdfw/firewall/blob/multi-tenant/src/groups-per-user-map.c
 */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <mockfail.h>
#include <stdlib.h>
#include <stdio.h>
#include <safe_lib.h>
#include <unistd.h>
#include <limits.h>

#include "atomic.h"
#include "kit-alloc.h"
#include "groups-per-user-map.h"

#define MAX_CHAR_IN_UINT32 (sizeof("4294967295") - 1)

// Big number for the max size of rule field
// Its actually size of - 0 to 65535 seperated by comma :)
#define MAX_RULE_FIELD_STR 447642

// Initially allocate memory for GROUPS_CHUNK_SIZE groups per user and grow
// by this much if more needed
#define GROUPS_CHUNK_SIZE  5

#define MAX_GPU_WIDTH   40000
#define USERCOUNT_ARRAY_SIZE 1000000

/* This function was called get_groups_for_user
 */
groups_per_user_t *
groups_per_user_map_get_groups(groups_per_user_map_t *gpum, uint32_t user_id) {

    groups_per_user_t *gpu = NULL;

    if (!gpum) {
        SXEL1("get_groups_for_user, gpum is NULL");
        return NULL;
    }

    gpu = gpum->gpu[user_id % gpum->gpu_width];

    while (gpu) {
        if (gpu->user_id == user_id)
            return gpu;

        gpu = gpu->next;
        /* COVERAGE EXCLUSION: Need a test where a user is not the first user in it's bucket */
    }

    return NULL;
}

void
groups_per_user_map_debug_log(groups_per_user_map_t *gpum)
{
    (void)gpum;
#if SXE_DEBUG
    size_t i = 0;
    size_t table_cells_used = 0;
    size_t gpus_total_depth = 0;
    size_t gpu_avg_depth = 0;
    size_t avg_groups_count = 0;

    for (i = 0; i < gpum->gpu_width; i++) {
        if (gpum->gpu[i]) {
            table_cells_used++;
            groups_per_user_t *p = gpum->gpu[i];
            while (p) {
                gpus_total_depth++;
                avg_groups_count += p->count;
                p = p->next;
            }
        }
    }

    if (avg_groups_count > 0) {
        avg_groups_count = avg_groups_count / gpus_total_depth;
    }

    if (table_cells_used != 0) {
        gpu_avg_depth = gpus_total_depth / table_cells_used;
    }

    SXEL6("GPU: gpu-width:%zu  cells-used:%zu  avg-gpu-depth:%zu  avg_groups:%zu  total_depth:%zu",
        gpum->gpu_width, table_cells_used, gpu_avg_depth, avg_groups_count, gpus_total_depth);
#endif
}

/* This function was called count_users
 */
size_t
groups_per_user_map_count_users(groups_per_user_map_t *gpum) {

    size_t count = 0;

    for (size_t i = 0; i < gpum->gpu_width; i++) {
        groups_per_user_t *p = gpum->gpu[i];

        while (p) {
            count++;
            p = p->next;
        }
    }

    return count;
}

static int
parse_users_for_counting(const char *line, unsigned *users, size_t users_len)
{
    const char *str = line;
    char *end;
    uint32_t group_id;
    uint32_t user_id;
    const char *cur;

    group_id = (uint32_t)strtoul(str, &end, 10);
    if (end == str) {
        SXEL2("Failed parsing group_id: '%s'", line);
        return 1;
    }

    if (group_id == 0) {
        SXEL2("Invalid group_id '%d': '%s'", group_id, line);
        return 1;
    }

    str = end;

    while (*str != '\0' && (isspace(*str) || (*str == ':')))
            str++;    // skip whitespace  or ':'

    while (*str != '\0' && *str != '\n') {
        cur = str;
        user_id = (uint32_t)strtoul(str, &end, 10);
        str = end;

        if (user_id == 0) {
            SXEL2("Invalid user_id '%u' is present in this line: '%s' so not loading the new map", user_id, line);
            return 1;
        }

        // The following marks the spot in the users array indicating a user and incrementing the count indicates the
        // amount of groups for this user. If the array is chosen large enough then there should be few clashes.
        users[user_id % users_len]++;

        // The following will skip over comma separated or just whitespace separated groups
        while (*str != '\0' && *str != '\n' && (isspace(*str) || (*str == ',')))
            str++;    // skip whitespace  or ','

        if (cur == str) {
            SXEL2("There is an error while parsing this line: '%s'", line);    /* COVERAGE EXCLUSION: Can't happen */
            return 1;                                                          /* COVERAGE EXCLUSION: Can't happen */
        }
    }

    return 0;
}

/* The groupsprefs format lists users per group but we need groups per user, so the
 * parse function below is called parse_users_per_group_txt because it parses the
 * groupsprefs line that lists users per group e.g. 'group1: user1 user2 user3'
 * This function flips this order around i.e. it wants groups per user.
 * To do this finds every user on the line and makes sure it has an entry in the
 * map of groups_per_user and then adds the group for that user in the list of groups
 * for that user's map entry.
 *
 * @return 0 Success, 1 Failed
 */
static int
parse_users_per_group_txt(groups_per_user_map_t *gpum, const char *line, unsigned version, size_t avg_groups_per_user)
{
    // user-group-id-1: user-id-1 user-id-2 user-id-3 user-id-4
    // user-group-id-2: user-id-5 user-id-6
    // thus:
    // 123: 222 333 444
    // 456: 333 666 777 999

    (void) version; //not yet used
    const char *str = line;
    char *end;
    uint32_t group_id;
    uint32_t user_id;
    const char *cur;

    group_id = (uint32_t)strtoul(str, &end, 10);

    if (end == str) {
        SXEL2("Failed parsing group_id: '%s'", line);   /* COVERAGE EXCLUSION: Already checked by parse_users_for_counting */
        return 1;                                       /* COVERAGE EXCLUSION: Already checked by parse_users_for_counting */
    }

    if (group_id == 0) {
        SXEL2("Invalid group_id '%d': '%s'", group_id, line);   /* COVERAGE EXCLUSION: Already checked by parse_users_for_counting */
        return 1;                                          /* COVERAGE EXCLUSION: Already checked by parse_users_for_counting */
    }

    str = end;

    while (*str != '\0' && (isspace(*str) || (*str == ':')))
        str++;    // skip whitespace  or ':'

    while (*str != '\0' && *str != '\n') {
        cur = str;
        user_id = (uint32_t) strtoul(str, &end, 10);
        str = end;

        if (user_id == 0) {
            SXEL2("Invalid user_id '%u' is present in this line: '%s' so not loading the new map", user_id, line);   /* COVERAGE EXCLUSION: Already checked by parse_users_for_counting */
            return 1;                                      /* COVERAGE EXCLUSION: Already checked by parse_users_for_counting */
        }

        if (gpum->gpu[user_id % gpum->gpu_width] == NULL) {
            groups_per_user_t *p = (groups_per_user_t *) kit_malloc(sizeof(groups_per_user_t));
            gpum->gpu[user_id % gpum->gpu_width] = p;
            p->user_id = user_id;
            p->groups = (uint32_t *)kit_malloc(sizeof(uint32_t)*avg_groups_per_user);
            p->size = avg_groups_per_user;
            p->count = 1;
            p->groups[0] = group_id;
            p->next = NULL;
        } else {
            groups_per_user_t *p = gpum->gpu[user_id % gpum->gpu_width];
            groups_per_user_t *prev = NULL;

            while (p) {
                if (p->user_id == user_id) {
                    if (p->size <= p->count) {
                        p->size += GROUPS_CHUNK_SIZE;
                        p->groups = (uint32_t *)kit_realloc(p->groups, sizeof(uint32_t)*p->size);
                    }

                    p->groups[p->count] = group_id;
                    p->count++;
                    break;
                }

                prev = p;
                p = p->next;

                if (!p) {
                    p = (groups_per_user_t *) kit_malloc(sizeof(groups_per_user_t));
                    p->user_id = user_id;
                    p->groups = (uint32_t *)kit_malloc(sizeof(uint32_t)*avg_groups_per_user);
                    p->size = avg_groups_per_user;
                    p->count = 1;
                    p->groups[0] = group_id;
                    prev->next = p;
                    p->next = NULL;
                    break;
                }
            }
        }

        // The following will skip over comma separated or just whitespace separated groups
        while (*str != '\0' && *str != '\n' && (isspace(*str) || (*str == ',')))
            str++;    // skip whitespace or ','

        if (cur == str) {
            SXEL2("There is an error while parsing this line: '%s'", line);    /* COVERAGE EXCLUSION: Can't happen */
            return 1;                                                          /* COVERAGE EXCLUSION: Can't happen */
        }
    }

    return 0;
}

static groups_per_user_map_t *
groups_per_user_map_parse(const char *list, int list_len, struct object_fingerprint *of, uint32_t flags)
{
    groups_per_user_map_t *gpum = NULL;
    unsigned version;
    size_t i = 0;
    size_t grouprows_count = 0;
    const char *str;
    const char *end;
    const char *temp;
    size_t user_count = 0;
    size_t avg_groups_count = 0;
    unsigned *users = NULL;

    SXEE6("groups_per_user_map_parse(list=%p, list_len=%d, of=%p, flags=0x%X)", list, list_len, of, flags);

    if (list_len == 0 && !(flags & LOADFLAGS_UTG_ALLOW_EMPTY_LISTS)) {
        goto DONE;
    }

    if (sscanf(list, "version %u\n", &version) != 1) {
        SXEL3("Failed to read groupsprefs 'version'");
        goto DONE;
    }

    switch (version) {
    case 1:
        if (sscanf(list, "version 1\ncount %zu", &grouprows_count) != 1) {
            SXEL3("Failed to read groupsprefs version 1 headers");
            goto DONE;
        }
        break;

    default:
        SXEL3("Unkown groupsprefs version '%u'", version);
        goto DONE;
    }

    SXEL6("groupsprefs V%u: Count:%zu", version, grouprows_count);

    if (grouprows_count == 0)
        goto DONE;

    if ((users = MOCKFAIL(GPUM_ALLOC_USERCOUNT, NULL, kit_calloc(1, USERCOUNT_ARRAY_SIZE * sizeof(unsigned)))) == NULL) {
        SXEL2("Failed to allocate %zu bytes for user counting", USERCOUNT_ARRAY_SIZE * sizeof(unsigned));
        goto DONE;
    }

    memset_s(users, USERCOUNT_ARRAY_SIZE * sizeof(unsigned), 0, USERCOUNT_ARRAY_SIZE * sizeof(unsigned));
    str = list;

    while (*str != '\0' && *str != '\n')
        str++;    // skip version line

    str++;

    while (*str != '\0' && *str != '\n')
        str++;    // skip count line

    str++;
    temp = str;

    for (end = str; end != (list + list_len); str++) {
        end = str;

        while (end != (list + list_len)) {
            if (*end == '\n')
                break;

            end++;
        }

        if (end != str) {
            if (i == grouprows_count) {
                SXEL3("group lines exceeds 'count' header in groupspref");
                goto ERROR_OUT;
            }

            char buf[end - str + 1];
            memcpy_s(buf, sizeof(buf), str, end - str);
            buf[end - str] = '\0';

            switch (parse_users_for_counting(buf, users, USERCOUNT_ARRAY_SIZE)) {
            case 0:
                break;
            default:
                SXEL3("parse_users_for_counting failed for line %zu in groupspref", i);
                goto ERROR_OUT;
            }

            i++;
        }

        str = end;
    }

    if (i != grouprows_count) {
        SXEL3("Mismatched number of lines vs 'count' in groupsprefs file (count=%zu, read=%zu)", grouprows_count, i);
        goto ERROR_OUT;
    }

    // Count the users and get the average count of groups per user
    for (i = 0; i < USERCOUNT_ARRAY_SIZE; i++) {
        if (users[i] > 0) {
            user_count++;
            avg_groups_count += users[i];
        }
    }
    if (avg_groups_count > 0) {
        avg_groups_count = avg_groups_count / user_count;
    }

    SXEL6("user_count = %zu and avg_groups_count = %zu", user_count, avg_groups_count);
    kit_free(users);
    users = NULL;

    // Done with counting users and their groups, now use that to allocate the structs...
    if ((gpum = MOCKFAIL(GPUM_ALLOC_GPUMS, NULL, kit_calloc(1, sizeof(groups_per_user_map_t) + (of && of->hash ? of->len : 0))))
     == NULL) {
        SXEL1("Failed to allocate %zu bytes for groups_per_user_map", sizeof(groups_per_user_map_t));
        goto DONE;
    }

    // A width of 1/4 of the amount of users (e.g. if 1000 users then a width of 250)
    // seems to give the best performance from lookup and space point of view i.e.
    // nearly all of the cells in the array are used and the average depth will be 4 items giving
    // an average lookup depth of 2 which is very reasonable.
    // Example: Capping the max width at 40 000, for an org of 400 000 users the average depth
    // will be 10 and the average lookup for a user will be a depth of 5 which is reasonable for
    // such a large org.

    if (user_count > 0) {
        gpum->gpu_width = user_count / 4;

        if (gpum->gpu_width > MAX_GPU_WIDTH) {
            gpum->gpu_width = MAX_GPU_WIDTH;    /* COVERAGE EXCLUSION: Not sure how to cover this */
        } else if (gpum->gpu_width == 0) {
            gpum->gpu_width = 1;
        }

        SXEL6("Optimal gpu width determined as %zu", gpum->gpu_width);
    } else {
        SXEL3("Zero user count for org");
        goto ERROR_OUT;
    }

    if ((gpum->gpu = MOCKFAIL(GPUM_ALLOC_GPU, NULL, kit_calloc(1, sizeof(groups_per_user_t) * gpum->gpu_width))) == NULL) {
        SXEL1("Failed to allocate %zu bytes for groups_per_user", gpum->gpu_width*sizeof(groups_per_user_t));
        goto ERROR_OUT;
    }

    for (i = 0; i < gpum->gpu_width; i++)
        gpum->gpu[i] = NULL;

    i = 0;

    str = temp;
    // removed the checks that were performed in above looping through lines
    for (end = str; end != (list + list_len); str++) {
        end = str;

        while (end != (list + list_len)) {
            if (*end == '\n') { break; }
            end++;
        }

        if (end != str) {
            // Dont have to check if (i == grouprows_count) as it was done above when counting
            char buf[end - str + 1];
            memcpy_s(buf, sizeof(buf), str, end - str);
            buf[end - str] = '\0';

            if (parse_users_per_group_txt(gpum, buf, version, avg_groups_count)) {
                SXEL1("parse_users_per_group_txt failed for line %zu in groupspref", i);    /* COVERAGE EXCLUSION: Can't fail because file is validate in parse_users_for_counting */
                goto ERROR_OUT;        /* COVERAGE EXCLUSION: Can't fail because file is validate in parse_users_for_counting */
            }

            i++;
        }

        str = end;
    }

    groups_per_user_map_debug_log(gpum);

    // Success
    goto DONE;

ERROR_OUT:
    groups_per_user_map_free(gpum);
    gpum = NULL;

    if (users)
        kit_free(users);

DONE:
    SXER6("return gpum=%p", gpum);
    return gpum;
}

groups_per_user_map_t *
groups_per_user_map_new_from_buffer(const char *buf, int len, struct object_fingerprint *of, uint32_t loadflags)
{
    groups_per_user_map_t *gpum = NULL;
    SXEE7("(buf=%p, len=%d, of=%p, loadflags=0x%" PRIX32 ")", buf, len, of, loadflags);
    gpum = groups_per_user_map_parse(buf, len, of, loadflags);
    SXER7("return %p", gpum);
    return gpum;
}

groups_per_user_map_t *
groups_per_user_map_new_from_file(struct conf_loader *cl, uint32_t loadflags)
{
    groups_per_user_map_t *gpum = NULL;
    size_t buf_len;
    char *buf;

    SXEE7("(cl=%p, loadflags=0x%" PRIX32 ") // path=%s", cl, loadflags, conf_loader_path(cl));

    if ((buf = conf_loader_readfile(cl, &buf_len, 0)) != NULL) {
        gpum = groups_per_user_map_parse(buf, buf_len, NULL, loadflags);
        kit_free(buf);
    }

    if (gpum == NULL)
        errno = EINVAL;

    SXER7("return %p", gpum);
    return gpum;
}

void *
groups_per_user_map_new_segment(uint32_t id, struct conf_loader *cl, const struct conf_info *info)
{
    groups_per_user_map_t *gpum;

    if ((gpum = groups_per_user_map_new_from_file(cl, info->loadflags)) != NULL) {
        conf_segment_init(&gpum->cs, id, cl, false);
    }

    return gpum;
}

groups_per_user_map_t *
groups_per_user_map_new(struct conf_loader *cl)
{
    return groups_per_user_map_new_from_file(cl, LOADFLAGS_UTG_ALLOW_EMPTY_LISTS);
}

void
groups_per_user_map_free(groups_per_user_map_t *gpum)
{
    unsigned i;

    if (!gpum) {
        return;
    }

    for (i = 0; i < gpum->gpu_width; i++) {
        if (gpum->gpu && gpum->gpu[i]) {
            groups_per_user_t *cur = gpum->gpu[i];
            groups_per_user_t *next;

            while (cur) {
                kit_free(cur->groups);
                next = cur->next;
                kit_free(cur);
                cur = next;
            }
        }
    }

    kit_free(gpum->gpu);
    kit_free(gpum);
}

void
groups_per_user_map_refcount_inc(void *obj)
{
    groups_per_user_map_t *gpum = obj;

    if (gpum) {
        ATOMIC_INC_INT(&gpum->cs.refcount);
    }
}

void
groups_per_user_map_refcount_dec(void *obj)
{
    groups_per_user_map_t *gpum = obj;

    if (gpum && ATOMIC_DEC_INT_NV(&gpum->cs.refcount) == 0) {
        groups_per_user_map_free(gpum);
    }
}
