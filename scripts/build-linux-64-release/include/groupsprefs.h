/* Copied from: https://github.office.opendns.com/cdfw/firewall/blob/multi-tenant/src/groupsprefs.h
 */

#ifndef GROUPSPREFS_H
#define GROUPSPREFS_H

#include "conf.h"
#include "groups-per-user-map.h"

#define GROUPSPREFS_VERSION 1

extern module_conf_t CONF_GROUPSPREFS;

void                   groupsprefs_register(module_conf_t *m, const char *name, const char *fn);
groups_per_user_map_t *groupsprefs_get_groups_per_user_map(const struct confset *set, module_conf_t m, uint32_t org_id);

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define GROUPSPREFS_CLONE       ((const char *)groupsprefs_register + 0)
#   define GROUPSPREFS_CLONE_GPUMS ((const char *)groupsprefs_register + 1)
#   define GROUPSPREFS_MORE_ORGS   ((const char *)groupsprefs_register + 2)
#endif

#endif
