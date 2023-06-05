#ifndef DIRPREFS_PRIVATE_H
#define DIRPREFS_PRIVATE_H

#include "dirprefs.h"

struct dirprefs {
    struct conf conf;
    unsigned count;            /* # allocated org entries */
    time_t mtime;              /* last modification */
    struct prefs_org **org;    /* a block of 'count' organization pointers */
};

/*-
 * A struct dirprefs is a dynamic array of dirprefs_org structure pointers:
 *
 *                        org[0]                                           org[1]                    ........                      org[N]
 *  .----------------------------------------------. .----------------------------------------------.        .----------------------------------------------.
 *  |        .-----------------------------------. | |        .-----------------------------------. |        |        .-----------------------------------. |
 *  |        |     struct fileprefs fp           | | |        |     struct fileprefs fp           | |        |        |     struct fileprefs fp           | |
 *  |        |-----------------------------------| | |        |-----------------------------------| |        |        |-----------------------------------| |
 *  | orgid  |  keys                   values    | | | orgid  |  keys                   values    | |        | orgid  |  keys                   values    | |
 *  |        |  .----------------.   .--------.  | | |        |  .----------------.   .--------.  | |        |        |  .----------------.   .--------.  | |
 *  | digest |  | dirprefs_key0  |   | pref0  |  | | | digest |  | dirprefs_key0  |   | pref0  |  | |        | digest |  | dirprefs_key0  |   | pref0  |  | |
 *  |        |  |----------------|   |--------|  | | |        |  |----------------|   |--------|  | |........|        |  |----------------|   |--------|  | |
 *  | alloc  |  | dirprefs_key1  |   | pref1  |  | | | alloc  |  | dirprefs_key1  |   | pref1  |  | |        | alloc  |  | dirprefs_key1  |   | pref1  |  | |
 *  |        |  .                .   .        .  | | |        |  .                .   .        .  | |        |        |  .                .   .        .  | |
 *  |        |  .                .   .        .  | | |        |  .                .   .        .  | |        |        |  .                .   .        .  | |
 *  |        |  .----------------.   .--------.  | | |        |  .----------------.   .--------.  | |        |        |  .----------------.   .--------.  | |
 *  |        |  | dirprefs_keyN  |   | prefN  |  | | |        |  | dirprefs_keyN  |   | prefN  |  | |        |        |  | dirprefs_keyN  |   | prefN  |  | |
 *  |        |  `----------------'   `--------'  | | |        |  `----------------'   `--------'  | |        |        |  `----------------'   `--------'  | |
 *  |        `-----------------------------------' | |        `-----------------------------------' |        |        `-----------------------------------' |
 *  `----------------------------------------------' `----------------------------------------------'        `----------------------------------------------'
 *
 * Each fileprefs keysz is set to sizeof(struct dirprefs_key).
 */

#if defined(SXE_DEBUG) || defined(SXE_COVERAGE)    // Define unique tags for mockfails
#   define DIRPREFS_CLONE      ((const char *)dirprefs_register + 0)
#   define DIRPREFS_CLONE_ORGS ((const char *)dirprefs_register + 1)
#   define DIRPREFS_MOREORGS   ((const char *)dirprefs_register + 2)
#endif

#endif
