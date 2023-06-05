#ifndef PREFBUILDER_H
#define PREFBUILDER_H

#include "conf-loader.h"
#include "pref.h"

#define PREFBUILDER_FLAG_NONE             0x00
#define PREFBUILDER_FLAG_NO_EXTERNAL_REFS 0x01    // Don't create external list or category refs

struct prefbuilder {
    uint32_t            flags;                    // PREFBUILDER_FLAG_* bits
    struct conf_loader *loader;                   // The confloader being used to load the prefs
    void               *user;                     // Arbitrary data for the user of this prefbuilder
    struct {
        char *block;
        unsigned count;
        unsigned alloc;
    } names;
    struct {
        struct preflist *block;
        unsigned         count;
        unsigned         alloc;
    } list;
    struct preflistrefblock listref;              // listref indexes into list.block
    struct preflistrefblock extlistref;
    struct {
        struct preflist *block;
        unsigned         count;
        unsigned         alloc;
    } disclists;
    struct {
        struct prefsettinggroup *block;
        unsigned                 count;
        unsigned                 alloc;
    } settinggroup;
    struct {
        struct prefbundle *block;                 // indexes into listref.block for each action
        unsigned           count;
        unsigned           alloc;
    } bundle;
    struct {
        struct preforg *block;
        unsigned        count;
        unsigned        alloc;
    } org;
    struct prefidentity *identity;                // indexes into org.block and bundle.block
    unsigned count;
    unsigned alloc;
};

#include "prefbuilder-proto.h"

static inline const char *
prefbuilder_get_path(const struct prefbuilder *me)
{
    return conf_loader_path(me->loader);
}

static inline unsigned
prefbuilder_get_line(const struct prefbuilder *me)
{
    return conf_loader_line(me->loader);
}

#endif
