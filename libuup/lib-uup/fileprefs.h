#ifndef FILEPREFS_H
#define FILEPREFS_H

#include "prefbuilder.h"

struct fileprefs;

/**
 * Define a section of a prefs file, typically with a statically initailized singleton in the file type implementation
 *
 * @member name    Section name. e.g. 'lists' or 'identities'
 * @member namelen Length of the name.
 * @member alloc   Prefbuilder method to allocate the section
 * @member read    Fileprefs method to read a line of the section
 * @member last    Set if a section must be the last section in a prefs file
 */
struct fileprefs_section {
    const char *name;
    int         namelen;
    bool      (*alloc)(struct prefbuilder *, unsigned);
    bool      (*read)(struct fileprefs *, struct prefbuilder *, struct conf_loader *, const char *);
    unsigned    last : 1;
};

/**
 * Define a particular prefs file type, typically with a statically initailized singleton in the file type implementation
 *
 * @member type               Prefs type string; e.g. 'dirprefs', 'netprefs' etc
 * @member keysz              Keys entry length or 0 if the prefs type doesn't have org keys
 * @member parsekey           Method to parse a line; returns cosumed, 0 on error; NULL if prefs type doesn't have identities
 * @member key_to_str         Method to convert a fileprefs key to a string; NULL if the prefs type doesn't have identities
 * @member free               Method to free the fileprefs object, usually fileprefs_free; NULL if not freeable
 * @member sections           Definition of the sections in the file; NULL to use the default fileprefs_sections
 * @member num_sections       Number of sections; number of default_sections if sections is NULL
 * @member supported_versions Zero terminated array of allowed version numbers
 */
struct fileprefops {
    const char                     *type;
    size_t                          keysz;
    int                           (*parsekey)(struct fileprefs *me, int item, const struct conf_loader *cl, const char *line);
    const char                   *(*key_to_str)(struct fileprefs *me, unsigned item);
    void                          (*free)(struct fileprefs *me);
    const struct fileprefs_section *sections;
    unsigned                        num_sections;
    unsigned                        supported_versions[];
};

struct pbcindex;

/*-
 * struct fileprefs contains a 'keys' block and a pref block.  Part of the pref
 * block is the identities block which matches the keys block 1-to-1.
 *
 *  keys                         values->identity
 *  .------------------.         .------------------------------------.
 *  | key0 (len keysz) |         | originid | orgid | actype | bundle |
 *  |------------------|         |------------------------------------|
 *  | key1             |         | ident1                             |
 *  .                  .         .                                    .
 *  .                  .         .                                    .
 *  .------------------.         .------------------------------------|
 *  | keyN             |         | identN                             |
 *  `------------------'         `------------------------------------'
 *
 * There are 'values->count.identities' keys and a pref block with
 * 'values->count.identities' identities.  We search 'keys' using bsearch (usually!)
 * via one of (dev|dir|net|site)prefs and use the resulting index to create a pref_t.
 * A pref_t is simply a prefblock pointer and an identity index.
 *
 * The pref_t is used to obtain data via PREF_IDENT(), PREF_ORG(), PREF_BUNDLE()
 * and PREF_LIST().
 */
struct fileprefs {
    unsigned version;                 /* file version number */
    const struct fileprefops *ops;    /* file operations - specific to each file type */
    void *keys;                       /* key block - see above */
    struct prefblock *values;         /* value block - see above */
    unsigned total;                   /* Total number of prefblock items (the sum of values->count.*) */
    unsigned loadflags;               /* LOADFLAGS_* bits below */
};

#define FILEPREFS_COUNT(fp, var) ((fp) && (fp)->values ? (fp)->values->count.var : 0)
#define PREFS_COUNT(p, var)      ((p) && (p)->fp.values ? (p)->fp.values->count.var : 0)

#define LOADFLAGS_FP_ALLOW_OTHER_TYPES    (1 << 0)    // Disable error if undesired types (e.g. CIDRS) are found
#define LOADFLAGS_FP_ALLOW_BUNDLE_EXTREFS (1 << 1)    // Allow unresolved external references in bundles
#define LOADFLAGS_FP_STRICT_REFS          (1 << 2)    // Treat missing references as errors, except allowed bundle extrefs above
#define LOADFLAGS_FP_SEGMENTED            (1 << 3)    // For segmented prefs type
#define LOADFLAGS_FP_FAILED               (1 << 4)    // This was the result of a failed load, maintained for tracking purposes
#define LOADFLAGS_FP_NO_LTYPE             (1 << 5)    // List lines in lists files don't have ltypes
#define LOADFLAGS_FP_ETYPES_SHIFT         6           // Should be +1 of the highest non-etypes flag

// One bit for each elementtype. If more non etype flags are added, increase LOADFLAGS_FP_ETYPES_SHIFT
#define LOADFLAGS_FP_TO_ELEMENTTYPES(lfs)    ((lfs) >> LOADFLAGS_FP_ETYPES_SHIFT)
#define LOADFLAGS_FP_ELEMENTTYPE(etype)      (PREF_LIST_ELEMENTTYPE_BIT(etype) << LOADFLAGS_FP_ETYPES_SHIFT)
#define LOADFLAGS_FP_ELEMENTTYPE_DOMAIN      LOADFLAGS_FP_ELEMENTTYPE(PREF_LIST_ELEMENTTYPE_DOMAIN)
#define LOADFLAGS_FP_ELEMENTTYPE_URL         LOADFLAGS_FP_ELEMENTTYPE(PREF_LIST_ELEMENTTYPE_URL)
#define LOADFLAGS_FP_ELEMENTTYPE_CIDR        LOADFLAGS_FP_ELEMENTTYPE(PREF_LIST_ELEMENTTYPE_CIDR)
#define LOADFLAGS_FP_ELEMENTTYPE_APPLICATION LOADFLAGS_FP_ELEMENTTYPE(PREF_LIST_ELEMENTTYPE_APPLICATION)

enum fileprefs_section_status {
    FILEPREFS_SECTION_NOT_FOUND,
    FILEPREFS_SECTION_ERROR,
    FILEPREFS_SECTION_LOADED,
};

#include "fileprefs-proto.h"

#endif
