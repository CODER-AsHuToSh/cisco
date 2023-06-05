#include <kit-alloc.h>
#include <mockfail.h>

#include "conf-loader.h"
#include "devices-private.h"
#include "fileprefs.h"
#include "unaligned.h"
#include "xray.h"

/*-
 * A struct device is a mapping from a device id to an origin id, origin type id, and org id.
 *
 *  keys                     values
 *  .-------------.         .-----------------------------------.
 *  | device_id0  |         | originid | origin_type_id | orgid |
 *  |-------------|         |-----------------------------------|
 *  | device_id1  |         | value1                            |
 *  .-------------.         .-----------------------------------|
 *  .             .         .                                   .
 *  .             .         .                                   .
 *  .-------------.         .-----------------------------------|
 *  | device_idN  |         | valueN                            |
 *  `-------------'         `-----------------------------------'
 *
 * keys are uint64_t; all value fields are uint32_t
 */

#define CONSTCONF2DEVICES(confp) (const struct devices *)((confp) ? (const char *)(confp) - offsetof(struct devices, conf) : NULL)
#define CONF2DEVICES(confp)      (struct devices *)((confp) ? (char *)(confp) - offsetof(struct devices, conf) : NULL)

module_conf_t CONF_DEVICES;

static struct conf *devices_allocate(const struct conf_info *info, struct conf_loader *cl);
static void devices_free(struct conf *base);

static const struct conf_type devicesct = {
    "devices",
    devices_allocate,
    devices_free,
};

void
devices_register(module_conf_t *m, const char *name, const char *fn, bool loadable)
{
    SXEA1(*m == 0, "Attempted to re-register %s as %s", name, fn);
    *m = conf_register(&devicesct, NULL, name, fn, loadable, LOADFLAGS_NONE, NULL, 0);
}

const struct devices *
devices_conf_get(const struct confset *set, module_conf_t m)
{
    const struct conf *base = confset_get(set, m);
    SXEA6(!base || base->type == &devicesct, "devices_conf_get() with unexpected conf_type %s", base->type->name);
    return CONSTCONF2DEVICES(base);
}

/*
 * Note: Can't return (*(const uint64_t *)key - ((const struct *)device)->device_id) because values can overflow an 'int'
 */
static int
devices_compare(const void *key, const void *device)
{
    return memcmp(key, device, sizeof(struct kit_deviceid));
}

const struct device *
devices_get(const struct devices *me, const struct kit_deviceid *device_id, struct xray *x)
{
    const struct device *device = NULL;

    SXEE7("(me=%p, device_id=%s, x=?)", me, kit_deviceid_to_str(device_id));

    if (me != NULL) {
        if ((device = bsearch(device_id, me->devices, me->count, sizeof(struct device), devices_compare)) != NULL)
            XRAY7(x, "devices match: found: org %" PRIu32 " origin %" PRIu32 " for deviceid=%s",
                  device->org_id, device->origin_id, kit_deviceid_to_str(device_id));
        else
            XRAY7(x, "devices match: none for deviceid=%s", kit_deviceid_to_str(device_id));
    }

    SXER7("return %p // org_id=%" PRIu32 ", origin_id=%" PRIu32, device, device ? device->org_id : 0,
          device ? device->origin_id : 0);
    return device;
}

static struct conf *
devices_allocate(const struct conf_info *info, struct conf_loader *cl)
{
    struct devices *me;

    SXEA6(info->type == &devicesct, "%s() with unexpected conf_type %s", __FUNCTION__, info->type->name);
    SXE_UNUSED_PARAMETER(info);

    if ((me = devices_new(cl)) != NULL)
        conf_report_load("devices", DEVICES_VERSION);

    return me ? &me->conf : NULL;
}

static bool
devices_allocdevices(struct prefbuilder *pref_builder, unsigned num_devices)
{
    struct devices *me = pref_builder->user;

    SXEA6(me,          "Pointer to devices structure in pref_builder must no be NULL");
    SXEA6(num_devices, "Should never be called with num_devices == 0");

    me->count = num_devices;

    if ((me->devices = MOCKFAIL(DEVICE_ARRAY_NEW, NULL, kit_malloc(num_devices * sizeof(*me->devices)))) == NULL) {
        SXEL2("%s: %u: Failed to malloc a device array", prefbuilder_get_path(pref_builder),
              prefbuilder_get_line(pref_builder));
        return false;
    }

    return true;
}

static bool
devices_readdevice(struct fileprefs *fp, struct prefbuilder *pb, struct conf_loader *cl, const char *line)
{
    struct devices *me     = pb->user;
    struct device  *device = &me->devices[pb->count];
    uint64_t        device_id, origin_id, origin_type, org_id;
    char            separator;

    if (sscanf(line, "%16" SCNx64 ":%10" SCNu64 ":%10" SCNu64 ":%10" SCNu64 "%c", &device_id, &origin_id, &origin_type,
               &org_id, &separator) < 4)
        return fileprefs_log_error(fp, line, __FUNCTION__, pb->loader, "device", "deviceid:originid:origintypeid:orgid",
                                   pb->count, me->count);

    if ((device->origin_id = origin_id) != origin_id)
        SXEL2("%s: %u: Origin id %" PRIu64 " overflows 32 bits", conf_loader_path(cl), conf_loader_line(cl), origin_id);
    else if ((device->org_id = org_id) != org_id)
        SXEL2("%s: %u: Org id %" PRIu64 " overflows 32 bits", conf_loader_path(cl), conf_loader_line(cl), org_id);
    else if (separator != '\n')
        SXEL2("%s: %u: Org id is followed by '%c', not end of line", conf_loader_path(cl), conf_loader_line(cl), separator);
    else {
        unaligned_htonll(&device->device_id, device_id);

        // If this is the first deviced id or is greater that the previous one, its good.
        if (pb->count == 0
         || memcmp(&me->devices[pb->count - 1].device_id, &device->device_id, sizeof(struct kit_deviceid)) < 0) {
            pb->count++;
            return true;
        }

        SXEL2("%s: %u: Device id %" PRIx64 " is not greater than previous device id %s", conf_loader_path(cl),
              conf_loader_line(cl), device_id, kit_deviceid_to_str(&me->devices[pb->count - 1].device_id));
    }

    return false;
}


struct devices *
devices_new(struct conf_loader *cl)
{
    struct fileprefs                prefs;
    struct prefbuilder              builder;
    struct devices                 *me;
    unsigned                       *ok_vers = NULL;
    const struct fileprefs_section *section = NULL;
    unsigned                        count, loaded, total;
    enum fileprefs_section_status   status;

    static struct fileprefs_section devices_section = {
        .name    = "devices",
        .namelen = sizeof("devices") - 1,
        .alloc   = devices_allocdevices,
        .read    = devices_readdevice
    };

    static struct fileprefops devices_ops = {
        .type               = "devices",
        .sections           = &devices_section,
        .num_sections       = 1,
        .supported_versions = { DEVICES_VERSION, 0 }
    };

    SXEE6("(cl=%s)", conf_loader_path(cl));
    me    = NULL;
    count = 0;
    fileprefs_init(&prefs, &devices_ops, 0);

    // First line should be 'devices' followed by at least one integer version number
    if (!fileprefs_load_fileheader(&prefs, cl, &total, &ok_vers))
        goto EARLY_OUT;

    if ((me = MOCKFAIL(DEVICES_NEW, NULL, kit_malloc(sizeof(*me)))) == NULL) {
        SXEL2("%s: Failed to malloc a devices structure", conf_loader_path(cl));
        goto EARLY_OUT;
    }

    conf_setup(&me->conf, &devicesct);
    prefbuilder_init(&builder, 0, cl, me);
    me->count   = 0;
    me->devices = NULL;

    for (loaded = 0;
         (status = fileprefs_load_section(&prefs, cl, &builder, ok_vers, &section, &count)) == FILEPREFS_SECTION_LOADED;
         loaded += count) {
    }

    if (status == FILEPREFS_SECTION_ERROR)
        goto ERROR_OUT;

    if (!conf_loader_eof(cl)) {
        if (section == NULL)
            SXEL2("%s: %u: Expected section header", conf_loader_path(cl), conf_loader_line(cl));
        else
            SXEL2("%s: %u: Unexpected [%s] line - wanted only %u item%s", conf_loader_path(cl), conf_loader_line(cl),
                  section->name, count, count == 1 ? "" : "s");

        goto ERROR_OUT;
    }

    if (loaded == total)
        goto EARLY_OUT;

    SXEL2("%s: %u: Incorrect total count %u - read %u data line%s", conf_loader_path(cl), conf_loader_line(cl),
          total, loaded, loaded == 1 ? "" : "s");

ERROR_OUT:
    if (me) {
        if (me->devices)
            kit_free(me->devices);

        kit_free(me);
        me = NULL;
    }

    prefbuilder_fini(&builder);

EARLY_OUT:
    if (ok_vers)
        kit_free(ok_vers);

    SXER6("return %p // %u records", me, count);
    return me;
}

static void
devices_free(struct conf *base)
{
    struct devices *me = CONF2DEVICES(base);

    if (me && me->devices)
        kit_free(me->devices);

    kit_free(me);
}
