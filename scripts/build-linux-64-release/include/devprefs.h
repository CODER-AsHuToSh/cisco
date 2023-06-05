#ifndef DEVPREFS_H
#define DEVPREFS_H

#include "pref.h"

#define DEVPREFS_VERSION 14

extern module_conf_t CONF_DEVPREFS;     /* per-org devprefs */
extern module_conf_t CONF_DEVPREFS0;    /* org0 devprefs */

#include "devprefs-proto.h"

#endif
