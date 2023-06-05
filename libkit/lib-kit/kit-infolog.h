#ifndef KIT_INFOLOG_H
#define KIT_INFOLOG_H

#include "kit-spinlocks.h"

#include <sxe-log.h>      // For __printflike

#define KIT_INFOLOG_MAX_LINE 1024

#define INFOLOG(flag_suffix, format, ...)                           \
    do {                                                            \
        if (kit_infolog_flags & INFOLOG_FLAGS_ ## flag_suffix) {    \
            kit_infolog_printf(format, ## __VA_ARGS__); }           \
    } while (0)

extern unsigned kit_infolog_flags;

#include "kit-infolog-proto.h"

#endif
