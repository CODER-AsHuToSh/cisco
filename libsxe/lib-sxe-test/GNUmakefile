LIBRARIES        = sxe-test

include ../dependencies.mak

# Special case: usually only ./test/*.c files include tap.h
ifndef SXE_EXTERNAL_TAP
    IFLAGS += $(CC_INC)$(COM.dir)/../libsxe/lib-tap/$(DST.dir)
endif
