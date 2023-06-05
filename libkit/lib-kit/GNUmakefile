LIBRARIES = kit

ifdef ZEUS_TOP.dir
# Use the ZEUS libsxe
ifdef LIBSXE_DEV_ROOT
SXE.dir = $(LIBSXE_DEV_ROOT)
else
SXE.dir = $(ZEUS_TOP.dir)/libsxe
endif
else
SXE.dir = $(TOP.dir)/libsxe
endif

include ../dependencies.mak

ifdef ZEUS_TOP.dir
IFLAGS_TEST   := $(filter-out -I$(TOP.dir)/libsxe/lib-tap/$(DST.dir), $(IFLAGS_TEST))
endif

# List of the libraries in linker order.
LIB_DEPENDENCIES = jemalloc

MAKE_ALLOW_LOWERCASE_TYPEDEF = 1

IFLAGS        += $(if $(findstring port,$(LIB_DEPENDENCIES)),$(CC_INC)$(COM.dir)/lib-port/$(OS_class),) \
                 -I$(SXE.dir)/$(DST.dir)/include -I$(TOP.dir)/libjemalloc/$(DST.dir)
LINK_FLAGS    += $(TOP.dir)/libkit/lib-kit/$(DST.dir)/kit$(EXT.lib)
LINK_FLAGS    += $(TOP.dir)/libjemalloc/$(DST.dir)/jemalloc$(EXT.lib)
LINK_FLAGS    += $(SXE.dir)/$(DST.dir)/libsxe$(EXT.lib)
LINK_FLAGS    += -lrt -rdynamic -pthread -ldl -pie -z noexecstack
CFLAGS        += -D_GNU_SOURCE=1 -D_FORTIFY_SOURCE=2    # man 7 feature_test_macros
CFLAGS        += -pthread
CFLAGS_WFORMAT = -Wformat=2
CFLAGS_MARCH   =
