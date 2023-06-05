COM.dir    := $(patsubst %/,%,$(dir $(word $(words $(MAKEFILE_LIST)), $(MAKEFILE_LIST))))
TOP.dir     = $(COM.dir)/..
MAK_VERSION = 2
DISTRO      = $(shell sed -n -e 's/^VERSION_CODENAME=//p' -e 's/^PRETTY_NAME=.*(\(\S*\)).*$$/\1/p' /etc/os-release|head -1)

# List of the libraries in linker order.
# This is used by both the package GNUmakefiles and the top level GNUmakefile
#
ALL_LIBRARIES = crl uup

remove_to = $(if $(filter $(1),$(2)),$(call remove_to,$(1),$(wordlist 2,$(words $(2)),$(2))),$(2))

LIB_DEPENDENCIES = $(call remove_to,$(LIBRARIES),$(ALL_LIBRARIES))

MAKE_ALLOW_LOWERCASE_TYPEDEF = 1

include $(TOP.dir)/mak/mak-common.mak

ifneq ($(DISTRO),stretch)
	CJSON_LINK_FLAGS = -lcjson
# To use a locally built cjson library regardless of the presence of a local
# package uncomment this section
# ifeq (,$(wildcard $(TOP.dir)/cjson/libcjson.so))
#     CJSON_IFLAGS     = -I$(TOP.dir)
#     CJSON_LINK_FLAGS = $(TOP.dir)/cjson/libcjson.a
# endif
else
	# If this is not Debian 9/stretch then there should be a cjson package installed
	# Otherwise, there should also be a cjson directory in the TOPDIR that contains the header files
    CJSON_IFLAGS     = -I$(TOP.dir)
    CJSON_LINK_FLAGS = $(TOP.dir)/cjson/libcjson.a
    TEST_ENV_VARS    = LD_LIBRARY_PATH=$(abspath $(TOP.dir))/cjson
endif

GCCVERGTEQ9   := $(shell expr `$(CC) -dumpversion | cut -f1 -d.` \>= 9)

ifeq ($(GCCVERGTEQ9),1)
CFLAGS        += -Wno-address-of-packed-member
endif

CFLAGS     += -D_GNU_SOURCE=1
IFLAGS     += $(CJSON_IFLAGS) -I$(TOP.dir)/libsxe/$(DST.dir)/include -I$(TOP.dir)/libjemalloc/$(DST.dir) \
              -I$(TOP.dir)/libkit/$(DST.dir)/include
LINK_FLAGS += $(TOP.dir)/libkit/$(DST.dir)/libkit$(EXT.lib) $(TOP.dir)/libjemalloc/$(DST.dir)/jemalloc$(EXT.lib) \
              $(TOP.dir)/libsxe/$(DST.dir)/libsxe$(EXT.lib) $(CJSON_LINK_FLAGS) -lcrypto -pthread -lz

ifeq ($(OS_name), linux)
LINK_FLAGS    += -lbsd
endif

#LINK_FLAGS += -lrt -rdynamic -lbsd -lsodium -lcrypto -pthread -lpcap -lm -ldl -lz

