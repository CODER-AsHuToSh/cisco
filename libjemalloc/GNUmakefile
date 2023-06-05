# Wrapper makefile for the third party package: jemalloc

TOP.dir = ..

LIB_DEPENDENCIES =
LIBRARIES        = jemalloc
THIRD_PARTY.dir  = jemalloc-4.1.0
CONFIGURE_ARGS   = --with-jemalloc-prefix=je_
ifneq ($(filter debug,$(MAKECMDGOALS)),)
CONFIGURE_ARGS  += --enable-debug --enable-fill CFLAGS="${CFLAGS_OPT_OFF}"
else
CONFIGURE_ARGS  += CFLAGS="${CFLAGS_OPT_ON}"
endif

include $(TOP.dir)/mak/mak-common.mak

JEMALLOC_PATH_LIB = $(THIRD_PARTY.dir)/lib
JEMALLOC_PATH_INC = $(THIRD_PARTY.dir)/include/jemalloc
HEADERS = jemalloc.h jemalloc_defs.h

$(DST.dir)/jemalloc$(EXT.lib): $(THIRD_PARTY_DST.dir)/$(JEMALLOC_PATH_LIB)/libjemalloc$(EXT.lib)
	@$(MAKE_PERL_ECHO) "make[$(MAKELEVEL)]:  copying: $@"
	$(MAKE_RUN) $(COPY) $(HEADERS:%=$(THIRD_PARTY_DST.dir)/$(JEMALLOC_PATH_INC)/%) $(DST.dir)/
	$(MAKE_RUN) $(COPY) $(THIRD_PARTY_DST.dir)/$(JEMALLOC_PATH_LIB)/libjemalloc$(EXT.lib) $(DST.dir)/jemalloc$(EXT.lib)

$(THIRD_PARTY_DST.dir)/$(JEMALLOC_PATH_LIB)/libjemalloc$(EXT.lib):
	@$(MAKE_PERL_ECHO) "make[$(MAKELEVEL)]: configuring: $@"
	$(MAKE_RUN) cd $(THIRD_PARTY_DST.dir)/$(THIRD_PARTY.dir) && ./configure $(CONFIGURE_ARGS)
	@$(MAKE_PERL_ECHO) "make[$(MAKELEVEL)]: building: $@"
	$(MAKE_RUN) cd $(THIRD_PARTY_DST.dir)/$(THIRD_PARTY.dir) && ${MAKE}

