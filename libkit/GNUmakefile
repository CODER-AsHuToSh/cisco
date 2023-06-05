LIBRARIES=	kit

DST.lib+=	$(DST.dir)/libkit$(EXT.lib)

libsources  = $(wildcard $(1)/*.c) $(subst $(OS_class)/,,$(wildcard $(1)/$(OS_class)/*.c))
libobjects  = $(foreach SOURCE,$(call libsources,$(1)),$(patsubst $(1)/%.c,$(1)/$(DST.dir)/%$(EXT.obj),$(SOURCE)))
DST.obj     = $(foreach PACKAGE,$(ALL_LIBRARIES),$(call libobjects,$(COM.dir)/lib-$(PACKAGE)))

libheaders=	$(wildcard $(1)/*.h) $(wildcard $(1)/$(DST.dir)/*.h) $(wildcard $(1)/$(OS_class)/*.h)
SRC.inc.lib=	$(filter-out %-private.h,$(foreach PACKAGE,$(ALL_LIBRARIES),$(call libheaders,$(COM.dir)/lib-$(PACKAGE))))
DST.inc.lib=	$(filter-out %-private.h,$(foreach PACKAGE,$(ALL_LIBRARIES),$(subst /$(OS_class),,$(subst ./lib-$(PACKAGE),$(DST.dir)/include,$(call libheaders,$(COM.dir)/lib-$(PACKAGE))))))
SRC.inc=	$(SRC.inc.lib)
DST.inc=	$(DST.inc.lib)

include dependencies.mak

ifdef MAKE_DEBUG
$(info make: debug: SRC.inc           : $(SRC.inc))
endif

include:
	@$(MAKE_PERL_ECHO_BOLD) "make[$(MAKELEVEL)]: updating: $(DST.dir)/include"
	-$(MAKE_RUN)$(MKDIR) $(call OSPATH,$(DST.dir)/include) $(TO_NUL) $(FAKE_PASS)
	$(MAKE_RUN) $(COPYFILES2DIR) $(SRC.inc.lib) $(DST.dir)/include

ifeq ($(filter remote,$(MAKECMDGOALS)),)
clean::         $(DEP.dirs)
realclean::     $(DEP.dirs)
endif
