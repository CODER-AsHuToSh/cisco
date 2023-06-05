ifeq ($(REMOTE_HOST),)
$(error make[$(MAKELEVEL)]: specify $$REMOTE_HOST=localhost|<remote-host> to build remotely)
endif

RELATIVE_PATH    := $(subst $(shell cd $(TOP.dir) && $(PWD)),,$(CURDIR))

remote:
ifneq ($(REMOTE_HOST),localhost)
	@$(MAKE_PERL_ECHO_BOLD) "make[$(MAKELEVEL)]: remote:   host: $(REMOTE_HOST), path: $(REMOTE_PATH)$(RELATIVE_PATH)"
ifeq ($(filter shell,$(MAKECMDGOALS)),)
	@$(MAKE_PERL_ECHO)      "make[$(MAKELEVEL)]: rsync:    host: $(REMOTE_HOST), path: $(REMOTE_PATH)$(RELATIVE_PATH)"
	@$(SSH) $(SSH_OPTS) $(REMOTE_HOST) '$(REMOTE_MKDIR) $(REMOTE_PATH)' \
	    || { echo "make: SSH failed; consider running 'ssh -fN -Dlocalhost:2222 $(REMOTE_PROXY)'" >&2; false; }
	@$(RSYNC) $(RSYNC_OPTS) $(TOP.dir)/ $(REMOTE_HOST):$(REMOTE_PATH)/
endif
	@$(SSH) $(SSH_OPTS) $(SSH_INTERACTIVE) $(REMOTE_HOST) 'cd $(REMOTE_PATH)$(RELATIVE_PATH) && $(REMOTE_SETENV) && $(REMOTE_CMDPREFIX)$(REMOTE_MAKE) $(filter-out remote,$(MAKECMDGOALS)) REMOTE_SHELL=$(REMOTE_SHELL) $(REMOTE_CMDEXTRA)$(REMOTE_CMDSUFFIX)'
else
	@mkdir -p $(REMOTE_PATH)
	@$(RSYNC) $(RSYNC_OPTS) $(TOP.dir)/ $(REMOTE_PATH)/
	@$(MAKE) -C $(REMOTE_PATH)$(RELATIVE_PATH) $(filter-out remote,$(MAKECMDGOALS))
endif

all release debug coverage test check convention shell usage :
	@$(PERL) -e0

clean realclean ::
	@$(PERL) -e0

