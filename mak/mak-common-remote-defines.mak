# Remote build support. Use '?=' so that commands can be exported in the environment or overridden on the commandline.
REMOTE_PROXY     ?= cuba
REMOTE_USER      ?= dev
REMOTE_PATH      ?= /tmp/$(USER)/build
REMOTE_MKDIR     ?= /bin/mkdir -p
REMOTE_MAKE      ?= $(MAKE)
REMOTE_SETENV    ?= true
REMOTE_SHELL     ?= bash

SSH              ?= ssh
SSH_OPTS         := -l $(REMOTE_USER)
ifneq ($(REMOTE_PROXY),)
SSH_OPTS         += -oProxyCommand='nc -x localhost:2222 -X 5 %h %p'
endif
ifneq ($(filter shell,$(MAKECMDGOALS)),)
SSH_INTERACTIVE  := -t
endif

RSYNC            ?= rsync
RSYNC_EXCLUDE    := *.swp build-*
RSYNC_OPTS       := --compress-level=9 --recursive --links --checksum --delete $(RSYNC_EXCLUDE:%=--exclude='%')
RSYNC_RSH        := $(SSH) $(SSH_OPTS)
export RSYNC_RSH

