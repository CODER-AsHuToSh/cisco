SUBMODULES = libsxe libjemalloc libkit libuup

.PHONY: cJSON

cJSON:
	make -C cJSON
	ln -fs cJSON cjson

release debug coverage: cJSON
	make -C libsxe      $(MAKECMDGOALS) MAK_VERSION=2
	make -C libjemalloc $(MAKECMDGOALS) MAK_VERSION=2
	make -C libkit      $(MAKECMDGOALS) MAK_VERSION=2
	make -C libuup      $(MAKECMDGOALS) MAK_VERSION=2

test:
	@sync

clean::
	for dir in cJSON $(SUBMODULES); do \
		make -C $$dir clean; \
	done

convention:
	make -C libsxe convention MAK_VERSION=2 MAKE_ALLOW_SPACE_AFTER_ASTERISK=1
	make -C libkit convention MAK_VERSION=2
	make -C libuup convention MAK_VERSION=2

realclean::
	make -C cJSON       clean
	make -C libsxe      realclean
	make -C libjemalloc clean
	make -C libkit      clean
	make -C libuup      clean
