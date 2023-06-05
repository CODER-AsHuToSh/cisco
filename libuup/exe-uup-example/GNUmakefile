EXECUTABLES=    uup-example
PKG=            uup-example-service

ifdef MAKE_DEBS
ADDITIONAL_EXECUTABLES += uup-example-deb.ok
endif

include ../dependencies.mak

ifdef MAKE_DEBS
# Generate a complete list of files the .deb depends on
DEB.DEPENDENCIES = $(shell find etc/ debian/ -type f | egrep -v '(\#.*\#|.swp$$|~$$)' )

DEB_BUILD_NUMBER = $(shell echo -$${BUILD_NUMBER-dev})

# Copy all dependencies to the build directory
${filter-out ${DST.dir}/debian/changelog, ${DEB.DEPENDENCIES:%=$(DST.dir)/%}}:	$(DST.dir)/%:	%
	@mkdir -p ${@D}
	[ -f $@ ] && sh -c 'cat $< >$@' || cp -fp $< $@

$(DST.dir)/debian/changelog:  debian/changelog
	@mkdir -p ${@D}
	@err=$$(dpkg-parsechangelog -l $< 2>&1 >/dev/null); [ -z "$$err" ] || { echo "$$err"; false; }
	perl -nale '$$_ =~ s/\(([0-9\.]+)\)/($$1$(DEB_BUILD_NUMBER))/; print' <$< >$@

# Build the .deb and move results into the build directory.  Uses a touch file
# to indicate success as the actual build product's name changes based on
# version and architecture.
$(DST.dir)/uup-example-deb.ok:	$(DST.dir)/uup-example ${DEB.DEPENDENCIES:%=$(DST.dir)/%}
	@$(MAKE_PERL_ECHO) "make[$(MAKELEVEL)]: building $(DST.dir)/${PKG}_*.deb"
	cd $(DST.dir) && dpkg-buildpackage -b -rfakeroot -uc -us
	cd $(DST.dir) && mv ../${PKG}_*.deb .
	cd $(DST.dir) && mv ../${PKG}_*.changes .
	-cd $(DST.dir) && mv ../${PKG}_*.buildinfo .
	touch $@
endif
