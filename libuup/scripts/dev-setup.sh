#/bin/sh

set -e

case $(uname -o) in
FreeBSD)
    PATH=/sbin:$PATH

    for pkg in libcjson; do
        if ! pkg info -q $pkg ; then
            pkg install -y $pkg
        fi
    done
    ;;

GNU/Linux)
    export DEBIAN_FRONTEND=noninteractive

    DISTRO=$(sed -n -e 's/^VERSION_CODENAME=//p' -e 's/^PRETTY_NAME=.*(\(\S*\)).*$/\1/p' /etc/os-release|head -1)

    if [ -z "${DISTRO}" ]; then
        echo "FAILED to determine DISTRO from /etc/os.releases"
        exit 1
    fi

    # Point to the dev repo, needed for libtap
    rm -f /etc/apt/sources.list.d/packages_opendns_com_opendns_${DISTRO}.list    # Get rid of any old package config
    PKGCFG=/etc/apt/sources.list.d/packages_aptly_opendns_com_dev_${DISTRO}.list
    CONTENT="deb http://packages-aptly.opendns.com/opendns/${DISTRO} dev main"

    if [ ! -f $PKGCFG ] || ! fgrep -q "$CONTENT" $PKGCFG; then
        apt-get -y install gnupg2 wget # Needed for apt-key command
        wget -O - http://packages-aptly.opendns.com/opendns/${DISTRO}/opendns-packages-48E8D732.asc | apt-key add -
        echo "$CONTENT" >$PKGCFG
    fi

    if [ "${DISTRO}" = 'stretch' ]; then
        # There are no packaged versions of cJSON for debian-9/stretch (or ubuntu-16/xenial, though we no longer support that)
        LIBCJSON=
    else
        LIBCJSON="libcjson1 libcjson-dev"
    fi


    # Install the required packages...
    apt-get update
    apt-get -y install at git fakeroot dpkg-dev debhelper bash build-essential curl libbsd-dev ${LIBCJSON} libssl-dev libtap \
                       net-tools zlib1g-dev ||
         { echo "FAILED to install required packages."; exit 1; }
    ;;

*)
    echo "I don't know what I'm doing" >&2
    ;;
esac

exit 0
