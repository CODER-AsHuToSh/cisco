#! /usr/bin/env bash

set -e

case $(uname -o) in
GNU/Linux)
    export DEBIAN_FRONTEND=noninteractive

    DISTRO=$(sed -n -e 's/^VERSION_CODENAME=//p' -e 's/^PRETTY_NAME=.*(\(\S*\)).*$/\1/p' /etc/os-release|head -1)

    # Point to the dev repo, needed for libtap
    if [ -n "${DISTRO}" ]; then
        rm -f /etc/apt/sources.list.d/packages_opendns_com_opendns_${DISTRO}.list    # Get rid of any old package config
        PKGCFG=/etc/apt/sources.list.d/packages_aptly_opendns_com_dev_${DISTRO}.list
        CONTENT="deb http://packages-aptly.opendns.com/opendns/${DISTRO} dev main"

        if [ ! -f $PKGCFG ] || ! fgrep -q "$CONTENT" $PKGCFG; then
            apt-get -y install gnupg2 wget # Needed for apt-key command
            wget -O - http://packages-aptly.opendns.com/opendns/${DISTRO}/opendns-packages-48E8D732.asc | apt-key add -
            echo "$CONTENT" >$PKGCFG
        fi
    fi

    # Install the required packages...
    apt-get update
    apt-get -y install at git fakeroot dpkg-dev debhelper bash build-essential curl libbsd-dev libssl-dev libtap net-tools \
                       zlib1g-dev ||
         { echo "FAILED to install required packages."; exit 1; }
    ;;

*)
    echo "I don't know what I'm doing" >&2
    ;;
esac

# Also run the libuup setup script
cd `git rev-parse --show-toplevel`
./libuup/scripts/dev-setup.sh
