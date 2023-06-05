ZEUS_BUILD_PACKAGE_NAME=opendns-libsxe-dev
ZEUS_BUILD_PACKAGE_VERSION=0.1

function zeus_build_package_prepare()
{
    local dest_dir=$1
    export PREFIX=$dest_dir
    echo $PREFIX
    make install
}
