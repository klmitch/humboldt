#!/bin/sh

# Exit on the first error
set -ev

# Determine the build tree directory
if [ "${CI}" = true ]; then
    build_root="${TRAVIS_BUILD_DIR}"
else
    build_root=`dirname $0`/..
fi

# Canonicalize the directory and switch there
cd ${build_root}
build_root=`pwd`

# Run distcheck
if [ -z "${HUMBOLDT_TESTENV}" -o "${HUMBOLDT_TESTENV}" = make ]; then
    # Begin by generating the autoconf files
    ./autogen.sh

    # Create a build directory and cd there
    if [ ! -d build ]; then
	mkdir build
    fi
    cd build

    # Configure the repository
    ${build_root}/configure

    # Run a simple make distcheck
    make distcheck

    # Done; go back to the build root
    cd ${build_root}
fi

# Run tox on our tools
if [ -z "${HUMBOLDT_TESTENV}" -o "${HUMBOLDT_TESTENV}" = tox ]; then
    # Make sure we have tox
    pip install tox

    # Run tox on all the tox.ini files in the tools directory
    for tox_ini in tools/*/tox.ini; do
	tox -c ${tox_ini}
    done
fi
