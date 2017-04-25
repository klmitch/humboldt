#!/bin/sh

# Exit on the first error
set -e

# Determine the build tree directory
if [ "${CI}" = true ]; then
    build_root="${TRAVIS_BUILD_DIR}"
else
    build_root=`dirname $0`/..
fi

# Canonicalize the directory and switch there
cd ${build_root}
build_root=`pwd`

# Set up the banner printer
sep="======================================================================"
banner () {
    leader=$1
    shift
    if [ ${leader} -gt 0 ]; then
	echo ${sep}
    fi
    python -c "import textwrap;print(textwrap.fill('$*'))"
    echo ${sep}
}

banner 1 "Running tests on ${build_root}"

# Run distcheck
if [ -z "${HUMBOLDT_TESTENV}" -o "${HUMBOLDT_TESTENV}" = make ]; then
    args=
    if [ -n "${DISTCHECK_CONFIGURE_FLAGS}" ]; then
	args=" with configure flags: ${DISTCHECK_CONFIGURE_FLAGS}"
    fi
    banner 0 "Testing Humboldt${args}"

    # Begin by generating the autoconf files
    banner 0 "  Running autogen.sh..."
    ./autogen.sh >/dev/null 2>&1

    # Create a build directory and cd there
    banner 0 "  Creating build directory"
    if [ ! -d travis-build ]; then
	mkdir travis-build
    fi
    cd travis-build

    # Configure the repository
    banner 0 "  Configuring the repository"
    ${build_root}/configure

    # Run a simple make distcheck
    banner 1 "  Running \"make distcheck\"${args}"
    make distcheck

    # Done; go back to the build root
    banner 1 "  Done testing Humboldt"
    cd ${build_root}
fi

# Run tox on our tools
if [ -z "${HUMBOLDT_TESTENV}" -o "${HUMBOLDT_TESTENV}" = tox ]; then
    args=
    if [ -n "${TOXENV}" ]; then
	args=" on tox environment(s): ${TOXENV}"
    fi
    banner 0 "Testing Humboldt Python tools with tox${args}"

    # Make sure we have tox
    banner 0 "  Installing tox"
    pip install tox >/dev/null 2>&1

    # Run tox on all the tox.ini files in the tools directory
    lead=0
    for tox_ini in tools/*/tox.ini; do
	tool=`dirname ${tox_ini}`
	tool=`basename ${tool}`
	banner ${lead} "  Running tox on ${tool}${args}"
	tox -c ${tox_ini}
	banner 1 "  Done testing ${tool}"
	lead=1
    done
fi

banner 0 "Done testing Humboldt"
