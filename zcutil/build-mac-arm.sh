#!/bin/bash
set -eu -o pipefail

if [ "x$*" = 'x--help' ]
then
    cat <<EOF
Usage:

$0 --help
  Show this help message and exit.

$0 [ --enable-lcov ] [ --enable-debug ] [ MAKEARGS... ]
  Build Verus and most of its transitive dependencies from
  source. MAKEARGS are applied to both dependencies and Verus itself. 
  If --enable-lcov is passed, Verus is configured to add coverage
  instrumentation, thus enabling "make cov" to work.
  If --enable-debug is passed, Verus is built with debugging information. It
  must be passed after the previous arguments, if present.
EOF
    exit 0
fi

# If --enable-lcov is the first argument, enable lcov coverage support:
LCOV_ARG=''
HARDENING_ARG='--disable-hardening'
if [ "x${1:-}" = 'x--enable-lcov' ]
then
    LCOV_ARG='--enable-lcov'
    HARDENING_ARG='--disable-hardening'
    shift
fi

# If --enable-debug is the next argument, enable debugging
DEBUGGING_ARG=''
if [ "x${1:-}" = 'x--enable-debug' ]
then
    DEBUG=1
    export DEBUG
    DEBUGGING_ARG='--enable-debug'
    shift
fi

TRIPLET=`./depends/config.guess`
PREFIX="$(pwd)/depends/$TRIPLET"

MACOSX_DEPLOYMENT_TARGET=13.0 make "$@" -C ./depends v=1 NO_PROTON=1 NO_QT=1 HOST=aarch64-apple-darwin
./autogen.sh

# -mcpu=apple-m2 -mcpu=apple-m3 -mcpu=apple-m4 for M2, M3, M4 optimizations
export CXXFLAGS="-DSSE2NEON_SUPPRESS_WARNINGS -mcpu=apple-m1 -O2 \
-fwrapv -fno-strict-aliasing -Wno-deprecated-declarations \
-Wno-deprecated-builtins -Wno-enum-constexpr-conversion \
-Wno-unknown-warning-option -Werror -Wno-error=attributes" 
export CFLAGS="-DSSE2NEON_SUPPRESS_WARNINGS -mcpu=apple-m1 -O2"

CONFIG_SITE="$PWD/depends/aarch64-apple-darwin/share/config.site" ./configure --enable-tests --disable-bench --with-gui=no --host=aarch64-apple-darwin "$HARDENING_ARG" "$LCOV_ARG" "$DEBUGGING_ARG"
MACOSX_DEPLOYMENT_TARGET=13.0 make "$@" STATIC=1
