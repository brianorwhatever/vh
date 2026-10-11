#!/bin/sh
# Source versions are fixed; install only under this implementation directory.
set -eu
cd "$(dirname "$0")/.."
VHLOG_PREFIX="$(pwd)/.deps"
VHLOG_BUILD="$VHLOG_PREFIX/build"
mkdir -p "$VHLOG_BUILD"
fetch() {
    curl --fail --location --silent --show-error "$1" -o "$2"
    printf '%s  %s\n' "$3" "$2" | sha256sum --check
}
fetch https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz \
    "$VHLOG_BUILD/sodium.tar.gz" \
    ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19
fetch https://github.com/rakudo/rakudo/releases/download/2026.09/rakudo-2026.09.tar.gz \
    "$VHLOG_BUILD/rakudo.tar.gz" \
    7216aeea9e9780917deb49ec66cd64bc18ad67ce1d8657d8f61cf37d275a468e
cd "$VHLOG_BUILD"
tar xzf sodium.tar.gz
tar xzf rakudo.tar.gz
cd libsodium-1.0.20
./configure --prefix="$VHLOG_PREFIX"
make -j "${VHLOG_JOBS:-2}"
make check
make install
cd ../rakudo-2026.09
# The release's NQP_REVISION pins NQP 2026.09; its build pins matching MoarVM.
perl Configure.pl --gen-moar --gen-nqp --backends=moar --prefix="$VHLOG_PREFIX"
make -j "${VHLOG_JOBS:-2}"
make install
cd "$VHLOG_PREFIX/.."
sh scripts/test.sh
