#!/bin/sh
# Prerequisites: opam, curl, tar, perl, make, a C compiler, and g++ >= 12.
# For Debian 12: apt-get install opam curl build-essential pkg-config perl
set -eu
cd "$(dirname "$0")/.."
if [ "$(uname -s)" != Linux ]; then
  echo 'setup-linux.sh requires Linux' >&2
  exit 1
fi
opam init --bare --no-setup --yes
if [ ! -d _opam ]; then
  opam switch create . ocaml-base-compiler.5.5.1 --yes
fi
mkdir -p _deps
if [ ! -f _deps/openssl/lib/libcrypto.a ]; then
  curl -fL --retry 3 https://www.openssl.org/source/openssl-3.6.5.tar.gz -o _deps/openssl-3.6.5.tar.gz
  echo 'a2157c2830efdec3788939b00c9b0638306d3f0bbb76dc4832ee503bb397df98  _deps/openssl-3.6.5.tar.gz' | sha256sum -c -
  tar -xzf _deps/openssl-3.6.5.tar.gz -C _deps
  ssl_prefix="$(pwd)/_deps/openssl"
  (cd _deps/openssl-3.6.5 && ./Configure --prefix="$ssl_prefix" --libdir=lib no-shared && make -j"${JOBS:-2}" && make install_sw)
fi
opam exec -- sh scripts/build.sh
