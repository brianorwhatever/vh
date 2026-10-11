#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p _build
OCAMLC=${OCAMLC:-ocamlc}
OCAMLOPT=${OCAMLOPT:-ocamlopt}
CXX=${CXX:-c++}
if [ -n "${OPENSSL_PREFIX:-}" ]; then
  ssl_include="-I$OPENSSL_PREFIX/include"
  ssl_lib="-L$OPENSSL_PREFIX/lib"
elif [ -d _deps/openssl/include ]; then
  ssl_include="-I$(pwd)/_deps/openssl/include"
  ssl_lib="-L$(pwd)/_deps/openssl/lib"
elif command -v brew >/dev/null 2>&1; then
  ssl_prefix=$(brew --prefix openssl@3)
  ssl_include="-I$ssl_prefix/include"
  ssl_lib="-L$ssl_prefix/lib"
else
  ssl_include=$(pkg-config --cflags openssl)
  ssl_lib=$(pkg-config --libs-only-L openssl)
fi
# Intentional shell splitting for compiler flags from pkg-config.
$CXX -std=c++17 -O2 -fPIC -I"$($OCAMLC -where)" $ssl_include -c src/native.cpp -o _build/native.o
ar rcs _build/libvh_native.a _build/native.o
for module in json crypto vh_log; do
  if [ -f src/$module.mli ]; then
    $OCAMLOPT -I _build -c src/$module.mli -o _build/$module.cmi
  fi
  $OCAMLOPT -I _build -c src/$module.ml -o _build/$module.cmx
done
case $(uname -s) in
  Darwin) cpp_lib=-lc++; system_libs="" ;;
  *) cpp_lib=-lstdc++; system_libs="-ldl -lpthread" ;;
esac
$OCAMLOPT -a -o _build/vh_log.cmxa _build/json.cmx _build/crypto.cmx _build/vh_log.cmx \
  -cclib -lvh_native -cclib "$ssl_lib" -cclib -lcrypto -cclib "$cpp_lib" -cclib "$system_libs"
$OCAMLOPT -I _build -c src/driver.ml -o _build/driver.cmx
$OCAMLOPT -I _build -o _build/driver _build/vh_log.cmxa _build/driver.cmx
