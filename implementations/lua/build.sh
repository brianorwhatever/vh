#!/bin/sh
set -eu
CXX=${CXX:-c++}
LUA_PKG=${LUA_PKG:-lua}
if ! pkg-config --exists "$LUA_PKG"; then LUA_PKG=lua5.4; fi
case "$(uname -s)" in
  Darwin) shared='-bundle -undefined dynamic_lookup' ;;
  *) shared='-shared' ;;
esac
$CXX -std=c++17 -O2 -fPIC $shared $(pkg-config --cflags "$LUA_PKG" libsodium) native.cpp -o vh_native.so $(pkg-config --libs "$LUA_PKG" libsodium)
