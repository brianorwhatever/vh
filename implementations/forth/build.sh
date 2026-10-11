#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p bin
if command -v brew >/dev/null 2>&1; then
  forth_prefix=$(brew --prefix)
  export CPATH="$forth_prefix/include${CPATH:+:$CPATH}"
  export LIBRARY_PATH="$forth_prefix/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
fi
case $(uname -s) in
  Darwin) suffix=dylib; shared='-dynamiclib' ;;
  *) suffix=so; shared='-shared' ;;
esac
c++ -std=c++17 -O2 -Wall -Wextra -Werror -fPIC "$shared" native.cpp -lsodium -lutf8proc -o "bin/libvhforth.$suffix"
