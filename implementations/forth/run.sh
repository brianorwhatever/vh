#!/bin/sh
set -eu
cd "$(dirname "$0")"
if command -v brew >/dev/null 2>&1; then
  export CPATH="$(brew --prefix gforth)/include${CPATH:+:$CPATH}"
fi
export LIBRARY_PATH="$PWD/bin${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$PWD/bin${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export DYLD_LIBRARY_PATH="$PWD/bin${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
exec gforth -m 64M -d 4M -r 4M "${1:-driver.fs}"
