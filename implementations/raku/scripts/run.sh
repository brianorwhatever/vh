#!/bin/sh
set -eu
export PATH="$(pwd)/.deps/bin:/opt/homebrew/bin:$PATH"
if [ -f "$(pwd)/.deps/lib/libsodium.so" ]; then
    export VHLOG_SODIUM="$(pwd)/.deps/lib/libsodium.so"
fi
exec raku -Ilib driver.raku
