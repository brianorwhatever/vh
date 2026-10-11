#!/bin/sh
set -eu
export PATH="$(pwd)/.deps/bin:/opt/homebrew/bin:$PATH"
if [ -f "$(pwd)/.deps/lib/libsodium.so" ]; then
    export VHLOG_SODIUM="$(pwd)/.deps/lib/libsodium.so"
fi
command -v raku >/dev/null
c++ -std=c++17 -O2 -shared -fPIC native/number.cpp -o native/libvhnumber.so
raku -Ilib -c lib/VHLog/JSON.rakumod >&2
raku -Ilib -c lib/VHLog/Crypto.rakumod >&2
raku -Ilib -c lib/VHLog.rakumod >&2
raku -Ilib -c driver.raku >&2
