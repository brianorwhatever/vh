#!/bin/sh
set -eu
mkdir -p bin
if command -v brew >/dev/null 2>&1; then
    sodium_prefix=$(brew --prefix libsodium)
    json_prefix=$(brew --prefix json-c)
    "${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Wpedantic -I"$sodium_prefix/include" -I"$json_prefix/include" src/vh_log.c src/driver.c -L"$sodium_prefix/lib" -L"$json_prefix/lib" -lsodium -ljson-c -lm -o bin/vh-log-driver
else
    "${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Wpedantic src/vh_log.c src/driver.c -lsodium -ljson-c -lm -o bin/vh-log-driver
fi
