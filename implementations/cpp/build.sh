#!/bin/sh
set -eu
mkdir -p bin
if command -v brew >/dev/null 2>&1; then
    sodium_prefix=$(brew --prefix libsodium)
    json_prefix=$(brew --prefix nlohmann-json)
    "${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Wpedantic -I"$sodium_prefix/include" -I"$json_prefix/include" src/vh_log.cpp src/driver.cpp -L"$sodium_prefix/lib" -lsodium -o bin/vh-log-driver
else
    "${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Wpedantic src/vh_log.cpp src/driver.cpp -lsodium -o bin/vh-log-driver
fi
