#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
sh scripts/build.sh
sh scripts/build.sh test_library
./bin/test-library
if command -v node >/dev/null 2>&1; then node tests/numbers.mjs; fi
