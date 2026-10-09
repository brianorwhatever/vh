#!/bin/sh
# Fetches pinned dependencies (once) and builds bin/vh-log-driver.
set -eu
cd "$(dirname "$0")/.."
./scripts/fetch-deps.sh
sbcl --noinform --non-interactive --no-userinit --no-sysinit --load scripts/build.lisp >&2
