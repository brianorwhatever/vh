#!/bin/sh
# Runs the library's unit tests and the shared vectors through the library.
set -eu
cd "$(dirname "$0")/.."
./scripts/fetch-deps.sh
sbcl --noinform --non-interactive --no-userinit --no-sysinit --load scripts/env.lisp \
     --eval '(asdf:load-system "vh-log/tests")' \
     --eval '(sb-ext:exit :code (if (uiop:symbol-call :vh-log/tests :run-all) 0 1))'
