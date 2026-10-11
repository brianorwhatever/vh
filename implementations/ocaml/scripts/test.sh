#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
sh scripts/build.sh
OCAMLOPT=${OCAMLOPT:-ocamlopt}
$OCAMLOPT -I _build -c src/test.ml -o _build/test.cmx
$OCAMLOPT -I _build -o _build/test _build/vh_log.cmxa _build/test.cmx
./_build/test
