#!/bin/sh
set -eu
mkdir -p bin build
ghc -O2 -isrc -outputdir build $(pkg-config --cflags --libs libsodium) src/Main.hs -o bin/vh-log-driver >&2
