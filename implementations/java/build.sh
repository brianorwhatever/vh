#!/bin/sh
set -eu
mkdir -p build/classes
javac --release 21 -d build/classes src/org/vhlog/*.java
