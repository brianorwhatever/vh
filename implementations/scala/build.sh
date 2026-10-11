#!/bin/sh
set -eu
mkdir -p bin
scala-cli --power package . --assembly --server=false --main-class vhlog.Driver -o bin/vh-log-driver.jar --force >&2
