#!/bin/sh
set -eu
mkdir -p bin
dart pub get >&2
dart compile exe tool/driver.dart -o bin/vh-log-driver >&2
