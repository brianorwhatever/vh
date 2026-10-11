#!/bin/sh
set -eu
dart pub get >&2
dart compile exe bin/driver.dart -o bin/vh-log-driver >&2
