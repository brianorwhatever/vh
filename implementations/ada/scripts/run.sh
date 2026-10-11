#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
exec ./bin/vh-log-driver
