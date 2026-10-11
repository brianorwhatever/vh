#!/bin/sh
set -eu
exec erl -noshell -pa build/dev/erlang/*/ebin -eval 'vh_log:main(),halt().'
