#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p obj bin
if ! command -v gnatmake >/dev/null 2>&1; then
  for candidate in "$HOME"/.local/share/alire/toolchains/gnat_native_*/bin/gnatmake; do
    if [ -x "$candidate" ]; then PATH="$(dirname "$candidate"):$PATH"; export PATH; break; fi
  done
fi
case "$(uname -s)" in
 Darwin) sodium_prefix=$(brew --prefix libsodium); /usr/bin/clang++ -std=c++17 -c src/number.cpp -o obj/number.o; libs="-L$sodium_prefix/lib -lsodium -lc++" ;;
 *)
   c++ -std=c++17 -c src/number.cpp -o obj/number.o
   if [ -f tools/sodium/lib/libsodium.a ]; then
     libs="$(pwd)/tools/sodium/lib/libsodium.a -lstdc++"
   else libs="-lsodium -lstdc++"
   fi ;;

esac
case "${1:-driver}" in
  driver) source_file=src/driver.adb; executable=bin/vh-log-driver ;;
  test_library) source_file=tests/test_library.adb; executable=bin/test-library ;;
  *) echo 'Unknown build target' >&2; exit 1 ;;
esac
gnatmake -q -gnat2022 -gnata -gnato -O2 -Isrc -Itests -D obj "$source_file" -o "$executable" -largs obj/number.o $libs
