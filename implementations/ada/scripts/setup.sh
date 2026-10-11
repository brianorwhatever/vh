#!/bin/sh
# Native toolchain bootstrap; run after installing libsodium and a C++17 compiler.
set -eu
cd "$(dirname "$0")/.."
alire_version=2.1.1
gnat_version=16.1.0
case "$(uname -s)" in
  Darwin) platform=macos ;;
  Linux) platform=linux ;;
  *) echo 'Supported platforms: macOS and Linux' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  arm64|aarch64) architecture=aarch64 ;;
  x86_64|amd64) architecture=x86_64 ;;
  *) echo 'Supported architectures: aarch64 and x86_64' >&2; exit 1 ;;
esac
mkdir -p tools
if [ "$platform" = linux ]; then
  sodium_version=1.0.22
  sodium_archive="tools/libsodium-$sodium_version.tar.gz"
  sodium_checksum=adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349
  if [ ! -f tools/sodium/lib/libsodium.a ]; then
    curl -LfsS "https://download.libsodium.org/libsodium/releases/libsodium-$sodium_version.tar.gz" -o "$sodium_archive"
    echo "$sodium_checksum  $sodium_archive" | sha256sum -c -
    tar -xzf "$sodium_archive" -C tools
    sodium_prefix="$(pwd)/tools/sodium"
    (cd "tools/libsodium-$sodium_version" && ./configure --prefix="$sodium_prefix" --disable-shared && make -j2 && make install)
  fi
fi
archive="tools/alire.zip"
curl -LfsS "https://github.com/alire-project/alire/releases/download/v$alire_version/alr-$alire_version-bin-$architecture-$platform.zip" -o "$archive"
unzip -oq "$archive" -d tools
rm "$archive"
tools/bin/alr --non-interactive toolchain --select "gnat_native=$gnat_version"
echo "GNAT $gnat_version installed; scripts/build.sh locates it automatically." >&2
