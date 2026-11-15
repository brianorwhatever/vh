#!/bin/sh
# Installs the pinned CryptX release into ./local (a local::lib-style tree)
# unless it is already there. Needs curl, a C compiler and make. The tarball
# is verified against the SHA-256 recorded below before it is built.
set -eu
cd "$(dirname "$0")"

CRYPTX_VERSION=0.091
CRYPTX_SHA256=3a82d5cf786985e5de5339d1236ce4b27306db5e6b1ed5fa15038ded6d44859a
CRYPTX_URL="https://cpan.metacpan.org/authors/id/M/MI/MIK/CryptX-$CRYPTX_VERSION.tar.gz"
PERL=${PERL:-perl}

# Absolute: macOS's hardened system perl refuses to load XS from relative paths.
if "$PERL" -I"$(pwd)/local/lib/perl5" -e "use CryptX; exit(\$CryptX::VERSION eq '$CRYPTX_VERSION' ? 0 : 1)" 2>/dev/null; then
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL --retry 3 -o "$work/CryptX.tar.gz" "$CRYPTX_URL"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$work/CryptX.tar.gz" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$work/CryptX.tar.gz" | cut -d' ' -f1)
fi
if [ "$actual" != "$CRYPTX_SHA256" ]; then
  echo "CryptX-$CRYPTX_VERSION.tar.gz checksum mismatch: $actual" >&2
  exit 1
fi
tar -xzf "$work/CryptX.tar.gz" -C "$work"
prefix="$(pwd)/local"
(
  cd "$work/CryptX-$CRYPTX_VERSION"
  "$PERL" Makefile.PL INSTALL_BASE="$prefix" >&2
  make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" >&2
  make install >&2
)
