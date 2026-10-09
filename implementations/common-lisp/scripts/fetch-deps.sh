#!/bin/sh
# Fetches the pinned Lisp dependencies into deps/. Each one is checked out at an
# exact commit, so a build is reproducible on any machine with git and SBCL.
# Only Ironclad is used directly (SHA-256 and Ed25519); the rest are its
# dependencies.
set -eu
cd "$(dirname "$0")/.."
mkdir -p deps

fetch() { # name url commit
  dir="deps/$1"
  if [ -d "$dir/.git" ] && [ "$(git -C "$dir" rev-parse HEAD)" = "$3" ]; then
    return 0
  fi
  rm -rf "$dir"
  git clone --quiet "$2" "$dir"
  git -C "$dir" -c advice.detachedHead=false checkout --quiet "$3"
}

fetch ironclad         https://github.com/sharplispers/ironclad.git            d4fe172e4a44b2ac5ab73cf97372314f98e8b8a7 # v0.61
fetch bordeaux-threads https://github.com/sionescu/bordeaux-threads.git         21619023facf4709b58d240af816f3f7b488d2f6 # v0.9.4
fetch alexandria       https://gitlab.common-lisp.net/alexandria/alexandria.git 49e82add16cb9f1ffa72c77cd687271247181ff3 # v1.4
fetch global-vars      https://github.com/lmj/global-vars.git                   c749f32c9b606a1457daa47d59630708ac0c266e
fetch trivial-features https://github.com/trivial-features/trivial-features.git f6e8dd7268ae0137dbde4be469101a7f735f6416 # v1.0
fetch trivial-garbage  https://github.com/trivial-garbage/trivial-garbage.git   b1f757132a0f50aa844b99714b6bbaee974448f7 # v0.21
