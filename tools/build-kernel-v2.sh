#!/bin/bash
# Build / test the second-round verified kernel (kernel-v2).
#
# kernel-v2 is its OWN cargo workspace (see kernel-v2/Cargo.toml).  It is
# invoked from a neutral CWD because cargo discovers .cargo/config.toml
# relative to the current directory: the repo-root config defaults every
# build to the aarch64-unknown-none bare-metal target with `-Z
# build-std=core` (correct for the prototype kernel, fatal for host unit
# tests — cargo merges config arrays, so the root's build-std cannot be
# cleared from a nested config).  Running from a directory outside the
# repo takes the repo-root config out of the discovery chain entirely.
#
# Usage:
#   tools/build-kernel-v2.sh [--release] [--test] [--fmt]
set -euo pipefail

ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
K2="$ROOTDIR/kernel-v2"

# Artifacts stay inside kernel-v2/ regardless of the invocation CWD.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$K2/target}"
# Neutral CWD: /tmp always exists and has no config chain into the repo.
NEUTRAL="$(mktemp -d)"
trap 'rm -rf "$NEUTRAL"' EXIT

cd "$NEUTRAL"

if [ "${1:-}" = "--fmt" ]; then
    cargo fmt --manifest-path "$K2/Cargo.toml" -- --check
    echo "OK: kernel-v2 format check passed."
    exit 0
fi

if [ "${1:-}" = "--test" ] || [ "${2:-}" = "--test" ] || [ "${2:-}" = "" ]; then
    cargo test --manifest-path "$K2/Cargo.toml"
fi

if [ "${1:-}" = "--release" ] || [ "${2:-}" = "--release" ]; then
    cargo build --manifest-path "$K2/Cargo.toml" --release
fi
