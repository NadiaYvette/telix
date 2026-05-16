#!/bin/bash
# Run the phys-chunk loom tests in isolation from the parent kernel's
# cargo config.  The kernel's `.cargo/config.toml` sets
# `[unstable] build-std = ["core"]` to build core from source for the
# no-std kernel target; that setting gets inherited by sub-crates and
# conflicts with std-using loom tests (duplicate `sized` lang item).
#
# Workarounds:
#   * Use the stable toolchain (no `-Z build-std` available).
#   * Use a target dir outside the kernel tree so cached artefacts
#     from a prior build don't poison the rebuild.
#
# Usage: tests/loom-phys-chunk/run-tests.sh [-- <extra cargo args>]

set -euo pipefail
cd "$(dirname "$0")"

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/loom-phys-chunk-target}" \
RUSTFLAGS="--cfg loom" \
    cargo +stable test --target=x86_64-unknown-linux-gnu --release "$@"
