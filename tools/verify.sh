#!/bin/bash
# Telix-side verification entry point.
#
# Runs the host checks for the second-round verified kernel (kernel-v2):
# unit tests + format hygiene (via tools/build-kernel-v2.sh, which
# neutralises the repo-root bare-metal cargo config).  The Rocq/Iris
# kernel specs live in the Tessera tree and are built there
# (make verify-rocq / tessera's hardware/rocq/build.sh); see
# docs/kernel-v2-build-plan.md.
set -euo pipefail

ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOTDIR"

echo "=== kernel-v2 host unit tests ==="
"$ROOTDIR/tools/build-kernel-v2.sh" --test

echo "=== kernel-v2 format check ==="
"$ROOTDIR/tools/build-kernel-v2.sh" --fmt

echo "OK: Telix-side checks passed."
