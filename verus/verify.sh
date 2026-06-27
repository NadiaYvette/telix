#!/usr/bin/env bash
# Verify the stage-1 Verus seed for telix mm/extent.rs coalescing.
#
# Needs: a Verus toolchain (a verus-lang/verus prebuilt release — binary + vstd + z3)
# and its pinned rust toolchain (1.96.0; install minimal + rustc-dev + llvm-tools).
# Point VERUS at the verus binary if it is not on PATH.
#
# Expected output: `verification results:: 11 verified, 0 errors`.
set -e
cd "$(dirname "$0")"
VERUS="${VERUS:-$HOME/verus/verus-x86-linux/verus}"
echo "verus: $("$VERUS" --version | head -1)"
for f in extent_coalesce.rs extent_leaf.rs extent_node.rs extent_split.rs extent_chain.rs extent_link.rs rmap.rs; do
  echo "--- $f ---"
  "$VERUS" --crate-type=lib --triggers-mode silent "$f"
done
