#!/usr/bin/env bash
# verus/verify-intree.sh — the single CI entry point for telix's in-tree Verus verification.
#
# Runs the PINNED Verus over the in-tree proof modules, AND the drift-guard that ties those
# (standalone) proofs to the real mm/ source. Verification is standalone because Verus's pinned
# rustc cannot compile the edition-2024 no_std kernel crate — see verus/INTEGRATION.md (the shape)
# and verus/TOOLCHAIN.md (the version coupling). The kernel's own `cargo build` is a separate,
# independent CI job and is unaffected by any of this.
#
#   verus/verify-intree.sh         # verify + drift-guard (CI)
#
# Env: VERUS=/path/to/verus to override the binary location.
set -euo pipefail
cd "$(dirname "$0")"

VERUS="${VERUS:-$HOME/verus/verus-x86-linux/verus}"
VERUS_PIN="0.2026.06.20"   # see TOOLCHAIN.md; bump deliberately (tessera green-lights specs, then telix)

echo "== telix in-tree Verus verification =="
if [ ! -x "$VERUS" ]; then
  echo "FAIL: verus binary not found at '$VERUS' (set VERUS=...). See TOOLCHAIN.md for the pinned release." >&2
  exit 1
fi
ver="$("$VERUS" --version 2>/dev/null | sed -n 's/.*Version:[[:space:]]*//p' | head -1)"
[ -n "$ver" ] || ver="$("$VERUS" --version 2>/dev/null | head -1)"
echo "verus: $ver"
case "$ver" in
  "$VERUS_PIN"*) echo "pin:   $VERUS_PIN (match)";;
  *) echo "pin:   $VERUS_PIN  *** WARNING: running Verus does not match the pinned version ***";;
esac

echo
echo "-- 1/2  drift-guard: proofs vs real mm/ source --"
./drift-guard.sh

echo
echo "-- 2/2  verify proof modules --"
./verify.sh

echo
echo "== in-tree Verus verification PASSED =="
