#!/bin/sh
# verus/drift-guard.sh — keep the standalone Verus proofs honest against the real kernel code.
#
# The in-tree Verus modules (verus/*.rs) are verified STANDALONE (Verus's pinned rustc cannot
# compile the edition-2024 no_std kernel crate — see verus/INTEGRATION.md), so a proof's struct
# defs / method bodies are verbatim copies of the real `mm/` source. This guard fails if a
# real function wrapped in `// VERUS-MIRROR-BEGIN <name>` … `// VERUS-MIRROR-END <name>` markers
# has changed since its proof was last verified — forcing a deliberate re-verify + baseline bump.
#
# Usage:
#   verus/drift-guard.sh            # CI check: fail on drift
#   verus/drift-guard.sh --update   # record the current regions as the verified baseline
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KSRC="$ROOT/kernel/src"
BASELINE="$ROOT/verus/mirror-baseline.sha256"
CUR="$(mktemp)"
trap 'rm -f "$CUR"' EXIT

# Emit "<region-name>  <sha256-of-body>" for every marked region, sorted by name.
for f in $(grep -rl 'VERUS-MIRROR-BEGIN' "$KSRC" 2>/dev/null | sort); do
  for name in $(sed -n 's|.*VERUS-MIRROR-BEGIN \([A-Za-z0-9_]*\).*|\1|p' "$f"); do
    body="$(awk -v n="$name" '
      index($0, "VERUS-MIRROR-BEGIN " n) { cap=1; next }
      index($0, "VERUS-MIRROR-END " n)   { cap=0 }
      cap { print }
    ' "$f")"
    h="$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)"
    printf '%s  %s  %s\n' "$name" "$h" "${f#"$ROOT"/}"
  done
done | sort > "$CUR"

if [ "${1:-check}" = "--update" ]; then
  cp "$CUR" "$BASELINE"
  echo "drift-guard: baseline updated — $(wc -l < "$BASELINE" | tr -d ' ') mirrored region(s)."
  exit 0
fi

if [ ! -f "$BASELINE" ]; then
  echo "drift-guard: no baseline at verus/mirror-baseline.sha256."
  echo "  After verifying (verus/verify-intree.sh), run: verus/drift-guard.sh --update"
  exit 1
fi

if diff "$BASELINE" "$CUR" >/dev/null 2>&1; then
  echo "drift-guard: OK — $(wc -l < "$CUR" | tr -d ' ') mirrored region(s) match the verified baseline."
  exit 0
fi

echo "drift-guard: DRIFT DETECTED — a Verus-mirrored kernel region changed since it was proved:"
echo
diff "$BASELINE" "$CUR" 2>/dev/null | sed 's/^/    /' || true
echo
echo "A function proved standalone in verus/*.rs no longer matches mm/. Either the change is"
echo "semantics-preserving (re-run verus/verify-intree.sh to confirm the proof still holds) or"
echo "it changed the logic (update the proof, re-verify). Then: verus/drift-guard.sh --update"
exit 1
