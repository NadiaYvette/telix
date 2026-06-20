#!/bin/bash
# run-loom.sh — run a loom concurrency model (or all of them) in isolation.
#
# WHY THIS EXISTS: the loom crates live under tests/loom-*/ inside the telix
# workspace, but the workspace .cargo/config.toml pins target=aarch64-unknown-none
# + build-std=["core"].  Those leak into a plain `cargo test` even with the loom
# crate's own .cargo/config override, producing "duplicate lang item core" errors.
# The robust fix is to run each loom crate from a temp dir OUTSIDE the workspace
# tree, where no parent .cargo/config applies.  (Discovered 2026-06-20 while
# authoring tests/loom-spawn-publish; see project_228_allocator_double_issue.)
#
# Usage:
#   tools/run-loom.sh                 # run all tests/loom-* crates
#   tools/run-loom.sh spawn-publish   # run tests/loom-spawn-publish only
#   tools/run-loom.sh loom-turnstile  # leading "loom-" optional
# Env:
#   LOOM_MAX_PREEMPTIONS (default 3)  # loom interleaving depth
#   TELIX_LOOM_CORES (default 0-9,11-13)  # taskset cpuset
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORES="${TELIX_LOOM_CORES:-0-9,11-13}"
PRE="${LOOM_MAX_PREEMPTIONS:-3}"
TMPROOT="$(mktemp -d /tmp/telix-loom.XXXXXX)"
trap 'rm -rf "$TMPROOT"' EXIT

run_one() {
  local dir="$1" name
  name="$(basename "$dir")"
  [ -f "$dir/Cargo.toml" ] || { echo "SKIP $name (no Cargo.toml)"; return 0; }
  local work="$TMPROOT/$name"
  mkdir -p "$work"
  # Copy only the crate sources (not target/) into the isolated dir.
  cp -r "$dir/src" "$work/src" 2>/dev/null
  cp "$dir/Cargo.toml" "$work/Cargo.toml"
  [ -f "$dir/Cargo.lock" ] && cp "$dir/Cargo.lock" "$work/Cargo.lock"
  local log="$TMPROOT/$name.log"
  ( cd "$work" && RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS="$PRE" \
      taskset -c "$CORES" cargo test --release ) >"$log" 2>&1
  local rc=$?
  local res
  # Report the UNIT-test result (first "test result:" line); the trailing one
  # is the 0-test doc-test suite and would misleadingly read "0 passed".
  res="$(grep -aE '^test result:' "$log" | head -1)"
  if [ $rc -eq 0 ]; then
    echo "PASS $name — ${res:-(no test result line)}"
  else
    echo "FAIL $name (rc=$rc) — ${res:-see log}"
    grep -aE '^error|panicked|assertion|test result:' "$log" | head -8 | sed 's/^/    /'
  fi
  return $rc
}

sel="${1:-}"
fail=0
if [ -z "$sel" ]; then
  for d in "$ROOT"/tests/loom-*/; do run_one "$d" || fail=1; done
else
  d="$ROOT/tests/$sel"
  [ -d "$d" ] || d="$ROOT/tests/loom-$sel"
  [ -d "$d" ] || { echo "no such loom crate: $sel (looked in tests/$sel and tests/loom-$sel)"; exit 2; }
  run_one "$d" || fail=1
fi
exit $fail
