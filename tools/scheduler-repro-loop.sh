#!/bin/bash
# scheduler-repro-loop.sh — accumulate kernel scheduler-stall data.
#
# Runs the H13 boot in a tight loop with the FOCUS_H13 skip set,
# archives each log under /tmp/sched-runs/run-NN.log, and writes a
# rolling /tmp/sched-runs/SUMMARY.txt of where each run got stuck +
# how many WATCHDOG fires per run + the latest pre-stall Phase /
# Step marker.  Designed to be killed at any point — partial data
# is still useful.
#
# Usage:  tools/scheduler-repro-loop.sh
set -e
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTDIR="/tmp/sched-runs"
mkdir -p "$OUTDIR"
KERNEL="$ROOTDIR/target/x86_64-unknown-none/release/telix-kernel"
SUMMARY="$OUTDIR/SUMMARY.txt"

# Find next run number.
N=$(ls "$OUTDIR"/run-*.log 2>/dev/null | wc -l)

while :; do
    N=$((N+1))
    LOG="$OUTDIR/run-$(printf '%03d' "$N").log"
    echo "=== run $N starting at $(date +%H:%M:%S) → $LOG"

    # Make sure no leftover QEMU on port 3222.
    pkill -f qemu-system-x86_64 2>/dev/null || true
    sleep 2

    timeout 1500 env TELIX_ACCEL=kvm "$ROOTDIR/tools/run-qemu-x86.sh" "$KERNEL" > "$LOG" 2>&1 || true

    # Extract per-run summary.
    LAST_PHASE=$(grep -aE "^(Phase|Step) " "$LOG" | tail -n 1 || true)
    WD_COUNT=$(grep -caE "^WATCHDOG: IPC stall" "$LOG" || true)
    LINES=$(wc -l < "$LOG")
    H13_RESULT=$(grep -aE "^Step H13" "$LOG" | tail -n 1 || true)
    XW_BANNER=$(grep -aE "X.Org Foundation Xwayland|Could not write pid|Fatal server error" "$LOG" | head -n 1 || true)

    {
        echo "[run $(printf '%03d' "$N")] lines=$LINES wd=$WD_COUNT"
        echo "  last marker: $LAST_PHASE"
        [ -n "$H13_RESULT" ] && echo "  $H13_RESULT"
        [ -n "$XW_BANNER" ]  && echo "  xwayland: $XW_BANNER"
    } >> "$SUMMARY"

    sleep 2
done
