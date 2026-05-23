#!/bin/bash
# boot-h14.sh — drive a single H13/H14 boot under QEMU + KVM and capture
# the serial output to /tmp/h14/{id}.log with start/end marker lines so
# log-bisection scripts can find boot boundaries.
#
# Usage:   tools/boot-h14.sh [id]
# Examples:
#   tools/boot-h14.sh                 # auto-pick id from /tmp/h14 sequence
#   tools/boot-h14.sh aa9mfsq400      # explicit id
#
# Env knobs:
#   TELIX_BOOT_TIMEOUT  — seconds, default 1500
#   TELIX_SKIP_BUILD    — set to non-empty to skip kernel rebuild
#   TELIX_ACCEL         — passed through to run-qemu-x86.sh; default kvm
#                         (KVM is required — TCG deadlocks the kernel
#                         timer, per feedback_kvm_required.md)
#   TELIX_BOOT_SLOT     — integer offset (default 0) for host port
#                         allocation.  SSH port = 3222 + SLOT;
#                         GDB port = 3234 + SLOT.  Use distinct slots
#                         when launching parallel boots so they don't
#                         collide on host TCP forwarding.  See
#                         tools/boot-h14-multi.sh for the wrapper.

set -e

ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
LOGDIR=/tmp/h14
mkdir -p "$LOGDIR"

# Pick a fresh id if not supplied: bump the highest existing NNN-suffix
# in the dir.  Naming convention "<letters><digit>mfsq<NNN>" is whatever
# we used in earlier sessions; we keep the trailing NNN strictly
# increasing so chronological log greps stay obvious.
if [ -n "${1:-}" ]; then
    ID="$1"
else
    LAST=$(ls "$LOGDIR" 2>/dev/null \
            | sed -n 's/.*mfsq\([0-9][0-9]*\)\.log$/\1/p' \
            | sort -n | tail -1)
    NEXT=$(( ${LAST:-0} + 1 ))
    # Two-letter prefix advances every 10 NNN (cosmetic, for grep
    # clustering by phase of work).
    LETTERS=$(printf "%c%c" \
        $(( 97 + ((NEXT - 1) / 26 / 10) % 26 )) \
        $(( 97 + ((NEXT - 1) / 10) % 26 )) | head -c2)
    ID="${LETTERS}amfsq${NEXT}"
fi

LOGFILE="$LOGDIR/${ID}.log"
TIMEOUT="${TELIX_BOOT_TIMEOUT:-1500}"
ACCEL="${TELIX_ACCEL:-kvm}"

# Per-slot host-port assignment so parallel boots don't collide on
# port 3222 / 3234.  See boot-h14-multi.sh for the orchestrator that
# uses this.
SLOT="${TELIX_BOOT_SLOT:-0}"
export TELIX_SSH_PORT="$((3222 + SLOT))"
export TELIX_GDB_PORT="$((3234 + SLOT))"

if [ -z "${TELIX_SKIP_BUILD:-}" ]; then
    echo "  [boot-h14] building kernel + userspace..."
    "$ROOTDIR/tools/build-kernel.sh" x86_64 --release > /tmp/h14/.lastbuild.log 2>&1 \
        || { echo "  [boot-h14] build FAILED — see /tmp/h14/.lastbuild.log"; exit 1; }
fi

KERNEL="$ROOTDIR/target/x86_64-unknown-none/release/telix-kernel"
[ -f "$KERNEL" ] || { echo "  [boot-h14] kernel not found at $KERNEL"; exit 1; }

START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[boot $ID start] $START_TS" > "$LOGFILE"

# QEMU exits 124 on timeout (matches GNU `timeout`'s exit code).
ID="$ID" TELIX_ACCEL="$ACCEL" timeout --foreground "${TIMEOUT}" \
    "$ROOTDIR/tools/run-qemu-x86.sh" "$KERNEL" >> "$LOGFILE" 2>&1
RC=$?

END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[boot $ID end exit=$RC] $END_TS" >> "$LOGFILE"

echo "  [boot-h14] $ID exit=$RC log=$LOGFILE"
exit $RC
