#!/bin/bash
# boot-h14-pair.sh — drive TWO QEMU instances over a virtual L2 link
# (QEMU socket netdev, no host-side bridge / TAP) so the Tier-5
# clustering stack can be exercised end-to-end with two real peers.
#
# Usage:   tools/boot-h14-pair.sh [base-id]
# Example: tools/boot-h14-pair.sh                      # auto-pick id
#          tools/boot-h14-pair.sh 99amfsq545           # explicit id
#
# Both instances run the same kernel + initramfs.  They differ only
# in their MAC addresses (set in run-qemu-x86.sh's sock_listen vs
# sock_connect cases) and in their LOCAL_UUID, which discovery_srv
# generates from getrandom at startup.  Both share CLUSTER_PSK so
# they're in the same cluster.
#
# Logs land at /tmp/h14/<id>_a.log and /tmp/h14/<id>_b.log so a single
# `tail -f /tmp/h14/<id>_*.log` shows both streams interleaved.

set -e

ROOTDIR="$(cd "$(dirname "$0")" && cd .. && pwd)"
LOGDIR=/tmp/h14
mkdir -p "$LOGDIR"

if [ -n "${1:-}" ]; then
    BASE_ID="$1"
else
    LAST=$(ls "$LOGDIR" 2>/dev/null \
            | sed -n 's/.*mfsq\([0-9][0-9]*\)\.log$/\1/p' \
            | sort -n | tail -1)
    NEXT=$(( ${LAST:-0} + 1 ))
    LETTERS=$(printf "%c%c" \
        $(( 97 + ((NEXT - 1) / 26 / 10) % 26 )) \
        $(( 97 + ((NEXT - 1) / 10) % 26 )) | head -c2)
    BASE_ID="${LETTERS}amfsq${NEXT}"
fi

LOG_A="$LOGDIR/${BASE_ID}_a.log"
LOG_B="$LOGDIR/${BASE_ID}_b.log"
SOCK_PORT="${TELIX_NET_PORT:-7710}"
TIMEOUT="${TELIX_BOOT_TIMEOUT:-1500}"
ACCEL="${TELIX_ACCEL:-kvm}"

if [ -z "${TELIX_SKIP_BUILD:-}" ]; then
    echo "  [boot-h14-pair] building kernel + userspace..."
    "$ROOTDIR/tools/build-kernel.sh" x86_64 --release > /tmp/h14/.lastbuild.log 2>&1 \
        || { echo "  [boot-h14-pair] build FAILED — see /tmp/h14/.lastbuild.log"; exit 1; }
fi

KERNEL="$ROOTDIR/target/x86_64-unknown-none/release/telix-kernel"
[ -f "$KERNEL" ] || { echo "  [boot-h14-pair] kernel not found at $KERNEL"; exit 1; }

START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[pair $BASE_ID start] $START_TS sock_port=$SOCK_PORT" > "$LOG_A"
echo "[pair $BASE_ID start] $START_TS sock_port=$SOCK_PORT" > "$LOG_B"

# Launch instance A first (it's the listener — the second instance
# connects to it).  Use distinct serial ssh-fwd ports so the two
# QEMUs can coexist on the host.
echo "  [boot-h14-pair] launching instance A on socket :$SOCK_PORT (listener)..."
TELIX_ACCEL="$ACCEL" \
TELIX_NET=sock_listen \
TELIX_NET_PORT="$SOCK_PORT" \
TELIX_SSH_PORT="3232" \
TELIX_GDB_PORT="3244" \
timeout --foreground "${TIMEOUT}" \
    "$ROOTDIR/tools/run-qemu-x86.sh" "$KERNEL" >> "$LOG_A" 2>&1 &
PID_A=$!

# Give A a moment to bind the listening socket.
sleep 1

echo "  [boot-h14-pair] launching instance B (connector)..."
TELIX_ACCEL="$ACCEL" \
TELIX_NET=sock_connect \
TELIX_NET_PORT="$SOCK_PORT" \
TELIX_NET_HOST="127.0.0.1" \
TELIX_SSH_PORT="3233" \
TELIX_GDB_PORT="3245" \
timeout --foreground "${TIMEOUT}" \
    "$ROOTDIR/tools/run-qemu-x86.sh" "$KERNEL" >> "$LOG_B" 2>&1 &
PID_B=$!

echo "  [boot-h14-pair] A=$PID_A B=$PID_B (timeout ${TIMEOUT}s)"
echo "  [boot-h14-pair] logs: $LOG_A and $LOG_B"

wait "$PID_A"
RC_A=$?
wait "$PID_B"
RC_B=$?

END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[pair $BASE_ID end exit_a=$RC_A exit_b=$RC_B] $END_TS" >> "$LOG_A"
echo "[pair $BASE_ID end exit_a=$RC_A exit_b=$RC_B] $END_TS" >> "$LOG_B"

echo "  [boot-h14-pair] $BASE_ID exit_a=$RC_A exit_b=$RC_B"
exit $(( RC_A != 0 ? RC_A : RC_B ))
