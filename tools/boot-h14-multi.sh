#!/bin/bash
# boot-h14-multi.sh — orchestrate N parallel boot-h14.sh instances.
#
# Builds the kernel ONCE, then spawns N boots with distinct slot
# assignments so they don't collide on host port 3222.  Each boot
# writes to its own /tmp/h14/<ID>.log.
#
# Usage:
#   tools/boot-h14-multi.sh [--cleanup] <N>
#
# Examples:
#   tools/boot-h14-multi.sh 4              # 4 parallel boots
#   tools/boot-h14-multi.sh --cleanup 4    # kill stale Telix qemus first
#
# --cleanup matches ONLY qemus using THIS tree's kernel binary path
# (i.e. $ROOTDIR/target/.../telix-kernel.mb32), so other Telix trees
# / other developers / parallel Linux-kernel work are not touched.

set -e

ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
LOGDIR=/tmp/h14
mkdir -p "$LOGDIR"

CLEANUP=0
if [ "${1:-}" = "--cleanup" ]; then
    CLEANUP=1
    shift
fi

N="${1:?Usage: boot-h14-multi.sh [--cleanup] <count>}"

if ! [[ "$N" =~ ^[1-9][0-9]*$ ]]; then
    echo "  [multi] count must be a positive integer, got: $N" >&2
    exit 1
fi

KERNEL="$ROOTDIR/target/x86_64-unknown-none/release/telix-kernel"
KERNEL_PATTERN="${KERNEL}.mb32"

if [ "$CLEANUP" = "1" ]; then
    if pgrep -f "$KERNEL_PATTERN" >/dev/null 2>&1; then
        echo "  [multi] killing stale qemus using $KERNEL_PATTERN"
        pkill -TERM -f "$KERNEL_PATTERN" 2>/dev/null || true
        sleep 2
        pkill -KILL -f "$KERNEL_PATTERN" 2>/dev/null || true
    else
        echo "  [multi] --cleanup: no stale qemus to kill"
    fi
fi

# Build ONCE here, then tell each boot-h14.sh to skip its own rebuild.
# Without this, N parallel boots would race on the build dir.
if [ -z "${TELIX_SKIP_BUILD:-}" ]; then
    echo "  [multi] building kernel + userspace (once)..."
    "$ROOTDIR/tools/build-kernel.sh" x86_64 --release > "$LOGDIR/.lastbuild.log" 2>&1 \
        || { echo "  [multi] build FAILED — see $LOGDIR/.lastbuild.log"; exit 1; }
fi
export TELIX_SKIP_BUILD=1

PIDS=()
for ((i=0; i<N; i++)); do
    TELIX_BOOT_SLOT="$i" "$ROOTDIR/tools/boot-h14.sh" &
    PIDS+=($!)
    # Brief stagger to reduce log-id collisions and avoid simultaneous
    # qemu launches stepping on each other during early init.
    sleep 0.3
done

echo "  [multi] launched $N boots, PIDs: ${PIDS[*]}"

FAILED=0
for pid in "${PIDS[@]}"; do
    if ! wait "$pid"; then
        FAILED=$((FAILED + 1))
    fi
done

echo "  [multi] done.  failed=$FAILED / total=$N"
exit "$FAILED"
