#!/bin/bash
# Multi-QEMU B.A.T.M.A.N. mesh test harness.
#
# Creates a 3-node linear mesh topology: A <-> B <-> C
# (A and C cannot communicate directly — only through B.)
#
# Uses a Linux bridge + TAP devices. Direct A<->C communication is
# blocked via ebtables so multi-hop routing is required.
#
# Requirements: qemu-system-x86_64, brctl/ip, ebtables, root or
# appropriate CAP_NET_ADMIN.
#
# Usage: sudo tools/run-mesh-test.sh [timeout_seconds]
set -e

TIMEOUT="${1:-60}"
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL="$ROOTDIR/target/x86_64-unknown-none/release/telix-kernel"
KERNEL32="${KERNEL}.mb32"
DISK_IMG="$ROOTDIR/test.img"

BRIDGE="br-mesh"
TAP_A="tap-mesh-a"
TAP_B="tap-mesh-b"
TAP_C="tap-mesh-c"

MAC_A="52:54:00:00:00:01"
MAC_B="52:54:00:00:00:02"
MAC_C="52:54:00:00:00:03"

LOG_A="/tmp/telix-mesh-a.log"
LOG_B="/tmp/telix-mesh-b.log"
LOG_C="/tmp/telix-mesh-c.log"

ACCEL="${TELIX_ACCEL:-tcg}"
case "$ACCEL" in
    kvm)  CPU_MODEL=host ;;
    *)    CPU_MODEL=qemu64; ACCEL=tcg ;;
esac

# -------------------------------------------------------------------
# Cleanup function.
# -------------------------------------------------------------------
cleanup() {
    echo "Cleaning up..."
    for pid in $PID_A $PID_B $PID_C; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    # Remove ebtables rules.
    ebtables -D FORWARD -i "$TAP_A" -o "$TAP_C" -j DROP 2>/dev/null || true
    ebtables -D FORWARD -i "$TAP_C" -o "$TAP_A" -j DROP 2>/dev/null || true
    # Tear down TAPs and bridge.
    for tap in "$TAP_A" "$TAP_B" "$TAP_C"; do
        ip link set "$tap" down 2>/dev/null || true
        ip link set "$tap" nomaster 2>/dev/null || true
        ip tuntap del dev "$tap" mode tap 2>/dev/null || true
    done
    ip link set "$BRIDGE" down 2>/dev/null || true
    ip link del "$BRIDGE" 2>/dev/null || true
    echo "Cleanup done."
}
trap cleanup EXIT

# -------------------------------------------------------------------
# Convert kernel to 32-bit Multiboot ELF.
# -------------------------------------------------------------------
if [ ! -f "$KERNEL" ]; then
    echo "ERROR: kernel not found at $KERNEL"
    echo "Build with: RUSTC=... cargo build --target x86_64-unknown-none --release"
    exit 1
fi
objcopy -O elf32-i386 "$KERNEL" "$KERNEL32"

# -------------------------------------------------------------------
# Create bridge + TAP devices.
# -------------------------------------------------------------------
echo "Setting up bridge $BRIDGE with TAPs..."

ip link add "$BRIDGE" type bridge 2>/dev/null || true
ip link set "$BRIDGE" up

for tap in "$TAP_A" "$TAP_B" "$TAP_C"; do
    ip tuntap add dev "$tap" mode tap 2>/dev/null || true
    ip link set "$tap" up
    ip link set "$tap" master "$BRIDGE"
done

# Block direct A<->C traffic (force multi-hop through B).
echo "Installing ebtables rules (block A<->C direct)..."
ebtables -A FORWARD -i "$TAP_A" -o "$TAP_C" -j DROP
ebtables -A FORWARD -i "$TAP_C" -o "$TAP_A" -j DROP

echo "Bridge and TAPs ready."

# -------------------------------------------------------------------
# Build QEMU command for one node.
# -------------------------------------------------------------------
run_node() {
    local name="$1" tap="$2" mac="$3" log="$4"
    local args=(
        -machine q35,accel=$ACCEL
        -cpu $CPU_MODEL
        -m 256M
        -kernel "$KERNEL32"
        -smp 2
        -nographic
        -serial file:"$log"
        -netdev tap,id=net0,ifname="$tap",script=no,downscript=no
        -device virtio-net-pci,netdev=net0,mac="$mac"
    )
    if [ -f "$DISK_IMG" ]; then
        args+=(
            -drive file="$DISK_IMG",format=raw,if=none,id=disk0,snapshot=on
            -device virtio-blk-pci,drive=disk0
        )
    fi
    echo "Starting node $name (MAC=$mac, TAP=$tap, log=$log)..."
    qemu-system-x86_64 "${args[@]}" &
    eval "PID_${name}=$!"
}

# -------------------------------------------------------------------
# Launch 3 nodes.
# -------------------------------------------------------------------
run_node A "$TAP_A" "$MAC_A" "$LOG_A"
run_node B "$TAP_B" "$MAC_B" "$LOG_B"
run_node C "$TAP_C" "$MAC_C" "$LOG_C"

echo "3 nodes launched. Waiting ${TIMEOUT}s for mesh convergence..."
sleep "$TIMEOUT"

# -------------------------------------------------------------------
# Analyse logs for mesh convergence.
# -------------------------------------------------------------------
echo ""
echo "=== Mesh Test Results ==="
echo ""

PASS=true

for node in A B C; do
    eval "log=\$LOG_${node}"
    eval "mac=\$MAC_${node}"
    echo "--- Node $node ($mac) ---"

    if grep -q "batman control channel ready" "$log"; then
        echo "  batman_srv: UP"
    else
        echo "  batman_srv: NOT STARTED"
        PASS=false
    fi

    if grep -q "registered as 'bat0'" "$log"; then
        echo "  bat0: registered"
    else
        echo "  bat0: NOT registered"
        PASS=false
    fi

    neigh=$(grep -c "new neighbor:" "$log" || true)
    echo "  Neighbors discovered: $neigh"

    orig=$(grep -c "new originator:" "$log" || true)
    echo "  Originators discovered: $orig"

    # Show neighbor MACs.
    grep "new neighbor:" "$log" | while read -r line; do
        echo "    $line"
    done

    # Show originator MACs.
    grep "new originator:" "$log" | while read -r line; do
        echo "    $line"
    done

    echo ""
done

# Node B should see 2 neighbors (A and C).
# Nodes A and C should each see 1 neighbor (B only, since A<->C is blocked).
B_NEIGH=$(grep -c "new neighbor:" "$LOG_B" || true)
A_NEIGH=$(grep -c "new neighbor:" "$LOG_A" || true)
C_NEIGH=$(grep -c "new neighbor:" "$LOG_C" || true)

echo "=== Topology Verification ==="
if [ "$B_NEIGH" -ge 2 ]; then
    echo "  Node B sees >= 2 neighbors: PASS"
else
    echo "  Node B sees $B_NEIGH neighbors (expected >= 2): FAIL"
    PASS=false
fi

if [ "$A_NEIGH" -ge 1 ]; then
    echo "  Node A sees >= 1 neighbor: PASS"
else
    echo "  Node A sees $A_NEIGH neighbors (expected >= 1): FAIL"
    PASS=false
fi

if [ "$C_NEIGH" -ge 1 ]; then
    echo "  Node C sees >= 1 neighbor: PASS"
else
    echo "  Node C sees $C_NEIGH neighbors (expected >= 1): FAIL"
    PASS=false
fi

# Nodes A and C should see each other as originators (via B).
A_ORIG=$(grep -c "new originator:" "$LOG_A" || true)
C_ORIG=$(grep -c "new originator:" "$LOG_C" || true)

if [ "$A_ORIG" -ge 1 ]; then
    echo "  Node A has >= 1 originator (multi-hop): PASS"
else
    echo "  Node A has $A_ORIG originators (expected >= 1): FAIL"
    PASS=false
fi

if [ "$C_ORIG" -ge 1 ]; then
    echo "  Node C has >= 1 originator (multi-hop): PASS"
else
    echo "  Node C has $C_ORIG originators (expected >= 1): FAIL"
    PASS=false
fi

echo ""
if $PASS; then
    echo "=== MESH TEST: PASSED ==="
else
    echo "=== MESH TEST: FAILED ==="
    echo "(Check logs: $LOG_A $LOG_B $LOG_C)"
fi
