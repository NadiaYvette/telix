#!/bin/bash
# Start a netbsd-iscsi target for testing Telix iSCSI initiator.
#
# Creates a 1MB raw disk image and exports it as an iSCSI LUN.
# QEMU SLIRP forwards guest connections to 10.0.2.2:3260 → host localhost:3260.

set -e

DISK_IMG="/tmp/telix-iscsi-test.raw"
CONF="/tmp/telix-iscsi-targets.conf"
PORT=13260

# Create 1MB test disk with known pattern (for read verification).
if [ ! -f "$DISK_IMG" ]; then
    dd if=/dev/zero of="$DISK_IMG" bs=1M count=1 2>/dev/null
    # Write a known signature at sector 0.
    echo -n "TELIX_ISCSI_TEST_LUN_BLOCK0_SIG" | dd of="$DISK_IMG" bs=1 count=31 conv=notrunc 2>/dev/null
    echo "Created test disk: $DISK_IMG (1MB)"
fi

# Write target configuration.
cat > "$CONF" << 'EOF'
# Telix iSCSI test target
extent0 /tmp/telix-iscsi-test.raw 0 1MB
device0 RAID0 extent0
target0=iqn.com.example.disk rw device0 0/0
EOF

echo "Configuration:"
cat "$CONF"
echo ""

# Kill any existing target.
pkill -f "iscsi-target.*$PORT" 2>/dev/null || true
sleep 0.5

# Start target in foreground (for debugging) or background.
echo "Starting iscsi-target on port $PORT..."
if [ "${1}" = "-D" ]; then
    exec iscsi-target -4 -D -p $PORT -f "$CONF" -v all
else
    iscsi-target -4 -p $PORT -f "$CONF" &
    PID=$!
    sleep 0.5
    if kill -0 $PID 2>/dev/null; then
        echo "iscsi-target running (PID $PID)"
        echo "To stop: kill $PID"
    else
        echo "ERROR: iscsi-target failed to start"
        exit 1
    fi
fi
