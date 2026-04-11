#!/bin/bash
# Create a test XFS image and append it to test.img at 36 MiB offset.
# The XFS region starts at byte offset 37748736.
# Requires: xfsprogs (mkfs.xfs); needs 300 MiB minimum for mkfs.xfs 6.x.
# Uses mkfs.xfs -p (protofile) to populate without needing root.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"

if [ ! -f "$DISK_IMG" ]; then
    echo "ERROR: $DISK_IMG not found. Run earlier make-*.sh scripts first."
    exit 1
fi

XFS_OFFSET=$((36 * 1024 * 1024))
XFS_SIZE=$((300 * 1024 * 1024))  # 300 MiB (mkfs.xfs 6.x minimum)
TOTAL_SIZE=$((XFS_OFFSET + XFS_SIZE))

# Extend disk image to include XFS region.
truncate -s "$TOTAL_SIZE" "$DISK_IMG"

# Create temporary files for content.
PROTO_DIR=$(mktemp -d)
echo -n "Hello from XFS!" > "$PROTO_DIR/hello.txt"
mkdir -p "$PROTO_DIR/subdir"
echo -n "Nested XFS file." > "$PROTO_DIR/subdir/nested.txt"
echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz" > "$PROTO_DIR/alpha.txt"

# Create protofile for mkfs.xfs -p.
PROTO_FILE="$PROTO_DIR/proto"
cat > "$PROTO_FILE" <<EOF
/
0 0
d--755 0 0
hello.txt ---644 0 0 $PROTO_DIR/hello.txt
alpha.txt ---644 0 0 $PROTO_DIR/alpha.txt
subdir d--755 0 0
nested.txt ---644 0 0 $PROTO_DIR/subdir/nested.txt
\$
\$
EOF

# Create temporary XFS image.
XFS_TMP=$(mktemp)
dd if=/dev/zero of="$XFS_TMP" bs=1M count=300 2>/dev/null

# Format as XFS v5 with protofile to populate files.
if ! mkfs.xfs -f -b size=4096 -m crc=1 -p file="$PROTO_FILE" "$XFS_TMP" >/dev/null 2>&1; then
    echo "  WARNING: mkfs.xfs failed, skipping XFS image"
    rm -rf "$PROTO_DIR" "$XFS_TMP"
    exit 0
fi

rm -rf "$PROTO_DIR"

# Append to disk image.
dd if="$XFS_TMP" of="$DISK_IMG" bs=1M seek=$((XFS_OFFSET / 1024 / 1024)) conv=notrunc 2>/dev/null
XFS_ACTUAL=$(wc -c < "$XFS_TMP")
rm -f "$XFS_TMP"

echo "  XFS image appended to test.img at offset $XFS_OFFSET ($((XFS_ACTUAL / 1024 / 1024)) MiB XFS)"
