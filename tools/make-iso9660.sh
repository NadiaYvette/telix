#!/bin/bash
# Create a test ISO 9660 image and append it to test.img at 32 MiB offset.
# The ISO region starts at byte offset 33554432.
# Requires: genisoimage (or mkisofs)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"

if [ ! -f "$DISK_IMG" ]; then
    echo "ERROR: $DISK_IMG not found. Run make-fat16.sh / make-ext2.sh first."
    exit 1
fi

ISO_OFFSET=$((32 * 1024 * 1024))
ISO_SIZE=$((1 * 1024 * 1024))  # Reserve 1 MiB for ISO
TOTAL_SIZE=$((ISO_OFFSET + ISO_SIZE))

# Extend disk image to include ISO region.
truncate -s "$TOTAL_SIZE" "$DISK_IMG"

# Create temp directory with test content.
ISO_TMP=$(mktemp -d)
mkdir -p "$ISO_TMP/sub"
echo -n "Hello from ISO 9660!" > "$ISO_TMP/hello.txt"
echo -n "Nested file content" > "$ISO_TMP/sub/deep.txt"
echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZ" > "$ISO_TMP/alpha.txt"

# Generate ISO 9660 image with Rock Ridge extensions.
ISO_IMG=$(mktemp)
genisoimage -R -quiet -o "$ISO_IMG" "$ISO_TMP" 2>/dev/null

# Splice the ISO into test.img at 32 MiB offset.
dd if="$ISO_IMG" of="$DISK_IMG" bs=1M seek=32 conv=notrunc 2>/dev/null

ISO_ACTUAL_SIZE=$(stat -c %s "$ISO_IMG")
echo "  ISO 9660 image appended to test.img at offset $ISO_OFFSET ($((ISO_ACTUAL_SIZE / 1024)) KiB ISO)"

rm -rf "$ISO_TMP" "$ISO_IMG"
