#!/bin/bash
# Create a test APFS image and append it to test.img at 337 MiB offset.
# Layout: after XFS at 37+300 MiB = 337 MiB.
# Requires: mkapfs from linux-apfsprogs (~/src/apfsprogs/mkapfs/mkapfs).
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"
MKAPFS="${MKAPFS:-$HOME/src/apfsprogs/mkapfs/mkapfs}"

if [ ! -f "$DISK_IMG" ]; then
    echo "ERROR: $DISK_IMG not found. Run earlier make-*.sh scripts first."
    exit 1
fi

if [ ! -x "$MKAPFS" ]; then
    echo "  WARNING: mkapfs not found at $MKAPFS, skipping APFS image"
    exit 0
fi

APFS_OFFSET=$((337 * 1024 * 1024))
APFS_SIZE=$((32 * 1024 * 1024))  # 32 MiB
TOTAL_SIZE=$((APFS_OFFSET + APFS_SIZE))

# Extend disk image to include APFS region.
truncate -s "$TOTAL_SIZE" "$DISK_IMG"

# Create temporary APFS image.
APFS_TMP=$(mktemp)
dd if=/dev/zero of="$APFS_TMP" bs=1M count=32 2>/dev/null

# Format as APFS with a volume labelled "TestVol".
if ! "$MKAPFS" -L TestVol "$APFS_TMP" 2>/dev/null; then
    echo "  WARNING: mkapfs failed, skipping APFS image"
    rm -f "$APFS_TMP"
    exit 0
fi

# Splice the APFS image into test.img at the correct offset.
dd if="$APFS_TMP" of="$DISK_IMG" bs=1M seek=$((APFS_OFFSET / 1024 / 1024)) conv=notrunc 2>/dev/null
APFS_ACTUAL=$(wc -c < "$APFS_TMP")
rm -f "$APFS_TMP"

echo "  APFS image appended to test.img at offset $APFS_OFFSET ($((APFS_ACTUAL / 1024 / 1024)) MiB APFS)"
