#!/bin/bash
# Create a test UDF image and append it to test.img at 35 MiB offset.
# Layout: 1 MiB GPT + 16 MiB FAT16 + 16 MiB ext2 + 2 MiB gap + 2 MiB UDF.
# Requires: genisoimage (or mkisofs)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"

if [ ! -f "$DISK_IMG" ]; then
    echo "ERROR: $DISK_IMG not found. Run make-fat16.sh / make-ext2.sh first."
    exit 1
fi

UDF_OFFSET=$((35 * 1024 * 1024))
UDF_SIZE=$((2 * 1024 * 1024))  # Reserve 2 MiB for UDF
TOTAL_SIZE=$((UDF_OFFSET + UDF_SIZE))

# Extend disk image to include UDF region.
truncate -s "$TOTAL_SIZE" "$DISK_IMG"

# Create temp directory with test content.
UDF_TMP=$(mktemp -d)
mkdir -p "$UDF_TMP/sub"
echo -n "Hello from UDF!" > "$UDF_TMP/hello.txt"
echo -n "Nested UDF file" > "$UDF_TMP/sub/deep.txt"
echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZ" > "$UDF_TMP/alpha.txt"

# Generate UDF image.
UDF_IMG=$(mktemp)
genisoimage -udf -quiet -o "$UDF_IMG" "$UDF_TMP" 2>/dev/null

# Splice the UDF into test.img at 35 MiB offset.
dd if="$UDF_IMG" of="$DISK_IMG" bs=1M seek=$((UDF_OFFSET / 1024 / 1024)) conv=notrunc 2>/dev/null

UDF_ACTUAL_SIZE=$(stat -c %s "$UDF_IMG")
echo "  UDF image appended to test.img at offset $UDF_OFFSET ($((UDF_ACTUAL_SIZE / 1024)) KiB UDF)"

rm -rf "$UDF_TMP" "$UDF_IMG"
