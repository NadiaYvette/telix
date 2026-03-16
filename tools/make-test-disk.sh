#!/bin/bash
# Create a small raw disk image with known content for testing.
set -e
OUTFILE="$(dirname "$0")/../test.img"
# 1 MiB disk image
dd if=/dev/zero of="$OUTFILE" bs=512 count=2048 2>/dev/null
# Write a signature to sector 0
echo -n "TELIX_BLK_TEST_SECTOR_0" | dd of="$OUTFILE" bs=1 count=23 conv=notrunc 2>/dev/null
echo "test.img created: $(wc -c < "$OUTFILE") bytes"
