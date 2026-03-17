#!/bin/bash
# Create a 1 MiB FAT16-formatted test disk image with a test file.
# Requires: dosfstools (mkfs.fat), mtools (mcopy)
set -e
OUTFILE="$(dirname "$0")/../test.img"

# 16 MiB = 32768 sectors of 512 bytes (minimum viable FAT16 size)
dd if=/dev/zero of="$OUTFILE" bs=512 count=32768 2>/dev/null

# Format as FAT16: 1 FAT copy, 4 sectors per cluster, 512-byte sectors
mkfs.fat -F 16 -f 1 -s 4 -S 512 "$OUTFILE"

# Create test file and copy it into the FAT16 image
TMPFILE=$(mktemp)
echo -n "Hello from FAT16!" > "$TMPFILE"
mcopy -i "$OUTFILE" "$TMPFILE" ::HELLO.TXT
rm -f "$TMPFILE"

echo "test.img created: $(wc -c < "$OUTFILE") bytes (FAT16, contains HELLO.TXT)"
