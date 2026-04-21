#!/bin/bash
# Create a test disk image with FAT16 partition at 1 MiB offset.
# The first 1 MiB is reserved for GPT structures (written by make-gpt.sh).
# Requires: dosfstools (mkfs.fat), mtools (mcopy)
set -e
OUTFILE="$(dirname "$0")/../test.img"

GPT_RESERVED=$((1 * 1024 * 1024))   # 1 MiB for GPT header + entries
FAT16_SIZE=$((16 * 1024 * 1024))     # 16 MiB FAT16 partition
TOTAL_SIZE=$((GPT_RESERVED + FAT16_SIZE))

# Create disk image with space for GPT + FAT16.
dd if=/dev/zero of="$OUTFILE" bs=1M count=$((TOTAL_SIZE / 1024 / 1024)) 2>/dev/null

# Create FAT16 in a temporary image, then splice it in at 1 MiB.
FAT16_TMP=$(mktemp)
dd if=/dev/zero of="$FAT16_TMP" bs=512 count=32768 2>/dev/null
mkfs.fat -F 16 -f 1 -s 4 -S 512 "$FAT16_TMP"

# Create test file and copy it into the FAT16 image.
TMPFILE=$(mktemp)
echo -n "Hello from FAT16!" > "$TMPFILE"
mcopy -i "$FAT16_TMP" "$TMPFILE" ::HELLO.TXT
rm -f "$TMPFILE"

# Create 32 KB benchmark data file (repeating 0x00-0xFF pattern).
BENCHFILE=$(mktemp)
python3 -c "import sys; sys.stdout.buffer.write(bytes(range(256)) * 128)" > "$BENCHFILE"
mcopy -i "$FAT16_TMP" "$BENCHFILE" ::BENCH.DAT
rm -f "$BENCHFILE"

# Optionally copy a hello ELF binary for exec-from-filesystem testing.
# Usage: make-fat16.sh [target-triple]
# e.g.:  make-fat16.sh x86_64-unknown-none
if [ -n "$1" ]; then
    HELLO_BIN="$(dirname "$0")/../target/$1/release/hello"
    if [ -f "$HELLO_BIN" ]; then
        mcopy -i "$FAT16_TMP" "$HELLO_BIN" ::HELLO.ELF
        echo "  Copied hello binary as HELLO.ELF ($(wc -c < "$HELLO_BIN") bytes)"
    fi
fi

# Splice FAT16 into disk image at 1 MiB offset.
dd if="$FAT16_TMP" of="$OUTFILE" bs=1M seek=1 conv=notrunc 2>/dev/null
rm -f "$FAT16_TMP"

echo "test.img created: $(wc -c < "$OUTFILE") bytes (FAT16 at 1 MiB)"
