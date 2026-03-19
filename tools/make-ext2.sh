#!/bin/bash
# Append a 16 MiB ext2 partition to test.img after the FAT16 region.
# The ext2 region starts at byte offset 16777216 (sector 32768).
# Requires: e2fsprogs (mke2fs), debugfs or e2tools or fuse2fs
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"

# Ensure FAT16 portion exists (should be 16 MiB from make-fat16.sh).
if [ ! -f "$DISK_IMG" ]; then
    echo "ERROR: $DISK_IMG not found. Run make-fat16.sh first."
    exit 1
fi

FAT16_SIZE=$((16 * 1024 * 1024))
EXT2_SIZE=$((16 * 1024 * 1024))
TOTAL_SIZE=$((FAT16_SIZE + EXT2_SIZE))

# Truncate to include both partitions.
truncate -s "$TOTAL_SIZE" "$DISK_IMG"

# Create a temporary ext2 image.
EXT2_TMP=$(mktemp)
dd if=/dev/zero of="$EXT2_TMP" bs=1M count=16 2>/dev/null

# Format as ext2: 1024-byte blocks, 128-byte inodes, no journal.
mke2fs -t ext2 -b 1024 -I 128 -F -q "$EXT2_TMP"

# Populate with test files using debugfs and temp files.
TMPFILE=$(mktemp)
echo -n "Hello from ext2!" > "$TMPFILE"

TMPFILE2=$(mktemp)
python3 -c "import sys; sys.stdout.buffer.write(bytes(range(256)) * 4)" > "$TMPFILE2"

TMPFILE3=$(mktemp)
echo -n "File with restricted permissions" > "$TMPFILE3"

# Use debugfs to populate the filesystem.
debugfs -w "$EXT2_TMP" <<DEBUGFS_EOF
mkdir testdir
write $TMPFILE hello.txt
write $TMPFILE2 bench.dat
write $TMPFILE3 secret.txt
set_inode_field hello.txt mode 0100644
set_inode_field hello.txt uid 1000
set_inode_field hello.txt gid 1000
set_inode_field bench.dat mode 0100644
set_inode_field bench.dat uid 0
set_inode_field bench.dat gid 0
set_inode_field secret.txt mode 0100600
set_inode_field secret.txt uid 0
set_inode_field secret.txt gid 0
set_inode_field testdir mode 040755
set_inode_field testdir uid 1000
set_inode_field testdir gid 1000
DEBUGFS_EOF

rm -f "$TMPFILE" "$TMPFILE2" "$TMPFILE3"

# Splice the ext2 image into test.img at the FAT16 boundary.
dd if="$EXT2_TMP" of="$DISK_IMG" bs=1M seek=16 conv=notrunc 2>/dev/null
rm -f "$EXT2_TMP"

echo "  ext2 partition appended to test.img at offset $FAT16_SIZE ($((EXT2_SIZE / 1024)) KiB ext2)"
