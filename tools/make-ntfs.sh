#!/bin/bash
# Create a test NTFS image and append it to test.img at 369 MiB offset.
# Layout: after APFS at 337+32 MiB = 369 MiB.
# Requires: mkntfs from ntfs-3g (ntfsprogs).
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"

if [ ! -f "$DISK_IMG" ]; then
    echo "ERROR: $DISK_IMG not found. Run earlier make-*.sh scripts first."
    exit 1
fi

if ! command -v mkntfs >/dev/null 2>&1; then
    echo "  WARNING: mkntfs not found, skipping NTFS image"
    exit 0
fi

NTFS_OFFSET=$((369 * 1024 * 1024))
NTFS_SIZE=$((32 * 1024 * 1024))  # 32 MiB
TOTAL_SIZE=$((NTFS_OFFSET + NTFS_SIZE))

# Extend disk image to include NTFS region.
truncate -s "$TOTAL_SIZE" "$DISK_IMG"

# Create temporary NTFS image.
NTFS_TMP=$(mktemp)
dd if=/dev/zero of="$NTFS_TMP" bs=1M count=32 2>/dev/null

# Format as NTFS with label "TelixNTFS".
if ! mkntfs -F -L TelixNTFS -s 512 -c 4096 "$NTFS_TMP" >/dev/null 2>&1; then
    echo "  WARNING: mkntfs failed, skipping NTFS image"
    rm -f "$NTFS_TMP"
    exit 0
fi

# Mount and populate with test files using ntfs-3g if available,
# otherwise use ntfscp if available.
NTFS_MNT=$(mktemp -d)
POPULATED=false

# Try ntfs-3g mount (may require fuse/root).
if command -v ntfs-3g >/dev/null 2>&1; then
    if ntfs-3g -o no_def_opts,silent "$NTFS_TMP" "$NTFS_MNT" 2>/dev/null; then
        echo -n "Hello from NTFS!" > "$NTFS_MNT/hello.txt"
        mkdir -p "$NTFS_MNT/subdir"
        echo -n "Nested NTFS file." > "$NTFS_MNT/subdir/nested.txt"
        echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz" > "$NTFS_MNT/alpha.txt"
        fusermount -u "$NTFS_MNT" 2>/dev/null || umount "$NTFS_MNT" 2>/dev/null || true
        POPULATED=true
    fi
fi

# Fallback: ntfscp (doesn't need mount).
if [ "$POPULATED" = "false" ] && command -v ntfscp >/dev/null 2>&1; then
    TMPF=$(mktemp)
    echo -n "Hello from NTFS!" > "$TMPF"
    ntfscp "$NTFS_TMP" "$TMPF" hello.txt >/dev/null 2>&1 && POPULATED=true
    echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz" > "$TMPF"
    ntfscp "$NTFS_TMP" "$TMPF" alpha.txt >/dev/null 2>&1 || true
    rm -f "$TMPF"
fi

if [ "$POPULATED" = "false" ]; then
    echo "  (NTFS image formatted but no test files added — ntfs-3g/ntfscp unavailable)"
fi

rmdir "$NTFS_MNT" 2>/dev/null || true

# Splice the NTFS image into test.img at the correct offset.
dd if="$NTFS_TMP" of="$DISK_IMG" bs=1M seek=$((NTFS_OFFSET / 1024 / 1024)) conv=notrunc 2>/dev/null
NTFS_ACTUAL=$(wc -c < "$NTFS_TMP")
rm -f "$NTFS_TMP"

echo "  NTFS image appended to test.img at offset $NTFS_OFFSET ($((NTFS_ACTUAL / 1024 / 1024)) MiB NTFS)"
