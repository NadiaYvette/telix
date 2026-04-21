#!/bin/bash
# Create a 32 MiB btrfs test image and splice it into test.img at 401 MiB.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"
BTRFS_SIZE=$((32 * 1024 * 1024))    # 32 MiB
BTRFS_OFFSET=$((401 * 1024 * 1024)) # after NTFS partition

if ! command -v mkfs.btrfs >/dev/null 2>&1; then
    echo "  WARNING: mkfs.btrfs not found, skipping btrfs image"
    exit 0
fi

TMP_IMG=$(mktemp /tmp/btrfs_XXXXXX.img)
TMP_DIR=$(mktemp -d /tmp/btrfs_root_XXXXXX)
trap "rm -f '$TMP_IMG'; rm -rf '$TMP_DIR'" EXIT

# Prepare test content.
echo "Hello from btrfs!" > "$TMP_DIR/hello.txt"
mkdir -p "$TMP_DIR/subdir"
echo "Nested btrfs file" > "$TMP_DIR/subdir/nested.txt"
echo "Alpha file" > "$TMP_DIR/alpha.txt"

# Create btrfs image with --rootdir (no mount required).
truncate -s "$BTRFS_SIZE" "$TMP_IMG"
if mkfs.btrfs -f -M -d single -m single --rootdir "$TMP_DIR" "$TMP_IMG" >/dev/null 2>&1; then
    : # success
elif mkfs.btrfs -f -M --rootdir "$TMP_DIR" "$TMP_IMG" >/dev/null 2>&1; then
    : # fallback without explicit profiles
elif mkfs.btrfs -f --rootdir "$TMP_DIR" -b "$BTRFS_SIZE" "$TMP_IMG" >/dev/null 2>&1; then
    : # fallback for older btrfs-progs
else
    echo "  WARNING: mkfs.btrfs --rootdir failed, trying mount"
    mkfs.btrfs -f -M "$TMP_IMG" >/dev/null 2>&1 || mkfs.btrfs -f "$TMP_IMG" >/dev/null 2>&1
    TMP_MNT=$(mktemp -d /tmp/btrfs_mnt_XXXXXX)
    if sudo -n mount -o loop "$TMP_IMG" "$TMP_MNT" 2>/dev/null; then
        sudo cp -r "$TMP_DIR/"* "$TMP_MNT/"
        sudo umount "$TMP_MNT"
    else
        echo "  WARNING: could not mount btrfs image, test files missing"
    fi
    rmdir "$TMP_MNT" 2>/dev/null || true
fi

# Ensure disk image is large enough.
NEEDED=$((BTRFS_OFFSET + BTRFS_SIZE))
CURRENT=$(stat -c%s "$DISK_IMG" 2>/dev/null || echo 0)
if [ "$CURRENT" -lt "$NEEDED" ]; then
    truncate -s "$NEEDED" "$DISK_IMG"
fi

dd if="$TMP_IMG" of="$DISK_IMG" bs=1M seek=401 conv=notrunc 2>/dev/null
echo "  btrfs image appended to test.img at offset $BTRFS_OFFSET ($((BTRFS_SIZE / 1024 / 1024)) MiB btrfs)"
