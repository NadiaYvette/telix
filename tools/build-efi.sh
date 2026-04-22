#!/bin/bash
# Build the Telix EFI boot loader for x86-64.
#
# Usage: build-efi.sh [--release]
#
# Produces:
#   boot/efi/target/x86_64-unknown-uefi/release/telix-efi.efi
#   boot/efi/telix-efi-disk.img  (FAT32 image for QEMU OVMF)
#
# The kernel must be built first (tools/build-kernel.sh x86_64 --release).

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."

KERNEL_ELF="$ROOT/target/x86_64-unknown-none/release/telix-kernel"
if [ ! -f "$KERNEL_ELF" ]; then
    echo "ERROR: Kernel not found at $KERNEL_ELF"
    echo "       Run: tools/build-kernel.sh x86_64 --release"
    exit 1
fi

echo "=== Building Telix EFI loader ==="
echo "  Kernel: $KERNEL_ELF ($(stat -c%s "$KERNEL_ELF") bytes)"

cd "$ROOT/boot/efi"
NIGHTLY_CARGO="$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/cargo"
NIGHTLY_RUSTC="$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/rustc"
TELIX_KERNEL_PATH="$KERNEL_ELF" \
    RUSTC="$NIGHTLY_RUSTC" \
    "$NIGHTLY_CARGO" build --release -Zbuild-std=core 2>&1

EFI_BIN="$ROOT/boot/efi/target/x86_64-unknown-uefi/release/telix-efi.efi"
if [ ! -f "$EFI_BIN" ]; then
    echo "ERROR: EFI binary not found"
    exit 1
fi
echo "  EFI binary: $EFI_BIN ($(stat -c%s "$EFI_BIN") bytes)"

# Create a FAT32 disk image for QEMU OVMF testing.
IMG="$ROOT/boot/efi/telix-efi-disk.img"
dd if=/dev/zero of="$IMG" bs=1M count=64 status=none
# Create GPT + EFI System Partition.
sgdisk -Z "$IMG" >/dev/null 2>&1 || true
sgdisk -n 1:2048:131038 -t 1:ef00 "$IMG" >/dev/null 2>&1

# Format as FAT32 and copy files.
LOOP=$(sudo losetup --show -fP "$IMG")
sudo mkfs.vfat -F32 "${LOOP}p1" >/dev/null 2>&1
MNT=$(mktemp -d)
sudo mount "${LOOP}p1" "$MNT"
sudo mkdir -p "$MNT/EFI/BOOT"
sudo cp "$EFI_BIN" "$MNT/EFI/BOOT/BOOTX64.EFI"
sudo umount "$MNT"
rmdir "$MNT"
sudo losetup -d "$LOOP"

echo "  Disk image: $IMG (64 MiB)"
echo "=== EFI build complete ==="
echo ""
echo "Test with QEMU OVMF:"
echo "  qemu-system-x86_64 -bios /usr/share/OVMF/OVMF_CODE.fd \\"
echo "    -drive file=$IMG,format=raw -m 256M -nographic"
