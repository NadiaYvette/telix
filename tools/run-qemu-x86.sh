#!/bin/bash
# Run the Telix kernel on QEMU x86-64 (q35 machine, Multiboot1).
# Usage: run-qemu-x86.sh <kernel-elf> [--debug]
#
# QEMU's -kernel Multiboot loader requires a 32-bit ELF.
# We convert the 64-bit ELF to 32-bit with objcopy.

set -e

KERNEL="${1:?Usage: run-qemu-x86.sh <kernel-elf> [--debug]}"
shift

# Convert 64-bit ELF to 32-bit ELF for QEMU's Multiboot loader.
KERNEL32="${KERNEL}.mb32"
objcopy -O elf32-i386 "$KERNEL" "$KERNEL32"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"

QEMU_ARGS=(
    -machine q35
    -cpu qemu64
    -m 256M
    -nographic
    -serial mon:stdio
    -kernel "$KERNEL32"
    -smp 4
)

# Add virtio-blk disk if test.img exists.
if [ -f "$DISK_IMG" ]; then
    QEMU_ARGS+=(
        -drive file="$DISK_IMG",format=raw,if=none,id=disk0
        -device virtio-blk-pci,drive=disk0
    )
fi

# Add virtio-net (QEMU user-mode networking).
QEMU_ARGS+=(
    -netdev user,id=net0
    -device virtio-net-pci,netdev=net0
)

# Add debug flags if requested.
if [ "${1:-}" = "--debug" ]; then
    QEMU_ARGS+=(-S -s)
    echo "Waiting for GDB on localhost:1234 ..." >&2
fi

exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
