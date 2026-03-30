#!/bin/bash
# Run the Telix kernel on QEMU mips64el Malta machine.
# Usage: run-qemu-mips64.sh <kernel-elf> [--debug]

set -e

KERNEL="${1:?Usage: run-qemu-mips64.sh <kernel-elf> [--debug]}"
shift

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"

QEMU_ARGS=(
    -M malta
    -cpu MIPS64R2-generic
    -m 256M
    -nographic
    -serial mon:stdio
    -kernel "$KERNEL"
)

# Add virtio-blk-pci disk if test.img exists.
if [ -f "$DISK_IMG" ]; then
    QEMU_ARGS+=(
        -drive file="$DISK_IMG",format=raw,if=none,id=disk0
        -device virtio-blk-pci,drive=disk0
    )
fi

# Add virtio-net-pci (QEMU user-mode networking).
QEMU_ARGS+=(
    -netdev user,id=net0,guestfwd=tcp:10.0.2.100:1234-cmd:cat,hostfwd=tcp::2223-:22
    -device virtio-net-pci,netdev=net0
)

# Add debug flags if requested.
if [ "${1:-}" = "--debug" ]; then
    QEMU_ARGS+=(-S -s)
    echo "Waiting for GDB on localhost:1234 ..." >&2
fi

exec qemu-system-mips64el "${QEMU_ARGS[@]}"
