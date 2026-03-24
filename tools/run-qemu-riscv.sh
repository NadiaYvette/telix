#!/bin/bash
# Run the Telix kernel on QEMU riscv64 virt machine.
# Usage: run-qemu-riscv.sh <kernel-elf> [--debug]

set -e

KERNEL="${1:?Usage: run-qemu-riscv.sh <kernel-elf> [--debug]}"
shift

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"

QEMU_ARGS=(
    -machine virt
    -cpu rv64
    -m 256M
    -nographic
    -serial mon:stdio
    -bios default
    -kernel "$KERNEL"
    -smp 4
)

# Add virtio-blk disk if test.img exists.
if [ -f "$DISK_IMG" ]; then
    QEMU_ARGS+=(
        -drive file="$DISK_IMG",format=raw,if=none,id=disk0
        -device virtio-blk-device,drive=disk0
    )
fi

# Add virtio-net (QEMU user-mode networking).
QEMU_ARGS+=(
    -netdev user,id=net0,guestfwd=tcp:10.0.2.100:1234-cmd:cat,hostfwd=tcp::2222-:22
    -device virtio-net-device,netdev=net0
)

# Add debug flags if requested.
if [ "${1:-}" = "--debug" ]; then
    QEMU_ARGS+=(-S -s)
    echo "Waiting for GDB on localhost:1234 ..." >&2
fi

exec qemu-system-riscv64 "${QEMU_ARGS[@]}"
