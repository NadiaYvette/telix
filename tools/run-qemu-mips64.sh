#!/bin/bash
# Run the Telix kernel on QEMU mips64el Malta machine.
# Usage: run-qemu-mips64.sh <kernel-elf> [--debug]
#
# Port overrides (to avoid conflicts with other QEMU sessions):
#   TELIX_SSH_PORT  — host SSH forwarding port (default 3223)
#   TELIX_GDB_PORT  — GDB listen port (default 3234)

set -e

KERNEL="${1:?Usage: run-qemu-mips64.sh <kernel-elf> [--debug]}"
shift

SSH_PORT="${TELIX_SSH_PORT:-3223}"
GDB_PORT="${TELIX_GDB_PORT:-3234}"

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

# Pass kernel command line via YAMON -append if TELIX_CMDLINE is set.
if [ -n "${TELIX_CMDLINE:-}" ]; then
    QEMU_ARGS+=(-append "$TELIX_CMDLINE")
fi

# Add virtio-blk-pci disk if test.img exists.
if [ -f "$DISK_IMG" ]; then
    QEMU_ARGS+=(
        -drive file="$DISK_IMG",format=raw,if=none,id=disk0
        -device virtio-blk-pci,drive=disk0
    )
fi

# Add virtio-net-pci (QEMU user-mode networking).
QEMU_ARGS+=(
    -netdev user,id=net0,guestfwd=tcp:10.0.2.100:1234-cmd:cat,hostfwd=tcp::${SSH_PORT}-:22
    -device virtio-net-pci,netdev=net0
)

# Add debug flags if requested.
if [ "${1:-}" = "--debug" ]; then
    QEMU_ARGS+=(-S -gdb tcp::${GDB_PORT})
    echo "Waiting for GDB on localhost:${GDB_PORT} ..." >&2
fi

exec qemu-system-mips64el "${QEMU_ARGS[@]}"
