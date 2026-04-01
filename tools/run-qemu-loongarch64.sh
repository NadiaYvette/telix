#!/bin/bash
# Run the Telix kernel on QEMU loongarch64 virt machine.
# Usage: run-qemu-loongarch64.sh <kernel-elf> [--debug]
#
# Port overrides (to avoid conflicts with other QEMU sessions):
#   TELIX_SSH_PORT  — host SSH forwarding port (default 3222)
#   TELIX_GDB_PORT  — GDB listen port (default 3234)

set -e

KERNEL="${1:?Usage: run-qemu-loongarch64.sh <kernel-elf> [--debug]}"
shift

SSH_PORT="${TELIX_SSH_PORT:-3222}"
GDB_PORT="${TELIX_GDB_PORT:-3234}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"

QEMU_ARGS=(
    -machine virt
    -cpu la464
    -m 256M
    -nographic
    -serial mon:stdio
    -kernel "$KERNEL"
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
    -netdev user,id=net0,guestfwd=tcp:10.0.2.100:1234-cmd:cat,hostfwd=tcp::${SSH_PORT}-:22
    -device virtio-net-pci,netdev=net0
)

# LoongArch64 virt doesn't pass -append via DTB/FW_CFG standard items.
# Use a custom fw_cfg file to pass the kernel command line.
if [ -n "${TELIX_CMDLINE:-}" ]; then
    TMPFILE=$(mktemp)
    printf '%s' "$TELIX_CMDLINE" > "$TMPFILE"
    QEMU_ARGS+=(-fw_cfg "name=opt/telix/cmdline,file=$TMPFILE")
fi

# Add debug flags if requested.
if [ "${1:-}" = "--debug" ]; then
    QEMU_ARGS+=(-S -gdb tcp::${GDB_PORT})
    echo "Waiting for GDB on localhost:${GDB_PORT} ..." >&2
fi

exec qemu-system-loongarch64 "${QEMU_ARGS[@]}"
