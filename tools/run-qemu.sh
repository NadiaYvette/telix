#!/bin/bash
# Run the Telix kernel on QEMU aarch64 virt machine.
# Usage: run-qemu.sh <kernel-elf> [--debug]
#
# Port overrides (to avoid conflicts with other QEMU sessions):
#   TELIX_SSH_PORT  — host SSH forwarding port (default 3222)
#   TELIX_GDB_PORT  — GDB listen port (default 3234)
#   TELIX_SMP       — number of CPUs (default 4)

set -e

KERNEL="${1:?Usage: run-qemu.sh <kernel-elf> [--debug]}"
shift

SSH_PORT="${TELIX_SSH_PORT:-3222}"
GDB_PORT="${TELIX_GDB_PORT:-3234}"
SMP="${TELIX_SMP:-4}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"

# QEMU aarch64 virt doesn't pass DTB to ELF kernels (x0=0).
# Generate a compact DTB and inject it at RAM base (0x40000000) via the
# generic loader so the kernel's RAM-scan finds it.
DTB_FILE="${SCRIPT_DIR}/../.qemu-virt.dtb"

QEMU_ARGS=(
    -machine virt,gic-version=3
    -cpu cortex-a72
    -m 256M
    -nographic
    -serial mon:stdio
    -kernel "$KERNEL"
    -smp "$SMP"
)

# Add virtio-blk disk if test.img exists.
DISK_ARGS=()
if [ -f "$DISK_IMG" ]; then
    DISK_ARGS=(
        -drive file="$DISK_IMG",format=raw,if=none,id=disk0,snapshot=on
        -device virtio-blk-device,drive=disk0
    )
    QEMU_ARGS+=("${DISK_ARGS[@]}")
fi

# Add virtio-net (QEMU user-mode networking).
NET_ARGS=(
    -netdev user,id=net0,guestfwd=tcp:10.0.2.100:1234-cmd:cat,hostfwd=tcp::${SSH_PORT}-:22
    -device virtio-net-device,netdev=net0
)
QEMU_ARGS+=("${NET_ARGS[@]}")

# Generate the DTB matching our exact device configuration.
# dumpdtb causes QEMU to write the DTB and exit immediately.
qemu-system-aarch64 \
    -machine virt,gic-version=3,dumpdtb="$DTB_FILE" \
    -cpu cortex-a72 -m 256M -smp "$SMP" \
    "${DISK_ARGS[@]}" "${NET_ARGS[@]}" 2>/dev/null || true

# Compact it (remove padding) and inject at 0x40000000.
if command -v dtc &>/dev/null && [ -f "$DTB_FILE" ]; then
    dtc -I dtb -O dtb -p 0 "$DTB_FILE" -o "$DTB_FILE" 2>/dev/null || true
fi
if [ -f "$DTB_FILE" ]; then
    QEMU_ARGS+=(-device loader,file="$DTB_FILE",addr=0x40000000,force-raw=on)
fi

# Add debug flags if requested.
if [ "${1:-}" = "--debug" ]; then
    QEMU_ARGS+=(-S -gdb tcp::${GDB_PORT})
    echo "Waiting for GDB on localhost:${GDB_PORT} ..." >&2
fi

exec qemu-system-aarch64 "${QEMU_ARGS[@]}"
