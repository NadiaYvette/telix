#!/bin/bash
# Run the Telix kernel on QEMU loongarch64 virt machine.
# Usage: run-qemu-loongarch64.sh <kernel-elf> [--debug]

set -e

KERNEL="${1:?Usage: run-qemu-loongarch64.sh <kernel-elf> [--debug]}"
shift

QEMU_ARGS=(
    -machine virt
    -cpu la464
    -m 256M
    -nographic
    -serial mon:stdio
    -kernel "$KERNEL"
    -smp 4
)

# Add debug flags if requested.
if [ "${1:-}" = "--debug" ]; then
    QEMU_ARGS+=(-S -s)
    echo "Waiting for GDB on localhost:1234 ..." >&2
fi

exec qemu-system-loongarch64 "${QEMU_ARGS[@]}"
