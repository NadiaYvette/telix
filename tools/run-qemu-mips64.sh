#!/bin/bash
# Run the Telix kernel on QEMU mips64el Malta machine.
# Usage: run-qemu-mips64.sh <kernel-elf> [--debug]

set -e

KERNEL="${1:?Usage: run-qemu-mips64.sh <kernel-elf> [--debug]}"
shift

QEMU_ARGS=(
    -M malta
    -cpu MIPS64R2-generic
    -m 256M
    -nographic
    -serial mon:stdio
    -kernel "$KERNEL"
)

# Add debug flags if requested.
if [ "${1:-}" = "--debug" ]; then
    QEMU_ARGS+=(-S -s)
    echo "Waiting for GDB on localhost:1234 ..." >&2
fi

exec qemu-system-mips64el "${QEMU_ARGS[@]}"
