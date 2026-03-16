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

QEMU_ARGS=(
    -machine q35
    -cpu qemu64
    -m 256M
    -nographic
    -serial mon:stdio
    -kernel "$KERNEL32"
    -smp 4
)

# Add debug flags if requested.
if [ "${1:-}" = "--debug" ]; then
    QEMU_ARGS+=(-S -s)
    echo "Waiting for GDB on localhost:1234 ..." >&2
fi

exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
