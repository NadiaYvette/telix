#!/bin/bash
# Build a CPIO newc-format initramfs archive from the per-arch initramfs tree.
# Usage: tools/make-initramfs.sh [aarch64|riscv64|x86_64|loongarch64|mips64]
# Default: aarch64.
# Output: kernel/src/io/initramfs.cpio (per-arch tree → single shared cpio
# embedded by the kernel; rerun for each arch you want to boot).
# #259: per-arch initramfs trees.
set -e

ARCH="${1:-aarch64}"
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
SRCDIR="$ROOTDIR/initramfs-$ARCH"
OUTFILE="$ROOTDIR/kernel/src/io/initramfs.cpio"

if [ ! -d "$SRCDIR" ]; then
    echo "make-initramfs: $SRCDIR does not exist." >&2
    echo "  Run tools/build-user.sh $ARCH first to populate it." >&2
    exit 1
fi

cd "$SRCDIR"
find . -mindepth 1 | sort | cpio -o -H newc --quiet > "$OUTFILE"
echo "initramfs.cpio created from $SRCDIR: $(wc -c < "$OUTFILE") bytes"
