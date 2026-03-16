#!/bin/bash
# Build a CPIO newc-format initramfs archive from the initramfs/ directory.
# Output: kernel/src/io/initramfs.cpio
set -e

SRCDIR="$(dirname "$0")/../initramfs"
OUTFILE="$(dirname "$0")/../kernel/src/io/initramfs.cpio"

cd "$SRCDIR"
find . -mindepth 1 | sort | cpio -o -H newc --quiet > "$OUTFILE"
echo "initramfs.cpio created: $(wc -c < "$OUTFILE") bytes"
