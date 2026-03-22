#!/bin/bash
# Build a C test binary for Telix x86_64.
# Usage: musl-telix/build-x86_64.sh
set -e

ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
MUSL="$ROOTDIR/musl-telix"
OUTDIR="$MUSL/out"
CC="${CC:-clang}"

mkdir -p "$OUTDIR"

CFLAGS="-target x86_64-unknown-none \
    -ffreestanding -nostdlib -nostdinc \
    -fno-stack-protector -fno-exceptions -fno-unwind-tables \
    -fno-asynchronous-unwind-tables \
    -mcmodel=large -mno-red-zone -mno-sse -mno-sse2 -mno-mmx \
    -isystem $MUSL/include \
    -Wall -Wextra -O2"

echo "Compiling musl-telix for x86_64..."

# Assemble startup and syscall stubs.
$CC $CFLAGS -c "$MUSL/arch/x86_64/crt_start.S" -o "$OUTDIR/crt_start.o"
$CC $CFLAGS -c "$MUSL/arch/x86_64/syscall.S"   -o "$OUTDIR/syscall.o"

# Compile C sources.
for src in ipc fd write exit init; do
    $CC $CFLAGS -c "$MUSL/src/$src.c" -o "$OUTDIR/$src.o"
done

# Compile the test program.
$CC $CFLAGS -c "$MUSL/test/hello.c" -o "$OUTDIR/hello_c.o"

# Link everything.
$CC -target x86_64-unknown-none -nostdlib -static \
    -T "$MUSL/link-x86_64.ld" \
    "$OUTDIR/crt_start.o" \
    "$OUTDIR/syscall.o" \
    "$OUTDIR/ipc.o" \
    "$OUTDIR/fd.o" \
    "$OUTDIR/write.o" \
    "$OUTDIR/exit.o" \
    "$OUTDIR/init.o" \
    "$OUTDIR/hello_c.o" \
    -o "$OUTDIR/hello_c"

SIZE=$(wc -c < "$OUTDIR/hello_c")
echo "  hello_c: $SIZE bytes"
echo "Done."
