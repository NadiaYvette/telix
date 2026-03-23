#!/bin/bash
# Build C userspace binaries (musl-telix) for a given architecture.
# Usage: musl-telix/build.sh [aarch64|riscv64|x86_64]
set -e

ARCH="${1:-x86_64}"
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
MUSL="$ROOTDIR/musl-telix"
OUTDIR="$MUSL/out/$ARCH"

mkdir -p "$OUTDIR"

case "$ARCH" in
    aarch64)
        CC="${CC:-clang}"
        TARGET="aarch64-unknown-none"
        ARCHFLAGS="-target aarch64-unknown-none -mgeneral-regs-only"
        LINKSCRIPT="$MUSL/link-aarch64.ld"
        ;;
    riscv64)
        CC="${CC:-clang}"
        TARGET="riscv64-unknown-none-elf"
        ARCHFLAGS="--target=riscv64-unknown-elf -march=rv64gc -mabi=lp64d -mcmodel=medany"
        LINKSCRIPT="$MUSL/link-riscv64.ld"
        ;;
    x86_64)
        CC="${CC:-clang}"
        TARGET="x86_64-unknown-none"
        ARCHFLAGS="-target x86_64-unknown-none -mcmodel=large -mno-red-zone -mno-sse -mno-sse2 -mno-mmx"
        LINKSCRIPT="$MUSL/link-x86_64.ld"
        ;;
    *)
        echo "Unknown arch: $ARCH (expected aarch64, riscv64, x86_64)"
        exit 1
        ;;
esac

CFLAGS="$ARCHFLAGS \
    -ffreestanding -nostdlib -nostdinc \
    -fno-stack-protector -fno-exceptions -fno-unwind-tables \
    -fno-asynchronous-unwind-tables \
    -isystem $MUSL/include \
    -Wall -Wextra -O2"

echo "Compiling musl-telix for $ARCH..."

# Assemble startup and syscall stubs.
$CC $CFLAGS -c "$MUSL/arch/$ARCH/crt_start.S" -o "$OUTDIR/crt_start.o"
$CC $CFLAGS -c "$MUSL/arch/$ARCH/syscall.S"   -o "$OUTDIR/syscall.o"

# Compile C sources.
for src in ipc fd write read exit init socket pipe poll \
           string malloc printf file process signal dup env; do
    $CC $CFLAGS -c "$MUSL/src/$src.c" -o "$OUTDIR/$src.o"
done

# Common object files (runtime + library).
COMMON_OBJS="$OUTDIR/crt_start.o $OUTDIR/syscall.o \
    $OUTDIR/ipc.o $OUTDIR/fd.o $OUTDIR/write.o $OUTDIR/read.o \
    $OUTDIR/exit.o $OUTDIR/init.o $OUTDIR/socket.o $OUTDIR/pipe.o \
    $OUTDIR/poll.o \
    $OUTDIR/string.o $OUTDIR/malloc.o $OUTDIR/printf.o $OUTDIR/file.o \
    $OUTDIR/process.o $OUTDIR/signal.o $OUTDIR/dup.o $OUTDIR/env.o"

# Link function — use ld.lld for cross-arch, clang for native.
link_binary() {
    local OUTPUT="$1"
    shift
    case "$ARCH" in
        x86_64)
            $CC -target x86_64-unknown-none -nostdlib -static \
                -T "$LINKSCRIPT" "$@" -o "$OUTPUT"
            ;;
        aarch64)
            ld.lld -T "$LINKSCRIPT" --static "$@" -o "$OUTPUT"
            ;;
        riscv64)
            ld.lld -T "$LINKSCRIPT" --static "$@" -o "$OUTPUT"
            ;;
    esac
}

# Build hello_c.
$CC $CFLAGS -c "$MUSL/test/hello.c" -o "$OUTDIR/hello_c.o"
link_binary "$OUTDIR/hello_c" $COMMON_OBJS "$OUTDIR/hello_c.o"
SIZE=$(wc -c < "$OUTDIR/hello_c")
echo "  hello_c: $SIZE bytes"

# Build sock_test.
$CC $CFLAGS -c "$MUSL/test/sock_test.c" -o "$OUTDIR/sock_test.o"
link_binary "$OUTDIR/sock_test" $COMMON_OBJS "$OUTDIR/sock_test.o"
SIZE=$(wc -c < "$OUTDIR/sock_test")
echo "  sock_test: $SIZE bytes"

# Build tsh (shell + coreutils).
$CC $CFLAGS -c "$MUSL/test/tsh.c" -o "$OUTDIR/tsh.o"
link_binary "$OUTDIR/tsh" $COMMON_OBJS "$OUTDIR/tsh.o"
SIZE=$(wc -c < "$OUTDIR/tsh")
echo "  tsh: $SIZE bytes"

# Build getty_login.
$CC $CFLAGS -c "$MUSL/test/getty_login.c" -o "$OUTDIR/getty_login.o"
link_binary "$OUTDIR/getty_login" $COMMON_OBJS "$OUTDIR/getty_login.o"
SIZE=$(wc -c < "$OUTDIR/getty_login")
echo "  getty_login: $SIZE bytes"

echo "Done."
