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
    mips64)
        CC="${CC:-clang}"
        TARGET="mips64el-unknown-none"
        ARCHFLAGS="--target=mips64el-unknown-elf -march=mips64r2 -mabi=64 -mno-abicalls -fno-pic -G0"
        LINKSCRIPT="$MUSL/link-mips64.ld"
        ;;
    loongarch64)
        CC="${CC:-clang}"
        TARGET="loongarch64-unknown-none"
        ARCHFLAGS="--target=loongarch64-unknown-linux-gnu -mabi=lp64d -mno-lsx -mno-lasx"
        LINKSCRIPT="$MUSL/link-loongarch64.ld"
        ;;
    *)
        echo "Unknown arch: $ARCH (expected aarch64, riscv64, x86_64, mips64, loongarch64)"
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

# Assemble arch-specific sources (setjmp).
if [ -f "$MUSL/arch/$ARCH/setjmp.S" ]; then
    $CC $CFLAGS -c "$MUSL/arch/$ARCH/setjmp.S" -o "$OUTDIR/setjmp.o"
fi

# Compile C sources.
for src in ipc fd write read exit init socket pipe poll \
           string malloc printf file process signal dup env \
           syslog locale time_util mman pthread netdb epoll timer sysvipc \
           errno ctype strconv stdio_file assert \
           dirent getopt select termios random pwgrp regex \
           crypto_sha256 crypto_sha512 crypto_chacha20 \
           crypto_curve25519 crypto_ed25519 crypto_csprng \
           byteorder ssh_transport ssh_session; do
    $CC $CFLAGS -c "$MUSL/src/$src.c" -o "$OUTDIR/$src.o"
done

# Common object files (runtime + library).
COMMON_OBJS="$OUTDIR/crt_start.o $OUTDIR/syscall.o \
    $OUTDIR/ipc.o $OUTDIR/fd.o $OUTDIR/write.o $OUTDIR/read.o \
    $OUTDIR/exit.o $OUTDIR/init.o $OUTDIR/socket.o $OUTDIR/pipe.o \
    $OUTDIR/poll.o \
    $OUTDIR/string.o $OUTDIR/malloc.o $OUTDIR/printf.o $OUTDIR/file.o \
    $OUTDIR/process.o $OUTDIR/signal.o $OUTDIR/dup.o $OUTDIR/env.o \
    $OUTDIR/syslog.o $OUTDIR/locale.o $OUTDIR/time_util.o $OUTDIR/mman.o \
    $OUTDIR/pthread.o $OUTDIR/netdb.o $OUTDIR/epoll.o $OUTDIR/timer.o \
    $OUTDIR/sysvipc.o \
    $OUTDIR/errno.o $OUTDIR/ctype.o $OUTDIR/strconv.o \
    $OUTDIR/stdio_file.o $OUTDIR/assert.o \
    $OUTDIR/dirent.o $OUTDIR/getopt.o $OUTDIR/select.o \
    $OUTDIR/termios.o $OUTDIR/random.o $OUTDIR/pwgrp.o $OUTDIR/regex.o \
    $OUTDIR/crypto_sha256.o $OUTDIR/crypto_sha512.o $OUTDIR/crypto_chacha20.o \
    $OUTDIR/crypto_curve25519.o $OUTDIR/crypto_ed25519.o $OUTDIR/crypto_csprng.o \
    $OUTDIR/byteorder.o $OUTDIR/ssh_transport.o $OUTDIR/ssh_session.o"

# Add setjmp.o if it exists for this arch.
if [ -f "$OUTDIR/setjmp.o" ]; then
    COMMON_OBJS="$COMMON_OBJS $OUTDIR/setjmp.o"
fi

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
        mips64)
            ld.lld -T "$LINKSCRIPT" --static "$@" -o "$OUTPUT"
            ;;
        loongarch64)
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

# Build ld-telix (dynamic linker — built as regular static binary,
# kernel loads it at INTERP_BASE via load_elf_at_base).
$CC $CFLAGS -c "$MUSL/test/ld-telix.c" -o "$OUTDIR/ld-telix.o"
link_binary "$OUTDIR/ld-telix" $COMMON_OBJS "$OUTDIR/ld-telix.o"
SIZE=$(wc -c < "$OUTDIR/ld-telix")
echo "  ld-telix: $SIZE bytes"

# Build tz_test (Phase 72).
$CC $CFLAGS -c "$MUSL/test/tz_test.c" -o "$OUTDIR/tz_test.o"
link_binary "$OUTDIR/tz_test" $COMMON_OBJS "$OUTDIR/tz_test.o"
SIZE=$(wc -c < "$OUTDIR/tz_test")
echo "  tz_test: $SIZE bytes"

# Build pthread_test (Phase 74).
$CC $CFLAGS -c "$MUSL/test/pthread_test.c" -o "$OUTDIR/pthread_test.o"
link_binary "$OUTDIR/pthread_test" $COMMON_OBJS "$OUTDIR/pthread_test.o"
SIZE=$(wc -c < "$OUTDIR/pthread_test")
echo "  pthread_test: $SIZE bytes"

# Build initdb_test (Phase 80).
$CC $CFLAGS -c "$MUSL/test/initdb_test.c" -o "$OUTDIR/initdb_test.o"
link_binary "$OUTDIR/initdb_test" $COMMON_OBJS "$OUTDIR/initdb_test.o"
SIZE=$(wc -c < "$OUTDIR/initdb_test")
echo "  initdb_test: $SIZE bytes"

# Build postmaster_test (Phase 81).
$CC $CFLAGS -c "$MUSL/test/postmaster_test.c" -o "$OUTDIR/postmaster_test.o"
link_binary "$OUTDIR/postmaster_test" $COMMON_OBJS "$OUTDIR/postmaster_test.o"
SIZE=$(wc -c < "$OUTDIR/postmaster_test")
echo "  postmaster_test: $SIZE bytes"

# Build pg_full_test (Phase 82).
$CC $CFLAGS -c "$MUSL/test/pg_full_test.c" -o "$OUTDIR/pg_full_test.o"
link_binary "$OUTDIR/pg_full_test" $COMMON_OBJS "$OUTDIR/pg_full_test.o"
SIZE=$(wc -c < "$OUTDIR/pg_full_test")
echo "  pg_full_test: $SIZE bytes"

# Build libc_test (Phase 102).
$CC $CFLAGS -c "$MUSL/test/libc_test.c" -o "$OUTDIR/libc_test.o"
link_binary "$OUTDIR/libc_test" $COMMON_OBJS "$OUTDIR/libc_test.o"
SIZE=$(wc -c < "$OUTDIR/libc_test")
echo "  libc_test: $SIZE bytes"

# Build calc (Phase 103).
$CC $CFLAGS -c "$MUSL/test/calc.c" -o "$OUTDIR/calc.o"
link_binary "$OUTDIR/calc" $COMMON_OBJS "$OUTDIR/calc.o"
SIZE=$(wc -c < "$OUTDIR/calc")
echo "  calc: $SIZE bytes"

# Build stress_test (Phase 104).
$CC $CFLAGS -c "$MUSL/test/stress_test.c" -o "$OUTDIR/stress_test.o"
link_binary "$OUTDIR/stress_test" $COMMON_OBJS "$OUTDIR/stress_test.o"
SIZE=$(wc -c < "$OUTDIR/stress_test")
echo "  stress_test: $SIZE bytes"

# Build sshd (SSH server).
$CC $CFLAGS -c "$MUSL/test/sshd.c" -o "$OUTDIR/sshd.o"
link_binary "$OUTDIR/sshd" $COMMON_OBJS "$OUTDIR/sshd.o"
SIZE=$(wc -c < "$OUTDIR/sshd")
echo "  sshd: $SIZE bytes"

echo "Done."
