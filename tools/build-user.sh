#!/bin/bash
# Build userspace ELF binaries for Telix and pack them into initramfs.
# Usage: tools/build-user.sh [aarch64|riscv64|x86_64]
set -e

ARCH="${1:-aarch64}"
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
USERLIB="$ROOTDIR/userlib"
INITRAMFS_DIR="$ROOTDIR/initramfs"
RUSTC="${RUSTC:-/home/nyc/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/rustc}"
CARGO="${CARGO:-/home/nyc/.cargo/bin/cargo}"

case "$ARCH" in
    aarch64)
        TARGET="aarch64-unknown-none"
        LINKER="$USERLIB/link-aarch64.ld"
        ;;
    riscv64)
        TARGET="riscv64gc-unknown-none-elf"
        LINKER="$USERLIB/link-riscv64.ld"
        ;;
    x86_64)
        TARGET="x86_64-unknown-none"
        LINKER="$USERLIB/link-x86_64.ld"
        EXTRA_RUSTFLAGS="-C relocation-model=static -C code-model=large"
        ;;
    *)
        echo "Unknown arch: $ARCH (expected aarch64, riscv64, x86_64)"
        exit 1
        ;;
esac

echo "Building userspace binaries for $ARCH ($TARGET)..."

# Build with user linker script, overriding workspace rustflags.
RUSTFLAGS="-C link-arg=-T$LINKER ${EXTRA_RUSTFLAGS:-}" \
    RUSTC="$RUSTC" "$CARGO" build \
    --target "$TARGET" \
    -p telix-userlib \
    --release \
    --config "unstable.build-std=[\"core\"]" \
    --config "unstable.build-std-features=[\"compiler-builtins-mem\"]"

BINDIR="$ROOTDIR/target/$TARGET/release"

# Build C userspace binaries (musl-telix).
echo "Building C userspace (musl-telix) for $ARCH..."
bash "$ROOTDIR/musl-telix/build.sh" "$ARCH"
MUSL_OUTDIR="$ROOTDIR/musl-telix/out/$ARCH"
for cbin in hello_c sock_test tsh getty_login ld-telix tz_test pthread_test initdb_test postmaster_test pg_full_test libc_test calc stress_test sshd; do
    if [ -f "$MUSL_OUTDIR/$cbin" ]; then
        cp "$MUSL_OUTDIR/$cbin" "$BINDIR/$cbin"
    fi
done

# Copy ELF binaries to initramfs directory.
for bin in init hello echo_client initramfs_srv ramdisk_srv blk_srv cache_srv fat16_srv ext2_srv console_srv shell net_srv pipe_upper spin bench pong grant_echo macro_bench cap_test security_srv shm_srv vfs_srv tmpfs_srv devfs_srv procfs_srv uds_srv pipe_srv pty_srv event_srv inotify_srv syslog_srv sysv_srv hello_c sock_test tsh getty_login ld-telix tz_test pthread_test initdb_test postmaster_test pg_full_test libc_test calc stress_test sshd proxy_srv; do
    if [ -f "$BINDIR/$bin" ]; then
        cp "$BINDIR/$bin" "$INITRAMFS_DIR/$bin"
        SIZE=$(wc -c < "$INITRAMFS_DIR/$bin")
        echo "  $bin: $SIZE bytes"
    else
        echo "  WARNING: $bin not found in $BINDIR"
    fi
done

# Rebuild the FAT16 test disk with hello ELF for exec-from-filesystem test.
echo "Building FAT16 test disk..."
"$ROOTDIR/tools/make-fat16.sh" "$TARGET"

# Append ext2 partition to the test disk.
echo "Building ext2 partition..."
"$ROOTDIR/tools/make-ext2.sh"

# Rebuild the CPIO archive.
echo "Packing initramfs..."
"$ROOTDIR/tools/make-initramfs.sh"

echo "Done! User binaries packed into initramfs."
