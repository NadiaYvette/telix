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
    loongarch64)
        TARGET="loongarch64-unknown-none"
        LINKER="$USERLIB/link-loongarch64.ld"
        EXTRA_RUSTFLAGS="-C relocation-model=static"
        ;;
    mips64)
        TARGET="$ROOTDIR/targets/mips64el-telix-none.json"
        LINKER="$USERLIB/link-mips64.ld"
        EXTRA_BUILD_FLAGS="-Z build-std=core -Z build-std-features=compiler-builtins-mem -Z json-target-spec"
        ;;
    *)
        echo "Unknown arch: $ARCH (expected aarch64, riscv64, x86_64, loongarch64, mips64)"
        exit 1
        ;;
esac

echo "Building userspace binaries for $ARCH ($TARGET)..."

# Build with user linker script, overriding workspace rustflags.
if [ -n "${EXTRA_BUILD_FLAGS:-}" ]; then
    # Custom target (e.g. mips64) — use -Z flags directly.
    RUSTFLAGS="-C link-arg=-T$LINKER ${EXTRA_RUSTFLAGS:-}" \
        RUSTC="$RUSTC" "$CARGO" build \
        --target "$TARGET" \
        -p telix-userlib \
        --release \
        $EXTRA_BUILD_FLAGS
else
    RUSTFLAGS="-C link-arg=-T$LINKER ${EXTRA_RUSTFLAGS:-}" \
        RUSTC="$RUSTC" "$CARGO" build \
        --target "$TARGET" \
        -p telix-userlib \
        --release \
        --config "unstable.build-std=[\"core\"]" \
        --config "unstable.build-std-features=[\"compiler-builtins-mem\"]"
fi

case "$ARCH" in
    mips64)
        BINDIR="$ROOTDIR/target/mips64el-telix-none/release"
        ;;
    *)
        BINDIR="$ROOTDIR/target/$TARGET/release"
        ;;
esac

# Build C userspace binaries (musl-telix) — skip for arches musl doesn't support.
echo "Building C userspace (musl-telix) for $ARCH..."
bash "$ROOTDIR/musl-telix/build.sh" "$ARCH" || echo "  (musl-telix not available for $ARCH, skipping)"
MUSL_OUTDIR="$ROOTDIR/musl-telix/out/$ARCH"
for cbin in hello_c sock_test sock6_test tsh getty_login ld-telix tz_test pthread_test initdb_test postmaster_test pg_full_test libc_test calc stress_test sshd; do
    if [ -f "$MUSL_OUTDIR/$cbin" ]; then
        cp "$MUSL_OUTDIR/$cbin" "$BINDIR/$cbin"
    fi
done

# Phase 171: build a real host-glibc static binary so the Linux personality
# can prove it executes upstream binaries (Gap A).  x86_64 only for now.
if [ "$ARCH" = "x86_64" ] && command -v gcc >/dev/null 2>&1; then
    echo "Building host-glibc test binary (Phase 171)..."
    if gcc -static-pie -fPIE -O2 -fno-stack-protector -s -o "$BINDIR/glibc_hello" "$ROOTDIR/tools/glibc_hello.c" 2>&1; then
        echo "  glibc_hello: $(wc -c < "$BINDIR/glibc_hello") bytes"
    else
        echo "  WARNING: glibc_hello build failed"
    fi
    # Step F: Wayland infrastructure smoke test (DRM + evdev + memfd + UDS).
    echo "Building wayland_test (Step F)..."
    if gcc -static-pie -fPIE -O2 -fno-stack-protector -s -o "$BINDIR/wayland_test" "$ROOTDIR/tools/wayland_test.c" 2>&1; then
        echo "  wayland_test: $(wc -c < "$BINDIR/wayland_test") bytes"
    else
        echo "  WARNING: wayland_test build failed"
    fi
    # Step G: handwritten minimal Wayland compositor + test client.
    # Regenerate the embedded XKB_V1 keymap header if xkbcomp is available;
    # otherwise the existing checked-in copy is used.  xkbcomp output is
    # stable across machines, so the checked-in header also stays stable.
    if command -v xkbcomp >/dev/null 2>&1; then
        echo "Regenerating tools/xkb_keymap_us.h from xkbcomp..."
        echo 'xkb_keymap {
  xkb_keycodes  { include "evdev+aliases(qwerty)" };
  xkb_types     { include "complete" };
  xkb_compat    { include "complete" };
  xkb_symbols   { include "pc+us+inet(evdev)" };
};' | xkbcomp -xkb - - 2>/dev/null > "$ROOTDIR/tools/xkb_keymap_us.txt"
        xxd -i -n xkb_keymap_us "$ROOTDIR/tools/xkb_keymap_us.txt" \
            > "$ROOTDIR/tools/xkb_keymap_us.h"
    fi
    echo "Building wl_compositor_min + hello_wl (Step G)..."
    if gcc -static-pie -fPIE -O2 -fno-stack-protector -s -o "$BINDIR/wl_compositor_min" "$ROOTDIR/tools/wl_compositor_min.c" 2>&1; then
        echo "  wl_compositor_min: $(wc -c < "$BINDIR/wl_compositor_min") bytes"
    else
        echo "  WARNING: wl_compositor_min build failed"
    fi
    if gcc -static-pie -fPIE -O2 -fno-stack-protector -s -o "$BINDIR/hello_wl" "$ROOTDIR/tools/hello_wl.c" 2>&1; then
        echo "  hello_wl: $(wc -c < "$BINDIR/hello_wl") bytes"
    else
        echo "  WARNING: hello_wl build failed"
    fi
    # glibc_dyn_hello: minimal dynamically-linked test for Phase 172e.
    # Always rebuild against the host's current libc.so.6 so that our
    # initramfs/lib64/libc.so.6 (also from the host) and this binary
    # agree on glibc version and ABI.
    echo "Building glibc_dyn_hello (Phase 172e)..."
    if gcc -pie -fPIE -O2 -fno-stack-protector -s \
            -o "$BINDIR/glibc_dyn_hello" "$ROOTDIR/tools/glibc_dyn_hello.c" 2>&1; then
        echo "  glibc_dyn_hello: $(wc -c < "$BINDIR/glibc_dyn_hello") bytes"
        cp "$BINDIR/glibc_dyn_hello" "$ROOTDIR/initramfs/glibc_dyn_hello"
    else
        echo "  WARNING: glibc_dyn_hello build failed"
    fi
    # fsprobe: minimal static-PIE Linux probe that exercises the FS
    # path (open + fstat + read) for /lib64/libc.so.6 with NO ld.so /
    # glibc so we can isolate kernel/linux_srv/ext_srv issues from
    # glibc dyn-link issues.  Diagnostic output goes to stderr.
    echo "Building fsprobe (Linux personality FS probe)..."
    if gcc -static-pie -fPIE -O2 -fno-stack-protector -nostdlib -nostartfiles \
            -s -o "$BINDIR/fsprobe" "$ROOTDIR/tools/fsprobe.c" 2>&1; then
        echo "  fsprobe: $(wc -c < "$BINDIR/fsprobe") bytes"
    else
        echo "  WARNING: fsprobe build failed"
    fi
    # Tier-0 Xwayland porting: dynamically-linked smoke test that calls
    # libxcvt.so.0 (Fedora's copy, dropped into initramfs/lib64/).  Headers
    # are vendored in tools/xport/include/ since libxcvt-devel isn't
    # necessarily installed on the build host.
    if [ -f "$ROOTDIR/initramfs/lib64/libxcvt.so.0" ]; then
        echo "Building libxcvt_dyn_test (Tier-0 Xwayland)..."
        # Pass -lc explicitly BEFORE -l:libxcvt.so.0 so the resulting
        # binary's DT_NEEDED list has libc.so.6 first.  glibc's ld.so
        # iterates NEEDED in order, and our loader exposes a bug
        # where if libxcvt loads first its dependency on libc.so.6 is
        # dropped from libxcvt_dyn_test's symbol search list — see
        # project_phase172_tier1.md.  Reordering side-steps the bug
        # by ensuring libc.so.6 is in scope before libxcvt's
        # version_r is processed.
        if gcc -pie -fPIE -O2 -fno-stack-protector -s \
                -I"$ROOTDIR/tools/xport/include" \
                -o "$BINDIR/libxcvt_dyn_test" \
                "$ROOTDIR/tools/libxcvt_dyn_test.c" \
                -L"$ROOTDIR/initramfs/lib64" \
                -Wl,--no-as-needed -lc -Wl,--as-needed \
                -l:libxcvt.so.0 \
                -Wl,-rpath,/lib64 2>&1; then
            echo "  libxcvt_dyn_test: $(wc -c < "$BINDIR/libxcvt_dyn_test") bytes"
        else
            echo "  WARNING: libxcvt_dyn_test build failed"
        fi
    fi
    # Tier-0 round-out: libdrm + libxshmfence dyn-link smoke tests, same
    # pattern as libxcvt_dyn_test.  Inlined struct decls in the test
    # sources avoid a libdrm-devel / libxshmfence-devel build-host dep.
    if [ -f "$ROOTDIR/initramfs/lib64/libdrm.so.2" ]; then
        echo "Building libdrm_dyn_test (Tier-0 Xwayland)..."
        if gcc -pie -fPIE -O2 -fno-stack-protector -s \
                -o "$BINDIR/libdrm_dyn_test" \
                "$ROOTDIR/tools/libdrm_dyn_test.c" \
                -L"$ROOTDIR/initramfs/lib64" \
                -Wl,--no-as-needed -lc -Wl,--as-needed \
                -l:libdrm.so.2 \
                -Wl,-rpath,/lib64 2>&1; then
            echo "  libdrm_dyn_test: $(wc -c < "$BINDIR/libdrm_dyn_test") bytes"
        else
            echo "  WARNING: libdrm_dyn_test build failed"
        fi
    fi
    if [ -f "$ROOTDIR/initramfs/lib64/libxshmfence.so.1" ]; then
        echo "Building libxshmfence_dyn_test (Tier-0 Xwayland)..."
        if gcc -pie -fPIE -O2 -fno-stack-protector -s \
                -o "$BINDIR/libxshmfence_dyn_test" \
                "$ROOTDIR/tools/libxshmfence_dyn_test.c" \
                -L"$ROOTDIR/initramfs/lib64" \
                -Wl,--no-as-needed -lc -Wl,--as-needed \
                -l:libxshmfence.so.1 \
                -Wl,-rpath,/lib64 2>&1; then
            echo "  libxshmfence_dyn_test: $(wc -c < "$BINDIR/libxshmfence_dyn_test") bytes"
        else
            echo "  WARNING: libxshmfence_dyn_test build failed"
        fi
    fi
    # Tier-1 Xwayland porting: libXau dyn-link smoke (cookie-auth lib,
    # 19 KiB on Fedora 43).
    if [ -f "$ROOTDIR/initramfs/lib64/libXau.so.6" ]; then
        echo "Building libXau_dyn_test (Tier-1 Xwayland)..."
        if gcc -pie -fPIE -O2 -fno-stack-protector -s \
                -o "$BINDIR/libXau_dyn_test" \
                "$ROOTDIR/tools/libXau_dyn_test.c" \
                -L"$ROOTDIR/initramfs/lib64" \
                -Wl,--no-as-needed -lc -Wl,--as-needed \
                -l:libXau.so.6 \
                -Wl,-rpath,/lib64 2>&1; then
            echo "  libXau_dyn_test: $(wc -c < "$BINDIR/libXau_dyn_test") bytes"
        else
            echo "  WARNING: libXau_dyn_test build failed"
        fi
    fi
fi

# Copy ELF binaries to initramfs directory.
for bin in init hello echo_client initramfs_srv rootfs_srv ramdisk_srv blk_srv nvme_srv iwl_srv cache_srv fat16_srv fat_srv ext2_srv ext_srv xfs_srv iso9660_srv udf_srv apfs_srv iscsi_srv sctp_srv acpi_srv pci_srv part_srv console_srv shell net_srv eth_srv batman_srv ip6_srv tcp4_srv pipe_upper pipe_drain spin bench pong grant_echo grant_echo_srv grant_echo_test macro_bench cap_test call_reply_test security_srv shm_srv vfs_srv tmpfs_srv devfs_srv procfs_srv uds_srv pipe_srv pty_srv event_srv inotify_srv syslog_srv sysv_srv hello_c sock_test sock6_test tsh getty_login ld-telix tz_test pthread_test initdb_test postmaster_test pg_full_test libc_test calc stress_test sshd proxy_srv linux_srv linux_exit42 glibc_hello wayland_test wl_compositor_min hello_wl libxcvt_dyn_test libdrm_dyn_test libxshmfence_dyn_test libXau_dyn_test fsprobe fb_srv input_srv compositor_srv term_srv mtk_srv ntfs_srv btrfs_srv i915_srv usb_srv hda_srv; do
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

echo "Building ISO 9660 test image..."
"$ROOTDIR/tools/make-iso9660.sh"

echo "Building UDF test image..."
"$ROOTDIR/tools/make-udf.sh"

echo "Building XFS test image..."
"$ROOTDIR/tools/make-xfs.sh"

echo "Building APFS test image..."
"$ROOTDIR/tools/make-apfs.sh"

echo "Building NTFS test image..."
"$ROOTDIR/tools/make-ntfs.sh"

echo "Building btrfs test image..."
"$ROOTDIR/tools/make-btrfs.sh"

echo "Writing GPT partition table..."
"$ROOTDIR/tools/make-gpt.sh"

# Rebuild the CPIO archive.
echo "Packing initramfs..."
"$ROOTDIR/tools/make-initramfs.sh"

echo "Done! User binaries packed into initramfs."
