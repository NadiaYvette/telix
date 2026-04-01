#!/bin/bash
# Build userspace + kernel for a given architecture.
# Usage: tools/build-kernel.sh [aarch64|riscv64|x86_64] [--release]
set -e

ARCH="${1:-aarch64}"
RELEASE_FLAG=""
if [ "${2:-}" = "--release" ]; then
    RELEASE_FLAG="--release"
fi

ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"

case "$ARCH" in
    aarch64) TARGET="aarch64-unknown-none" ;;
    riscv64) TARGET="riscv64gc-unknown-none-elf" ;;
    x86_64)      TARGET="x86_64-unknown-none" ;;
    loongarch64) TARGET="loongarch64-unknown-none" ;;
    mips64)      TARGET="targets/mips64el-telix-none.json" ;;
    *)
        echo "Unknown arch: $ARCH"
        exit 1
        ;;
esac

# Step 1: Build userspace binaries and pack initramfs.
echo "=== Building userspace for $ARCH ==="
"$ROOTDIR/tools/build-user.sh" "$ARCH"

# Step 1b: Update HELLO.ELF in test.img for the target architecture.
# For mips64, the target path strips "targets/" prefix and ".json" suffix.
HELLO_TARGET="${TARGET#targets/}"
HELLO_TARGET="${HELLO_TARGET%.json}"
HELLO_BIN="$ROOTDIR/target/$HELLO_TARGET/release/hello"
DISK_IMG="$ROOTDIR/test.img"
if [ -f "$HELLO_BIN" ] && [ -f "$DISK_IMG" ] && command -v mcopy >/dev/null 2>&1; then
    mdel -i "$DISK_IMG" ::HELLO.ELF 2>/dev/null || true
    mcopy -i "$DISK_IMG" "$HELLO_BIN" ::HELLO.ELF 2>/dev/null && \
        echo "  Updated HELLO.ELF in test.img for $ARCH" || true
fi

# Step 2: Build kernel.
echo "=== Building kernel for $ARCH ($TARGET) ==="
EXTRA_FLAGS=""
if [ "$ARCH" = "mips64" ]; then
    EXTRA_FLAGS="-Z build-std=core -Z build-std-features=compiler-builtins-mem -Z json-target-spec"
fi
RUSTUP_TOOLCHAIN=nightly \
    RUSTC="${RUSTC:-$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/rustc}" \
    "$HOME/.cargo/bin/cargo" build \
    --target "$TARGET" \
    -p telix-kernel \
    $RELEASE_FLAG $EXTRA_FLAGS

echo "=== Build complete ==="
echo "Kernel: $ROOTDIR/target/$TARGET/${2:+release}${2:-debug}/telix-kernel"
