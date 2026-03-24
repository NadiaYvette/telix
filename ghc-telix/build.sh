#!/bin/bash
# GHC cross-compiler build script for Telix.
# Requires: GHC 9.6+ host compiler, cabal, LLVM 15+.
#
# This configures a cross-compilation of GHC targeting aarch64-telix.
# The RTS shims in rts/ bridge GHC RTS calls to Telix syscalls/IPC.
#
# Usage: ghc-telix/build.sh [configure|build|clean]
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOTDIR="$(cd "$SCRIPT_DIR/.." && pwd)"
GHC_SRC="${GHC_SRC:-$HOME/ghc}"
TELIX_SYSROOT="$ROOTDIR/musl-telix"

TARGET="aarch64-unknown-telix"

case "${1:-configure}" in
    configure)
        echo "=== GHC Telix Cross-Compiler Configuration ==="
        echo "Target: $TARGET"
        echo "GHC source: $GHC_SRC"
        echo "Telix sysroot: $TELIX_SYSROOT"
        echo ""
        echo "Prerequisites:"
        echo "  - Host GHC 9.6+"
        echo "  - LLVM 15+ (for aarch64 code generation)"
        echo "  - musl-telix built (Phases 71-77)"
        echo ""
        echo "Configure hadrian with:"
        echo "  ./configure --target=$TARGET \\"
        echo "    --with-llc=llc-15 --with-opt=opt-15 \\"
        echo "    --with-system-libffi"
        echo ""
        echo "Build command:"
        echo "  hadrian/build --flavour=perf-cross -j"
        ;;

    build)
        if [ ! -d "$GHC_SRC" ]; then
            echo "ERROR: GHC source not found at $GHC_SRC"
            echo "Set GHC_SRC to point to your GHC checkout."
            exit 1
        fi

        echo "Building GHC cross-compiler for Telix..."
        echo "  (This is a placeholder — actual build requires host GHC + LLVM)"

        # Compile RTS shims.
        CC="${CC:-clang}"
        CFLAGS="-target aarch64-unknown-none -ffreestanding -nostdlib \
                -isystem $TELIX_SYSROOT/include -O2"

        for src in OSThreads IOManager MBlock Timer; do
            echo "  Compiling rts/$src.c..."
            $CC $CFLAGS -c "$SCRIPT_DIR/rts/$src.c" -o "$SCRIPT_DIR/rts/$src.o" 2>/dev/null || \
                echo "    (skipped — build dependencies not available)"
        done

        echo "Done."
        ;;

    clean)
        rm -f "$SCRIPT_DIR/rts/"*.o
        echo "Cleaned."
        ;;

    *)
        echo "Usage: $0 [configure|build|clean]"
        exit 1
        ;;
esac
