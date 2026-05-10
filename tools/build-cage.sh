#!/bin/bash
# tools/build-cage.sh — build the cage Wayland compositor (and its wlroots
# stack) for Telix and install into initramfs/.
#
# This script is currently a STUB / documentation-of-steps.  It will not run
# end-to-end yet; missing pieces are clearly marked TODO.  See
# docs/wayland-compositor-port-plan.md for the full plan it implements.
#
# Usage:
#   tools/build-cage.sh [step]
#
# where [step] is one of: deps, wayland-server, xkbcommon, libinput,
# wlroots, cage, install, all (default).
#
# Layout:
#   vendor/                      — upstream tarballs (gitignored)
#       wayland-1.24.0/
#       libxkbcommon-1.7.0/
#       libinput-1.26.0/
#       wlroots-0.18.2/
#       cage-0.2.0/
#   build/<arch>/<pkg>/          — out-of-tree meson build dirs
#   stage/<arch>/                — temporary install root (DESTDIR)
#   initramfs/lib64/             — final destination for *.so
#   initramfs/usr/bin/cage       — final destination for cage binary
#
# Patches (carried in tools/patches/):
#   wlroots-noop-session.patch       — bypass seatd/logind; open
#                                      /dev/dri/card0 and /dev/input/event*
#                                      directly.  See port plan §1.
#   wlroots-no-systemd.patch         — drop libsystemd link dep.
#   cage-xdg-runtime-dir.patch       — default XDG_RUNTIME_DIR=/tmp.

set -euo pipefail

ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-x86_64}"
JOBS="${JOBS:-$(nproc)}"

# --- Pinned versions ---------------------------------------------------------
WAYLAND_VER=1.24.0           # already vendored as src.rpm at repo root
XKBCOMMON_VER=1.7.0
LIBINPUT_VER=1.26.0
WLROOTS_VER=0.18.2
CAGE_VER=0.2.0

# --- Layout ------------------------------------------------------------------
VENDOR="$ROOTDIR/vendor"
BUILD="$ROOTDIR/build/$ARCH"
STAGE="$ROOTDIR/stage/$ARCH"
INITRAMFS="$ROOTDIR/initramfs"
PATCHES="$ROOTDIR/tools/patches"

# --- Sysroot we link against -------------------------------------------------
# The Telix initramfs lib64 is treated as the target sysroot for these
# packages.  glibc + ld-linux-x86-64.so.2 already live there.
SYSROOT_LIB="$INITRAMFS/lib64"
SYSROOT_INCLUDE="${SYSROOT_INCLUDE:-/usr/include}"  # TODO: vendor headers

PKG_CONFIG_PATH="$STAGE/usr/lib64/pkgconfig:$STAGE/usr/share/pkgconfig"
export PKG_CONFIG_PATH
export PKG_CONFIG_LIBDIR="$PKG_CONFIG_PATH"

mkdir -p "$VENDOR" "$BUILD" "$STAGE" "$PATCHES"

# --- Helpers -----------------------------------------------------------------

die() { echo "build-cage: $*" >&2; exit 1; }
log() { echo "[build-cage] $*"; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"
}

require meson
require ninja
require pkg-config
require wget
require tar

# Standard meson invocation for our packages.
meson_setup() {
    local src=$1 build=$2; shift 2
    meson setup --reconfigure --buildtype=release --prefix=/usr \
        --libdir=lib64 --sysconfdir=/etc \
        "$build" "$src" "$@"
}

meson_install() {
    local build=$1
    DESTDIR="$STAGE" ninja -C "$build" install
}

# --- Steps -------------------------------------------------------------------

step_deps() {
    log "Fetching upstream tarballs into $VENDOR/"
    # TODO: actual fetch + signature verification.  Pseudocode:
    #
    # fetch_and_verify https://wayland.freedesktop.org/releases/wayland-${WAYLAND_VER}.tar.xz
    # fetch_and_verify https://xkbcommon.org/download/libxkbcommon-${XKBCOMMON_VER}.tar.xz
    # fetch_and_verify https://gitlab.freedesktop.org/libinput/libinput/-/archive/${LIBINPUT_VER}/libinput-${LIBINPUT_VER}.tar.bz2
    # fetch_and_verify https://gitlab.freedesktop.org/wlroots/wlroots/-/releases/${WLROOTS_VER}/downloads/wlroots-${WLROOTS_VER}.tar.gz
    # fetch_and_verify https://github.com/cage-kiosk/cage/archive/v${CAGE_VER}.tar.gz
    log "TODO: implement fetch+verify; for now, drop tarballs in $VENDOR/ manually"
}

step_wayland_server() {
    log "Building wayland $WAYLAND_VER (server side)"
    local src="$VENDOR/wayland-$WAYLAND_VER"
    local b="$BUILD/wayland"
    [[ -d "$src" ]] || die "missing $src — run 'deps' or extract src.rpm"
    meson_setup "$src" "$b" \
        -Dscanner=true \
        -Dlibraries=true \
        -Ddocumentation=false \
        -Dtests=false
    ninja -C "$b" -j"$JOBS"
    meson_install "$b"
}

step_xkbcommon() {
    log "Building libxkbcommon $XKBCOMMON_VER"
    local src="$VENDOR/libxkbcommon-$XKBCOMMON_VER"
    local b="$BUILD/xkbcommon"
    [[ -d "$src" ]] || die "missing $src"
    meson_setup "$src" "$b" \
        -Denable-x11=false \
        -Denable-docs=false \
        -Denable-wayland=true \
        -Denable-xkbregistry=false
    ninja -C "$b" -j"$JOBS"
    meson_install "$b"
}

step_libinput() {
    log "Building libinput $LIBINPUT_VER"
    local src="$VENDOR/libinput-$LIBINPUT_VER"
    local b="$BUILD/libinput"
    [[ -d "$src" ]] || die "missing $src"
    meson_setup "$src" "$b" \
        -Ddebug-gui=false \
        -Dtests=false \
        -Ddocumentation=false \
        -Dlibwacom=false \
        -Dudev-dir=/usr/lib/udev
    ninja -C "$b" -j"$JOBS"
    meson_install "$b"
}

step_wlroots() {
    log "Building wlroots $WLROOTS_VER (with Telix patches)"
    local src="$VENDOR/wlroots-$WLROOTS_VER"
    local b="$BUILD/wlroots"
    [[ -d "$src" ]] || die "missing $src"

    # Apply Telix-specific patches if not already applied (idempotent guard).
    if [[ ! -f "$src/.telix-patched" ]]; then
        for p in wlroots-noop-session.patch wlroots-no-systemd.patch; do
            if [[ -f "$PATCHES/$p" ]]; then
                log "Applying patch $p"
                ( cd "$src" && patch -p1 <"$PATCHES/$p" )
            else
                log "WARN: patch $PATCHES/$p missing (TODO: write it)"
            fi
        done
        touch "$src/.telix-patched"
    fi

    meson_setup "$src" "$b" \
        -Dxwayland=enabled \
        -Dexamples=false \
        -Dbackends=drm,libinput \
        -Drenderers=pixman \
        -Dxcb-errors=disabled \
        -Dsession=disabled
    ninja -C "$b" -j"$JOBS"
    meson_install "$b"
}

step_cage() {
    log "Building cage $CAGE_VER"
    local src="$VENDOR/cage-$CAGE_VER"
    local b="$BUILD/cage"
    [[ -d "$src" ]] || die "missing $src"

    if [[ ! -f "$src/.telix-patched" ]]; then
        if [[ -f "$PATCHES/cage-xdg-runtime-dir.patch" ]]; then
            ( cd "$src" && patch -p1 <"$PATCHES/cage-xdg-runtime-dir.patch" )
        else
            log "WARN: cage-xdg-runtime-dir.patch missing (TODO)"
        fi
        touch "$src/.telix-patched"
    fi

    meson_setup "$src" "$b" \
        -Dxwayland=true
    ninja -C "$b" -j"$JOBS"
    meson_install "$b"
}

step_install() {
    log "Installing artifacts from $STAGE into $INITRAMFS"
    # libs
    install -d "$INITRAMFS/lib64"
    cp -av "$STAGE/usr/lib64/"libwayland-server.so* "$INITRAMFS/lib64/" || true
    cp -av "$STAGE/usr/lib64/"libxkbcommon.so*       "$INITRAMFS/lib64/" || true
    cp -av "$STAGE/usr/lib64/"libinput.so*           "$INITRAMFS/lib64/" || true
    cp -av "$STAGE/usr/lib64/"libwlroots*.so*        "$INITRAMFS/lib64/" || true
    # binary
    install -d "$INITRAMFS/usr/bin"
    cp -av "$STAGE/usr/bin/cage" "$INITRAMFS/usr/bin/cage"
    # data
    install -d "$INITRAMFS/usr/share"
    cp -av "$STAGE/usr/share/wayland"           "$INITRAMFS/usr/share/" 2>/dev/null || true
    cp -av "$STAGE/usr/share/wayland-protocols" "$INITRAMFS/usr/share/" 2>/dev/null || true
    log "Now run tools/make-initramfs.sh to repack."
}

main() {
    local step="${1:-all}"
    case "$step" in
        deps)            step_deps ;;
        wayland-server)  step_wayland_server ;;
        xkbcommon)       step_xkbcommon ;;
        libinput)        step_libinput ;;
        wlroots)         step_wlroots ;;
        cage)            step_cage ;;
        install)         step_install ;;
        all)
            step_deps
            step_wayland_server
            step_xkbcommon
            step_libinput
            step_wlroots
            step_cage
            step_install
            ;;
        *)
            die "unknown step: $step (expected: deps | wayland-server | xkbcommon | libinput | wlroots | cage | install | all)"
            ;;
    esac
}

main "$@"
