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

# Prepend our staging dir to the system pkg-config path so we find e.g.
# our just-built wayland-server before the system one (if any), while
# still picking up host deps like libffi.pc, libudev.pc.  Do NOT set
# PKG_CONFIG_LIBDIR — that would *replace* the default search path and
# hide host deps.
PKG_CONFIG_PATH="$STAGE/usr/lib64/pkgconfig:$STAGE/usr/share/pkgconfig:$(pkg-config --variable=pc_path pkg-config)"
export PKG_CONFIG_PATH

# Rewrite -I/usr/include and -L/usr/lib64 in OUR staged .pc files to
# $STAGE/usr/include and $STAGE/usr/lib64 — but ONLY for the files we
# build ourselves (those have prefix=/usr).  System .pc files (in the
# real /usr/lib64/pkgconfig) also have prefix=/usr, and the sysroot
# rewrite gets applied to those too, which would hide host headers.
# So we use a separate variant: copy our staged .pc files into a
# rewritten dir with absolute paths baked in.
STAGE_PC_REWRITE="$STAGE/usr/lib64/pkgconfig-rewritten"
rewrite_staged_pkgconfig() {
    mkdir -p "$STAGE_PC_REWRITE"
    for pc in "$STAGE/usr/lib64/pkgconfig/"*.pc; do
        [[ -f "$pc" ]] || continue
        sed "s|^prefix=/usr|prefix=$STAGE/usr|" "$pc" > "$STAGE_PC_REWRITE/$(basename "$pc")"
    done
}
rewrite_staged_pkgconfig
PKG_CONFIG_PATH="$STAGE_PC_REWRITE:$PKG_CONFIG_PATH"
export PKG_CONFIG_PATH

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
require curl
require tar
require sha256sum

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

# SHA256 hashes pinned 2026-05-12 from the first successful fetch.  If
# upstream rotates a release tarball (rare but happens with regenerated
# release archives), update both the hash and the bump rationale here.
WAYLAND_SHA256=82892487a01ad67b334eca83b54317a7c86a03a89cfadacfef5211f11a5d0536
XKBCOMMON_SHA256=65782f0a10a4b455af9c6baab7040e2f537520caa2ec2092805cdfd36863b247
LIBINPUT_SHA256=bda944e6d60741432e10f29001c3326ee8aba2968787f78611f420f90580bd8b
WLROOTS_SHA256=cf776c169169f279808d9eabc6583f484338dcd454c966a285ff178c88c105d4
CAGE_SHA256=9d3f659e0f19636a958f9e1bf4d22268d7e2705d7e2989888401ec443c1cb6c3

# fetch_and_verify <url> <expected_sha256> <out_name>
fetch_and_verify() {
    local url=$1 want=$2 out="$VENDOR/$3"
    if [[ -f "$out" ]]; then
        local got
        got=$(sha256sum "$out" | cut -d' ' -f1)
        if [[ "$got" == "$want" ]]; then
            log "  $3 already present (sha256 ok)"
            return 0
        fi
        log "  $3 present but sha256 mismatch — refetching"
        rm -f "$out"
    fi
    log "  fetch $url"
    curl -fsSL --retry 3 --max-time 120 -o "$out" "$url"
    local got
    got=$(sha256sum "$out" | cut -d' ' -f1)
    [[ "$got" == "$want" ]] || die "  sha256 mismatch for $3: got $got want $want"
    log "  $3 ok"
}

# extract_tarball <tarball> <expected_dir>
extract_tarball() {
    local tb="$VENDOR/$1" dir="$VENDOR/$2"
    if [[ -d "$dir" ]]; then
        log "  $2 already extracted"
        return 0
    fi
    log "  extract $1"
    ( cd "$VENDOR" && tar -xf "$tb" )
    [[ -d "$dir" ]] || die "  extraction did not yield $2"
}

step_deps() {
    log "Fetching upstream tarballs into $VENDOR/"
    # Wayland: we already have the Fedora src.rpm at the repo root, which
    # carries the upstream tarball + a signature.  Reuse it if vendor/ is
    # missing the tarball; otherwise fetch from wayland.freedesktop.org.
    if [[ ! -f "$VENDOR/wayland-${WAYLAND_VER}.tar.xz" ]]; then
        local rpm="$ROOTDIR/wayland-${WAYLAND_VER}-1.fc43.src.rpm"
        if [[ -f "$rpm" ]] && command -v rpm2cpio >/dev/null 2>&1; then
            log "  extract wayland-${WAYLAND_VER}.tar.xz from $(basename "$rpm")"
            ( cd "$VENDOR" && rpm2cpio "$rpm" | cpio -idmv "wayland-${WAYLAND_VER}.tar.xz" >/dev/null 2>&1 )
        fi
    fi
    if [[ ! -f "$VENDOR/wayland-${WAYLAND_VER}.tar.xz" ]]; then
        fetch_and_verify \
            "https://gitlab.freedesktop.org/wayland/wayland/-/releases/${WAYLAND_VER}/downloads/wayland-${WAYLAND_VER}.tar.xz" \
            "$WAYLAND_SHA256" "wayland-${WAYLAND_VER}.tar.xz"
    else
        local got
        got=$(sha256sum "$VENDOR/wayland-${WAYLAND_VER}.tar.xz" | cut -d' ' -f1)
        [[ "$got" == "$WAYLAND_SHA256" ]] || die "wayland tarball sha256 mismatch: $got != $WAYLAND_SHA256"
        log "  wayland-${WAYLAND_VER}.tar.xz ok (sha256 verified)"
    fi

    fetch_and_verify \
        "https://xkbcommon.org/download/libxkbcommon-${XKBCOMMON_VER}.tar.xz" \
        "$XKBCOMMON_SHA256" "libxkbcommon-${XKBCOMMON_VER}.tar.xz"

    fetch_and_verify \
        "https://gitlab.freedesktop.org/libinput/libinput/-/archive/${LIBINPUT_VER}/libinput-${LIBINPUT_VER}.tar.gz" \
        "$LIBINPUT_SHA256" "libinput-${LIBINPUT_VER}.tar.gz"

    fetch_and_verify \
        "https://gitlab.freedesktop.org/wlroots/wlroots/-/releases/${WLROOTS_VER}/downloads/wlroots-${WLROOTS_VER}.tar.gz" \
        "$WLROOTS_SHA256" "wlroots-${WLROOTS_VER}.tar.gz"

    fetch_and_verify \
        "https://github.com/cage-kiosk/cage/archive/refs/tags/v${CAGE_VER}.tar.gz" \
        "$CAGE_SHA256" "cage-${CAGE_VER}.tar.gz"

    log "Extracting tarballs"
    extract_tarball "wayland-${WAYLAND_VER}.tar.xz"        "wayland-${WAYLAND_VER}"
    extract_tarball "libxkbcommon-${XKBCOMMON_VER}.tar.xz" "libxkbcommon-${XKBCOMMON_VER}"
    extract_tarball "libinput-${LIBINPUT_VER}.tar.gz"      "libinput-${LIBINPUT_VER}"
    extract_tarball "wlroots-${WLROOTS_VER}.tar.gz"        "wlroots-${WLROOTS_VER}"
    extract_tarball "cage-${CAGE_VER}.tar.gz"              "cage-${CAGE_VER}"

    log "deps step complete"
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
        -Denable-wayland=false \
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
    log "Building wlroots $WLROOTS_VER"
    local src="$VENDOR/wlroots-$WLROOTS_VER"
    local b="$BUILD/wlroots"
    [[ -d "$src" ]] || die "missing $src"

    # wlroots 0.18.2 doesn't actually link libsystemd, and libseat's
    # builtin backend (LIBSEAT_BACKEND=builtin) handles the no-seatd /
    # no-logind case at runtime — no source patches needed.  cage will be
    # launched with LIBSEAT_BACKEND=builtin so libseat opens DRM/evdev
    # directly via open(2).  Patches dir kept for future hooks.
    if [[ ! -f "$src/.telix-patched" ]]; then
        for p in wlroots-noop-session.patch wlroots-no-systemd.patch; do
            if [[ -f "$PATCHES/$p" ]]; then
                log "Applying patch $p"
                ( cd "$src" && patch -p1 <"$PATCHES/$p" )
            fi
        done
        touch "$src/.telix-patched"
    fi

    # -Drenderers is array-typed with choices [auto, gles2, vulkan]; pixman
    # is always built unconditionally.  Pass an empty list to disable both
    # GLES and Vulkan, leaving pixman as the only software renderer.
    # session=enabled is required because backends=drm,libinput pull in
    # the session backend (which links libseat).
    meson_setup "$src" "$b" \
        -Dxwayland=enabled \
        -Dexamples=false \
        -Dbackends=drm,libinput \
        -Drenderers=[] \
        -Dallocators=auto \
        -Dxcb-errors=disabled \
        -Dcolor-management=disabled \
        -Dlibliftoff=disabled \
        -Dsession=enabled
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

    # cage 0.2.0 has only one meson option: man-pages.  Xwayland support is
    # automatic if wlroots was built with it (we did).  We skip man pages
    # to avoid the scdoc dep.
    meson_setup "$src" "$b" \
        -Dman-pages=disabled
    ninja -C "$b" -j"$JOBS"
    meson_install "$b"
}

step_install() {
    log "Installing artifacts from $STAGE into $INITRAMFS"
    install -d "$INITRAMFS/lib64"

    # Helper: copy a glob of files if any match.  Skip silently otherwise.
    copy_if_present() {
        local pat=$1 dst=$2
        # shellcheck disable=SC2206
        local matches=( $pat )
        if [[ -e "${matches[0]}" ]]; then
            cp -av "${matches[@]}" "$dst"
        fi
    }

    # libs (each can be missing if its build step didn't run)
    copy_if_present "$STAGE/usr/lib64/libwayland-server.so*" "$INITRAMFS/lib64/"
    copy_if_present "$STAGE/usr/lib64/libxkbcommon.so*"      "$INITRAMFS/lib64/"
    copy_if_present "$STAGE/usr/lib64/libinput.so*"          "$INITRAMFS/lib64/"
    copy_if_present "$STAGE/usr/lib64/libwlroots*.so*"       "$INITRAMFS/lib64/"

    # Host-side runtime deps libinput links against — these are not in our
    # staging dir but the initramfs glibc loader needs them present too.
    # Only ship if libinput got installed (gated by file presence).
    if [[ -e "$INITRAMFS/lib64/libinput.so.10" ]]; then
        for hostlib in /usr/lib64/libmtdev.so.1* /usr/lib64/libevdev.so.2*; do
            [[ -e "$hostlib" ]] && cp -av "$hostlib" "$INITRAMFS/lib64/"
        done
    fi

    # wlroots links libseat for session management.  We pass
    # LIBSEAT_BACKEND=builtin at cage launch so libseat opens DRM/evdev
    # directly via open(2) — no seatd / logind needed on Telix.
    # Also pull in libdisplay-info (EDID parsing) and the xcb-icccm /
    # xcb-ewmh helpers — all NEEDED by libwlroots-0.18.so at runtime.
    if [[ -e "$INITRAMFS/lib64/libwlroots-0.18.so" ]] \
       || compgen -G "$INITRAMFS/lib64/libwlroots*.so*" > /dev/null; then
        # Use a broader glob — libdisplay-info on Fedora has an unusual
        # .so.2 → .so.0.2.0 redirect, so .so.2* alone misses the real file.
        for hostlib in \
                /usr/lib64/libseat.so.1* \
                /usr/lib64/libdisplay-info.so* \
                /usr/lib64/libxcb-ewmh.so.2* \
                /usr/lib64/libxcb-icccm.so.4*; do
            [[ -e "$hostlib" ]] && cp -av "$hostlib" "$INITRAMFS/lib64/"
        done
    fi

    # cage binary — only when the cage step has run
    if [[ -x "$STAGE/usr/bin/cage" ]]; then
        install -d "$INITRAMFS/usr/bin"
        cp -av "$STAGE/usr/bin/cage" "$INITRAMFS/usr/bin/cage"
    fi

    # Wayland protocol data is read at runtime by libwayland-server callers.
    install -d "$INITRAMFS/usr/share"
    [[ -d "$STAGE/usr/share/wayland" ]]           && cp -av "$STAGE/usr/share/wayland"           "$INITRAMFS/usr/share/"
    [[ -d "$STAGE/usr/share/wayland-protocols" ]] && cp -av "$STAGE/usr/share/wayland-protocols" "$INITRAMFS/usr/share/"

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
