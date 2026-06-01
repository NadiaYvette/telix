#!/bin/bash
# Non-interactive T2 SDE config generator.
#
# Usage:
#   tools/t2/generate-config.sh [--name NAME] [--arch ARCH] [--libc LIBC]
#                               [--target T] [--cross|--no-cross] [--clean]
#
# What it does:
#   1. Picks a target arch (default: --arch from host uname -m, mapped to
#      T2's naming).
#   2. Decides cross vs. native by comparing target arch to host arch
#      (override with --cross/--no-cross).  We don't search for cross
#      compilers on the host — T2 bootstraps its own toolchain in
#      stage 0/1 when SDECFG_USE_CROSSCC=1 (the default).
#   3. Sources the requested target's config.in to pull in its
#      SDECFGSET_* defaults.
#   4. Writes $T2_HOME/config/<NAME>/config + packages files directly,
#      bypassing scripts/Config's ncurses TUI.
#
# Why this works:
#   T2's scripts/config-functions.in set_data() (line 146-148) reads
#   SDECFGSET_<KEY> first and skips the menu prompt if it's set.  We
#   pre-populate those, then write config + packages exactly the way
#   scripts/Config would on its final cycle.  scripts/Build-Target
#   only reads from config/<NAME>/{config,packages}, not from any TUI
#   state.
#
# Expected env:
#   TELIX_T2_HOME    path to a t2sde checkout (default: ~/src/t2sde)
#   TELIX_TARGET     T2 target name (default: tlx-min)

set -e

# --- args -----------------------------------------------------------------

NAME=telix-min
TARGET=${TELIX_TARGET:-tlx-min}
ARCH=
LIBC=glibc
INIT=busybox
OPT=size
CROSS=auto
CLEAN=0
T2_HOME=${TELIX_T2_HOME:-$HOME/src/t2sde}

while [ "$1" ]; do
    case "$1" in
        --name)     NAME="$2";   shift 2 ;;
        --target)   TARGET="$2"; shift 2 ;;
        --arch)     ARCH="$2";   shift 2 ;;
        --libc)     LIBC="$2";   shift 2 ;;
        --init)     INIT="$2";   shift 2 ;;
        --opt)      OPT="$2";    shift 2 ;;
        --cross)    CROSS=1;     shift ;;
        --no-cross) CROSS=0;     shift ;;
        --clean)    CLEAN=1;     shift ;;
        --t2-home)  T2_HOME="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^set -e/{ /^set -e/d; s/^# \?//; p; }' "$0"
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

if [ ! -d "$T2_HOME" ]; then
    echo "T2 SDE not found at $T2_HOME" >&2
    echo "  clone with: git clone --depth=1 https://github.com/rxrbln/t2sde $T2_HOME" >&2
    exit 1
fi

# --- arch mapping ---------------------------------------------------------
#
# T2 arch names live under $T2_HOME/architecture/.  Map host uname -m to
# T2's naming when the user didn't pass --arch.

host_arch=$(uname -m)
host_t2_arch=
case "$host_arch" in
    x86_64)         host_t2_arch=x86-64 ;;
    aarch64)        host_t2_arch=arm64 ;;
    riscv64)        host_t2_arch=riscv64 ;;
    loongarch64)    host_t2_arch=loongarch64 ;;
    mips64*)        host_t2_arch=mips64 ;;
    ppc64le)        host_t2_arch=powerpc64 ;;
    *)              host_t2_arch="$host_arch" ;;
esac

if [ -z "$ARCH" ]; then
    ARCH=$host_t2_arch
fi

if [ ! -d "$T2_HOME/architecture/$ARCH" ]; then
    echo "Unknown T2 arch '$ARCH' (no $T2_HOME/architecture/$ARCH)" >&2
    echo "Available:" >&2
    ls "$T2_HOME/architecture/" | grep -vE '^(README|share)$' | sed 's/^/  /' >&2
    exit 1
fi

if [ "$CROSS" = auto ]; then
    if [ "$ARCH" = "$host_t2_arch" ]; then
        CROSS=0
    else
        CROSS=1
    fi
fi

# --- target sync ----------------------------------------------------------
#
# If the user is building our local tlx-min target, make sure it's been
# sync'd into the T2 tree first.

if [ "$TARGET" = tlx-min ] && [ ! -d "$T2_HOME/target/$TARGET" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [ -x "$SCRIPT_DIR/sync-target.sh" ]; then
        echo "Syncing $TARGET into $T2_HOME ..."
        TELIX_T2_HOME="$T2_HOME" "$SCRIPT_DIR/sync-target.sh"
    fi
fi

if [ ! -d "$T2_HOME/target/$TARGET" ]; then
    echo "Target '$TARGET' missing from $T2_HOME/target/" >&2
    exit 1
fi

# --- config name ----------------------------------------------------------

cfg_dir="$T2_HOME/config/$NAME"
if [ -d "$cfg_dir" ] && [ "$CLEAN" = 1 ]; then
    rm -rf "$cfg_dir"
fi
mkdir -p "$cfg_dir"

# --- build the config file ------------------------------------------------
#
# Order copies scripts/Config: header, SDECFGSET_* assignments (one per
# `set_data` call in config.in), then SDECFG_ID at the end.  We don't
# emit the navigation breadcrumbs (current/menu_current) — those only
# matter for re-entering the TUI; build scripts don't read them.

sdever=$(cd "$T2_HOME" && sed -n 's/^sdever=\(.*\)/\1/p' scripts/parse-config 2>/dev/null | tr -d '"')
[ -z "$sdever" ] && sdever=$(cd "$T2_HOME" && awk -F= '/^sdever=/{gsub(/"/,"",$2); print $2; exit}' scripts/parse-config 2>/dev/null)
[ -z "$sdever" ] && sdever=unknown

cfg_file="$cfg_dir/config"

{
    echo "#"
    echo "# T2 $sdever Config File"
    echo "#"
    echo

    # Core target identity.
    echo "export SDECFGSET_ARCH='$ARCH'"
    echo "export SDECFGSET_TARGET='$TARGET'"
    echo "export SDECFGSET_KERNEL='linux'"
    echo "export SDECFGSET_LIBC='$LIBC'"
    echo "export SDECFGSET_INIT='$INIT'"
    echo "export SDECFGSET_OPT='$OPT'"
    echo "export SDECFGSET_EXPERT=1"

    # Cross vs native.  USE_CROSSCC=1 makes T2 bootstrap its own
    # toolchain (binutils + gcc) before building any user package,
    # so we don't depend on host cross compilers.
    if [ "$CROSS" = 1 ]; then
        echo "export SDECFGSET_CROSSBUILD=1"
        echo "export SDECFGSET_USE_CROSSCC=1"
    else
        echo "export SDECFGSET_CROSSBUILD=0"
        echo "export SDECFGSET_USE_CROSSCC=1"
    fi

    # Things our tlx-min target wants by default.  These mirror
    # tools/t2/targets/tlx-min/config.in so the standalone target file
    # stays the single source of truth even if you later switch to
    # T2's TUI for tuning.
    echo "export SDECFGSET_DO_REBUILD_STAGE=0"
    echo "export SDECFGSET_DISABLE_NLS=1"
    echo "export SDECFGSET_PARANOIA_CHECK=1"
    echo "export SDECFGSET_CREATE_DOCS=0"
    echo "export SDECFGSET_DO_CHECK=0"
    echo "export SDECFGSET_LTO=0"
    echo "export SDECFGSET_LD_AS_NEEDED=0"
    echo "export SDECFGSET_STATIC=0"
    echo "export SDECFGSET_STATIC_IN_USR=0"
    echo "export SDECFGSET_LIMITCXX=0"
    echo "export SDECFGSET_MULTILIB=0"
    echo "export SDECFGSET_SOFTFLOAT=0"
    echo "export SDECFGSET_DEBUG=0"
    echo "export SDECFGSET_IDCKSUM=0"
    echo "export SDECFGSET_CREATE_CACHE=1"

    # Mirror the SDECFGSET_* values to SDECFG_* — set_data writes both
    # under the hood (SDECFG_KEY is what build scripts read; SDECFGSET_*
    # is the override-defaults mechanism).
    for v in SDECFG_ARCH SDECFG_TARGET SDECFG_KERNEL SDECFG_LIBC \
             SDECFG_INIT SDECFG_OPT SDECFG_CROSSBUILD SDECFG_USE_CROSSCC \
             SDECFG_DO_REBUILD_STAGE SDECFG_DISABLE_NLS \
             SDECFG_PARANOIA_CHECK SDECFG_CREATE_DOCS SDECFG_DO_CHECK \
             SDECFG_LTO SDECFG_LD_AS_NEEDED SDECFG_STATIC \
             SDECFG_STATIC_IN_USR SDECFG_LIMITCXX SDECFG_MULTILIB \
             SDECFG_SOFTFLOAT SDECFG_DEBUG SDECFG_IDCKSUM \
             SDECFG_CREATE_CACHE SDECFG_EXPERT; do
        set_var=SDECFGSET_${v#SDECFG_}
        echo "export $v=\"\${$set_var:-}\""
    done

    # Final ID — build scripts use it as the build dir suffix.
    id_arch=$ARCH
    [ "$CROSS" = 1 ] && id_arch="cross-$ARCH"
    echo
    echo "export SDECFG_ID='$NAME-$sdever-$id_arch'"
} > "$cfg_file"

echo "Wrote $cfg_file"

# --- generate the package list --------------------------------------------
#
# scripts/Create-PkgList is non-interactive: it just walks package/* and
# emits the X/O selection lines based on T2's standard selection model.
# We then apply our target's pkgsel overrides.

pkg_file="$cfg_dir/packages"
(
    cd "$T2_HOME"
    if [ -x scripts/Create-PkgList ]; then
        scripts/Create-PkgList "$ARCH" linux > "$pkg_file"
        echo "Wrote $pkg_file ($(wc -l < "$pkg_file") packages)"
    else
        echo "WARN: $T2_HOME/scripts/Create-PkgList missing — packages file left empty" >&2
        : > "$pkg_file"
    fi
)

# Apply our target's pkgsel overrides.  Real pkgsel format per
# t2sde/scripts/config-functions.lua pkgsel_parse:
#   <action> <pattern>
# where action is X (select), O (unselect), - (remove), = (baseline),
# include (sub-file).  Pattern is glob.  The packages file's package
# name lives in column 5 (`X stages pri category PKG ver ...`).
target_pkgsel="$T2_HOME/target/$TARGET/pkgsel"
apply_pkgsel() {
    local sel="$1"
    [ -f "$sel" ] || return 0
    while IFS= read -r line; do
        line=${line%%#*}
        # Trim.
        line=$(echo "$line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
        [ -z "$line" ] && continue
        local action pattern
        action=$(echo "$line" | awk '{print $1}')
        pattern=$(echo "$line" | awk '{print $2}')
        [ -z "$action" ] && continue
        case "$action" in
            X|x|O|o)
                local flag=${action^^}
                if [ "$pattern" = "*" ]; then
                    sed -i -E "s/^[XO]( )/$flag\1/" "$pkg_file"
                else
                    # Pattern -> awk regex.  Anchor on the package-name
                    # column (5th field, space-separated).
                    awk -v flag="$flag" -v pat="$pattern" '
                        BEGIN { gsub(/\*/, ".*", pat); gsub(/\?/, ".", pat); pat="^" pat "$" }
                        { if ($5 ~ pat) $1=flag; print }
                    ' OFS=' ' "$pkg_file" > "$pkg_file.tmp" && mv "$pkg_file.tmp" "$pkg_file"
                fi
                ;;
            -)
                # Remove rows whose package name matches.
                awk -v pat="$pattern" '
                    BEGIN { gsub(/\*/, ".*", pat); gsub(/\?/, ".", pat); pat="^" pat "$" }
                    !($5 ~ pat) { print }
                ' "$pkg_file" > "$pkg_file.tmp" && mv "$pkg_file.tmp" "$pkg_file"
                ;;
            include)
                # Recurse.  Resolve relative to the parent pkgsel's dir.
                local sub="$pattern"
                [ -e "$sub" ] || sub="$(dirname "$sel")/$pattern"
                apply_pkgsel "$sub"
                ;;
            *)
                echo "  pkgsel: skipping unknown action '$action' in $sel" >&2
                ;;
        esac
    done < "$sel"
}
if [ -f "$target_pkgsel" ]; then
    apply_pkgsel "$target_pkgsel"
    echo "Applied $target_pkgsel overrides"
fi

# --- summary --------------------------------------------------------------

selected=$(grep -c '^X ' "$pkg_file" 2>/dev/null || echo 0)
echo
echo "Config '$NAME' ready in $cfg_dir:"
echo "  arch=$ARCH target=$TARGET libc=$LIBC init=$INIT cross=$CROSS"
echo "  packages selected: $selected"
echo
echo "Build with:"
echo "  cd $T2_HOME && ./t2 build -cfg $NAME"
