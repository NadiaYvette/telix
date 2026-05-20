#!/bin/bash
# tools/t2/install-into-initramfs.sh — merge a built T2 `tlx-min`
# userspace tree into Telix's initramfs/ before make-initramfs.sh runs.
#
# Usage:
#   TELIX_T2_HOME=/path/to/t2sde \
#   TELIX_T2_BUILD=<config-name>  \
#   tools/t2/install-into-initramfs.sh
#
# `TELIX_T2_BUILD` is the config name used at `./t2 config --cfg <name>`
# (default: telix-min).  The script looks for the produced rootfs tree
# under $TELIX_T2_HOME/build/$TELIX_T2_BUILD-*/rootfs/.
#
# What lands where:
#   * /bin, /sbin, /usr/bin, /usr/sbin, /usr/lib, /lib, /etc — copied
#     into initramfs/ as a parallel tree.  Doesn't disturb Telix's
#     own server binaries (which live under their own paths and
#     don't conflict with standard FHS locations).
#   * The merge is additive; existing initramfs/ entries are preserved
#     unless a T2 file has the same path.

set -e

ROOTDIR="$(cd "$(dirname "$0")/../.." && pwd)"
INITRAMFS="$ROOTDIR/initramfs"

if [ -z "${TELIX_T2_HOME:-}" ]; then
    echo "TELIX_T2_HOME is not set.  See tools/t2/sync-target.sh."
    exit 1
fi

CFG="${TELIX_T2_BUILD:-telix-min}"

# T2 build dirs follow the pattern build/<cfg>-<ver>-<arch>/.  Pick the
# newest one matching our config name.
ROOTFS=$(ls -td "$TELIX_T2_HOME"/build/"$CFG"-*/rootfs 2>/dev/null | head -1)
if [ -z "$ROOTFS" ] || [ ! -d "$ROOTFS" ]; then
    echo "No built rootfs found at $TELIX_T2_HOME/build/$CFG-*/rootfs"
    echo "Did you finish ./t2 build $CFG ?"
    exit 1
fi

echo "Merging T2 rootfs from: $ROOTFS"
echo "Into Telix initramfs:   $INITRAMFS"
echo

# Use cp -a for archive-mode (preserves perms, symlinks).  --no-clobber
# so we never overwrite a Telix-shipped file by accident.
cp -a --no-clobber "$ROOTFS"/* "$INITRAMFS"/ 2>&1 | tail -20 || true
echo
echo "Merge complete.  Rebuild initramfs with:"
echo "  tools/make-initramfs.sh"
echo
du -sh "$INITRAMFS"
