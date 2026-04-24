#!/bin/bash
# tools/xport/fetch-and-install.sh — install a Fedora dynamic library into
# Telix's initramfs so the Linux personality can dlopen it.
#
# Usage: tools/xport/fetch-and-install.sh <rpm-name> [<rpm-name>...]
#
# For each RPM name (e.g. libxcvt, libwayland-client, pixman), the script:
#   1. Downloads the RPM from the host's default dnf repo if not cached.
#   2. Extracts the .so files and symlinks under /usr/lib64/ from the RPM.
#   3. Copies them into initramfs/lib64/, preserving symlinks.
#
# Only the runtime .so artefacts land in initramfs — no /usr/include,
# no /usr/share, no /usr/lib/pkgconfig.  (X11 bitmap fonts and locale
# data are handled by a separate helper when we get to them.)
#
# Assumptions:
#   - dnf5 with `download` subcommand is available on the build host.
#   - rpm2cpio + cpio are installed.
#
# Re-running with an already-installed lib is idempotent: the .so files
# get overwritten in initramfs/lib64/ from the (potentially newer)
# cached RPM.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TELIX_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CACHE_DIR="${SCRIPT_DIR}/cache"
DEST_DIR="${TELIX_ROOT}/initramfs/lib64"

mkdir -p "${CACHE_DIR}"
mkdir -p "${DEST_DIR}"

for pkg in "$@"; do
    echo "===> ${pkg}"

    # Fetch RPM if we don't already have it cached.  Explicitly request
    # the x86_64 arch so multilib doesn't hand us the i686 copy (which
    # installs under /usr/lib instead of /usr/lib64 and would silently
    # copy nothing).
    cached=$(ls "${CACHE_DIR}"/${pkg}-[0-9]*.x86_64.rpm 2>/dev/null | head -n 1 || true)
    if [ -z "${cached}" ]; then
        (cd "${CACHE_DIR}" \
            && dnf5 download --arch x86_64 "${pkg}" 2>&1 | tail -n 5)
        cached=$(ls "${CACHE_DIR}"/${pkg}-[0-9]*.x86_64.rpm 2>/dev/null | head -n 1)
        if [ -z "${cached}" ]; then
            echo "  FAIL: could not download ${pkg}" >&2
            exit 1
        fi
    fi
    echo "  rpm: $(basename "${cached}")"

    # Extract into a staging dir, then copy only the .so artefacts.
    stage="${CACHE_DIR}/stage-${pkg}"
    rm -rf "${stage}"
    mkdir -p "${stage}"
    (cd "${stage}" && rpm2cpio "${cached}" | cpio -idm --quiet 2>/dev/null)

    # Copy .so files from {/usr}/lib64.  Use `cp -L` to dereference
    # symlinks: our initramfs / VFS doesn't follow symlinks, so the
    # canonical soname (e.g. libxcvt.so.0) needs to be a real file
    # holding the .so contents, not a symlink to libxcvt.so.0.1.2.
    # That duplicates bytes but keeps each requested soname openable.
    shopt -s nullglob
    for src_root in "${stage}/usr/lib64" "${stage}/lib64"; do
        [ -d "${src_root}" ] || continue
        for entry in "${src_root}"/*.so*; do
            name="$(basename "${entry}")"
            # Skip stripped debug symbols and static archives.
            case "${name}" in
                *.a) continue ;;
                *.debug) continue ;;
            esac
            # Remove first so cp can replace either a stale symlink or
            # a stale regular file from a previous install.
            rm -f "${DEST_DIR}/${name}"
            cp -L "${entry}" "${DEST_DIR}/${name}"
            echo "  + lib64/${name} ($(stat -c %s "${DEST_DIR}/${name}") bytes)"
        done
    done
    shopt -u nullglob

    # Leave the stage dir in place so future re-runs can diff / audit
    # what was installed.  `tools/xport/clean.sh` will nuke the cache.
done

echo "===> done.  initramfs/lib64 contents:"
ls -la "${DEST_DIR}" | tail -n +2 | awk '{print "  " $NF " ( " $5 " bytes )"}'
