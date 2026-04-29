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

# Patch libc.so.6's __intl_freemem to a bare `ret`.  Telix's
# Linux personality leaves the libc i18n machinery in a state that
# makes __intl_freemem walk a corrupt _nl_domain_bindings list and
# fault at `mov 0x8(%rbx),%rdi` with rbx=NULL — symptom is
# `Unhandled #PF: CR2=0x8 RIP=libc+0x1416d` whenever a binary exits
# via libc's atexit cleanup.  Replacing the function entry with 0xc3
# (ret) leaks the i18n state at exit (we don't care, the process is
# dying) but unblocks any binary that uses exit() instead of _exit().
# Offset 0x14110 in glibc-2.42 (Fedora 43); verify before patching.
LIBC_SO="${DEST_DIR}/libc.so.6"
if [ -f "${LIBC_SO}" ]; then
    if [ "$(xxd -s 0x14110 -l 4 -p "${LIBC_SO}")" = "f30f1efa" ]; then
        printf '\xc3' | dd of="${LIBC_SO}" bs=1 seek=82192 count=1 conv=notrunc 2>/dev/null
        echo "===> patched libc.so.6 __intl_freemem -> ret"
    elif [ "$(xxd -s 0x14110 -l 1 -p "${LIBC_SO}")" = "c3" ]; then
        : # already patched
    else
        echo "===> WARNING: libc.so.6 __intl_freemem signature changed; not patching" >&2
    fi

    # Patch __dcigettext at 0x13820 to a fast no-translation
    # `mov %rsi, %rax; ret` (returns msgid1 unchanged).  Same defensive
    # rationale as __intl_freemem: under Telix's personality, Xwayland's
    # threads occasionally land in the middle of __dcigettext's
    # instruction stream (RIP=libc+0x1405d, mid-jmp-displacement) and
    # GP-fault.  TLS / FSBASE corruption is the suspected upstream
    # cause; until that's properly diagnosed, short-circuit gettext
    # entirely so its body never executes.  C-locale binaries like
    # Xwayland (with LANG=C) get back the same untranslated string
    # they passed in, so this is functionally a no-op for them.
    if [ "$(xxd -s 0x13820 -l 4 -p "${LIBC_SO}")" = "f30f1efa" ]; then
        printf '\x48\x89\xf0\xc3' | dd of="${LIBC_SO}" bs=1 seek=79904 count=4 conv=notrunc 2>/dev/null
        echo "===> patched libc.so.6 __dcigettext -> mov rsi,rax; ret"
    elif [ "$(xxd -s 0x13820 -l 4 -p "${LIBC_SO}")" = "4889f0c3" ]; then
        : # already patched
    else
        echo "===> WARNING: libc.so.6 __dcigettext signature changed; not patching" >&2
    fi
fi

# Dedupe: when fetch produces both libfoo.so.X (the soname) and
# libfoo.so.X.Y.Z (the canonical file) with identical content, drop
# the longer-named copy.  initramfs_srv has a fixed file-table cap
# (MAX_FILES) — every dup we keep eats a slot for nothing, and ld.so
# only ever opens by soname.
shopt -s nullglob
for soname in "${DEST_DIR}"/*.so.[0-9]; do
    for longer in "${soname}".[0-9]*; do
        if [ -f "$longer" ] && cmp -s "$soname" "$longer" 2>/dev/null; then
            rm -f "$longer"
        fi
    done
done
shopt -u nullglob

echo "===> done.  initramfs/lib64 contents:"
ls -la "${DEST_DIR}" | tail -n +2 | awk '{print "  " $NF " ( " $5 " bytes )"}'
