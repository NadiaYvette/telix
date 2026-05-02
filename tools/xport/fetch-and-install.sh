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
# `Unhandled #PF: CR2=0x8 RIP=libc+0x14???` whenever a binary exits
# via libc's atexit cleanup.  An entry-only patch (single 0xC3 at
# 0x14110) is insufficient because something — perhaps tail-call
# optimization, an indirect dispatch, or a registered atexit pointer
# at +0x30 — re-enters the function in the middle of the loop and
# still hits the deref.  So we splat the whole 209-byte function
# body with 0xC3: every byte becomes a single-byte `ret` instruction,
# making any control flow into ANY offset within the function range
# return immediately.  Leaks the i18n state at exit (we don't care,
# the process is dying) but unblocks binaries that exit() through
# libc's atexit cleanup.
# Offset 0x14110, length 0xd2 in glibc-2.42 (Fedora 43); verify
# before patching.
LIBC_SO="${DEST_DIR}/libc.so.6"
if [ -f "${LIBC_SO}" ]; then
    # Accept either the original `f30f1efa` (endbr64) prologue or the
    # entry-only patched `c3` — in both cases we want to splat the
    # full body.  Re-detect by reading the byte at 0x14111: if it
    # still starts with the original endbr/push-rbp pattern (any
    # non-c3 in the trailing 0xd1 bytes), do the splat.
    SECOND_BYTE="$(xxd -s 0x14111 -l 1 -p "${LIBC_SO}")"
    if [ "$SECOND_BYTE" != "c3" ]; then
        # Generate 209 (0xd1) c3 bytes following the entry, leaving
        # the entry itself c3 too (210 = 0xd2 total).
        python3 -c "
import sys
with open('${LIBC_SO}', 'r+b') as f:
    f.seek(0x14110)
    f.write(b'\\xc3' * 0xd2)
" 2>/dev/null \
        || perl -e '
open(my $f, "+<", "'${LIBC_SO}'") or die;
seek($f, 0x14110, 0);
print $f "\xc3" x 0xd2;
close($f);
' 2>/dev/null \
        || dd if=/dev/zero of=/dev/null 2>/dev/null # last-resort fallback no-op
        echo "===> patched libc.so.6 __intl_freemem body -> ret slide (210 bytes)"
    else
        : # already body-splatted
    fi

    # Patch __dcigettext at 0x13820.  Entry-only patch (mov rsi,rax; ret)
    # was insufficient: Xwayland still GP-faults at RIP=libc+0x1405d,
    # mid-instruction, even with the entry patched — the indirect
    # dispatch must be re-entering the function body partway through.
    # Same fix as __intl_freemem above: splat the entire function body
    # with 0xC3 (single-byte `ret`).  Any control-flow landing on any
    # offset inside the function returns immediately.
    #
    # r47 still GP-faulted at libc+0x1405d, which falls into the gap
    # between the prior 0x800-byte __dcigettext splat (ending at
    # 0x14020) and the __intl_freemem splat (starting at 0x14110) —
    # 0xF0 bytes of unpatched i18n helpers (DCIGETTEXT_internal_realloc
    # / plural_eval / similar) that the indirect dispatch jumps into.
    # Bumped to 0x9E0 bytes so the splat runs from 0x13820 through
    # 0x14200, covering the full __intl_freemem range too — single
    # contiguous 0xC3 slide makes any control-flow into the entire
    # i18n region return immediately.  C-locale binaries (Xwayland
    # with LANG=C) get back the same untranslated string they passed
    # in, so behavior-wise this is a no-op for them.
    SECOND_BYTE_DC="$(xxd -s 0x13821 -l 1 -p "${LIBC_SO}")"
    if [ "$SECOND_BYTE_DC" != "c3" ]; then
        python3 -c "
import sys
with open('${LIBC_SO}', 'r+b') as f:
    f.seek(0x13820)
    f.write(b'\\xc3' * 0x9e0)
" 2>/dev/null \
        || perl -e '
open(my $f, "+<", "'${LIBC_SO}'") or die;
seek($f, 0x13820, 0);
print $f "\xc3" x 0x9e0;
close($f);
' 2>/dev/null \
        || dd if=/dev/zero of=/dev/null 2>/dev/null # last-resort no-op
        echo "===> patched libc.so.6 __dcigettext+gap+__intl_freemem -> ret slide (2528 bytes)"
    else
        : # already body-splatted
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
