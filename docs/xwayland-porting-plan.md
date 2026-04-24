# Xwayland + X11-Side Porting Plan

## Goal

Run upstream Xwayland on Telix so legacy X11 applications work atop the
Telix Wayland compositor (`tools/wl_compositor_min.c`).  Xwayland is a
Wayland *client* that presents an X11 display to other X11 clients, so
from Telix's perspective it's "yet another Linux binary" — but a big
one with a long dependency chain.

## Build strategy: dynamic linking via Telix's Linux personality

Telix already has the scaffolding for dynamic PIE binaries:
- `initramfs/lib64/ld-linux-x86-64.so.2` (glibc's dynamic loader)
- `initramfs/lib64/libc.so.6`
- `initramfs/lib64/libpthread.so.0`
- A dynamically-linked test binary `glibc_dyn_hello` (Phase 172 in
  `userlib/bin/init.rs`)
- `linux_srv` already handles `/etc/ld.so.cache`, `/lib64/ld-linux*.so`,
  ld.so's `mmap`-fixed reserve-then-replace pattern, and the long-path
  VFS protocol that ld.so uses for library lookup.

Our path is to copy the required .so files from Fedora into
`initramfs/lib64/` and let ld.so handle linking.  This sidesteps the
"rebuild everything statically" path — Fedora ships ~30 .so libraries
Xwayland needs; rebuilding each as `.a` would be weeks of work.

**Prerequisite (tracked separately):** Phase 172 (glibc_dyn_hello) is
in `userlib/bin/init.rs` but has been "in progress" per
`project_phase172_tier1.md`.  Confirm it passes on x86-64 KVM before
expecting bigger dynamically-linked binaries to work.

## Dependency tree (from Xwayland 24.1.10 src.rpm BuildRequires)

```
Xwayland
├── Wayland
│   ├── libwayland-client     pkg: wayland-libs
│   └── wayland-protocols     pkg: wayland-protocols-devel (headers only)
├── Pixman / DRM
│   ├── libpixman-1           pkg: pixman
│   ├── libdrm                pkg: libdrm
│   ├── libxshmfence          pkg: libxshmfence
│   └── libxcvt               pkg: libxcvt       ← starter dep
├── X11 core libs
│   ├── libX11                pkg: libX11
│   ├── libXau                pkg: libXau
│   ├── libXdmcp              pkg: libXdmcp
│   ├── libXtrans             header-only: xtrans
│   ├── libXext               pkg: libXext
│   ├── libXfixes             pkg: libXfixes
│   ├── libXi                 pkg: libXi
│   ├── libXinerama           pkg: libXinerama
│   ├── libxkbfile            pkg: libxkbfile
│   ├── libXmu                pkg: libXmu
│   ├── libXrender            pkg: libXrender
│   ├── libXres               pkg: libXres
│   ├── libXtst               pkg: libXtst
│   └── libXv                 pkg: libXv
├── Fonts
│   ├── libXfont2             pkg: libXfont2
│   ├── libfontenc            pkg: libfontenc
│   └── libfreetype           pkg: freetype
├── GL (optional)
│   └── libepoxy              pkg: libepoxy      ← can --disable-glamor
├── System deps (already in glibc)
│   ├── libssl                pkg: openssl-libs
│   ├── libcrypto             pkg: openssl-libs
│   └── libtirpc              pkg: libtirpc
└── base
    ├── libc, libm, libpthread    (already shipped)
    └── ld-linux-x86-64.so.2       (already shipped)
```

## Port order (leaves first, so each dep has its own deps ready)

1. **Prereq check:** verify dynamic linking works — run Phase 172 to
   completion on current master; if it fails, fix before proceeding.
2. **Tier-0 leaves** (no X11 headers, no wayland):
   - libxcvt  — 302 LOC, pure C.  Starter.
   - libdrm   — for DRI3 path (can skip with `-Ddri3=disabled` initially).
   - libxshmfence — 300 LOC, pure C.  Used by MIT-SHM sync.
3. **Tier-1 fundamentals:**
   - libXau, libXdmcp — cookie auth, tiny.
   - libXtrans — header-only, just install headers.
   - libpixman-1 — software composite, pure C + asm.
4. **Tier-2 libwayland:**
   - libwayland-client (the .so that Xwayland links).  Also provides
     `wayland-scanner` at build time.
   - wayland-protocols — headers only.
5. **Tier-3 X11 stack:**
   - libX11, libXext, libXfixes, libXi, libxkbfile, libXmu, libXrender,
     libXres, libXtst, libXv, libXinerama (mostly in-parallel).
6. **Tier-4 fonts:**
   - libfreetype, libfontenc, libXfont2.
7. **Tier-5 optional:**
   - libepoxy (skip initially — disable glamor).
   - libssl, libtirpc, libcrypto (try --disable those first; many paths
     are runtime-optional).
8. **Tier-6 Xwayland itself:**
   - Disable glamor, DRI3, GL-related features initially.
   - Disable SELinux, audit, systemd, ei, libdecor.
   - Enable MIT-SHM, composite, damage — the basics.

## Approach: copy Fedora .so → initramfs, not from-source rebuild

For each lib in order 1→6, our "port" is:

1. Locate `/lib64/lib<name>.so.<abi>` on the Fedora host.
2. Copy into `initramfs/lib64/`, preserving the exact soname.
3. Copy symlinks (`libfoo.so → libfoo.so.N.M`) — ld.so follows them.
4. Run `initramfs/lib64/glibc_dyn_hello_that_uses_libfoo` to verify ld.so
   can load it under the Linux personality.
5. If something breaks — missing syscall, weird mmap path, etc. — fix in
   `linux_srv.rs` / kernel and move on.

We rebuild from source only when Fedora's .so has:
- Dependencies Telix can't satisfy (e.g. NSS, PAM, dbus).
- Features that trip on Telix kernel (e.g. `getrandom` flags not
  implemented).

Expected painful cases: anything linking to systemd / dbus / tirpc —
trim those paths at build time.

## Current session's concrete deliverables

- This planning document: `docs/xwayland-porting-plan.md`.
- `tools/xport/` directory: porting scripts.
- `tools/xport/fetch-and-install.sh <lib>`: leverages `dnf download` +
  rpm extract to drop a lib's .so files into `initramfs/lib64/`.
- Start with `libxcvt` as a smoke test — the smallest and most
  self-contained dep.
- `.gitignore`: `tools/xport/cache/` (tarballs, extracted sources) —
  local only, not tracked.

## Tracking

- `project_xwayland_goal.md` memory is updated.
- When ready to run a real Xwayland binary, we'll know quickly whether
  ld.so support holds: unresolved symbols or page-fault noise will
  point at the next fix.
