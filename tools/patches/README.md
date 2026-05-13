# Telix-side patches for the Wayland compositor port

These patches are applied by `tools/build-cage.sh` against the upstream
sources under `vendor/`. Each one carries a single, narrowly scoped
change against the corresponding upstream — no refactoring, no
cleanups, no "while-we're-here." Keep them small to make the rebase on
each upstream version bump trivial.

Patches needed:

## `wlroots-noop-session.patch` — NOT NEEDED for wlroots 0.18.2

**Resolution 2026-05-13 (Stage 4 audit):** libseat itself has a
"builtin" backend that just does `open(O_RDWR|O_CLOEXEC)` on the
device path — no seatd, no logind, no D-Bus, no daemon. Cage will
be launched with `LIBSEAT_BACKEND=builtin` in the environment and
libseat will skip seatd / logind entirely.

`libseat.so.1` is shipped to `initramfs/lib64/` from the host
package; runtime size is small. The wlroots session.c source is
linked as-is, no patches.

If a future wlroots version drops the builtin backend or the libseat
ABI changes, revisit and write the patch then.

## `wlroots-no-systemd.patch` — NOT NEEDED for wlroots 0.18.2

**Resolution 2026-05-13 (Stage 4 audit):** Verified by grep —
`wlroots-0.18.2/meson.build` and `backend/*/meson.build` contain
zero `systemd` / `elogind` / `hwdata` references. The libsystemd
dep mentioned in older docs was wlroots 0.16 or earlier; 0.18
talks to libudev directly without going through libsystemd.

## `cage-xdg-runtime-dir.patch` (against cage 0.2.x)

**Why:** cage calls `wl_display_add_socket_auto`, which walks
`/run/user/$UID/wayland-N`. Telix has no `/run/user`; the existing
H13 stub uses `/tmp/wayland-0`.

**What it does:** If `XDG_RUNTIME_DIR` is unset, default to
`/tmp` before the socket bind. One-liner in `cage.c::main()`
near the `setenv("WAYLAND_DISPLAY", ...)` block. Alternative:
just set `XDG_RUNTIME_DIR=/tmp` in the init.rs spawn — that's
arguably cleaner; document the choice in the commit.

---

Status as of 2026-05-13: all three patches are TODO. The build
script handles their absence gracefully — it logs `WARN: ... patch
missing (TODO)` and proceeds. So step_wlroots / step_cage will
fail to apply the patches today but otherwise run; the resulting
binaries simply won't run on Telix until the patches land.
