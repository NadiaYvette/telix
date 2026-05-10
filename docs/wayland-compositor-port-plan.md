# Wayland Compositor Port Plan (Telix)

Status: planning / scaffolding (no code yet).
Author: research session, 2026-05-09.
Scope: pick a real Wayland compositor and document everything required to
replace `tools/wl_compositor_min.c` with a production-grade compositor that
can host Xwayland (and eventually GTK/Qt clients) on Telix.

Cross-references:
- `docs/xwayland-gnome-firefox-roadmap.md` — overall arc.
- `docs/xwayland-porting-plan.md` — the Xwayland-side port plan.
- `tools/wl_compositor_min.c` — current stub compositor used for the H13
  test.  Advertises wl_compositor v4, wl_shm v1, wl_output v3, xdg_wm_base
  v3, wl_seat v5; forwards opcodes but does not actually push pixels to
  DRM and has no real input-event delivery to clients.
- `userlib/bin/linux_srv.rs` — the syscall bridge the compositor will use
  (must cover everything the chosen compositor calls).
- `initramfs/lib64/` — already-deployed shared libraries we can link
  against (libdrm, libgbm, libpixman, libwayland-client, libEGL, libGL,
  libxshmfence, libepoxy, libxcb-*, etc.).

---

## 1. Chosen compositor: cage 0.2.0 (or latest 0.2.x) on wlroots 0.18.x

### Rationale

`cage` (https://github.com/cage-kiosk/cage) is a kiosk compositor: it runs
exactly one Wayland client fullscreen, with no chrome, no panels, no
multi-window management, no IPC layer of its own.  This is *exactly* the
shape the Telix Xwayland demo needs — we want to launch
`cage -- Xwayland :0` (or `cage -- xeyes`) and have the compositor
disappear from the picture.

Compared to the alternatives:

| Compositor | LoC (compositor only) | wlroots-based | Reason rejected/accepted |
|------------|----------------------:|---------------|--------------------------|
| **cage**   | ~1.5 k C             | yes           | **CHOSEN**: smallest viable wlroots compositor; single-client model; minimal config surface; no IPC/XML/protocol extras |
| sway       | ~30 k C              | yes           | Big.  i3-style tiling, ipc.json, swaybar/swaylock/swayidle ecosystem.  Pulls in pcre2/json-c/scdoc.  Overkill for a single-Xwayland host |
| labwc      | ~20 k C              | yes           | Pulls libxml2 (theming/menu config) and a stacking WM model we don't need |
| weston     | ~80 k C              | **no** — its own libweston | Reference impl, but its own backend stack (DRM, X11, fbdev, headless, RDP) duplicates what wlroots already gives us, and its wayland-server abstraction layer is more invasive to port.  We'd own a second backend tree |
| mir        | very large (C++)     | no            | Canonical-ecosystem-shaped; hard build (gtest/gmock/boost-ish C++); not minimal |

cage's smallness also matters because we will likely have to **fork it** to
work around two Telix realities:

1. seatd / logind: cage normally talks to seatd (or logind) over D-Bus or a
   private UDS to acquire the DRM master / open input devices.  Telix has
   neither.  We will need a "noop seat" backend that just opens
   `/dev/dri/card0` and `/dev/input/event*` directly (linux_srv exposes
   them with no privilege gate today).  This is a ~50 LoC patch in
   wlroots' `backend/session/`.
2. `wl_display_add_socket_auto` walks `/run/user/$UID/wayland-N`.  Telix
   doesn't have `/run/user/$UID`; we use `/tmp/wayland-0` in the existing
   stub.  Either set `XDG_RUNTIME_DIR=/tmp` or patch.

Both patches are tiny, localised, and can be carried as Telix-side
out-of-tree patches against the upstream tarball.

### Versions

- cage: latest 0.2.x release (`v0.2.0` or whatever ships against wlroots
  0.18 — pin once the build works).
- wlroots: 0.18.x to match cage 0.2.x.  wlroots 0.19+ keeps moving fast
  and we don't want a moving target.
- wayland: 1.24.0 (already vendored as `wayland-1.24.0-1.fc43.src.rpm`
  and built into `initramfs/lib64/libwayland-client.so.0`; need to also
  build and install `libwayland-server.so.0`).
- libxkbcommon: required by wlroots and cage; not yet in initramfs.
- libinput: required by wlroots (input backend); not yet in initramfs.
- pixman: present (`libpixman-1.so.0`).

---

## 2. Already-vendored / built artifacts (Telix-side audit)

Source RPMs at repo root:
- `wayland-1.24.0-1.fc43.src.rpm`
- `libxcb-1.17.0-6.fc43.src.rpm`, `libxcvt-0.1.2-10.fc43.src.rpm`,
  `libX11-1.8.13-1.fc43.src.rpm`, `libXt-1.3.1-3.fc43.src.rpm`,
  `xeyes-1.3.0-6.fc43.src.rpm`, `xorg-x11-server-Xwayland-24.1.10-1.fc43.src.rpm`.
- **No** wlroots, cage, libinput, libxkbcommon, seatd source RPMs vendored
  yet — those need to be added.

`initramfs/lib64/` already contains (relevant to the compositor port):
- `libwayland-client.so.0` (no server-side counterpart yet)
- `libdrm.so.2`, `libgbm.so.1`, `libxshmfence.so.1`
- `libpixman-1.so.0`
- `libEGL.so.1`, `libEGL_mesa.so.0`, `libGL.so.1`, `libGLX_mesa.so.0`,
  `libGLdispatch.so.0`, `libepoxy.so.0`
- `libudev.so.1`, `libsystemd.so.0`, `libcap.so.2`, `libcap-ng.so.0`
- `libei.so.1`, `liboeffis.so.1` (interesting: emulated input infra
  already present)

What's **missing and must be built**:
- `libwayland-server.so.0` (build from the same wayland-1.24.0 source — already vendored)
- `libxkbcommon.so.0`
- `libinput.so.10`
- `libwlroots.so.13` (or whatever soname ships with 0.18.x)
- `cage` binary itself

No wlroots/cage/etc. source is currently vendored anywhere in the tree
(searched `find /home/nyc/src/telix -maxdepth 4 -type d -iname '*wlroots*'`
etc., all empty).

---

## 3. Linux syscall surface (compositor side)

The compositor process makes far more demanding syscalls than a Wayland
*client* does.  Inferred from wlroots/libinput/cage source plus a typical
strace of cage on Linux (we can't strace locally — no compositor
installed; this list is from source inspection of wlroots 0.18 and cage
0.2 plus general knowledge of wlroots backends):

### Filesystem / FD primitives
- `openat`, `read`, `write`, `close`, `lseek`, `pread64`, `pwrite64`
- `fstat`, `statx`, `readlinkat`, `access`/`faccessat`
- `pipe2`, `dup`, `dup2`, `dup3`, `close_range`
- `fcntl` with `F_GETFD`, `F_SETFD` (CLOEXEC), `F_GETFL`, `F_SETFL` (O_NONBLOCK), `F_DUPFD_CLOEXEC`
- `getdents64` (scanning `/dev/input`, `/dev/dri`)
- `mkdir`/`mkdirat` (XDG_RUNTIME_DIR)
- `unlink`/`unlinkat` (stale wayland-N socket cleanup)

### Memory / shared memory
- `mmap` with both `MAP_PRIVATE|MAP_ANON` and `MAP_SHARED` (the latter is
  critical — clients hand the compositor wl_shm fds and the compositor
  mmaps them MAP_SHARED to read pixels)
- `munmap`, `mprotect`, `madvise`
- `memfd_create`, `ftruncate`, `fcntl(F_ADD_SEALS)` (some xkbcommon
  builds use sealed memfd for keymap delivery)
- `brk` (musl/glibc heap)

### IPC / sockets
- `socket(AF_UNIX, SOCK_STREAM, 0)` / `SOCK_SEQPACKET` for the wayland
  display socket
- `bind`, `listen`, `accept4` (with `SOCK_NONBLOCK|SOCK_CLOEXEC`)
- `connect` (only if cage talks to seatd — we'll patch that out)
- `recvmsg` / `sendmsg` with **SCM_RIGHTS** ancillary data — *every*
  wl_shm and dmabuf transfer rides on this; this is the critical socket
  feature to validate
- `getsockname`, `getpeername`
- `getsockopt` with `SO_PEERCRED` (some compositors check peer uid)
- `shutdown`

### Event loop
- `epoll_create1(EPOLL_CLOEXEC)`, `epoll_ctl(ADD/MOD/DEL)`, `epoll_wait`
- `eventfd2(0, EFD_CLOEXEC|EFD_NONBLOCK)` — wlroots event loop
  wakeups
- `timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC|TFD_NONBLOCK)`,
  `timerfd_settime` — repeat key, idle timers
- `signalfd4` — wlroots optionally; we'll set
  `WLR_SESSION=noop`-style and avoid this
- `poll`/`ppoll` — libwayland-server's main loop variant

### Clocks / random / process
- `clock_gettime(CLOCK_MONOTONIC|CLOCK_REALTIME)`
- `getrandom` (XDG/wayland cookie)
- `getpid`, `getppid`, `gettid`, `getuid`, `geteuid`
- `prctl(PR_SET_NAME, ...)`, `arch_prctl` (TLS)
- `set_robust_list`, `set_tid_address`
- `rt_sigaction`, `rt_sigprocmask`, `sigaltstack`
- `clone`/`clone3` (wlroots and pixman have worker threads)
- `futex` (pthreads)
- `wait4`/`waitid` (cage launches the kiosk client as a child)
- `execve` (same)

### Graphics-specific
- `ioctl(/dev/dri/card0, ...)` — every DRM_IOCTL_* listed in
  linux_srv.rs:291 onwards (VERSION, GET_CAP, MODE_GETRESOURCES,
  MODE_GETCONNECTOR, MODE_GETENCODER, MODE_GETCRTC, MODE_SETCRTC,
  MODE_CREATE_DUMB, MODE_MAP_DUMB, MODE_DESTROY_DUMB, MODE_ADDFB,
  MODE_RMFB, MODE_PAGE_FLIP).  Also `SET_MASTER`/`DROP_MASTER` (currently
  no-op in linux_srv — fine)
- DRM ioctls **probably also needed** that linux_srv doesn't yet handle:
  - `DRM_IOCTL_MODE_ATOMIC` (atomic kms — wlroots' default in 0.18; can
    be disabled via `WLR_DRM_NO_ATOMIC=1`)
  - `DRM_IOCTL_MODE_GETPLANE_RES`, `DRM_IOCTL_MODE_GETPLANE`,
    `DRM_IOCTL_MODE_OBJ_GETPROPERTIES` — wlroots probes planes
  - `DRM_IOCTL_PRIME_HANDLE_TO_FD`, `DRM_IOCTL_PRIME_FD_TO_HANDLE` —
    needed for dmabuf / GBM (zero-copy with Mesa)
  - `DRM_IOCTL_GEM_CLOSE`
  - `DRM_IOCTL_MODE_CREATE_BLOB`, `DRM_IOCTL_MODE_DESTROYPROPBLOB`
  - `DRM_IOCTL_MODE_CURSOR2`
- `ioctl(/dev/input/eventN, ...)` — already covered by
  `handle_evdev_ioctl` (linux_srv.rs:7643).  Confirm coverage of
  `EVIOCGRAB` (libinput grabs devices) and `EVIOCREVOKE` (seat handover).

---

## 4. linux_srv coverage gaps

Cross-referenced against `userlib/bin/linux_srv.rs` (verified by
`grep -nE "fn handle_..."`).  Status legend: OK = handler exists; STUB =
returns sensible default but not real; ABSENT = ENOSYS today.

| Syscall / ioctl | Status | Action |
|-----------------|--------|--------|
| epoll_create1, epoll_ctl, epoll_wait | OK | — |
| eventfd2, timerfd_create/settime/gettime | OK | — |
| memfd_create + F_ADD_SEALS | OK (allow_sealing for /dev/shm) | confirm `MFD_ALLOW_SEALING` flag honoured |
| shm_open / /dev/shm/* | OK (memfd-backed) | — |
| socket/bind/listen/accept4/connect (AF_UNIX) | OK | — |
| sendmsg/recvmsg with SCM_RIGHTS | OK (linux_srv.rs:10248,10480) | **smoke test: open memfd, send fd via UDS, mmap on receive side** — this is the single most important compatibility check |
| signalfd | STUB (no events ever delivered) | acceptable — set `WAYLAND_DEBUG=1`-style env to skip; or real impl later |
| inotify_init1/add_watch | STUB (no events) | acceptable for cage; xkbcommon does NOT use inotify |
| pidfd_open / pidfd_send_signal | check coverage | low priority; cage's child wait works with wait4 |
| DRM_IOCTL_MODE_ATOMIC | ABSENT | **gap**: set `WLR_DRM_NO_ATOMIC=1` initially; full atomic later |
| DRM_IOCTL_MODE_GETPLANE_RES / GETPLANE / OBJ_GETPROPERTIES | ABSENT | **gap**: needed even without atomic; either implement or short-circuit to "no overlay planes" |
| DRM_IOCTL_PRIME_HANDLE_TO_FD / FD_TO_HANDLE | ABSENT | **gap**: blocks GBM/dmabuf path; workaround = wl_shm-only rendering (`WLR_RENDERER=pixman`) |
| DRM_IOCTL_GEM_CLOSE | ABSENT | needed even with dumb buffers (lifecycle of FB handle).  Currently DESTROY_DUMB exists but wlroots may also call GEM_CLOSE — verify |
| DRM_IOCTL_MODE_CREATE_BLOB / DESTROYPROPBLOB | ABSENT | needed for atomic; defer with no-atomic |
| DRM_IOCTL_MODE_CURSOR2 | ABSENT | wlroots falls back to software cursor if absent — fine |
| EVIOCGRAB, EVIOCREVOKE | unverified | audit `handle_evdev_ioctl` for these two |
| sched_setscheduler / setpriority | unverified | wlroots may bump itself to SCHED_RR; should be allowed-or-EPERM-no-fail |

**Action items for linux_srv (in priority order):**

1. **Smoke-test SCM_RIGHTS end-to-end with a memfd** — write a tiny C
   test under `tools/` that creates a memfd, sends it over a UDS pair,
   mmaps it on the receiver, validates contents.  Without this the whole
   compositor port is doomed.
2. **Audit `handle_evdev_ioctl` for `EVIOCGRAB`(0x40044590) and
   `EVIOCREVOKE`(0x40044591)**: libinput will issue both.  EVIOCGRAB
   returning success-no-op is fine.  EVIOCREVOKE can ENOSYS.
3. **Add the DRM ioctls in the "gap" rows above**, gated by what wlroots
   actually issues at boot.  Strategy: run cage, watch for "DRM ioctl
   0xXXXX returned ENOSYS" log lines from linux_srv, implement
   one-by-one.
4. **Validate epoll_wait + timerfd interaction** under multiple ready
   timers — wlroots' main loop hammers this.

We will defer:
- atomic KMS (use `WLR_DRM_NO_ATOMIC=1`)
- GBM/dmabuf (use `WLR_RENDERER=pixman`)
- hardware cursor (let wlroots fall back to SW cursor)

That gets us the smallest possible first-light path.

---

## 5. Build-system approach

Vendor each tarball under `vendor/<name>-<version>/`, build with meson (or
autotools where forced) into a Telix sysroot, install into `initramfs/`,
and pack with `tools/make-initramfs.sh`.

`tools/build-cage.sh` (created — see below) drives the full chain.  It
builds, in order:

1. `wayland 1.24.0` — server side (`-Dscanner=true -Dlibraries=true
   -Ddocumentation=false -Dtests=false`).  We already have client; this
   adds `libwayland-server.so.0` and `wayland-scanner` (host tool;
   currently we'd cross-build, so keep host scanner separate).
2. `libxkbcommon` (e.g. 1.7.0) — `-Denable-x11=false
   -Denable-docs=false -Denable-wayland=true`.
3. `libinput` (e.g. 1.26.x) — `-Ddebug-gui=false -Dtests=false
   -Ddocumentation=false -Dlibwacom=false`.
4. `wlroots 0.18.x` — `-Dxwayland=enabled -Dexamples=false
   -Dbackends=drm,libinput -Drenderers=pixman -Dxcb-errors=disabled`.
   Apply two patches:
   - `wlroots-noop-session.patch` — bypass seatd/logind, open
     `/dev/dri/card0` and `/dev/input/event*` directly.
   - `wlroots-no-systemd.patch` — drop libsystemd dependency.
5. `cage 0.2.x` — `-Dxwayland=true`.  Apply
   `cage-xdg-runtime-dir.patch` to default `XDG_RUNTIME_DIR=/tmp` if
   unset.
6. Install all `.so`/binaries into `initramfs/`.
7. Pack with `tools/make-initramfs.sh`.

Cross-toolchain choice: link against the **glibc** sysroot we already
ship in `initramfs/lib64/` (libc.so.6, ld-linux-x86-64.so.2).  This
matches the toolchain Xwayland and xeyes are already built with — keeping
one libc minimises ABI surprises.  musl is an option later if size
matters.

---

## 6. Test approach

In escalating order of confidence:

### Step H+1 (parity)
1. Build cage, install into initramfs.
2. Replace the H13 invocation of `wl_compositor_min` with `cage --
   /usr/bin/xeyes`.
3. Goal: cage's wl_display socket is bound at `/tmp/wayland-0`, xeyes
   connects, gets the same global advertisements as today, runs the same
   roundtrip, and exits cleanly.  This validates that cage + wlroots is
   functionally **at least** as capable as `wl_compositor_min`.

### Step H+2 (real pixels)
4. Re-enable cage's DRM scanout path.  xeyes now actually draws pixels
   on the framebuffer (visible in QEMU SDL/GTK display).  This is the
   first real "graphical Telix" milestone.

### Step H+3 (Xwayland on cage)
5. `cage -- Xwayland :0` then `DISPLAY=:0 xeyes` from a separate Telix
   process.  This replaces the current "Xwayland directly hosts xeyes"
   path with the Linux-canonical "Xwayland is just a Wayland client of a
   real compositor" arrangement.  Side benefit: we shed a lot of the
   xtrans/abstract-socket workarounds documented in
   `project_xwayland_x0_listen_race.md` and friends.

### Step H+4 (toolkit clients)
6. Run a tiny GTK4 hello-world (or `gtk4-demo`) directly as a Wayland
   client of cage (no Xwayland).  Then a Qt6 equivalent.  Each adds
   roughly one library family (gtk: glib/pango/cairo; qt:
   qtbase).  These uncover the next round of personality gaps.

### Regression gate
- Existing H13 test (`tools/wl_compositor_min`) stays in tree as a
  protocol-conformance smoke test for any future linux_srv work that
  could regress AF_UNIX or memfd.

---

## 7. Open questions / risks

- **Wayland socket location.** wlroots-side patch must agree with what
  Xwayland/clients look for.  Standardise on `/tmp/wayland-0` and
  `XDG_RUNTIME_DIR=/tmp` across all of init.rs spawn sites
  (`project_xeyes_envp_compiler_elision.md` is a reminder to be careful
  with envp materialisation).
- **DRM master.** linux_srv currently no-ops `SET_MASTER`/`DROP_MASTER`.
  If cage is the only compositor that ever runs, this is fine.  When/if
  we add VT switching, revisit.
- **Pixman renderer is slow.**  Expect <30 fps at 1024x768 in QEMU TCG;
  KVM should be fine.  Per `feedback_kvm_required.md`, all QEMU tests
  must use `TELIX_ACCEL=kvm`.
- **wlroots 0.18 vs 0.19.**  0.19 dropped some legacy interfaces and
  reshuffled the session API.  Pinning to 0.18 simplifies the noop-seat
  patch.  Re-evaluate after first light.
- **libei / liboeffis** are already in initramfs.  They're not strictly
  required by cage, but they may be pulled in transitively; double-check
  link lines.

---

## 8. Recommended sequencing for the actual port work

Roughly one PR per step.  Each step is independently testable.

1. **Vendor sources**: download wlroots/cage/libinput/libxkbcommon
   tarballs + sigs into `vendor/`.  Add `tools/build-cage.sh` (already
   stubbed).  No build on CI yet.
2. **Build wayland-server + libxkbcommon + libinput** on a normal Linux
   host using the Telix sysroot.  Verify they install cleanly into a
   staging dir.  Ship the resulting .so files into `initramfs/`.
3. **SCM_RIGHTS + memfd round-trip test** under `tools/scm_rights_test.c`
   — fastest way to find linux_srv.rs:10248/10480 ABI bugs before they
   manifest as cage hangs.
4. **Build wlroots 0.18 with noop-session patch**.  Standalone smoke
   test: link a 50-line C program against libwlroots that just creates a
   `wl_display`, registers globals, and runs the event loop for 1 s.
5. **Build cage**.  First boot under Telix with `cage -- /bin/true` —
   pure protocol-and-init smoke test, no graphics.
6. **cage hosting xeyes** via wl_shm/pixman renderer.  This is the
   parity milestone with `wl_compositor_min`.
7. **cage hosting Xwayland**, then `xeyes` against `:0`.  Retire
   `wl_compositor_min` from the H13 path (keep the source for
   regression).
8. **GTK hello-world** under cage — a fresh client family, validates
   protocol coverage beyond what Xwayland exercises.
9. **Atomic KMS + GBM/dmabuf** — productionisation; unblocks GL
   acceleration for Mesa software-on-llvmpipe → Mesa-on-virtio-gpu
   later.

Each of steps 4–6 will likely surface 3–5 linux_srv ENOSYS gaps; budget
accordingly.
