# Roadmap Intersections: Path to Xwayland + GNOME + Firefox on Telix

## Overview

This document identifies which Telix development roadmap items intersect with the goal of running Xwayland + GNOME (or a Wayland compositor) + Firefox on Telix. This is a demanding target: Firefox alone exercises syscalls, signals, threads, IPC, shared memory, GPU rendering, networking, and font/locale infrastructure.

---

## Critical Path Items

### 1. Linux Personality Server (Roadmap Section 7)

**This is the single largest dependency.** Firefox, GNOME, and Xwayland are Linux binaries. They make Linux syscalls, expect Linux signal semantics, and depend on `/proc` and `/sys`.

**Required subsystems within the personality server:**

| Component | Why |
|-----------|-----|
| Syscall translation (~300+ syscalls) | Firefox uses a huge syscall surface: `clone3`, `memfd_create`, `epoll`, `eventfd`, `timerfd`, `signalfd`, `mmap`/`mprotect`/`mremap`, `futex`, `sched_*`, `socket`/`sendmsg`/`recvmsg`, `ioctl`, `fcntl`, etc. |
| Linux FD table emulation | Firefox opens hundreds of FDs: sockets, pipes, memfds, eventfds, epoll instances, `/proc` files, fonts, shared libs |
| Full signal semantics | `SA_SIGINFO`, `SA_RESTART`, `SA_ONSTACK`, real-time signals, signal masks during `epoll_wait` |
| `/proc` emulation | `/proc/self/maps` (crash reporter), `/proc/self/exe`, `/proc/meminfo`, `/proc/cpuinfo`, `/proc/sys/...` |
| `/sys` emulation | DRM device enumeration via `/sys/class/drm/`, `/sys/devices/...` |
| Thread semantics (`clone`/`clone3`) | Firefox is heavily multi-threaded: content processes, compositor, WebRender, JS workers, network thread |
| Process management (`fork`/`exec`/`wait`) | GNOME session management, Firefox multi-process (Fission) |
| Namespace/cgroup stubs | Firefox sandbox uses `CLONE_NEWUSER`, `CLONE_NEWNET`, seccomp-bpf; need at least stubs that don't fail |

**Fast-path table coverage:** `read`, `write`, `close`, `mmap`, `mprotect`, `munmap`, `brk`, `lseek`, `ioctl`, `fcntl`, `dup2`, `getpid`, `gettid`, `clock_gettime` should all be kernel-translated for performance.

### 2. Filesystem Infrastructure (Roadmap Section 2)

Firefox and GNOME need a real filesystem:

| Need | Roadmap Item |
|------|-------------|
| Root filesystem with standard FHS layout | ext2/ext4 or btrfs read-write support |
| Shared library loading | `/lib`, `/usr/lib` — dynamic linker (`ld-linux.so`) support via personality server |
| Font loading | `/usr/share/fonts/`, fontconfig cache files |
| Config/data files | `/etc/`, `~/.config/`, XDG directories |
| Temporary storage | `/tmp`, `/run`, `tmpfs` emulation |
| Device nodes | `/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/shm` (POSIX shared memory), DRM devices |

The existing ext2_srv provides a starting point but needs significant extension for write support, permissions, timestamps, and symlinks.

### 3. Networking (Roadmap Section 3)

Firefox needs a TCP/IP stack:

| Component | Notes |
|-----------|-------|
| TCP/IP socket API | `socket`, `connect`, `bind`, `listen`, `accept`, `send`/`recv`, `sendmsg`/`recvmsg` |
| DNS resolution | `getaddrinfo` via nsswitch or direct DNS client |
| TLS | Usually handled by NSS (Firefox) or OpenSSL — these are userspace, but need socket API |
| Unix domain sockets | Wayland compositor ↔ client communication, D-Bus |
| Abstract sockets | D-Bus uses `\0`-prefixed abstract namespace sockets |
| `epoll`/`poll`/`select` | Firefox's event loop is epoll-based |
| `SO_PEERCRED` | D-Bus authentication |

Homa (Priority 1 in roadmap) is interesting for Telix-native networking but Firefox needs BSD sockets over TCP/IP. The existing net_srv provides UDP/TCP basics but likely needs significant extension.

### 4. Graphics / DRM / GPU (Not in current roadmap)

**This is a major new area not covered by the existing roadmap.** The stack is:

```
Firefox WebRender → EGL/OpenGL ES → Mesa → DRM/KMS → GPU hardware (or virtio-gpu)
Wayland compositor → DRM/KMS (modesetting) + GBM (buffer allocation)
Xwayland → Wayland client protocol + X11 server
```

| Component | Effort |
|-----------|--------|
| DRM/KMS subsystem | Kernel-side: modesetting, framebuffer management, GEM/dumb buffer allocation. In Telix: a DRM server that presents `/dev/dri/card0` interface |
| virtio-gpu driver | QEMU's virtio-gpu provides 2D/3D acceleration; needs a Telix driver server |
| GBM (Generic Buffer Management) | Userspace library for buffer allocation; Mesa provides this |
| Mesa with virtio-gpu backend | Cross-compile Mesa with the `virgl` Gallium driver for software 3D via virtio-gpu |
| Wayland protocol | The compositor needs `libwayland-server`; clients need `libwayland-client`. These are pure userspace socket protocol libraries — they work if Unix domain sockets work |
| Shared memory (`mmap` + `memfd_create`) | Wayland SHM protocol for software rendering fallback |
| DMA-BUF / fencing | Zero-copy buffer sharing between compositor and clients; may need kernel support |

**Minimum viable path:** virtio-gpu with virgl (3D) or just dumb framebuffer (2D) + software rendering. Firefox can fall back to software rendering if no GPU acceleration.

### 5. Shared Memory & IPC Mechanisms

Beyond Telix's native IPC:

| Mechanism | Users |
|-----------|-------|
| POSIX shared memory (`shm_open`/`mmap`) | Wayland SHM, Firefox IPC |
| `memfd_create` | Firefox, Wayland |
| System V shared memory | Some X11 extensions (MIT-SHM) |
| `futex` | pthread synchronization (already in Telix) |
| `eventfd` | epoll integration, Firefox IPC |
| `signalfd` | Some daemons |
| Pipes / `pipe2` | Process spawning, shell |
| `socketpair` | Process communication |

### 6. Dynamic Linking

Firefox and GNOME are dynamically linked against dozens of shared libraries:

| Component | Notes |
|-----------|-------|
| ELF dynamic linker (`ld-linux-*.so`) | Must run in the Linux personality context |
| `dlopen`/`dlsym` | Firefox loads NSS, NSPR, Mesa, etc. at runtime |
| `LD_LIBRARY_PATH` / `RUNPATH` | Library search path resolution |
| Symbol versioning | glibc symbol versions (`GLIBC_2.17`, etc.) |

The existing `ld-telix` is a minimal static-binary linker. The Linux personality needs a full dynamic linker — likely `musl`'s `ld-musl-*.so` or glibc's `ld-linux-*.so` running natively.

---

## Dependency Order

```
Phase 0: Kernel infrastructure (current)
   ├── Personality routing (IN PROGRESS)
   ├── Shared page tables (planned)
   └── Boot-time PAGE_MMUSHIFT (roadmap Section 6)

Phase 1: Linux personality core
   ├── Syscall translation (top ~100 syscalls)
   ├── FD table, pipe, socket stubs
   ├── /proc/self/maps, /proc/self/exe
   ├── Signal fidelity (SA_SIGINFO, SA_RESTART)
   ├── clone/clone3 → Telix thread creation
   └── LTP smoke test (target: 50%+)

Phase 2: Filesystem + networking
   ├── ext2/ext4 read-write (or use rootfs_srv initially)
   ├── TCP/IP socket API (BSD sockets over net_srv)
   ├── Unix domain sockets
   ├── DNS resolution
   └── Dynamic linker support (musl ld.so or ld-linux.so)

Phase 3: Graphics
   ├── virtio-gpu driver server
   ├── DRM/KMS emulation (dumb framebuffer at minimum)
   ├── Cross-compile Mesa (virgl or softpipe)
   ├── Wayland compositor (wlroots-based, e.g. sway or cage)
   └── Xwayland

Phase 4: Desktop integration
   ├── D-Bus (session bus)
   ├── GNOME/GTK dependencies (glib, pango, harfbuzz, fontconfig)
   ├── Firefox build + runtime testing
   └── Polishing: seccomp stubs, /sys enumeration, extended /proc
```

---

## Effort Estimates by Area

| Area | Relative Effort | Notes |
|------|----------------|-------|
| Linux personality (syscall translation) | Very large | ~300 syscalls, iterative — LTP-driven |
| Filesystem (r/w ext2 + tmpfs + devfs) | Large | ext2_srv exists, needs hardening |
| Networking (TCP sockets + UDS) | Large | net_srv exists, needs BSD socket layer |
| Graphics (DRM + virtio-gpu + Mesa) | Large | Mostly new; Mesa cross-compile is complex |
| Dynamic linking | Medium | Leverage existing musl/glibc ld.so |
| Shared memory / IPC extensions | Medium | memfd, shm, eventfd, signalfd |
| /proc + /sys emulation | Medium | Incremental, driven by what apps need |
| D-Bus | Medium | Userspace daemon, needs UDS + credential passing |
| Personality kernel infrastructure | Small | IN PROGRESS — the foundation for everything else |

---

## What's NOT Needed (at least initially)

- **Audio** (PulseAudio/PipeWire) — Firefox works without audio
- **Printing** (CUPS) — not relevant
- **Bluetooth** — not relevant for QEMU
- **Hardware GPU drivers** — virtio-gpu is sufficient for QEMU
- **Full systemd** — minimal init is fine; just need D-Bus
- **SELinux/AppArmor** — security policies not needed for initial bring-up
- **cgroups v2** — stub out; Firefox sandbox can be disabled for testing
- **io_uring** — Firefox doesn't require it (epoll is sufficient)
- **eBPF** — not needed for desktop apps

---

## Key Insight

The personality server architecture (three-layer decomposition of ISA variant, syscall ABI, and personality semantics) is the keystone. Once the routing infrastructure is in place, every other component builds on it incrementally. The fast-path table optimization means that even a partial personality server can run real applications at reasonable speed — common syscalls are translated in-kernel.

The Wayland path (vs. X11 directly) is strongly preferred because:
1. Wayland's protocol is simpler and socket-based (works with Unix domain sockets)
2. No need for X11's complex server-side rendering model
3. Xwayland provides X11 compatibility for apps that need it
4. Modern Firefox and GNOME prefer Wayland natively
