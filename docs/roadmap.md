# Telix Roadmap: From Microkernel to Full Desktop OS

Telix is a microkernel operating system with multi-architecture support (x86_64, riscv64, aarch64). As of Phase 39, it has IPC ports, demand-paged virtual memory, COW fork, M:N green threads, async completion, virtio drivers (blk, net), FAT16 and ext2 filesystem servers, a capability-based security model, SMP scheduling with topology awareness and CPU hotplug, and a basic interactive shell.

This roadmap describes the path from the current state to running PostgreSQL, GHC Haskell, GNOME, and Firefox. It uses **Option B** (musl-libc with a Telix IPC backend) for the POSIX compatibility layer — the more microkernel-native approach where POSIX semantics live in userspace rather than the kernel.

---

## Stream A: Kernel Primitives for POSIX (Phases 40-50)

These are the minimal kernel-side additions needed. Most POSIX semantics live in musl-telix and userspace servers.

### Phase 40: `execve` syscall

Replace current process's address space with a new ELF. Tear down old VMAs, load new ELF segments, reset signal dispositions, close close-on-exec FDs (communicated via IPC to VFS server), set up new user stack with argv/envp/auxv. The existing `spawn` stays for fork-less process creation; `execve` enables the POSIX `fork()+exec()` pattern.

Depends on: nothing new.

### Phase 41: Signal delivery framework

`sigaction`, `sigprocmask`, `sigpending`, `sigsuspend`, `sigreturn`. Kernel stores per-thread signal mask + pending set + handler table. On return-to-user, if pending & ~mask != 0, divert to user handler trampoline (push signal frame, redirect to handler, `sigreturn` restores). Critical signals: SIGCHLD (auto on child exit), SIGPIPE (on write to broken pipe/socket), SIGTERM/SIGINT/SIGKILL, SIGALRM, SIGSEGV/SIGBUS (from page faults). Timer-based signals (SIGALRM, ITIMER_REAL) need per-process interval timer.

Depends on: nothing new.

### Phase 42: `mprotect` / `mremap` syscalls

`mprotect(addr, len, prot)`: walk VMA, split if needed, update PTE permissions, TLB flush. `mremap(old, old_size, new_size, flags)`: grow/shrink/move a mapping. Both are purely kernel MM operations on existing VMA infrastructure.

Depends on: nothing new.

### Phase 43: Process groups, sessions, controlling terminal

`setpgid`, `getpgid`, `setsid`, `getsid`, `tcsetpgrp`, `tcgetpgrp`. Add `pgid` and `sid` fields to task struct. Controlling terminal association (links a session to a console/PTY server port). `kill(-pgid, sig)` sends to process group. Needed for: job control in shell, `SIGHUP` on session leader exit.

Depends on: Phase 41 (signals).

### Phase 44: `clock_gettime` / `nanosleep` / interval timers

`clock_gettime(CLOCK_REALTIME | CLOCK_MONOTONIC)`: read hardware timer, convert to timespec. `nanosleep`: block thread with a timer wakeup (add `BlockReason::Sleep { deadline }`, wake in tick handler). `setitimer`/`timer_create`: per-process periodic timer that delivers SIGALRM.

Depends on: Phase 41 (for SIGALRM).

### Phase 45: File-backed `mmap` (kernel side)

`mmap(addr, len, prot, MAP_PRIVATE|MAP_SHARED, fd, offset)`: VMA records (fd, vfs_port, handle, offset). On page fault, kernel sends FS_READ IPC to the VFS server to populate the page. `MAP_SHARED` dirty pages get written back on `msync`/`munmap`. Requires the kernel to initiate IPC on behalf of a faulting thread (kernel-originated send to VFS port, block thread until reply). This is the hardest single kernel change — breaks the "kernel never does IPC" assumption. Alternative: have a pager thread per address space in userspace.

Depends on: Phase 51 (VFS server).

### Phase 46: POSIX shared memory (kernel side)

Named memory objects: `shm_open` creates a memory object in a shm server, returns an FD. `mmap` on that FD maps the shared pages. Implementation: a `shm_srv` userspace server that allocates physical pages and grants them to callers. The kernel needs no special support beyond existing grants.

Depends on: Phase 51 (VFS, for `/dev/shm` path routing).

### Phase 47: `dup` / `dup2` / `fcntl` / `ioctl` support

These operate on the FD table. In Option B, the FD table is in musl-telix (per-process userspace). `dup`/`dup2` are purely library-side. `fcntl(F_SETFL, O_NONBLOCK)` sets a flag in the FD entry that musl checks before IPC. `ioctl` is routed to the appropriate server via IPC (e.g., terminal ioctls go to PTY server). No kernel changes needed.

Depends on: Phase 52 (musl-telix).

### Phase 48: Credential syscalls

`getuid`, `geteuid`, `getgid`, `getegid`, `setuid`, `setgid`, `setgroups`. Add uid/gid/euid/egid fields to task struct (initialized from parent or from exec of setuid binary). Kernel enforces: only uid 0 can `setuid`. FS servers receive caller credentials via IPC and check file permissions.

Depends on: nothing new.

### Phase 49: `wait4` / `waitpid` improvements

Current `waitpid` is polling. Need: `WNOHANG`, `WUNTRACED`, `WCONTINUED`, wait-for-any-child (`pid == -1`), wait-for-process-group (`pid < -1`). Integrate with SIGCHLD delivery. The thread blocks in `BlockReason::WaitChild` and gets woken when any child in scope exits.

Depends on: Phase 41 (SIGCHLD), Phase 43 (process groups).

### Phase 50: Resource limits

`getrlimit`/`setrlimit`/`prlimit`: RLIMIT_NOFILE, RLIMIT_AS, RLIMIT_STACK, RLIMIT_NPROC. Store per-task, enforce in relevant syscalls and mmap. Low priority but PostgreSQL's `postmaster` checks these at startup.

Depends on: nothing new.

---

## Stream B: Userspace POSIX Infrastructure (Phases 51-62)

This is the bulk of the work. Each phase is a userspace server or library component.

### Phase 51: VFS server

Central path-resolution and mount-table server. Maintains:
- Mount table: `[("/", ext2_port), ("/tmp", tmpfs_port), ("/dev", devfs_port), ("/proc", procfs_port)]`
- Per-process FD table proxy (or delegates to musl-telix)
- Path resolution: splits path, walks mount points, sends FS_OPEN to correct server
- Symlink following (read target, restart resolution)
- `..` handling, relative paths via per-process CWD

Protocol: `VFS_OPEN(path, flags, mode, reply_port)` looks up mount, forwards to FS server, returns (fd, fs_port, handle). Subsequent read/write goes directly to FS server (bypassing VFS). `VFS_MOUNT`, `VFS_UNMOUNT`, `VFS_STAT`, `VFS_CHDIR`.

This is the single most important userspace component.

Depends on: nothing new (can start immediately).

### Phase 52: musl-libc Telix backend

Fork musl. Replace `src/internal/syscall.h` and arch-specific `__syscall` with Telix IPC stubs. Major subsystems:

- **File I/O** (`open` -> VFS_OPEN IPC, `read` -> FS_READ IPC, etc.): ~30 functions
- **Memory** (`mmap` -> SYS_MMAP_ANON or file-backed, `munmap`, `mprotect`, `mremap`): ~8 functions
- **Process** (`fork` -> SYS_FORK, `execve` -> SYS_EXEC, `waitpid`, `getpid`, `kill`): ~15 functions
- **Signals** (`sigaction` -> SYS_SIGACTION, etc.): ~10 functions
- **Threads** (pthreads -> `SYS_THREAD_CREATE` + futex): ~25 functions
- **Sockets** (`socket` -> connect to net_srv/uds_srv, `bind/listen/accept/connect/send/recv`): ~20 functions
- **Time** (`clock_gettime`, `nanosleep`, `gettimeofday`): ~5 functions
- **Misc** (`getcwd`, `chdir`, `getenv`, `uname`, `sysconf`): ~15 functions

Per-process state stored in TLS/globals: FD table (array of `{server_port, handle, flags}`), CWD, umask, signal handlers (mirrors kernel). The FD table maps Linux-style small integers to (server_port, server_handle) pairs.

This can start in parallel with Phase 51; initially stub out unimplemented calls with ENOSYS.

Depends on: Phase 40 (exec), Phase 41 (signals) for full functionality. Can bootstrap incrementally.

### Phase 53: ext2 write support

Extend ext2_srv with: `FS_CREATE` (allocate inode, add directory entry, allocate data blocks), `FS_WRITE` (write data blocks, extend file, update size), `FS_TRUNCATE`, `FS_RENAME`, `FS_UNLINK` (free blocks + inode, remove dir entry), `FS_MKDIR`/`FS_RMDIR`, `FS_SYMLINK`/`FS_READLINK`, `FS_CHMOD`/`FS_CHOWN`. Block allocation: read block bitmap, find free, mark used. Inode allocation: similarly. `FS_FSYNC`: flush dirty blocks to disk (write-back via blk_srv).

Depends on: nothing new (builds on existing ext2_srv).

### Phase 54: tmpfs server

In-memory filesystem for `/tmp`, `/run`, `/var`. Stores file data in allocated pages, directory tree in a simple hash/tree structure. Supports all FS protocol operations. Fast (no disk I/O). Important for: build systems, PostgreSQL temp files, X11/Wayland sockets in `/run`.

Depends on: nothing new.

### Phase 55: devfs server

Serves `/dev/*`. Static entries: `/dev/null` (read->EOF, write->discard), `/dev/zero` (read->zeros), `/dev/full` (write->ENOSPC), `/dev/random`/`/dev/urandom` (read from RDRAND or timer-based entropy), `/dev/tty`/`/dev/console` (proxy to console_srv), `/dev/ptmx` + `/dev/pts/*` (Phase 62).

Depends on: nothing new.

### Phase 56: procfs server

Serves `/proc/*`. Critical files: `/proc/self/maps` (PostgreSQL, Firefox check this), `/proc/self/exe` (symlink to own binary), `/proc/meminfo`, `/proc/cpuinfo`, `/proc/self/fd/*`, `/proc/self/status`, `/proc/self/cmdline`. Queries kernel via syscalls for process/memory info.

Depends on: Phase 48 (credentials for /proc/self/status).

### Phase 57: Unix domain socket server

`AF_UNIX` / `AF_LOCAL` socket support. A userspace `uds_srv` that:
- Manages named sockets (bound to filesystem paths via VFS)
- Handles `SOCK_STREAM` (connection-oriented) and `SOCK_DGRAM` (datagram)
- `accept` creates new connected pair
- Data transfer via grant-based zero-copy or inline IPC
- `SCM_RIGHTS` (FD passing): the VFS server mediates transferring FD table entries between processes
- `SCM_CREDENTIALS`: passes pid/uid/gid

Used by: PostgreSQL (client connections), D-Bus, Wayland, X11, GHC I/O manager.

Depends on: Phase 51 (VFS, for path-based socket binding).

### Phase 58: BSD socket API completion

In musl-telix, implement the full socket API routing to net_srv (TCP/UDP/ICMP) and uds_srv (Unix). `socket()` creates a port, connects to the appropriate server. `setsockopt` -> IPC to server. `getaddrinfo` -> DNS query (musl has a built-in resolver that needs UDP sockets). `sendmsg`/`recvmsg` with ancillary data (cmsg).

Depends on: Phase 57 (UDS), net_srv improvements.

### Phase 59: Pipe improvements

Full POSIX pipe semantics: `pipe()` creates an FD pair (reader + writer). EOF when all write FDs closed. `SIGPIPE` on write to pipe with no readers. `O_NONBLOCK` support. `pipe2(O_CLOEXEC)`. Can be implemented as a `pipe_srv` or inline in musl-telix.

Depends on: Phase 41 (SIGPIPE).

### Phase 60: `poll` / `select` / `epoll`

The I/O multiplexing layer. Implementation strategy:

- Each FD's server supports a `POLL_REGISTER(handle, events, notify_port)` IPC that sends a notification when the handle becomes ready
- `poll()` in musl: create a temporary port set, register interest with each FD's server, `port_set_recv` with timeout, translate results
- `epoll` is similar but persistent (the epoll FD holds persistent registrations)

Alternatively: kernel-side `poll` syscall that takes an array of (port, events) and does multiplexed blocking. This is more efficient but requires kernel changes.

Critical for: every server, PostgreSQL, Firefox, GHC I/O manager.

Depends on: Phase 51 (VFS FD routing).

### Phase 61: File locking

`flock()` and `fcntl(F_SETLK/F_SETLKW)`. FS servers maintain per-file lock tables. `F_SETLKW` blocks until lock is available. Mandatory vs advisory (Linux is advisory-only). PostgreSQL uses advisory locks extensively.

Depends on: nothing new (FS server extension).

### Phase 62: PTY subsystem

Pseudo-terminals for terminal emulators, SSH, and proper job control. A `pty_srv` that:
- `openpty()` / `posix_openpt()` + `grantpt()` + `unlockpt()`: creates master/slave pair
- Master side: terminal emulator writes/reads here
- Slave side: shell's stdin/stdout/stderr
- Line discipline: canonical mode (line editing, ^C -> SIGINT, ^Z -> SIGTSTP), raw mode
- `TIOCGWINSZ`/`TIOCSWINSZ`: window size ioctls
- Registered as `/dev/ptmx` + `/dev/pts/N` via devfs

Needed for: any real terminal interaction, SSH, screen/tmux, `script`.

Depends on: Phase 55 (devfs), Phase 43 (process groups for ^C/^Z).

---

## Milestone 1: LOGIN

**Requires: Phases 40-44, 48-49, 51-55, 59, 62**

### Phase 63: Port a POSIX shell (dash)

Statically link dash against musl-telix. dash needs: fork, exec, waitpid, pipe, dup2, open/read/write/close, signal handling, process groups (job control). This replaces the current toy shell. Test: launch dash, run basic commands.

Depends on: Phase 52 (musl-telix with basic syscalls working).

### Phase 64: Coreutils

Either port busybox (static, against musl-telix) or write minimal versions: `ls`, `cat`, `cp`, `mv`, `rm`, `mkdir`, `rmdir`, `pwd`, `echo`, `env`, `chmod`, `chown`, `wc`, `head`, `tail`, `grep`, `mount`, `umount`, `ps`, `kill`, `id`, `whoami`, `date`, `uname`, `true`, `false`, `test`, `sleep`. Busybox is the fast path — one binary, ~200 applets.

Depends on: Phase 52, Phase 53 (ext2 write).

### Phase 65: `getty` / `login` / user accounts

- `getty`: listens on `/dev/console` (or PTY), prints login prompt, reads username, execs `login`
- `login`: reads `/etc/passwd` (and optionally `/etc/shadow`), verifies password (crypt), sets uid/gid (Phase 48), execs user's shell
- `/etc/passwd` format: `root:x:0:0:root:/root:/bin/dash`
- `/etc/group` format: `root:x:0:`
- Initial setup: ext2 image includes `/etc/passwd`, `/etc/group`, `/bin/dash`, coreutils in `/bin`

After this phase: boot Telix -> kernel starts init -> init spawns getty on console -> user types username/password -> login sets uid/gid -> dash shell -> user runs commands.

**LOGIN MILESTONE: Interactive multi-user system with filesystem, shell, and basic utilities.**

---

## Stream C: Application Infrastructure (Phases 66-73)

### Phase 66: Dynamic linker (`ld-telix.so`)

ELF interpreter: kernel loads it from ELF's `PT_INTERP`, it loads shared libraries, resolves relocations (GOT/PLT), calls constructors, jumps to `_start`. musl includes a dynamic linker (`ldso/`); the Telix port needs:
- `mmap` file-backed (Phase 45) or manual ELF loading via read+mmap_anon+copy
- `mprotect` for W^X (Phase 42)
- `dl_iterate_phdr` for stack unwinding
- `dlopen`/`dlsym`/`dlclose` for runtime loading

Needed for: everything dynamically linked (most of the GNU/Linux ecosystem).

Depends on: Phase 45 (file-backed mmap) or workaround with read+anon mmap.

### Phase 67: Auxiliary vector and ELF improvements

Pass auxv on the stack at exec: `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_ENTRY`, `AT_BASE` (dynamic linker base), `AT_RANDOM` (16 random bytes for stack canary), `AT_PAGESZ`, `AT_CLKTCK`, `AT_HWCAP`, `AT_EXECFN`, `AT_SECURE`, `AT_UID`/`AT_GID`/`AT_EUID`/`AT_EGID`. musl's `__init_libc` reads these.

Depends on: Phase 40 (exec), Phase 48 (credentials).

### Phase 68: `eventfd` / `signalfd` / `timerfd`

Linux-specific but widely used FD types:
- `eventfd`: semaphore-like FD, used for thread/process wakeup (GHC, systemd, Firefox)
- `signalfd`: receive signals as FD reads (alternative to signal handlers)
- `timerfd_create`/`timerfd_settime`: timer as an FD (epollable)

Implement as small userspace servers or special FD types in musl-telix.

Depends on: Phase 60 (poll/epoll, so they're epollable).

### Phase 69: `inotify` (or equivalent)

Filesystem change notification. FS servers send notifications when files change. Used by: GLib's file monitoring, build systems, editors. Can be simplified initially (just support `IN_MODIFY`, `IN_CREATE`, `IN_DELETE` on watched directories).

Depends on: Phase 51 (VFS).

### Phase 70: ASLR and `mmap` improvements

Randomize stack, heap, mmap base, dynamic linker base. `mmap` with `MAP_FIXED` must handle overlaps (unmap existing). `MAP_FIXED_NOREPLACE` (fail instead of clobber). Needed for: security, Firefox sandbox, GHC RTS memory layout.

Depends on: nothing new (MM improvements).

### Phase 71: `syslog` / `openlog`

Logging infrastructure. A `syslog_srv` that collects log messages via Unix domain socket at `/dev/log`. Low priority but PostgreSQL logs via syslog by default.

Depends on: Phase 57 (UDS).

### Phase 72: Locale and timezone support

`/usr/share/zoneinfo`, `/etc/localtime`, locale data files. musl has minimal locale support. Enough for PostgreSQL timestamps and GLib.

Depends on: Phase 53 (ext2 write, for installing data files).

### Phase 73: `/etc/resolv.conf` and DNS

musl's DNS resolver reads `/etc/resolv.conf` for nameserver IPs. Need the file in ext2, and working UDP sockets to the nameserver.

Depends on: Phase 58 (socket API).

---

## Stream D: GHC Runtime Integration (Phases 74-78)

GHC's runtime (RTS) is the interface between compiled Haskell and the OS. Telix's M:N threading and async I/O map naturally to GHC's model.

### Phase 74: GHC RTS Telix backend — threading

GHC's RTS has "capabilities" (OS threads) and "Haskell threads" (green threads scheduled by the RTS onto capabilities). The Telix mapping:
- **Capability** = Telix kernel thread (one per CPU, pinned via affinity)
- **Haskell thread** = Telix green fiber (Phase 30's M:N infrastructure)
- Replace GHC's `pthread_create` for capability threads with `SYS_THREAD_CREATE`
- Replace `pthread_mutex`/`pthread_cond` with Telix futex
- `yieldCapability()` -> Telix `yield_now()` or green fiber yield
- Work-stealing scheduler: GHC already has one; wire it to Telix's per-CPU topology

Key design choice: GHC normally manages its own green thread stacks (heap-allocated, segmented, growable). Recommended approach: let GHC manage its own stacks and just use Telix kernel threads as capabilities. This minimizes RTS changes.

Depends on: Phase 52 (musl-telix, for basic libc functions the RTS needs).

### Phase 75: GHC I/O manager — async completion integration

This is the high-value integration. GHC's I/O manager currently uses `epoll` (Linux) or `kqueue` (macOS) to multiplex I/O. Telix's async completion model (Phase 34) provides a natural fit:

- **Option 1 (conservative)**: Implement epoll (Phase 60) and let GHC use it unchanged. Works but doesn't exploit Telix's IPC-based async model.
- **Option 2 (native)**: Write a new GHC I/O manager backend (`GHC.Event.Telix`) that:
  - Submits I/O requests as non-blocking IPC sends to FS/net/blk servers
  - Registers completion notifications on a port set
  - `poll` = `port_set_recv` with timeout
  - Each pending Haskell thread has an associated completion port
  - When completion arrives, wake the Haskell thread

Option 2 means Haskell `readFile` -> GHC I/O manager -> non-blocking `FS_READ` IPC -> Haskell thread parks -> completion arrives -> Haskell thread wakes. No epoll, no kernel involvement beyond IPC delivery. File and network I/O use the same unified path.

This gives GHC **unified async file + network I/O** that most operating systems can't provide (Linux's io_uring is the closest analog, and GHC only recently got an io_uring backend).

Depends on: Phase 60 (for Option 1) or Telix async completion infrastructure (already exists, Phase 34) for Option 2.

### Phase 76: GHC RTS — signal handling and GC

GHC uses signals for:
- **GC safe points**: timer signal (SIGVTALRM/SIGALRM) interrupts mutator threads to enter GC
- **User interrupts**: SIGINT -> `UserInterrupt` exception to main thread
- **Stack overflow**: SIGSEGV on guard page -> grow Haskell stack

Wire these to Telix's signal delivery (Phase 41). For GC, Telix's timer tick can directly set a flag (cheaper than signal delivery) — the RTS checks this flag in the "scheduler loop."

Depends on: Phase 41 (signals), Phase 42 (mprotect for guard pages).

### Phase 77: GHC RTS — memory management

GHC's RTS uses `mmap` for its block allocator (MBlocks, typically 1 MiB aligned). Needs:
- `mmap(MAP_ANON)` with alignment (already have)
- `madvise(MADV_DONTNEED)` for returning unused blocks to OS (implement as VMA hint or new syscall)
- Compact regions: `mmap` + `mremap` for moving GC

Depends on: Phase 42 (mremap).

### Phase 78: GHC cross-compiler and bootstrap

Build a GHC cross-compiler targeting Telix (x86_64-unknown-telix or similar). Requires:
- Telix target in GHC's build system (configure, Hadrian)
- musl-telix as the C library for the target
- LLVM backend (GHC's native codegen only targets a few platforms; LLVM backend is more portable)
- Bootstrap: initially cross-compile from Linux; eventually self-host

Depends on: Phases 74-77 (RTS integration complete).

---

## Stream E: PostgreSQL (Phases 79-82)

### Phase 79: Static PostgreSQL build against musl-telix

Cross-compile PostgreSQL with `./configure --host=x86_64-telix --with-system-tzdata=/usr/share/zoneinfo`. Disable optional features initially: no SSL, no PAM, no systemd, no readline (use libedit or none). Static link. Fix compilation issues (missing headers, syscall stubs).

Depends on: Phase 52 (musl-telix complete enough), Phase 53 (ext2 write), Phase 57 (UDS), Phase 60 (poll).

### Phase 80: `initdb` and catalog bootstrap

Run `initdb` to create the PostgreSQL data directory (`/var/lib/postgresql/data`). This exercises: filesystem (create ~1000 files), fork+exec, shared memory, semaphores, file locking. Debug failures one by one.

Depends on: Phase 79, Phase 46 (shm), Phase 61 (file locking).

### Phase 81: `postmaster` startup and single-user mode

Start PostgreSQL in single-user mode (`postgres --single -D /data mydb`). This avoids networking initially. Exercises: shared memory setup, buffer pool (mmap), WAL (fsync), the SQL engine. Run basic queries: `CREATE TABLE`, `INSERT`, `SELECT`.

Depends on: Phase 80.

### Phase 82: Full PostgreSQL with network clients

Start postmaster in normal mode. Accept connections via Unix domain socket and/or TCP. Run `psql` as a client. Test: concurrent connections, transactions, `COPY`, joins.

Depends on: Phase 81, Phase 57 (UDS), Phase 58 (TCP sockets).

**POSTGRESQL MILESTONE: Running database with SQL queries over network connections.**

---

## Stream F: Graphics Stack (Phases 83-90)

### Phase 83: Framebuffer driver

For QEMU: virtio-gpu (paravirtualized) or simple VBE/GOP linear framebuffer. Virtio-gpu: MMIO transport (already have pattern from virtio-blk/net), 2D operations (resource create, transfer, set scanout). Simpler option: QEMU's `-device VGA` with VESA BIOS Extensions (multiboot provides framebuffer info). A `fb_srv` userspace server that maps the framebuffer and exposes `FB_SETMODE`, `FB_MAP_BUFFER`, `FB_FLIP`.

Depends on: nothing new.

### Phase 84: Input device drivers

- **Keyboard**: PS/2 i8042 (x86, already have serial-based getchar) or virtio-input. Produce keycodes -> keysyms (using a keymap table). Deliver as input events to an `input_srv`.
- **Mouse**: PS/2 mouse or virtio-input. Relative motion + buttons.
- `input_srv` collects events from all input devices, broadcasts to interested clients (compositor).

Depends on: nothing new.

### Phase 85: DRM/KMS equivalent (display server protocol)

A display management protocol: mode setting (resolution, refresh), plane management, buffer allocation, page flip. Simpler than Linux DRM — Telix only needs single-display, single-plane initially. The framebuffer server (Phase 83) handles this.

Depends on: Phase 83.

### Phase 86: Wayland compositor (minimal)

A small compositor (`wl_srv`) that:
- Accepts client connections via Unix domain socket (`/run/wayland-0`)
- Clients create shared-memory buffer pools (`wl_shm`), allocate buffers, render into them, commit
- Compositor reads committed buffers, composites (initially just blit, no transparency), writes to framebuffer
- Delivers input events to focused client
- Pointer cursor rendering, window focus, basic window management

Can start with a subset of the Wayland protocol. A from-scratch minimal compositor may be simpler for Telix than porting wlroots.

Depends on: Phase 57 (UDS), Phase 46 (shm), Phase 83, Phase 84.

### Phase 87: `libwayland` port

Port libwayland-client and libwayland-server. These are the protocol marshalling libraries that GTK/Firefox use. Relatively small C libraries, need: Unix domain sockets, poll, mmap (shm), cmsg (SCM_RIGHTS for FD passing).

Depends on: Phase 57, Phase 60.

### Phase 88: Mesa software rendering (llvmpipe)

Port Mesa3D with the llvmpipe (CPU-based) Gallium driver. This provides OpenGL (and potentially Vulkan via lavapipe) without hardware GPU acceleration. Needs: pthreads, mmap, large memory allocation, LLVM JIT (or pre-compiled shaders). This is a large build but the code is portable.

Depends on: Phase 52 (musl-telix), Phase 66 (dynamic linker — Mesa is typically a shared library).

### Phase 89: Font rendering stack

Port: FreeType (font rasterizer), HarfBuzz (text shaping), Fontconfig (font discovery/matching). All are C libraries needing basic libc + filesystem access. Install fonts in `/usr/share/fonts/`.

Depends on: Phase 52, Phase 66.

### Phase 90: Cairo / Pixman

2D graphics libraries used by GTK and Firefox. Cairo provides vector graphics (paths, gradients, text). Pixman provides fast pixel manipulation. Both are C, need libc + optionally SIMD (SSE/NEON).

Depends on: Phase 52.

---

## Stream G: Desktop Infrastructure (Phases 91-97)

### Phase 91: D-Bus daemon

Port dbus-daemon (or rewrite a minimal one). D-Bus is GNOME's IPC backbone — every GNOME component communicates over it. Needs: Unix domain sockets, poll/epoll, fork/exec, user authentication (`/etc/passwd`). System bus (`/run/dbus/system_bus_socket`) and session bus (`/run/user/1000/bus`).

Depends on: Phase 57, Phase 60, Phase 65 (user accounts).

### Phase 92: GLib / GObject / GIO port

GNOME's core libraries:
- **GLib**: event loop (needs poll/epoll + timerfd + signalfd), mainloop, hash tables, strings, unicode, file utilities, spawn (fork+exec), thread pool (pthreads)
- **GObject**: OOP type system (pure C, no special OS needs)
- **GIO**: async I/O, file operations, D-Bus client, network sockets, settings, application framework

GLib's event loop is the heart — it needs solid poll/epoll. File monitoring needs inotify (Phase 69).

Depends on: Phase 52, Phase 60, Phase 68, Phase 69, Phase 91.

### Phase 93: GTK 4 port

Port GTK 4 with Wayland backend. GTK needs: GLib, Cairo, Pango (text layout, uses HarfBuzz), GDK (backend layer -> Wayland), GSK (rendering -> Cairo or OpenGL via Mesa). Large build but primarily a matter of getting dependencies right.

Depends on: Phase 87, Phase 88, Phase 89, Phase 90, Phase 92.

### Phase 94: Terminal emulator

Port or write a terminal emulator (VTE-based like gnome-terminal, or simpler like st/foot). Needs: PTY (Phase 62), Wayland client, font rendering, escape sequence parser. This is essential — it's how users interact with the system in a graphical environment.

Depends on: Phase 62, Phase 86, Phase 89.

### Phase 95: PipeWire / audio (optional initially)

Audio subsystem. PipeWire replaces PulseAudio, handles audio routing. Needs a sound device driver (virtio-snd or Intel HDA). Lower priority — Firefox and GNOME work without audio (with warnings).

Depends on: Phase 57, Phase 68, Phase 91.

### Phase 96: Accessibility (AT-SPI)

GNOME's accessibility framework. Uses D-Bus. Lower priority but GNOME components log warnings without it.

Depends on: Phase 91.

### Phase 97: System services

- `init` improvements: service supervision, dependency ordering (like s6, runit, or minimal systemd)
- `udevd` equivalent: device event handling, `/dev` population
- `logind` or equivalent: session management, seat management, PAM integration
- `NetworkManager` or simpler (`dhcpcd` for DHCP, `wpa_supplicant` for WiFi — not needed in QEMU)

Depends on: Phase 91 (D-Bus), various.

---

## Stream H: Firefox (Phases 98-101)

### Phase 98: NSS / NSPR port

Firefox's crypto and platform abstraction libraries. NSS (Network Security Services) needs: pthreads, mmap, /dev/urandom. NSPR (Netscape Portable Runtime) is the OS abstraction layer — needs a Telix backend (threads, locks, I/O, sockets, time). Alternatively, build with system OpenSSL if easier.

Depends on: Phase 52.

### Phase 99: Rust toolchain targeting Telix

Firefox is partially written in Rust. Need a `x86_64-unknown-telix` Rust target that links against musl-telix. Provide target JSON spec, build std with Telix backend.

Depends on: Phase 52.

### Phase 100: Firefox build

Cross-compile Firefox (ESR branch, most stable) with `--disable-jemalloc --disable-sandbox --enable-application=browser`. Disable optional features initially: no WebRTC, no Crash Reporter, no Telemetry. Use system libs where possible (system NSS, system ICU). This is a huge build — Firefox has ~20M lines of code.

Depends on: Phase 66, Phase 87, Phase 88, Phase 89, Phase 90, Phase 92, Phase 93, Phase 98, Phase 99.

### Phase 101: Multi-process Firefox debugging

Firefox runs multiple processes (parent, GPU, content renderer, networking). Each needs fork+exec, Unix domain sockets for IPC, shared memory for compositing. Debug: process launch, IPC channel setup, compositor, content rendering.

Depends on: Phase 100.

**FIREFOX MILESTONE: Web browser rendering pages.**

---

## Stream I: GNOME (Phases 102-104)

### Phase 102: GNOME Shell / Mutter

GNOME's compositor and shell. Mutter is a Wayland compositor + window manager. GNOME Shell runs as a Mutter plugin with a JavaScript UI (SpiderMonkey/GJS). Needs: everything in Streams F and G, plus Clutter (scene graph), Cogl (GL abstraction), GJS (JavaScript engine). Very large.

Depends on: Phase 86, Phase 88, Phase 92, Phase 93, Phase 91.

### Phase 103: Core GNOME apps

Files (Nautilus), Settings, Text Editor, Terminal (gnome-terminal). Each is a GTK app. Mostly a matter of getting GTK working properly.

Depends on: Phase 93, Phase 94.

### Phase 104: GNOME session

`gnome-session` starts the shell, settings daemon, and core services. Needs: D-Bus, logind/elogind, XDG runtime directory.

Depends on: Phase 91, Phase 97, Phase 102, Phase 103.

**GNOME MILESTONE: Full desktop environment.**

---

## Dependency Graph — Critical Path

```
Kernel:    40 ----> 41 ----> 43 ----> 49
            |        |               |
            42       44              |
            |                        |
            45 (needs 51) -----------+
            48                       |
                                     |
Userspace: 51 ----> 52 ----> 53 ----> 63 ----> 64 ----> 65  LOGIN
            |        |        |
            54       57 ----> 60
            55       58
            56       59
                     62
                      |
GHC:       74 ----> 75 ----> 76 ----> 77 ----> 78
                      |
PgSQL:     79 ----> 80 ----> 81 ----> 82  POSTGRESQL
                      |
Graphics:  83 ----> 86 ----> 87
           84        |
                     88 ----> 93 ----> 100 ----> 101  FIREFOX
           89        |
           90        91 ----> 92 ----> 102 ----> 104  GNOME
                     |
                     66 ----> 67 ----> 68
```

## Summary

| Milestone   | Phase | Phases from now | Key dependencies |
|-------------|-------|-----------------|------------------|
| Login       | 65    | ~25             | exec, signals, VFS, musl-telix, ext2 write, dash, coreutils |
| PostgreSQL  | 82    | ~42             | Login + UDS, poll, shm, file locking, fsync |
| GHC native  | 78    | ~38             | Login + RTS port, async I/O manager, signal/GC integration |
| Firefox     | 101   | ~61             | PostgreSQL deps + dynamic linker, Wayland, Mesa, GTK, Rust target |
| GNOME       | 104   | ~64             | Firefox deps + D-Bus, GLib, Mutter, GNOME Shell |

Total phases: 65 (Phase 40 through Phase 104).
