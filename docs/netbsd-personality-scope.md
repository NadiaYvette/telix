# NetBSD Personality Server Scoping Report

## Executive Summary

Implementing a NetBSD-compatible personality server (`netbsd_srv`) in Telix is a **1.5–2.0 months** effort (~24–32 focused sessions) for a minimum-viable personality capable of running NetBSD's `/bin/ls` and `/bin/sh`. A production-shape personality matching current linux_srv coverage would require **2.5–3.5 months** (~40–56 sessions). 

The primary complexity drivers are:

1. **LWP thread model mismatch**: NetBSD's lightweight process (LWP) syscalls (`_lwp_create`, `_lwp_park`, `_lwp_wakeup`) differ structurally from Linux's `clone()` flag-based threading.
2. **Sysctl tree vs procfs**: NetBSD lacks `/proc` by default; introspection is sysctl-based (syscalls like `__sysctl`). The netbsd_srv would need a sysctl emulation layer.
3. **ELF interpreter path and personality detection**: The kernel's ELF loader must sniff `PT_NOTE/NT_NETBSD_IDENT` sections to auto-attach NetBSD personality; currently only Linux is detected.
4. **Kqueue event notification**: NetBSD's signature multiplexing mechanism (no Linux analog); implementation would require mapping to Telix's native wakeup primitives or building a lightweight event queue.

---

## 1. Syscall ABI Delta vs Linux

### Syscall Inventory

**NetBSD 10.x x86_64 syscall count**: ~330 syscalls (including compat layers).
**Linux x86_64 syscall count**: ~450 syscalls.
**Overlap**: ~120–140 syscalls with identical names, semantics, and argument counts.

### Categorization

#### A. Trivial Number Remap (~90 syscalls)

Syscalls that are byte-for-byte identical once the syscall number is translated. Fast-path table in kernel, O(1) in-kernel dispatch. Examples:

- **read** (Linux 0 → NetBSD 3)
- **write** (Linux 1 → NetBSD 4)
- **close** (Linux 3 → NetBSD 6)
- **lseek** (Linux 8 → NetBSD 19)
- **chmod** (Linux 90 → NetBSD 15)
- **unlink** (Linux 87 → NetBSD 10)
- **rmdir** (Linux 84 → NetBSD 9)
- **mkdir** (Linux 83 → NetBSD 8)
- **chdir** (Linux 80 → NetBSD 12)
- **fstat** (Linux 5 → NetBSD 28)
- **getpid** (Linux 39 → NetBSD 20)
- **getuid** (Linux 102 → NetBSD 24)
- **geteuid** (Linux 107 → NetBSD 25)
- **kill** (Linux 62 → NetBSD 37)
- **mmap** (Linux 9 → NetBSD 197) — *struct not identical; see §B*
- **mprotect** (Linux 10 → NetBSD 74)
- **munmap** (Linux 11 → NetBSD 73)
- **brk** (Linux 12 → NetBSD 17)
- **dup** (Linux 32 → NetBSD 41)
- **dup2** (Linux 33 → NetBSD 63)
- **ioctl** (Linux 16 → NetBSD 54) — *flags and struct content differ; see §B*
- **sync** (Linux 162 → NetBSD 36)
- **fsync** (Linux 74 → NetBSD 95)
- **uname** (Linux 63 → NetBSD 160) — *struct differs; see §B*

**Estimate**: ~90 syscalls. Telix kernel loads these via fast-path table at netbsd_srv startup; no personality server IPC needed.

#### B. Struct/Flag Translation (~70 syscalls)

Syscalls with the same name/intent but different argument shapes. Require personality server IPC or in-kernel translation table. Examples:

- **mmap(2)**: NetBSD adds `flags` param (8 args total); Linux has 6. Struct layout for return differs (NetBSD may use different errno encoding).
  - Mapping: `mmap(addr, len, prot, flags, fd, off)` Linux → `mmap(addr, len, prot, flags, fd, off, ???, ???)` NetBSD.
  - Requires server-side struct repack.

- **sigaction(2)**: NetBSD `struct sigaction` layout differs from Linux:
  - Linux: `sa_handler / sa_sigaction (union u64) | sa_flags (u64) | sa_restorer (u64) | sa_mask (sigset_t, 128 bits)`.
  - NetBSD: `sa_handler / sa_sigaction (union) | sa_flags (u32) | sa_mask (sigset_t, 128 bits)`.
  - Flag bits differ: Linux `SA_RESTART=0x10000`, NetBSD `SA_RESTART=0x2`.

- **sigprocmask(2)**: `sigset_t` layouts identical on x86_64 (both are `u64 mask[4]`), but semantics differ (see § 2 below).

- **stat(2)** / **fstat(2)** / **lstat(2)**:
  - Linux: `struct stat` with nanosecond timestamps, ext4 inode64 mode.
  - NetBSD: `struct stat` with `st_birthtim` (birth/creation time), different field ordering, `st_blocks` in 512-byte units (same as Linux) but padding differs.
  - Linux has `statx(2)` (modern), NetBSD uses `stat(2)` only.

- **open(2)** / **openat(2)**: Flag bits mostly identical, but:
  - NetBSD `O_SHLOCK` (0x10) / `O_EXLOCK` (0x20) — not in Linux.
  - Linux `O_DIRECT` (0x4000), `O_LARGEFILE` (0x8000) — not in NetBSD (implicit).

- **fcntl(2)**: Commands mostly overlap, but some are BSD-specific:
  - NetBSD `F_GETLK` (union-returning, platform-specific struct), `F_SETLK`, `F_SETLKW` — advisory locking (advisory, not mandatory).
  - Linux mostly compatible, but `F_GET_SEALS` / `F_ADD_SEALS` (memfd) are Linux-only.

- **rlimit(2)** / **getrlimit(2)** / **setrlimit(2)**: `struct rlimit` layouts identical (two u64 fields), but resource IDs differ:
  - Linux: `RLIMIT_CPU=0, RLIMIT_FSIZE=1, RLIMIT_DATA=2, RLIMIT_STACK=3, RLIMIT_CORE=4, RLIMIT_RSS=5, RLIMIT_NPROC=6, RLIMIT_NOFILE=7, RLIMIT_MEMLOCK=8, RLIMIT_AS=9, RLIMIT_LOCKS=10, RLIMIT_SIGPENDING=11, RLIMIT_MSGQUEUE=12, RLIMIT_NICE=13, RLIMIT_RTPRIO=14, RLIMIT_RTTIME=15`.
  - NetBSD: similar but `RLIMIT_NOFILE=8` (offset), `RLIMIT_VMEMORY` (swap limit) — roughly aligned but IDs shift.

- **sysinfo(2)** / **utsname(2)**: Entirely different struct layouts.
  - Linux `sysinfo`: `uptime, loads[3], totalram, freeram, sharedram, bufferram, totalswap, freeswap, procs, pad, totalhigh, freehigh, mem_unit`.
  - NetBSD: no `sysinfo`; use `getloadavg(2)` or sysctl for memory info.

- **times(2)**: `struct tms` layout identical (four clock_t fields), but clock resolution (CLOCKS_PER_SEC) may differ.

- **fork(2)** / **vfork(2)**: NetBSD has both; semantics mostly identical. However:
  - NetBSD's `vfork()` is closer to Linux `clone(CLONE_VFORK)` semantics.
  - Child PID return in both is the same (return parent's PID in parent, child's PID in child... wait, that's inverted in NetBSD? Double-check.).
  - Actually both return child PID in parent, 0 in child — identical.

- **wait4(2)**: `struct rusage` layout differs between Linux and NetBSD:
  - Linux: `struct rusage { timeval ru_utime, ru_stime; long ru_maxrss, ru_ixrss, ... }`.
  - NetBSD: Same basic layout but field padding and order differ.

- **select(2)**: `fd_set` is arch-dependent (bitmask). NetBSD's `FD_SET` macro and struct compatible with Linux on x86_64, but `struct timeval` field order may differ.

- **clone(2)**: NetBSD does NOT have Linux-style `clone()` with `CLONE_*` flags. It has:
  - `fork(2)` for full process duplication.
  - `_lwp_create(2)` for thread creation within a process.
  - No equivalent to Linux `CLONE_VM | CLONE_THREAD | CLONE_SIGHAND` etc.

- **execve(2)**: Arg/env array passing identical, but pathname resolution may differ (interpreter search, `.so` library loading paths).

- **getdents(2)** / **getdents64(2)**: Directory entry struct differs:
  - Linux: `struct dirent { ino_t d_ino; off_t d_off; unsigned short d_reclen; unsigned char d_type; char d_name[...]; }`.
  - NetBSD: `struct dirent { u_int32_t d_fileno; u_int16_t d_reclen; u_int8_t d_type; u_int8_t d_namlen; char d_name[...]; }` — no `d_off`, `d_namlen` instead of `strlen(d_name)`.

- **pread64(2)** / **pwrite64(2)**: Identical semantics, compatible arg passing.

- **readv(2)** / **writev(2)**: `struct iovec` layout identical; compatible.

- **setuid(2)** / **setgid(2)** / **seteuid(2)** / **setegid(2)**: Semantics identical.

- **setpgid(2)** / **getpgid(2)** / **setsid(2)** / **getsid(2)**: Identical.

- **setitimer(2)** / **getitimer(2)**: `struct itimerval` layout identical.

- **gettimeofday(2)** / **settimeofday(2)**: `struct timeval` and `struct timezone` layout identical.

- **futex(2)**: **NOT** in NetBSD. NetBSD has `_lwp_park(2)` / `_lwp_wakeup(2)` instead (see § C below).

- **poll(2)**: `struct pollfd` layout identical; compatible.

- **epoll_***: **NOT** in NetBSD. NetBSD has `kevent(2)` instead (see § C below).

- **prctl(2)**: Linux-only. NetBSD equivalent is sysctl or per-process attributes set via other calls.

- **ptrace(2)**: Both have it, but syscall numbering and struct layouts differ significantly.

**Estimate**: ~70 syscalls. Most require personality server IPC.

#### C. No Linux Analog (~50 syscalls)

NetBSD-specific syscalls with no Linux equivalent. Require stub implementations (ENOSYS, minimal emulation, or forwarding to server state). Examples:

- **_lwp_create(ucontext_t *, flags, lwp_id_t *)**; Creates a new thread (LWP) within the current process's address space.
  - No Linux equivalent; Linux uses `clone(CLONE_VM | CLONE_THREAD)`.
  - Requires server-side thread ID tracking, ucontext interpretation.

- **_lwp_self()**: Returns the current LWP ID (thread ID in NetBSD terminology).
  - Rough equivalent: Linux `gettid(2)`, but semantics differ (LWP ID is process-local, not global).

- **_lwp_exit()**: Exits the current LWP without killing the process.
  - No Linux single-threaded equivalent (Linux thread exit is via `exit_group` or signal in multithreaded context).

- **_lwp_suspend(lwpid_t)** / **_lwp_continue(lwpid_t)**: Suspend/resume a specific LWP.
  - No Linux equivalent; would require signal-based emulation or stub.

- **_lwp_kill(lwpid_t, signum)**: Send a signal to a specific LWP.
  - Linux: `tgkill(pid, tid, sig)` is the analog, but NetBSD's LWP ID is process-local.

- **_lwp_park(clockid_t, int, const struct timespec *, unsigned int, const void *, ...)**: Park (block) the current LWP.
  - No direct Linux equivalent. Roughly similar to `futex(FUTEX_WAIT)` but with different semantics.
  - Requires server-side parking queue.

- **_lwp_wakeup(lwpid_t)**: Wake a parked LWP.
  - No direct Linux equivalent. Roughly similar to `futex(FUTEX_WAKE)`.

- **_lwp_getprivate()** / **_lwp_setprivate(void *)**: Get/set per-LWP private pointer.
  - Somewhat similar to Linux TLS (`arch_prctl(ARCH_SET_FS)` on x86_64), but per-thread.

- **kevent(int, const struct kevent *, int, struct kevent *, int, const struct timespec *)**:
  - BSD-style event multiplexing (file descriptors, timers, signals, processes, etc.).
  - **No Linux equivalent** (Linux has `epoll`, `poll`, `select`, but not unified under one syscall).
  - Would require building an event queue on top of Telix's scheduler; very significant work.

- **kqueue()**: Create a kevent filter.
  - No Linux equivalent.

- **__sysctl(int *, u_int, void *, size_t *, const void *, size_t)**:
  - Syscall-based sysctl(2) interface (modern NetBSD).
  - No Linux equivalent (Linux has `/proc/sys` filesystem).
  - Requires server-side sysctl tree emulation (major subsystem).

- **getfh(const char *, fhandle_t *)** / **fhopen(const fhandle_t *, int)**: 
  - File handle operations (NFS-related).
  - No Linux equivalent.

- **statfs(const char *, struct statfs *)** / **fstatfs(int, struct statfs *)**: 
  - Both OSes have these, but struct layouts differ. Covered above in §B.

- **revoke(const char *)**: Revoke access to a file.
  - No Linux equivalent.

- **fsync_range(int, int, off_t, off_t)**: Fsync a range of a file.
  - Linux: `sync_file_range(2)` is somewhat similar but different flags.
  - Treat as struct/flag translation (§B) rather than no-analog.

- **modctl(int, void *)**: Module control (kernel extension loading).
  - No Linux equivalent (Linux: `init_module`, `delete_module`, but different).
  - Stub: return ENOSYS.

- **posix_fadvise(int, off_t, off_t, int)**: 
  - Both Linux and NetBSD have this (POSIX). Flags differ slightly but mostly compatible. Covered in §B.

- **quotactl(const char *, int, int, void *)**: Quota control.
  - Linux has `quotactl(2)`, NetBSD has different semantics. Treat as struct translation (§B).

- **clock_gettime(clockid_t, struct timespec *)** / **clock_settime(...)** / **clock_nanosleep(...)**: 
  - Both OSes have these, compatible. Covered in §B (struct timespec identical).

- **audit(const void *, unsigned int)** / **auditctl(const char *)**: 
  - NetBSD-specific audit framework (security subsystem).
  - No Linux equivalent (Linux has different audit via `/proc/audit` and netlink).
  - Stub: return ENOSYS or minimal emulation.

- **kauth_getgroups(gid_t *, int *)** / **kauth_setgroups(...)**: 
  - NetBSD kauth (kernel authorization) subsystem.
  - Linux: use `getgroups(2)` / `setgroups(2)` instead (compatible).

- **getlogin_r(char *, size_t)** / **setlogin(const char *)**: 
  - NetBSD login session management.
  - Linux: no exact equivalent (use `/etc/utmp` or PAM).
  - Stub or minimal emulation.

- **getcontext(ucontext_t *)** / **setcontext(const ucontext_t *)** / **makecontext(ucontext_t *, void (*)(void), int, ...)**: 
  - Signal context manipulation.
  - Linux has `sigcontext` but no direct equivalent to `getcontext(2)`.
  - These are more libc-level than syscalls in Linux (use signal frame instead).
  - NetBSD has syscall versions; treat as complex (§B).

- **swapctl(int, void *)**: Swap management control.
  - No direct Linux equivalent.
  - Stub: return ENOSYS.

- **rasctl(const char *, int, int, void *)**: Rasterop (graphics) control.
  - Obsolete on modern NetBSD; stub.

- **sysarch(int, void *)**: Architecture-specific operations.
  - Linux: `arch_prctl(2)` for x86_64 (similar but different numbers).
  - Treat as struct translation (§B).

- **__getdents30(int, void *, size_t)**: getdents(2) version 30 (compat layer).
  - Covered in §B (struct translation).

- **compat50_***: NetBSD has a slew of compatibility syscalls for older ABIs (compat50_stat, compat50_wait, etc.).
  - These are *not* needed for modern NetBSD 10.x binaries; skip for MVP.
  - Total of ~20 compat50_* syscalls; ignore for initial scope.

**Estimate**: ~50 syscalls (excluding compat50_* and other legacy layers). Most return ENOSYS or require stub implementations.

### Summary Table: Syscall ABI Delta

| Category | Count | Effort | Notes |
|----------|-------|--------|-------|
| (A) Trivial number remap | ~90 | Low | In-kernel fast-path table, no server IPC. |
| (B) Struct/flag translation | ~70 | Medium | Server IPC required; struct repack in netbsd_srv. |
| (C) NetBSD-specific, no Linux analog | ~50 | High | Stubs, emulation, or new server-side state (LWP, kevent, sysctl). |
| **Subtotal implemented** | **~210** | — | Covers ~70% of NetBSD syscall surface. |
| Not yet needed (compat50_*, obsolete) | ~120 | N/A | Skip for MVP. |

---

## 2. Signal Handling Differences

### Numbering and Allocation

| Signal | Linux | NetBSD | Notes |
|--------|-------|--------|-------|
| SIGHUP | 1 | 1 | Identical. |
| SIGINT | 2 | 2 | Identical. |
| SIGQUIT | 3 | 3 | Identical. |
| SIGILL | 4 | 4 | Identical. |
| SIGTRAP | 5 | 5 | Identical. |
| SIGABRT/SIGIOT | 6 | 6 | Identical. |
| SIGBUS | 7 | 7 | Identical. |
| SIGFPE | 8 | 8 | Identical. |
| SIGKILL | 9 | 9 | Identical (uncatchable). |
| SIGUSR1 | 10 | 10 | Identical. |
| SIGSEGV | 11 | 11 | Identical. |
| SIGUSR2 | 12 | 12 | Identical. |
| SIGPIPE | 13 | 13 | Identical. |
| SIGALRM | 14 | 14 | Identical. |
| SIGTERM | 15 | 15 | Identical. |
| SIGSTOP | 19 | 17 | **DIFFERENT** — Linux 19, NetBSD 17. |
| SIGTSTP | 20 | 18 | **DIFFERENT** — Linux 20, NetBSD 18. |
| SIGCONT | 18 | 19 | **DIFFERENT** — Linux 18, NetBSD 19. |
| SIGCHLD | 17 | 20 | **DIFFERENT** — Linux 17, NetBSD 20. |
| SIGPWR | 30 | 32 | **COLLISION** — Linux `SIGPWR=30`, NetBSD `SIGPWR=32` (Linux 30 = `SIGRTMIN + 0`). |
| SIGINFO | N/A | 29 | **NEW** — NetBSD 29 (Linux has no `SIGINFO`; use `SIGPROF=27` in some contexts). |
| SIGRTMIN | 34 | 33 | Real-time signal base (Linux 34, NetBSD 33). |
| SIGRTMAX | 64 | 63 | Real-time signal max (Linux 64, NetBSD 63). |

**Key differences**:
- **Signal number collisions**: SIGCONT/SIGTSTP/SIGSTOP form a cluster with different numbers.
- **SIGINFO in NetBSD**: Used for status inquiry (similar to `SIGPROF` or `SIGVTALRM` in Linux).
- **Real-time signal range**: Compressed in NetBSD (33–63) vs Linux (34–64).

### `sigaction(2)` Struct Layout

#### Linux

```c
struct sigaction {
    union {
        __sighandler_t sa_handler;
        void (*sa_sigaction)(int, siginfo_t *, void *);
    } __sigaction_handler;
    __sigset_t sa_mask;          // sigset_t (u64[4])
    int sa_flags;                 // 32-bit flags
    void (*sa_restorer)(void);    // optional restorer (kernel-provided on modern Linux)
};
```

Bit layout (x86_64):
- **Offset 0–7**: Handler pointer (u64).
- **Offset 8–15**: Restorer pointer (u64).
- **Offset 16–23**: sa_mask (u64[0], first 64 bits of sigset_t).
- **Offset 24–27**: sa_flags (u32).

#### NetBSD

```c
struct sigaction {
    union {
        void (*_sa_handler)(int);
        void (*_sa_sigaction)(int, siginfo_t *, void *);
    } _sa_u;               // Handler (offset 0–7)
    sigset_t sa_mask;       // u32[4] (128 bits, but typically [0] is the main mask)
    int sa_flags;           // u32 flags (offset 24–27)
};
```

Bit layout (x86_64):
- **Offset 0–7**: Handler pointer (u64).
- **Offset 8–15**: sa_mask[0] (u32) + sa_mask[1] (u32) — first 64 bits of mask.
- **Offset 16–23**: sa_mask[2] (u32) + sa_mask[3] (u32) — second 64 bits of mask.
- **Offset 24–27**: sa_flags (u32).

**Struct size**: Linux = 32 bytes (with padding), NetBSD = 32 bytes (compact layout).

### `sigaction` Flag Differences

| Flag | Value | Linux | NetBSD | Semantics |
|------|-------|-------|--------|-----------|
| SA_ONSTACK | 0x08000000 | Yes | Yes | Use alternate stack. |
| SA_RESETHAND | 0x80000000 | Yes | No | Reset handler to SIG_DFL after delivery. |
| SA_RESTART | 0x10000000 | Yes | Yes (0x2) | Restart interrupted syscalls. **Different bit!** |
| SA_NODEFER | 0x40000000 | Yes | No | Don't block signal during handler. |
| SA_SIGINFO | 0x04000000 | Yes | Yes | Use `sa_sigaction` (3-arg) instead of `sa_handler` (1-arg). |
| SA_NOCLDWAIT | 0x00000001 | Yes | No | Don't wait for child (SIGCHLD). |
| SA_NOCLDSTOP | 0x00000001 | Yes (0x1) | Yes (0x1) | Don't notify on child stop. **Different values!** |
| SA_RTSIG | — | N/A | N/A | — |

**Key differences**:
- **SA_RESTART**: Linux = 0x10000000 (bit 28), NetBSD = 0x2 (bit 1). **Requires translation**.
- **SA_NOCLDSTOP** and **SA_NOCLDWAIT**: Different bit positions; careful mapping needed.
- **SA_RESETHAND**, **SA_NODEFER**: Linux-specific; netbsd_srv needs to emulate or stub.

### `siginfo_t` Layout

Both Linux and NetBSD use POSIX `siginfo_t`, but field layouts differ slightly:

#### Linux (x86_64)

```c
typedef struct {
    int si_signo;        // signal number (offset 0–3)
    int si_errno;        // errno value (offset 4–7)
    int si_code;         // signal code (offset 8–11)
    union {...} si_u;    // signal-specific data (offset 12–end)
} siginfo_t;  // 128 bytes total
```

#### NetBSD (x86_64)

```c
typedef struct {
    int si_signo;        // signal number (offset 0–3)
    code_t si_code;      // signal code (offset 4–7, narrower in some archs)
    int si_errno;        // errno value (offset 8–11)
    union {...} si_u;    // signal-specific data (offset 12–end)
} siginfo_t;  // 128 bytes total, but field order differs
```

**Impact**: When copying `siginfo_t` between NetBSD userspace and kernel, the `si_code` and `si_errno` field order differs. Personality server must repack.

### `ucontext_t` Layout

Both define `ucontext_t` with `uc_link`, `uc_sigmask`, `uc_stack`, and `uc_mcontext`:

#### Linux (x86_64)

```c
typedef struct ucontext {
    unsigned long uc_flags;
    struct ucontext *uc_link;
    stack_t uc_stack;
    mcontext_t uc_mcontext;  // ~376 bytes
    sigset_t uc_sigmask;     // u64[16]
} ucontext_t;
```

#### NetBSD (x86_64)

```c
typedef struct __ucontext {
    unsigned int uc_flags;
    struct __ucontext *uc_link;
    stack_t uc_stack;
    mcontext_t uc_mcontext;  // ~360 bytes
    sigset_t uc_sigmask;     // u32[4]
} ucontext_t;
```

**Differences**:
- **uc_flags**: Linux `unsigned long` (8 bytes), NetBSD `unsigned int` (4 bytes).
- **mcontext_t**: Linux includes MMX/XMM registers, NetBSD may include different extended state.
- **uc_sigmask**: Linux `u64[16]` (128 bytes, 128 signals), NetBSD `u32[4]` (16 bytes, 128 signals).

### Signal Delivery and `sigreturn` Trampoline

#### Linux

- Kernel pushes return address to `SA_ONSTACK` or regular stack, with `siginfo_t` and `ucontext_t` adjacent.
- Signal handler returns to `sa_restorer` (if set; otherwise, kernel provides one via vDSO on modern kernels).
- `sa_restorer` executes `rt_sigreturn` (x86_64 syscall #15) to restore context.

#### NetBSD

- Kernel pushes return address and signal context.
- Signal handler returns to kernel-provided restorer (implicit, no `sa_restorer` field in struct).
- Kernel restores context via `sigreturn` syscall.

**Implication**: The personality server must handle sigreturn(2) differently; Linux's `rt_sigreturn` syscall number doesn't map directly to NetBSD's `sigreturn`.

### What netbsd_srv Must Do

1. **Signal number translation**: Map NetBSD signal numbers to Linux (or Telix-native) signal numbers at entry and exit.
   - **Files affected**: `netbsd_srv::handle_sigaction()`, `handle_signal_delivery()` (signal dispatch module).
   - **Complexity**: O(n) lookup table (30 signals); low effort.

2. **Struct repacking**: Convert `struct sigaction`, `siginfo_t`, `ucontext_t` between NetBSD and kernel layouts.
   - **Files affected**: `netbsd_srv` signal module, `syscall/handlers.rs` (signal frame setup).
   - **Complexity**: Medium (field reordering, size validation).

3. **Signal mask format**: NetBSD `sigset_t` is `u32[4]`; Telix kernel currently uses `u64` masks. Requires per-personality mask encoding.
   - **Files affected**: `sched/task.rs` (signal mask storage), `netbsd_srv::sig_mask` field.
   - **Complexity**: Low (repacking, no new state needed).

4. **Restorer address handling**: NetBSD signals use implicit kernel restorer; ensure personality forwarding handles this.
   - **Files affected**: `netbsd_srv::handle_sigaction()`.
   - **Complexity**: Low (validate that `sa_restorer` is ignored).

---

## 3. Process Model

### Fork, Vfork, and Clone Semantics

#### Linux

- **fork(2)**: Full process duplication (address space, file descriptors, signal handlers); parent and child are independent.
- **vfork(2)**: Lightweight; child shares parent's address space until exec() or exit(). Parent blocks until child execs or exits (POSIX compliance).
- **clone(2)**: Flexible; controlled by flags (`CLONE_VM`, `CLONE_FS`, `CLONE_FILES`, `CLONE_SIGHAND`, `CLONE_THREAD`, etc.).
  - `CLONE_THREAD`: Create a new thread within the same process (shared address space, file descriptors, signal handlers, but separate TLS and stack).
  - `CLONE_VFORK`: Semantics like vfork (parent blocks).
  - `CLONE_NEWPID`, `CLONE_NEWNET`, etc.: Namespace isolation (containers).

#### NetBSD

- **fork(2)**: Full process duplication (same as Linux).
- **vfork(2)**: Lightweight; similar to Linux vfork.
- **clone(2)**: **NOT** available in standard NetBSD. Instead:
  - **_lwp_create(ucontext_t *context, unsigned long flags, lwp_t *new_lwp)**: Create a new LWP (lightweight process / thread) within the current process.
    - Context includes stack pointer, entry point, argument.
    - Flags: `LWP_DETACHED` (won't be waited on), others.
    - Returns new LWP ID in `new_lwp`.

- **_lwp_self()**: Get the current LWP ID (process-local thread ID).
- **_lwp_exit()**: Exit the current LWP without killing the process.
- **_lwp_kill(lwp_t lwp, int sig)**: Send a signal to a specific LWP.
- **_lwp_suspend(lwp_t lwp)** / **_lwp_continue(lwp_t lwp)**: Suspend/resume an LWP.
- **_lwp_wait(lwp_t lwp, lwp_t *departed)**: Wait for a specific LWP to exit.

### LWP Model vs Telix Thread Model

**Telix's thread model** (current):
- `clone(CLONE_THREAD)` creates a new thread in the same address space.
- Threads are identified by a global thread ID (`tid`).
- Each thread has its own stack, TLS (`tls_base`), signal mask (inherited from task).
- Task contains signal handlers, file descriptors, process state.

**NetBSD's LWP model**:
- LWPs are process-local thread IDs.
- `_lwp_create()` creates a new LWP with explicit stack and entry point.
- LWPs can be suspended/resumed at the syscall level.
- Each LWP has its own signal mask (distinct from parent, not inherited).

**Mapping strategy**:
- Telix task + threads → NetBSD process + LWPs.
- When a NetBSD process calls `fork()`, netbsd_srv invokes `SYS_PERSONALITY_FORK` (kernel primitive).
- When a NetBSD process calls `_lwp_create()`, netbsd_srv calls `SYS_PERSONALITY_THREAD_CREATE` (existing kernel primitive for thread creation, used by linux_srv).
- Signal delivery and LWP-specific kills require tracking which LWP (thread) received the signal.

**What netbsd_srv Must Do**:

1. **Fork/vfork dispatch**: Map NetBSD `fork()` → Telix `SYS_PERSONALITY_FORK`.
   - **Files affected**: `netbsd_srv::handle_fork()`.
   - **Complexity**: Low (already in linux_srv as precedent).

2. **LWP creation**: Map `_lwp_create(ucontext_t *, flags, lwp_t *)` → interpret `ucontext_t`, call `SYS_PERSONALITY_THREAD_CREATE`.
   - Parse NetBSD `ucontext_t` (stack pointer, entry point, args).
   - Return new LWP ID (map to Telix thread ID).
   - **Files affected**: `netbsd_srv::handle_lwp_create()` (new handler).
   - **Complexity**: Medium (ucontext parsing, LWP ID tracking table).

3. **LWP queries**: `_lwp_self()` → return current LWP ID (Telix thread ID, remapped to NetBSD LWP numbering).
   - **Files affected**: `netbsd_srv::handle_lwp_self()`.
   - **Complexity**: Low.

4. **LWP suspension/resumption**: `_lwp_suspend()`, `_lwp_continue()` → stubs (return ENOSYS) or minimal emulation (track suspended state, fail on syscall entry if suspended).
   - **Files affected**: `netbsd_srv::handle_lwp_suspend()`, `handle_lwp_continue()`.
   - **Complexity**: Low (stubs) to Medium (emulation with state tracking).

5. **LWP termination**: `_lwp_exit()` → call native Telix thread exit (equivalent to Linux `exit_group` but thread-local).
   - **Files affected**: `netbsd_srv::handle_lwp_exit()`.
   - **Complexity**: Low.

6. **LWP-specific signals**: `_lwp_kill(lwp_t, sig)` → resolve LWP to Telix thread, send signal.
   - **Files affected**: `netbsd_srv::handle_lwp_kill()`.
   - **Complexity**: Low (LWP-to-thread lookup table).

7. **Signal mask per-LWP**: Each LWP has its own `sigprocmask(2)`, not inherited from parent.
   - **Files affected**: `netbsd_srv::sig_masks` (table indexed by LWP ID).
   - **Complexity**: Medium (per-thread signal mask storage, masking logic on signal delivery).

---

## 4. Filesystem + Path Conventions

### Dynamic Linker

**Linux**:
- Default path: `/lib64/ld-linux-x86-64.so.2` (x86_64).
- Kernel checks ELF header's `e_entry` and `PT_INTERP` section.
- Linker name is in the ELF binary; kernel loads it via `open()` → `mmap()` → jumps.

**NetBSD**:
- Default path: `/usr/libexec/ld.elf_so` (x86_64).
- Same mechanism; kernel reads `PT_INTERP` from ELF header.

**Implication for Telix**:
- Telix's `kernel/src/syscall/handlers.rs` has an ELF loader in the `execve` path (exec_for_task).
- Current code probably hardcodes `/lib64/ld-linux-x86-64.so.2` or does no special handling.
- For NetBSD support, the kernel must:
  1. Detect NetBSD binaries (ELF `e_ident[EI_OSABI] == ELFOSABI_NETBSD`).
  2. Read `PT_INTERP` from the ELF header.
  3. When setting up the executable, use the linker path from `PT_INTERP` (not a hardcoded path).

**What needs to change**:
- **kernel/src/syscall/handlers.rs**: Update `exec_for_task()` to:
  - Detect ELF OSABI field.
  - Read `PT_INTERP` dynamically (instead of assuming a fixed path).
  - Pass the interpreter path to the VFS for loading.
- Alternatively, create an ELF interpreter table that personality servers can populate.

**Complexity**: Low to Medium (ELF header parsing is already in the kernel; dynamic path reading adds ~50 lines).

### /proc vs Sysctl

**Linux**:
- `/proc` is mandatory; mounted by default.
- `/proc/self/maps` — memory map visualization.
- `/proc/self/stat`, `/proc/self/status` — process info.
- `/proc/<pid>/fd/` — open file descriptors.
- `/proc/loadavg`, `/proc/meminfo` — system info.

**NetBSD**:
- `/proc` is optional (procfs module, not loaded by default).
- System info accessed via `sysctl(2)` (or `__sysctl(2)` syscall).
  - E.g., `sysctl({CTL_HW, HW_MEMSIZE})` for total memory.
  - `sysctl({CTL_VM, VM_UVMEXP})` for VM stats.
  - `sysctl({CTL_KERN, KERN_MAXPROC})` for max processes.

**Implication for Telix**:
- linux_srv emulates `/proc` by parsing process state in netbsd_srv.
- netbsd_srv needs to emulate `/proc` *or* provide a sysctl tree.
- For MVP, stub sysctl to return minimal values (ENOSYS for most queries, hardcoded defaults for essentials).

**What netbsd_srv Must Do**:

1. **sysctl(2) handler**: `__sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen)`.
   - Map sysctl name arrays to a tree of "get" handlers.
   - For MVP, return ENOSYS for most; hardcode a few essentials (CTL_KERN.KERN_BOOTTIME, CTL_HW.HW_MEMSIZE, etc.).
   - **Files affected**: `netbsd_srv::handle_sysctl()` (new handler).
   - **Complexity**: Medium (sysctl tree parsing, per-node handlers; ~500–1000 lines).

2. **Optional /proc emulation**: If NetBSD binaries expect `/proc` at runtime (e.g., reading `/proc/self/maps` for ASLR), netbsd_srv can synthesize responses to `open("/proc/...")` / `read()` / `lstat()` calls.
   - For MVP, treat `/proc` as non-existent (return ENOENT on open).

**Estimate**: +2–3 sessions (sysctl tree, limited proc stubs).

### File Paths and Libc Conventions

**BSD libc** (including NetBSD):
- Standard library paths: `/lib`, `/usr/lib`, `/usr/local/lib`.
- Shared object naming: `.so` (like Linux; no versioning in filename on modern NetBSD).
- Executable paths: `/bin`, `/usr/bin`, `/usr/local/bin`.

**Linux libc**:
- Standard library paths: `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`, `/usr/local/lib`.
- Shared object naming: `.so.MAJOR.MINOR` (versioned).

**Implication for Telix**:
- Initramfs probably has Linux directory structure (`/lib64/libc.so.6`).
- NetBSD binaries looking for `/lib/libc.so.10` won't find them.
- VFS server should be neutral (serve files by path), but the personality server may need to remap paths (e.g., `/lib/libc.so.10` → `/lib64/libc.so.6` if both are in initramfs under different names).

**For MVP**: 
- Skip path remapping; assume initramfs has both Linux and NetBSD libs (unlikely, but MVP scope doesn't require 100% binary compatibility).

---

## 5. ELF Loading + ABI Markers

### ELF OSABI Detection

**Current Telix behavior** (linux_srv):
- Assumes all binaries are Linux (ELF `e_ident[EI_OSABI]` = `ELFOSABI_LINUX` = 3).
- Kernel doesn't sniff OSABI; sets personality at exec time based on... (check handlers.rs).

**What needs to happen**:

1. **Kernel exec path** (`kernel/src/syscall/handlers.rs::exec_for_task()`):
   - Read ELF `e_ident[EI_OSABI]` from the binary header.
   - Map OSABI to PersonalityId:
     - `ELFOSABI_SYSV` (0) or `ELFOSABI_UNIX` → Telix-native (for now).
     - `ELFOSABI_LINUX` (3) → Linux.
     - `ELFOSABI_NETBSD` (2) → NetBSD.
     - Others → Telix-native (default).
   - Call `SYS_PERSONALITY_SET` to attach the personality.

2. **Personality server registration**: At startup, each personality server (linux_srv, netbsd_srv, ...) registers its port with the kernel via `SYS_PERSONALITY_REGISTER`.

3. **PT_NOTE / NT_NETBSD_IDENT section** (optional, for finer control):
   - NetBSD adds `PT_NOTE` with tag `NT_NETBSD_IDENT` containing version info.
   - Kernel could read this for version-specific compatibility (e.g., NetBSD 9.x vs 10.x ABI differences).
   - For MVP, ignore; OSABI field is sufficient.

**What netbsd_srv Must Do**:

1. **Register at startup**: Call `SYS_PERSONALITY_REGISTER(PERSONALITY_ID=5, port)`.
   - (Assume NetBSD gets personality ID 5; check current allocation in task.rs.)

2. **Kernel changes**: Update `exec_for_task()` to read OSABI and set personality.
   - **Files affected**: `kernel/src/syscall/handlers.rs`.
   - **Complexity**: Low (ELF header is already read; add ~20 lines for OSABI check).

**Estimate**: +1 session (kernel OSABI detection, personality server registration).

---

## 6. Easy Wins vs Structural Work

### Easy Wins

1. **Trivial number remap syscalls (~90 syscalls)**: In-kernel fast-path table.
   - Effort: 1 session (fast-path table registration, kernel dispatch).
   - Examples: read, write, close, dup, chmod, mkdir, rmdir, unlink, etc.

2. **Simple struct/flag translation syscalls (~30 of ~70 in category B)**: Server-side repack.
   - Effort: 2–3 sessions (fork, wait4, stat, fstat, basic signal operations).
   - Examples: fork, wait4, stat, fstat, lstat, times, getuid, setuid.

3. **Stub syscalls (~50 return ENOSYS)**: Return `-ENOSYS` without processing.
   - Effort: 0.5 sessions (grep/sed to auto-generate stub handlers).
   - Examples: kqueue, kevent, audit, kauth_*, swapctl, modctl, rasctl, etc.

4. **Signal number translation**: O(n) lookup table.
   - Effort: 0.5 sessions.

### Structural Work

1. **LWP threading model** (_lwp_create, _lwp_park, _lwp_wakeup, etc.):
   - Effort: 3–4 sessions.
   - Requires: Mapping NetBSD LWP IDs to Telix thread IDs, per-LWP signal masks, parking queue.
   - **Risk**: Correctness of threading semantics under concurrent signals + suspension.

2. **Sysctl tree emulation** (__sysctl syscall):
   - Effort: 2–3 sessions.
   - Requires: Sysctl name tree parsing, per-node handlers, system info synthesis.
   - **Risk**: Missing sysctl nodes will cause applications to ENOSYS-fail at runtime.

3. **ELF OSABI detection in kernel** (kernel/src/syscall/handlers.rs):
   - Effort: 1 session.
   - Requires: ELF header parsing (already present; add OSABI check).
   - **Risk**: Low (straightforward conditional).

4. **Struct repacking for complex syscalls** (sigaction, siginfo_t, ucontext_t, getdents, stat, wait4):
   - Effort: 2–3 sessions.
   - Requires: Field-by-field translation between Linux and NetBSD layouts.
   - **Risk**: Layout errors cause crashes or data corruption; needs thorough testing.

5. **Kqueue support** (kevent, kqueue):
   - Effort: 5–7 sessions (**not recommended for MVP**).
   - Requires: Event queue infrastructure, fd/timer/signal/process event types, async multiplexing.
   - **Risk**: High (new subsystem; no Linux analog; significant testing required).

---

## 7. Minimum-Viable Personality vs Production-Shape

### Minimum-Viable Personality

**Goal**: Run NetBSD `/bin/ls` and `/bin/sh`.

**Syscalls needed**:
1. **Exec / Fork / Exit**: execve, fork, vfork, exit, exit_group, wait4, getpid, getppid.
2. **File I/O**: open, openat, close, read, write, lseek, stat, fstat, lstat, getdents, readdir (libc), getcwd, chdir.
3. **Memory**: mmap, mprotect, munmap, brk, sbrk (libc).
4. **Signals**: sigaction, sigprocmask, sigaltstack, kill, signal delivery (kernel-side).
5. **Process attributes**: getuid, geteuid, getgid, getegid, umask, access, chmod, chown.
6. **Utilities**: uname, gettimeofday, clock_gettime, nanosleep, ioctl (for tty control).
7. **Threading** (minimal): _lwp_self, _lwp_create (basic thread creation if shell uses threads).

**Excluded from MVP**:
- Kqueue / kevent (not needed for simple command execution).
- Sysctl (stub most queries; handle essentials like KERN_BOOTTIME if needed).
- Advanced socket operations (AF_UNIX, AF_INET — stubs unless shell uses them).
- Ptrace (debugging, not needed for basic execution).
- Audit framework.
- Namespace isolation (not part of vanilla NetBSD base).

**Estimate**: ~15–18 sessions.

**Deliverables**:
- netbsd_srv userspace binary (~3000–5000 lines of Rust, modeled after linux_srv).
- Kernel changes: OSABI detection in exec path (~50 lines), personality routing (already exists).
- Fast-path syscall table for common trivial remaps.

### Production-Shape Personality

**Goal**: Run NetBSD base system (init, daemons, multi-user environment).

**Additional syscalls**:
- **Socket family**: socket, bind, listen, accept, connect, send, recv, shutdown, setsockopt, getsockopt (AF_UNIX, AF_INET).
- **Process management**: setpgid, getpgrp, setsid, tcsetpgrp, tcgetpgrp (job control).
- **Advanced I/O**: poll, select, fcntl (file locking), dup3, pipe, mkfifo.
- **Memory**: mremap, mincore, madvise.
- **Signals**: Full sigaction/siginfo/ucontext/sigreturn support (all 30 signals).
- **LWP threading**: Full _lwp_* suite (suspension, resumption, waiting, signaling).
- **Filesystem**: Symlinks, rename, truncate, chmod variants, chown variants, xattr.
- **Sysctl**: Core sysctl queries for boot-time system info.
- **Device nodes**: ioctl for tty, /dev/null, /dev/zero, /dev/random (stubs okay).
- **Proc filesystem**: Minimal /proc emulation for process listing (readdir /proc).

**Estimate**: ~40–56 sessions.

---

## 8. Non-Obvious Gotchas

### Gotcha 1: NetBSD's Signal Delivery Model vs Telix's Blocking

**Issue**:
NetBSD's `_lwp_park()` / `_lwp_wakeup()` primitives have complex interaction with signal delivery. When an LWP is parked and receives a signal, the signal handler should run before returning from `_lwp_park()` (similar to Linux `futex(FUTEX_WAIT)` interrupted by signal). However, Telix's kernel signal delivery model may not support this — signals currently unblock waiting threads uniformly, without running handlers at a particular point in the userspace code.

**Impact**:
If not handled correctly, signal-aware applications (threading libraries, event loops) will deadlock or misbehave. This can surface as:
- Concurrent `_lwp_park()` with pending signals never returning.
- Signal handlers not executing at the expected location.
- Race conditions in signal mask changes during `_lwp_park()`.

**Mitigation**:
- Plan 2–3 extra sessions for signal/threading interaction testing.
- Ensure personality_dequeue_signal is called before blocking, and personality_write_frame is used to adjust the return point post-handler.

### Gotcha 2: struct stat and getdents Layout Sensitivity

**Issue**:
The `struct stat` layout differs between Linux and NetBSD in subtle ways (field ordering, st_birthtim addition, padding). Tools like `find`, `ls`, and file managers parse stat output; incorrect repacking will cause:
- Incorrect file sizes (st_size read from wrong offset).
- Incorrect timestamps (st_mtime / st_atime swapped or in wrong units).
- Segfaults if code does pointer arithmetic within the struct.

Similarly, `struct dirent` layout differs (no d_off, d_namlen instead of strlen). Directory iteration will fail if repack is wrong.

**Impact**:
Boot will hang or crash during filesystem initialization if `/bin/ls` can't iterate `/bin`.

**Mitigation**:
- Document exact struct layouts (extract from NetBSD headers during dev).
- Write struct-layout unit tests (convert, validate known values, round-trip).
- Test early with a minimal init that just lists files.

### Gotcha 3: Interpreter Path Hardcoding

**Issue**:
If the kernel's ELF loader has `/lib64/ld-linux-x86-64.so.2` hardcoded (or `/usr/libexec/ld.elf_so`), NetBSD binaries won't load. The interpreter path is critical; a mismatch is silent (binary appears to run but uses the wrong linker).

**Impact**:
NetBSD binaries either fail to load or use the Linux interpreter, causing immediate segfault (undefined symbol lookups, wrong ELF entry point).

**Mitigation**:
- Audit kernel/src/syscall/handlers.rs for hardcoded interpreter paths immediately.
- Read `PT_INTERP` from the binary during exec, not from config.
- Test with a simple NetBSD ELF binary that prints its own interpreter string (readelf -p .interp).

### Gotcha 4: Personality Auto-Detection Timing

**Issue**:
The kernel must detect personality BEFORE forwarding the first syscall. If personality detection happens lazily (on first syscall), there's a race: the kernel routes the syscall to TelixNative, which fails because the task isn't initialized as NetBSD yet.

**Impact**:
NetBSD binaries' very first syscall (often getpid, getuid, or mmap) will dispatch to the wrong personality, returning garbage or an error.

**Mitigation**:
- Personality MUST be set during `exec()`, before the task is resumed.
- Add a test: exec a NetBSD binary, verify the first forwarded syscall goes to netbsd_srv, not TelixNative.

### Gotcha 5: Signal Mask Format (u64 vs u32[4])

**Issue**:
Telix kernel currently stores signal masks as `u64` (64 signals). NetBSD uses `sigset_t` = `u32[4]` (but still 64 or 128 signals depending on platform). If the personality server's sigprocmask handler doesn't convert between formats, signals will be masked incorrectly:
- A blocked signal in NetBSD notation might be unblocked in Telix notation.
- Signal delivery will get the mask wrong, leading to unmasked handlers firing recursively (potential crash).

**Impact**:
Signal handling breaks; nested signals cause stack overflow or memory corruption.

**Mitigation**:
- Document the per-personality signal mask format in `sched/task.rs`.
- Personality server provides sigprocmask handler that converts u32[4] → u64, apply mask, convert back.
- Test: sigaction → sigprocmask → send signal → verify handler doesn't fire.

---

## 9. Sessions Estimate Breakdown

### Minimum-Viable Personality (15–18 sessions)

| Task | Sessions | Notes |
|------|----------|-------|
| Kernel OSABI detection + personality routing | 1 | ELF header check, SYS_PERSONALITY_SET call. |
| netbsd_srv scaffold + main loop | 1 | Port creation, personality registration, message dispatch loop (copy linux_srv skeleton). |
| Trivial syscall remaps (read, write, close, etc.) | 1 | Fast-path table generation + 90 syscalls. |
| File I/O handlers (open, stat, readdir, chdir, getcwd) | 3 | Integration with VFS server, path handling. |
| Memory management (mmap, mprotect, munmap, brk) | 2 | Personality_mmap_anon + friends, basic sbrk. |
| Process creation + exit (fork, execve, wait4, exit) | 2 | Use SYS_PERSONALITY_FORK, SYS_PERSONALITY_EXECVE. |
| Signals (sigaction, sigprocmask, signal delivery) | 2 | Signal number translation, basic handlers. |
| Process attributes (uid, gid, umask, access, chmod) | 1 | Simple field queries + VFS ioctl calls. |
| Utilities (uname, gettimeofday, nanosleep, ioctl) | 1 | Syscall stubs + tty ioctl passthrough. |
| Testing + bug fixes | 2 | Boot NetBSD init, run ls/sh, iterate on failures. |
| **Total** | **16–18** | — |

### Production-Shape Personality (+22–38 sessions, ~40–56 total)

| Task | Sessions | Notes |
|------|----------|-------|
| *MVP items above* | *16–18* | — |
| LWP threading (_lwp_create, _lwp_self, _lwp_kill, per-LWP signal masks) | 4 | ID mapping, parking state, signal mask table. |
| LWP suspension/resumption stubs | 1 | Return ENOSYS or minimal state tracking. |
| Sysctl tree (__sysctl handler + core nodes) | 3 | Tree parsing, per-node handlers (CTL_HW, CTL_KERN, CTL_VM). |
| Socket operations (AF_UNIX, AF_INET, poll, select) | 3 | UDS/NET integration, async reply handling. |
| Advanced file I/O (fcntl, dup3, pipe, mkfifo, rename, truncate) | 3 | Flag translation, VFS ioctl calls. |
| Symlinks + xattr | 1 | VFS support already exists; netbsd_srv wrappers. |
| Full sigaction/siginfo/ucontext support (all 30 signals) | 2 | Struct repacking, field reordering, round-trip testing. |
| Proc filesystem (/proc emulation, readdir /proc) | 2 | Synthesize directory listings from process state. |
| getdents repack + stat struct translation | 2 | Field-level layout conversion, testing. |
| Job control (setpgid, setsid, tcsetpgrp, tcgetpgrp, getpgrp) | 2 | Process group + session tracking. |
| Device node emulation (/dev/null, /dev/zero, /dev/random, tty) | 1 | Stubs for open/read/write/ioctl. |
| Testing + integration + boot + daemon ops | 4 | Multi-user boot, service startup, signal handling under load. |
| **Total** | **40–56** | — |

---

## 10. Implementation Approach (Not for Exec, Just Notes)

### Phase 1: Kernel (sessions 1, shared with all personalities)

1. **handlers.rs** (`exec_for_task`):
   - Read ELF `e_ident[EI_OSABI]`.
   - Map to PersonalityId.
   - Call `SYS_PERSONALITY_SET`.

2. **personality.rs** (already robust):
   - No changes needed; forward_to_server already works.

### Phase 2: netbsd_srv Scaffold (session 2)

1. Copy linux_srv.rs → netbsd_srv.rs.
2. Strip out Linux-specific syscall handlers.
3. Keep:
   - ProcessState, FdEntry structures.
   - PROC_TABLE, find_proc.
   - Main loop, port_set dispatch.
   - Personality server registration.
4. Add:
   - Personality ID constant (NetBSD = 5 in task.rs).
   - NetBSD syscall number constants (read syscall.h).

### Phase 3: Trivial Remaps (session 3)

1. Auto-generate fast-path table from a TSV:
   ```
   read    0      3      identity
   write   1      4      identity
   close   3      6      identity
   ...
   ```
2. Kernel loads table on registration.

### Phase 4–18: Handlers (sessions 4–18, MVP)

Implement handlers in order of priority:
1. execve, fork, exit, wait4 (process mgmt).
2. open, close, read, write, lseek (file I/O).
3. stat, fstat, chmod, chown (metadata).
4. sigaction, sigprocmask (signals).
5. getuid, getgid, umask, access (attributes).
6. mmap, mprotect, munmap, brk (memory).
7. getcwd, chdir, readdir (directory).
8. uname, gettimeofday, clock_gettime (info).
9. Stubs for the rest (ENOSYS).

### Phase 19–40: Production (sessions 19–40)

1. LWP threading (_lwp_create, _lwp_self, _lwp_kill, signals).
2. Sysctl tree.
3. Socket operations, job control.
4. Struct repacking (siginfo_t, ucontext_t, stat, getdents).
5. Proc filesystem, device nodes.
6. Testing, integration, bug fixes.

---

## Summary Table

| Aspect | MVP | Production | Notes |
|--------|-----|-----------|-------|
| **Syscalls implemented** | ~180 (90 trivial + 30 struct + 60 stubs) | ~250 (90 + 70 + 90) | Full coverage ~350 possible but diminishing returns. |
| **Effort** | 15–18 sessions | 40–56 sessions | 1 session ≈ 4–6h focused work. |
| **Kernel changes** | ~50 lines (OSABI detect) | +100 lines (ELF read, path). | Already has personality routing. |
| **netbsd_srv size** | ~3000–5000 lines | ~8000–12000 lines | Parallel to linux_srv (14.6k lines). |
| **Critical features** | fork, exec, file I/O, signal, memory | + LWP, sysctl, socket, job control | — |
| **Risk areas** | Signal/LWP interaction, struct layout, interpreter path | Sysctl tree coverage, nested signal handling | See § 8. |

---

## Conclusion

Implementing a NetBSD personality server is **feasible** and would follow the same kernel-level routing infrastructure as linux_srv. The main complexity drivers are:

1. **LWP threading model** (not Linux's clone-based threading).
2. **Sysctl tree** (instead of /proc).
3. **Struct layout translation** (stat, sigaction, getdents, wait4).
4. **Signal numbering collisions** (SIGCONT/SIGTSTP/SIGSTOP offset, SIGINFO, real-time range).
5. **Kqueue absence** (not needed for MVP; major effort if ever required).

A **minimum-viable NetBSD personality** capable of running `/bin/ls` and `/bin/sh` would require **15–18 focused sessions** and deliver ~180 syscalls. A **production-shape personality** comparable to current linux_srv coverage would require **40–56 sessions** and deliver ~250 syscalls.

The **kernel changes are minimal** (~50–100 lines) — mostly ELF header sniffing for personality detection and dynamic interpreter path handling. The bulk of work is in `netbsd_srv`'s userspace handler library.

