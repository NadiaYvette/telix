# Telix

A from-scratch microkernel operating system written in Rust, targeting five 64-bit architectures: aarch64, x86-64, RISC-V 64, LoongArch64, and MIPS64.

## What is Telix?

Telix (from Latin *tela*, web/fabric) is a capability-based microkernel inspired by L4/seL4 and Mach. It is a research and portfolio project exploring two architectural ideas:

- **Coremap-free virtual memory with configurable page clustering.** Telix uses extent-based VM management (B+ trees of intervals) instead of the traditional per-page coremap array. The allocation page size is a configurable multiple of the hardware 4 KiB MMU page, with subpage superpages constructed by composing contiguous MMU pages.

- **Network-unified asynchronous I/O.** All I/O is message-passing: filesystem drivers, device drivers, and network services are userspace servers communicating via L4-style synchronous IPC. There is no synchronous VFS call stack in the kernel. This maps naturally to both local and remote operation.

## Architecture

| Aspect | Design |
|--------|--------|
| Kernel structure | Microkernel (~25K SLOC Rust) |
| IPC model | L4-style synchronous, register-passed messages |
| Process model | Mach-style tasks + threads, M:N threading with scheduler activations |
| Security | seL4-derived capability-based access control |
| VM subsystem | Coremap-free, extent-based, COW with group tracking |
| Supported architectures | aarch64, x86-64, riscv64, loongarch64, mips64el |
| Development platform | QEMU (all targets), Fedora x86-64 host |

## Current Status

**105 integration test phases** pass on aarch64, x86-64, and RISC-V 64, covering:

- Multi-core SMP boot and scheduling (up to 8 CPUs)
- Demand paging with WSCLOCK replacement and superpage promotion
- Copy-on-write fork with COW group tracking
- Capability-based IPC (ports, port sets, grants, proxied cross-node sends)
- Userspace servers: initramfs (CPIO), ext2 filesystem, block device, name server, network (TCP/UDP), event (epoll/timerfd/eventfd)
- ELF loading, dynamic linker stub, `execve`
- POSIX signals (`sigaction`, `sigprocmask`, `sigaltstack`, signal delivery during syscalls)
- POSIX process model (fork, wait4, process groups, sessions, controlling terminal)
- Scheduler activations (M:N user-level threading)
- C userspace via musl-telix (custom musl-compatible C runtime)
- Cryptographic primitives (SHA-256/512, ChaCha20, Ed25519, Curve25519, CSPRNG)
- SSH server (key exchange, encrypted channels)
- Priority inheritance futexes, coscheduling, CPU hotplug

LoongArch64 and MIPS64 pass 79+ and 82+ phases respectively (limited by QEMU TCG timing, not correctness).

## Building

Requires Rust nightly with `-Zbuild-std` support and architecture-specific LLVM targets.

```bash
# Build kernel for a target architecture
bash tools/build-kernel.sh aarch64        # or x86_64, riscv64, loongarch64, mips64

# Build Rust userspace binaries
bash tools/build-user.sh aarch64

# Build C userspace binaries (musl-telix)
bash musl-telix/build.sh aarch64

# Run under QEMU
bash tools/run-qemu.sh target/aarch64-unknown-none/release/telix-kernel
```

Cross-compilation toolchain: `clang` and `ld.lld` (for C userspace), Rust nightly (for kernel and Rust userspace).

## Project Structure

```
kernel/src/
  arch/           Per-architecture code (boot, MMU, traps, timers)
    aarch64/
    x86_64/
    riscv64/
    loongarch64/
    mips64/
  mm/             Virtual memory (address spaces, page tables, fault handling, COW, superpages)
  sched/          Scheduler, tasks, threads, SMP, topology
  ipc/            Ports, port sets, messages, ART (adaptive radix tree)
  syscall/        Syscall dispatch, handlers, personality routing
  cap/            Capability system (CNode, CDT, CapSet)
  io/             Userspace server framework, initramfs, name server, IRQ dispatch
  sync/           Spinlocks, futexes, turnstiles, RCU
  drivers/        virtio-blk, virtio-mmio

userlib/          Rust userspace library and binaries
  src/syscall.rs  Syscall wrappers
  bin/init.rs     Init process (test harness + server launcher)

musl-telix/       C userspace runtime (musl-compatible libc subset)
  arch/           Per-arch assembly (crt_start, syscall stubs, setjmp/longjmp)
  src/            C library sources (malloc, printf, string, socket, pthread, crypto, SSH)
  test/           C test binaries (shell, PostgreSQL stubs, SSH server, stress tests)

tools/            Build and run scripts
docs/             Design documents and roadmap
```

## OS Personality Layer

Telix includes infrastructure for running foreign OS binaries through a three-layer personality decomposition:

1. **ISA Variant** (per-trap): How did the CPU get here? (64-bit, 32-bit compat, Thumb, etc.)
2. **Syscall ABI** (per-task): Which registers hold syscall number, arguments, return value?
3. **Personality** (per-task): What do syscall numbers mean? (Linux, NT, Darwin, etc.)

The kernel routes non-native syscalls to userspace personality servers via IPC. A fast-path translation table allows common syscalls (read/write/close/mmap) to be translated in-kernel without IPC overhead.

Supported personality targets: Linux, Windows NT, Darwin, FreeBSD, Plan 9, Haiku, POSIX.

See [`docs/personality-architecture.md`](docs/personality-architecture.md) for the full design.

## License

This project is currently unlicensed. A license will be selected before any release.

## Author

Nadia Yvette Chambers ([NadiaYvette](https://github.com/NadiaYvette))
