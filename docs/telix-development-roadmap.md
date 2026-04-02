# Telix Microkernel Development Roadmap

## Document Purpose

This document is a structured development roadmap for **Telix**, a from-scratch microkernel-based operating system. It is intended to be loaded as context into Claude Opus sessions within the development environment to provide continuity, architectural awareness, and task-level guidance across sessions.

---

## 1. Project Identity & Architecture Summary

### 1.1 Naming

- **Primary name:** Telix (from Latin *tela*, web/fabric/warp)
- **Reserve names:** Tessix, Nitix, Weft

### 1.2 Core Architectural Commitments

| Aspect | Decision |
|--------|----------|
| Structure | Microkernel, L4/seL4-style IPC |
| Process model | Mach-style task/thread, M:N threading with scheduler activations |
| Security | seL4-derived capability-based security |
| I/O architecture | Fully asynchronous, message-passing IPC; no synchronous Unix VFS call stack |
| VM subsystem | Extent-based (no per-page struct array); B+ trees of intervals or adaptive radix trees |
| Page size | Configurable via `PAGE_MMUSHIFT`/`PAGE_MMUCOUNT`; subpage superpages by construction |
| Implementation language | Rust |
| Primary target | ARM64 (secondary: x86-64, RISC-V, LoongArch64, MIPS64) |
| Development environment | QEMU-based; host is x86-64 Fedora |
| Architecture support goal | All 64-bit QEMU system targets; 32-bit as stretch |

### 1.3 I/O Architecture — Critical Context for All Subsystem Work

Telix's I/O and VFS layers are **message-passing-based and fully asynchronous**, resembling networking APIs more than traditional Unix VFS. Key implications:

- **No synchronous call stack.** Where Linux does `sb_bread()` and blocks, Telix sends a read-request message and receives a reply asynchronously.
- **Filesystem drivers are servers.** They sit in a message receive loop, dispatch on message type (open, read, write, readdir, stat, etc.), and send reply messages.
- **The page cache is separate.** Caching is handled by a dedicated cache server or the VFS layer, not by filesystem drivers directly.
- **Locking semantics change.** Single-threaded or actor-model message-processing servers may need no internal locking, or restructured concurrency around per-message processing.
- **Every synchronous block read in reference code becomes a continuation.** In Rust async/await, this maps to `.await` points, but control flow restructuring relative to C reference implementations is significant.

**When porting any subsystem from Linux reference code, the CPS (continuation-passing style) transformation of synchronous I/O paths is the central engineering challenge.**

---

## 2. Filesystem Implementation Roadmap

### 2.1 Feasibility Assessment (Legal/IP & Documentation)

Filesystems are ranked by combined legal safety and documentation quality for independent implementation.

#### Tier 1 — Fully Implementable (Read-Write)

**btrfs**
- License: GPL (kernel code); on-disk format freely documented
- Patents: None known; developed by Oracle/Chris Mason, contributed to kernel
- Documentation: Kernel source, btrfs wiki, `btrfs-progs` source
- Strategy: Clean-room Rust implementation from documented on-disk format
- Host tooling: `mkfs.btrfs`, `btrfs check` available in Fedora repos; work on image files directly

**ZFS (via OpenZFS)**
- License: CDDL (weak copyleft; file-level, not project-level)
- Patents: Oracle holds patents; CDDL provides patent grant to CDDL users. Since Telix is not GPL, CDDL/GPL incompatibility is irrelevant
- Documentation: 2006 on-disk specification draft, full OpenZFS source, extensive community docs
- Strategy: Port OpenZFS code (respecting CDDL per-file) or clean-room from spec + source study
- Host tooling: Full OpenZFS userspace stack (`zpool`, `zfs`, `zdb`) available on Fedora

**NTFS**
- License: Proprietary format, but no known patents
- Documentation: Russon/Fledel NTFS Documentation (reverse-engineered), Microsoft Open Specifications ([MS-FSCC], [MS-FSA]), Windows Internals books, Paragon's GPL NTFS3 driver source, NTFS-3G source
- Strategy: Clean-room Rust implementation from published documentation; multiple reference implementations available for cross-validation
- Host tooling: `mkntfs`, `ntfsfix`, `ntfsinfo` etc. from `ntfs-3g` package in Fedora repos
- Note: Highest interop value — most likely filesystem on removable media or dual-boot disks. On-disk format frozen since NTFS 3.1 (Windows XP era)

#### Tier 2 — Implementable with Caveats

**bcachefs**
- License: GPL-2.0
- Patents: None known (individual developer)
- Documentation: Source code, ~100-page "Principles of Operation" document (as of v1.37)
- Caveats: On-disk format has been a moving target; ejected from Linux kernel (6.18+), now externally maintained; uncertain long-term stability
- Strategy: Defer unless format stabilizes; if pursued, clean-room from PoO docs + source
- Host tooling: `bcachefs-tools` (format, fsck) available but version-coupled to kernel

#### Tier 3 — Partial / Read-Only Feasible

**APFS**
- License: Proprietary; Apple published partial spec (September 2018) covering read-only access to unencrypted, non-Fusion volumes
- Patents: Almost certainly held by Apple; no patent grant of any kind
- Documentation: Apple File System Reference PDF (on-disk structures), libfsapfs (LGPL, reverse-engineered)
- Strategy: Read-only driver from published spec is feasible. Read-write carries substantial patent risk
- Host tooling: No Linux creation tools; `apfs-fuse` (read-only), libfsapfs (read-only parsing)

#### Tier 4 — Avoid

**ReFS**
- License: Proprietary; internal structures officially undocumented by Microsoft
- Patents: Held by Microsoft; no patent grant
- Documentation: Forensic reverse-engineering papers only; libfsrefs (experimental, v1 only)
- Strategy: Not recommended unless specific interop need arises
- Host tooling: None on Linux

### 2.2 Implementation Sequencing

#### Phase 1: Bootstrap (use existing host tools for image creation)

1. Write Telix VFS message protocol specification (analogous to 9P / QNX resource manager messages)
2. Implement NTFS read-only driver as first filesystem target
   - Highest interop value, frozen on-disk format, extensive documentation
   - Core work: MFT parsing, attribute reading, index B-tree traversal, runlist decoding
   - All metadata reads become async message exchanges with block I/O server
3. Validate against `mkntfs`-created images mounted in QEMU
4. Extend to NTFS read-write (journaling, bitmap updates, MFT allocation)

#### Phase 2: COW Filesystem

5. Implement btrfs read-only, then read-write
   - More complex due to COW transaction model; transaction commit semantics must be carefully mapped to async I/O ordering
6. Implement ZFS support (port from OpenZFS under CDDL or clean-room)

#### Phase 3: Native Rust Tooling

7. Write `mkfs` / `fsck` equivalents in Rust for each supported filesystem
   - Share on-disk structure code between host tools and Telix drivers
   - Host tools use `File::write_all()`; Telix drivers use async block I/O messages
   - Validation loop: create image with Rust tool → mount with Linux host tool → verify

### 2.3 LLM-Assisted Development Guidance

**What Claude Opus handles well (~60-70% of work):**
- Data structure parsing and construction (MFT records, B-tree nodes, superblocks)
- Message dispatch scaffolding
- Basic async I/O path transformations (synchronous C → async Rust)
- `mkfs` tooling (deterministic, testable, no concurrency)

**What requires human expertise (~30-40%):**
- Concurrency correctness in async execution model
- Transaction semantics preservation (especially COW filesystems)
- Subtle invariants from synchronous-assumption code that break under async execution
- Error propagation in CPS-transformed code paths

---

## 3. Networking & Transport Roadmap

### 3.1 Protocol Implementation Priority

#### Priority 1 — Homa Transport (Best architectural fit)

- **Why first:** Homa is message-oriented, connectionless, receiver-driven — maps directly to Telix's IPC model
- **Reference:** Ousterhout's 2018 SIGCOMM paper + Linux kernel module (~10K lines)
- **Architecture:** First-class native transport; local IPC and remote Homa use same message abstractions
- **Key implementation details:** Unscheduled bytes, grant mechanism (maps to IPC flow control), priority assignment, overcommitment handling
- **QEMU testing:** No special hardware needed; standard virtio-net between two Telix instances
- **Barrier:** Low-moderate

#### Priority 2 — QUIC

- **Reference implementation:** Quinn (Rust, runtime-agnostic `quinn-proto` core)
- **Architecture:** Userspace library or network stack server component
- **Porting strategy:** Connect `quinn-proto`'s I/O interface to Telix UDP server's message interface; `quinn-proto` operates on "here are bytes I received, give me bytes to send" callbacks
- **QEMU testing:** No special hardware; runs over UDP via virtio-net
- **Performance dependencies:** GSO/GRO, sendmmsg/recvmmsg batching, zero-copy paths (deferred optimization)
- **Barrier:** Low-moderate for basic functionality; moderate for production performance

### 3.2 eBPF & XDP

#### eBPF Runtime

- **Architecture in Telix:** Sandboxed execution engine for packet filters, tracing probes, and policy logic
- **Motivation differs from Linux:** Not needed to avoid user/kernel boundary (servers are already separate); valuable for ecosystem compatibility (bpftrace, Cilium, Katran, Falco emit BPF bytecode)
- **Implementation components:**
  1. BPF bytecode verifier
  2. JIT compiler for ARM64 and x86-64
  3. BPF map infrastructure (hash maps, array maps, per-CPU maps)
  4. Attachment point design: **message interposition** — BPF programs sit between servers and inspect/modify/drop messages
- **Reference implementations:** uBPF, rbpf (Rust eBPF VM)
- **QEMU testing:** Fully software; no special hardware needed
- **Barrier:** Moderate (well-understood VM, but novel attachment-point design)

#### XDP

- **Architecture in Telix:** BPF programs run in NIC driver server's receive path, before packets become messages to network stack server
- **Critical design constraint:** BPF runtime must be a library linked into NIC driver server, NOT a separate service (preserves fast-path performance)
- **Actions map to:** drop message, pass message to network stack, redirect/bounce
- **QEMU testing:** Fully functional against virtio-net (can't test NIC-offloaded XDP performance)
- **Barrier:** Moderate

### 3.3 io_uring Compatibility

- **Key insight:** Telix's native I/O model already IS what io_uring approximates
- **Telix native:** Process sends I/O request message → receives completion message (already async, already batched)
- **io_uring compat shim:** SQE ring → batched message submission; CQE ring → batched completion receive
- **Scope:** ~60 opcodes for full Linux compatibility; core ring mechanism is straightforward
- **Decision point:** Full io_uring API compat (for Linux app porting) vs. native Telix IPC only
- **QEMU testing:** No special hardware; pure software interface
- **Barrier:** Low-moderate

---

## 4. SmartNIC & DPU Offloading Roadmap

### 4.1 Current QEMU Simulation Status

**QEMU has NO SmartNIC/DPU emulation.** No device model exists for programmable NICs with flow tables, match-action pipelines, embedded processors, or offload control interfaces (devlink, switchdev, representor ports, TC flower callbacks).

### 4.2 Phased Approach

#### Phase 1 — Software Simulation (No QEMU Patches)

Develop and test all offload protocol logic in pure software:

1. Design offload message protocol: network stack server → NIC driver server messages for "offload this flow", confirmations, statistics, miss notifications
2. Implement software flow table in NIC driver server (exact-match + wildcard-match)
3. Test against standard virtio-net in QEMU
4. Multi-process DPU simulation: one process = "host", another = "DPU", communicate via Unix domain sockets simulating PCIe control channel

#### Phase 2 — Custom Virtio Offload Device (Small QEMU Extension)

Estimated effort: 2-4 weeks focused work.

1. Define custom virtio device type for flow offload programming
2. Implement QEMU backend: software flow table, matching against packets in virtio-net path, direct delivery (simulating HW offload) vs. guest forwarding (simulating miss)
3. Implement Telix-side driver for custom virtio offload device
4. This tests: offload control path correctness, basic data path behavior, protocol design

**Does NOT test:** Vendor-specific firmware interactions, PCIe BAR layout, register-level hardware compatibility, real performance characteristics.

#### Phase 3 — Real Hardware Validation

Options for obtaining hardware:
- **CloudLab:** Free access to BlueField-2 DPU nodes for researchers (Clemson facility)
- **Used hardware:** ConnectX-6 Dx available affordably on secondary market as datacenters refresh to ConnectX-7
- **Target vendors:** NVIDIA BlueField (best documented via DOCA SDK), Intel E810 (ice driver, IPU), AMD Pensando

### 4.3 Microkernel Advantage

Telix's message-passing architecture makes the simulation boundary **cleaner** than in a monolithic kernel:
- In Linux, SmartNIC offload is entangled with internal kernel structures (`net_device`, TC subsystem, `ndo_setup_tc`, switchdev)
- In Telix, the offload interface is just another message protocol between servers
- Swapping "real NIC server" for "simulated NIC server" preserves the same message interface
- This is the microkernel advantage manifesting as practical testability

---

## 5. Cross-Cutting Concerns

### 5.1 Current Architecture Test Results (2026-04-01)

| Architecture | Passed | Failed | Skipped | Notable Issues |
|-------------|--------|--------|---------|----------------|
| x86_64 | 105 | 0 | 0 | Clean; reference platform |
| aarch64 | 105 | 0 | 0 | Clean; primary development target |
| riscv64 | 105 | 0 | 0 | Clean |
| loongarch64 | 88 | 3 | 7 | Failures are missing C cross-binaries only (Phase 66/72/74); remaining phases not yet reached (timeout). `#[inline(never)]` on `send()` works around LLVM release codegen bug; `ibar` after `tlbfill`/`invtlb` fixes intermittent INE. |
| mips64el | ~10 | crashes | — | Crashes ~Phase 12; preexisting TLB/stack issues partially fixed but intermittent faults remain |

### 5.2 Development Environment

| Component | Tool/Platform |
|-----------|---------------|
| Host OS | Fedora x86-64 |
| Target emulation | QEMU (ARM64 primary, x86-64 secondary) |
| Language | Rust |
| Filesystem image creation | Existing Linux host tools (Phase 1), native Rust tools (Phase 3) |
| Network testing | QEMU virtio-net, multiple Telix instances |
| Source control | GitHub (NadiaYvette) |

### 5.3 The Async Impedance Mismatch — Universal Porting Pattern

When porting any subsystem from Linux reference code to Telix:

1. **Identify all synchronous I/O points** in the reference code (`sb_bread()`, `submit_bio()`, `wait_on_buffer()`, etc.)
2. **Transform each to async message + await** — every function touching disk becomes `async fn`; this propagates up the call stack
3. **Invert the VFS-facing interface** — instead of kernel calling filesystem via function pointers, filesystem server receives messages and dispatches
4. **Separate page cache concerns** — page cache interaction (`readpage`, `writepage`, `readahead`) maps to cache server messages, not direct page cache manipulation
5. **Simplify or restructure locking** — message-processing servers may eliminate internal locking entirely if single-threaded, or use structured concurrency with clear ownership

### 5.4 Testing Strategy

| Layer | Method |
|-------|--------|
| Filesystem on-disk correctness | Create image with Telix tools → mount with Linux host tools (and vice versa) |
| Filesystem driver correctness | Create image with Linux host tools → mount in Telix under QEMU → verify reads/writes |
| Network protocol correctness | Two QEMU instances running Telix, connected via virtio-net |
| eBPF/XDP correctness | Pure software testing in Telix under QEMU with virtio-net |
| SmartNIC offload protocol | Phase 1: multi-process simulation; Phase 2: custom virtio device |
| Performance | Deferred to real hardware for networking; QEMU for functional regression |

### 5.5 Relationship to Frankenstein/Organ Bank

Telix is a separate but complementary project to Nadia's polyglot compiler work (Frankenstein/Organ Bank). There is no direct code dependency, but shared interests include:
- Rust toolchain and runtime considerations
- Potential for Telix to serve as a native execution target for Frankenstein-compiled binaries
- Shared infrastructure around build systems and development tooling

---

### 5.6 Session Usage Guide for Claude Opus

#### When Starting a New Session

Load this document as context. Then specify which roadmap area you're working on. Example prompts:

- "I'm working on Phase 1 of the filesystem roadmap — implementing the VFS message protocol. Here's my current draft of the message types..."
- "I'm implementing the NTFS MFT parser in Rust. Here's the current code for attribute header parsing..."
- "I'm designing the eBPF attachment point model for message interposition. Let's work through the API..."
- "I'm writing the custom virtio offload device for QEMU Phase 2. Here's the device model skeleton..."

#### Key Reminders for Claude Opus During Development

1. **All I/O is async message-passing.** Never produce synchronous blocking I/O code for Telix components. Every disk or network operation is a message send + async reply.
2. **Filesystem drivers are servers.** They receive request messages and send reply messages. They do not register callbacks with a VFS layer.
3. **Reference code is C/Linux.** When consulting Linux kernel source as reference, the translation to Rust + async + message-passing is the core task, not a minor adaptation.
4. **Existing host tools are the first validation oracle.** `mkfs.btrfs`, `mkntfs`, `zpool create` on Fedora produce reference images. Telix drivers must read these correctly.
5. **Test on QEMU ARM64 first** (primary target), x86-64 second.
6. **CDDL files stay CDDL.** If using OpenZFS code, files under CDDL remain CDDL-licensed. This is fine since Telix is not GPL.
7. **No known NTFS patents.** Safe for clean-room implementation.
8. **bcachefs format is unstable.** Do not invest heavily until format settles.
9. **SmartNIC work uses software simulation first.** Do not design against specific hardware registers until real hardware is available.
10. **Homa is the natural first network transport** due to its message-oriented, receiver-driven design aligning with Telix's IPC model.

---

## 6. Boot-Time Configurable PAGE_MMUSHIFT

### 6.1 Motivation

This is the **highest-priority infrastructure change** because it accelerates all subsequent development. Currently, `PAGE_SIZE` (the allocation page size, a multiple of the 4 KiB MMU page) is a compile-time constant selected by cargo feature flags (`page_size_16k`, `page_size_64k`, etc.). Every page-size configuration requires a separate kernel build. This means:

- Benchmarking page-size effects requires N builds and N boot cycles
- CI/CD must build and test every configuration separately
- Exploring non-power-of-two or unusual page sizes requires code changes
- The design doc's "configurable PAGE_MMUSHIFT" contribution claim is weakened by "configurable at compile time only"

Making `PAGE_MMUSHIFT` a boot-time parameter (selected via kernel command line, device tree, or relocation processing) transforms it into a runtime knob that strengthens the research contribution and speeds up all experiments.

### 6.2 Current State

```
MMUPAGE_SIZE = 4096              (fixed, hardware)
PAGE_SIZE    = MMUPAGE_SIZE << PAGE_MMUSHIFT
PAGE_MMUSHIFT = compile-time     (2 → 16K, 4 → 64K, 5 → 128K, 6 → 256K)
```

Constants in `kernel/src/mm/page.rs` are used pervasively: physical allocator, slab allocator, VMA management, fault handler, COW, superpage promotion, ELF loader, and all arch-specific HAT code.

### 6.3 Design: Relocation-Based Configuration

The key insight: **most uses of PAGE_SIZE are shifts, masks, and loop bounds** — they can be computed from a single runtime variable without performance loss on modern CPUs (shift by variable vs. shift by immediate is ~1 cycle difference, invisible next to TLB miss costs).

#### Phase 1: Convert constants to statics

1. Replace `pub const PAGE_SIZE` / `PAGE_SHIFT` / `PAGE_MMUCOUNT` / `PAGE_MMUSHIFT` with `pub static` variables initialized at boot
2. Audit all uses — most are in cold paths (fault handler, allocator init, VMA operations). Hot-path uses (TLB refill) don't reference PAGE_SIZE
3. `MMUPAGE_SIZE` stays `const` (hardware-fixed)
4. `SUPERPAGE_LEVELS` becomes a static slice selected at boot (or computed from PAGE_SIZE + arch constants)

#### Phase 2: Boot-time selection

1. **Kernel command line parsing:** Parse `page_mmushift=N` from the command line (passed by bootloader or QEMU `-append`)
2. **Device tree / ACPI:** Read from firmware tables where available
3. **Relocation processing:** For ELF-loaded kernels, a custom relocation type could patch PAGE_SIZE references at load time (eliminates the static-variable indirection for truly zero-cost runtime configuration)
4. **Default:** If no parameter specified, use `PAGE_MMUSHIFT=4` (64 KiB, current default)

#### Phase 3: Validation

1. Single kernel binary boots with `page_mmushift=2` through `page_mmushift=6`
2. Full test suite passes at each setting
3. Benchmark suite captures per-configuration performance data in one boot session (iterate over page sizes in userspace test)

### 6.4 Relocation-Patching Approach (Advanced)

For zero overhead: define a custom ELF relocation type `R_TELIX_PAGE_SHIFT` that patches immediate operands in shift/mask instructions at load time. The bootloader or early-boot code:

1. Reads desired PAGE_MMUSHIFT from command line
2. Walks the kernel's relocation table
3. Patches each `R_TELIX_PAGE_SHIFT` site with the concrete shift value

This gives the performance of compile-time constants with the flexibility of runtime configuration. The cost is a custom linker script and a small relocation-processing loop in early boot.

### 6.5 Kernel Command Line Infrastructure

Implementing `page_mmushift=N` requires general kernel command line parsing, which is independently useful:

- **QEMU:** `-append "page_mmushift=4 console=ttyS0 loglevel=7"`
- **Device tree:** `/chosen/bootargs` property
- **UEFI:** Command line from boot services
- **Malta (MIPS64):** YAMON bootloader passes args at fixed address

Parser: simple `key=value` tokenizer in early boot (before allocator init), storing results in a static `BootConfig` struct.

---

## 7. OS Personality Layer (Linux Compatibility & Beyond)

### 7.1 Concept

An **OS personality** is a translation layer that presents a specific OS's system call interface, process model, and behavioral semantics on top of Telix's native microkernel primitives. The primary target is a Linux personality testable with the **Linux Test Project (LTP)**, but the architecture should support future personalities for other operating systems.

### 7.2 Linux Personality

#### Goal

Pass a substantial subset of LTP test cases, demonstrating that Telix can run unmodified Linux binaries (ELF, dynamically linked against musl or glibc) with correct POSIX/Linux semantics.

#### Architecture

```
┌──────────────────────────────────────────────┐
│  Linux Binary (ELF, glibc/musl-linked)       │
├──────────────────────────────────────────────┤
│  Linux Personality Server (userspace)         │
│  ┌─────────────┬──────────┬────────────────┐ │
│  │ Syscall     │ /proc    │ Signal         │ │
│  │ Translation │ /sys     │ Semantics      │ │
│  │ (nr→msg)    │ Emulation│ Translation    │ │
│  └─────────────┴──────────┴────────────────┘ │
├──────────────────────────────────────────────┤
│  Telix Native Kernel (IPC, VM, scheduler)    │
└──────────────────────────────────────────────┘
```

- **Syscall interception:** Linux `syscall` instruction traps to kernel, which dispatches to the personality server via IPC. The personality server translates Linux syscall semantics to Telix native operations.
- **File descriptor table:** Maintained by personality server, mapping Linux FDs to Telix port/handle pairs.
- **Signal delivery:** Linux signal semantics (sigaction, sigprocmask, SA_RESTART, etc.) implemented in the personality server, translating to/from Telix's native signal mechanism.
- **Procfs/sysfs emulation:** The personality server synthesizes `/proc/self/maps`, `/proc/stat`, `/sys/...` responses that LTP tests check.
- **Personality-specific state:** Each process's personality is tracked; `fork()` inherits personality; `exec()` can switch personality based on ELF note or configuration.

#### Implementation Phases

1. **Syscall translation core:** Map the ~50 most common Linux syscalls (open, read, write, close, mmap, mprotect, brk, ioctl, fcntl, socket, clone, wait4, exit_group, etc.) to Telix IPC
2. **LTP smoke test:** Run LTP's `quickhit` subset; fix failures iteratively
3. **Signal fidelity:** Full sigaction/sigprocmask/sigaltstack/SA_RESTART semantics
4. **Thread semantics:** clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND) → Telix thread creation with shared resources
5. **Procfs:** Enough of `/proc` to satisfy LTP and common userspace (ps, top, etc.)
6. **Full LTP run:** Target 80%+ pass rate on LTP's syscall test suite

#### Testing with LTP

- Cross-compile LTP for each target architecture (LTP supports cross-compilation)
- Mount LTP test binaries via rootfs_srv or ext2 image
- Run `runltp` harness inside Telix under QEMU
- Parse LTP output for pass/fail/skip counts
- CI integration: track pass rate over time

### 7.3 Future Personality Stubs

The personality framework should be designed with extensibility for:

| Personality | Motivation | Complexity |
|-------------|-----------|------------|
| **Linux** | Primary target; LTP validation; run existing binaries | High (hundreds of syscalls, subtle semantics) |
| **FreeBSD** | Second-largest open-source syscall surface; validates personality abstraction | Medium (similar to Linux but different ioctl/socket/signal details) |
| **Windows (NT)** | Massive ecosystem value; WINE-style approach possible | Very high (NT object model, registry, Win32 subsystem) |
| **macOS (Mach/BSD)** | Telix already uses Mach-style tasks; natural fit for Mach trap translation | Medium-high (Mach traps + BSD syscalls + IOKit) |
| **Plan 9** | Simplest personality; 9P maps almost directly to Telix IPC | Low (small syscall surface, everything-is-a-file) |
| **Bare POSIX** | Minimal POSIX.1-2024 compliance without Linux-specific extensions | Medium (subset of Linux personality) |

Each personality is a separate userspace server. Multiple personalities can coexist — different processes can use different personalities simultaneously.

---

## 8. Multi-Architecture Support

### 8.1 Current Status

| Architecture | Kernel | Userland | QEMU Machine | Test Status |
|-------------|--------|----------|--------------|-------------|
| aarch64 | Full | Full | virt | 105/105 pass |
| x86_64 | Full | Full | q35 | 105/105 pass |
| riscv64 | Full | Full | virt | 105/105 pass |
| loongarch64 | Full | Full (Rust) | virt | 88 pass, 3 fail (missing C bins), 7 skip |
| mips64el | Full | Full | malta | ~10 pass, crashes ~Phase 12 |

### 8.2 Expansion Plan — 64-bit Architectures

Priority order based on ecosystem relevance and Rust toolchain support:

#### Tier 1 — High Value (next targets)

**s390x (IBM Z / mainframe)**
- QEMU: `qemu-system-s390x -M s390-ccw-virtio`
- Rust target: `s390x-unknown-linux-gnu` (Tier 2 in rustc)
- Value: Only mainstream 64-bit big-endian target with active use; tests endianness assumptions throughout codebase
- Machine: z/Architecture with channel I/O, virtio-ccw transport (different from PCI)
- Barrier: Moderate — unique I/O model (channel subsystem), different interrupt architecture (SIE, program interrupts)

**ppc64 (POWER)**
- QEMU: `qemu-system-ppc64 -M pseries` (big-endian) or `-M powernv` (bare metal)
- Rust target: `powerpc64le-unknown-linux-gnu` (Tier 2), `powerpc64-unknown-linux-gnu`
- Value: Active server architecture; bi-endian; tests different page table formats (hash page table or radix)
- Barrier: Moderate — hypervisor-oriented (PAPR), hash page table is architecturally unique

**sparc64 (SPARC V9)**
- QEMU: `qemu-system-sparc64 -M sun4u`
- Rust target: `sparc64-unknown-linux-gnu` (Tier 2)
- Value: Register-window architecture tests calling convention assumptions; historically important
- Barrier: Moderate-high — register windows, TSO memory model, unique trap handling

#### Tier 2 — Educational / Completeness

**alpha (DEC Alpha)**
- QEMU: `qemu-system-alpha -M clipper`
- Rust target: None upstream (would need custom target JSON)
- Value: First 64-bit RISC; historically significant; very different from modern ISAs
- Barrier: High — no Rust target, weak QEMU support

**hppa (PA-RISC)**
- QEMU: `qemu-system-hppa -M hppa`
- Rust target: None upstream
- Value: Unusual architecture (upward-growing stack, unique TLB); educational
- Barrier: Very high — no Rust target, minimal tooling

### 8.3 Expansion Plan — 32-bit Architectures

Lower priority but demonstrates portability:

| Architecture | QEMU Machine | Rust Target | Notes |
|-------------|-------------|-------------|-------|
| arm (ARMv7) | `virt` | `armv7a-none-eabi` | Natural downport from aarch64 |
| riscv32 | `virt` | `riscv32imac-unknown-none-elf` | Natural downport from riscv64 |
| i386 | `q35` | `i686-unknown-none` | Legacy x86 |
| mipsel | `malta` | Custom JSON | 32-bit MIPS |
| m68k | `virt` | Custom JSON | ColdFire; unique architecture |
| sh4 | `r2d` | Custom JSON | SuperH; embedded focus |

### 8.4 Architecture Porting Checklist

For each new architecture, the following must be implemented:

1. **Target specification:** Custom JSON target spec in `targets/` or use upstream Rust target
2. **Boot assembly:** `boot.S` — entry point, stack setup, BSS clear, jump to Rust
3. **Exception vectors:** `vectors.S` — interrupt/trap/syscall entry, register save/restore
4. **Trap handler:** `trap.rs` — exception dispatch, timer interrupt, syscall routing
5. **MMU / HAT:** `mm.rs` — page table format, TLB management, PteFormat trait impl
6. **Serial output:** `serial.rs` — UART or equivalent for early boot console
7. **Linker script:** `linker.ld` — memory layout, section placement
8. **QEMU launch script:** `tools/run-qemu-<arch>.sh`
9. **Userland linker script:** `userlib/link-<arch>.ld`
10. **PCI / device discovery:** Architecture-specific device enumeration (if needed beyond virtio-mmio)
11. **Test validation:** All 105 test phases passing

---

## 9. Swap Subsystem

### 9.1 Architecture

Telix's WSCLOCK page reclamation already identifies pages to evict. Currently, evicted anonymous pages are simply discarded (and re-faulted as zero pages). Adding swap means:

1. **Swap map:** Track which swap slot holds each evicted page (per-object swap radix tree or per-aspace swap table)
2. **Swap-out path:** WSCLOCK selects victim → write page to swap device via block I/O server → record swap slot in PTE (not-present + swap-slot encoding)
3. **Swap-in path:** Page fault on swap PTE → read from swap device → install page → resume
4. **Swap device:** A block device (partition or file) managed by a userspace swap server, or direct kernel-managed swap for simplicity

### 9.2 Implementation Phases

1. **Swap PTE encoding:** Define not-present PTE format that encodes swap device + slot number (similar to Linux's `swp_entry_t`)
2. **Swap server (userspace):** Manages swap space allocation/deallocation, handles read/write requests via IPC
3. **WSCLOCK integration:** When reclaiming a dirty anonymous page, send it to swap server before freeing
4. **Fault handler integration:** Recognize swap PTEs, issue swap-in read, block faulting thread until I/O completes
5. **Swap-backed tmpfs:** tmpfs pages that exceed RAM are swapped out (makes rootfs_srv viable for larger workloads)

### 9.3 Testing

- Create a swap partition on the QEMU disk image
- Stress test: allocate more anonymous memory than physical RAM, verify correctness
- Measure swap throughput via virtio-blk

---

## 10. Graphical Desktop (Xwayland + GNOME + Firefox)

### 10.1 Goal

Boot Telix under QEMU with a graphical desktop environment — specifically Xwayland running under a Wayland compositor, with GNOME Shell and Firefox rendering to a QEMU display. This is the "screenshot milestone" that demonstrates Telix as a usable OS, not just a test harness.

### 10.2 Prerequisites

Before attempting a graphical desktop:

| Dependency | Status | Notes |
|-----------|--------|-------|
| Linux personality (syscall compat) | Planned (Section 7) | GNOME/Firefox are Linux binaries |
| Dynamic linker (ld-telix) | Working | Phase 66 passes |
| Shared libraries (musl libc) | Working | Phase 52 passes |
| VFS with writable root | Working | rootfs_srv |
| Framebuffer / GPU driver | Not started | virtio-gpu or bochs-display in QEMU |
| Input device driver | Not started | virtio-input (keyboard/mouse) |
| Unix domain sockets | Working | Phase 57 passes |
| Wayland protocol | Not started | Needs UDS + shared memory |
| X11 (Xwayland) | Not started | Runs on top of Wayland compositor |
| dbus | Not started | GNOME requires session bus |
| glib/GTK | Not started | Needs Linux personality |

### 10.3 Implementation Phases

#### Phase 1: Framebuffer console

1. Implement virtio-gpu driver (simple 2D framebuffer mode)
2. Implement virtio-input driver (keyboard + mouse events)
3. Render text console to framebuffer (fbcon equivalent)
4. Validate: QEMU shows text output in graphical window

#### Phase 2: Wayland compositor

1. Implement minimal Wayland compositor (wlroots-based or custom)
2. SHM buffer passing via Telix shared memory
3. Render client surfaces to virtio-gpu framebuffer
4. Input event routing from virtio-input → compositor → clients

#### Phase 3: Xwayland + toolkit apps

1. Run Xwayland (X11 server on Wayland) under Linux personality
2. Run simple X11 apps (xterm, xclock)
3. Run GTK apps (requires glib, dbus)

#### Phase 4: Full desktop

1. Run GNOME Shell (Mutter compositor in Xwayland mode initially)
2. Run Firefox
3. Capture screenshots for documentation / paper

### 10.4 QEMU Configuration

```bash
qemu-system-x86_64 \
    -M q35 -m 2G -smp 4 \
    -device virtio-gpu-pci \
    -device virtio-keyboard-pci \
    -device virtio-mouse-pci \
    -device virtio-net-pci,netdev=net0 \
    -netdev user,id=net0 \
    -drive file=telix-desktop.img,format=raw,if=virtio \
    -kernel target/x86_64-unknown-none/release/telix-kernel \
    -display gtk
```

---

## 11. Kernel Command Line & Boot Configuration

### 11.1 Command Line Parsing

Implement a generic kernel command line parser available before allocator init:

```
page_mmushift=4 console=ttyS0,115200 loglevel=7 swap=/dev/vda2
personality=linux root=/dev/vda1 rootfs=ext2 init=/sbin/init
```

#### Delivery Mechanisms

| Platform | Source |
|----------|--------|
| QEMU (all) | `-append "..."` passed to kernel entry |
| Device tree | `/chosen/bootargs` string property |
| UEFI | EFI_LOADED_IMAGE_PROTOCOL command line |
| MIPS64 Malta | YAMON environment at fixed memory address |
| Multiboot2 (x86) | Command line tag in boot information structure |

#### Parser Design

Simple tokenizer in `kernel/src/boot/cmdline.rs`:
- Split on whitespace
- Split each token on first `=`
- Store in fixed-size `BootConfig` struct with known keys
- Unknown keys stored in overflow array for personality-specific options

### 11.2 Boot-Time Configuration via Relocation

For configuration that must be resolved before any Rust code runs (like PAGE_MMUSHIFT), use the relocation-patching approach described in Section 6.4. The boot assembly:

1. Reads command line (architecture-specific)
2. Extracts `page_mmushift=N`
3. Walks the kernel's relocation table (embedded in the ELF)
4. Patches `R_TELIX_PAGE_SHIFT` relocations with the concrete value
5. Jumps to Rust `main()`

This means the Rust code sees PAGE_SIZE as a constant — no static-variable overhead — but the value was determined at boot time.

---

## 12. Development Velocity & Prioritized Roadmap

### 12.1 Priority Order

The following order maximizes development velocity by front-loading infrastructure that accelerates everything else:

| Priority | Item | Section | Rationale |
|----------|------|---------|-----------|
| **P0** | Boot-time PAGE_MMUSHIFT | 6 | Eliminates rebuild cycles for page-size experiments; strengthens research contribution |
| **P0** | Kernel command line parsing | 11 | Required for PAGE_MMUSHIFT; independently useful for all boot config |
| **P1** | Linux personality (core syscalls) | 7.2 | Unlocks LTP testing; prerequisite for running real-world binaries |
| **P1** | LTP integration | 7.2 | Quantitative correctness metric; drives bug discovery |
| **P2** | Swap subsystem | 9 | Enables workloads that exceed physical RAM |
| **P2** | NTFS read-only | 2.2 | First real filesystem; highest interop value |
| **P2** | Homa transport | 3.1 | Native network transport aligned with IPC model |
| **P3** | Additional architectures (s390x, ppc64) | 8.2 | Tests portability assumptions; big-endian validation |
| **P3** | QUIC (via quinn-proto) | 3.1 | Modern encrypted transport |
| **P3** | btrfs / ZFS | 2.2 | COW filesystems |
| **P4** | Framebuffer + virtio-gpu | 10.3 | First step toward graphical desktop |
| **P4** | eBPF runtime | 3.2 | Ecosystem compatibility |
| **P5** | Wayland compositor | 10.3 | Graphical applications |
| **P5** | SmartNIC simulation | 4.2 | Requires Phase 1 software flow tables |
| **P6** | Full GNOME + Firefox | 10.4 | Screenshot milestone; requires substantial Linux compat |
| **P6** | 32-bit architectures | 8.3 | Completeness |

### 12.2 How PAGE_MMUSHIFT Acceleration Works

With boot-time configurable PAGE_MMUSHIFT:

- **Before:** Test 4 page sizes × 5 architectures = 20 separate builds, 20 separate QEMU runs
- **After:** 5 architecture builds, each run tests all page sizes in one session
- **Benchmark suite** can sweep page sizes in a loop within a single boot
- **CI** builds one kernel per architecture, tests all page-size configurations
- **Research paper** data collection goes from hours to minutes

---

## 13. Driver Model

Telix drivers are userspace servers accessing hardware via capabilities and communicating through standard IPC. The full design is in [`docs/driver_model.md`](driver_model.md).

**Key points:**
- Hardware access via typed capabilities: MMIO regions, port I/O ranges, interrupt lines, DMA-capable buffers
- Device manager server handles lifecycle, driver matching, capability distribution, power state, hotplug
- Bus servers (PCI, Platform/Devicetree, USB) enumerate devices and create sub-device capabilities
- Layered composition: multi-layer driver stacks (e.g., USB HCI → USB bus → class driver) via message forwarding
- Phased introduction: Phase 1 (kernel primitives) → Phase 2 (bus enumeration) → Phase 3 (driver library) → Phase 4 (hotplug/power)
- Retrenchment strategies available if IPC overhead is unacceptable: polling, co-location, kernel migration

---

## 14. OS Personality Servers

Userspace servers that emulate other OS's syscall semantics atop Telix's native IPC. The full design is in [`docs/personality_servers.md`](personality_servers.md).

**Priority ordering:**
1. **POSIX** — Foundational; testable via Sortix os-test and LTP
2. **Linux syscall compat** — Highest practical value; LTP as validation target
3. **Plan 9** — Smallest surface; intellectually aligned with message-passing
4. **Haiku/BeOS** — Non-Unix personality with structured kit-based API
5. **BSD** — Incremental over POSIX (kqueue, jails, Capsicum)
6. **Windows/NT** — Highest ecosystem impact via Wine model
7. **Redox** — Small Rust-typed API; limited incremental value

**Cross-cutting:** Personalities are distinct from ABIs (calling conventions) and ISA variants (32-bit compat). Multiple personalities coexist — different processes can use different personalities simultaneously.

---

## 15. Tracing Infrastructure

Native tracing with kernel probe engine and userspace tracing server. The full design is in [`docs/tracing_infrastructure.md`](tracing_infrastructure.md).

**Architecture:**
- **Kernel-side:** Minimal per-architecture probe engine (~200 LoC/ISA) for breakpoint insertion, context capture, single-stepping
- **Userspace:** Tracing server handles filtering, aggregation, output formatting, script/policy language
- **Probe providers:** Syscall, IPC, scheduler, VM, and server-side probe points
- **Interaction with microkernel:** Probe events flow through standard IPC; subject to port capacity backpressure
- **Evaluation use:** IPC overhead attribution, server profiling, VM subsystem analysis for the paper

---

## 16. Network & Storage I/O Architecture

Unified I/O model decomposing network and storage stacks into layered servers. The full design is in [`docs/network_storage_io.md`](network_storage_io.md).

**Three standardized interface boundaries:**
1. **Block device interface** — between filesystem/application servers and block device drivers
2. **Transport interface** — between applications and transport protocols (TCP, UDP, SCTP, RDMA)
3. **Link/network interface** — between transport layer and link-layer drivers

**Key subsystems:**
- Network stack: NIC drivers → Ethernet server → IP server → TCP/UDP/SCTP/RDMA servers
- Storage-over-network: iSCSI, NVMe-oF, Fibre Channel, AoE as layered protocol servers
- Multipath I/O: distribution server with pluggable algorithms (round-robin, active/passive, queue-depth)
- Zero-copy: capability-threaded DMA buffers; simplified single-copy initial approach
- Protocol composition without cross-layer coupling

---

## 17. Graphics Architecture

Graphics stack from QEMU virtio-gpu through real hardware. The full design is in [`docs/graphics_architecture.md`](graphics_architecture.md).

**Phased approach:**
- **Phase A:** QEMU virtio-gpu — 2D framebuffer (A.1), VirGL OpenGL acceleration (A.2), Venus Vulkan (A.3)
- **Phase B:** Intel Iris Xe on real hardware via DRM compatibility layer
- **Phase C:** Discrete GPUs (AMD Radeon, NVIDIA) via same DRM compat approach

**Architecture:**
- Display server (KMS equivalent): CRTCs, encoders, connectors, planes, framebuffers
- GPU server: command buffer submission, synchronization, memory management
- DRM compatibility layer: translates Linux DRM ioctls to GPU/display server messages, enabling reuse of Mesa's existing drivers
- Software rendering fallback: LLVMpipe (OpenGL) and Lavapipe (Vulkan)
- Path: framebuffer console → Wayland compositor → Xwayland + GTK → GNOME Shell + Firefox

---

## 18. 32-bit Compatibility & Superpages

Analysis of how 32-bit process compat interacts with the VM superpage machinery. The full analysis is in [`docs/32bit_compat_superpages.md`](32bit_compat_superpages.md).

**Summary:** Minimal impact. PAGE_SIZE is system-wide (unaffected by process bitness). The existing per-memory-object alignment class mechanism already handles mapping heterogeneity across different page table formats. Per-architecture notes:
- **x86-64/i386:** 4K/2M/1G vs 4K/2M(PAE) — minimal impact
- **ARM64/AArch32:** Different superpage spectrums; 32-bit case easier than 64-bit
- **MIPS64:** Identical TLB/superpage behavior regardless of address width
- **RISC-V:** No native 32-bit execution mode on 64-bit; does not arise

**Recommendation:** Defer 32-bit compat to Phase 4+; keep PAGE_SIZE system-wide; implement per-page-table-format superpage size tables when needed.

---

## 19. Detailed Phase Roadmap (Phases 40–104)

The full phase-by-phase roadmap with dependencies is in [`docs/roadmap.md`](roadmap.md), organized into 9 streams:

| Stream | Phases | Scope |
|--------|--------|-------|
| A: Kernel Primitives | 40–50 | execve, signals, mprotect, process groups, timers, mmap, shm, FDs, creds, wait, rlimits |
| B: Userspace POSIX | 51–62 | VFS, musl, ext2-write, tmpfs, devfs, procfs, UDS, sockets, pipes, poll, flock, PTY |
| C: Application Infrastructure | 63–73 | Shell, coreutils, login, dynamic linker, eventfd, inotify, ASLR, syslog, locale, DNS |
| D: GHC Runtime | 74–78 | RTS threading, I/O manager, signals, memory management, cross-compiler bootstrap |
| E: PostgreSQL | 79–82 | Static build, initdb, single-user, full network server |
| F: Graphics | 83–90 | Framebuffer, input, DRM/KMS, Wayland, libwayland, Mesa, fonts, Cairo |
| G: Desktop | 91–97 | D-Bus, GLib/GTK 4, terminal, audio, accessibility, system services |
| H: Firefox | 98–101 | NSS/NSPR, Rust toolchain, Firefox build, multi-process |
| I: GNOME | 102–104 | Shell/Mutter, core apps, session startup |

---

## 20. Version History

| Date | Change |
|------|--------|
| 2026-04-01 | Integrated specialized design docs (driver model, personality servers, tracing, network/storage I/O, graphics, 32-bit compat) as Sections 13–18; added detailed phase roadmap cross-reference (Section 19); updated test results to current state (LoongArch64 88/3/7, RISC-V 105/105) |
| 2026-03-30 | Expanded roadmap: boot-time PAGE_MMUSHIFT, Linux personality + LTP, multi-architecture plan (s390x, ppc64, sparc64, 32-bit targets), swap subsystem, graphical desktop (Xwayland + GNOME + Firefox), kernel command line parsing, prioritized development order |
| 2026-03-30 | Initial roadmap created from extended design discussion covering filesystems (ZFS, btrfs, NTFS, bcachefs, APFS, ReFS), networking (eBPF, XDP, io_uring, Homa, QUIC), and SmartNIC/DPU offloading with QEMU simulation strategy |
