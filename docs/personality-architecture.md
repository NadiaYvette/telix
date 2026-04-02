# Personality Server Architecture: Three-Layer Decomposition

## Overview

Telix supports multiple OS personalities (Linux, Windows/NT, Darwin, BeOS/Haiku, POSIX, Plan 9, native Telix) through a three-layer decomposition that cleanly separates instruction set detection, calling convention handling, and syscall semantics. This document describes the architecture with enough generality to handle all target personalities, 32-bit/64-bit process compatibility, and ISA variants like ARM Thumb and MIPS N64/O32/N32.

---

## Three-Layer Decomposition

```
Layer 3: Personality    (per-task)     What does syscall nr N mean?
Layer 2: Syscall ABI    (per-task)     Which registers hold nr, args, return?
Layer 1: ISA Variant    (per-trap)     How did the CPU get here? (32/64, Thumb, etc.)
```

These compose: a 32-bit Linux ARM process on aarch64 hardware is ISA=AArch32 + ABI=EABI + Personality=Linux. A 64-bit Windows process on x86_64 is ISA=x86_64 + ABI=Win64 + Personality=NT. They are orthogonal but the kernel needs all three to correctly extract a syscall and route it.

---

## Layer 1: ISA Variant (per-trap, hardware-detected)

The CPU tells you which instruction set the trap came from. This is not stored anywhere — it is read from exception state at trap time:

| Arch | How detected | Variants |
|------|-------------|----------|
| aarch64 | `ESR_EL1.IL` / `PSTATE.nRW` | AArch64, AArch32 (ARM), AArch32 (Thumb) |
| x86_64 | CS selector | Long mode (64-bit), Compat mode (32-bit), maybe 16-bit |
| mips64 | `Status.KSU` + `Status.UX/SX` | N64, N32, O32 |
| riscv64 | N/A (no 32-bit compat mode) | rv64 only |
| loongarch64 | `CSR.MISC` LA32 bit | LA64, LA32 |

The ISA variant determines the **trap mechanism** (which instruction caused entry) and constrains which ABIs are valid. Thumb vs ARM does not change the syscall ABI (both use `svc` with r7/r0-r5), but it matters for return address fixup and single-step behavior (relevant for tracing/debugging).

---

## Layer 2: Syscall ABI (per-task, set at exec)

The ABI determines register extraction — where the syscall number lives, where arguments are, how to write the return value. This is a (personality, architecture, bitness) tuple collapsed into a small enum:

```rust
#[repr(u8)]
pub enum SyscallAbi {
    // Native Telix (current behavior, all arches)
    TelixNative = 0,

    // Linux ABIs (one per arch x bitness)
    LinuxAarch64   = 1,   // nr=x8, args=x0-x5, ret=x0
    LinuxAarch32   = 2,   // nr=r7, args=r0-r5, ret=r0
    LinuxX86_64    = 3,   // nr=rax, args=rdi/rsi/rdx/r10/r8/r9, ret=rax
    LinuxI386      = 4,   // nr=eax, args=ebx/ecx/edx/esi/edi/ebp, ret=eax
    LinuxRv64      = 5,   // nr=a7, args=a0-a5, ret=a0
    LinuxMipsN64   = 6,   // nr=v0 (5000+), args=a0-a5, ret=v0
    LinuxMipsO32   = 7,   // nr=v0 (4000+), args=a0-a3 (+stack), ret=v0
    LinuxMipsN32   = 8,   // nr=v0 (6000+), args=a0-a5, ret=v0
    LinuxLa64      = 9,   // nr=a7, args=a0-a5, ret=a0

    // Windows NT ABIs
    NtX86_64       = 16,  // nr=rax, args=rcx/rdx/r8/r9 (+stack), ret=rax
    NtAarch64      = 17,  // nr=x8(?), args=x0-x7, ret=x0 (Windows ARM64)
    NtI386         = 18,  // nr=eax, args on stack (stdcall), ret=eax

    // Darwin ABIs
    DarwinX86_64   = 32,  // nr=rax (class in high bits), args=rdi/rsi/rdx/r10/r8/r9
    DarwinAarch64  = 33,  // nr=x16, args=x0-x5, ret=x0 (carry=error)

    // Other personalities
    Plan9Amd64     = 48,
    HaikuX86_64    = 64,
}
```

Each ABI variant maps to a concrete implementation of:

```rust
trait AbiOps {
    fn extract_nr(frame: &TrapFrame) -> u64;
    fn extract_arg(frame: &TrapFrame, n: usize) -> u64;
    fn set_return(frame: &mut TrapFrame, val: u64);
    fn set_error(frame: &mut TrapFrame, errno: u64);
    fn arg_width() -> u8;  // 32 or 64 for sign/zero extension
}
```

The key observation: the existing `trapframe.rs` functions (`syscall_nr`, `syscall_arg`, `set_return`) are already ABI implementations — they are just hardcoded to one ABI per architecture. The refactor is to make them dynamic based on a per-task field.

---

## Layer 3: Personality (per-task, set at exec)

The personality determines **what syscall numbers mean**. Linux `open` is nr 2 (x86_64) or 56 (aarch64). Darwin `open` is nr 5 (but in the BSD syscall class). NT `NtOpenFile` is nr 0x33. The personality translates between these foreign syscall semantics and Telix's native operations.

```rust
#[repr(u8)]
pub enum PersonalityId {
    TelixNative = 0,  // Direct kernel dispatch (current behavior)
    Posix       = 1,  // Minimal POSIX.1 without OS-specific extensions
    Linux       = 2,
    Darwin      = 3,
    WindowsNt   = 4,
    FreeBsd     = 5,
    Plan9       = 6,
    Haiku       = 7,
}
```

---

## Kernel-Side Routing

The kernel changes are deliberately minimal. The kernel does not implement any foreign personality — it just **routes**:

```
trap entry (arch-specific)
    |
    v
detect ISA variant from hardware state
    |
    v
look up task's SyscallAbi + PersonalityId
    |
    +-- PersonalityId::TelixNative --> extract via ABI, dispatch(frame) [current path]
    |
    +-- anything else --> extract via ABI, package into IPC message,
                          forward to personality server, park thread
```

Concretely, the Task struct gains three fields:

```rust
pub struct Task {
    // ... existing fields ...
    pub personality: PersonalityId,    // Set at exec(), inherited on fork()
    pub syscall_abi: SyscallAbi,       // Set at exec(), derived from ELF + personality + arch
    pub personality_port: u64,         // Port of the personality server handling this task
}
```

The kernel's exec path detects personality from ELF metadata:
- `EI_OSABI` in ELF header (Linux, FreeBSD, etc.)
- `PT_NOTE` sections (GNU ABI tag, Go buildid, etc.)
- NT PE headers (for Windows binaries — different executable format entirely)
- Explicit `personality_set()` syscall (like Linux's `personality()`)

---

## Fast-Path Optimization

The concern with pure IPC forwarding is performance: Firefox does thousands of syscalls/second, and each one round-tripping through a personality server is expensive. The solution is a **registered fast-path table**:

The personality server, at startup, registers a translation table with the kernel:

```rust
/// Registered by personality server via SYS_PERSONALITY_REGISTER
struct FastPathEntry {
    foreign_nr: u32,          // e.g., Linux __NR_read = 0
    native_nr: u32,           // e.g., Telix SYS_RECV = 4
    arg_mapping: [u8; 6],     // How to remap args (identity, swap, constant, etc.)
    flags: u32,               // FD translation needed? errno translation? etc.
}
```

Simple syscalls like read/write/close/mmap get translated in-kernel in O(1) via table lookup — no IPC. Complex syscalls (clone, execve, ioctl, ptrace) go to the personality server via IPC. This gives:

- **~90% of syscalls** (read, write, mmap, close, etc.): translated in-kernel, same cost as native
- **~10% of syscalls** (fork, exec, signal-related, ioctl): IPC to personality server, slower but infrequent

---

## Personality Server Architecture (Userspace)

Each personality server is a normal Telix userspace process:

```
+--------------------------------------------------+
|         Personality Server (e.g., Linux)          |
|                                                   |
|  +----------+  +----------+  +----------------+  |
|  | Syscall  |  | FD Table |  | Signal         |  |
|  | Handlers |  | Manager  |  | Translator     |  |
|  | (complex |  | (Linux   |  | (sigaction ->  |  |
|  |  subset) |  |  FD->port)|  |  Telix sigs)  |  |
|  +----------+  +----------+  +----------------+  |
|  +----------+  +----------+  +----------------+  |
|  | /proc    |  | /sys     |  | Futex/Thread   |  |
|  | Emulator |  | Emulator |  | Compat         |  |
|  +----------+  +----------+  +----------------+  |
+--------------------------------------------------+
```

The server receives forwarded syscall messages from the kernel, performs the translation, invokes Telix native operations, and resumes the client thread. It maintains per-client state:

- **FD table**: Maps Linux file descriptors to Telix ports/handles
- **Signal state**: Linux sigaction table, pending signals, signal masks
- **Process relationships**: PID-to-TaskId mapping, process groups, sessions
- **procfs/sysfs**: Synthesized responses for `/proc/self/maps`, etc.

---

## 32-bit / 64-bit Interaction Examples

### 32-bit Linux ARM binary on aarch64 Telix

1. exec() detects: ELF `e_machine=EM_ARM`, `EI_CLASS=ELFCLASS32`, `EI_OSABI=ELFOSABI_LINUX`
2. Kernel sets: `task.personality = Linux`, `task.syscall_abi = LinuxAarch32`
3. Kernel configures: PSTATE to allow AArch32 execution, 32-bit address space
4. At syscall: hardware traps with `ESR_EL1` indicating AArch32 SVC
5. Kernel: extracts nr from r7 (not x8), args from r0-r5 (sign-extended to 64-bit)
6. Routes through Linux personality fast-path or server

### MIPS O32 binary on MIPS64 Telix

1. exec() detects: ELF `e_machine=EM_MIPS`, `EI_CLASS=ELFCLASS32`, `e_flags` with O32 ABI
2. Kernel sets: `task.syscall_abi = LinuxMipsO32`
3. At syscall: nr in v0 is 4000-range (O32 numbering), args a0-a3 only (rest on stack)
4. ABI layer knows to read 4 stack args for 6+ arg syscalls, zero-extend from 32-bit

### Win64 binary on x86_64 Telix

1. exec() detects: PE/COFF header (not ELF at all)
2. Kernel sets: `task.personality = WindowsNt`, `task.syscall_abi = NtX86_64`
3. At syscall: nr in rax, but args in rcx/rdx/r8/r9 (NOT rdi/rsi like Linux)
4. Routes to NT personality server

---

## Darwin: Mach Traps + BSD Syscalls

Darwin has **two syscall interfaces**: BSD syscalls (positive numbers via `syscall`) and Mach traps (negative numbers via the same instruction). The personality server handles both — the kernel just sees a syscall instruction with a number, extracts it per the ABI, and forwards.

Darwin also has the **commpage** (shared read-only memory at a fixed address with fast-path kernel data). The Darwin personality server can map a synthetic commpage into client processes via Telix's grant mechanism.

---

## Windows (NT) Specifics

NT does not use ELF. The kernel's exec path needs to detect PE/COFF headers and route to the NT personality server for loading. The NT personality server handles:

- PE loading (sections, imports, relocations)
- The PEB/TEB (Process/Thread Environment Block) — allocated in client address space
- NT object namespace (`\Device\HarddiskVolume1` etc.)
- Registry emulation (minimal, from hive files)
- Win32 subsystem messages (csrss.exe equivalent)

This is the Wine model. Wine's `ntdll.dll` reimplementation is the core of the NT personality, with Telix-native I/O underneath instead of Linux syscalls.

---

## Implementation Plan

### Kernel-side (foundation for all personalities)

1. **Add fields to Task**: `personality: u8`, `syscall_abi: u8`, `personality_port: u64`
2. **Refactor `trapframe.rs`**: Make `syscall_nr`/`syscall_arg`/`set_return` dispatch on `syscall_abi` instead of `cfg(target_arch)` alone
3. **Add personality routing in `dispatch()`**: Before the native match, check personality — if non-native, forward via IPC
4. **Add `SYS_PERSONALITY_REGISTER`**: Lets a personality server claim a personality ID and register its fast-path table
5. **Add `SYS_PERSONALITY_SET`**: Lets exec() or a privileged process set a task's personality
6. **ELF exec detection**: Read `EI_OSABI` and set personality + ABI at exec time

This is ~200-300 lines of kernel code and establishes the framework for all future personalities.

### Linux personality server (first personality)

The Linux personality server is a pure userspace project that grows incrementally: start with `read`/`write`/`open`/`close`/`mmap`, add syscalls as LTP tests demand them. The fast-path table handles the common cases in-kernel; the server handles the long tail.

### Future personalities

Each additional personality is a new userspace server. The kernel infrastructure is personality-agnostic — the same routing, fast-path, and ABI machinery serves all of them.
