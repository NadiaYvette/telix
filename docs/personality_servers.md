# Personality Servers

## Overview

Telix's microkernel architecture and POSIX-emulation-in-userspace design naturally support **personality servers**: userspace servers that emulate the syscall semantics of other operating systems, allowing binaries or source-compatible programs from those systems to run on Telix. The native kernel interface (ports, messages, capabilities) is powerful enough to build arbitrary OS personality layers atop it, and the message-passing model means personality servers are structurally identical to any other Telix server.

This document surveys candidate OS personalities, assesses the availability of conformance tests or equivalent test infrastructure for each, and evaluates the feasibility of using AI coding assistance to generate compatibility tests where formal suites do not exist.

## Design Principles

Each personality server translates foreign syscall conventions into Telix's native message-passing operations. For example, a POSIX personality translates `open()` into a name server lookup and filesystem server connect, `read()` into a receive message on the resulting channel, and so on. The personality server may run as a library linked into the application (a libc shim) or as a standalone server that interposes on syscall traps, depending on whether source or binary compatibility is the goal.

Multiple personality servers can coexist. A system could simultaneously run POSIX applications, Linux binaries (via a Linux personality), and Haiku applications (via a BeOS personality), each using its own personality server, all communicating with the same underlying Telix servers for file I/O, networking, and memory management.

## Tier 1: POSIX

### Rationale

POSIX is the foundational personality. It is already planned as the primary compatibility surface, implemented as a userspace `libc` shim atop the native syscall interface. Every other Unix-derived personality (Linux, BSD, Plan 9 to some extent) builds on or extends POSIX semantics.

### Test Infrastructure

POSIX has the strongest conformance test ecosystem of any OS interface:

**Sortix os-test:** An actively maintained, ISC-licensed test suite for POSIX.1-2024. Runs across many operating systems (Linux, macOS, FreeBSD, illumos, Managarm, Redox) with comparative results published. This is the most practical starting point — it's up-to-date, cross-compilable, and already used by other research OSes for test-driven development.

**The Open Group VSX-PCTS:** The official POSIX conformance test suite, required for formal POSIX certification. Available with a free twelve-month license for open source projects. Uses the VSXgen/TET framework, which is complex to configure but represents the definitive conformance standard.

**Open POSIX Test Suite:** GPL-2 licensed, covers POSIX.1-2001. Includes conformance, functional, stress, and performance tests. Not maintained since ~2006, but still useful as a supplementary source. Originally developed by Intel and Qualcomm engineers.

**Linux Test Project (LTP):** While LTP is Linux-specific in many details, its POSIX-oriented tests (syscalls, filesystem semantics, signal handling) are broadly applicable and well-maintained.

### Assessment

Excellent test coverage. POSIX personality development can be fully test-driven from day one.

## Tier 2: Linux Syscall Compatibility

### Rationale

Linux binary compatibility is the most practically valuable personality after POSIX. It would allow running unmodified Linux binaries on Telix, dramatically expanding the set of available software. FreeBSD's Linuxulator demonstrates that this is achievable and that LTP provides an effective validation target.

### Test Infrastructure

**Linux Test Project (LTP):** Comprehensive regression and conformance suite maintained by IBM, Cisco, Fujitsu, SUSE, Red Hat, and others. Covers syscalls, filesystems, memory management, IPC, scheduling, networking, and more. FreeBSD already uses LTP to validate its Linux compatibility layer. LTP provides an excellent test-driven development target for a Linux personality.

**Linux-specific syscall tests:** Beyond LTP, the Linux kernel's own `tools/testing/selftests/` directory contains per-subsystem test suites for Linux-specific features (io_uring, eBPF, namespaces, cgroups, etc.). These are relevant for deep Linux compatibility but may be beyond the scope of initial work.

### Assessment

Excellent test coverage via LTP. A Linux personality is a substantial engineering effort (the Linux syscall surface is large and has many Linux-specific extensions beyond POSIX), but AI coding assistance can generate syscall translation stubs systematically from the well-documented Linux syscall table. FreeBSD's Linuxulator provides architectural precedent and a reference implementation for handling Linux-specific quirks.

## Tier 3: Windows/NT (via Wine Model)

### Rationale

Windows compatibility would be the highest-impact personality in terms of available software. The Wine project has already mapped the entire Windows API, implemented translations, and — critically — developed thousands of tests that document expected behavior. AI coding assistance makes this significantly more tractable than it would be for a manual effort, because the API is organized into relatively independent subsystems (kernel32, ntdll, user32, gdi32, advapi32, etc.) that can be generated in parallel.

### Win64 as the Primary Target

The native Windows personality should target **Win64** (the 64-bit Windows ABI, also called x64 on AMD64 and ARM64 Windows). Win64 is the native ABI on x86-64 and ARM64 — both of Telix's primary target architectures. It is also simpler than Win32 in several respects: a cleaner calling convention (Microsoft x64 ABI uses registers RCX, RDX, R8, R9 for the first four integer arguments, versus Win32's mix of stdcall, cdecl, and thiscall conventions), no segmented memory model remnants, and no thunking complications.

The NT kernel's native syscall interface (through ntdll) has a 64-bit variant that is the natural translation target. Wine fully supports Win64, and its test suite covers both 32-bit and 64-bit Windows APIs.

### Win32 and WoW64

Running legacy 32-bit Windows binaries on a 64-bit Telix system would require a WoW64-equivalent layer — translating 32-bit Win32 calls (with 32-bit pointers, different struct layouts, and stack-based calling conventions) into the 64-bit personality server's interface. This is a substantial additional effort beyond the Win64 personality itself. Microsoft's WoW64 and Wine's wow64 implementation provide reference architectures. This is best deferred until the Win64 personality is functional, as Win32 compatibility is decreasingly important for modern Windows software.

### Test Infrastructure

**Wine test suite:** Extensive, covering both Win32 and Win64 APIs comprehensively. Tests document the expected behavior of Windows APIs through conformance checks that run against both Wine and real Windows. The test suite is effectively a machine-readable specification of Windows API behavior.

**Wine source code:** The Wine implementation itself serves as a reference for how Windows API calls translate to Unix syscalls, which can be adapted to translate to Telix's native interface instead.

### Assessment

The test infrastructure exists and is excellent. The engineering effort is enormous but parallelizes well across API subsystems. AI assistance is particularly valuable here: given Wine's test expectations as input, an AI can generate personality server stubs that pass those tests, subsystem by subsystem. The kernel32/ntdll layer (process management, file I/O, synchronization, memory management) maps most directly to Telix's native primitives. Higher-level APIs (user32, gdi32, COM) require additional infrastructure (a window manager, graphics stack) that extends beyond the personality server itself.

## Tier 4: BSD Compatibility

### Rationale

BSD compatibility (FreeBSD in particular) provides access to BSD-specific extensions beyond POSIX: kqueue, jails, Capsicum capabilities, and BSD-specific socket options. The incremental value over a POSIX personality is modest unless specifically targeting FreeBSD binary compatibility, but the effort is also modest since BSD semantics are close to POSIX.

### Test Infrastructure

**FreeBSD test suite (ATF/Kyua):** FreeBSD maintains its own test suite covering syscalls, filesystem operations, networking, and BSD-specific extensions. Well-maintained and cross-compilable.

**Sortix os-test:** Also covers some BSD-specific behaviors alongside POSIX.

### Assessment

Good test coverage. The incremental effort over the POSIX personality is relatively small, focused on BSD-specific extensions. This personality could be implemented as a thin layer atop the POSIX personality rather than a separate server.

## Tier 5: Plan 9

### Rationale

Plan 9 is intellectually interesting for Telix specifically because of the deep resonance between Plan 9's design philosophy and Telix's architecture. Plan 9's 9P protocol — a message-passing protocol for accessing all resources uniformly — maps naturally onto Telix's message-passing I/O model. A Plan 9 personality could be architecturally very clean, and would serve as a demonstration that Telix's I/O unification genuinely delivers on the promise of protocol-transparent resource access.

### Test Infrastructure

No formal conformance suite exists. However, the API is very small — roughly 40 syscalls — and well-documented in the Plan 9 man pages. The 9P protocol is separately well-specified and has multiple independent implementations (plan9port, u9fs, diod, etc.) that serve as reference behavior.

### AI Test Generation Feasibility

**Excellent.** The small, well-documented API makes comprehensive AI-generated test coverage trivially achievable. The Plan 9 man pages can be fed directly to an AI model, which can generate conformance tests for every documented syscall and 9P message type. The 9P protocol's message-based nature means tests can verify exact message sequences, making them precise and unambiguous.

### Assessment

No existing tests, but the API is small enough that AI-generated comprehensive test coverage is practical. The architectural fit with Telix makes this a high-value demonstration personality despite Plan 9's small user base.

## Tier 6: Haiku/BeOS

### Rationale

Haiku's BeOS-compatible API is a well-defined, moderate-size C++ interface organized into discrete "kits" (Application Kit, Interface Kit, Storage Kit, Media Kit, Network Kit, etc.). The API represents a genuinely different approach to OS interface design from the Unix tradition — pervasive multithreading, a message-passing application framework (BMessage/BLooper/BHandler), and integrated media and UI primitives. A BeOS personality would demonstrate that Telix's native message-passing model can support non-Unix API paradigms.

### Test Infrastructure

Haiku has CppUnit-based unit tests covering the Storage, Support, and App Kit APIs. These are structured as add-ons run by a test runner (UnitTester) and include single-threaded and multi-threaded tests. However, coverage is not comprehensive — many kits lack full test suites.

The Be Book (the complete BeOS R5 API reference, available online with permission from Access Co.) provides thorough documentation of every class and method across all kits.

### AI Test Generation Feasibility

**Very good.** The combination of thorough documentation (Be Book) and a structured, moderate-size API organized by kits makes systematic AI test generation highly practical. Each kit can be processed independently. The Be Book's method-level documentation provides clear specifications of expected behavior, return values, and error conditions that translate directly into test assertions. Haiku's existing tests can serve as reference style and coverage targets.

### Assessment

Partial existing tests (Haiku's CppUnit suite) supplemented by AI-generated tests from the Be Book. The structured kit-based API organization makes this one of the most tractable targets for AI-assisted test generation among non-trivial APIs.

## Tier 7: Redox Native

### Rationale

Redox is a Rust-based microkernel OS with a small, well-documented native syscall API exposed through the `redox_syscall` crate. It takes inspiration from Plan 9, seL4, and POSIX, with a scheme-based resource model.

### Test Infrastructure

Redox uses Sortix os-test for POSIX compliance testing and has its own acid test suite for correctness and stress testing. The native syscall API is documented in Rust type signatures, which provide a form of machine-readable specification.

### AI Test Generation Feasibility

Good. The Rust type system constrains the API surface and makes test generation straightforward. However, Redox's primary compatibility surface is POSIX, so a Redox native personality for Telix would provide marginal incremental value over the POSIX personality.

### Assessment

Small and well-typed API, easy to test, but limited practical value as a distinct personality. The scheme-based resource model is interesting but closely parallels Telix's own message-passing model — porting Redox applications might be better served by direct adaptation rather than a compatibility layer.

## Other Candidates Considered

**Managarm:** POSIX-oriented testing via os-test. Native API (mbus-based) is less well-documented. Low incremental value.

**Genode:** Well-documented component framework, but its API is about OS construction rather than application-facing syscalls. A "personality" in the Genode sense would mean something different — more like a framework port than a syscall emulation layer.

**SerenityOS:** Had a small, well-documented, intentionally retro-Unix syscall set with extensive test infrastructure before its focus shifted to the Ladybird browser. The syscall API is well-suited to test generation, but the project's direction has moved away from OS development.

## Priority Ordering

For development sequencing, considering both practical value and test infrastructure quality:

1. **POSIX** — Foundation. Excellent tests. Required for everything else.
2. **Linux** — Highest practical value. Excellent tests via LTP. Large effort but AI-parallelizable.
3. **Plan 9** — High architectural demonstration value. Trivial API, trivial AI test generation. Low effort.
4. **Haiku/BeOS** — Unique non-Unix personality. Good AI test generation feasibility. Moderate effort.
5. **BSD** — Thin layer over POSIX. Good tests. Low incremental effort.
6. **Windows/NT (Win64)** — Highest impact if achieved. Enormous effort but AI-assisted and parallelizable. Win32 deferred until Win64 is functional. Long-term goal.
7. **Redox native** — Low incremental value over POSIX.

## Personalities, ABIs, and ISA Variants

The personality server concept operates at the **syscall semantics** level — what operations the OS provides and what they mean. Below this, there are two additional layers that the system must handle, and it is important to distinguish them clearly.

### Personalities (Syscall Semantics)

A personality defines the API contract: what syscalls exist, what their arguments mean, what side effects they have, and what values they return. POSIX `open()` has specific semantics regardless of whether you are on a 32-bit or 64-bit machine, on ARM or x86. Linux `clone()` has Linux-specific semantics regardless of ISA. The personality layer is architecture-independent.

### ABIs (Calling Convention and Data Layout)

An ABI specifies how a personality's syscalls are invoked on a specific architecture: which register or trap instruction initiates a syscall, which registers carry arguments, what sizes `long`, `int`, and pointers are, how structures are laid out in memory, and what the syscall number mapping is.

A single personality can have multiple ABIs. Linux on x86-64, for example, supports three:

- **x86-64 native (LP64):** 64-bit pointers, 64-bit `long`, syscall via `SYSCALL` instruction, syscall numbers from the x86-64 table.
- **x32:** 64-bit registers but 32-bit pointers, a distinct syscall number range (native numbers | 0x40000000).
- **i386 compat (ILP32):** Full 32-bit ABI, syscall via `INT 0x80` or `SYSENTER`, syscall numbers from the i386 table, completely different struct layouts.

Similarly, MIPS has o32, n32, and n64 ABIs for the same Linux personality; ARM64 has the native AArch64 ABI and the AArch32 compat ABI.

For Telix, ABI handling sits between the personality server and the kernel's syscall entry path. The kernel must correctly decode the trap mechanism and register layout for each supported ABI, then present the decoded arguments to the personality server in a normalized form.

### ISA Variants (Instruction Encoding)

Below the ABI, ISA variants affect instruction encoding and execution mode but do not necessarily change the ABI or personality:

- **ARM Thumb/Thumb-2:** Different instruction encoding from ARM mode, but the same AAPCS calling convention. The kernel must correctly handle the T bit in CPSR/SPSR for context save/restore and must correctly decode the SVC instruction in both ARM and Thumb encodings. But the personality and ABI are unchanged — the same Linux AArch32 personality handles both ARM and Thumb mode code.
- **MIPS16/microMIPS:** Compact instruction encodings. Similar to Thumb — different encodings, same ABI.
- **RISC-V compressed (C extension):** 16-bit instruction variants. Transparent to the ABI and personality.
- **x86 real mode / protected mode / long mode:** These do change the ABI (16-bit vs 32-bit vs 64-bit), so they are really ABI transitions rather than mere ISA variants.

ISA variant handling is a kernel responsibility (correct trap decoding, context save/restore, single-stepping for the tracing infrastructure) and is transparent to personality servers.

### 32-bit Process Support

Running 32-bit processes on a 64-bit Telix system is an ABI concern, not a personality concern. A 32-bit Linux process and a 64-bit Linux process use the same Linux personality but different ABIs. The support requirements are:

**Kernel support:** The kernel must handle 32-bit syscall traps (e.g., `INT 0x80` on x86-64, `SVC` in AArch32 mode on ARM64), save and restore 32-bit register state, and manage 32-bit address spaces (restricting virtual addresses to the low 4 GiB). The page table format may differ (e.g., ARM64 uses different page table base registers for AArch32 compat processes).

**Personality server adaptation:** The personality server must handle the different struct layouts and pointer sizes of the 32-bit ABI. A `struct stat` from a 32-bit Linux process has different field sizes and offsets than from a 64-bit process. The personality server must translate between the 32-bit ABI's data layout and Telix's native (64-bit) internal representation.

**Thunking for cross-ABI calls:** If a 32-bit process interacts with 64-bit servers (as it inevitably will in Telix's microkernel model — the filesystem server is a 64-bit process), the IPC mechanism must handle the width mismatch. Messages from 32-bit processes carry 32-bit values; the receiving server expects 64-bit values. A thunking layer (in the kernel, in the personality server, or in a dedicated ABI translation server) must widen and narrow values appropriately.

**Per-architecture 32-bit compat matrix:**

- **x86-64:** i386 compat (32-bit x86). Well-understood; Linux, FreeBSD, and Windows all support this.
- **ARM64:** AArch32 compat (32-bit ARM and Thumb). ARM64 hardware has optional AArch32 support at EL0 (user mode), but some ARM64 implementations are dropping it (Apple Silicon does not support AArch32; some Cortex-A cores are AArch64-only).
- **RISC-V (64-bit):** 32-bit RISC-V compat is not a standard feature — RV64 does not execute RV32 binaries natively. 32-bit RISC-V support would require full emulation or a separate 32-bit kernel.
- **MIPS64:** o32 and n32 compat ABIs for 32-bit MIPS. Both are supported by Linux on MIPS64.

32-bit compat support is not required for the initial Telix implementation but should be planned for architecturally — particularly the IPC thunking question, which is unique to microkernels (monolithic kernels handle width translation inside the kernel where both ABIs are accessible).

## AI-Assisted Test Generation Strategy

For personalities without comprehensive existing test suites (Plan 9, Haiku/BeOS, portions of Windows), the following workflow is proposed:

1. **Gather API documentation:** Man pages, API references (Be Book, Plan 9 man pages), header files, type signatures.
2. **Generate assertion-based tests:** For each documented function/method/syscall, generate test cases covering: correct behavior for valid inputs, documented error conditions, edge cases (null pointers, zero-length buffers, boundary values), and concurrency behavior where documented as thread-safe.
3. **Cross-validate against reference implementations:** Where a reference implementation exists (Haiku for BeOS, plan9port for Plan 9, Wine for Windows), run generated tests against the reference to confirm that the test expectations match actual behavior.
4. **Iterate:** Fix test expectations that don't match reference behavior. Add tests for undocumented-but-expected behavior discovered through reference implementation testing.

This workflow is well-suited to AI coding assistance, which can process API documentation systematically and generate repetitive but correct test code at scale.
