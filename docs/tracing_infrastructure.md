# Tracing Infrastructure

## Overview

Telix requires a tracing and observability infrastructure for both development-time debugging and the attribution-based profiling described in the evaluation strategy. Rather than porting an existing tracing framework (DTrace, eBPF/bpftrace), the design follows a native approach consistent with the microkernel's message-passing architecture: a small per-architecture probe engine in the kernel, with all filtering, aggregation, and analysis performed by an architecture-independent tracing server in userspace.

## Motivation for a Native Design

Existing tracing frameworks have narrow architecture coverage relative to Telix's porting ambitions. DTrace effectively covers only x86-64 and ARM64 (with legacy SPARC). Linux's eBPF-based tooling is broader (x86-64, ARM64, RISC-V, s390x, MIPS, PowerPC, LoongArch) but is deeply coupled to Linux kernel internals. Both would require extensive adaptation to a microkernel's structure, and neither would automatically extend to new ISA ports.

A native tracing facility designed around the message-passing IPC avoids these constraints. The architecture-specific surface is small and well-understood; the architecture-independent surface is the bulk of the system and needs to be written only once.

## Architecture

### Kernel-Side Probe Engine

The kernel provides a minimal probe engine with a clean per-architecture port layer. The probe engine's responsibilities are:

**Probe insertion and removal:** Insert and remove breakpoint or trap instructions at designated probe points (function entry/exit, arbitrary instrumentation sites). Every ISA provides a suitable trap instruction (ARM64: `BRK`; x86-64: `INT3`; RISC-V: `EBREAK`; MIPS: `BREAK`; PowerPC: `TRAP`; s390x: illegal instruction sequences; etc.).

**Context capture:** When a probe fires, save the register state and any probe-specific context (function arguments, return values, timestamps) into a message-sized structure.

**Probe event emission:** Deliver the captured context as a message to a designated tracing port. This uses the standard IPC mechanism — the probe event is a message like any other, and the tracing server receives it through its port set.

**Single-step support:** After a breakpoint fires and the probe event is emitted, single-step past the replaced instruction so that normal execution can resume. This is the most architecture-sensitive component, as instruction lengths, PC-relative addressing modes, and branch semantics vary considerably by ISA.

**Function entry/exit instrumentation:** Support for compiler-inserted instrumentation calls (GCC's `-pg`/`mcount`, or equivalent) that can be NOP-patched at load time and selectively activated by replacing NOPs with calls to the probe engine. This avoids the complexity of binary patching for the common case of function-level tracing.

### Per-Architecture Port Surface

The per-architecture code required to support the probe engine is:

- Breakpoint instruction insertion and removal (trivial: write/restore a few bytes)
- Register context save/restore at probe points
- Single-step past a replaced instruction (the fiddliest part — varies by ISA)
- Function entry/exit hook mechanism

This is estimated at a few hundred lines of architecture-specific code per ISA — a manageable port surface that scales linearly with the number of supported architectures.

### Tracing Server

The tracing server is an architecture-independent privileged userspace server that receives probe event messages and implements the tracing policy:

**Filtering:** Discard events that do not match active tracing predicates. Filtering can be expressed as predicates on the probe context (e.g., "only events from process X," "only when argument 0 > threshold").

**Aggregation:** Accumulate statistics across probe events — counts, histograms, min/max/average of traced values. Aggregation is the primary mechanism for low-overhead production tracing, as it reduces the data volume from one message per event to periodic aggregate summaries.

**Output formatting:** Present trace data in human-readable or machine-parseable formats.

**Script/policy language:** A domain-specific language for expressing tracing programs (predicates, actions, aggregations). Whether this adopts DTrace's D language syntax (for familiarity) or a custom language is an open design question. The D language has the advantage of a large existing script corpus and user familiarity; a custom language could be simpler and better fitted to the message-passing model.

### Probe Providers

Following DTrace's provider model, different subsystems register probe points with the kernel's probe engine:

**Syscall provider:** Probes at native syscall entry and exit.

**IPC provider:** Probes at message send and receive, capturing port identifiers, message types, and sizes. This is particularly valuable in a microkernel where IPC is the dominant inter-component communication mechanism.

**Scheduler provider:** Probes at context switch, thread migration, priority inheritance events, and scheduler activation upcalls.

**VM provider:** Probes at page fault, superpage promotion/demotion, extent coalescing/splitting, and reclaim events.

**Server-side probes:** Privileged servers (filesystem, cache, block device) can register their own probe points, enabling tracing of server-internal operations (cache hits/misses, block I/O submission/completion, filesystem metadata operations) through the same infrastructure.

## Interaction with the Microkernel Architecture

The tracing server receives probe events through ordinary IPC, which means it benefits from the same L4-style handoff scheduling, priority inheritance, and flow control as any other server. Under high probe firing rates, the bounded port capacity provides natural backpressure — if the tracing server cannot keep up, the probe engine's send to the tracing port will either block briefly or drop events (configurable per probe).

Tracing a server's internals does not require special privilege beyond holding a capability to that server's tracing port. This composes naturally with the capability model — the tracing server is granted capabilities to the probe ports it needs, and cannot trace servers for which it lacks capabilities.

## Relationship to the Evaluation Strategy

The tracing infrastructure directly supports the attribution-based profiling approach (§10.2 of the design document):

- **IPC overhead attribution** uses the IPC provider to measure time spent in message passing.
- **Server overhead attribution** uses server-side probes to identify hot paths within each server.
- **VM subsystem attribution** uses the VM provider to profile extent operations, WSCLOCK scanning, and superpage management.

The mechanism verification goals (§10.1) also benefit: superpage allocation success rates, TLB miss correlation, and I/O completion latency distributions can all be measured via appropriately placed probes.

## Open Questions

- **Script language choice:** Adopt DTrace D language syntax for familiarity, or design a custom language better fitted to the message-passing model?
- **In-kernel filtering:** For very high-frequency probes (e.g., every function entry), sending a message per event may be prohibitively expensive even with backpressure. In-kernel pre-filtering (evaluating a simple predicate before emitting the message) may be necessary to reduce event volume. This adds complexity to the per-architecture probe engine but may be essential for production use.
- **Probe overhead budget:** What is the acceptable overhead for active probes? The message-per-event model is more expensive than DTrace's in-kernel aggregation approach. Quantifying this trade-off is needed to determine whether in-kernel aggregation is also necessary.
- **Interaction with coscheduling:** Tracing events from coscheduled thread groups (e.g., VM vCPU threads) may perturb the coscheduling timing. Whether this is significant and whether trace-aware coscheduling adjustments are needed is an empirical question.
