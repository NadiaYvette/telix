# Scheduler Activations Enable Reference Count Demotion

**Status: DRAFT / SPECULATIVE DESIGN NOTE for future work.** This
document is downstream of `completion_based_syscalls.md` — the
activation upcalls it relies on are the same mechanism described in
that document's §2.4. Implementation timeline assumes the
completion-based syscall ABI lands first.

A novel observation connecting two previously separate lines of
systems research: scheduler activations (Anderson et al. 1992, K42)
and Perceus-style reference counting (Leijen/Reinking et al. 2021).
The core insight is that a non-blocking kernel interface with
upcalls gives language runtimes precise knowledge of thread
scheduling state, which enables safe demotion of reference counts
from synchronised (atomic) to unsynchronised (non-atomic) operation —
a transition that is unsafe under conventional blocking kernel
interfaces where the kernel can unpredictably migrate or stall
threads.

This has direct implications for the Frankenstein/Organ Bank
polyglot compiler, where Perceus serves as the common memory
management runtime across modules compiled from many source
languages, each with a potentially different threading model.
Significant caveats apply to Frankenstein's current state (discussed
in §6).

---

## 1. Background

### 1.1 Perceus Reference Counting

Perceus (Leijen, Reinking et al., PLDI 2021) is a compile-time
reference counting insertion algorithm for functional languages. It
emits precise reference count operations such that programs are
"garbage free" — only live references are retained, and dead
references are released immediately. Perceus additionally performs
reuse analysis, enabling Functional But In-Place (FBIP) programming
where purely functional code achieves in-place mutation when the
compiler can prove unique ownership.

Perceus as implemented in Koka uses a two-state model for heap
blocks:

- **Unsynchronised (thread-local):** Reference counts are positive
  integers. Increment and decrement operations are non-atomic —
  ordinary loads and stores. This is extremely cheap on modern
  hardware.

- **Synchronised (thread-shared):** Reference counts are negative
  integers (the sign bit serves as the sharing flag). Increment and
  decrement operations use atomic instructions (e.g., `lock xadd` on
  x86, `ldxr/stxr` on ARM64). This is substantially more expensive —
  atomic operations require cache-line exclusive ownership and
  memory ordering enforcement.

The transition from unsynchronised to synchronised is one-way in the
current Perceus design: once a heap block is marked as shared, it
remains shared for its entire lifetime, even if the sharing
condition is later resolved (e.g., all but one thread drops its
reference). The rationale is that determining when sole ownership
has been re-established is unsafe under conventional threading
models where the kernel can preempt or migrate threads at any time.

**Important note on Koka's current implementation status:** The
Perceus paper describes the synchronised/unsynchronised mechanism at
the theoretical level. Koka's actual runtime as of this writing
appears to be effectively single-threaded — Daan Leijen has
described plans for libuv-based async with effect handlers but real
multi-threaded support is unimplemented. The sign-bit thread-sharing
protocol is designed but not battle-tested under concurrent load.
**This means Frankenstein cannot assume Koka's runtime provides
working multi-threading; the threading layer is something
Frankenstein must build, not inherit.**

### 1.2 Scheduler Activations

Scheduler activations (Anderson, Bershad, Lazowska, Levy, 1992) are
a kernel mechanism that provides user-level thread schedulers with
explicit notification of kernel-level threading events. Instead of
the kernel silently blocking a thread inside a system call and
later resuming it, the kernel:

1. Notifies userspace when a thread blocks (via an upcall to the
   user-level scheduler).
2. Provides a new virtual processor (activation) so userspace can
   continue running other work.
3. Notifies userspace when the blocked thread becomes runnable
   again.

The non-blocking kernel interface variant (as in Zircon and K42)
goes further: system calls are generally non-blocking, returning
immediately with a result or a "would block" status. Blocking is an
explicit, voluntary action by the user-level scheduler (waiting on
a port or event). The kernel never surprises the runtime by seizing
a thread.

The key property for our purposes is: **the user-level scheduler
has precise knowledge of which activations (virtual processors) are
running, which are idle, and when transitions between these states
occur.** The kernel does not make scheduling decisions that are
invisible to the runtime.

The kernel's activation upcall mechanism supports two distinct
runtime models above it (see §2.5 of
`completion_based_syscalls.md`): an *event-loop* model where the
runtime drains a completion queue and dispatches handlers by handle,
and a *continuation-passing* model where each operation submission
carries a continuation that the kernel invokes directly on
completion via upcall. Both models are first-class consumers of
the same kernel facility; the demotion protocol below is described
under both, since the choice materially affects where quiescent
points fall.

---

## 2. The Problem: Unnecessary Atomic Operations in Polyglot Runtimes

### 2.1 The Single-Language Case

In a single-language runtime, the threading model is uniform. The
compiler and runtime cooperate to track when data crosses thread
boundaries, and the one-way synchronisation transition
(unsynchronised → synchronised) is a reasonable approximation: most
functional data is created, used, and destroyed within a single
thread, and the minority that is shared pays the atomic overhead
permanently.

### 2.2 The Polyglot Case (Frankenstein/Organ Bank)

Frankenstein harvests typed IR from multiple compiler frontends and
links modules from different source languages into a single
executable, using Perceus as the common memory management runtime
across all modules. Each source language has a different threading
model:

- **GHC (Haskell):** Lightweight green threads (Haskell threads)
  multiplexed onto a small number of OS threads (capabilities). The
  RTS performs work-stealing across capabilities. *Stress-tested in
  Frankenstein's bootstrap.*
- **Mercury:** Implicit parallelism via parallel conjunctions
  (work-stealing across "engines"), explicit threading available.
  Uses Boehm conservative GC. The mode system provides compile-time
  uniqueness tracking that Perceus could exploit to skip reference
  counting for unique values.
- **Koka:** Effect handlers with Perceus reference counting
  (single-threaded in current implementation as noted above).
- **Other frontends:** Various threading and memory management
  assumptions, ranging from manual (Rust, C) to tracing GC (Java,
  Go) to actor models (Erlang). Each frontend brings its own
  runtime assumptions that need to be discovered and either handled,
  worked around, or proven irrelevant to the use case.

When a value created by one language module is passed to another
language module potentially running on a different thread, Perceus
marks it as synchronised. The problem arises in several scenarios:

**Scenario 1: Green thread migration.** GHC's RTS moves a green
thread from capability A to capability B (work stealing). The green
thread's data was created on OS thread A and is now accessed on OS
thread B. From Perceus's perspective, this is a thread-sharing event
requiring synchronisation. From the application's perspective, the
same logical computation is the sole owner of the data — no sharing
has occurred.

**Scenario 2: Pipeline-style parallelism.** A value is created by
module X (running on thread A), passed to module Y (running on
thread B) for processing, and the result is returned to module X.
During the processing by Y, the value has two references (X's
reference and Y's reference) across two threads, requiring
synchronised reference counting. After Y finishes, X holds the sole
reference again — but under current Perceus rules, the value
remains permanently synchronised.

**Scenario 3: Kernel-forced migration.** Under a blocking kernel
interface, an OS thread blocks inside a system call (e.g., page
fault, I/O). The language runtime must migrate green threads from
the blocked OS thread to another OS thread to keep processors busy.
All data accessible to the migrated green threads undergoes a
thread-sharing transition, even though the migration was forced by
the kernel, not requested by the application.

In all three scenarios, the permanent synchronisation is overly
conservative. The data eventually returns to sole ownership by a
single thread/activation, but the atomic overhead persists.

---

## 3. The Insight: Activations Enable Safe Demotion

### 3.1 The Safety Requirement

A reference count demotion (synchronised → unsynchronised) is safe
if and only if:

1. The heap block's reference count is exactly 1 (sole ownership).
2. The sole reference is held by a specific, known activation.
3. No other activation can access the heap block.
4. The runtime can verify conditions 1–3 without racing with any
   concurrent access.

Under a conventional blocking kernel interface, condition 4 is the
problem. The kernel can preempt a thread between checking the
reference count and performing the demotion. Another thread could
acquire a reference during this window. The kernel can also migrate
threads in ways invisible to the runtime, making condition 2
unverifiable.

### 3.2 Why Activations Make It Safe

With scheduler activations and a non-blocking kernel interface:

- **The runtime controls all scheduling.** No thread runs unless
  the runtime explicitly schedules it on an activation. The kernel
  never silently resumes a thread that the runtime thought was
  parked.

- **The runtime knows exactly which activations are active.** When
  an activation is idle (the runtime has no work for it), the
  runtime knows no code is executing on that activation. When an
  activation receives an upcall (a previously blocked operation has
  completed), the runtime is notified before the activation begins
  executing user code.

- **Kernel operations don't block.** I/O submission returns
  immediately. Page faults generate an activation upcall rather
  than silently blocking the thread. The kernel never holds a
  thread in a state invisible to the runtime.

These properties mean the runtime can verify the demotion safety
conditions atomically with respect to its own scheduling state:

1. **Check reference count = 1.** Because the runtime controls
   scheduling, it can ensure no other activation is in the middle of
   an operation that might increment this block's reference count.

2. **Identify the owning activation.** The sole reference is
   reachable from a specific green thread, which is assigned to a
   specific activation. The runtime tracks this.

3. **Verify no concurrent access.** The runtime knows which
   activations are running and what green threads are assigned to
   them. If no other green thread on any active activation has a
   reference path to the block, demotion is safe.

4. **Perform the demotion atomically with scheduling.** The
   demotion can be performed as part of the runtime's scheduling
   decision — between dispatching one green thread and the next,
   when the runtime has full knowledge of the system state.

### 3.3 The Demotion Protocol

A practical demotion protocol for a Perceus runtime on a
scheduler-activation-based kernel. The protocol's *triggers* depend
on the runtime model (event loop vs continuation passing); the
*safety verification* is identical in both. Each block describes
the trigger under one model and the equivalent under the other.

**At green thread quiescent points** (scheduling boundaries, GC
safepoints, or explicit yield points):

1. The runtime examines recently-desynchronised values — values
   whose reference count has dropped to 1 after previously being
   shared. These can be tracked in a per-activation demotion
   candidate list.

2. For each candidate, verify that the sole reference is held by a
   green thread assigned to the current activation.

3. If verified, flip the sign bit (demote to unsynchronised).
   Subsequent reference count operations on this block use
   non-atomic instructions.

*Under the event-loop model:* the quiescent points are the natural
"between dispatches" instants — after one handler returns and
before the next is dispatched. The runtime's event loop runs the
demotion scan at this boundary.

*Under the continuation-passing model:* every continuation entry
and exit is a quiescent point. The runtime can either scan on
every continuation boundary (highest demotion density, highest
per-boundary cost) or amortise by scanning only when the
candidate list grows past a threshold or when an activation
becomes idle.

**On activation idle transitions** (an activation runs out of work):

1. All demotion candidates reachable solely from green threads that
   were assigned to this activation and are now parked can be
   bulk-demoted, because no activation is executing code that could
   access them.

*Both runtime models hit this trigger identically* — an idle
activation is an idle activation regardless of how it got there.
Under the event-loop model the activation enters this state when
its loop calls `ring_wait` with no immediately-available
completions; under the continuation-passing model it enters this
state when all registered continuations have run to completion
and no new submissions are pending.

**On green thread migration** (work stealing moves a green thread
from activation A to activation B):

1. All data reachable from the migrating green thread is promoted
   to synchronised (as in current Perceus).
2. After migration, if activation A's remaining green threads are
   the sole owners of some previously-shared data, those blocks
   become demotion candidates.

*Under both runtime models* migration is an explicit runtime
action; the runtime knows it's happening and runs the
promote/candidate-mark step inline with the migration.

### 3.4 Quiescent-Point Density and Demotion Throughput

The continuation-passing model gives the demotion protocol
substantially more frequent and more precisely-placed quiescent
points than the event-loop model. Under the event loop, demotion
runs once per completion-dispatch cycle — typically several
operations are batched between scans. Under continuation passing,
every continuation entry/exit is a quiescent point, which means
the runtime can demote *immediately* after a continuation drops
its reference, instead of waiting for the next loop boundary.

This matters for the pipeline-parallelism workload pattern
(§4.2 scenario 2): a value is shared during a consumer
continuation, the consumer drops its reference at continuation
exit, and the producer's next continuation sees the value as
already-demoted with no scan latency between the drop and the
demotion.

In quantitative terms, the demotion-window cost — the duration
during which a block is unnecessarily synchronised after its
reference count has returned to 1 — is bounded by the inter-scan
interval. Under event loop, that's the cycle time of the
dispatcher (typically tens of microseconds under load). Under
continuation passing, it's the time from the dropping continuation's
exit to its caller's next reference-count operation (typically
nanoseconds). For workloads where the same value is repeatedly
shared and unshared on short timescales, the continuation model
captures demotion opportunities the event-loop model would miss.

The corresponding cost is bookkeeping overhead per continuation
boundary. The right answer depends on workload: for runtimes that
heavily share short-lived values across activations (pipelines,
fork-join), continuation passing's denser quiescent points pay
back; for runtimes dominated by long-lived shared structures
(caches, configuration), the event-loop model's looser cadence is
adequate and cheaper.

---

## 4. Performance Implications

### 4.1 Quantitative Argument

The cost difference between atomic and non-atomic reference count
operations is substantial:

- Non-atomic increment/decrement: 1 cycle (fused with surrounding
  loads/stores, no memory ordering overhead).
- Atomic increment/decrement: 10–40 cycles on x86 (`lock` prefix
  forces cache-line exclusive state and full memory fence), 15–50
  cycles on ARM64 (LL/SC loop with acquire/release semantics), plus
  cache coherence traffic if the cache line is shared.

For data that is temporarily shared and then returns to sole
ownership (the pipeline pattern), the permanent synchronisation
penalty means every subsequent reference count operation for the
block's entire remaining lifetime pays the 10–50× overhead, even
though the sharing lasted for a fraction of the block's lifetime.

### 4.2 Workload Patterns That Benefit

- **Pipeline parallelism:** Producer → consumer → result return.
  Data is shared during the consumer phase and sole-owned before
  and after.
- **Fork-join parallelism:** Data is shared during the parallel
  phase and sole-owned during the sequential phase.
- **Temporary sharing for I/O:** Data is shared with an I/O server
  for serialisation, then the I/O server releases its reference
  after sending. The original thread retains sole ownership.
- **Green thread work stealing:** Data is logically thread-local but
  undergoes OS-thread migration due to the runtime's load balancer.

### 4.3 Workload Patterns That Don't Benefit

- **Permanently shared data:** Global configuration, shared caches,
  long-lived shared data structures. These remain synchronised
  throughout their lifetime, and demotion never triggers.
- **Short-lived shared data:** If a block is shared and then
  immediately freed (reference count goes to 0 rather than back to
  1), there is no opportunity for demotion.

---

## 5. Relationship to Existing Work

### 5.1 Biased Reference Counting

Biased reference counting (Jiménez, 2017; also explored in Swift's
runtime) assigns each object a "home" thread. Operations on the
home thread are non-atomic; operations on other threads are atomic
and may additionally require synchronisation with the home thread
for deallocation. The demotion idea extends this: rather than a
fixed home, the "home" can migrate when sole ownership is
re-established on a different activation.

### 5.2 Lean 4

Lean 4 uses a similar reference counting scheme to Perceus with a
thread-sharing bit. The Lean runtime does not currently perform
demotion. The activation-based demotion protocol could be applied
to Lean's runtime on a suitable kernel.

### 5.3 Epoch-Based Reclamation

The demotion protocol has structural similarities to epoch-based
reclamation (EBR): the runtime tracks scheduling epochs, and
demotion is safe when all activations have passed through a
quiescent point since the block's reference count dropped to 1. The
scheduling boundary between green threads is a natural quiescent
point.

### 5.4 Mercury's Mode System

Mercury's mode system tracks instantiation state (free, ground,
unique, dead) at the type level, with the compiler verifying these
declarations. Unique values, by definition, have exactly one
reference and need no reference counting at all — the compiler has
statically proven what Perceus would otherwise need to verify
dynamically. For Frankenstein, this means Mercury modules can
potentially bypass Perceus reference counting entirely for their
unique values, providing compile-time elimination of even the
non-atomic reference count operations. The mode system's
determinism categories (det, semidet, multi, nondet) additionally
constrain control flow in ways that simplify the placement of
reference count operations.

This is a substantial optimisation opportunity that's specific to
the Frankenstein polyglot context: Mercury modules contribute
mode-checked code where reference counting is largely eliminated by
static analysis, while modules from languages without uniqueness
guarantees use runtime Perceus. The hybrid is something no
single-language runtime can achieve.

---

## 6. Implications for Frankenstein/Organ Bank — Current State and Caveats

### 6.1 Frankenstein's Current Maturity

Frankenstein has reached bootstrap fixpoint — the compiler can
compile itself to a bit-identical binary on the second iteration of
self-hosting. This is a strong correctness signal demonstrating
that the polyglot compilation pipeline works end-to-end for at
least the language subset exercised by the compiler's own source
code. The Haskell frontend (GHC IR through OrganIR) has been
stressed by realistic library usage during the bootstrap.

However, several important caveats apply:

**The atheoretic code generation strategy works; the
Plotkin-influenced alternative was not fully debugged at the point
where work was paused.** This means there are at least two parallel
code generation paths in the codebase with different maturity
levels.

**Frontends other than the one(s) exercised by the bootstrap have
not been validated for realistic codebases.** The frontend matrix
is present but each frontend's ability to compile non-trivial
programs with extensive library usage is largely unproven.

**Standard library handling is the dominant unresolved question for
each frontend.** Mercury's standard library uses Boehm GC and
`pragma foreign_proc` C blocks that allocate via Boehm macros.
GHC's runtime makes deep assumptions about its generational copying
GC, threaded runtime, and closure layouts. Java would bring its
tracing GC's assumptions. Each language's standard library reaches
below the level where the HLDS-equivalent IR stays clean of memory
management decisions, and addressing this is a per-language effort
proportional to the language's library surface.

### 6.2 The C-Mediated FFI Strategy

One mitigation for the standard library problem is that most
languages' FFI ultimately routes through C. If Frankenstein's C
frontend is itself solid (which is plausible since C is the
universal compilation target), then FFI calls from Haskell,
Mercury, etc. into C can be compiled by Frankenstein rather than
handed off to a system C compiler. The FFI boundary stays within
the Frankenstein universe, and memory management semantics remain
uniform.

This works to the extent that:
- The C frontend handles all the language-specific FFI conventions
  (Haskell's `Foreign.C.Types`, Mercury's `pragma foreign_proc`,
  etc.).
- The C code being compiled doesn't itself link against system
  shared libraries that bring foreign assumptions back in.
- Memory allocation in FFI'd C code routes through Frankenstein's
  Perceus-compatible allocator rather than the system malloc.

On a Telix host, the strategy becomes substantially more tenable
because "system calls" are IPC messages to user-space servers — the
boundary between Frankenstein-compiled code and external code is a
message boundary with explicit memory ownership, not a function
call boundary with shared allocator assumptions.

### 6.3 Pipeline Depth Considerations Per Language

For each frontend, the question is at what point in the language's
compilation pipeline Frankenstein taps the IR. The goal is to tap
at a level where:
- All semantic information needed for Perceus insertion is present
  (types, modes/effects, control flow).
- Language-specific runtime assumptions have not yet been lowered
  into the IR.

For Mercury, this means tapping at HLDS rather than MLDS or LLDS —
Boehm assumptions enter at the lowering passes, and the standard
library's `pragma foreign_proc` C code embeds them directly. The
HLDS preserves mode and determinism information that Perceus can
exploit for static elimination of reference counting on unique
values.

For Haskell, the equivalent question is whether Frankenstein taps
at GHC Core (where the type system is rich but the lazy evaluation
model is implicit) or at STG (where laziness is explicit but the
runtime closure model is taking shape). Each level has different
implications for what runtime assumptions need to be handled.

These language-specific pipeline depth choices determine the
difficulty of the standard library work for each frontend.

### 6.4 The Threading Question Specifically

For the activation-based demotion protocol described in this
document to apply to Frankenstein-compiled code, the runtime must:

1. **Provide multi-activation execution.** This is not present in
   Koka's runtime and cannot be inherited from it. Frankenstein
   must build this independently.

2. **Track green-thread-to-activation assignments.** This is the
   per-runtime work-stealing scheduler. Mercury's runtime already
   does this for its engines/contexts model — porting Mercury's
   scheduler concepts to Frankenstein's runtime is a more tractable
   path than building from scratch.

3. **Integrate with Telix's upcall interface.** When Telix provides
   activations and delivers I/O completion upcalls, the Frankenstein
   runtime must translate these into green thread scheduling
   decisions.

4. **Choose between event-loop and continuation-passing runtime
   models** (see §1.2 and §3.4). For Frankenstein the
   continuation-passing model is the natural fit: language
   frontends that compile to Perceus typically have first-class
   closures, and the denser quiescent points improve demotion
   throughput on the pipeline-and-fork-join workloads functional
   programs tend to produce. The Mercury frontend specifically
   benefits because its mode system already statically places
   uniqueness boundaries that align with continuation boundaries —
   the runtime gets precise demotion opportunities at points the
   compiler has already verified are safe.

The most realistic near-term path is therefore: get one language's
threading model working under Frankenstein on Telix (Mercury's,
given its mature runtime), pick the continuation-passing runtime
model from the start (since it composes more cleanly with Mercury's
mode-system-driven uniqueness analysis), validate the demotion
protocol with that single-language workload, then generalize to
cross-language scenarios as additional frontends' threading models
are addressed. Other frontends whose source languages don't naturally
produce continuation-shaped code (e.g. Java, where the runtime
expects threads-and-monitors) can keep the event-loop runtime model
for their own activations — different activations in the same
Frankenstein-built process can use different runtime models against
the same kernel ABI (§2.5 of `completion_based_syscalls.md`).

---

## 7. Open Questions

1. **Demotion candidate tracking overhead.** Maintaining a
   per-activation list of demotion candidates adds bookkeeping. Is
   the overhead of tracking candidates offset by the savings from
   avoided atomic operations? This likely depends on the ratio of
   temporarily-shared to permanently-shared blocks in typical
   workloads.

2. **Interaction with cycle collection.** Perceus does not handle
   cycles. If a cycle collector is added (as may be needed for some
   source languages in Frankenstein), the demotion protocol must
   interact correctly with the collector's traversal — demoting a
   block that is part of a cycle being collected could introduce a
   race.

3. **Verification.** The demotion safety conditions could
   potentially be formally verified with Verus, connecting to the
   broader Telix verification strategy. The key invariant is: a
   block is unsynchronised if and only if it is reachable from at
   most one activation's green threads.

4. **Cache effects.** Demoting a reference count from atomic to
   non-atomic changes the cache coherence behaviour of the cache
   line containing the header. If the demotion triggers a cache-line
   state transition (e.g., from shared to exclusive), the first
   non-atomic operation after demotion may have a one-time cost.
   Whether this matters depends on the cache line's state at
   demotion time.

5. **Activation count as a proxy for thread count.** The protocol
   assumes that the number of activations is small (comparable to
   the number of physical CPUs). If the runtime creates many more
   activations than CPUs, the demotion verification (checking that
   no other activation can access the block) becomes more
   expensive.

6. **Mercury mode system integration.** How much of Mercury's static
   uniqueness analysis can be carried through OrganIR to inform
   Perceus insertion? A unique value at the Mercury source level
   should ideally result in zero reference counting in the generated
   code — neither atomic nor non-atomic — because the compiler has
   already proven sole ownership. Achieving this requires the
   OrganIR representation to preserve Mercury's mode annotations
   through whatever transformations occur between frontend
   ingestion and code generation.

7. **Standard library strategy per language.** What's the right
   approach for each frontend? Options include: reimplementing core
   operations in the source language (avoiding C FFI entirely),
   routing FFI through Frankenstein's C frontend (uniform memory
   management), or shimming language-specific runtime calls
   (intercepting Boehm allocation, GHC RTS calls, etc.). Each
   frontend likely needs a different choice based on the language's
   library surface and runtime structure.

---

## 8. Conclusion

The interaction between scheduler activations and reference
counting demotion is, to our knowledge, unexplored in the
literature. The two research threads — non-blocking kernel
interfaces from the OS community and precise reference counting
from the PL community — have developed independently. The
observation that the runtime scheduling knowledge provided by
activations enables safe reference count demotion connects them in
a way that could yield practical performance improvements for
polyglot runtimes and M:N threading models on microkernel operating
systems.

This idea is particularly relevant to the Telix/Frankenstein system
architecture, where the non-blocking upcall-based kernel interface,
the Perceus common runtime, and the polyglot compilation model all
converge. **However, realistic application of these ideas depends on
substantial intermediate work:** Frankenstein's frontends beyond the
bootstrap-stressed Haskell path need validation for realistic
codebases, standard library handling per language needs concrete
strategies, and the threading layer for Frankenstein's runtime
needs to be built (it cannot be inherited from Koka, which is
effectively single-threaded). The Mercury frontend may offer the
most tractable near-term path because Mercury's runtime already
implements work-stealing and its mode system provides static
information that Perceus can exploit.

A prototype implementation within the Frankenstein runtime,
measured against the existing one-way synchronisation policy, would
quantify the benefit and establish whether the demotion overhead is
justified. The realistic timeline for such a prototype is gated on
the prerequisite work described above, not on the demotion protocol
itself, which is comparatively simple to implement once the runtime
infrastructure exists.

---

## Appendix A: Connections to the Current Telix Codebase and Today's Work

The proposal sits downstream of the completion-based syscall ABI
(`docs/completion_based_syscalls.md`). This appendix flags where
the existing Telix tree already has structure that supports the
activation/demotion idea, and where today's work has surfaced
patterns that turn out to be directly relevant.

### A.1 The dependency chain

The activation/demotion protocol is gated on three layers, in
order:

1. **The completion-ring ABI** — non-blocking submit/completion
   with shared-memory rings. The kernel can't deliver activation
   upcalls in any useful form until syscall semantics are themselves
   non-blocking; otherwise an upcall during a blocked syscall has
   nowhere coherent to land.
2. **The upcall delivery mechanism** itself — covered in §2.4 of
   `completion_based_syscalls.md`. The signal-frame plumbing in
   `linux_srv` and the kernel's existing exception entry give us
   the mechanics; the registration ABI is the new surface.
3. **A userspace runtime with activation-aware scheduling.** No
   language runtime currently running on Telix qualifies — the
   Linux personality and Telix-native userspace both treat
   syscalls as blocking from the language-runtime perspective. The
   Frankenstein runtime is the first plausible candidate.

So the demotion proposal is not near-term work, but the prerequisite
work has a concrete starting point.

### A.2 BlockReason as a primitive activation-state record

Telix's `kernel/src/sched/thread.rs` already carries a `BlockReason`
enum on every Thread struct, recording WHY a thread is blocked
(IpcRecv, CallReply, WaitChild, Kswapd,
[[project_suspend_wake_race|SuspendedMemPressure]], etc.). For an
activation-aware runtime, this is already most of the information
the kernel needs to provide via upcall when an activation parks:
"thread T parked, reason R." The shape of the upcall payload is
already present in the kernel's per-thread state.

### A.3 The async-continuation pattern as runtime template

The work landed today (`PendingAsyncKind::ConnectInitramfs` and the
existing `AcceptUnix` / `RecvUnix` / `IrfsReadFd` / `IrfsReadMmap`
variants in `linux_srv`) is structurally the same pattern the
Frankenstein runtime would need: per-logical-thread state machine
keyed by a correlation/handle, dispatched off a reply port. If you
squint, `linux_srv` today is a tiny, hand-written version of what
§4.2 describes for the language-runtime layer — except the "Linux
threads" are real Linux processes rather than green threads, and
the dispatcher is an event-loop shape (single thread of control
polling the reply port via `port_set_recv`).

This is an unexpectedly direct precedent. The Mercury or
Frankenstein runtime building its own scheduler on Telix would
recapitulate the same shape with green threads replacing Linux
processes — and, if it picks the continuation-passing runtime model,
with kernel-delivered upcalls replacing the explicit `port_set_recv`
poll.

The `PENDING_ASYNC` table itself is shape-compatible with both
runtime models: it's already a slot-indexed continuation table.
Under the event-loop model the dispatcher reads completions and
indexes into it; under the continuation-passing model the kernel's
upcall handler does the same indexing. The structural change is
where the dispatch happens (top-of-loop vs upcall-entry), not in
the table itself. This is reassuring for the migration story: the
existing PENDING_ASYNC table doesn't need to be redesigned to
accommodate the runtime-model choice.

### A.4 Verus connection (open question 7.3)

The proposed invariant — *"a block is unsynchronised iff reachable
from at most one activation's green threads"* — is exactly the kind
of state-relationship the user has been using Verus for elsewhere
(`tests/verus-phys/`, `tests/loom-balance-set/`). The pattern is:
two-state classification + a per-state invariant + a transition
predicate. The phys.rs Verus retrofit (#158) demonstrates the same
shape over a different domain. The demotion proof would be a
natural extension of that effort once a runtime exists to verify.

### A.5 Loom connection (the suspend/wake race precedent)

Today's loom-balance-set work (commit `dd017d7`) found a race in
non-atomic Thread::state updates across two threads — exactly the
*kernel-side analogue* of what condition 4 in §3.1 warns about for
the runtime side. The same loom permutation-testing approach would
apply directly to the demotion protocol's atomic-window analysis.
"What happens when an activation receives an upcall mid-demotion?"
is the kind of question loom is designed to answer.

If a Frankenstein prototype ever lands on Telix, a loom model of
the demotion state transitions should accompany the implementation
the same way `loom-balance-set` accompanies the kernel's
suspend/resume primitives.

### A.6 Activation count and Telix's current SMP shape

§7.5 worries about activation count vs. physical CPU count. Telix's
current bench is 4 vCPUs on 4 dedicated host P-cores (cpus 4,6,8,10
per the cgroup recipe). The activation/CPU ratio is already
naturally bounded for this configuration. As Telix scales out
across cores or across hosts (per
`docs/telix_distributed_strategy.md`), this assumption needs
revisiting — particularly in the clustered case, where "activation
on a remote node" stretches what "the runtime knows where this
activation is" means. The demotion proof relies on local
runtime omniscience; distributed activations would need a different
analysis.

### A.7 Parent-constructed children and initial ownership state

The parent-constructs-child pattern (see §2.6 of
`completion_based_syscalls.md`) interacts cleanly with the demotion
protocol. When a parent task spawns a child by populating the
child's initial state directly, the parent already knows *exactly*
which heap blocks are reachable from the child's initial root set.
The parent can mark those blocks with the appropriate
synchronisation state at spawn time:

- Blocks unique to the child (transferred to the child as part of
  the spawn) start unsynchronised — only the child's activation can
  reach them.
- Blocks shared between parent and child (e.g. shared message
  buffers, configuration) start synchronised, with the demotion
  protocol available to demote them later if the parent drops its
  reference.
- The Mercury mode system's uniqueness information at the source
  level translates directly: a unique-mode value transferred to the
  child can be marked unsynchronised from the start without any
  runtime check.

This means the child never has an "initial synchronisation
upgrade" cost — the cap-table population step that the parent
performs is also where the synchronisation state of each transferred
block is set. Contrast with a self-initialising child that would
have to scan its initial heap and decide synchronisation status
itself, paying atomic costs unnecessarily.

The combination is particularly valuable for fork-join-style
parallelism: the parent spawns a child to compute on a value, marks
the value synchronised at spawn, the child runs, the child exits,
the parent reclaims sole ownership and demotes. End-to-end this
adds exactly one synchronised→unsynchronised demotion to the
critical path, with no other atomic-RC overhead beyond what the
sharing duration genuinely requires.

### A.8 The "Mercury first" tactical recommendation

§6.4's suggestion to start with Mercury is well-grounded against
the codebase: Telix already has a working
[[project_xwayland_goal|Linux personality]] sufficient to host
Mercury's GHC-bootstrap-style binaries, the IPC patterns Mercury's
runtime would need (parking on events, work stealing across
contexts) match Telix's existing port + thread machinery
structurally, and Mercury's uniqueness mode information feeds
directly into the demotion-or-skip decision Perceus already wants
to make.

Practically: a "Mercury hello-world running with Perceus on Telix"
milestone is far more reachable than "Frankenstein's full polyglot
linker" and would let the demotion protocol be prototyped against
a real workload.

### A.9 What this means for the near-term

The completion-based syscall doc (`completion_based_syscalls.md`)
is the immediate next architectural piece. Once that lands, the
upcall mechanism becomes a kernel facility — and at that point a
Frankenstein/Mercury runtime experiment becomes possible. The
demotion protocol is the *third* layer of this stack; trying to
build it before the lower layers exist would be putting the
cleverness ahead of the foundation.

The framing in the user's draft is right: this is "speculative
design for future work." The value of the draft now is that the
completion-based syscall design (which IS near-term) ends up being
informed by what its downstream consumers want — and Appendix A.7
of the completion-based doc, on clusterability, can be cross-read
with this document's §A.6 to think about whether the upcall
mechanism's design needs distributed-friendly hooks from the
start.
