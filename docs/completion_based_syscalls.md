# Telix Completion-Based Asynchronous Syscall Interface

**Status: DRAFT / DESIGN IN PROGRESS** — not yet committed; the document
captures a direction for converting Telix's native syscall ABI to a
completion-based, ring-backed model with upcall-based handling of
exceptional events. Details below are subject to revision as
implementation concerns surface.

**Motivation:** Provide a fundamental architectural foundation that,
among other benefits, addresses the Linux personality server
concurrency issue more elegantly than concurrency mechanisms layered
on top of a blocking interface.

---

## 1. Goals and Non-Goals

### 1.1 Goals

- Replace Telix's blocking native syscall interface with a
  completion-based asynchronous interface.
- Use shared submission/completion rings between kernel and userspace
  for the high-volume routine operations (IPC, memory mapping, I/O).
- Reserve scheduler activation upcalls for involuntary kernel entries
  (page faults requiring userspace handling) and exceptional events
  (signal-like notifications, activation availability changes).
- Preserve the existing semantics of every syscall — only the
  invocation and result delivery mechanism changes.
- Support both sophisticated language runtimes (which use the ring
  interface directly for maximum concurrency) and simple programs
  (which use blocking convenience wrappers for the existing
  programming model).
- Provide a natural foundation for the Linux personality server's
  concurrency, replacing the need for per-syscall blocking threads
  with per-process state machines that submit and await completions.

### 1.2 Non-Goals

- This document does not propose restructuring the kernel's internal
  architecture beyond what is needed for the ring-based interface.
  The dispatch logic, capability checking, IPC routing, etc. remain
  as they are.
- This document does not specify the exact ring entry format
  (operation codes, field layouts). Those are implementation details
  that follow from the interface decisions described here.
- This document does not address the kernel's own internal asynchrony
  (whether kernel handlers themselves yield or run to completion).
  That is orthogonal to the userspace-facing interface.

### 1.3 Comparison Anchor Points

The closest existing systems are:

- **Linux io_uring:** Shared submission/completion rings, asynchronous
  syscall batching. The dominant contemporary realization of
  completion-based I/O.
- **Windows I/O Completion Ports (IOCP):** Long-established
  kernel-managed completion queue mechanism.
- **K42 scheduler activations:** Kernel notifies userspace about
  thread blocking events; userspace scheduler responds.
- **Mach continuations and AST:** Continuation-based asynchronous
  syscalls with asynchronous trap notifications.

This design borrows from all of these but is not a direct port of any
one. The closest match is io_uring augmented with K42-style upcalls
for events that don't fit the submit/complete pattern.

A fuller bibliography for the language+OS co-design tradition this
work draws on — including the Midori lineage, Akaros, Barrelfish,
the Mach continuations paper, the capability-language tradition,
and the polyglot-managed-runtime literature relevant to
Frankenstein — is maintained in
`docs/related_work_reading_list.md`.

---

## 2. Architecture Overview

### 2.1 Completion Delivery as a Per-Submission Choice

Every syscall under this design is logically split into two halves:
*submission* (asks the kernel to do something, returns immediately
with a correlation handle) and *completion* (the result, delivered
later when the operation finishes). The submission half is uniform
across all syscalls — userspace fills in an operation code,
arguments, and a *completion destination* tag.

The destination tag selects, per-submission, where the completion
will be delivered. The kernel implements a small fixed enumeration:

1. **Synchronous return.** The operation completes in bounded time
   without yielding the calling thread; the result is returned in
   the submission syscall's own return path. Used for fast
   operations where the submit/complete round-trip would add more
   overhead than the operation itself costs.

2. **Reply capability.** A generation-counted reply slot is allocated
   on the caller's behalf and the completion lands as a reply
   message there. Identical to today's `sys_call` + reply-cap
   mechanism in `kernel/src/ipc/call_reply.rs`. Backward compatible
   with every existing Telix server.

3. **Port message.** The completion is delivered as an IPC message
   to a specified port. The port may be local or remote (routed
   transparently through `proxy_srv`), making this the natural
   cluster-friendly choice. Bounded by the port's queue length;
   the usual `send_nb` semantics apply if the port is full.

4. **Ring entry.** The completion is written into a specified
   ring's CQ in shared memory; userspace polls or waits on the
   ring. Best for high-throughput batched workloads. Only
   submissions that explicitly select this destination contribute
   to ring fullness — so ring overflow is contained to workloads
   that opted in.

5. **Direct upcall.** The kernel transfers control to a registered
   continuation, with the completion frame on the upcall stack.
   Pairs with the continuation-passing runtime model.

The kernel's "operation complete" path is a small dispatch table
keyed by destination tag — the operation handlers themselves don't
need to know how their results will be delivered.

Each destination has different overflow, latency, and cluster
behaviour, so per-submission choice matters: a high-throughput
storage workload uses (4) rings to amortise dispatch; a remote
service call uses (3) port message for transparent routing through
the existing distributed-service substrate; a trivially fast
operation uses (1) sync return to skip async overhead; an
existing-pattern Telix server keeps using (2) reply cap unchanged;
a continuation-style language runtime uses (5) upcall delivery.

Beyond these five completion paths, an orthogonal mechanism handles
events that userspace did not explicitly submit: page faults that
require userspace handling, activation-availability changes,
signal-like notifications from other processes. These flow through
the *upcall* facility, structurally the same machinery as (5) above
but registered per-process (per upcall type) rather than
per-submission. The two share the kernel's upcall delivery path;
the choice of "is this completion of a userspace-submitted op" vs
"is this an externally-originated event" is just whether the
upcall registration matches a pending submission's correlation tag
or a long-lived per-process registration.

The remainder of this section details each destination type. (1),
(2), and (3) reuse machinery already in
`kernel/src/syscall/handlers.rs`, `kernel/src/ipc/call_reply.rs`,
and `kernel/src/ipc/port.rs` respectively. (4) and (5) are the
genuinely new mechanisms — the shared-memory ring layer and the
per-process upcall registration.

### 2.2 The Ring Data Structures

Each thread (or each activation, depending on the granularity
choice — see §6.1) has two rings in shared memory mapped into both
the kernel address space and the userspace address space:

**Submission Queue (SQ):** Userspace writes; kernel reads. Each entry
contains:
- Operation code (which syscall is being invoked).
- Handle (a small integer chosen by userspace, used to correlate the
  completion with the submission).
- Arguments (operation-specific, fixed layout per operation).

**Completion Queue (CQ):** Kernel writes; userspace reads. Each entry
contains:
- Handle (matching the original submission's handle).
- Result code (success/error status).
- Result data (operation-specific, fixed layout per operation).

Both rings use lock-free producer/consumer access via
memory-barrier-protected head and tail pointers in shared memory.
The kernel is the consumer of SQ and the producer of CQ; userspace is
the producer of SQ and the consumer of CQ.

### 2.3 The Wait Primitives

A small set of operations remain blocking by design — they exist
precisely so userspace can sleep until events arrive:

- `ring_wait(min_completions, timeout)` — Suspend the calling thread
  until at least `min_completions` entries are available in the CQ,
  or the timeout expires.
- `ring_wait_handle(handle, timeout)` — Suspend until the completion
  for a specific handle arrives.

These are the only operations that explicitly block. Everything else
returns immediately, success or fail, without putting the thread to
sleep.

### 2.4 The Upcall Mechanism

Upcalls are delivered by the kernel preempting the userspace
activation and transferring control to a registered handler. The
handler receives information about the event (e.g., faulting address
and instruction pointer for a page fault) and can either:
- Resolve the situation and resume the interrupted computation
  (typically by returning from the handler).
- Yield to the userspace scheduler, which dispatches other work while
  the original computation remains parked.

The kernel maintains a per-process registration of upcall handlers,
one per upcall type. If an upcall fires for a type with no registered
handler, the kernel takes a default action (typically signal-like
termination for unhandled faults).

### 2.5 Five Runtime Patterns Over the Five Destinations

Each completion destination from §2.1 admits a natural runtime
pattern that uses it as the dominant delivery mechanism. The five
patterns are summarised here side by side for comparison. The
kernel ABI is agnostic to which pattern a given runtime adopts;
different activations within the same process can use different
patterns, and a single activation can mix destinations across its
own submissions. The "dominant pattern" framing below is the
typical case, not a constraint.

Each subsection follows the same structure: **shape** (what code
looks like), **concurrency** (how parallelism is expressed),
**workload** (where it fits), **precedent** (existing systems),
**cluster** (how the pattern behaves across hosts), and
**tradeoffs**.

#### 2.5.1 Synchronous code (destination 1: sync return)

**Shape.** Straight procedural code:
```rust
let result = syscall_do_thing(arg)?;
process(result);
```
No event loop, no callbacks, no rings. Each operation completes
before the next line runs.

**Concurrency.** None within a single thread; multiple threads
each execute their own straight-line code. Concurrency is
expressed by spawning more threads, not by interleaving operations.

**Workload.** Simple CLI tools, scripts, embedded compute, test
harnesses, the body of any code whose performance is bounded by
computation rather than I/O wait. Also the right default for
operations the kernel can complete in bounded time without
yielding (capability lookups, thread-state queries).

**Precedent.** Every K&R-style C program. Most shell tools. The
default mode of every traditional Unix syscall.

**Cluster.** Poor fit. A "remote" sync operation would block the
calling thread until the round trip completes; that's acceptable
for a few operations but pathological as a default.

**Tradeoffs.** Simplest possible programming model — debuggable
with `printf`, no state machines, no race windows around completion
delivery. Cost is that operations involving any wait (I/O, IPC,
page faults) block the thread; the only concurrency escape valve
is more threads.

#### 2.5.2 Classic server (destination 2: reply capability)

**Shape.** Recv/dispatch/reply loop, each request servicing running
to completion (possibly invoking nested sync calls) before the next
request is dequeued:
```rust
loop {
    let (msg, reply_cap) = recv_with_cap(port);
    let result = handle(msg);
    reply(reply_cap, result);
}
```

**Concurrency.** One thread per server, or a thread pool drawing
from a shared port. Concurrency among clients is the queue depth
of the port; concurrency within request handling is whatever the
handler itself does (usually nothing — handlers run to completion).

**Workload.** Stateless or simple-stateful services. Existing
Telix init_srv, namesrv, discovery_srv, proxy_srv all use this
pattern today.

**Precedent.** Mach servers, L4 servers, every microkernel's
"service" component, classic Plan 9 file servers.

**Cluster.** Reply caps are local-only; a reply cap allocated on
node A cannot be invoked from node B without proxy_srv-style
re-marshalling. Pattern works *to* a remote server (the client
sends to a port that's locally a proxy stub, gets a local reply
cap), but the server-side reply path is bound to the server's host.

**Tradeoffs.** Backward compatible with every existing Telix
server — no refactor required. Bottleneck is the per-server thread
parking on a sync backend call (`linux_srv`'s blocking
`IRFS_IO_CONNECT` problem from earlier today is the canonical
case). Mitigations: thread pool, or split into multiple servers
per logical responsibility. Pattern is well-understood and
inexpensive to debug.

#### 2.5.3 Actor / message-passing (destination 3: port message)

**Shape.** Each "actor" is a process or activation with an inbox;
the runtime is a recv loop dispatching by message type, possibly
sending fresh messages to other actors:
```rust
loop {
    let msg = recv(inbox);
    match msg.tag {
        Tag::DoX(args) => { send(peer, Tag::XResult(compute(args))); }
        Tag::DoY(args) => { /* ... */ }
    }
}
```

**Concurrency.** Inherent: every actor is independently scheduled,
sharing no mutable state, communicating only via messages. The
runtime can run many actors per OS thread, or one actor per
thread, or any mixture.

**Workload.** Distributed services, supervised process trees, soft
real-time systems, telecom-style "let it crash" architectures.
Anything where the unit of concurrency *is* the message handler.

**Precedent.** Erlang/OTP, Akka, Orleans, Microsoft Service Fabric.
The runtime-as-OS model: BEAM is structurally an operating system
implementing only the actor abstraction.

**Cluster.** The pattern's best feature. Ports may be local or
remote (routed transparently through proxy_srv), and the actor
code doesn't know or care which. Supervision trees, naming, and
failure detection all extend naturally across nodes.

**Tradeoffs.** Encoding sequential logic that doesn't fit the
message-handler shape (long-lived state machines, multi-step
transactions) requires explicit state-machine bookkeeping inside
the actor — not as ergonomic as event-loop or continuation
patterns for those workloads. But the cluster property is a
direct, no-effort win that no other pattern matches.

#### 2.5.4 Event loop (destination 4: ring entry)

**Shape.** Top-level loop polls or waits on a completion ring,
drains entries, dispatches each by correlation handle to a
runtime-maintained handler table:
```rust
loop {
    let completions = ring_wait(min=1, timeout=...);
    for c in completions {
        let handler = handler_table.lookup(c.handle);
        handler(c.result);
    }
}
```
Each "asynchronous" operation is encoded as a state machine living
in the handler table.

**Concurrency.** The ring drains many completions per loop
iteration, so concurrency manifests as interleaved handler calls
on the same OS thread. For multi-thread parallelism, one ring per
worker thread.

**Workload.** High-throughput I/O servers: web servers, databases,
proxies, network packet processors. Any workload where the win is
amortising dispatch overhead across batched completions.

**Precedent.** Linux io_uring, libuv (Node.js), Tokio (Rust),
.NET's IOCP-based runtime, every modern async HTTP server.

**Cluster.** Ring is local-only — shared memory between kernel and
userspace on a single host. Cluster operations need the escape
valve of mixing destinations (a remote operation submitted with
destination=port-message rather than ring).

**Tradeoffs.** Best throughput for batched workloads; the ring
amortises dispatch cost. Cost is the per-completion overhead of
"look up handler in table" + the global ordering imposed by a
single drainer (parallelism comes from multiple rings, not from
within one ring). Ring overflow is a real concern (see §6 and §7),
bounded to the ring's workload.

#### 2.5.5 Continuation passing (destination 5: direct upcall)

**Shape.** No top-level loop. Each submission carries its
continuation; the kernel invokes the continuation directly when
the operation completes, on whichever activation the runtime has
marked available:
```rust
ring_submit_with_continuation(DO_THING, arg, |result| {
    // this runs as an upcall when the operation completes
    process(result);
    // possibly submit more with their own continuations
});
// activation returns to its scheduler
```

**Concurrency.** Continuations are independent units of work; the
runtime can run them in parallel on any available activation. No
single drainer thread — concurrency comes from many activations
each running their own current continuation. Cilk-style
work-stealing fits naturally here.

**Workload.** Language runtimes with first-class closures (Verona,
Pony, Cilk, OCaml effect handlers), work-stealing schedulers,
fine-grained parallel computation (parallel reductions,
divide-and-conquer algorithms). Also the natural fit for the
activation-aware Perceus demotion protocol
(`docs/activation_perceus_demotion.md`) because every continuation
boundary is a precisely-located quiescent point.

**Precedent.** Mach continuations (1990s), K42 closure-based
activations, Cilk's spawn-and-sync, modern JavaScript async/await
(after compilation to CPS-style state machines).

**Cluster.** Local-only by default; upcalls don't cross machines.
A continuation that needs a remote result mixes destinations (the
remote call uses destination=port-message; the local post-processing
uses destination=upcall).

**Tradeoffs.** Lowest per-completion latency (no poll-then-dispatch),
no central bottleneck, natural locality (the continuation runs where
the upcall landed), and the finest-grained quiescent points
available. Cost is more invasive code shape — each operation needs
its closure data structured for the continuation pipeline — and
harder debugging (no central "event loop thread" to inspect).
Requires the runtime to be designed around CPS from the start;
retrofitting an existing event-loop runtime to CPS is rarely worth
the effort.

#### 2.5.6 Comparing the five

The patterns trade off along consistent axes:

| Pattern              | Shape          | Concurrency       | Cluster   | Latency           | Code cost |
|----------------------|----------------|-------------------|-----------|-------------------|-----------|
| 2.5.1 Sync           | line-by-line   | thread-level only | poor      | varies (blocking) | trivial   |
| 2.5.2 Classic server | recv/reply     | server pool       | poor      | bounded by IPC    | low       |
| 2.5.3 Actor          | msg handler    | per-actor         | excellent | port latency      | medium    |
| 2.5.4 Event loop     | poll/dispatch  | batched           | local only| dispatch + drain  | medium    |
| 2.5.5 Continuation   | CPS            | per-continuation  | local only| minimal           | high      |

For Telix's near-term consumers, the typical fit is:

- **Existing system servers** (init_srv, discovery_srv, namesrv,
  proxy_srv): 2.5.2, unchanged from today.
- **Linux personality server** (`linux_srv`): currently 2.5.2 with
  hand-coded async state machines via `PENDING_ASYNC`; would
  benefit from migrating to 2.5.4 (event loop) for the
  many-concurrent-Linux-processes case.
- **Distributed-service substrate** (proxy_srv, discovery_srv when
  routing cross-node): inherently 2.5.3 — port-message delivery is
  what makes cluster routing transparent.
- **A future Frankenstein language runtime** with first-class
  closures: 2.5.5 (continuation passing), to take advantage of the
  activation-aware Perceus demotion protocol.
- **Simple Telix-native binaries** (test tools, init helpers):
  2.5.1, the blocking convenience wrappers from §3.1.

Different activations within the same process can use different
patterns; a single Frankenstein-compiled program might use 2.5.5
for its main computation while invoking a Telix server via 2.5.2
for capability operations and the network stack via 2.5.4 for
high-throughput packet I/O. The ABI doesn't constrain the mix.

### 2.6 Parent-Constructed Child Tasks

Orthogonal to the runtime-model choice above, the spawning interface
itself follows a *parent-constructs-child* pattern: the spawning
task uses ordinary userspace operations to configure the to-be-spawned
child's initial state — capability table, IPC endpoints, initial
activation entrypoint, ring registration, upcall handler
registration, file-descriptor inheritance — *before* the child runs
any instruction. The child wakes up fully configured; there is no
`init()` phase in the child where it queries the kernel for what
it needs.

This is the seL4 / Genode pattern (the parent constructs the child's
entire cap space and the child runs with exactly what it has),
generalised from Plan 9's `rfork` (sharing/non-sharing flags) and
POSIX's `posix_spawn` with file actions (parent-side `dup2`,
`chdir`, `sigaction` etc. applied before the child runs).

Concretely on Telix the existing `sys_spawn` evolves to take a
parent-constructed initial-state descriptor: a list of capabilities
to populate the child's cap table with, an initial entry frame
(pc/sp/argv/envp), and — under the new ABI — pre-configured ring
addresses and the initial continuation/upcall registrations the
child should boot with. The parent has full authority over what the
child can do and which entrypoints it can be activated at; the child
has no need to call back into the kernel for setup.

The combination with the continuation-passing runtime model is
particularly clean: a child task can be configured to receive its
first activation as a kernel upcall into a parent-registered
entrypoint, with the parent's chosen rings and continuation table
already mapped. The child literally never executes an "I am starting
up" code path of its own. This is the shape modern capability
kernels favour, and Telix's existing capability model
(`kernel/src/ipc/call_reply.rs`'s generation-counted reply caps,
the per-task `aspace_id` / cap table) already supports it.

This pattern remains valuable under the event-loop runtime model
too — the parent simply registers the child's initial activation as
a long-running event loop instead of a one-shot continuation — but
it shines most where the child's lifetime is a finite sequence of
continuations rather than a perpetual loop.

---

## 3. The Syscall Conversion

### 3.1 What Each Syscall Becomes

A current blocking syscall such as:

```rust
let result = ipc_send_recv(endpoint, request)?;
process(result);
```

becomes a pair of operations: a non-blocking submission and a
deferred completion retrieval.

```rust
let handle = ring_submit(IPC_SEND_RECV, endpoint, request)?;
// ... thread can do other work or wait ...
let completion = ring_wait_handle(handle, timeout)?;
process(completion.result);
```

For code that wants the original blocking semantics, a thin library
wrapper preserves the API:

```rust
fn ipc_send_recv_blocking(endpoint: Endpoint, request: Request) -> Result {
    let handle = ring_submit(IPC_SEND_RECV, endpoint, request)?;
    ring_wait_handle(handle, NEVER)?.result
}
```

For code using the continuation-passing model (§2.5), the same
operation is expressed by registering a continuation at submission
time and never explicitly waiting:

```rust
ring_submit_with_continuation(IPC_SEND_RECV, endpoint, request,
    |completion| process(completion.result))?;
// activation returns to its scheduler; the closure runs on whichever
// activation receives the completion upcall.
```

For the event-loop model, the runtime maintains a handler table and
the top-level loop dispatches by handle:

```rust
let handle = ring_submit(IPC_SEND_RECV, endpoint, request)?;
handler_table.register(handle, |completion| process(completion.result));
// ... event_loop() elsewhere pulls completions, dispatches by handle ...
```

All three wrappers are implemented in the userspace runtime library,
not in the kernel. The kernel sees only ring operations and (for
the continuation form) the upcall registration that turns each new
CQ entry into an immediate handler invocation.

### 3.2 What Stays Synchronous

Not every operation benefits from the ring interface. Operations that
should remain synchronous (direct register-based calls) include:

- **Capability lookup and validation operations** that are extremely
  fast and self-contained. The submit/complete round-trip would add
  overhead disproportionate to the operation cost.
- **State-changing operations on the calling thread itself.** Setting
  thread-local registers, exiting the thread, modifying the thread's
  own scheduling parameters. Deferring these complicates the
  userspace runtime's bookkeeping because it must model whether the
  operation has actually taken effect.
- **Polling/peek operations on the rings themselves.**
  `ring_peek_completion()` to check if there are completions without
  sleeping must be synchronous; it's the primitive userspace uses to
  drive the event loop.

These remain as direct synchronous syscalls, distinct from the ring
interface. The set of synchronous syscalls is small — perhaps a dozen
operations — and they coexist with the ring-based asynchronous
interface.

### 3.3 Multi-Stage Operation Semantics

Some operations internally consist of multiple stages (e.g., an IPC
operation involving capability lookup, message routing, and delivery
to the destination). Under the blocking model, all stages happen
during the syscall. Under the asynchronous model, the submission
triggers the operation; the completion fires only after all stages
finish. The semantics are equivalent but the timing observable to
userspace differs — the calling thread regains control immediately
after submission, before the operation has actually completed.

This is the same model as io_uring and presents the same
considerations: userspace must not assume that a submitted operation
has taken effect until its completion arrives.

---

## 4. The Linux Personality Server Connection

### 4.1 The Concurrency Problem

The Linux personality server translates between Linux syscall
semantics and Telix message semantics. Each Linux process running
under the personality server makes blocking Linux syscalls; the
personality server must service these syscalls by communicating with
Telix services (filesystem servers, network servers, etc.) and
returning results to the Linux process.

Under a blocking Telix syscall interface, the personality server
faces a difficult concurrency design:

- **One Telix thread per Linux thread:** Each Linux thread blocks in
  the personality server while its syscall is being serviced. This
  works but ties up many Telix threads, one per outstanding Linux
  syscall. Scaling is limited by the kernel thread count and the
  per-thread memory cost.
- **State machine per Linux thread, multiplexed over a thread pool:**
  The personality server uses async I/O internally (epoll-equivalent
  or careful continuation passing) to handle many Linux threads with
  few Telix threads. This requires implementing concurrency
  primitives in userspace on top of the blocking Telix interface,
  with all the complexity that entails.
- **Hybrid approaches:** Some operations use blocking Telix threads,
  others use async state machines. This is the most common pragmatic
  choice but has the complexity of both alternatives.

Active work on the personality server has been addressing this
through various concurrency mechanisms layered on the blocking Telix
interface.

### 4.2 How Completion-Based Telix Resolves This Naturally

Under the completion-based Telix interface, the personality server's
structure can take either runtime shape from §2.5. Both eliminate
the blocking-thread-per-Linux-syscall problem; they differ in how
the work is dispatched.

**Event-loop shape** (the natural fit for the personality server's
current style):

- One Telix thread (or a small pool, one per activation) running
  the personality server's event loop.
- A state machine per Linux thread, recording what Linux syscall is
  in progress, what Telix operations have been submitted to service
  it, and what return value to provide to the Linux thread when
  servicing completes.
- The event loop reads completions from the Telix completion ring,
  looks up which Linux thread is waiting for each completion,
  advances that Linux thread's state machine, and either submits
  more Telix operations (if the Linux syscall requires multiple
  stages) or returns the final result to the Linux thread.

**Continuation-passing shape** (lower per-syscall latency, no
central loop):

- The personality server has no top-level loop. Each Linux process
  is represented as a chain of continuations; the entry point for
  each Linux syscall arrival is itself a continuation that the
  kernel invokes via upcall when a Linux process's syscall message
  arrives on the personality port.
- The "state machine per Linux thread" is encoded as the closure
  data carried by each in-flight continuation. When the personality
  server submits a Telix operation to service the Linux syscall, it
  registers the next-step continuation with the submission; on
  completion, the kernel dispatches directly into that continuation
  on the appropriate activation.
- The transition from "Linux syscall arrived" to "Linux syscall
  replied" is a chain of activation entries, never a poll loop.

Either way, the personality server never blocks except (in the
event-loop case) on the explicit ring wait. It services many
concurrent Linux syscalls with a small, fixed number of Telix
threads. The state machine per Linux thread is exactly the
bookkeeping required to model Linux's blocking semantics — it
cannot be avoided, but it's no longer in addition to a Telix-level
concurrency mechanism.

The choice between the two shapes for the personality server can
be made empirically once both are buildable. The event-loop shape
is closer to the current `linux_srv` architecture (commit
`4569f0d` extends its `PendingAsyncKind` table); the
continuation-passing shape is more invasive to introduce but
cleaner if measurements show the per-completion dispatch overhead
matters for the personality server's typical workload (many short
syscalls, modest in-flight depth).

### 4.3 Why This Is More Fundamental Than Layered Concurrency

The current layered approaches add a concurrency mechanism in the
personality server on top of the blocking Telix interface. They work,
but they involve solving the same async/event-driven problem that
the Telix kernel could solve once and provide to all of its users.

When the Telix interface is itself completion-based, the personality
server is just one of many consumers of that interface. The same
mechanism that serves the personality server's concurrency needs
serves the filesystem server's concurrency needs, the network
server's concurrency needs, and the needs of every sophisticated
runtime running on Telix. The concurrency machinery exists in one
place (the kernel ring infrastructure and the userspace runtime
library) rather than being reinvented in each server.

The Linux personality server stops being a special case requiring
its own concurrency design and becomes another application of the
standard Telix programming model.

---

## 5. Implementation Scope

### 5.1 Kernel Changes

**Ring data structure management.** New per-thread or per-activation
ring buffers in shared memory. Lock-free head/tail pointer management
with appropriate memory barriers. Approximately 500–1000 lines of new
code.

**Submission entry point.** Replace the syscall entry point with a
ring drainer that reads submission entries and dispatches to the
appropriate handlers. The handlers themselves remain largely
unchanged — they no longer return results in registers but instead
enqueue completion entries. Roughly equivalent code size to the
existing syscall dispatch.

**Completion delivery.** Each syscall handler is modified to enqueue
a completion entry when the operation finishes. For synchronous
operations (immediate completion), this happens at the same point
where the handler would currently return. For asynchronous
operations (those that wait for external events like IPC replies or
I/O completion), the completion is enqueued when the awaited event
fires. Mechanical modification across all syscall handlers —
substantial line count but low conceptual complexity per handler.

**Wait primitives.** New kernel code implementing `ring_wait` and
`ring_wait_handle`. These suspend the calling thread until the
relevant condition is met. Approximately 200–500 lines.

**Upcall delivery mechanism.** Kernel infrastructure for preempting
userspace execution to deliver an upcall, transferring control to
the registered handler with appropriate context (faulting address,
instruction pointer, etc.). Per-process upcall handler registration.
Approximately 500–1000 lines.

**Per-thread/per-activation initialization.** Setting up rings during
thread creation. Cleanup during thread destruction. Approximately
200–300 lines added to existing thread management code.

Total kernel changes: approximately 2,000–5,000 lines of new or
modified code. Most modifications are mechanical (changing return
paths in syscall handlers); the genuinely new code is the ring
infrastructure, wait primitives, and upcall delivery.

### 5.2 Userspace Runtime Library Changes

**Low-level ring primitives.** Functions to submit entries, peek for
completions, drain completions, wait for completions. Direct mapping
to the kernel ring interface. Approximately 500 lines.

**Blocking convenience wrappers.** Implementations of the existing
syscall API on top of submit-then-wait. Mechanical wrapping of each
syscall. Approximately 1000–2000 lines (one wrapper per syscall,
mostly boilerplate).

**Event loop and dispatcher.** A library-provided event loop that
polls or sleeps on the completion ring, dispatches completions to
waiters, and integrates with upcall handlers. Used by sophisticated
runtimes and the personality server. Approximately 500–1000 lines.

**Upcall handler registration and default handlers.** Userspace
infrastructure for registering handlers and providing reasonable
defaults for unhandled upcall types. Approximately 200–500 lines.

Total userspace library changes: approximately 2,000–4,000 lines.

### 5.3 Consumer Updates

**Existing system servers** (filesystem servers, block device server,
etc.) continue to work via the blocking convenience wrappers. No
required changes for correctness, though they can be progressively
converted to use the ring interface directly for better concurrency.

**The Linux personality server** is reorganized around the event loop
pattern described in §4. This is a substantial refactoring of the
personality server but the result is significantly simpler than the
current layered concurrency approach.

**Sophisticated language runtimes** (Frankenstein's runtime when it
materializes, future GHC ports, etc.) are designed against the ring
interface from the start.

---

## 6. Design Decisions

### 6.1 Ring Granularity: Per-Thread vs. Per-Process

**Per-thread rings:** Each thread has its own SQ/CQ pair. No
synchronization needed within a thread (it's the sole producer of its
SQ and sole consumer of its CQ). Higher memory overhead (rings per
thread × ring size).

**Per-process rings:** All threads in a process share one SQ/CQ pair.
Lower memory overhead. Requires synchronization among threads
accessing the rings, partially defeating the lock-free design.

**Per-activation rings:** If the kernel grants activations rather
than scheduling traditional threads, each activation has its own
rings. Conceptually clean — each unit of execution has its own event
stream.

io_uring takes the per-process (actually per-file-descriptor)
approach with userspace responsible for any required synchronization.
The decision for Telix should be guided by the typical usage pattern:
if each Telix thread has its own logical work stream, per-thread
makes sense; if Telix threads serve as workers drawing from a shared
queue of logical tasks, per-process makes sense. Given that
sophisticated runtimes typically have one OS thread per activation
and many green threads multiplexed on each, per-activation aligns
naturally.

### 6.2 Synchronous Versus Asynchronous Per Operation

Each existing syscall must be classified:

- **Always asynchronous:** IPC send/recv, memory map (when backed by
  file or device), block I/O, network I/O, message delivery between
  processes, anything that involves waiting for an external event.
- **Always synchronous:** Capability operations that complete in
  bounded time without waiting, ring peek operations, thread state
  changes affecting the caller itself.
- **Either:** Some operations (memory map for anonymous memory,
  certain scheduling operations) could go either way. The decision
  is per-operation based on whether the typical use case benefits
  from async semantics.

This classification is an early design task — the wrong choice for
any individual operation can be fixed later, but it's helpful to
have a default for each.

### 6.3 Handle Management

Handles correlate submissions with completions. Options:

**Userspace-chosen handles:** Userspace provides a value when
submitting; the kernel echoes it back in the completion. The kernel
doesn't track handles at all. Simplest. Requires userspace to ensure
handle uniqueness for outstanding operations. ABA problems are
userspace's responsibility.

**Kernel-assigned handles with generation counters:** The kernel
returns a handle from submission. The handle is a slot index plus a
generation counter, preventing ABA. Adds kernel-side handle tracking
but provides better safety.

io_uring uses userspace-chosen handles (the `user_data` field). This
is the simpler choice and probably the right default.

### 6.4 Overflow Handling Per Destination

With completion delivery as a per-submission destination choice
(§2.1), overflow ceases to be a single design decision and becomes
a per-destination question. Each destination has its own overflow
semantics, which is one of the reasons to make the destination
choice per-submission rather than process-wide.

- **Destination 1 (sync return)** — no overflow concept. The
  operation completes inline; there is no queue to fill.

- **Destination 2 (reply cap)** — overflow is "reply-slot pool
  exhausted," already handled by `kernel/src/ipc/call_reply.rs`
  with its generation-counter allocator. Either submission fails
  with a clear error or the caller waits for a slot to free.
  Telix has years of operational experience with this case.

- **Destination 3 (port message)** — overflow is "destination
  port queue full." Existing `send_nb` returns EAGAIN; `send`
  blocks the caller. Standard behaviour; well-understood by every
  existing Telix consumer.

- **Destination 4 (ring entry)** — the genuinely new overflow
  case. When the submission ring (SQ) fills, the submitter has
  three options:
  - *Block* the submitter until ring space is available.
  - *Return error* and the submitter handles it explicitly
    (typically by waiting for some completions to clear).
  - *Wait then submit* — a combined operation that drains some
    completions if needed before submitting.

  When the completion ring (CQ) fills, the kernel has the harder
  problem (the operation has already completed somewhere
  internally; there's no "wait" option). io_uring's answer is an
  overflow buffer in kernel memory, which makes laggy consumers
  grow kernel memory unboundedly. The cleaner answer here is
  *backpressure at submission time*: when the CQ is full, the
  kernel refuses to accept new submissions destined for that ring
  until the CQ drains. This bounds the total in-flight work per
  ring to (SQ size + CQ size), making memory accounting
  predictable.

  The right answer is to provide all three submission options for
  SQ-full and the backpressure rule for CQ-full. Most callers use
  a wrapper that picks the appropriate one based on context.

- **Destination 5 (direct upcall)** — overflow is "the
  registered continuation can't be invoked right now" (e.g., the
  target activation is unavailable). The kernel either parks the
  completion until an activation is available, or invokes a
  fallback upcall (signalling "your upcall fired with no
  activation to receive it") that the runtime registers
  separately. The choice is per-process at upcall registration
  time.

The fact that overflow is *per-destination* means ring overflow
(the most architecturally novel case) only constrains workloads
that opt into ring delivery. Workloads that use the other four
destinations have overflow semantics already proven in Telix or
elsewhere.

### 6.5 Default Completion Destination per Operation

With destinations as a per-submission choice, each syscall in the
ABI also has a *default* destination — what happens if userspace
submits without explicitly specifying. The defaults should follow
each operation's natural use case:

- **Capability operations, thread-state queries, ring-peek
  operations**: default destination 1 (sync return). These complete
  in bounded time; async overhead would dominate.

- **IPC send/recv on a port**: default destination 2 (reply cap)
  for `call`-style operations; destination 3 (port message) for
  fire-and-forget sends. Matches existing Telix semantics.

- **File I/O, block I/O, network I/O**: no clear single default —
  these are the operations where the destination choice matters
  most. Suggest defaulting to destination 2 (reply cap) for
  backward compatibility, with high-throughput consumers
  explicitly opting into destination 4 (ring entry).

- **Page-fault handling operations** (user-managed mmap regions):
  default destination 5 (upcall) — these are naturally upcall-shaped.

The defaults can be overridden per-submission. The point of having
defaults is that simple programs (using the destination 1 / 2
defaults) don't need to know about the multi-destination machinery
at all; the design degrades gracefully into "Telix as it is today"
for callers that don't care.

### 6.6 Runtime Pattern Choice

With five completion destinations (§2.1) come five natural runtime
patterns (§2.5). The choice is per-activation and per-submission;
the kernel ABI doesn't constrain the mix.

The design decision is therefore not "which pattern does Telix
prescribe?" but "how minimal a kernel ABI suffices to support all
five?" The answer is: the kernel exposes the five destination tags
plus the ring data structures (for destination 4) plus the upcall
registration table (for destination 5). Destinations 1, 2, and 3
reuse existing primitives unchanged.

Per-handle continuations (the destination 5 use case) could
alternatively be a kernel-tracked concept (each SQ entry carrying
a continuation pointer the kernel remembers and invokes directly
on completion), but pushing this into the kernel ABI doesn't add
expressiveness: a per-process upcall-on-CQ-edge + userspace-side
continuation table is functionally equivalent and keeps the
kernel ABI minimal. The kernel just delivers "completion arrived";
the userspace runtime knows how to dispatch.

### 6.6 Cancellation

Best-effort cancellation by handle. The kernel attempts to cancel the
operation if it hasn't yet started. If it has started, cancellation
may not succeed. Either way, a completion event is eventually
delivered for the handle (possibly with a "cancelled" status).

This matches io_uring's `IORING_OP_ASYNC_CANCEL` behavior and is the
only semantically clean approach when operations can be in arbitrary
stages of execution.

---

## 7. Risks and Mitigations

**Memory ordering correctness in ring access.** The lock-free ring
access (destination 4 only) requires careful use of memory barriers.
Getting this wrong causes hard-to-reproduce races. Risk is scoped
to ring-using workloads; the other four destinations don't use
lock-free shared memory. Mitigation: use well-tested ring data
structures (e.g., the same approach as io_uring's verified
implementation), write specifications, formally verify the ring
access patterns with Verus.

**Performance overhead for fast operations.** Routing through any
async destination (rings, ports, upcalls) is more work than a
direct synchronous syscall for operations that complete immediately.
Mitigation: keep truly fast operations on destination 1 (sync
return) by default (per §6.5), so the destination machinery is
opt-in for operations that actually benefit.

**Userspace complexity for simple programs.** Programs that don't
have an event loop or actor structure should use destination 1
(sync return) or destination 2 (reply cap), which both look like
ordinary syscalls. The other destinations are opt-in. Simple
programs don't pay for complexity they don't use.

**Migration complexity for existing servers.** Existing system
servers work but aren't optimized for the new interface. Mitigation:
blocking wrappers preserve correctness; progressive conversion to
direct ring use as servers benefit from it.

**Upcall delivery races.** An upcall arriving while the userspace
activation is in a critical section can cause subtle bugs in the
handler. Mitigation: provide upcall masking primitives (a
per-activation flag that temporarily defers upcalls), well-defined
reentrancy rules for upcall handlers.

**Handle exhaustion.** Per-thread handle space is bounded; sufficient
submission burst could exhaust it. Mitigation: size handle space
generously, return clear errors when exhausted, document the limit
for runtime sizing.

---

## 8. Conclusion

Converting Telix's native syscall interface to a completion-based
asynchronous model — with completion delivery as a per-submission
choice across five destinations (sync return, reply cap, port
message, ring entry, direct upcall) — is a bounded engineering
effort that produces an architectural foundation more amenable to
diverse high-concurrency workloads than the current blocking
interface. Approximately 4,000–9,000 lines of new or modified code
across the kernel and userspace runtime library; most of the
destination types reuse existing Telix primitives (capability
slots, port queues, reply caps), so the genuinely new mechanisms
are the shared-memory ring layer and the generalised upcall
registration table.

The Linux personality server's concurrency challenge dissolves
naturally under this interface: rather than layering concurrency
machinery on top of a blocking kernel, the personality server
uses whichever of the five runtime patterns fits its workload
(typically the event-loop pattern for many-concurrent-Linux-process
service). Other sophisticated consumers (language runtimes using
the continuation-passing pattern, distributed service proxies
using the actor pattern, high-throughput I/O servers using the
event-loop pattern) each pick the destination mix that fits.

Cluster operation is no longer a special case requiring a separate
substrate: port-message destination delivery routes transparently
through proxy_srv to remote nodes, and the calling code doesn't
know whether the completion came from local or remote. The same
kernel ABI serves single-host and cluster scenarios.

The design is well-anchored in prior art (io_uring, Windows IOCP,
K42, Mach continuations, Erlang/BEAM, Singularity's contract
channels) without being a direct port of any single system. It is
achievable with the current Telix codebase, does not require
restructuring the kernel's internal architecture, and preserves the
existing syscall semantics — only the invocation and result
delivery mechanism changes. The conversion is a candidate for
serious near-term work once the existing kernel stability and I/O
infrastructure milestones are sufficiently complete.

---

## Appendix A: Grounding to the Current Codebase

This appendix maps the proposed design onto what is already in the
tree at the time of writing (commit `4569f0d`). The short version:
most of the IPC primitives the design relies on already exist; the
genuinely new work is the shared-memory ring layer, generalised
upcall plumbing beyond the existing signal path, and a `ring_wait`
primitive that subsumes today's `port_set_recv`. The Linux personality
server is already structured around a partial form of the
state-machine pattern described in §4.

### A.1 Existing primitives the design can build on

The codebase already supports the message + correlation + reply
pattern that completion rings would generalise:

- **Per-thread message queue with cap-bearing recv.** `sys_send_nb`
  / `sys_recv_with_cap` / `sys_recv_with_cap_nb` in
  `kernel/src/syscall/handlers.rs` already give us non-blocking
  submit and recv with a one-shot reply cap. A ring-based dispatcher
  would internally call into the same `ipc::port` code; the only
  delta is that submission/completion are queued in shared memory
  instead of register-passed.
- **Multi-port wait.** `sys_port_set_create` +
  `port_set_recv` already let one thread sleep across multiple
  ports — `linux_srv` uses this to combine its main service port
  with `BACKEND_REPLY_PORT`. The proposed `ring_wait`
  generalises this to "sleep on the CQ for this activation."
- **Generation-counted reply caps.** `kernel/src/ipc/call_reply.rs`
  already maintains a slot table with generation counters; the
  proposed kernel-assigned handle scheme (§6.3) is structurally the
  same machinery applied to ring entries.
- **Adaptive radix tree for port lookup.** `kernel/src/ipc/art.rs`
  gives O(log n) port → object lookup; a per-thread ring registry
  fits the same pattern.
- **send_nb with 4 data words.** `userlib/src/syscall.rs::send_nb_4`
  is exactly the "submit, do not block, kernel echoes correlation
  back later" primitive in single-call form. The ring extends this
  from "one in-flight per recv loop" to "as many as the ring holds."
- **PENDING_ASYNC continuation table in `linux_srv`.** The
  `PendingAsync` struct and dispatch in
  `userlib/bin/linux_srv.rs` (UDS_ACCEPT_ASYNC,
  IRFS_IO_READ_ASYNC, IRFS_IO_CONNECT_ASYNC at commit `4569f0d`) is
  precisely the per-Linux-thread state-machine pattern §4.2
  describes — implemented today in userspace on top of the message
  ABI, but the same shape.

### A.2 What is genuinely new

Of the five completion destinations from §2.1:

- **Destinations 1, 2, 3** (sync return, reply cap, port message)
  reuse existing Telix primitives unchanged. The "new" work is just
  the per-submission *destination tag* — a small enum the kernel
  reads from the SQ entry and dispatches against.
- **Destinations 4 and 5** (ring entry, direct upcall) are the
  genuinely new mechanisms, with the kernel-side machinery sketched
  below.

Specifically:

- **Shared-memory rings (destination 4).** Today, every IPC submission
  is a syscall (`sys_send_nb`); even non-blocking calls trap into
  the kernel. The ring design moves the submit/peek hot path to
  userspace-only memory accesses, with a syscall only on
  ring-empty/ring-full or explicit wait. That is the qualitative
  jump in throughput. Only workloads opting into destination 4 use
  this path; everything else routes through the existing
  primitives.

- **A `ring_wait` primitive.** `port_set_recv` is close but
  port-keyed; the new primitive is CQ-keyed and integrates with
  `ring_wait_handle` for the blocking-wrapper case (§3.1).

- **Generalised upcall delivery (destination 5).** A signal-style
  upcall path exists for Linux personality processes (sigaction etc.
  plumbed in `linux_srv` and the kernel's signal-frame setup), but
  it is Linux-personality-specific and not exposed to Telix-native
  consumers. The proposed upcall mechanism is a single, native
  facility — kernel writes a frame, transfers control to a
  registered handler, returns to the original context on handler
  exit. The kernel-side mechanics are mostly present; the API
  surface and per-process registration table are new.

- **Per-thread/per-activation ring registration in `Thread`.** Adds
  ring base/length fields to the `Thread` struct in
  `kernel/src/sched/thread.rs`, plus init in
  `scheduler::alloc_thread_id` and teardown in the thread-death
  path. Only allocated when destination 4 is in use. Mechanical but
  touches every thread-create site.

- **The submission-side destination tag and dispatch table.** A
  small kernel-side switch in the submission handler that reads the
  destination tag and routes the eventual completion to the
  appropriate path. The handler implementations themselves don't
  change — they still produce a result; the dispatch table just
  decides where it goes.

### A.3 Capability semantics in a handle-based world

Telix's existing reply caps are unforgeable: a reply cap is a
generation-stamped slot index that the kernel verifies on every
`reply()`. The proposed userspace-chosen handle (§6.3) does NOT have
this property — it is a userspace-namespaced correlation tag, not a
capability.

This is fine for the submitter's correlation between its own SQ
entries and CQ entries (the kernel echoes whatever handle userspace
chose). But it means **the ring interface does not by itself replace
the existing capability check on each operation.** Each SQ entry must
still carry, for example, the destination port (a real cap) and the
kernel still validates that cap on submission. The handle is purely
client-side bookkeeping.

In other words: rings are an ABI for *invoking* syscalls, not a
replacement for the capability system that gates *which* syscalls a
caller may invoke on which objects. The existing cap-handle
arguments stay where they are; only the call-and-return mechanism
changes. (io_uring on Linux works the same way — operations still
take file descriptors, which Linux gates as kernel-owned caps.)

### A.4 The clusterability angle

The user asked whether this design has implications for distributed
operation. There are several:

1. **Ring entries are messages by shape.** A submission entry is
   `(op, handle, args...)`; a completion entry is `(handle, result,
   data...)`. Both fit Telix's existing `Message` struct in
   `kernel/src/ipc/message.rs`. A "ring" whose backing memory is
   actually a network-attached queue (managed by something like the
   existing `proxy_srv` / `router_srv` / `discovery_srv` chain)
   would let a process on node A submit to a service on node B
   without local syscall semantics changing at all.
2. **Handle-based correlation extends naturally.** Userspace-chosen
   handles already work across address spaces (the kernel just
   echoes them back). A 64-bit handle with a node-prefix scheme
   (top 16 bits = origin node, low 48 bits = local correlation)
   gives globally-unique handles without a coordination service.
3. **Per-activation rings are a transport-agnostic abstraction.**
   The kernel currently does the SQ→handler dispatch; a remote
   variant would have a local "proxy ring" whose SQ entries are
   forwarded over the wire, with completions written into the local
   CQ when remote replies arrive. The userspace event loop never
   sees the difference. This is exactly what the existing
   `proxy_srv` does at the message level; ring-aware proxy is the
   evolution.
4. **Upcalls don't extend as cleanly.** Page faults and similar
   upcalls are inherently local-CPU events. A distributed system
   needs analogous remote events (e.g., "node X went away") but
   those are higher-level service events, not kernel upcalls. The
   ring path covers distributed I/O; the upcall path doesn't extend
   without separate cluster-membership infrastructure (which
   `discovery_srv` already provides today).
5. **The existing distributed strategy doc
   (`docs/telix_distributed_strategy.md`) already names
   `proxy_srv`-based forwarding as the route to clustering.** The
   ring interface is complementary: it lowers the local IPC cost
   enough that proxy_srv's per-message forwarding is no longer a
   relative-overhead concern.

In short: clusterability isn't blocked by the current blocking ABI,
but the ring design makes "this process is talking to a local kernel"
vs. "this process is talking to a proxy_srv that forwards remotely"
indistinguishable to userspace — which is the property a cluster
substrate wants.

### A.5 Migration path (incremental, not flag-day)

The Linux personality path inside `linux_srv` already uses the async
pattern at message granularity for the operations where it matters
most (UDS accept/recv, IRFS connect/read). A reasonable phased
migration of the *native Telix* ABI on top of that:

1. **Phase 1 — co-existence.** Add ring-based variants of
   `sys_send_nb` and `sys_recv_with_cap` as new syscall numbers.
   Per-thread rings live alongside the existing message queue. No
   existing code breaks.
2. **Phase 2 — runtime library default.** `userlib/src/syscall.rs`
   wrappers switch to the ring path when a ring exists, fall back to
   the syscall path when one doesn't. Existing servers don't notice
   the change.
3. **Phase 3 — internal kernel handlers.** Move heavy-traffic
   internal handlers (the personality forwarding path, file-server
   reads, mmap) to produce completions instead of returning via
   `reply()`. The existing `reply()` path stays for callers that
   haven't migrated.
4. **Phase 4 — personality refactor.** `linux_srv`'s event loop
   converts to a single `ring_wait` instead of `port_set_recv` over
   service/reply port pair. `PENDING_ASYNC` becomes the natural
   shape of the per-Linux-thread state machine §4.2 describes.
5. **Phase 5 — deprecation.** Once all heavy callers are on rings,
   the original `sys_send` / `sys_call` paths can be marked
   deprecated and eventually removed.

The flag-day cost is high (touching every callsite); the incremental
path lets each subsystem move when it benefits, and the existing
blocking wrappers around `syscall::call` continue to work throughout.

### A.6 Continuation passing and parent-constructed children in the current tree

The two patterns introduced in §2.5 and §2.6 already have partial
precedent in the codebase, and the kernel ABI changes to fully
support them are mostly in service of regularising what's already
ad-hoc.

For **continuation passing** (§2.5), Telix's existing
exception-handler delivery — the kernel writes a fault frame and
transfers to a userspace handler — is structurally an upcall. The
Linux personality's signal-frame setup
(`userlib/bin/linux_srv.rs` plus the kernel-side signal entry) is
the same mechanic dressed in Linux semantics. The new piece is a
*native* per-process registration table — `kernel/src/sched/task.rs`
has `sig_actions` for Linux signals; the equivalent for native
upcalls (CQ-edge, page-fault, activation-availability) is a parallel
table with a small set of upcall types.

For **parent-constructed children** (§2.6), `sys_spawn` already
takes the new task's name, priority, and parent's choice of initial
arg — the parent is shaping the child. `personality_set` is the
existing inflection where the parent imposes a personality before
the child runs Linux code. Extending this to "the parent populates
the child's full cap table and initial ring/continuation state
before the child is resumable" is incremental:

- The child's cap table (today implicit in the task's aspace_id +
  port ownership) becomes parent-writable for the pre-start window.
- The child's initial frame (entry rip, stack, registers) is
  already parent-controlled via the spawn syscall.
- New: the parent registers the child's initial ring buffer
  locations and (optionally) a first-activation continuation that
  the kernel invokes when the child is started, rather than
  resuming at the spawn-syscall return.

Combining the two: a child task can be configured by its parent to
boot directly into a continuation handler with its rings already
mapped — no "child startup" code in the child's image is required.
This is the seL4/Genode pattern adapted to Telix's port/cap model.

The kernel ABI delta for both patterns is small relative to the
ring infrastructure itself: a few new syscalls (or new operations on
existing ones) for upcall registration and parent-side child setup.
The userspace runtime library is where the bulk of the new code
lives.

### A.7 Open questions surfaced by the codebase

- **Where do completions land when the receiver is parked in
  `block_current`?** Today the kernel wakes the recv'er via
  `wake_thread`; with rings the wake target is "any waiter on this
  CQ", which is essentially the same thing but needs the kernel-side
  CQ→thread mapping. Probably maps onto the existing
  `port_set_park` structure.
- **What does cancellation mean in the presence of a
  `CALL_REPLY_SERVER_DIED` cascade?** The current 30s vCPU-runtime
  timeout (see `project_layer1_call_reply_vcpu`) fires
  `abandon_for_interrupt` and walks the reply slot. The
  ring-equivalent is "write a Cancelled completion." The state
  machine is the same; the delivery mechanism changes.
- **How does `loom-balance-set` and the suspend/wake race
  (`project_suspend_wake_race`) interact with completion-ring wakes?**
  Probably the same atomic state machine, but worth a dedicated
  loom model before commitment — the existing `loom-park-state` test
  is the right starting template.
- **Does the proposed handle-exhaustion error path (§7) interact
  badly with the existing `EMFILE`-equivalent paths?** Each personality
  has its own fd-limit semantics; the ring handle limit is a separate
  resource and probably wants its own errno-equivalent so callers
  can distinguish.

These are surfaces for follow-up design rather than blockers.
