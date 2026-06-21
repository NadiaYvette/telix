# Telix Completion + Scheduler-Activation ABI — Design (draft)

Status: **draft / living document**. Captures decisions from the 2026-06-20 design
discussion; recommendations are marked **[rec]**, open questions **[OPEN]**.
Author scope: the *native* API/ABI. The Linux personality consumes these primitives
but keeps its own (fork/exec, blocking-syscall) surface — see §6.

## 1. Goals / non-goals

**North star consumer:** an M:N user-level runtime for an advanced PL (GHC / Koka /
Perceus-style) — async-everywhere green threads over a small set of kernel vCPUs. Design
the primitive for *this* hardest consumer; everything else is a simpler special case.

Goals:
- Completion-based (async submit/reap) IPC + IO that subsumes the current sync call/reply.
- Lightweight scheduler-activation upcalls sufficient for a user-level 2nd-level scheduler.
- Capability-clean: every transfer/grant rides the cap system; no ambient authority.
- Structurally avoid the sync-IPC fragility surface (recv_or_park park/unpark + DirectTransfer
  handoff races — the #198/#173 dispatch-consistency family that wedges the demo path). A CQ
  reaped by a running vCPU has no parked-frame handoff to race on.
- Draw on precedent for the mechanism (not novel there); novelty is the **microkernel ABI ×
  PL-runtime co-design** (Midori/"frankenstein" async-everywhere from language to syscall).

Non-goals (initially):
- Transparent M:N of *arbitrary blocking* code (legacy Linux apps stay 1:1 / on the legacy
  personality). The native model assumes the consumer makes voluntary blocking async.
- Replacing the legacy ABI on day one (see §7 migration).

## 2. Precedent (for attribution + organisation)

- **io_uring** — shared-memory SQ/CQ rings; batched async submit/reap; CQE can install a
  resource (ACCEPT/OPENAT → new fd, "direct descriptors"). Ergonomics model for the local
  fast path.
- **Zircon** — *channels* transfer bytes+**handles(caps)** atomically; *ports* aggregate
  async readiness as handle-less packets. We fold notify+transfer together (cap-bearing CQE)
  but keep a routable packet form for distribution.
- **Akaros** (Rhoden, Berkeley) — **the primary precedent for the execution model.** MCP gets
  vcores; `vcore_entry()` upcall = the activation; async syscalls via shared queues; **page
  faults reflected** to the user 2LS; cooperative preemption via `preempt_pending`. This is the
  matured ("lightweight") form of scheduler activations we target.
- **Anderson et al. 1992** — original scheduler activations (heavier: per-block fresh activation
  stacks, block/unblock upcalls). We adopt the *idea* (kernel↔2LS cooperation) in Akaros's
  lighter realization; async IO removes the per-block upcalls.
- **Datacenter threading** (Shenango / Caladan / Arachne) — core-granularity allocation +
  preemption signalling atop async IO; corroborates "async + preemption upcall, skip block
  upcalls."
- **K42** — dispatcher abstraction (a vCPU upcalled to run user threads); lineage for the
  per-vCPU entrypoint.

## 3. Transport (two tiers — both coexist)

Rationale: shared-memory rings are inherently **local** (mapped pages, not routable);
self-contained packets are **routable** (marshalable across address spaces and **nodes**) →
the natural substrate for the clustering/distribution pipeline.

- **Tier A — SQ/CQ rings [rec]:** per-vCPU (or per-task) Submission + Completion ring pair in
  shared memory (io_uring lineage). High-volume, batchable, local fast path.
  - **SQE:** `{ opcode, target_cap (handle), flags, inline_data | grant_desc, user_data }`.
  - **CQE (cap-bearing) [rec]:** `{ user_data, result, delivered_cap (handle|none), inline_reply }`.
    A completion both signals done *and* installs the resulting cap into the task's cap-space,
    handle returned inline — folds Zircon's port-notify + channel-transfer into one step.
  - Opcodes (initial): `send`, `recv`, `call` (= send + await-reply correlated by user_data),
    `reply`, `grant`, `revoke`, `timer`, `poll_cap`.
- **Tier B — routable port packets:** self-contained `{type, key, status, small payload, cap
  refs}` messages for the distributable path; a `call` may begin as a Tier-A ring submission
  locally and **degrade to a Tier-B routed message** when the peer is on another node.

**[OPEN]** ring sizing/placement (per-vCPU vs per-task); CQ delivery (pure poll at vcore_entry
vs optional notification); SQE/CQE exact layout + versioning; backpressure/full-ring policy;
cancellation + timeout semantics; how cap revocation interacts with in-flight SQEs referencing
the cap.

## 4. Execution / blocking model (lightweight scheduler activations, Akaros idiom)

The vCPU ("vcore") is the unit of kernel scheduling given to a process; the user 2LS multiplexes
green threads onto it.

- **Per-vCPU upcall entrypoint** (`vcore_entry`-style): when the kernel (re)starts a vCPU it
  enters user code here; the 2LS drains its **event ring** and picks a green thread.
- **Voluntary blocking → completions.** IO/IPC is async (SQ/CQ); a completion = "green thread T
  is runnable." No block/unblock upcalls needed for these.
- **Involuntary blocking → reflected events.** The one unavoidable case is the **page fault**
  (and a small set of IO a runtime can't intercept). Instead of parking the faulting thread and
  losing the vCPU, the kernel **reflects** the fault to `vcore_entry` with the faulting
  *continuation*; the 2LS runs another green thread; a completion is posted when the page is in.
  - **Telix hook [rec]:** the demand-paging path already makes faults async —
    `FaultResult::NeedPager{token} → pager::initiate_fault(token)` then parks. The SA change is
    to *reflect* rather than park: hand the 2LS the continuation + the pager token, post a
    completion on resolution. Reuses existing plumbing; no new pager subsystem.
- **Preemption.** `preempt_pending` word (shared) + a preemption upcall so the 2LS can checkpoint
  its current green thread and yield/relinquish the vCPU gracefully (and learn when it resumes).
- **Continuation representation [OPEN]** — how the faulting/preempted uthread's register state is
  snapshotted + resumed across a reflection. This is the genuinely fiddly piece. Options: kernel
  saves to a user-mapped uthread context struct (Akaros) vs a CQE-carried opaque blob.

ABI reserves a **fixed upcall-vector table** (room for: preempt, reflected-fault, reflected-IO,
and future block/unblock) so we can grow toward fuller SA only if a non-async consumer ever
demands transparent blocking — without an ABI break.

## 5. Capability integration

- SQEs name caps by handle (cap-space is the security boundary); the kernel validates rights per
  opcode (SEND/RECV/GRANT…), as today.
- CQEs *deliver* caps: the kernel installs the resulting cap into the receiver's cap-space and
  returns the handle inline (reply caps, granted pages, accepted connections).
- **[OPEN]** revocation vs in-flight: an SQE referencing a cap revoked before completion must fail
  cleanly (CQE error), not UB. Define the ordering.

## 6. Process lifecycle / spawn (fork-less)

Unix `fork`+`exec` implicitly carry: AS (COW clone), fd table, signal dispositions, cwd, umask,
credentials, session/controlling-tty — and run arbitrary setup code in the cloned AS between
fork and exec. A cap kernel has none of that implicitly; each becomes an **explicit cap passed
at spawn**.

**Native primitive [rec] — create-suspended, furnish via caps, start** (seL4/Zircon/Akaros):
1. `process_create` → caps to a *suspended* process: AS/VMAR, cap-space, main thread.
2. Map program segments into the child AS (ELF load) — **in a userspace loader, not the kernel**
   [rec] (microkernel minimality).
3. **Explicitly grant the bootstrap cap set** — stdio ports, namespace/VFS caps, identity,
   rlimit-equivalents. No implicit inheritance; the spawner enumerates what crosses (Zircon
   processargs / posix_spawn file_actions lineage).
4. Completion-substrate setup: allocate + map SQ/CQ rings into the child, register the vCPU
   upcall entrypoint + event ring, set initial vCPU count.
5. `process_start`.

This *is* the fork-between-exec flexibility without fork — the spawner furnishes the suspended
child through caps rather than running code in a cloned AS (cleaner + cap-safe).

**Linux personality layers Unix on top:** `fork` = `process_create` + COW-clone parent mappings
(**reuse existing COW groups**) + duplicate fd/cap table; `exec` = fresh AS + load + preserve
non-CLOEXEC. `posix_spawn` ≈ the native primitive directly. Unix process state (signal
dispositions, umask, pgid/sid) is personality-tracked, not kernel state.

**[OPEN]** kernel-set vs child-self-bootstrapped rings (lean: minimal kernel-set initial vCPU +
entry, child self-maps rings from a bootstrap cap — smallest kernel ABI); the bootstrap-cap
hand-off protocol (a well-known initial handle à la Zircon processargs).

## 7. Migration strategy (personality-staged — user's plan)

Telix dispatches syscalls by `personality_id`; the new model is **just another personality**, so
both ABIs coexist with no flag day:
- **Phase 0:** register a `completion` personality (SQ/CQ + upcalls). Legacy native stays default.
  Reimplement legacy sync `call`/`reply` as a thin wrapper over `submit`+`reap` where convenient.
- **Phase 1:** port the hot servers (compositor path, then linux_srv's internals) to native
  completion; A/B against legacy in the same boot.
- **Phase 2:** add the preemption + reflected-page-fault upcalls; validate with a toy M:N 2LS.
- **Phase 3:** port the GHC / Koka RTS IO-manager to the CQ; the PL runtime becomes the flagship
  consumer (paper).
- **Phase 4:** flip the default personality to `completion`; demote legacy to non-default.
- **Phase 5 (later, optional):** remove the legacy ABI once nothing depends on it (the Linux
  personality can keep using legacy/1:1 indefinitely if useful).

## 8. Validation

- **loom** models for the SQ/CQ producer/consumer + the upcall/event-ring + preempt races (the
  user bakes loom artifacts into every concurrency/lifecycle fix — do it here from the start).
- The completion model is expected to retire the recv_or_park / DirectTransfer race surface
  (#198/#173) by construction; track that as an explicit success criterion.
- Per-arch: the upcall/continuation path is arch-specific (frame snapshot/restore) — needs the
  cross-arch matrix (x86_64, aarch64, riscv64, loong, mips).

## 9. Open decisions summary (for the architect)

1. CQ delivery: poll-only vs optional notification. **[rec]** poll at vcore_entry; notification later.
2. Continuation representation for reflected faults/preemption (§4). **biggest fiddly piece.**
3. Ring granularity (per-vCPU [rec] vs per-task) + sizing + backpressure.
4. Cap revocation vs in-flight SQEs (§5).
5. Kernel-set vs child-self-bootstrapped spawn (§6).
6. Tier-B packet format + the local→remote degrade path (clustering).

## Appendix A — Phase-0/1 scoping (2026-06-20, read-only survey)

- **Recv conversion surface:** `recv_with_cap` is the dominant server-recv API (~53 call sites in
  userlib). No single shared server-loop helper exists (servers hand-roll loops, e.g.
  initramfs_srv `server_loop`). ⇒ Phase 1 should introduce a `completion_server_loop` helper and
  convert servers to it, rather than 53 ad-hoc edits.
- **CORRECTION to §7 (personality framing):** Telix's existing `personality` mechanism
  (kernel/src/syscall/personality.rs) means "a task with a non-native personality_id has its
  syscalls FORWARDED to a userspace personality server via IPC" (the Linux personality = linux_srv,
  via SYS_PERSONALITY_REGISTER + a port). The completion ABI is the OPPOSITE shape: a NATIVE,
  in-kernel syscall surface (submit/reap handled by the kernel directly). So "completion = a new
  personality" means: a new **dispatch KIND** (in-kernel completion syscall table) selected by
  personality_id, coexisting with (a) legacy native and (b) forward-to-server (Linux). It is NOT a
  SYS_PERSONALITY_REGISTER of a server port. The migration still uses personality_id as the
  selector (no flag day), but the dispatch hook is in the kernel syscall path, not the forwarding
  registry. Confirm the exact selector plumbing when coding Phase 0.

## §9 — Decisions LOCKED (Phase-0 trio, 2026-06-20, with the user)

- **§9.1 CQ delivery:** make-runnable wake, **single CQ per server**. Userspace peek + blocking
  `reap_wait` with **transition-only (empty→non-empty) wakes** and a **re-check-before-sleep**
  lost-wakeup guard. eventfd-style *multiplex* (wait on several rings/timers) deferred.
- **§9.3 ring granularity:** **per-(v)CPU SPSC rings; per-worker CQs for pools** (kernel steers
  requests across workers — also dissolves the multi-consumer wedge by construction). Power-of-2
  depth (~128 default). **Size-to-rarely-hit + kernel overflow-backlog backstop** so completions
  are never lost; SQ-full → "would block".
- **§9.4 cap revocation vs in-flight:** **validate-at-use + generation-tagged handles +
  fail-clean CQE (`EREVOKED`)**; revoke stays cheap/non-blocking (mark dead + bump generation via
  the existing CDT walk). Eager cancel-on-revoke = optional later nicety. VERIFY when coding: do
  Telix cap-space handles already carry a generation? If not, add it (the one prerequisite).

Still OPEN (Phase-2+, NOT needed for the server fix): §9.2 continuation representation,
§9.5 spawn bootstrap (kernel-set vs child-self-bootstrap), §9.6 Tier-B packet format + degrade.
