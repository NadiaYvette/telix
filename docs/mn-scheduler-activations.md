# M:N threading via lightweight scheduler activations — synthesis & integration

Status: **design / living**. This doc is the *connective tissue* between the
existing M:N / scheduler-activation material and the **now-implemented**
completion ABI. It deliberately does not re-derive the ABI; it adds three things
the other docs lack: (1) the M:N gains stated plainly, (2) the **modern UMCG /
switchto** variant (the lineage in our docs stops at Akaros), and (3) how the
activation layer maps onto **what we have actually built** (the completion ring +
ring lifecycle) plus the concrete new kernel pieces.

Read alongside:
- `completion-abi-design.md` §4 — the lightweight-SA execution model (Akaros idiom) + the ABI decisions. *The design.*
- `completion_based_syscalls.md` §2.4 / §2.5 — the upcall mechanism + the five completion-delivery destinations. *The detail.*
- `scheduler_design.md` "Scheduler Activations" — the kernel scheduler's view (an upcall is a scheduling event; the handler is implicitly top-priority). *Scheduler integration.*
- `activation_perceus_demotion.md` — why a Perceus/Koka RTS specifically wants the upcalls (precise reference-count demotion). *PL-runtime motivation.*
- `completion-ring-process-lifecycle.md` — the ring lifecycle (Phase A, built) the upcall-stack lifecycle will reuse.

## 1. The M:N gains (why this is worth the kernel surface)

M:N = many user threads ("uthreads"/green threads/fibers) multiplexed over a
small set of kernel-scheduled carriers (vcores). Concretely it buys:

- **Cheap switching.** A uthread switch is a userspace function call + register
  swap (~ns); a kernel thread switch is a syscall + privilege transition + TLB/
  cache effects (~µs). A server fanning out 10⁵ in-flight requests can't afford
  a kernel thread each.
- **Concurrency without a kernel-thread explosion.** Millions of uthreads over K
  vcores; the kernel only tracks K schedulable entities, not the uthread count.
- **Blocking that doesn't waste a core.** When a uthread blocks, the carrier runs
  *another* uthread instead of the core going idle — the whole point. With pure
  async (completions) this is free; the residual involuntary cases (page fault,
  preemption) are exactly what the activation upcalls cover.
- **Locality & tail-latency control** (Shenango/Caladan lineage): userspace owns
  uthread→core placement and can react to preemption signals, which a 1:1 kernel
  scheduler can't do at uthread granularity.
- **The Telix north-star consumer**: a PL runtime (GHC/Koka/Perceus) maps its
  green threads + IO manager directly onto vcores + the completion ring; the
  paper's novelty is the microkernel-ABI × PL-runtime co-design, not the
  mechanism (`completion-abi-design.md` §1).
- **A structural bug-class win we are *already* banking**: a vcore reaping its own
  CQ has no parked-frame handoff to race, retiring the recv_or_park /
  DirectTransfer dispatch-consistency surface (#198 / #173).

## 2. The variant lineage — and the modern endpoint our docs were missing

Already characterised in our docs (`completion-abi-design.md` §2,
`related_work_reading_list.md`):
- **Anderson et al. 1992** — classic SA: an upcall on *every* block/unblock/
  preempt, on a *fresh activation stack* each time. Correct, complete — and heavy.
- **K42** — dispatcher / vCPU upcalled to run user threads.
- **Akaros** (Rhoden) — vcores + `vcore_entry()` upcall; **async syscalls remove
  the block/unblock upcalls**; page faults *reflected* to the 2LS; cooperative
  preempt via `preempt_pending`. Our docs call this the "matured (lightweight)"
  form and target it.
- **Shenango / Caladan / Arachne** — core-granularity allocation + a preemption
  signal atop async IO. Corroborates "async + preempt-upcall, skip block-upcalls."

**Missing until now — UMCG / switchto (Google → Linux, ~2021, Oskolkov), the
lightest realization yet:**
- Model: **server** threads (carriers ≈ vcores) + **worker** uthreads, all
  ordinary kernel threads. A per-thread shared **state word** + `sys_umcg_ctl` /
  `UMCG_WAIT` / `UMCG_WAKE`.
- When a worker blocks in the kernel, the kernel **wakes its server** — userspace
  then runs another worker. When a worker is ready, the server is told.
- The key primitive is a **directed context switch**: `umcg_wait(next_worker)` =
  "switch this carrier *straight to* worker N", bypassing the run queue. (This is
  Google's internal `switchto` generalised.)
- Lighter than Akaros vcores because it lives **inside** the host scheduler
  (carriers are normal threads — no gang core-allocation, no fresh upcall stack;
  the "activation" degenerates to "the carrier's kernel thread wakes and re-enters
  its scheduling loop"). Pairs naturally with io_uring for the async-IO half.
- Trade-off vs Akaros: **less core control** (no gang scheduling / dedicated
  cores), in exchange for a far smaller kernel mechanism and clean coexistence
  with a normal scheduler.

**The convergence point:** everyone modern lands on *async-IO (io_uring/CQ) for
voluntary blocking + a minimal kernel notify for the involuntary residual
(fault/preempt) + a directed switch.* The variants differ mainly in **how much
core control the kernel cedes** (Akaros: a lot; UMCG: little).

## 3. The recommended Telix shape — built on what exists

Telix already owns the **async-IO half** (the completion ring). So the lightweight
activation layer should *reuse it* rather than add a parallel mechanism:

- **Voluntary blocking → a completion CQE** ("uthread T runnable"). Already how it
  works; no upcall (Akaros idiom, `completion-abi-design.md` §4).
- **Directed switch (UMCG's key idea) → a ring primitive**: an SQE
  `OP_SWITCH_TO(uthread)` (or a `reap_wait` variant) where the kernel hands the
  vcore straight to a chosen carrier/uthread, skipping the run queue. This is also
  what *dissolves* the dispatch-churn we keep fighting — the handoff is explicit
  and race-free.
- **Involuntary blocking (page fault) → reflect to `vcore_entry`** instead of
  parking, posting a completion on resolution. The one genuine upcall.
- **Preemption → a `preempt_pending` shared word + a preemption upcall** (or a
  reserved CQE) so the 2LS checkpoints its current uthread and relinquishes the
  vcore gracefully.

Net: **activations are delivered as completions on the existing ring for the
common path; a per-vcore upcall entry is used only for the involuntary residual
(fault-reflect, preempt).** That is the Akaros-vcore × io_uring-ring ×
UMCG-directed-switch synthesis — the lightest thing that still gives real M:N.

### What it builds on (already implemented — the foundation is in place)
- **Completion ring** (Phase 0: `ipc/completion.rs` SQ/CQ, `io_setup`, the deliver
  hook, `REAP_WAIT`) — the activation transport itself.
- **Ring lifecycle** (Phase A: `clear_completion_ctx` on exec/exit, RCU-deferred
  free, zero-on-Task-reuse) — the per-vcore **upcall-stack** lifecycle is the
  *same* pattern (per-task kernel-managed VA + RCU teardown); reuse it verbatim.
- **Signals** (`sys_sigreturn` + the trampoline/frame builder, `handlers.rs`) — a
  *working* kernel→user control-transfer + register-frame save to model the vcore
  upcall delivery and the continuation snapshot on.
- **Async demand-paging hook** — `FaultResult::NeedPager{token}` →
  `pager::initiate_fault` then park. The SA change is to **reflect rather than
  park** (hand the 2LS the continuation + pager token, post a completion on
  resolution). Reuses existing plumbing; no new pager subsystem
  (`completion-abi-design.md` §4 "Telix hook").
- **Per-(v)CPU SPSC rings + per-worker CQ steering** (`completion-abi-design.md`
  §9.3, locked) — the vcore↔ring mapping is already the chosen granularity.

### The concrete new kernel pieces (the gap to implement, when prioritised)
1. **Per-vcore upcall-entry registration** — `register_vcore_entry(entry, stack)`,
   analogous to signal-handler registration; the stack region uses the
   ring-lifecycle pattern.
2. **Activation-event encoding** — reserved CQE opcodes on the ring + the
   fixed **upcall-vector table** already reserved in `completion-abi-design.md` §4
   (preempt, reflected-fault, reflected-IO, room for block/unblock).
3. **Directed-switch op** (`OP_SWITCH_TO`) + the `preempt_pending` shared word.
4. **Page-fault reflection** — flip the park to a reflect on the demand-paging path.
5. **Continuation snapshot/restore** — see §4 (the hard piece).

## 4. The genuinely hard pieces (flag, don't hand-wave)

- **Continuation representation** (`completion-abi-design.md` §9.2, still [OPEN]):
  snapshot/restore of a preempted/blocked uthread's register state across a
  reflection — per-arch, the fiddliest part. UMCG sidesteps explicit save (the
  uthread *is* a kernel thread, so its state lives in the kernel thread); Akaros
  saves to a user-mapped uthread-context struct. **Telix decision pending** — the
  UMCG carrier model is attractive precisely because it avoids hand-rolling the
  save/restore.
- **Preempted-lock-holder** (the classic SA hazard): preempting a uthread holding
  a *userspace* lock deadlocks its peers. UMCG's carrier model largely sidesteps
  it (the holder is a real kernel thread that keeps running until it blocks/
  yields); classic SA needs a recovery upcall. **Lean UMCG-style here** to avoid
  the recovery protocol.
- **Per-arch upcall + frame save** — ×5 arches (x86_64, aarch64, riscv64, loong,
  mips), exactly like signals. The cross-arch matrix from
  `completion-abi-design.md` §8 applies.

## 5. Status & priority

**Design-only. No scheduler-activation code exists** — only the completion ring
(Phase 0) and its lifecycle (Phase A) are built, and those are the foundation
either way (the activation transport). Per the user (2026-06-23) this is
**deferred behind H14 performance**; it is documented now so the modern-variant
decision (UMCG-carrier vs Akaros-vcore synthesis) and the integration-with-built-
state are captured before the trail goes cold. If a PL-runtime (paper) consumer
or transparent-blocking need rises in priority, this becomes the next major
subsystem; the recommended first step is the same audit→design→loom→implement
discipline used elsewhere, starting from the §3 "concrete new kernel pieces" list.
