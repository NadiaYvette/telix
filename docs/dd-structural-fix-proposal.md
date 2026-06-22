# Double-dispatch structural fix — proposal (for review)

Consolidates the 2026-06-22 session findings into one approvable plan. The
implementation is dispatch-core surgery, left gated on your steer. Detail lives in
memory notes project_208_double_dispatch_mb1 + project_preempt_count_dual_purpose.

## Problem
Double-dispatch (DD) = two CPUs execute one Thread → shared kstack → #208 wild-RIP
scribble. Root cause: a thread that is **still `current_thread` on a CPU** becomes
**claimable** (`on_cpu==PENDING`) and/or **heap-resident** (steal-able), so a peer
claims + runs it. It is MULTI-SOURCE and high-variance.

## The invariant (proven by tests/loom-dispatch-compose)
> A Thread that is `current_thread` on any CPU must be NEITHER claimable
> (`on_cpu==PENDING`) NOR present in any run-queue heap.
Equivalently: a release-of-running must be **off-kstack-first** (publish the
non-claimable `ON_CPU_RELEASING` while still on the kstack; flip to `PENDING` only at
the off-kstack `finalize` point). The Release fence on that publish is load-bearing.

## Two-part fix
**(A) RELEASE side — one validated "relinquish a running thread" helper.** Publish
`ON_CPU_RELEASING` + `transition_release_to_pending`; `finalize_release_after_stack_switch`
flips RELEASING→PENDING off-kstack. Route EVERY release-of-running site through it.
- Done: `voluntary_reschedule` (committed 40d333c), `try_switch` (pre-existing).
- Verified safe: the deferred/drain path — the remote drain enqueues RELEASING threads,
  which the claim CAS rejects (ddprod: 72 such enqueues, DD=0).
- To do: confirm no other site publishes PENDING-while-current (the `preempt_count`
  assert below names any).

**(B) CONSUME side — don't make a still-current thread claimable.** `rescue` (today
re-stamps `on_cpu=PENDING` + re-enqueues on `on_cpu==PENDING` ∧ `state≠Running`, but
NEVER checks `current_thread[any cpu]==tid`) and `percpu_enqueue` must, before
enqueuing/re-stamping `tid`, skip/re-defer when `current_thread[any cpu]==tid` **and**
`on_cpu==PENDING`. A cheap peer-scan (identical to the DD detector at scheduler.rs
859-908). CRITICAL nuance: do NOT skip the `RELEASING` case — those are CAS-protected
and benign; skipping them would STRAND the deferred thread (→ orphan/rescue churn).

## preempt_count — the unifying, dual-purpose instrument
Both parts are one rule: "don't make a thread claimable/enqueued while it's executing."
A minimal `preempt_count` makes it assertable: at every release/enqueue, assert the
thread is not current-on-any-cpu. As a debug assert it **deterministically names any
remaining producer** (finishes this bug); as a real counter it's the Phase-5
full-preemption foundation (docs/phase5-preemption-scope.md). Build it once, use twice.

## Loom validation (do before shipping the guard)
Extend `tests/loom-dispatch-compose` with the consume side: model `rescue`/`steal`
re-enqueue racing a release, assert the invariant holds. Prove (B) the way (A) was proven.

## ⚠ Scope caveat
This closes DOUBLE-DISPATCH only. It does NOT close the broader #208/#228 corruption
family: ddprod had DD=0 yet 3/8 boots still crashed with #208 wild-RIP (NULL-jump,
NX-into-kstack, Thread-region deref) = slab/kstack/Thread-struct corruption
(project_228_allocator_double_issue). #228 is a SEPARATE, still-active blocker; clean
SMP boots need both fixed.

## Sequencing / risk
1. `preempt_count` + release/enqueue assert — small, diagnostic, low-risk; names any
   remaining (A)/(B) violator deterministically.
2. Consume-side guard (B) — defensive, PENDING-vs-RELEASING-aware; low-risk.
3. Finish release-helper routing (A) — mostly done; medium.
4. loom-extend + validate (B); then flip on with confidence.
All in your dispatch core → your call. Validation needs sanctioned host pressure
(8-boot oversubscription on the qemu-rt cores; pgcl paused).
