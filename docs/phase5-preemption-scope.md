# Phase 5 (Full Kernel Preemption) — scope

Scoping per `docs/scheduler_design.md` §"Phase 5: Full Kernel Preemption".
Status as of 2026-06-22. **Scoping only — implementation is gated on finishing
the in-flight double-dispatch (release-of-running) bug first.**

## What "full preemption" means here
Today: **return-point preemption.** `check_preempt_on_return()` runs at every
arch's IRQ/syscall/exception return, gated on per-CPU `need_resched`, and (if no
switch is already staged) calls `voluntary_reschedule()`. So a thread is preempted
only at well-defined return boundaries; kernel code between them is effectively
non-preemptible, with critical sections protected by **IRQ-disable** (~36
`without_interrupts`/cli sites) + coding discipline — NOT a counter.

Full preemption = a higher-priority runnable thread can preempt kernel code at
*more* points (notably right after a lock release), with correctness guaranteed by
an explicit non-preemptible nesting counter rather than blanket IRQ-disable.

## What is already in place (the foundation, mostly built this session)
- **Proven safe switch+migrate primitive.** The release-of-running handoff
  (`ON_CPU_RELEASING` → `transition_release_to_pending` → off-kstack
  `finalize_release_after_stack_switch` flips RELEASING→PENDING) is now uniform
  across `try_switch` and `voluntary_reschedule`, and its safety invariant is
  loom-proven (`tests/loom-dispatch-compose`: "release-of-running must be
  off-kstack-first + Release-fenced"). **Every preemption exercises this path**, so
  this is the load-bearing prerequisite and it is in good shape.
- `need_resched` + `check_preempt_on_return` wired on all 5 arches.
- Deferred-switch machinery (`pending_switch_sp`, consumed at exception return).
- PV-aware + ticket spinlocks (fairness under host pause) already deployed.

## The gap (4 items)
1. **`preempt_count` — NOT built.** The design doc calls it the "day one
   foundation"; the code has only a `FORCED_PREEMPT_COUNT` *diagnostic*, no real
   per-thread non-preemptible nesting counter. This is the central missing piece.
2. **No sleeping-mutex primitive.** Lock inventory: 47 `SpinLock` + 39
   `lock_pv_aware` + 28 `TicketSpinLock` = 114 spin-type locks, **0 sleeping
   mutexes**. Phase 5's "convert long critical sections to sleeping locks" cannot
   start until a sleeping `Mutex` exists (it needs the block/wake path — which
   real-park now provides).
3. **Spinlock audit.** Of the 114, identify the long-critical-section holders
   (candidates: PROC_TABLE, namesrv TABLE, CDT, VFS/object tables) → sleeping
   mutex; keep the short/IRQ-context ones as spin + preempt-disable.
4. **IST / interrupt-context preempt gaps** (#285 `#UD-on-IST` preempt gap; #245
   `park_faulting_from_ist`). Preempting out of an IST stack needs the off-IST
   handoff nailed (related to the same off-kstack discipline).

## ★ The key insight (validating the "diagnostic value" intuition) ★
A minimal `preempt_count` is worth building **for the current DD bug, before any
preemption push** — because it is the missing *diagnostic invariant* for exactly
the bug class we're chasing:

> A running thread must never be released-for-migration (`on_cpu` → PENDING /
> finalize) while `preempt_count > 0`.

The dispatch/switch code runs preempt-disabled; the off-kstack `finalize` point is
where preemption re-enables. So `preempt_count == 0` ≈ "off-kstack and outside any
critical section" ≈ "safe to be migrated." Asserting `preempt_count == 0` at every
`on_cpu` release (and at finalize's PENDING publish) would **deterministically flag
every release-of-running site that violates the invariant** — which is precisely
the multi-source enumeration the DD bug now needs (Run-2 proved DD is multi-source;
the boot A/B is too noisy to localize sources). So the counter is *dual-purpose*:
diagnostic scaffold for finishing the DD bug now, and the Phase 5 foundation later.

This is the "step out of line worth taking even if preemption never gets dedicated
effort" — it pays for itself on the current bug.

## Suggested sequencing
0. **Finish the in-flight DD bug first** (enumerate + close all release-of-running
   sources). The "rung 1/2/3" framing of #173 is effectively retired: rung-2
   (membership-atomic) was shelved (it *caused* DD), and the work is now framed as
   the release-of-running / off-kstack-first invariant + a single validated release
   helper. There may be a small stack of related in-flight items (the residual DD
   sources, the COW-PT mmap gap, #228 family) — clear those.
1. **Build a minimal `preempt_count`** (per-thread or per-CPU nesting counter;
   inc/dec around the dispatch critical section + lock acquire/release + IRQ
   entry). Use it FIRST as a debug assertion at the `on_cpu` release sites to
   enumerate the DD sources — i.e., let it earn its keep on the current bug.
2. **Sleeping `Mutex` primitive** (atop real-park block/wake).
3. **Spinlock audit + conversion** of the long holders to sleeping mutexes.
4. **Add preemption points** (after lock release where `preempt_count` hits 0,
   check need_resched). Each new point is validated against the
   `loom-dispatch-compose` invariant (it's a release-of-running).
5. **Close the IST preempt gaps** (#245/#285).

## Effort / risk
- Step 1 (preempt_count + assertions): small, high diagnostic ROI, low risk
  (counter + asserts; no behavioral change until preemption points are added).
- Steps 2–3 (sleeping mutex + audit): medium, multi-session; touches many locks.
- Step 4 (preemption points): the actual "full preemption"; each point is a new
  release-of-running, de-risked by the proven loom invariant + the counter assert.
- Step 5 (IST): the trickiest; interrupt-context switching.

Bottom line: the proven switch primitive turned full preemption from "risky on a
corruption-prone base" into "additive on a proven base." The realistic near-term
move is Step 1 (preempt_count) as a DIAGNOSTIC for the current bug; the rest is a
deliberate multi-session effort to schedule when there's a breathing point.
