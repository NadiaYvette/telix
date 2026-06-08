# Dispatch protocol refactor — eliminate the phantom-pending window

Task #173.  Session 1 (2026-06-08): audit + phased plan.  No code
changes in this session.

## Problem

Telix's dispatch protocol is a two-step transition: a CPU pops a
thread `X` from its per-CPU run queue, stamps `X.on_cpu = PENDING`,
drops the rq lock, then does `CAS(X.on_cpu, PENDING, this_cpu)` in the
caller (`try_switch`, `voluntary_reschedule`, `park_current_for_ipc`).
Between the stamp and the CAS, the host can pause this vCPU.  While
paused, `X` is stranded — not in any rq, `on_cpu = PENDING`, no CPU
running it.  Linux's scheduler doesn't have this window because its
dispatch is single-atomic.

Today the fast-rescue path (commit `e443126`) catches stranded threads
after 1.5 s.  This refactor eliminates the window so the bug class
cannot occur, and fast-rescue becomes redundant for this case.

## Current protocol

```
percpu_pick_next(cpu, idle_id) -> ThreadId:
  rq.lock()
  X = class_pick_next()                  # pops X from heap/bitmap
  rq.unlock()
  X.in_queue := false
  dequeue_set_pending(X):
    X.on_cpu := ON_CPU_PENDING           # <-- phantom window starts
    X.pending_set_ns := vcpu_runtime_ns()
  return X

try_switch(current_sp) (or vol_resched / park_ipc):
  ...
  next = percpu_pick_next(cpu, idle_id)
  CAS(next.on_cpu, PENDING, this_cpu)    # <-- phantom window ends if Ok
                                         #     bails benignly if Err
  next.state := Running
  switch
```

Window: between `dequeue_set_pending` storing PENDING (with `rq` not
held) and the caller's CAS.

## Proposed protocol

Collapse the pop + on_cpu transition into a single critical section.

```
percpu_pick_next_and_claim(this_cpu, idle_id) -> ThreadId:
  rq.lock()
  loop {
    Y = class_pick_next()       # returns None when empty
    if Y is None:
      rq.unlock()
      return idle_id
    Y.in_queue := false
    # Try to claim Y inside the rq lock.  Y.on_cpu is expected to be
    # ON_CPU_PENDING here (set by the enqueue path before percpu_enqueue).
    if Y.on_cpu.compare_exchange(ON_CPU_PENDING, this_cpu,
                                 AcqRel, Acquire).is_ok():
      Y.state := Running
      rq.unlock()
      return Y
    # CAS failed — some other CPU already claimed Y via wake_thread's
    # direct path or a rescue.  Drop Y on the floor and try the next pick.
    # (Don't re-enqueue; the other CPU owns the lifecycle now.)
  }
```

Caller (try_switch / voluntary_reschedule / park_current_for_ipc):

```
next = percpu_pick_next_and_claim(this_cpu, idle_id)
# No CAS needed here — the pick already claimed.
# next.state == Running already.
switch to next
```

### Why this works

- The rq.lock window now covers both the heap pop AND the on_cpu
  transition.  A host pause between them is impossible — the lock is
  still held.
- A host pause AFTER the lock is released (while caller switches to
  `next`) doesn't leave `next` stranded — `next.on_cpu == this_cpu` and
  the next dispatch on this CPU will see it as Running and respect that.
- The CAS-failure branch handles the rare case where another path
  (rescue, wake_thread short-circuit) claimed `Y` before the rq.lock
  saw the canonical view.  Today that case is also rare; with the
  refactor we just retry the pick instead of bailing benignly.

### Why this doesn't break Ready-side enqueue

Type B sites (`wake_thread`, `clone_thread`, `kill_thread`'s wake-from-
sleep, `wake_parked_thread`'s deferred-enqueue, etc.) still stamp
`on_cpu = ON_CPU_PENDING` immediately BEFORE `percpu_enqueue`.  That
keeps the dispatch path's CAS pre-condition stable: `on_cpu == PENDING`
when the thread is on a rq and not yet picked.

## Audit: where `ON_CPU_PENDING` is written

80 references total across `kernel/src/sched/scheduler.rs` and
`kernel/src/sched/smp.rs`.  Stores grouped:

### Type A (dispatch-side — REMOVED by refactor)

| Site (scheduler.rs) | Function | Notes |
| --- | --- | --- |
| 2286 | `dequeue_set_pending` | The set-PENDING that opens the phantom window.  Helper goes away. |
| 5797 | `try_switch` fallback | "Restore on_cpu from PENDING back to cpu" — CAS-fail path; obsolete after refactor. |
| 6440 | `voluntary_reschedule` deferred-store | Mirrors `dequeue_set_pending`; same removal. |
| 10493 | Fast-rescue CAS | `CAS(X.on_cpu, PENDING, MAX)` to claim a stranded thread.  Bug class gone → consider removing fast-rescue. |
| 10852, 10965 | `RESCUE-STUCK-PENDING` | Same: rescue paths for phantom-pending.  Re-evaluate. |

### Type B (enqueue-side — RETAINED)

| Site | Function | Trigger |
| --- | --- | --- |
| 572 | `transition_to_pending` helper | Generic Blocked→Ready transition |
| 3631 / 3946 / 4054 | Thread creation paths | New thread, first enqueue |
| 6091 / 6469 / 9591 / 11478 | Main dispatch arms CAS(PENDING→cpu) | These become the **claim** under refactor (moved inside rq.lock) |
| 7439 | `kill_thread` wake-from-Sleep | Promote victim out of sleep_queue |
| 8192 / 8448 / 8581 | Fork/clone child first enqueue | Same as thread creation |
| 9322 | `clear_pending_switch` deferred-enqueue | Wake handshake parker side |
| 9799 | `wake_parked_thread` early-arbitrate | Parker hasn't switched yet |
| 11198 | Sleep wake (`sleep_queue` expiry) | Sleeper becomes Ready |
| 11607 | Sender direct-wake to receiver | IPC send wakeup path |

Most Type B sites are unchanged.  The four dispatch-arm CAS sites
(6091, 6469, 9591, 11478) merge into the new pick-and-claim helper.

### Readers (compare against `ON_CPU_PENDING`)

| Site | Purpose | Refactor impact |
| --- | --- | --- |
| 778 | kstack validator (transient state filter) | Unchanged — PENDING still means "on rq, not picked". |
| 829 | `on_ok` invariant check | Unchanged — PENDING remains valid. |
| 10169 / 10202 / 10928 / 10930 | Rescue dispatcher filters | Unchanged or simplified (the bug class it watched for is gone). |

## Phased migration plan

### Phase 1 — Add the new helper (additive, no behavior change)

- Introduce `percpu_pick_next_and_claim(this_cpu, idle_id)` returning
  `ThreadId` (or `idle_id` when empty / all picks fail CAS).
- Implement it AS the new protocol: rq.lock + pop + CAS-claim.
- Wire it through a feature gate or one call site behind a static bool
  for A/B comparison under stress.

### Phase 2 — Migrate `try_switch` to the new helper

- Replace `percpu_pick_next` + `dequeue_set_pending` + CAS with
  `percpu_pick_next_and_claim`.
- Keep `percpu_pick_next` available temporarily for the other dispatch
  arms.
- Validate: clean boot + WORKERS_ENABLED=true stress + boots under host
  pressure.

### Phase 3 — Migrate `voluntary_reschedule` and `park_current_for_ipc`

- Same pattern.  Watch for the `cur_id` (current thread's own
  on_cpu transition) wrinkle in `voluntary_reschedule` — `cur` doesn't
  go through the rq, it transitions Running→Ready directly.  The
  on_cpu=PENDING store on `cur` (line 6440) stays; only the `next`
  pick uses the new helper.

### Phase 4 — Migrate the cosched path

- `percpu_pick_next_cosched` is structurally identical to
  `percpu_pick_next`; mirror the refactor.

### Phase 5 — Reduce / remove fast-rescue PENDING claim

- The `RESCUE-STUCK-PENDING` paths (10852, 10965, 10493) catch the bug
  class this refactor eliminates.  Keep them as belt-and-suspenders for
  a few release cycles, then remove.
- Remove `dequeue_set_pending` and `pending_set_ns` once no caller
  remains.

### Phase 6 — Loom + Verus

- Add a loom test that models the new protocol: dispatch arms + wake
  paths racing on `on_cpu` transitions.  Invariant: a thread cannot be
  picked twice without going through Blocked or being on a rq.
- Verus contract on the helper's CAS branch — the property that a
  successful claim implies the rq held it at the moment of the CAS.

## Risks and mitigations

1. **A latent bug relying on the phantom window**.  Some rescue path
   may have grown to depend on observing PENDING for legitimate
   reasons.  Mitigation: Phase 5 keeps rescue paths until validation
   confirms zero PENDING observations under sustained stress.

2. **CAS-fail-then-drop semantics**.  If `percpu_pick_next_and_claim`'s
   CAS fails, we drop Y on the floor.  That means a fast wake by some
   other CPU "wins" and we just pick another.  Risk: priority
   inversion — a high-priority Y could be dropped repeatedly.
   Mitigation: bound the retry loop; on N failures, return idle and let
   the next dispatch tick re-pick.

3. **Rq.lock critical section grows by one CAS**.  Minor — CAS is fast.
   Worst case is `N * (pop + CAS)` under the lock, where N is the
   retry bound.  Empirically a single CAS pass is the common case.

4. **Cross-arch parity**.  aarch64's dispatch path mirrors x86_64 for
   on_cpu transitions.  Both archs need the same refactor.  aarch64
   has its own pending issues (#209) — sequence them carefully.

5. **Race against `wake_thread`'s direct fast-path**.  Some wake
   paths bypass the rq entirely when the target is currently HLT-idle
   on its last_cpu — they store on_cpu=cpu directly + IPI.  These
   paths don't go through `percpu_pick_next_and_claim` and so are
   immune.  Audit needed to confirm no overlap.

## Test plan

- **Unit**: loom model of the new protocol (Phase 6 deliverable).
- **Integration**: boot the kernel under default config, observe no
  regression in Phase 5+ boots.
- **Stress**: 4-multi under host pressure (TLXBURN active), confirm
  fast-rescue count drops to ~0 after Phase 2-3 lands.
- **Long-tail**: H14b multi-client X scenario (xeyes + xclock), confirm
  no new dispatch wedges.

## Effort estimate

- Phase 1: ~1 session.  Helper + tests.
- Phase 2-3: ~1 session.  Migration + boot validation.
- Phase 4: ~0.5 session.  Cosched mirror.
- Phase 5: ~1 session.  Cleanup pass + final validation.
- Phase 6: ~1-2 sessions.  Loom + Verus + final report.

Total: 4-5 sessions.

## Related

- [[project_phantom_pending_fast_rescue]] — today's symptom mitigation.
- [[project_135_host_desched]] — the underlying host-pause sensitivity.
- [[project_scheduler_paravirt_robustness]] — the broader paravirt
  roadmap this slots into.
