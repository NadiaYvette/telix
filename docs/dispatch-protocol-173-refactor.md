# #173 dispatch-protocol window-collapse refactor — design

Status: **design / not yet implemented.** Opens the durable, portable fix for the
145e systemic dispatch stall (the binding constraint to the H14 workload on hosts
we can't isolate). Captures the 2026-06-23 analysis so the implementation is a
focused, loom-backed next session. Related: [[project_phase5_gate_isolation]],
[[project_dispatch_protocol_refactor]], #173, the #135/#208 family.

## Problem
Under a host-pause storm (QEMU vCPU threads descheduled by the host), Phase 145e
exhibits a **systemic** dispatch breakdown: ~9 threads simultaneously orphaned
(`Ready, on_cpu=MAX, in_queue=false, heap_pos=NONE`), the boot stalls there until
timeout. Core-isolation (taskset) makes Phase 5 passable but does NOT eliminate the
residual host-pauses (`host_pause_peers` keeps climbing on cores other host
procs/IRQs still touch), so 145e still stalls.

**Incremental tolerance does not close it** (proven this session):
- `5e91ae9` rescue-CAS (CAS-coordinate the MAX-orphan re-stamp) — removes a
  loom-proven double-dispatch hazard but the stall persists.
- `280713b` Tier-0 routing (route wakes/rescue away from host-paused CPUs) — sound,
  but the stall persists.
Both are correct hardening, kept. The stall persists because the host-pause hits the
dispatch **window** on ~every dispatch, faster than any rescue/reroute recovers.

## The window (already-collapsed vs remaining)
The legacy pop→stamp(PENDING)→CAS window is ALREADY collapsed: the
`percpu_pick_next_*_and_claim` helpers pop + `CAS(on_cpu PENDING→cpu)` under the rq
lock (scheduler.rs ~5603/5738). **The remaining window is claim→switch:**

1. (rq lock) pop tid, `in_queue=false`, `dispatching_tid[cpu]=tid`,
   `CAS(on_cpu PENDING→cpu)` succeeds → tid is *claimed*.
2. (rq lock released) `state = Running`, `dispatch_count++`, return tid.
3. The caller (`try_switch`) does the **asm context-switch** (`mov rsp` to tid's
   kstack); `dispatching_tid[cpu]` is cleared around/after this.

If the CPU is **host-paused between 1/2 and 3**, tid is `Running, on_cpu=cpu` but the
CPU is not executing it. `reclaim_stale_on_cpu` deliberately REFUSES to reclaim it
(`owner.dispatching_tid==tid` ⇒ "legitimate direct-dispatch raced, leave it") — but
that assumption (the CPU will finish the switch soon) is FALSE under host-pause. So
the thread is stranded, un-reclaimable, until something resets it to `Ready+MAX`
(observed end state), where the orphan rescue catches it but it re-orphans (the
re-dispatch hits the same window). `dispatching_tid` evidence: it has set/clear pairs
across ALL dispatch paths (5630/5647, 5673/5691, 8241/8276/8319, 8690/8712/8764,
12428/12435/12446, 14485/14496/14525) — the protection is everywhere, so the
host-pause exemption must be added consistently.

## Proposed design — make claim→switch RECOVERABLE (not atomic)
The claim→switch ordering is inherent (you claim, then switch); it cannot be made
atomic. So the fix is **recoverability + double-execution safety**:

1. **Host-pause overrides `dispatching_tid` protection.** `reclaim_stale_on_cpu`
   (and the rescue) MAY reclaim a thread whose `on_cpu=cpu` and `dispatching_tid[cpu]
   ==tid` **iff `cpu` is host-paused** (both `last_try_switch_ns` + `last_irq_ns`
   stale past the window). The reclaim is a single `CAS(cpu→reclaimer)`; loses to any
   concurrent re-stamp.
2. **Resume-side re-validation closes double-execution.** `try_switch`, after the
   claim and **immediately before the asm switch** (i.e. after any host-pause that
   stranded it), MUST re-check `on_cpu == cpu`. If a peer reclaimed it
   (`on_cpu != cpu`), the resuming CPU **bails — does NOT switch** to tid (it goes
   idle / re-picks). This is the load-bearing safety property: a reclaimed thread is
   never run on two CPUs.
3. Keep `dispatching_tid` for the common (non-paused) case (it correctly prevents the
   benign direct-dispatch race); only the host-paused exemption is new.

### The invariant to preserve (and loom)
> A thread is `Running`/executing on **at most one** CPU at any instant. A claim
> (`CAS PENDING→cpu`) confers exclusive ownership UNTIL either (a) the asm switch
> completes (the CPU runs it), or (b) a host-pause-aware reclaim CAS(cpu→other)
> succeeds — and in case (b) the original CPU's resume-side re-check observes
> `on_cpu != cpu` and bails. No interleaving runs it twice.

## Loom plan (before any code)
Model the claim→reclaim→resume race:
- Thread P (picker): `CAS(PENDING→cpuP)` ok → [host-pause gap] → re-check
  `on_cpu==cpuP`? if yes asm-switch(run); if no bail.
- Thread R (reclaimer): observes cpuP host-paused + `dispatching_tid[cpuP]==tid` →
  `CAS(cpuP→cpuR)` → if ok, run on cpuR.
- INVARIANT: `run_count(tid) <= 1` across all interleavings (no double-execution),
  AND tid is never lost (some path runs it). Two should_panic negatives: (i) no
  resume-side re-check ⇒ double-run; (ii) reclaim via blind store ⇒ double-run.
New crate `tests/loom-dispatch-window` (sibling of loom-orphan-rescue).

## Phased implementation (fresh session, behind a flag)
0. **Probe (confirm)**: dump the full trace-ring history for a stuck tid at 145e
   (not just `trace_last`) to confirm the claim→switch stranding sequence end-to-end
   before changing the protocol. (Trace facilities: `record_trans`/`trace_sched`,
   the WAKE_TRACE_RING; may need a per-tid full-history dump.)
1. Loom the redesign (above) → 2/2.
2. Add the resume-side `on_cpu==cpu` re-check + bail in `try_switch` (the safety
   property) — gated behind a `DISPATCH_WINDOW_RECHECK` flag, default off.
3. Add the host-pause exemption to `reclaim_stale_on_cpu` + the rescue.
4. Apply consistently across ALL dispatch tails (the dispatching_tid sites above).
5. Flip the flag on; validate at 145e under isolation (does the systemic stall
   clear? watch the orphan-tid count + RESCUE/HOST_PAUSE counters) + a no-burner
   control + a stress fleet.

## Risk
HIGHEST in the codebase — this is the #208 double-dispatch family's home. The
resume-side re-check (step 2) is the safety net; it MUST land + be loom-proven before
the reclaim exemption (step 3) is enabled, or a reclaim could double-execute a thread.
Phase behind the flag; never enable 3 without 2.
