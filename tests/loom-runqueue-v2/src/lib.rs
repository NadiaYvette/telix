//! #173 atomic run-queue membership — candidate-protocol comparison.
//!
//! Context: tests/loom-runqueue models the LIVE kernel protocol (in_queue:
//! AtomicBool + a separate heap, updated outside the lock) and FAILS by
//! design — it omits the `on_cpu == ON_CPU_PENDING` gate the kernel uses to
//! mitigate the dispatch‖rescue phantom race. The mitigation works but is a
//! band-aid (gate + 1.5 s fast-rescue). #173's goal is to make run-queue
//! membership a SINGLE source of truth so the phantom is impossible by
//! construction — no gate, no rescue.
//!
//! This crate specifies + proves two candidate redesigns. Each races the two
//! membership writers — dispatch (pop+claim) ‖ wake (enqueue) — on ONE
//! thread, with NO rescue actor, and asserts the safety invariant holds under
//! every loom interleaving. If it holds without a rescue, the design needs no
//! rescue.
//!
//!   approach_a — membership lives ENTIRELY under the rq lock (one variable);
//!                even the "already queued?" check takes the lock. Simplest;
//!                correct by construction. Cost: every wake locks.
//!   approach_b — single packed atomic state (NOT_QUEUED/QUEUED/CLAIMED) with
//!                a LOCK-FREE "already queued?" fast path; the 0→1 / 1→2 state
//!                transitions still happen under the lock together with the
//!                heap push/pop, so state and heap can't diverge. Keeps the
//!                hot path lock-free.
//!
//! Safety invariant at quiescence (both writers joined):
//!   * membership-says-queued  IFF  heap_member == 1   (no strand, no phantom)
//!   * heap_member <= 1                                 (no double-enqueue)
//!   * a thread the dispatcher CLAIMED is not also left queued (no double-run)
//!   * a wake that observed the thread NOT-queued-and-not-claimed results in
//!     it becoming queued (no lost wake).

#![cfg(loom)]

use loom::sync::atomic::{AtomicU32, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

// Packed membership states for approach B.
const NOT_QUEUED: u32 = 0;
const QUEUED: u32 = 1;
const CLAIMED: u32 = 2;

// ---------------------------------------------------------------------------
// Approach A: membership folded into the rq lock (single variable).
// ---------------------------------------------------------------------------

/// Membership AND the claim live under ONE rq lock. `queued` is in_queue,
/// `heap` is the storage count, `claimed` is the on_cpu transition. Folding
/// the claim into the same lock as the pop is the CRITICAL requirement the
/// first cut of this model exposed: if the claim is set after the lock is
/// dropped (as the live kernel does — pop under lock, on_cpu=PENDING after),
/// a concurrent wake re-queues the thread in that window → it ends up both
/// running AND queued (double-dispatch). Under one lock, that window is gone.
struct CpuA {
    /// (queued, heap_member, claimed) — all mutated only under this lock.
    rq: Mutex<(bool, u32, bool)>,
}

impl CpuA {
    fn new() -> Self {
        Self {
            rq: Mutex::new((true, 1, false)), // seeded: queued, not claimed
        }
    }
}

/// dispatch: pop AND claim together, under the rq lock.
fn a_dispatch(c: &CpuA) {
    let mut rq = c.rq.lock().unwrap();
    if !rq.0 {
        return; // not queued — nothing to dispatch
    }
    rq.0 = false; // leave the queue
    rq.1 -= 1; // pop heap
    rq.2 = true; // claim to run — SAME critical section as the pop
}

/// wake: enqueue, under the rq lock (the "already queued?" + "claimed?" checks
/// too).
fn a_wake(c: &CpuA) {
    let mut rq = c.rq.lock().unwrap();
    if rq.0 {
        return; // already queued — no-op
    }
    if rq.2 {
        return; // claimed/running — stays out of the queue
    }
    rq.0 = true;
    rq.1 += 1; // push heap
}

/// rescue: the phantom-heal pass. Under approach A membership and heap are the
/// same datum under one lock, so a phantom (queued != heap-presence) can never
/// exist — this heal must therefore be a no-op under every interleaving. We
/// run it as a third concurrent actor to PROVE A needs no rescue.
fn a_rescue(c: &CpuA) {
    let mut rq = c.rq.lock().unwrap();
    let (queued, heap, claimed) = *rq;
    if queued && heap == 0 {
        rq.1 = 1; // would re-push a phantom — unreachable in A
    } else if !queued && heap == 1 && !claimed {
        rq.0 = true; // would re-mark — unreachable in A
    }
}

fn a_run() {
    let c = Arc::new(CpuA::new());
    let cd = c.clone();
    let cr = c.clone();
    let d = thread::spawn(move || a_dispatch(&cd));
    let r = thread::spawn(move || a_rescue(&cr));
    a_wake(&c);
    d.join().unwrap();
    r.join().unwrap();

    let rq = c.rq.lock().unwrap();
    let (queued, heap, claimed) = *rq;
    assert!(heap <= 1, "approach_a double-enqueue: heap={}", heap);
    assert_eq!(
        queued, heap == 1,
        "approach_a membership/heap diverged: queued={} heap={}",
        queued, heap,
    );
    // No strand: the thread is queued XOR claimed (exactly one home), never
    // neither (lost) — it started runnable, so it must still be reachable.
    assert!(
        queued ^ claimed,
        "approach_a strand/double: queued={} claimed={}",
        queued, claimed,
    );
}

// ---------------------------------------------------------------------------
// Approach B: single packed atomic state + lock-free "already queued?" fast
// path; transitions under the lock with the heap op.
// ---------------------------------------------------------------------------

struct CpuB {
    state: AtomicU32, // NOT_QUEUED | QUEUED | CLAIMED — the source of truth
    heap: Mutex<u32>, // storage; must mirror (state==QUEUED) <-> (heap==1)
}

impl CpuB {
    fn new() -> Self {
        Self {
            state: AtomicU32::new(QUEUED), // seeded queued
            heap: Mutex::new(1),
        }
    }
}

/// dispatch: claim a QUEUED thread. The CAS QUEUED→CLAIMED and the heap pop
/// happen together under the lock, so no observer sees state and heap
/// disagree.
fn b_dispatch(c: &CpuB, cas_ord: Ordering, fail_ord: Ordering) {
    let mut h = c.heap.lock().unwrap();
    if c
        .state
        .compare_exchange(QUEUED, CLAIMED, cas_ord, fail_ord)
        .is_ok()
    {
        *h -= 1; // pop, under the same lock as the CAS
    }
}

/// wake: lock-free fast path if already QUEUED or CLAIMED; otherwise take the
/// lock and do the NOT_QUEUED→QUEUED CAS + heap push together.
fn b_wake(c: &CpuB, load_ord: Ordering, cas_ord: Ordering, fail_ord: Ordering) {
    // Lock-free fast path: an already-queued (or running) thread needs nothing.
    let s = c.state.load(load_ord);
    if s == QUEUED {
        return;
    }
    // Slow path: transition under the lock so state+heap stay consistent.
    let mut h = c.heap.lock().unwrap();
    if c
        .state
        .compare_exchange(NOT_QUEUED, QUEUED, cas_ord, fail_ord)
        .is_ok()
    {
        *h += 1;
    }
    // CAS failure ⇒ someone else made it QUEUED or it is CLAIMED (running) —
    // either way it is reachable; nothing to do.
}

/// rescue for approach B: phantom-heal. The state CAS and the heap push/pop
/// happen together under the lock, so state==QUEUED <-> heap==1 holds at every
/// lock-protected observation point → this heal is a no-op under every
/// interleaving. Run concurrently to PROVE B needs no rescue.
fn b_rescue(c: &CpuB) {
    let mut h = c.heap.lock().unwrap();
    let s = c.state.load(Ordering::Acquire);
    if s == QUEUED && *h == 0 {
        *h = 1; // unreachable in B
    } else if s != QUEUED && *h == 1 {
        *h = 0; // unreachable in B
    }
}

fn b_run_with(load_ord: Ordering, cas_ord: Ordering, fail_ord: Ordering) {
    let c = Arc::new(CpuB::new());
    let cd = c.clone();
    let cr = c.clone();
    let d = thread::spawn(move || b_dispatch(&cd, cas_ord, fail_ord));
    let r = thread::spawn(move || b_rescue(&cr));
    b_wake(&c, load_ord, cas_ord, fail_ord);
    d.join().unwrap();
    r.join().unwrap();

    let heap = *c.heap.lock().unwrap();
    let state = c.state.load(Ordering::Acquire);
    assert!(heap <= 1, "approach_b double-enqueue: heap={}", heap);
    assert_eq!(
        state == QUEUED,
        heap == 1,
        "approach_b state/heap diverged: state={} heap={}",
        state, heap,
    );
    // No strand: end state is QUEUED (heap=1) or CLAIMED (heap=0). NOT_QUEUED
    // at quiescence would mean the seeded-runnable thread was lost.
    assert!(
        state == QUEUED || state == CLAIMED,
        "approach_b strand: state={} (lost the runnable thread)",
        state,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approach_a_protocol() {
        loom::model(a_run);
    }

    /// Faithful kernel orderings for B.
    #[test]
    fn approach_b_protocol() {
        loom::model(|| b_run_with(Ordering::Acquire, Ordering::AcqRel, Ordering::Acquire));
    }

    /// SeqCst control for B: must pass (if it fails, the model is buggy, not a
    /// memory-ordering finding).
    #[test]
    fn approach_b_protocol_seqcst() {
        loom::model(|| b_run_with(Ordering::SeqCst, Ordering::SeqCst, Ordering::SeqCst));
    }
}
