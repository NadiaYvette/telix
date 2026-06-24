//! H14 #173 targeted mitigation — orphan (on_cpu=MAX) recovery must be
//! CAS-coordinated, not blind-store — loom model.
//!
//! The 145e re-orphan cycle (project_phase5_gate_isolation): a Ready thread sits at
//! `on_cpu = MAX` (fully orphaned). The rescue makes it dispatchable + enqueues it;
//! a picker then claims it via `CAS(PENDING -> cpu)`. The proposed mitigation also
//! lets a picker reclaim the orphan directly via `CAS(MAX -> cpu)` instead of
//! dropping it. The danger is that today's rescue stamps the orphan dispatchable
//! via `set_on_cpu_pending` = an **unconditional `store(PENDING)`**. If a concurrent
//! path has just claimed the same orphan (`CAS(MAX -> cpu)`, i.e. it is now running
//! on a cpu), the rescue's blind `store(PENDING)` CLOBBERS the claim — the running
//! thread looks PENDING again and a second picker dispatches it = double-dispatch
//! (the #208 family).
//!
//!   INVARIANT: a thread claimed for dispatch (`on_cpu` = a real cpu) is never
//!   resurrected to PENDING by a concurrent orphan-rescue.
//!
//! `naive_store_rescue_resurrects` (#[should_panic]) — `load()==MAX` then
//! `store(PENDING)` is TOCTOU: the store lands after a concurrent `CAS(MAX->cpu)`
//! and clobbers it.
//! `cas_rescue_is_exclusive` — the rescue uses `CAS(MAX->PENDING)`; it and the
//! dispatch `CAS(MAX->cpu)` both compare-exchange from MAX, so exactly one wins and
//! a claimed thread is never resurrected.

#![cfg(loom)]

use loom::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use loom::sync::Arc;
use loom::thread;

const MAXV: u32 = 0xFFFF_FFFF; // on_cpu = MAX (orphan sentinel)
const PENDING: u32 = 0xFFFF_FFFE; // on_cpu = PENDING (dispatchable sentinel)
const CPU0: u32 = 0; // a real-cpu claim

/// `cas_rescue=false` models today's blind `store(PENDING)`; `true` the fix.
fn run(cas_rescue: bool) {
    let on_cpu = Arc::new(AtomicU32::new(MAXV));
    let owned = Arc::new(AtomicBool::new(false)); // a picker claimed MAX->CPU0 (running)
    let enq = Arc::new(AtomicBool::new(false)); // rescue published it as enqueueable

    // Dispatch/reclaim thread: claim the MAX orphan onto CPU0 (the proposed
    // picker reclaim-MAX). Atomic by construction.
    let (oc1, ow1) = (on_cpu.clone(), owned.clone());
    let d = thread::spawn(move || {
        if oc1
            .compare_exchange(MAXV, CPU0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            ow1.store(true, Ordering::Release); // now "running on CPU0"
        }
    });

    // Rescue thread: make the orphan dispatchable + enqueue it.
    let (oc2, en2) = (on_cpu.clone(), enq.clone());
    let r = thread::spawn(move || {
        if cas_rescue {
            // FIX: only publish if on_cpu is still MAX at the instant of the stamp.
            if oc2
                .compare_exchange(MAXV, PENDING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                en2.store(true, Ordering::Release);
            }
        } else {
            // TODAY (set_on_cpu_pending): observe orphan, then blind store —
            // the load and the store are not atomic together (TOCTOU).
            if oc2.load(Ordering::Acquire) == MAXV {
                oc2.store(PENDING, Ordering::Release);
                en2.store(true, Ordering::Release);
            }
        }
    });

    d.join().unwrap();
    r.join().unwrap();

    // Double-dispatch hazard: the thread is "running on CPU0" (owned) AND also
    // published pending+enqueued (a second picker will dispatch it again).
    let owned = owned.load(Ordering::Acquire);
    let resurrected = enq.load(Ordering::Acquire) && on_cpu.load(Ordering::Acquire) == PENDING;
    assert!(
        !(owned && resurrected),
        "claimed thread resurrected to PENDING by the rescue -> double-dispatch",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Today's blind store: TOCTOU lets the rescue clobber a concurrent claim.
    #[test]
    #[should_panic(expected = "double-dispatch")]
    fn naive_store_rescue_resurrects() {
        loom::model(|| run(false));
    }

    /// Fix: CAS(MAX->PENDING) is mutually exclusive with the dispatch CAS(MAX->cpu).
    #[test]
    fn cas_rescue_is_exclusive() {
        loom::model(|| run(true));
    }
}
