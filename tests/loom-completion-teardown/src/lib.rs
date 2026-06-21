//! Loom model of the completion-ABI `deliver ‖ io_teardown` race (Phase 0).
//!
//! `SYS_IO_TEARDOWN` lets a task that opened a completion ring for a bounded
//! purpose (e.g. init's boot self-test) drop it and return to normal `recv`
//! IPC. It clears `io_depth` (the send_direct deliver-hook's gate) then the
//! ring pointers. A sender may be mid-deliver concurrently:
//!
//!   deliver_to_completion_cq:                 io_teardown:
//!     if io_depth != 0 {                        io_depth   = 0   (Release)
//!       kva = io_cq_kva.load()                  io_cq_kva  = 0   (Relaxed)
//!       if kva != 0 { push CQE at kva }         // (current impl: LEAK pages)
//!     }
//!
//! Two memory-safety questions this model answers:
//!  1. Can deliver ever push to a NULL CQ? No — it bails when `kva == 0`
//!     (the `IODELIV-NOCTX` guard in `deliver_to_completion_cq`).
//!  2. Can deliver push to a FREED CQ (UAF)? With the current impl that LEAKS
//!     the ring pages: never (the pages stay mapped, so a `kva != 0` snapshot is
//!     always valid). With a naive "free the pages on teardown" variant: YES —
//!     deliver can snapshot `kva != 0`, teardown then frees, deliver pushes into
//!     freed memory. So reclaiming the CQ safely needs a refcount / RCU / quiesce
//!     (or per-port deliver scoping), NOT a bare free.
//!
//! The lost-MESSAGE window (deliver pushes a CQE into a CQ nobody reaps anymore)
//! is a liveness/semantic issue, not memory unsafety; it's benign in Phase 0
//! because the only teardown caller (init's self-test) has no concurrent
//! senders. Modeled as an observable below, not asserted.
//!
//! Kernel mapping: `io_depth` = `Task::io_depth`, `cq_kva` = `Task::io_cq_kva`,
//! `freed` = whether the ring's backing pages have been reclaimed.

use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use loom::sync::Arc;
use loom::thread;

#[derive(Clone, Copy, PartialEq)]
enum Discipline {
    /// Current kernel impl: teardown clears pointers but LEAKS the ring pages
    /// (they are never freed), so any non-null `kva` snapshot stays valid.
    LeakNoFree,
    /// Hypothetical unsafe variant: teardown also frees the ring pages. Used to
    /// show the model has teeth — this MUST be able to UAF.
    FreeOnTeardown,
}

struct Outcome {
    /// deliver dereferenced a freed CQ (use-after-free) — must never happen.
    uaf: bool,
    /// deliver pushed a CQE while/after teardown ran (lost message; benign in
    /// Phase 0). Observable only, not asserted.
    lost_message: bool,
}

/// One deliver ‖ teardown interleaving.
fn run(d: Discipline) -> Outcome {
    let io_depth = Arc::new(AtomicUsize::new(1)); // ring is set up
    let cq_kva = Arc::new(AtomicUsize::new(1)); // 1 = a valid CQ pointer, 0 = null
    let freed = Arc::new(AtomicBool::new(false)); // CQ backing pages reclaimed?
    let torn = Arc::new(AtomicBool::new(false)); // teardown has begun (for lost-msg obs)
    let uaf = Arc::new(AtomicBool::new(false));
    let lost = Arc::new(AtomicBool::new(false));

    // Sender's deliver_to_completion_cq, gated by the send_direct hook.
    let deliver = {
        let io_depth = io_depth.clone();
        let cq_kva = cq_kva.clone();
        let freed = freed.clone();
        let torn = torn.clone();
        let uaf = uaf.clone();
        let lost = lost.clone();
        thread::spawn(move || {
            // send_direct hook gate (port.rs): only route to CQ if io_depth != 0.
            if io_depth.load(Ordering::Acquire) != 0 {
                // deliver_to_completion_cq: snapshot the CQ pointer, bail if null.
                let kva = cq_kva.load(Ordering::Relaxed);
                if kva != 0 {
                    // "push" the CQE at `kva`. If the pages were freed, this is a
                    // use-after-free.
                    if freed.load(Ordering::Acquire) {
                        uaf.store(true, Ordering::Release);
                    }
                    // Whether or not teardown has begun, a push here lands in a CQ
                    // the task may no longer reap — observe the lost-message window.
                    if torn.load(Ordering::Acquire) {
                        lost.store(true, Ordering::Release);
                    }
                }
                // kva == 0 -> IODELIV-NOCTX bail; falls back to the legacy queue.
            }
        })
    };

    // io_teardown(): clear the gate, then the pointers, then (unsafe variant) free.
    let teardown = {
        let io_depth = io_depth.clone();
        let cq_kva = cq_kva.clone();
        let freed = freed.clone();
        let torn = torn.clone();
        thread::spawn(move || {
            torn.store(true, Ordering::Release); // mark teardown in progress (obs)
            io_depth.store(0, Ordering::Release); // gate closes first
            cq_kva.store(0, Ordering::Relaxed); // then drop the pointer
            if d == Discipline::FreeOnTeardown {
                freed.store(true, Ordering::Release); // unsafe: reclaim the pages
            }
        })
    };

    deliver.join().unwrap();
    teardown.join().unwrap();
    Outcome {
        uaf: uaf.load(Ordering::Acquire),
        lost_message: lost.load(Ordering::Acquire),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Current impl (leak the ring pages on teardown): deliver can NEVER touch
    /// freed memory across any interleaving — a non-null `kva` snapshot is always
    /// valid because the pages are never reclaimed.
    #[test]
    fn leak_teardown_is_uaf_safe() {
        loom::model(|| {
            let o = run(Discipline::LeakNoFree);
            assert!(!o.uaf, "UAF: deliver pushed into freed CQ pages");
            // lost_message may be true (benign in Phase 0); not asserted.
            let _ = o.lost_message;
        });
    }

    /// Naive "free the ring pages on teardown" variant: loom finds the
    /// interleaving where deliver snapshots a valid `kva`, teardown frees, and
    /// deliver then pushes into freed memory. Proves a bare free is unsound —
    /// reclaiming the CQ needs a refcount / RCU / per-port scoping.
    #[test]
    #[should_panic]
    fn free_on_teardown_can_uaf() {
        loom::model(|| {
            let o = run(Discipline::FreeOnTeardown);
            assert!(!o.uaf, "UAF: deliver pushed into freed CQ pages");
        });
    }
}
