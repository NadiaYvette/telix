//! Loom model of the completion-ABI `REAP_WAIT` / deliver lost-wakeup handshake.
//!
//! Abstracts the CQ as an `AtomicUsize` count (the ring's data movement is
//! validated in the sibling `loom-completion-ring`) and focuses on the NEW
//! concurrency step ③ introduces: the per-task `io_waiter` register / recheck /
//! wake handshake that lets a server block in `SYS_IO_REAP_WAIT` without losing
//! a wakeup from a concurrent deliver.
//!
//! ## The bug loom found (2026-06-21)
//! A naive "register tid, then recheck the CQ" using only Release/Acquire is a
//! **store-load (Dekker) race**: the deliver path can post the CQE and read
//! `io_waiter` (seeing no waiter) *before* the server stores its tid, while the
//! server's recheck reads a STALE empty CQ (the post not yet visible). On weak
//! memory (aarch64/riscv64) the server then sleeps with a CQE pending and no
//! wake. Release/Acquire does not order a store followed by a load to a
//! *different* location; that requires a full **SeqCst fence on each side**:
//!   deliver:    cq.post(Release) ; fence(SeqCst) ; swap(io_waiter)
//!   REAP_WAIT:  io_waiter.store  ; fence(SeqCst) ; recheck cq
//! The two SeqCst fences sit in one total order, giving the Dekker guarantee:
//! the deliver's waiter-read and the server's cq-recheck cannot both miss.
//!
//! Kernel mapping: `cq` = the server's CQ depth; `io_waiter` =
//! `Task::io_waiter: AtomicU32` (INVALID = none, else parked server tid).

use loom::sync::atomic::{fence, AtomicBool, AtomicU32, AtomicUsize, Ordering};
use loom::sync::Arc;
use loom::thread;

const INVALID: u32 = 0;
const WAITER_TID: u32 = 1;

#[derive(Clone, Copy)]
enum Discipline {
    /// register + recheck with only Release/Acquire — the buggy version.
    WeakRecheck,
    /// register + SeqCst fence + recheck, and deliver posts + SeqCst fence +
    /// swap — the fixed version.
    SeqCstFence,
}

/// One deliver ‖ reap interleaving. Returns `(slept, wake_sent)`.
fn run(d: Discipline) -> (bool, bool) {
    let cq = Arc::new(AtomicUsize::new(0));
    let io_waiter = Arc::new(AtomicU32::new(INVALID));
    let wake_sent = Arc::new(AtomicBool::new(false));

    // deliver path: post a CQE, then (fixed) fence, then claim+wake any waiter.
    let producer = {
        let cq = cq.clone();
        let io_waiter = io_waiter.clone();
        let wake_sent = wake_sent.clone();
        thread::spawn(move || {
            cq.fetch_add(1, Ordering::Release); // post CQE (empty -> non-empty)
            if let Discipline::SeqCstFence = d {
                fence(Ordering::SeqCst);
            }
            if io_waiter.swap(INVALID, Ordering::AcqRel) != INVALID {
                wake_sent.store(true, Ordering::Release);
            }
        })
    };

    // REAP_WAIT consumer: try to block once.
    let slept = {
        if cq.load(Ordering::Acquire) > 0 {
            false
        } else {
            io_waiter.store(WAITER_TID, Ordering::Release); // register intent
            if let Discipline::SeqCstFence = d {
                fence(Ordering::SeqCst);
            }
            if cq.load(Ordering::Acquire) > 0 {
                io_waiter.store(INVALID, Ordering::Release); // got work, unregister
                false
            } else {
                true // commit to sleep
            }
        }
    };

    producer.join().unwrap();
    (slept, wake_sent.load(Ordering::Acquire))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed discipline (SeqCst fence on each side): whenever the server sleeps,
    /// a wake must have been sent. No lost wakeup across any interleaving.
    #[test]
    fn reap_wait_seqcst_fence_no_lost_wakeup() {
        loom::model(|| {
            let (slept, wake_sent) = run(Discipline::SeqCstFence);
            if slept {
                assert!(wake_sent, "LOST WAKEUP: server slept but no wake was sent");
            }
        });
    }

    /// Buggy discipline (Release/Acquire only, no fence): loom finds the
    /// store-load race where the server sleeps with a CQE pending and no wake.
    #[test]
    #[should_panic]
    fn weak_recheck_loses_wakeup() {
        loom::model(|| {
            let (slept, wake_sent) = run(Discipline::WeakRecheck);
            if slept {
                assert!(wake_sent, "LOST WAKEUP: server slept but no wake was sent");
            }
        });
    }
}
