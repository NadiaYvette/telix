//! Completion-ring teardown ‖ deliver-hook race — loom model.
//!
//! Models the Phase-A ring-lifecycle fix (project_completion_ring_lifecycle).
//! A task's completion context is `io_depth` (the deliver-hook gate) plus two
//! ring pages reached via the direct-map `io_cq_kva`.  Two actors race:
//!
//!   * DELIVER HOOK (sender CPU, kernel/src/syscall/port.rs ~944 ->
//!     ipc/completion.rs ~519): `if io_depth != 0 { write CQE into the ring page }`.
//!   * clear_completion_ctx (exec via aspace::reset, or exit): clears `io_depth`
//!     and FREES the two ring pages.
//!
//!     INVARIANT: no deliver hook ever writes into a ring page that
//!     clear_completion_ctx has freed.
//!
//! `naive_immediate_free_is_use_after_free` (#[should_panic]) — the naive clear
//! (store io_depth=0, then free the page right away) loses the race: loom finds
//! the interleaving where a deliver that already passed the `io_depth != 0` gate
//! writes into the just-freed page.
//!
//! `rcu_grace_period_free_is_safe` — the fix: publish io_depth=0, then wait for
//! in-flight delivers to quiesce (RCU grace period) BEFORE freeing.  Safe under
//! every interleaving loom explores.
//!
//! WHY AN RwLock AND NOT A FLAG: the grace period is the crux. An obvious model
//! is a Dekker-style flag handshake (reader sets "in_deliver", clear publishes
//! io_depth=0 then spins until "in_deliver" clears), but that is only correct
//! under SeqCst's single total order — and loom does NOT fully model SeqCst, so
//! it reports a false UAF on that (actually-correct) construct.  So we model the
//! grace period with an `RwLock` instead, which loom models precisely: the
//! deliver holds a READ guard across its gate-check + write; the clear takes the
//! WRITE guard (= `synchronize_rcu`, which blocks until all readers drain) before
//! freeing.  This captures the grace period's SAFETY property (the free
//! happens-after every in-flight reader) — which is exactly the invariant — even
//! though real RCU readers are lock-free (a performance property we are not
//! verifying).
//!
//! KERNEL FIDELITY: the real deliver hook must therefore run inside a recognized
//! RCU read-side section (preempt-off / rcu_read_lock) so the kernel's grace
//! period actually covers it, and the page free must be deferred via call_rcu /
//! the existing RCU-defer path (aspace.rs:557) — NOT freed synchronously.

#![cfg(loom)]

use loom::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use loom::sync::{Arc, RwLock};
use loom::thread;

/// Shared completion context + the ring page's liveness + the RCU grace lock.
struct Ring {
    /// Deliver-hook gate: 0 = no completion context. Starts at 1 (set up).
    io_depth: AtomicU32,
    /// The ring page (io_cq_kva target): true once clear_completion_ctx freed it.
    /// A deliver writing while this is true is a use-after-free.
    freed: AtomicBool,
    /// RCU read-side / grace period (see the WHY note above).
    rcu: RwLock<()>,
}

impl Ring {
    fn new() -> Self {
        Ring {
            io_depth: AtomicU32::new(1),
            freed: AtomicBool::new(false),
            rcu: RwLock::new(()),
        }
    }

    /// The ring-page access: assert we never touch a freed page.
    fn write_cqe(&self) {
        assert!(
            !self.freed.load(Ordering::Acquire),
            "deliver hook wrote a CQE into a FREED ring page (use-after-free)",
        );
    }
}

// ---- NAIVE (buggy): no read-side, immediate free ----------------------------

fn deliver_naive(r: &Ring) {
    if r.io_depth.load(Ordering::Acquire) != 0 {
        r.write_cqe();
    }
}

fn clear_naive(r: &Ring) {
    r.io_depth.store(0, Ordering::Release);
    r.freed.store(true, Ordering::Release); // free NOW — no grace period
}

// ---- FIXED (RCU-deferred): read-side + grace-period free --------------------

fn deliver_rcu(r: &Ring) {
    let _read = r.rcu.read().unwrap(); // enter RCU read-side
    if r.io_depth.load(Ordering::Acquire) != 0 {
        r.write_cqe();
    }
} // read-side ends when _read drops

fn clear_rcu(r: &Ring) {
    r.io_depth.store(0, Ordering::Release); // stop the gate FIRST
    let _grace = r.rcu.write().unwrap(); // synchronize_rcu: blocks until readers drain
    r.freed.store(true, Ordering::Release); // now no in-flight deliver can touch it
}

fn run_naive() {
    let r = Arc::new(Ring::new());
    let (r1, r2) = (r.clone(), r.clone());
    let t1 = thread::spawn(move || deliver_naive(&r1));
    let t2 = thread::spawn(move || clear_naive(&r2));
    t1.join().unwrap();
    t2.join().unwrap();
}

fn run_rcu() {
    let r = Arc::new(Ring::new());
    let (r1, r2) = (r.clone(), r.clone());
    let t1 = thread::spawn(move || deliver_rcu(&r1));
    let t2 = thread::spawn(move || clear_rcu(&r2));
    t1.join().unwrap();
    t2.join().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BUG: immediate free races a deliver that already passed the gate.
    #[test]
    #[should_panic(expected = "FREED ring page")]
    fn naive_immediate_free_is_use_after_free() {
        loom::model(run_naive);
    }

    /// FIX: publish io_depth=0, then a grace period (write guard waits for all
    /// in-flight read-side delivers) before freeing. No UAF under any interleaving.
    #[test]
    fn rcu_grace_period_free_is_safe() {
        loom::model(run_rcu);
    }
}
