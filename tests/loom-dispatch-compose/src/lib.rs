//! Composed run-queue ⋈ claim ⋈ release model for #173 / #208 double-dispatch.
//!
//! The kernel's double-dispatch (two CPUs executing one Thread → shared kstack →
//! the #208 wild-RIP scribble) is NOT visible to either single-side loom model
//! we already have:
//!   * loom-claim-helper models the `on_cpu` claim mutex — and proves the CAS
//!     makes a double-*claim* impossible.  But DD does NOT require a double
//!     claim: it requires a thread to be *claimable* (on_cpu == PENDING) while
//!     its previous CPU is *still executing it*.  That's the release side.
//!   * loom-runqueue-v2 models `in_queue` membership — the enqueue/strand side.
//!
//! Neither carries an explicit notion of "which CPU is *executing* (current_thread
//! ==) this Thread" — the kstack owner — which is the thing DD violates.  This
//! model adds it (`run0`/`run1`) and proves the real invariant:
//!
//!     INVARIANT (no double-dispatch): at every instant, at most one CPU has
//!     this Thread as its running/current thread.  i.e. never (run0 ∧ run1).
//!
//! v1 isolates the release⋈claim core (one preempt-releaser on cpu0, one
//! pick+claimer on cpu1) to prove the load-bearing conditions for DD-freedom:
//!   (1) the preempt path must leave the kstack (clear `run0`) BEFORE it
//!       publishes `on_cpu = PENDING` (makes the Thread claimable) — the
//!       real-park / Fix-D "off-kstack point" ordering; and
//!   (2) that `on_cpu = PENDING` publish must be Release (paired with the
//!       claimer's Acquire CAS) — a Relaxed publish reopens the race.
//! The claim CAS being a perfect mutex is necessary but NOT sufficient; this is
//! what the single-side claim-helper proof could not show.

#![cfg(loom)]

use loom::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use loom::sync::Arc;
use loom::thread;

/// `on_cpu` sentinel: the Thread is claimable by any CPU.  Real CPUs are 0 / 1.
const PENDING: u32 = 2;

/// One Thread, shared by two CPUs.
struct Thread {
    /// Claim lease (the dispatch mutex target): a real cpu id, or PENDING.
    on_cpu: AtomicU32,
    /// `run{i}` = "this Thread is the current/executing thread on cpu i" — the
    /// kstack owner.  DD ⇔ run0 ∧ run1.  (Two bools, not one AtomicU32, so a
    /// transient overlap is observable rather than collapsed.)
    run0: AtomicBool,
    run1: AtomicBool,
    /// Run-queue membership: the Thread is enqueued and poppable by a picker.
    queued: AtomicBool,
}

impl Thread {
    /// Initial state: executing on cpu 0 (claimed + running there), not queued.
    fn running_on_cpu0() -> Self {
        Thread {
            on_cpu: AtomicU32::new(0),
            run0: AtomicBool::new(true),
            run1: AtomicBool::new(false),
            queued: AtomicBool::new(false),
        }
    }
}

/// cpu 0 preempts the Thread: it re-enqueues it (so a peer may pick it up — the
/// migration that sets up DD), then relinquishes ownership.
///
/// `off_kstack_first` — clear `run0` (leave the kstack) BEFORE publishing
/// `on_cpu = PENDING`.  True = the real-park / Fix-D ordering; false = the bug
/// (publish the claim while still executing).
/// `pending_ord` — memory ordering of the `on_cpu = PENDING` publish.
fn preempt_release(t: &Thread, off_kstack_first: bool, pending_ord: Ordering) {
    // Re-enqueue: the Thread is runnable, so the preempt path makes it poppable.
    t.queued.store(true, Ordering::Release);
    if off_kstack_first {
        t.run0.store(false, Ordering::Release); // off the kstack...
        t.on_cpu.store(PENDING, pending_ord); // ...THEN make it claimable
    } else {
        t.on_cpu.store(PENDING, pending_ord); // claimable WHILE still executing
        t.run0.store(false, Ordering::Release);
    }
}

/// cpu 1 dispatches: pop from the run-queue, claim via CAS(PENDING→1), then run.
fn pick_and_claim(t: &Thread) {
    if !t.queued.swap(false, Ordering::AcqRel) {
        return; // not enqueued — nothing to dispatch
    }
    if t
        .on_cpu
        .compare_exchange(PENDING, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // We hold the claim lease.  Begin executing on cpu 1.
        t.run1.store(true, Ordering::Release);
        // INVARIANT: the previous owner (cpu 0) must already be off the kstack.
        // If it is still executing, two CPUs run one Thread = double-dispatch.
        assert!(
            !t.run0.load(Ordering::Acquire),
            "DOUBLE-DISPATCH: cpu0 still executing when cpu1 claimed+ran",
        );
    } else {
        // Lost the claim (owned elsewhere) — put it back for the owner/rescue.
        t.queued.store(true, Ordering::Release);
    }
}

fn run(off_kstack_first: bool, pending_ord: Ordering) {
    let t = Arc::new(Thread::running_on_cpu0());
    let tr = t.clone();
    let releaser = thread::spawn(move || preempt_release(&tr, off_kstack_first, pending_ord));
    pick_and_claim(&t);
    releaser.join().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BUG: publishing `on_cpu = PENDING` while still executing (`run0` true)
    /// lets cpu1 claim+run concurrently.  loom must find the interleaving where
    /// the releaser is paused between the PENDING publish and `run0 = false`.
    #[test]
    #[should_panic(expected = "DOUBLE-DISPATCH")]
    fn buggy_publish_while_running_double_dispatches() {
        loom::model(|| run(false, Ordering::Release));
    }

    /// FIX: leave the kstack (`run0 = false`, Release) BEFORE publishing
    /// `on_cpu = PENDING` (Release).  cpu1's Acquire CAS synchronizes-with that
    /// publish, so it is guaranteed to observe `run0 == false`.  No interleaving
    /// double-dispatches.  (This is the property the claim-helper proof alone
    /// could not establish — it needs the execution-state + release ordering.)
    #[test]
    fn off_kstack_first_release_is_dd_free() {
        loom::model(|| run(true, Ordering::Release));
    }

    /// FENCE IS LOAD-BEARING: correct off-kstack-first order, but the
    /// `on_cpu = PENDING` publish is Relaxed → no release sequence pairs with
    /// the claimer's Acquire CAS → `run0 = false` is not guaranteed visible →
    /// DD returns.  Proves the Release on the claim publish is required, not
    /// incidental.
    #[test]
    #[should_panic(expected = "DOUBLE-DISPATCH")]
    fn off_kstack_first_but_relaxed_publish_reintroduces_dd() {
        loom::model(|| run(true, Ordering::Relaxed));
    }
}
