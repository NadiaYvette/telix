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
/// `on_cpu` intermediate: released but NOT yet claimable — the committed part-A
/// fix's `ON_CPU_RELEASING`.  The claim CAS (PENDING→cpu) rejects it.
const RELEASING: u32 = 3;

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

    /// A STALE ORPHAN sitting in a heap: `on_cpu` still names cpu0 but cpu0 no
    /// longer executes it (`run0=false`).  The guarded pick MUST still dispatch
    /// it — over-deferring orphans is the #262 rescue-churn regression.
    fn orphan_queued() -> Self {
        Thread {
            on_cpu: AtomicU32::new(0),    // stale real-cpu lease
            run0: AtomicBool::new(false), // NOT executing on cpu0
            run1: AtomicBool::new(false),
            queued: AtomicBool::new(true), // poppable from a heap
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

// ── pick‖release race: the PROVEN kernel bug (boot 91amfsq66) ───────────────
//
// The committed part-A fix publishes the non-claimable ON_CPU_RELEASING during
// the release window (off-kstack-first) and only flips it to PENDING at the
// off-kstack finalize.  BUT the dispatch PICK (dequeue_set_pending) does an
// UNCONDITIONAL `on_cpu.store(PENDING)` right after popping — overwriting
// RELEASING — and then claims.  That blind re-stamp defeats the release
// protection: a peer pops + re-stamps + runs the Thread while its prior CPU is
// still executing it (run0).  This is why part-A alone was insufficient.

/// cpu0 releases with the part-A protocol: RELEASING (on-kstack, non-claimable)
/// → enqueue → leave the kstack (`run0=false`) → finalize RELEASING→PENDING.
fn release_with_releasing(t: &Thread) {
    t.on_cpu.store(RELEASING, Ordering::Release); // on-kstack intermediate
    t.queued.store(true, Ordering::Release); // enqueue to a peer / steal target
    t.run0.store(false, Ordering::Release); // leave the kstack
    // finalize: flip RELEASING→PENDING via CAS, so a racing blind PENDING store
    // is not clobbered back to PENDING twice (no-op if already overwritten).
    let _ = t
        .on_cpu
        .compare_exchange(RELEASING, PENDING, Ordering::AcqRel, Ordering::Acquire);
}

/// BUG: `dequeue_set_pending`'s unconditional PENDING store at the pick.  Pops,
/// blindly stamps PENDING (overwriting RELEASING / the prior lease), then claims
/// + runs — ignoring whether the prior CPU is still executing the Thread.
fn pick_blind_store(t: &Thread) {
    if !t.queued.swap(false, Ordering::AcqRel) {
        return; // not enqueued
    }
    t.on_cpu.store(PENDING, Ordering::Release); // <-- THE BUG: blind re-stamp
    if t
        .on_cpu
        .compare_exchange(PENDING, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        t.run1.store(true, Ordering::Release);
        assert!(
            !t.run0.load(Ordering::Acquire),
            "DOUBLE-DISPATCH: blind pick re-stamped PENDING over RELEASING while cpu0 ran",
        );
    } else {
        t.queued.store(true, Ordering::Release);
    }
}

/// FIX (part B): the pick does NOT blind-store PENDING.  It inspects the lease
/// and re-defers IFF the Thread is RELEASING, or still EXECUTING on its prior CPU
/// (`on_cpu==c ∧ run[c]`) — the DD-dangerous states.  Otherwise (claimable
/// PENDING, OR a STALE real-cpu lease whose CPU no longer runs it = an orphan) it
/// claims via CAS from the *observed* lease.
///
/// NOTE the precision: pure `CAS(PENDING→1)` is also DD-safe but re-defers
/// orphans too — that over-deferral is the #262 rescue-churn regression
/// (`guarded_pick_dispatches_stale_orphan` fails for it).  So the guard must
/// claim from a stale-cpu lease as well, while still refusing a running one.
fn pick_guarded(t: &Thread) {
    if !t.queued.swap(false, Ordering::AcqRel) {
        return; // not enqueued
    }
    let on = t.on_cpu.load(Ordering::Acquire);
    // DD-dangerous: finalize not done (RELEASING), or cpu0 still executing it.
    if on == RELEASING || (on == 0 && t.run0.load(Ordering::Acquire)) {
        t.queued.store(true, Ordering::Release); // re-defer; not safely claimable
        return;
    }
    // Claimable (PENDING) or stale orphan (on==0 ∧ !run0): claim from the
    // observed lease.  If it changed under us (finalize RELEASING→PENDING, or a
    // peer claimed), the CAS fails and we re-defer — no double-dispatch.
    if t
        .on_cpu
        .compare_exchange(on, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        t.run1.store(true, Ordering::Release);
        assert!(
            !t.run0.load(Ordering::Acquire),
            "DOUBLE-DISPATCH: guarded pick claimed while cpu0 still ran",
        );
    } else {
        t.queued.store(true, Ordering::Release);
    }
}

/// STRENGTHENED guard (the kernel fix): scan EXECUTION STATE directly
/// (current_thread[any]==tid, modelled run0||run1) — NOT on_cpu — so it catches
/// producers that stamped on_cpu=PENDING while the Thread still runs (rescue,
/// boot 91amfsq73).  Re-defers if executing anywhere or RELEASING; else claims
/// (PENDING or stale orphan) via CAS from the observed lease.
fn pick_guarded_strong(t: &Thread) {
    if !t.queued.swap(false, Ordering::AcqRel) {
        return;
    }
    if t.run0.load(Ordering::Acquire) || t.run1.load(Ordering::Acquire) {
        // executing on some cpu → not safely claimable, regardless of on_cpu.
        t.queued.store(true, Ordering::Release);
        return;
    }
    let on = t.on_cpu.load(Ordering::Acquire);
    if on == RELEASING {
        t.queued.store(true, Ordering::Release);
        return;
    }
    if t
        .on_cpu
        .compare_exchange(on, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        t.run1.store(true, Ordering::Release);
        assert!(
            !t.run0.load(Ordering::Acquire),
            "DOUBLE-DISPATCH: strong guard claimed while cpu0 still ran",
        );
    } else {
        t.queued.store(true, Ordering::Release);
    }
}

/// A RESCUE-style producer (boot 91amfsq73, site8): blindly re-stamps
/// on_cpu=PENDING and re-enqueues a Thread STILL executing on cpu0 (run0 stays
/// true).  The blind PENDING store HIDES the running state from an on_cpu-only
/// pick guard, which then dispatches it → double-dispatch.
fn rescue_restamp_running(t: &Thread) {
    t.on_cpu.store(PENDING, Ordering::Release); // overwrite the real-cpu lease
    t.queued.store(true, Ordering::Release); // re-enqueue (poppable)
}

fn run_releasing(blind: bool) {
    let t = Arc::new(Thread::running_on_cpu0());
    let tr = t.clone();
    let releaser = thread::spawn(move || release_with_releasing(&tr));
    if blind {
        pick_blind_store(&t);
    } else {
        pick_guarded(&t);
    }
    releaser.join().unwrap();
}

/// Liveness scenario: a STALE orphan + the guarded pick, no concurrent releaser.
/// This checks the guard's DECISION (not an interleaving): the orphan MUST be
/// dispatched, not re-deferred.  Pure CAS(PENDING→1) would FAIL this assert
/// (it can't claim the stale-cpu lease) — that over-deferral is the #262
/// rescue-churn regression; the precise guard claims it.
fn run_orphan_liveness() {
    let t = Arc::new(Thread::orphan_queued());
    pick_guarded(&t);
    assert!(
        t.run1.load(Ordering::Acquire),
        "LIVENESS: guarded pick over-deferred a stale orphan (= #262 rescue churn)",
    );
}

/// Rescue scenario: cpu0 is executing the Thread (run0=true) when a rescue
/// re-stamps it PENDING + re-enqueues.  `strong` selects the execution-state
/// guard (catches it) vs the on_cpu-only guard (misses it → DD).
fn run_rescue(strong: bool) {
    let t = Arc::new(Thread::running_on_cpu0()); // cpu0 still executing (run0=true)
    let tr = t.clone();
    let rescuer = thread::spawn(move || rescue_restamp_running(&tr));
    if strong {
        pick_guarded_strong(&t);
    } else {
        pick_guarded(&t);
    }
    rescuer.join().unwrap();
}

/// The strengthened guard must be a strict SUPERSET of the on_cpu guard: also
/// DD-free against the release scenario.
fn run_releasing_strong() {
    let t = Arc::new(Thread::running_on_cpu0());
    let tr = t.clone();
    let releaser = thread::spawn(move || release_with_releasing(&tr));
    pick_guarded_strong(&t);
    releaser.join().unwrap();
}

/// ...and must still dispatch a stale orphan (liveness — no #262 over-deferral).
fn run_orphan_liveness_strong() {
    let t = Arc::new(Thread::orphan_queued());
    pick_guarded_strong(&t);
    assert!(
        t.run1.load(Ordering::Acquire),
        "LIVENESS: strong guard over-deferred a stale orphan (= #262 rescue churn)",
    );
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

    /// PROVEN KERNEL BUG (boot 91amfsq66): even with the part-A RELEASING release,
    /// the pick's unconditional `on_cpu.store(PENDING)` (dequeue_set_pending)
    /// overwrites RELEASING and lets cpu1 claim+run while cpu0 still executes.
    /// loom finds the interleaving where cpu0 is paused after enqueue, before it
    /// has left the kstack.  This is why part-A alone did not close DD.
    #[test]
    #[should_panic(expected = "DOUBLE-DISPATCH")]
    fn blind_pick_overwrites_releasing_double_dispatches() {
        loom::model(|| run_releasing(true));
    }

    /// FIX (part B) SAFETY: the guarded pick re-defers a RELEASING/executing
    /// Thread instead of blind-stamping it claimable, so it is DD-free against
    /// the very release the blind pick breaks on.
    #[test]
    fn guarded_pick_with_releasing_is_dd_free() {
        loom::model(|| run_releasing(false));
    }

    /// FIX (part B) LIVENESS: the guarded pick must STILL dispatch a stale orphan
    /// (on_cpu names a CPU that no longer runs it).  A pure CAS(PENDING→1) guard
    /// would over-defer it → #262 rescue churn; the precise guard claims it.
    /// Proves the fix trades #208 for nothing (not for #262).
    #[test]
    fn guarded_pick_dispatches_stale_orphan() {
        loom::model(run_orphan_liveness);
    }

    /// REGRESSION (boot 91amfsq73): the on_cpu-only guard MISSES a rescue producer
    /// that stamped on_cpu=PENDING while the Thread still executes — it reads PENDING
    /// ("claimable") and dispatches → DD.  Proves the on_cpu check is insufficient;
    /// the guard must scan execution state directly.
    #[test]
    #[should_panic(expected = "DOUBLE-DISPATCH")]
    fn rescue_restamp_defeats_oncpu_guard() {
        loom::model(|| run_rescue(false));
    }

    /// FIX (strengthened guard): scanning execution state directly catches the
    /// rescue producer regardless of on_cpu → re-defers → DD-free.
    #[test]
    fn strong_guard_survives_rescue_restamp() {
        loom::model(|| run_rescue(true));
    }

    /// The strengthened guard is a strict superset: still DD-free vs the release.
    #[test]
    fn strong_guard_is_dd_free_vs_release() {
        loom::model(run_releasing_strong);
    }

    /// ...and still dispatches a stale orphan (no #262 over-deferral).
    #[test]
    fn strong_guard_dispatches_stale_orphan() {
        loom::model(run_orphan_liveness_strong);
    }
}
