//! Loom model of the #173 dispatch claim helper.
//!
//! Validates the core invariants of `percpu_pick_next_and_claim` and
//! `percpu_pick_next_cosched_and_claim` (kernel/src/sched/scheduler.rs):
//!
//!  1. **CAS mutex**: at most one of {helper@A, helper@B, rescue}
//!     successfully claims a thread per attempt window.
//!  2. **Self-pick correctness**: when CAS fails AND on_cpu re-reads
//!     as `this_cpu`, the helper returns the tid (not idle).  This is
//!     the case where the picker popped `prev_id` that's still running
//!     on us (concurrent rescue/wake re-enqueued it during execution).
//!  3. **No spurious idle preempt**: try_switch must never swap to
//!     idle when prev is still running.
//!
//! The model abstracts the rq lock — we model only the on_cpu CAS
//! transitions, since the rq lock makes the pop+CAS step atomic from
//! the perspective of other CPUs.  This gives loom a tractable search
//! space while still exercising the key correctness property.

#![allow(dead_code)]

#[cfg(loom)]
use loom::sync::atomic::{AtomicU32, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(loom)]
use loom::thread;
#[cfg(not(loom))]
use std::thread;

#[cfg(loom)]
use loom::sync::Arc;
#[cfg(not(loom))]
use std::sync::Arc;

// On-cpu encoding matching scheduler.rs.
const ON_CPU_PENDING: u32 = u32::MAX - 1;
const ON_CPU_MAX: u32 = u32::MAX;
const CPU_A: u32 = 0;
const CPU_B: u32 = 1;
// #173 fix B (reclaim_stale_on_cpu): a third CPU id + the ncpus bound so the
// `on >= ncpus` sentinel test in the reclaim path is exercised.  Real CPUs are
// 0..NCPUS; PENDING/MAX are >= NCPUS.
const CPU_C: u32 = 2;
const NCPUS: u32 = 3;

/// Helper outcome — used by callers to decide whether to switch.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ClaimOutcome {
    /// CAS won — claimed the thread for `this_cpu`.  Caller should
    /// switch to it.
    Claimed(u32),
    /// CAS failed but on_cpu reads as `this_cpu` — self-pick.  Caller
    /// should treat this as no-op (prev still running).
    SelfPick(u32),
    /// CAS failed and on_cpu is on another CPU.  Caller should drop
    /// and retry (next iteration in the helper's loop).
    Lost,
}

/// The tid under test.  Nonzero; 0 means "no thread" in `holding`.
const TID: u32 = 7;

struct ThreadModel {
    on_cpu: AtomicU32,
    /// `holding[c] == TID` iff CPU `c` is mid-claiming **or** running TID.
    /// Models `PerCpuData.dispatching_tid`/`current_thread` as seen by the
    /// stale-check: #173 fix B publishes this BEFORE the claim CAS (and the
    /// kernel keeps it set through `current_thread` until dispatch completes),
    /// so a concurrent reclaimer observes an in-flight claim and declines.
    holding: [AtomicU32; NCPUS as usize],
}

impl ThreadModel {
    fn picked() -> Self {
        // After the rq.pop step, on_cpu is whatever the enqueue path
        // last set it to — ON_CPU_PENDING in the canonical case (Type
        // B enqueue stamp).
        Self {
            on_cpu: AtomicU32::new(ON_CPU_PENDING),
            holding: [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)],
        }
    }
    fn running_on(cpu: u32) -> Self {
        // Self-pick scenario: thread is currently running on `cpu`,
        // got concurrently re-enqueued, and the helper just popped it.
        Self {
            on_cpu: AtomicU32::new(cpu),
            holding: [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)],
        }
    }
}

/// Model of the claim helper's single-attempt CAS + self-pick check.
///
/// Returns `ClaimOutcome::Claimed(cpu)` on success, `SelfPick(cpu)` on
/// CAS-fail with on_cpu == this_cpu, `Lost` otherwise.
fn claim_attempt(t: &ThreadModel, this_cpu: u32) -> ClaimOutcome {
    match t.on_cpu.compare_exchange(
        ON_CPU_PENDING,
        this_cpu,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => ClaimOutcome::Claimed(this_cpu),
        Err(_) => {
            // Self-pick re-read: if on_cpu is still this_cpu, prev is
            // running on us.  Otherwise some other path owns it.
            if t.on_cpu.load(Ordering::Acquire) == this_cpu {
                ClaimOutcome::SelfPick(this_cpu)
            } else {
                ClaimOutcome::Lost
            }
        }
    }
}

/// Model of the rescue's fast-takeover: CAS PENDING → MAX.
fn rescue_attempt(t: &ThreadModel) -> bool {
    t.on_cpu
        .compare_exchange(ON_CPU_PENDING, ON_CPU_MAX, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Faithful model of the #173 fix B dispatch claim at one call site:
/// publish dispatch intent (`holding[this_cpu] = TID`) BEFORE the claim CAS,
/// then `normal_claim || reclaim_stale_on_cpu`, exactly as the kernel does.
///
/// The stale-check reads the NAMED CPU's `holding` (= `dispatching_tid` ||
/// `current_thread`): if that CPU has an in-flight or running claim on TID,
/// the reclaim declines.  Because intent is published before the CAS, any
/// reclaimer that observes our claimed `on_cpu` also observes our `holding`,
/// so it cannot mistake a just-claimed thread for a stale orphan.
fn claim_or_reclaim(t: &ThreadModel, this_cpu: u32) -> ClaimOutcome {
    // Publish intent BEFORE any claim CAS.
    t.holding[this_cpu as usize].store(TID, Ordering::Release);
    // 1. Normal claim: CAS PENDING → this_cpu.  Leaves holding = TID.
    if t
        .on_cpu
        .compare_exchange(ON_CPU_PENDING, this_cpu, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        return ClaimOutcome::Claimed(this_cpu);
    }
    // 2. Reclaim path: on_cpu is not PENDING.  Re-read and classify.
    let on = t.on_cpu.load(Ordering::Acquire);
    if on >= NCPUS {
        // PENDING(again)/RELEASING/MAX/sentinel — owned by another lifecycle
        // path.  Clear our intent and drop.
        t.holding[this_cpu as usize].store(0, Ordering::Release);
        return ClaimOutcome::Lost;
    }
    if on == this_cpu {
        // Self-pick: prev still running on this CPU.  Report SelfPick so
        // try_switch doesn't preempt to idle (intent stays — it's ours).
        return ClaimOutcome::SelfPick(this_cpu);
    }
    if t.holding[on as usize].load(Ordering::Acquire) == TID {
        // Named CPU is mid-claiming or running TID — decline, don't steal.
        t.holding[this_cpu as usize].store(0, Ordering::Release);
        return ClaimOutcome::Lost;
    }
    // 3. Stale orphan — single CAS from the observed stale value.
    match t
        .on_cpu
        .compare_exchange(on, this_cpu, Ordering::AcqRel, Ordering::Acquire)
    {
        Ok(_) => ClaimOutcome::Claimed(this_cpu), // leaves holding = TID
        Err(_) => {
            t.holding[this_cpu as usize].store(0, Ordering::Release);
            ClaimOutcome::Lost
        }
    }
}

/// Model of the rescue's stale-orphan reclaim: it re-stamps a stale real-CPU
/// `on_cpu` back to PENDING (claimable) via CAS.  Returns true if it re-stamped.
fn rescue_stale_restamp(t: &ThreadModel, stale_cpu: u32) -> bool {
    t.on_cpu
        .compare_exchange(stale_cpu, ON_CPU_PENDING, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Construct a thread popped into the claim helper's hand with a STALE
/// real-CPU `on_cpu` (no CPU holds it) — the gate=ON orphan fix B recovers.
fn stale_orphan(stale_cpu: u32) -> ThreadModel {
    ThreadModel {
        on_cpu: AtomicU32::new(stale_cpu),
        holding: [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)],
    }
}

/// Construct a thread genuinely running on `cpu` (holding[cpu] = TID) but
/// still observed with on_cpu = cpu — the legitimate case the reclaim must
/// DECLINE rather than steal.
fn running_with_holding(cpu: u32) -> ThreadModel {
    let m = ThreadModel {
        on_cpu: AtomicU32::new(cpu),
        holding: [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)],
    };
    m.holding[cpu as usize].store(TID, Ordering::Release);
    m
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// **Invariant 1 — CAS mutex**: helper@A and rescue racing on a
/// PENDING thread.  At most one wins.  The other observes Lost (helper)
/// or false (rescue).
#[cfg(loom)]
#[test]
fn helper_vs_rescue_is_mutex() {
    loom::model(|| {
        let t = Arc::new(ThreadModel::picked());
        let t_h = t.clone();
        let t_r = t.clone();

        let h = thread::spawn(move || claim_attempt(&t_h, CPU_A));
        let r = thread::spawn(move || rescue_attempt(&t_r));

        let h_out = h.join().expect("helper join");
        let r_won = r.join().expect("rescue join");

        let h_won = matches!(h_out, ClaimOutcome::Claimed(_));

        // At most one winner.
        assert!(
            !(h_won && r_won),
            "MUTEX FAIL: both helper and rescue won. on_cpu={:#x}",
            t.on_cpu.load(Ordering::Acquire)
        );
        // At least one winner — CAS race is decisive.
        assert!(
            h_won || r_won,
            "LIVENESS FAIL: both helper and rescue lost. on_cpu={:#x}",
            t.on_cpu.load(Ordering::Acquire)
        );
        // Helper's loss should be Lost (not SelfPick) — the rescue
        // moved on_cpu to MAX, not to A.
        if !h_won {
            assert!(
                matches!(h_out, ClaimOutcome::Lost),
                "WRONG-OUTCOME: helper lost but did not report Lost ({:?})",
                h_out
            );
        }
    });
}

/// **Invariant 1b — helper@A vs helper@B**: two different CPUs
/// concurrently attempt to claim the same thread (via different rq's
/// — modeled here as two CAS attempts on the same atomic).  At most
/// one wins.  Note: in practice this race can't happen because a
/// thread is in exactly one rq at a time, and the rq lock makes
/// pop+CAS atomic per CPU.  This test confirms the on_cpu atomic
/// would still arbitrate correctly if it did.
#[cfg(loom)]
#[test]
fn helper_a_vs_helper_b_is_mutex() {
    loom::model(|| {
        let t = Arc::new(ThreadModel::picked());
        let t_a = t.clone();
        let t_b = t.clone();

        let h_a = thread::spawn(move || claim_attempt(&t_a, CPU_A));
        let h_b = thread::spawn(move || claim_attempt(&t_b, CPU_B));

        let a_out = h_a.join().expect("helper A join");
        let b_out = h_b.join().expect("helper B join");

        let a_won = matches!(a_out, ClaimOutcome::Claimed(_));
        let b_won = matches!(b_out, ClaimOutcome::Claimed(_));

        assert!(
            !(a_won && b_won),
            "MUTEX FAIL: both helper@A and helper@B claimed. on_cpu={:#x}",
            t.on_cpu.load(Ordering::Acquire)
        );
        assert!(
            a_won || b_won,
            "LIVENESS FAIL: neither helper won. on_cpu={:#x}",
            t.on_cpu.load(Ordering::Acquire)
        );
    });
}

/// **Invariant 2 — self-pick correctness**: thread is already running
/// on A (on_cpu = A).  Helper@A pops it from the rq (it was
/// concurrently re-enqueued).  CAS PENDING→A must fail because on_cpu
/// is A (not PENDING).  Re-read sees A → self-pick.  Helper returns
/// SelfPick(A), NOT Lost.
///
/// This is the load-bearing case for try_switch — if helper reported
/// Lost here, try_switch would drop prev and possibly preempt to idle.
#[cfg(loom)]
#[test]
fn self_pick_detected_correctly() {
    loom::model(|| {
        let t = Arc::new(ThreadModel::running_on(CPU_A));
        let t_h = t.clone();

        let h = thread::spawn(move || claim_attempt(&t_h, CPU_A));

        let out = h.join().expect("helper join");

        assert!(
            matches!(out, ClaimOutcome::SelfPick(CPU_A)),
            "SELF-PICK FAIL: expected SelfPick(CPU_A), got {:?}.  This would cause try_switch to spuriously preempt prev to idle.",
            out
        );
        // on_cpu stays A.
        assert_eq!(
            t.on_cpu.load(Ordering::Acquire),
            CPU_A,
            "self-pick path mutated on_cpu — must be a no-op transition"
        );
    });
}

/// **Invariant 2b — self-pick under concurrent rescue**: thread is
/// running on A.  Helper@A pops it (re-enqueued).  Rescue races trying
/// to fast-takeover.  Rescue must fail (on_cpu is A, not PENDING).
/// Helper must observe SelfPick.
#[cfg(loom)]
#[test]
fn self_pick_under_concurrent_rescue() {
    loom::model(|| {
        let t = Arc::new(ThreadModel::running_on(CPU_A));
        let t_h = t.clone();
        let t_r = t.clone();

        let h = thread::spawn(move || claim_attempt(&t_h, CPU_A));
        let r = thread::spawn(move || rescue_attempt(&t_r));

        let h_out = h.join().expect("helper join");
        let r_won = r.join().expect("rescue join");

        // Rescue must NOT have won — on_cpu was A throughout, not
        // PENDING.  The CAS PENDING→MAX has no PENDING to match.
        assert!(
            !r_won,
            "RESCUE-SPURIOUS: rescue CAS'd PENDING→MAX but on_cpu was already A.  on_cpu={:#x}",
            t.on_cpu.load(Ordering::Acquire)
        );
        // Helper's outcome should be SelfPick(A).
        assert!(
            matches!(h_out, ClaimOutcome::SelfPick(CPU_A)),
            "SELF-PICK FAIL under concurrent rescue: got {:?}",
            h_out
        );
        assert_eq!(t.on_cpu.load(Ordering::Acquire), CPU_A);
    });
}

/// **Invariant 3 — recoverability**: after any race, the thread's
/// on_cpu is in a well-defined state for the scheduler to make
/// progress: either a real CPU number, ON_CPU_PENDING (someone will
/// pick it next sweep), or ON_CPU_MAX (rescue path will re-enqueue).
/// No interleaving leaves on_cpu in an undefined or stuck state.
#[cfg(loom)]
#[test]
fn terminal_state_is_recoverable() {
    loom::model(|| {
        let t = Arc::new(ThreadModel::picked());
        let t_h = t.clone();
        let t_r = t.clone();

        let h = thread::spawn(move || claim_attempt(&t_h, CPU_A));
        let r = thread::spawn(move || rescue_attempt(&t_r));

        let _ = h.join();
        let _ = r.join();

        let final_on_cpu = t.on_cpu.load(Ordering::Acquire);
        let recoverable = final_on_cpu == CPU_A
            || final_on_cpu == ON_CPU_MAX
            || final_on_cpu == ON_CPU_PENDING;
        assert!(
            recoverable,
            "STUCK: on_cpu={:#x} not in {{A, PENDING, MAX}}",
            final_on_cpu
        );
    });
}

// ---------------------------------------------------------------------------
// #173 fix B — stale-on_cpu reclaim invariants
// ---------------------------------------------------------------------------

/// **Reclaim liveness**: a stale orphan (on_cpu = real CPU C, nobody holding
/// it) popped by helper@A is recovered — A claims it instead of dropping it
/// on the floor.  This is the gate=ON wedge that fix B closes.
#[cfg(loom)]
#[test]
fn stale_reclaim_recovers_orphan() {
    loom::model(|| {
        let t = Arc::new(stale_orphan(CPU_C));
        let t_a = t.clone();
        let out = thread::spawn(move || claim_or_reclaim(&t_a, CPU_A))
            .join()
            .expect("helper join");
        assert!(
            matches!(out, ClaimOutcome::Claimed(CPU_A)),
            "RECLAIM-LIVENESS FAIL: stale orphan not recovered, got {:?}",
            out
        );
        assert_eq!(t.on_cpu.load(Ordering::Acquire), CPU_A);
    });
}

/// **Reclaim safety — decline a genuinely running/claiming thread**: on_cpu =
/// C and C holds tid (mid-claim or running — the legitimate direct-dispatch-
/// raced-the-pick case).  The reclaim MUST decline (Lost) and leave on_cpu = C
/// — it must never steal a thread another CPU is dispatching.
#[cfg(loom)]
#[test]
fn stale_reclaim_declines_running() {
    loom::model(|| {
        let t = Arc::new(running_with_holding(CPU_C));
        let t_a = t.clone();
        let out = thread::spawn(move || claim_or_reclaim(&t_a, CPU_A))
            .join()
            .expect("helper join");
        assert!(
            matches!(out, ClaimOutcome::Lost),
            "RECLAIM-SAFETY FAIL: reclaimed a held thread, got {:?}",
            out
        );
        assert_eq!(
            t.on_cpu.load(Ordering::Acquire),
            CPU_C,
            "reclaim mutated on_cpu of a held thread"
        );
    });
}

/// **Reclaim mutex — two reclaimers race (the v1 double-dispatch bug)**: two
/// CPUs both observe the same stale orphan and both run the publish-then-claim
/// path concurrently.  With #173 fix B publishing `holding` BEFORE the claim
/// CAS, the loser observes the winner's `holding` (once it sees the claimed
/// on_cpu) and declines — so at most one claims.  Without publish-before-CAS,
/// loom flags this as DOUBLE-DISPATCH (the v1 failure).
#[cfg(loom)]
#[test]
fn stale_reclaim_two_reclaimers_is_mutex() {
    loom::model(|| {
        let t = Arc::new(stale_orphan(CPU_C));
        let (ta, tb) = (t.clone(), t.clone());
        let a = thread::spawn(move || claim_or_reclaim(&ta, CPU_A));
        let b = thread::spawn(move || claim_or_reclaim(&tb, CPU_B));
        let ao = a.join().expect("A join");
        let bo = b.join().expect("B join");
        let aw = matches!(ao, ClaimOutcome::Claimed(_));
        let bw = matches!(bo, ClaimOutcome::Claimed(_));
        assert!(!(aw && bw), "DOUBLE-DISPATCH: both A and B claimed the orphan");
        assert!(aw || bw, "RECLAIM-LIVENESS FAIL: neither claimed orphan");
    });
}

/// **Reclaim coexists with rescue (single-owner)**: helper@A reclaims the
/// stale orphan (CAS C→A) while the rescue concurrently re-stamps it back to
/// PENDING (CAS C→PENDING).  The on_cpu CAS arbitrates.  Note: the rescue only
/// re-stamps (it never dispatches), so "A claims AND rescue re-stamped" is the
/// intended happy path — the rescue resets the orphan to PENDING and A then
/// claims that PENDING via the normal CAS.  The real safety property is that A
/// is the SOLE dispatcher: if A claimed, on_cpu == A; and the terminal state is
/// always recoverable.
#[cfg(loom)]
#[test]
fn stale_reclaim_vs_rescue_single_owner() {
    loom::model(|| {
        let t = Arc::new(stale_orphan(CPU_C));
        let (ta, tr) = (t.clone(), t.clone());
        let a = thread::spawn(move || claim_or_reclaim(&ta, CPU_A));
        let r = thread::spawn(move || rescue_stale_restamp(&tr, CPU_C));
        let ao = a.join().expect("A join");
        let _restamped = r.join().expect("rescue join");
        if matches!(ao, ClaimOutcome::Claimed(CPU_A)) {
            assert_eq!(
                t.on_cpu.load(Ordering::Acquire),
                CPU_A,
                "A reported Claimed but is not the sole owner of on_cpu"
            );
        }
        let on = t.on_cpu.load(Ordering::Acquire);
        assert!(
            on == CPU_A || on == ON_CPU_PENDING || on == CPU_C,
            "STUCK: on_cpu={:#x} not a recoverable state",
            on
        );
    });
}

/// **Reclaim recoverability**: after the reclaim-vs-rescue race, on_cpu is in
/// a well-defined state (a real CPU or PENDING) — never stuck/garbage.
#[cfg(loom)]
#[test]
fn stale_reclaim_terminal_is_recoverable() {
    loom::model(|| {
        let t = Arc::new(stale_orphan(CPU_C));
        let (ta, tr) = (t.clone(), t.clone());
        let a = thread::spawn(move || claim_or_reclaim(&ta, CPU_A));
        let r = thread::spawn(move || rescue_stale_restamp(&tr, CPU_C));
        let _ = a.join();
        let _ = r.join();
        let on = t.on_cpu.load(Ordering::Acquire);
        let ok = on == CPU_A || on == CPU_C || on == ON_CPU_PENDING;
        assert!(ok, "STUCK: on_cpu={:#x} not a recoverable state", on);
    });
}

// ---------------------------------------------------------------------------
// Non-loom smoke tests (for `cargo test` without loom-cfg).
// ---------------------------------------------------------------------------

#[cfg(not(loom))]
#[test]
fn smoke_claim_succeeds() {
    let t = ThreadModel::picked();
    let out = claim_attempt(&t, CPU_A);
    assert!(matches!(out, ClaimOutcome::Claimed(CPU_A)));
    assert_eq!(t.on_cpu.load(Ordering::Acquire), CPU_A);
}

#[cfg(not(loom))]
#[test]
fn smoke_self_pick() {
    let t = ThreadModel::running_on(CPU_A);
    let out = claim_attempt(&t, CPU_A);
    assert!(matches!(out, ClaimOutcome::SelfPick(CPU_A)));
    assert_eq!(t.on_cpu.load(Ordering::Acquire), CPU_A);
}

#[cfg(not(loom))]
#[test]
fn smoke_rescue_takeover() {
    let t = ThreadModel::picked();
    assert!(rescue_attempt(&t));
    assert_eq!(t.on_cpu.load(Ordering::Acquire), ON_CPU_MAX);
    // Subsequent helper attempt sees Lost (rescue moved on_cpu to MAX,
    // not to CPU_A, so re-read != CPU_A).
    let out = claim_attempt(&t, CPU_A);
    assert!(matches!(out, ClaimOutcome::Lost));
}
