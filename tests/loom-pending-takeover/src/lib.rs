//! Loom model of the phantom-pending fast-rescue race.
//!
//! The scenario reproduces what `91amfsq516` showed in the field
//! (tid=11 stuck on cpu=2 with on_cpu=PENDING + in_queue=false for
//! 2+ seconds):
//!
//!   - CPU A has called `class_pick_next` and `dequeue_set_pending`,
//!     so the thread is no longer in the runqueue and `on_cpu` =
//!     PENDING.
//!   - CPU A is about to enter `try_switch` and CAS(PENDING → A).
//!     Under host descheduling, A may be paused here for seconds.
//!   - Rescuer R, running on another vCPU, observes the stuck state
//!     and CAS-flips `on_cpu` PENDING → u32::MAX so the existing
//!     orphan-rescue path can re-enqueue the thread elsewhere.
//!
//! We model the racing pair `(A: CAS PENDING→A, R: CAS PENDING→MAX)`
//! plus A's CAS_FAIL handler which is benign on `Err(MAX)` and would
//! kill on a real `Err(cpu)`.
//!
//! Invariants checked under exhaustive loom interleaving:
//!   1. **Mutex**: at most one of {A wins, R wins} per run.
//!   2. **No spurious kill**: when R wins, A's `cas_fail_was_kill`
//!      flag is never set.
//!   3. **Recoverability**: post-race, the thread is either Running
//!      (A dispatched it) or in the orphan state {state=Ready,
//!      on_cpu=MAX} which the kernel's orphan handler will pick up
//!      on the next rescue sweep.

#![allow(dead_code)]

#[cfg(loom)]
use loom::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

#[cfg(loom)]
use loom::thread;
#[cfg(not(loom))]
use std::thread;

#[cfg(loom)]
use loom::sync::Arc;
#[cfg(not(loom))]
use std::sync::Arc;

/// Encoded on_cpu sentinel values, matching scheduler.rs.
const ON_CPU_PENDING: u32 = u32::MAX - 1; // 0xFFFF_FFFE
const ON_CPU_MAX: u32 = u32::MAX;
const CPU_A: u32 = 0;
const CPU_R: u32 = 1; // rescue CPU's identifier (unused in this minimal model)

/// Thread states.
const STATE_BLOCKED: u8 = 0;
const STATE_READY: u8 = 1;
const STATE_RUNNING: u8 = 2;

/// The thread we're tracking.
struct Thread {
    /// Matches scheduler.rs Thread.on_cpu (u32 atomic).
    on_cpu: AtomicU32,
    /// Matches scheduler.rs Thread.state (encoded as u8).
    state: AtomicU8,
    /// Matches scheduler.rs Thread.killed.  Set on TRUE double-pick;
    /// MUST remain false under rescue-takeover (the fix).
    killed: AtomicBool,
    /// Set if A's try_switch CAS_FAIL handler decided to kill the
    /// thread.  Distinct from `killed` so loom can assert on the
    /// decision regardless of whether the kill actually fired.
    cas_fail_was_kill: AtomicBool,
}

impl Thread {
    /// Initial state for this test: PENDING claim has just been made
    /// (`dequeue_set_pending` ran).  state=Ready, on_cpu=PENDING.
    fn new_picked() -> Self {
        Self {
            on_cpu: AtomicU32::new(ON_CPU_PENDING),
            state: AtomicU8::new(STATE_READY),
            killed: AtomicBool::new(false),
            cas_fail_was_kill: AtomicBool::new(false),
        }
    }
}

/// CPU A: model of try_switch's CAS step.  Returns `Ok(())` if A
/// dispatched the thread; `Err(other_cpu)` otherwise.  The matching
/// CAS_FAIL handler then decides whether to kill.
fn try_switch_cas(t: &Thread) -> Result<(), u32> {
    match t.on_cpu.compare_exchange(
        ON_CPU_PENDING,
        CPU_A,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            // Successful dispatch — state goes Running.
            t.state.store(STATE_RUNNING, Ordering::Release);
            Ok(())
        }
        Err(other) => {
            // CAS_FAIL handler under the new policy: ALWAYS benign.
            // The CAS itself is the dispatch-lease mutex (at most one
            // CPU wins PENDING→cpu), so any failure is a legitimate
            // loss — either a fast-rescue takeover (Err(MAX)) or a
            // rescued+redispatched thread now Running elsewhere
            // (Err(cpu_X)).  Kill would only destroy a legitimately-
            // owned thread.
            // (No kill assignment intentionally — verifying this.)
            let _ = other;
            Err(other)
        }
    }
}

/// Rescuer R: CAS-flip PENDING → MAX so the orphan-rescue path
/// can re-enqueue the thread on a healthy CPU.  Returns true on
/// successful takeover.
fn fast_rescue_cas(t: &Thread) -> bool {
    t.on_cpu
        .compare_exchange(
            ON_CPU_PENDING,
            u32::MAX,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

/// Composite scenario: A's try_switch and R's fast-rescue race.
/// Returns (a_won, r_won) so the test can assert mutex.
fn run_race(t: Arc<Thread>) -> (bool, bool) {
    let t_a = t.clone();
    let t_r = t.clone();

    let h_a = thread::spawn(move || try_switch_cas(&t_a));
    let h_r = thread::spawn(move || fast_rescue_cas(&t_r));

    let a_res = h_a.join().expect("CPU A join");
    let r_res = h_r.join().expect("rescue join");

    (a_res.is_ok(), r_res)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(loom)]
#[test]
fn cas_pair_is_mutex() {
    loom::model(|| {
        let t = Arc::new(Thread::new_picked());
        let (a_won, r_won) = run_race(t.clone());
        // Invariant 1: at most one CAS succeeds.
        assert!(
            !(a_won && r_won),
            "MUTEX FAIL: both A's CAS and R's CAS reported success — thread would be running on A and orphaned simultaneously"
        );
        // Invariant 2: exactly one CAS succeeds (no liveness loss —
        // the PENDING claim is always resolved).
        assert!(
            a_won || r_won,
            "LIVENESS FAIL: neither A's CAS nor R's CAS won.  on_cpu={:?}",
            t.on_cpu.load(Ordering::Acquire)
        );
    });
}

#[cfg(loom)]
#[test]
fn rescue_takeover_does_not_kill() {
    loom::model(|| {
        let t = Arc::new(Thread::new_picked());
        let (a_won, _r_won) = run_race(t.clone());
        if !a_won {
            // R won the takeover.  A's CAS_FAIL handler must NOT
            // have killed the thread.
            assert!(
                !t.killed.load(Ordering::Acquire),
                "KILL FAIL: rescue took over but A's CAS_FAIL killed the thread"
            );
            assert!(
                !t.cas_fail_was_kill.load(Ordering::Acquire),
                "DECISION FAIL: A's CAS_FAIL handler decided to kill despite Err(MAX)"
            );
        }
    });
}

#[cfg(loom)]
#[test]
fn terminal_state_is_recoverable() {
    loom::model(|| {
        let t = Arc::new(Thread::new_picked());
        let (a_won, r_won) = run_race(t.clone());
        let final_on_cpu = t.on_cpu.load(Ordering::Acquire);
        let final_state = t.state.load(Ordering::Acquire);
        if a_won {
            // A dispatched: state=Running, on_cpu=CPU_A.
            assert_eq!(final_state, STATE_RUNNING, "A won but state != Running");
            assert_eq!(final_on_cpu, CPU_A, "A won but on_cpu != CPU_A");
        } else if r_won {
            // R took over: on_cpu=MAX, state stays Ready.  The
            // orphan handler will re-enqueue on the next sweep.
            assert_eq!(final_on_cpu, u32::MAX, "R won but on_cpu != MAX");
            assert_eq!(final_state, STATE_READY, "R won but state changed away from Ready");
        }
    });
}

// Non-loom smoke test so plain `cargo test` validates the model
// shape without exploring interleavings.
#[cfg(not(loom))]
#[test]
fn smoke_run_once() {
    let t = Arc::new(Thread::new_picked());
    let (a_won, r_won) = run_race(t.clone());
    assert!(!(a_won && r_won));
    assert!(a_won || r_won);
    if !a_won {
        assert!(!t.killed.load(Ordering::Acquire));
    }
}
