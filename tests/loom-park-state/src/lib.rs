//! Loom model of the four-state PARK_* CAS protocol from
//! `kernel/src/sched/scheduler.rs`.
//!
//! This is intentionally a faithful, miniature copy of the protocol — not
//! a refactor of the kernel. The kernel is `no_std` and cannot link with
//! loom; replicating just the wake/park CAS arbitration in std-land lets
//! loom exhaustively explore interleavings.
//!
//! Mapping kernel → model:
//!
//! * `pre_save_frame`              -> Parker step 1: park_state = ENQUEUED.
//! * `park_current_for_ipc`        -> Parker step 2: set stack_switch_pending,
//!                                    CAS ENQUEUED→COMMITTED. On failure
//!                                    (= early wake), undo and finish.
//! * (assembly stack switch)       -> not modeled (loom can't model asm).
//! * `clear_pending_switch`        -> Parker step 3: clear
//!                                    stack_switch_pending; CAS WOKEN→NONE.
//!                                    If win, parker enqueues (counts as a
//!                                    wake — the parked thread becomes
//!                                    runnable again).
//! * `wake_parked_thread`          -> Waker thread:
//!                                    1) CAS ENQUEUED→NONE (early wake), or
//!                                    2) CAS COMMITTED→WOKEN, then if
//!                                       stack_switch_pending==false
//!                                       CAS WOKEN→NONE (fast path enqueue).
//!                                       Else defer to clear_pending_switch.
//!
//! Invariant we assert under loom:
//!
//!     wake_count == 1
//!
//! across every interleaving — no lost wakeups, no double-enqueues.
//! "wake_count" is incremented by whichever party performs the enqueue
//! (parker's early-wake unwind, waker's early-wake CAS, waker's fast-path
//! WOKEN→NONE, or clear_pending_switch's WOKEN→NONE).
//!
//! Things deliberately NOT modeled (yet):
//!   * Multiple wakers (real kernel has at most one logical sender per slot).
//!   * Timer-driven preemption between pre_save_frame and the COMMITTED CAS
//!     — the kernel disables IRQs across that span. To model preemption,
//!     introduce a third loom thread that re-saves saved_sp; not needed
//!     for wake-correctness.
//!   * The on_cpu / current_thread / pending_switch_sp dance — those
//!     affect *which CPU* runs the woken thread, not whether it gets woken.

#![cfg(loom)]

use loom::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use loom::sync::Arc;
use loom::thread;

const PARK_NONE: u8 = 0;
const PARK_ENQUEUED: u8 = 1;
const PARK_COMMITTED: u8 = 2;
const PARK_WOKEN: u8 = 3;

struct Thread {
    park_state: AtomicU8,
    stack_switch_pending: AtomicBool,
    /// Counts how many distinct paths "claimed the wake" (i.e. would
    /// result in the thread being made Ready / re-enqueued). MUST be
    /// exactly 1 in every interleaving where a single waker fires.
    wake_count: AtomicU32,
}

impl Thread {
    fn new() -> Self {
        Self {
            park_state: AtomicU8::new(PARK_NONE),
            stack_switch_pending: AtomicBool::new(false),
            wake_count: AtomicU32::new(0),
        }
    }
}

/// Parker side: does park_current_for_ipc + (after the "stack switch")
/// clear_pending_switch. The caller (test harness) is responsible for
/// running `pre_save_frame` BEFORE spawning either parker or waker —
/// this models the kernel invariant that pre_save_frame happens before
/// the thread becomes visible in any HAMT/turnstile, so a waker can
/// never observe state < PARK_ENQUEUED.
fn parker(t: &Thread) {
    // park_current_for_ipc body: stack_switch_pending = true BEFORE the
    // ENQUEUED→COMMITTED CAS. wake's slow path observes this flag.
    t.stack_switch_pending.store(true, Ordering::Release);

    match t.park_state.compare_exchange(
        PARK_ENQUEUED,
        PARK_COMMITTED,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            // Successfully committed. Simulate "off-CPU" period — loom will
            // explore other interleavings during this nothing-step. Then
            // simulate the parking CPU re-entering an exception, which runs
            // clear_pending_switch.
            //
            // clear_pending_switch:
            //   1) clear stack_switch_pending (assembly switch is done).
            //   2) try CAS PARK_WOKEN → PARK_NONE; if win, enqueue.
            t.stack_switch_pending.store(false, Ordering::Release);
            if t
                .park_state
                .compare_exchange(
                    PARK_WOKEN,
                    PARK_NONE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                // We are responsible for the enqueue.
                t.wake_count.fetch_add(1, Ordering::AcqRel);
            }
            // else: either still COMMITTED (no wake yet — would be a lost
            // wakeup if waker never fires; here the test always fires one)
            // or NONE (waker's fast path already enqueued).
        }
        Err(_) => {
            // Early wake unwind: waker did CAS ENQUEUED→NONE. The thread
            // is still on-CPU and "continues running". The waker counted
            // the wake itself.
            t.stack_switch_pending.store(false, Ordering::Release);
        }
    }
}

/// Waker side: wake_parked_thread.
fn waker(t: &Thread) {
    // Try early wake.
    if t
        .park_state
        .compare_exchange(
            PARK_ENQUEUED,
            PARK_NONE,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
    {
        t.wake_count.fetch_add(1, Ordering::AcqRel);
        return;
    }

    // Try normal wake: COMMITTED → WOKEN.
    if t
        .park_state
        .compare_exchange(
            PARK_COMMITTED,
            PARK_WOKEN,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
    {
        // Fast path: stack switch already complete?
        if !t.stack_switch_pending.load(Ordering::Acquire) {
            if t
                .park_state
                .compare_exchange(
                    PARK_WOKEN,
                    PARK_NONE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                t.wake_count.fetch_add(1, Ordering::AcqRel);
                return;
            }
            // CAS lost — clear_pending_switch beat us; it counted.
            return;
        }
        // Slow path: defer to clear_pending_switch (no IPI in the model).
        return;
    }

    // park_state is NONE or WOKEN — already handled. (Real kernel logs
    // a WAKE-PARK-NOOP; in this model with one waker it can only happen
    // if the parker hasn't started yet, which loom forbids since we
    // always seed park_state via pre_save_frame before spawning waker.)
}

/// Run one full interleaving. Loom's `model()` invokes this many times
/// with different scheduler choices.
fn one_run() {
    let t = Arc::new(Thread::new());

    // pre_save_frame: publish ENQUEUED on the main thread BEFORE spawning
    // the waker. This enforces the kernel invariant that the parking
    // thread is visible in the wake-target structure before any wake
    // can fire. (Without this, loom would explore "waker fires before
    // parker exists" which is an invalid kernel state.)
    t.park_state.store(PARK_ENQUEUED, Ordering::Release);

    let parker_t = {
        let t = t.clone();
        thread::spawn(move || parker(&t))
    };
    let waker_t = {
        let t = t.clone();
        thread::spawn(move || waker(&t))
    };

    parker_t.join().unwrap();
    waker_t.join().unwrap();

    // After both threads complete, the protocol must have produced
    // exactly one wake.
    let wakes = t.wake_count.load(Ordering::Acquire);
    assert_eq!(
        wakes,
        1,
        "wake_count must be exactly 1, got {}; park_state={}, stack_switch_pending={}",
        wakes,
        t.park_state.load(Ordering::Acquire),
        t.stack_switch_pending.load(Ordering::Acquire),
    );

    // And park_state must be back to PARK_NONE (no leaked WOKEN/COMMITTED).
    let final_state = t.park_state.load(Ordering::Acquire);
    assert_eq!(
        final_state, PARK_NONE,
        "park_state leaked: {} (should be PARK_NONE)",
        final_state
    );
}

/// Same model as `one_run`, but every atomic op on `stack_switch_pending`
/// uses SeqCst. This is a sanity check that the harness CAN reach a
/// passing state — i.e. that the test infrastructure itself works and
/// the failures observed in `one_run` are real protocol findings rather
/// than test-rig bugs.
fn one_run_seqcst() {
    let t = Arc::new(Thread::new());

    // pre_save_frame on main thread before spawning either side; see
    // `one_run` for rationale.
    t.park_state.store(PARK_ENQUEUED, Ordering::SeqCst);

    let p = {
        let t = t.clone();
        thread::spawn(move || {
            t.stack_switch_pending.store(true, Ordering::SeqCst);
            match t.park_state.compare_exchange(
                PARK_ENQUEUED,
                PARK_COMMITTED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    t.stack_switch_pending.store(false, Ordering::SeqCst);
                    if t
                        .park_state
                        .compare_exchange(
                            PARK_WOKEN,
                            PARK_NONE,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok()
                    {
                        t.wake_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Err(_) => {
                    t.stack_switch_pending.store(false, Ordering::SeqCst);
                }
            }
        })
    };
    let w = {
        let t = t.clone();
        thread::spawn(move || {
            if t
                .park_state
                .compare_exchange(
                    PARK_ENQUEUED,
                    PARK_NONE,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                t.wake_count.fetch_add(1, Ordering::SeqCst);
                return;
            }
            if t
                .park_state
                .compare_exchange(
                    PARK_COMMITTED,
                    PARK_WOKEN,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                if !t.stack_switch_pending.load(Ordering::SeqCst) {
                    if t
                        .park_state
                        .compare_exchange(
                            PARK_WOKEN,
                            PARK_NONE,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok()
                    {
                        t.wake_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        })
    };

    p.join().unwrap();
    w.join().unwrap();

    let wakes = t.wake_count.load(Ordering::SeqCst);
    let final_state = t.park_state.load(Ordering::SeqCst);
    let final_flag = t.stack_switch_pending.load(Ordering::SeqCst);
    assert_eq!(
        wakes, 1,
        "SeqCst variant should never lose a wake; got wakes={}, park_state={}, flag={}",
        wakes, final_state, final_flag,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Production protocol fidelity test — uses Release/Acquire/AcqRel
    /// like the kernel does. Loom may find ordering issues here.
    #[test]
    fn park_wake_protocol() {
        loom::model(one_run);
    }

    /// Sanity check: with SeqCst everywhere, the protocol must be
    /// loss-free across all interleavings. If THIS fails, the model
    /// itself is buggy (not a memory-ordering finding).
    #[test]
    fn park_wake_protocol_seqcst() {
        loom::model(one_run_seqcst);
    }
}
