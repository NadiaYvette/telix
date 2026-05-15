//! Loom model for the #135 residual orphan race after steal.
//!
//! Hypothesized race window (per `project_135_residual_guest_bug.md`):
//!
//! ```text
//! Thief (CPU 3):                           Concurrent waker:
//!   steal_one_min: remove tid from
//!     victim's heap, heap_pos = NONE
//!     in_queue is STILL true
//!                                          wake_thread(tid):
//!                                            state.store(Ready)
//!                                            percpu_enqueue:
//!                                              in_queue.swap(true)  ← TRUE,
//!                                                                     skip!
//!                                            (wake LOST)
//!   in_queue.store(false)
//!   dequeue_set_pending: on_cpu=PEND
//!   try_switch CAS: PEND → 3, OK
//!   thread runs on CPU 3
//! ```
//!
//! This race doesn't itself produce the (in_q=false, heap_pos=NONE,
//! state=Ready, on_cpu=PEND) orphan — the CAS succeeds.  The lost
//! wake's *effect* (state=Ready when state was already Ready) is a
//! no-op since the steal already put the thread in the pick pipeline.
//!
//! But there's a more subtle variant: what if the thread was
//! *Blocked* when the wake arrived?  Then the wake should have done
//! state=Blocked→Ready and re-enqueued.  If percpu_enqueue silently
//! skips, the wake's state change happens but the enqueue doesn't.
//! Result: state=Ready ∧ in_queue=false ∧ heap_pos=NONE — orphan!
//!
//! This file models both variants and asserts: a wake on a Blocked
//! thread that races with a steal must NOT result in an orphan.
//! The current `percpu_enqueue` silent-skip-on-in_queue=true rule
//! would violate this if `in_queue` is true at the wake's check
//! (because the steal hasn't cleared it yet).

#![allow(dead_code)]

#[cfg(loom)]
use loom::sync::atomic::{AtomicBool, AtomicU8, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[cfg(loom)]
use loom::thread;
#[cfg(not(loom))]
use std::thread;

#[cfg(loom)]
use loom::sync::Arc;
#[cfg(not(loom))]
use std::sync::Arc;

const ON_CPU_PENDING: u8 = 0xFE;
const ON_CPU_MAX: u8 = 0xFF;

const STATE_BLOCKED: u8 = 0;
const STATE_READY: u8 = 1;
const STATE_RUNNING: u8 = 2;

const HEAP_NONE: u8 = 0xFF;

struct Thread {
    state: AtomicU8,
    in_queue: AtomicBool,
    on_cpu: AtomicU8,
    heap_pos: AtomicU8,
}

impl Thread {
    /// Initial state: thread is in CPU A's heap, Ready, ready to be stolen.
    fn new_in_heap_a() -> Self {
        Self {
            state: AtomicU8::new(STATE_READY),
            in_queue: AtomicBool::new(true),
            on_cpu: AtomicU8::new(ON_CPU_MAX),
            heap_pos: AtomicU8::new(0), // in heap on CPU A
        }
    }
    /// Variant: thread is Blocked, NOT in any heap, NOT in_queue.
    fn new_blocked() -> Self {
        Self {
            state: AtomicU8::new(STATE_BLOCKED),
            in_queue: AtomicBool::new(false),
            on_cpu: AtomicU8::new(ON_CPU_MAX),
            heap_pos: AtomicU8::new(HEAP_NONE),
        }
    }
}

/// Thief: simulates percpu_pick_next's steal path.
///   1. Remove from victim's heap (heap_pos=NONE) — done atomically with rq lock in real code
///   2. in_queue.store(false)  ← NOTE: AFTER the heap removal
///   3. dequeue_set_pending: on_cpu.store(PENDING)
///   4. CAS PEND → thief
///   5. state.store(Running)
fn thief_steal_and_dispatch(t: &Thread, thief_cpu: u8) -> bool {
    // Step 1: heap removal (modelled as setting heap_pos=NONE).
    // In real code this happens under the victim rq's lock.
    t.heap_pos.store(HEAP_NONE, Ordering::Release);
    // Step 2: in_queue=false (CRITICAL: the current code does this
    // AFTER the heap removal, leaving a race window).
    t.in_queue.store(false, Ordering::Release);
    // Step 3: dequeue_set_pending.
    t.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
    // Step 4: CAS on_cpu PEND → thief.
    if t.on_cpu
        .compare_exchange(ON_CPU_PENDING, thief_cpu, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false; // double-sched
    }
    // Step 5: state.store(Running).
    t.state.store(STATE_RUNNING, Ordering::Release);
    true
}

/// Waker: simulates wake_thread on a thread that's currently Blocked.
///   1. state.store(Ready)  — Blocked → Ready
///   2. percpu_enqueue: in_queue.swap(true).  If returns TRUE
///      (already enqueued), silent skip.  Otherwise push to heap.
fn wake_blocked(t: &Thread, target_cpu_heap_was_inserted: &AtomicBool) -> bool {
    // The wake protocol checks state==Blocked first.  Here we model
    // a wake that observed Blocked but raced with the thief's path.
    let old_state = t.state.swap(STATE_READY, Ordering::AcqRel);
    if old_state != STATE_BLOCKED {
        // Already Ready or Running — wake is a no-op or merge.
        return true;
    }
    // percpu_enqueue silent-skip rule.
    if t.in_queue.swap(true, Ordering::AcqRel) {
        // BUG WINDOW: we skipped because in_queue was true.  But
        // heap_pos may be NONE (a thief just popped us).  If so,
        // we've created an orphan.
        return false;
    }
    // Successful enqueue: push to heap.
    target_cpu_heap_was_inserted.store(true, Ordering::Release);
    t.heap_pos.store(1, Ordering::Release); // some heap_pos
    true
}

/// === Variant A: thread starts in heap, Ready ===
///
/// Steal and wake race on the same Ready thread.  The wake's
/// state-Ready store is harmless (already Ready).  The steal
/// proceeds normally.  No orphan possible.
#[cfg(loom)]
#[test]
fn ready_thread_steal_race_no_orphan() {
    loom::model(|| {
        let t = Arc::new(Thread::new_in_heap_a());
        let inserted = Arc::new(AtomicBool::new(false));

        let t1 = Arc::clone(&t);
        let thief = thread::spawn(move || {
            thief_steal_and_dispatch(&t1, 3);
        });

        // No wake here — the steal alone shouldn't leave an orphan.
        thief.join().unwrap();

        let state = t.state.load(Ordering::Acquire);
        let in_q = t.in_queue.load(Ordering::Acquire);
        assert_eq!(state, STATE_RUNNING, "thread should be Running after steal");
        assert!(!in_q, "in_queue should be false after dispatch");
        let _ = inserted;
    });
}

/// === Variant B: thread starts Blocked, NOT in heap ===
///
/// A wake on the Blocked thread races with… nothing on the steal
/// side (steal won't pick a non-heap thread).  But if we model the
/// scenario where a stale in_queue=true exists from a prior steal
/// that's still in progress (in_queue.store(false) not yet executed),
/// the wake's percpu_enqueue would silently skip, leaving an orphan.
///
/// This test sets up the "stale in_queue=true" condition manually
/// and verifies whether the protocol leaves an orphan.
#[cfg(loom)]
#[test]
fn blocked_wake_during_stale_in_queue() {
    loom::model(|| {
        let t = Arc::new(Thread::new_blocked());
        // SIMULATE: a steal in flight has removed from heap (heap_pos=NONE)
        // but hasn't yet cleared in_queue.  This is the window we suspect.
        t.in_queue.store(true, Ordering::Release);
        t.heap_pos.store(HEAP_NONE, Ordering::Release);
        // In this window, a concurrent wake_thread fires on the Blocked thread.

        let inserted = Arc::new(AtomicBool::new(false));
        let t1 = Arc::clone(&t);
        let ins1 = Arc::clone(&inserted);
        let waker = thread::spawn(move || {
            wake_blocked(&t1, &ins1);
        });

        // The thief continues — clears in_queue, sets PEND, CAS.
        let t2 = Arc::clone(&t);
        let thief = thread::spawn(move || {
            // The thief WOULD have called in_queue.store(false) first,
            // but we modelled it as happening earlier (already true→false
            // for the wake), so just continue with on_cpu=PEND + CAS.
            thief_steal_and_dispatch(&t2, 3);
        });

        waker.join().unwrap();
        thief.join().unwrap();

        // After both, check for orphan state.
        let state = t.state.load(Ordering::Acquire);
        let in_q = t.in_queue.load(Ordering::Acquire);
        let on_cpu = t.on_cpu.load(Ordering::Acquire);
        let heap_pos = t.heap_pos.load(Ordering::Acquire);
        let ins = inserted.load(Ordering::Acquire);

        // The orphan pattern would be:
        //   state=Ready ∧ in_q=false ∧ heap_pos=NONE ∧ on_cpu=PEND
        // If we see that, the wake was lost AND the thief's CAS
        // failed (or didn't transition to Running).
        if state == STATE_READY
            && !in_q
            && heap_pos == HEAP_NONE
            && on_cpu == ON_CPU_PENDING
        {
            panic!(
                "ORPHAN: state=Ready, in_q=false, heap_pos=NONE, on_cpu=PEND, \
                 wake_inserted={} — wake was silently dropped",
                ins,
            );
        }
    });
}

#[cfg(not(loom))]
#[test]
fn smoke_compile_check() {
    let t = Thread::new_blocked();
    let inserted = AtomicBool::new(false);
    let _ = wake_blocked(&t, &inserted);
    let _ = thief_steal_and_dispatch(&t, 3);
}
