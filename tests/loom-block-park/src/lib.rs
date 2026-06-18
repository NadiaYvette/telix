//! Loom model: the SINGLE-KSTACK-OWNER invariant for `block_current`'s new
//! real-park path (#208 double-dispatch fix).
//!
//! `tests/loom-park-state` already proves the four-state PARK_* handshake is
//! *wake-correct* (`wake_count == 1`, no lost wakeups / double-enqueues) and
//! explicitly notes it does NOT model "which CPU runs the woken thread —
//! those affect *which CPU*, not *whether* it gets woken." That omission is
//! exactly the #208 bug: a thread woken & re-dispatched onto a SECOND CPU
//! while the first is still executing on its kstack.
//!
//! Field-confirmed bug (2026-06-17, `DOUBLE-DISPATCH: tid=33 this_cpu=3
//! other_cpu=0`): `block_current` is a SPIN-WAIT — the blocked thread keeps
//! running a WFI loop ON ITS OWN KSTACK. When `wake_thread` makes it
//! Ready+enqueued while it's still spinning, another CPU claims and
//! dispatches it (restores its saved_sp) → two CPUs scribble one kstack →
//! the wild-RIP corruption.
//!
//! The fix (this model): a real park that RELEASES the kstack (the asm stack
//! switch) BEFORE the thread is enqueued, with the enqueue gated by
//! `stack_switch_pending` exactly as `park_current_for_ipc` /
//! `wake_parked_thread` do. Then "enqueued ⟹ off the kstack", so a
//! dispatcher can never land on an occupied kstack.
//!
//! Invariant asserted under exhaustive loom interleaving:
//!
//!     kstack_execs <= 1   (a thread's kstack has at most one live executor)
//!
//! `new_park_single_owner` must hold it; `spin_wait_double_dispatch` shows the
//! current spin-wait design violates it (so loom panics → `#[should_panic]`).

#![cfg(loom)]

use loom::sync::atomic::{fence, AtomicBool, AtomicU8, AtomicU32, Ordering};
use loom::sync::Arc;
use loom::thread;

const PARK_NONE: u8 = 0;
const PARK_ENQUEUED: u8 = 1;
const PARK_COMMITTED: u8 = 2;
const PARK_WOKEN: u8 = 3;

struct T {
    park_state: AtomicU8,
    stack_switch_pending: AtomicBool,
    /// Set true when the parked thread has been made runnable (enqueued) and
    /// is therefore claimable by a dispatcher CPU.
    runnable: AtomicBool,
    /// Single-claimer guard for the dispatcher (the on_cpu PENDING→cpu CAS).
    claimed: AtomicBool,
    /// Number of CPUs currently EXECUTING on this thread's kstack. Starts at
    /// 1 (the parker is running `block_current` on it). MUST never exceed 1.
    kstack_execs: AtomicU32,
    /// Number of times the parked thread was "resumed" — either re-enqueued
    /// for dispatch OR continued-in-place after an early wake. MUST be exactly
    /// 1 (0 = lost wakeup, 2 = double-resume). Used by the revised model.
    resume_count: AtomicU32,
}

impl T {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            // pre_save_frame already published ENQUEUED before the parker /
            // waker race begins (same seeding as loom-park-state).
            park_state: AtomicU8::new(PARK_ENQUEUED),
            stack_switch_pending: AtomicBool::new(false),
            runnable: AtomicBool::new(false),
            claimed: AtomicBool::new(false),
            kstack_execs: AtomicU32::new(1),
            resume_count: AtomicU32::new(0),
        })
    }
    #[inline]
    fn assert_single_owner(&self) {
        assert!(
            self.kstack_execs.load(Ordering::Acquire) <= 1,
            "DOUBLE-DISPATCH: two CPUs executing one kstack (kstack_execs > 1)"
        );
    }
}

/// Dispatcher on a peer CPU: claims a runnable thread (the on_cpu CAS) and
/// RUNS it — i.e. restores its saved_sp and executes on its kstack. Common
/// to both designs; the difference is purely whether the thread can be
/// `runnable` while still on its kstack.
fn dispatcher(t: &T) {
    if t.runnable.load(Ordering::Acquire)
        && t
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        // Begin executing on the kstack.
        t.kstack_execs.fetch_add(1, Ordering::AcqRel);
        t.assert_single_owner(); // fires iff the parker is still on the kstack
        t.kstack_execs.fetch_sub(1, Ordering::AcqRel);
    }
}

// ----------------------------------------------------------------------------
// NEW real-park design (the fix): block_current routes through the same
// park_state + stack_switch_pending handshake as park_current_for_ipc.
// ----------------------------------------------------------------------------

fn new_parker(t: &T) {
    // park_current_blocking: arm the stack-switch flag BEFORE committing.
    t.stack_switch_pending.store(true, Ordering::Release);
    match t.park_state.compare_exchange(
        PARK_ENQUEUED,
        PARK_COMMITTED,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            // Committed → the asm stack switch runs: we LEAVE our kstack.
            t.kstack_execs.fetch_sub(1, Ordering::AcqRel); // off the kstack (→0)
            // clear_pending_switch: the switch is physically complete.
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
                // We own the enqueue — and we are already OFF the kstack, so
                // making the thread runnable now cannot double-dispatch.
                t.runnable.store(true, Ordering::Release);
            }
            // else still COMMITTED (no wake yet) or NONE (waker enqueued).
        }
        Err(_) => {
            // Early wake: the waker did ENQUEUED→NONE before we committed.
            // We never left the kstack; we just keep running on this CPU and
            // are NOT enqueued for any peer → no double-dispatch.
            t.stack_switch_pending.store(false, Ordering::Release);
            t.kstack_execs.fetch_sub(1, Ordering::AcqRel); // return up syscall path
        }
    }
}

fn new_waker(t: &T) {
    // Early wake: thread still ENQUEUED (hasn't committed) → continues on its
    // own CPU; NOT enqueued for a peer.
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
        return;
    }
    // Normal wake: COMMITTED → WOKEN.
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
        // Only enqueue once the stack switch is physically complete — this is
        // the gate that makes "runnable ⟹ off the kstack" hold.
        if !t.stack_switch_pending.load(Ordering::Acquire)
            && t
                .park_state
                .compare_exchange(
                    PARK_WOKEN,
                    PARK_NONE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            t.runnable.store(true, Ordering::Release);
        }
        // else: defer to the parker's clear_pending_switch enqueue.
    }
}

fn new_run() {
    let t = T::new();
    let p = { let t = t.clone(); thread::spawn(move || new_parker(&t)) };
    let w = { let t = t.clone(); thread::spawn(move || new_waker(&t)) };
    let d = { let t = t.clone(); thread::spawn(move || dispatcher(&t)) };
    p.join().unwrap();
    w.join().unwrap();
    d.join().unwrap();
    // Final: kstack fully released, no claim leaked beyond a single run.
    assert!(t.kstack_execs.load(Ordering::Acquire) <= 1);
}

// ----------------------------------------------------------------------------
// OLD spin-wait design (the bug): wake makes the thread runnable WITHOUT the
// parker ever leaving its kstack. Loom finds the interleaving where the
// dispatcher runs while the parker is still executing → invariant violated.
// ----------------------------------------------------------------------------

fn spin_parker(t: &T) {
    // block_current spin-wait: keep executing on the kstack across the wake
    // window (the WFI loop), then return. It never does a stack switch.
    thread::yield_now(); // the window during which a peer can be dispatched
    t.kstack_execs.fetch_sub(1, Ordering::AcqRel); // only leaves when it returns
}

fn spin_waker(t: &T) {
    // wake_thread: unconditionally Ready + on_cpu=PENDING + percpu_enqueue,
    // with NO stack_switch_pending gate — the thread is claimable while the
    // parker still spins on its kstack.
    t.runnable.store(true, Ordering::Release);
}

fn spin_run() {
    let t = T::new();
    let p = { let t = t.clone(); thread::spawn(move || spin_parker(&t)) };
    let w = { let t = t.clone(); thread::spawn(move || spin_waker(&t)) };
    let d = { let t = t.clone(); thread::spawn(move || dispatcher(&t)) };
    p.join().unwrap();
    w.join().unwrap();
    d.join().unwrap();
}

// ----------------------------------------------------------------------------
// REVISED DESIGN — faithful to block_current's ASYNC switch-off.
//
// Key kernel reality (the architecture finding): block_current can't reuse
// park_current_for_ipc / voluntary_reschedule — those save `syscall_frame_sp`
// and resume to USER. block_current resumes into KERNEL code, and ONLY because
// the TIMER ISR's `try_switch(current_sp)` saves the ISR-frame SP. So the
// switch-off is performed by a SEPARATE actor (the timer's try_switch on the
// parker's CPU), NOT by the parker synchronously.
//
// The parker is modeled implicitly by the seed (park_state=ENQUEUED,
// stack_switch_pending=true, kstack_execs=1 = "on its kstack in WFI"). The
// three racing actors are:
//   * rv_try_switch  — timer ISR on the parker's CPU: commit + off-kstack
//                      switch + (the crucial part) clear stack_switch_pending
//                      AFTER decrementing kstack_execs, then arbitration CAS.
//   * rv_waker       — wake_thread→wake_parked_thread on a peer CPU.
//   * dispatcher     — a peer CPU that claims+runs the enqueued thread.
//
// Invariants: kstack_execs <= 1 (single owner) AND resume_count == 1
// (exactly one resume: enqueued once, or continued-in-place once).
// ----------------------------------------------------------------------------

fn rv_try_switch(t: &T) {
    // The timer ISR's try_switch tries to switch the Blocked parker off.
    if t
        .park_state
        .compare_exchange(PARK_ENQUEUED, PARK_COMMITTED, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // Won the commit. Perform the off-kstack switch, THEN clear the flag.
        // ORDER IS LOAD-BEARING: kstack_execs-- (off the kstack) must be
        // visible before stack_switch_pending=false, or a waker could enqueue
        // while we're still on the kstack. (rv_try_switch_wrongorder below
        // inverts these two lines and loom finds the resulting double-dispatch.)
        t.kstack_execs.fetch_sub(1, Ordering::AcqRel); // off the kstack: 1 -> 0
        t.stack_switch_pending.store(false, Ordering::Release); // switch complete
        // SeqCst fence: pairs with rv_waker's fence (and the kernel's
        // wake_parked_thread/clear_pending_switch pair). Loom proved that
        // WITHOUT it, on weak memory the waker can read a stale
        // stack_switch_pending=true (and defer) while this CAS reads a stale
        // COMMITTED (and fails) → NOBODY enqueues → lost wakeup. The kernel's
        // try_switch (playing clear_pending_switch's role) needs this fence.
        fence(Ordering::SeqCst);
        // try_switch plays clear_pending_switch's arbitration role: if a waker
        // already advanced COMMITTED->WOKEN, claim the enqueue here.
        if t
            .park_state
            .compare_exchange(PARK_WOKEN, PARK_NONE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            t.runnable.store(true, Ordering::Release);
            t.resume_count.fetch_add(1, Ordering::AcqRel);
        }
        // else still COMMITTED (no wake yet) — the waker's fast path enqueues.
    } else {
        // CAS failed: a waker early-woke (ENQUEUED->NONE). The thread was never
        // switched off; it exits WFI and returns in place on this CPU. The
        // early-wake waker counts the resume; we just leave the kstack.
        t.kstack_execs.fetch_sub(1, Ordering::AcqRel); // parker returns: 1 -> 0
    }
}

/// WRONG ordering: clear stack_switch_pending BEFORE the off-kstack switch
/// (models running clear_pending_switch at handler entry, before try_switch
/// actually switches). Loom must find the double-dispatch this permits.
fn rv_try_switch_wrongorder(t: &T) {
    if t
        .park_state
        .compare_exchange(PARK_ENQUEUED, PARK_COMMITTED, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        t.stack_switch_pending.store(false, Ordering::Release); // PREMATURE
        t.kstack_execs.fetch_sub(1, Ordering::AcqRel); // too late: window open
        fence(Ordering::SeqCst); // same fence as correct path
        if t
            .park_state
            .compare_exchange(PARK_WOKEN, PARK_NONE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            t.runnable.store(true, Ordering::Release);
            t.resume_count.fetch_add(1, Ordering::AcqRel);
        }
    } else {
        t.kstack_execs.fetch_sub(1, Ordering::AcqRel);
    }
}

fn rv_waker(t: &T) {
    // wake_parked_thread on a peer CPU.
    if t
        .park_state
        .compare_exchange(PARK_ENQUEUED, PARK_NONE, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // Early wake: parker continues in place; NOT enqueued for a peer.
        t.resume_count.fetch_add(1, Ordering::AcqRel);
        return;
    }
    if t
        .park_state
        .compare_exchange(PARK_COMMITTED, PARK_WOKEN, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // Mirror the kernel's cross-variable SeqCst fence (wake_parked_thread).
        fence(Ordering::SeqCst);
        if !t.stack_switch_pending.load(Ordering::Acquire)
            && t
                .park_state
                .compare_exchange(PARK_WOKEN, PARK_NONE, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            // Off the kstack (stack_switch_pending observed false) → safe enqueue.
            t.runnable.store(true, Ordering::Release);
            t.resume_count.fetch_add(1, Ordering::AcqRel);
        }
        // else defer to rv_try_switch's WOKEN->NONE arbitration.
    }
}

fn rv_run_with(switcher: fn(&T)) {
    let t = T::new();
    // The parker (block_current), BEFORE it becomes wakeable, arms
    // stack_switch_pending=true (it's still on its kstack in WFI). This MUST
    // happen-before any waker can observe it, else the waker's
    // `!stack_switch_pending` gate passes immediately and it enqueues the
    // thread while it's still on the kstack — loom proves that omitting this
    // arm reintroduces the double-dispatch. Real-kernel constraint: block_current
    // sets stack_switch_pending=true before (or with) park_state=ENQUEUED.
    t.stack_switch_pending.store(true, Ordering::Release);
    let ts = { let t = t.clone(); thread::spawn(move || switcher(&t)) };
    let wk = { let t = t.clone(); thread::spawn(move || rv_waker(&t)) };
    let dp = { let t = t.clone(); thread::spawn(move || dispatcher(&t)) };
    ts.join().unwrap();
    wk.join().unwrap();
    dp.join().unwrap();
    assert!(
        t.kstack_execs.load(Ordering::Acquire) <= 1,
        "DOUBLE-DISPATCH (revised): kstack_execs > 1"
    );
    let rc = t.resume_count.load(Ordering::Acquire);
    assert_eq!(rc, 1, "resume_count must be exactly 1 (no lost/double wake), got {}", rc);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fix: the new real-park path never lets two CPUs execute one
    /// kstack, across every interleaving of parker ‖ waker ‖ dispatcher.
    #[test]
    fn new_park_single_owner() {
        loom::model(new_run);
    }

    /// The bug: the current spin-wait DOES allow double-dispatch — loom finds
    /// an interleaving where the dispatcher runs while the parker is still on
    /// the kstack, tripping the `assert_single_owner` panic.
    #[test]
    #[should_panic(expected = "DOUBLE-DISPATCH")]
    fn spin_wait_double_dispatch() {
        loom::model(spin_run);
    }

    /// The REVISED design (block_current keeps its async timer-`try_switch`
    /// switch-off, with park_state + stack_switch_pending gating): single
    /// owner AND exactly-one-resume hold across every interleaving of
    /// try_switch ‖ waker ‖ dispatcher. This is the proof that the planned
    /// kernel change is correct.
    #[test]
    fn revised_single_owner_and_wake_correct() {
        loom::model(|| rv_run_with(rv_try_switch));
    }

    /// The ordering constraint is load-bearing: if try_switch clears
    /// stack_switch_pending BEFORE the off-kstack switch (e.g. via
    /// clear_pending_switch at handler entry, which runs before try_switch),
    /// loom finds a double-dispatch. Proves WHY the clear must happen after
    /// the kstack hand-off inside try_switch.
    #[test]
    #[should_panic(expected = "DOUBLE-DISPATCH")]
    fn revised_wrong_clear_order_double_dispatch() {
        loom::model(|| rv_run_with(rv_try_switch_wrongorder));
    }
}
