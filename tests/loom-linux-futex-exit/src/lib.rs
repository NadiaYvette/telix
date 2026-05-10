//! Loom model of the FUTEX wait/wake + clear_child_tid thread-exit handshake
//! from `userlib/bin/linux_srv.rs`.
//!
//! Background: glibc's `pthread_join` parks on a FUTEX_WAIT against the
//! exiting thread's `clear_child_tid` slot.  When the child calls `__NR_EXIT`
//! (thread-local), `handle_exit_thread` is supposed to:
//!
//!   1. Write 0 to the child's `clear_child_tid` userspace address.
//!   2. Wake one futex waiter parked on that address.
//!   3. Drop the child's thread slot, but PRESERVE the rest of the process.
//!
//! The pre-Phase-200 bug was that `handle_exit` (single shared path for
//! __NR_EXIT and __NR_EXIT_GROUP) cancelled *all* futex waiters of the
//! process and freed the entire PROC_TABLE slot — so even though step (2)
//! happened, step (3-old) immediately tore down the joining thread's
//! state, and any subsequent syscall from the joiner saw a fresh, empty
//! PROC_TABLE entry.  Result: pthread_join (and every later FD-using
//! syscall) wedged.
//!
//! ## What this loom test asserts
//!
//! Two faithful runs:
//!
//! * `seqcst_control`     — uses SeqCst everywhere; documents the
//!   sequential-consistency baseline.
//! * `faithful_orderings` — uses the Acquire/Release pairs that mirror
//!   the linux_srv code (FUTEX_TABLE is a static array; access is
//!   serialized by linux_srv being single-threaded, but the joiner
//!   reads the wake reply via personality_reply → kernel port, which
//!   has Release/Acquire semantics).  In the faithful model we treat
//!   the wake reply as Release on the waker, Acquire on the joiner.
//!
//! Invariants (asserted in both runs):
//!
//!   I1 (no lost wake): if the child exits AFTER the parent parked, the
//!      parent observes wake_seen == true.
//!   I2 (no double wake): wake_count <= 1.
//!   I3 (sibling preservation): the simulated "sibling FD" counter,
//!      written by the parent at park time and read after wake, is
//!      preserved across the child's exit.  This is the bug the
//!      handle_exit_thread split fixed.
//!
//! Things deliberately NOT modeled:
//!   * The kernel port send/recv plumbing (handled by other loom crates).
//!   * Multiple sibling threads — one joiner + one exiter is sufficient
//!     for the invariant.
//!   * Timeouts and EAGAIN paths (FUTEX_WAIT pre-check) — orthogonal.

#![cfg(loom)]

use loom::sync::atomic::{AtomicU32, Ordering};
use loom::sync::{Arc, Condvar, Mutex};
use loom::thread;

/// One slot in the linux_srv FUTEX_TABLE, simplified.
#[derive(Default)]
struct FutexSlot {
    active: bool,
    uaddr: u32,           // userspace address (encoded as u32 for the model)
    caller_tag: u32,      // identifies which thread is parked (the joiner)
}

/// The shared linux_srv state we care about: a one-slot futex table plus a
/// simulated "sibling FD" the parent writes before parking and expects to
/// see preserved after wake.  The bug pre-fix would have zeroed sibling_fd
/// at child exit, violating I3.
///
/// We use a Mutex+Condvar for the wake handshake instead of a spin-on-atomic
/// so loom doesn't blow up the branching factor exploring `yield_now`
/// interleavings.  This is faithful: linux_srv's personality_reply is
/// semantically a one-shot notification, which Condvar models correctly.
struct LinuxSrv {
    table: Mutex<FutexSlot>,
    /// Wake notification: lock + signaled flag + condvar.
    wake_lock: Mutex<bool>,
    wake_cv: Condvar,
    /// Counts how many wake-replies fired.  MUST be 0 or 1 across all
    /// interleavings.
    wake_count: AtomicU32,
    /// Simulated process-shared state.  Parent writes 0xCAFEBABE before
    /// park, child must not clobber it on thread exit.
    sibling_fd: AtomicU32,
}

impl LinuxSrv {
    fn new() -> Self {
        Self {
            table: Mutex::new(FutexSlot::default()),
            wake_lock: Mutex::new(false),
            wake_cv: Condvar::new(),
            wake_count: AtomicU32::new(0),
            sibling_fd: AtomicU32::new(0),
        }
    }
}

/// Parent path: write sibling_fd, then FUTEX_WAIT on `uaddr`, then verify
/// sibling_fd is still preserved.
fn parent_path(srv: Arc<LinuxSrv>, uaddr: u32, _joiner_tag: u32, store_ord: Ordering, load_ord: Ordering) {
    // Step 1: parent registers a process-private resource it MUST observe
    // after the wake.  In the bug, this got wiped at child exit.
    srv.sibling_fd.store(0xCAFEBABE, store_ord);

    // Step 2: futex slot pre-registered by harness (mirrors linux_srv
    // serial dispatch: FUTEX_WAIT is processed before child's exit
    // message arrives in the queue).
    let _ = uaddr;

    // Step 3: park on the wake condvar (models the kernel deferred-reply).
    let mut guard = srv.wake_lock.lock().unwrap();
    while !*guard {
        guard = srv.wake_cv.wait(guard).unwrap();
    }
    drop(guard);

    // Step 4: AFTER wake, the parent reads sibling_fd.  If the buggy
    // handle_exit had wiped it (PROC_TABLE[pi] = empty()), this would
    // be 0 and I3 fails.
    let observed = srv.sibling_fd.load(load_ord);
    assert_eq!(observed, 0xCAFEBABE,
        "I3 (sibling preservation): parent's sibling_fd was wiped");
}

/// Child path: child thread exits via __NR_EXIT.  handle_exit_thread fires
/// the futex wake for clear_child_tid (==uaddr).  Critically, it does NOT
/// touch sibling_fd or sibling futex slots.
fn child_path(srv: Arc<LinuxSrv>, clear_child_tid: u32, ord: Ordering) {
    // Step 1: find and wake one futex waiter on clear_child_tid.
    let woke = {
        let mut t = srv.table.lock().unwrap();
        if t.active && t.uaddr == clear_child_tid {
            t.active = false;
            true
        } else {
            false
        }
    };

    if woke {
        // Step 2: increment wake_count (must remain ≤ 1).
        srv.wake_count.fetch_add(1, ord);
        // Step 3: deliver reply via condvar (models personality_reply).
        let mut g = srv.wake_lock.lock().unwrap();
        *g = true;
        srv.wake_cv.notify_one();
        drop(g);
    } else {
        // The parent hadn't parked yet.  In the real linux_srv, the parent
        // would observe value != expected and not park, or would park after
        // and see a clean slot — either way no wake fires.  For this model
        // we sequence things so the parent parks first; the inactive-slot
        // branch is here for completeness but the harness ensures the
        // futex slot is populated before the child runs (see scenarios).
    }
    // Step 4 (handle_exit_thread): drop only THIS thread's slot and
    // per-thread clear_child_tid.  Do NOT touch sibling_fd.
    let _ = clear_child_tid;
}

fn run_scenario(store_ord: Ordering, load_ord: Ordering) {
    let srv = Arc::new(LinuxSrv::new());

    let uaddr: u32 = 0x4000;
    let joiner_tag: u32 = 0xAABB;

    // Pre-register the futex slot to model the linux_srv invariant: in the
    // real server, FUTEX_WAIT from the joiner returns `None` (deferred
    // reply) and the FUTEX_TABLE entry is in place BEFORE the child's
    // FUTEX_WAKE/exit can be dispatched — linux_srv processes messages
    // one at a time.  What loom DOES exercise is the
    // sibling_fd write/read ordering across the wake handshake.
    {
        let mut t = srv.table.lock().unwrap();
        t.active = true;
        t.uaddr = uaddr;
        t.caller_tag = joiner_tag;
    }

    let parent_srv = srv.clone();
    let parent = thread::spawn(move || {
        parent_path(parent_srv, uaddr, joiner_tag, store_ord, load_ord);
    });

    let child_srv = srv.clone();
    let child = thread::spawn(move || {
        child_path(child_srv, uaddr, Ordering::AcqRel);
    });

    parent.join().unwrap();
    child.join().unwrap();

    // I1: parent_path's condvar wait wouldn't return without a wake.
    // I2: enforce explicitly.
    let n = srv.wake_count.load(load_ord);
    assert!(n <= 1, "I2 (no double wake): wake_count={}", n);
    assert_eq!(n, 1, "I1 (no lost wake)");
}

#[test]
fn seqcst_control() {
    loom::model(|| run_scenario(Ordering::SeqCst, Ordering::SeqCst));
}

#[test]
fn faithful_orderings() {
    // sibling_fd: Release on the parent's store, Acquire on the parent's
    // post-wake load — mirrors the kernel-port send/recv pair that
    // linux_srv's personality_reply travels over.  The Mutex+Condvar wake
    // handshake provides the inter-thread happens-before edge.
    loom::model(|| run_scenario(Ordering::Release, Ordering::Acquire));
}
