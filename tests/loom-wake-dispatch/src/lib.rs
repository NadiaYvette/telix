//! Loom model of the #135 real-block + wake_thread + try_switch race.
//!
//! IMPORTANT: this model assumes `state` is an AtomicU8.  In the
//! kernel today (kernel/src/sched/thread.rs), `state` is a plain
//! enum field, accessed from multiple CPUs without synchronization
//! — i.e. an existing data race.  Adding the SeqCst fence WITHOUT
//! also making `state` atomic empirically degrades boot reliability
//! (6× fewer userspace _start fires across a 6-boot histogram, see
//! reverted commit f918699 for the data).  The proper kernel fix is
//! to convert `state` to AtomicU8 (or equivalent) so the loom-proven
//! protocol works as written.  Until that lands, this test serves
//! as proof-of-bug, not as a recipe to lift directly.
//!
//! Kernel context: after commits 8386f90 and f8c2cb8, block_current is
//! a "real block" — the thread transitions to state=Blocked and leaves
//! the runqueue.  wake_thread transitions Blocked → Ready and
//! re-enqueues at base priority on the waker's CPU.  Empirically ~75%
//! of boots still wedge somewhere, and the canary symptom is a thread
//! (compositor_srv) stuck in (state=Ready, on_cpu=ON_CPU_PENDING) with
//! the rescue mechanism firing every 16s.
//!
//! This model checks the most fundamental wake invariant: every
//! `wake_thread` call must eventually result in a `dispatch` call for
//! that thread.  If loom finds an interleaving where wakeup was set
//! but the thread is never picked up by the run-queue consumer, we've
//! found a lost-wake race in the protocol.
//!
//! Specifically modeled state machine:
//!
//!   ┌──────────┐  block_current   ┌──────────┐
//!   │ Running  │ ───────────────► │ Blocked  │
//!   └──────────┘ ◄─────────────┐  └─────┬────┘
//!        ▲                     │        │ wake_thread
//!        │ dispatch            │        ▼
//!        │ (try_switch picks)  │  ┌──────────┐
//!        │                     └──┤  Ready   │
//!        └─────────────────────── └──────────┘
//!
//! and the wakeup flag (race-safe re-check inside block_current).
//!
//! Explicit modelling choices:
//!
//!   * `wakeup` is the per-thread bool that block_current re-reads
//!     after committing to Blocked.  The waker stores it Release;
//!     the blocker loads Acquire.
//!   * state transitions use AtomicU8 with the same orderings as the
//!     kernel.
//!   * The "runqueue" is a single AtomicBool (`in_queue`) — adequate
//!     because we model a single thread and a single per-CPU queue.
//!   * Loom permutes the scheduling of the two threads (blocker +
//!     waker).  The dispatch-side try_switch runs IFF the queue is
//!     non-empty AND in_queue=true.

#![cfg(loom)]

use loom::sync::atomic::{fence, AtomicBool, AtomicU8, Ordering};
use loom::sync::Arc;
use loom::thread;

/// Thread state.
const RUNNING: u8 = 0;
const BLOCKED: u8 = 1;
const READY: u8 = 2;

struct ThreadCb {
    state: AtomicU8,
    wakeup: AtomicBool,
    in_queue: AtomicBool,
}

impl ThreadCb {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(RUNNING),
            wakeup: AtomicBool::new(false),
            in_queue: AtomicBool::new(false),
        }
    }
}

/// block_current: the running thread commits to Blocked, then race-safe
/// re-checks the wakeup flag.  If wakeup arrived in the window, undo
/// the Blocked transition and return.  Otherwise yield (in the kernel
/// this is WFI; in the model we just stop here — the dispatch side
/// will pick us back up via the in_queue path after wake_thread).
fn block_current(t: &ThreadCb) {
    // 1. Commit to Blocked with SeqCst to order against wake_thread's
    //    SeqCst load of state below.  Plain Release allows the
    //    subsequent wakeup.load to be reordered with this store on
    //    x86, missing a concurrent waker.
    t.state.store(BLOCKED, Ordering::SeqCst);
    // 2. Full memory fence — without this, the store-then-load (on
    //    different atomic locations) can be reordered by the CPU's
    //    store buffer, missing a concurrent waker.  Mirrors Linux's
    //    smp_mb__after_set_current_state() pattern.
    fence(Ordering::SeqCst);
    if t.wakeup.load(Ordering::SeqCst) {
        t.state.store(RUNNING, Ordering::SeqCst);
        return;
    }
    // 3. In the kernel we WFI here until try_switch picks us up.  In
    //    the model the wake side has already (or will) set state=Ready
    //    + enqueue; dispatch will transition Ready→Running.  We return
    //    here; the test asserts that AFTER block_current returns, the
    //    invariant holds.
}

/// wake_thread: set wakeup=true, then (race-safely) transition
/// Blocked→Ready and enqueue.  If state is not Blocked at the moment
/// we check (race with block_current's re-check), the blocker will
/// see wakeup=true and undo — either way the thread runs.
fn wake_thread(t: &ThreadCb) {
    // 1. Set wakeup with SeqCst — pairs with block_current's SeqCst
    //    load of wakeup.  Plain Release would allow our state.load
    //    below to be reordered before this store on x86, leaving us
    //    blind to the blocker's recent state=Blocked.
    t.wakeup.store(true, Ordering::SeqCst);
    // 2. Full memory fence — same reasoning as block_current's fence:
    //    without it, store-then-load reorders across the store buffer.
    //    Mirrors Linux's smp_mb__after_atomic in try_to_wake_up.
    fence(Ordering::SeqCst);
    let s = t.state.load(Ordering::SeqCst);
    if s == BLOCKED {
        // Transition Blocked→Ready.  In the kernel this is a plain
        // store (no CAS); the race is benign because block_current's
        // re-check sees wakeup=true and undoes the Blocked.
        t.state.store(READY, Ordering::SeqCst);
        // Enqueue.
        let was = t.in_queue.swap(true, Ordering::SeqCst);
        assert!(!was, "double-enqueue: wake_thread saw in_queue=true");
    }
}

/// try_switch (dispatch side): if the thread is in the runqueue,
/// dequeue and transition Ready→Running.
fn try_switch(t: &ThreadCb) -> bool {
    if !t.in_queue.swap(false, Ordering::SeqCst) {
        return false;
    }
    // We popped the thread from the queue; transition Ready→Running.
    let s = t.state.swap(RUNNING, Ordering::SeqCst);
    assert!(
        s == READY || s == RUNNING,
        "try_switch picked a thread with state={} (expected READY or RUNNING)",
        s
    );
    true
}

#[test]
fn no_lost_wake_after_block() {
    loom::model(|| {
        let t = Arc::new(ThreadCb::new());

        // Blocker thread: simulates a Linux server calling block_current
        // (e.g., port_recv).  After block_current returns, the
        // invariant we expect is: if any wake fired during our block,
        // the blocker is now Running OR a subsequent try_switch will
        // make it Running.
        let blocker = {
            let t = t.clone();
            thread::spawn(move || {
                block_current(&t);
            })
        };

        // Waker thread: simulates another CPU calling wake_thread.
        let waker = {
            let t = t.clone();
            thread::spawn(move || {
                wake_thread(&t);
            })
        };

        blocker.join().unwrap();
        waker.join().unwrap();

        // Drain any leftover queue entry via dispatch.
        let _ = try_switch(&t);

        // Post-condition: wakeup was set (waker ran), and the thread is
        // not stuck in Blocked.
        assert!(
            t.wakeup.load(Ordering::SeqCst),
            "wakeup flag should be set after waker ran"
        );
        let final_state = t.state.load(Ordering::SeqCst);
        let final_inq = t.in_queue.load(Ordering::SeqCst);
        let final_wakeup = t.wakeup.load(Ordering::SeqCst);
        assert!(
            final_state == RUNNING || final_state == READY,
            "thread stuck in state={} after wake + dispatch — lost wake? \
             (wakeup={} in_queue={})",
            final_state, final_wakeup, final_inq,
        );
        // If state is RUNNING, the thread is correctly back on CPU.
        // If state is READY, the next try_switch will pick it (just
        // verified the queue protocol with the drain above).
        assert!(
            !t.in_queue.load(Ordering::SeqCst),
            "in_queue=true after drain — phantom queue entry"
        );
    });
}

#[test]
fn no_lost_wake_with_dispatch_interleaved() {
    // As above, but with the dispatcher firing concurrently with the
    // blocker + waker.  Loom should permute every interleaving;
    // we assert the same post-condition.
    loom::model(|| {
        let t = Arc::new(ThreadCb::new());

        let blocker = {
            let t = t.clone();
            thread::spawn(move || block_current(&t))
        };
        let waker = {
            let t = t.clone();
            thread::spawn(move || wake_thread(&t))
        };
        let dispatcher = {
            let t = t.clone();
            thread::spawn(move || {
                // Dispatcher runs try_switch up to twice — once for the
                // initial enqueue from wake_thread, once defensively in
                // case a spurious enqueue happened.
                let _ = try_switch(&t);
                let _ = try_switch(&t);
            })
        };

        blocker.join().unwrap();
        waker.join().unwrap();
        dispatcher.join().unwrap();

        // Final drain (no race — all the other threads have joined).
        let _ = try_switch(&t);

        let final_state = t.state.load(Ordering::SeqCst);
        let wakeup_set = t.wakeup.load(Ordering::SeqCst);
        let in_q = t.in_queue.load(Ordering::SeqCst);

        assert!(wakeup_set, "wakeup flag should be set");
        assert!(
            final_state == RUNNING || final_state == READY,
            "thread stuck after wake/dispatch: state={} in_queue={}",
            final_state, in_q
        );
        assert!(!in_q, "queue not drained: state={} in_queue={}", final_state, in_q);
    });
}
