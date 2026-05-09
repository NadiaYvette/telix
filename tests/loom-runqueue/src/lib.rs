//! Loom model of the per-CPU run-queue `in_queue` swap protocol from
//! `kernel/src/sched/scheduler.rs`.
//!
//! Three concurrent paths can race on a single thread's membership in
//! one CPU's run queue:
//!
//!   * wake_thread fast path  -> percpu_enqueue:
//!         if in_queue.swap(true, AcqRel) { return; }
//!         heap.push(tid)
//!
//!   * percpu_pick_next        -> dispatch:
//!         tid = heap.pop()                      // under rq lock
//!         in_queue.store(false, Release)        // OUTSIDE lock
//!
//!   * rescue self-heal        -> phantom-detect + re-enqueue:
//!         if in_queue && !heap.contains(tid) {
//!             in_queue.store(false, Release);
//!             percpu_enqueue(tid);              // -> swap(true) + push
//!         }
//!
//! Invariant: at every quiescent point,
//!     in_queue == (heap_member > 0)
//! and heap_member <= 1 (no double-enq).
//!
//! Mapping kernel → model:
//!
//!   `in_queue: AtomicBool`        ->  loom AtomicBool with same orderings.
//!   per-CPU heap                  ->  loom Mutex<u32> counter (membership
//!                                     count); Mutex models the per-CPU
//!                                     run-queue spinlock.
//!
//! Things deliberately NOT modeled:
//!   * EEVDF deadlines, priority bitmaps, work stealing, IPIs.
//!   * `dequeue_set_pending` / `on_cpu` transitions.  In the kernel,
//!     the dispatch path sets `on_cpu = ON_CPU_PENDING` BETWEEN
//!     heap.pop and in_queue.store(false), and rescue rejects
//!     candidates with on_cpu==ON_CPU_PENDING.  Without that gate, the
//!     rescue races with dispatch — and that race is exactly what loom
//!     reports here.  See test failure trace.
//!   * Multiple CPUs / cross-CPU rescue. The race window is intra-CPU
//!     at the AtomicBool level.

#![cfg(loom)]

use loom::sync::atomic::{AtomicBool, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

struct Cpu {
    in_queue: AtomicBool,
    /// Run-queue membership count. Mutex models the per-CPU SpinLock that
    /// the kernel takes around heap mutations.
    heap: Mutex<u32>,
}

impl Cpu {
    fn new() -> Self {
        Self {
            in_queue: AtomicBool::new(false),
            heap: Mutex::new(0),
        }
    }
}

/// `percpu_enqueue` from the kernel: AcqRel swap, then push under the rq
/// lock if we won the swap.
fn percpu_enqueue(c: &Cpu, swap_ord: Ordering) {
    if c.in_queue.swap(true, swap_ord) {
        return;
    }
    let mut h = c.heap.lock().unwrap();
    *h += 1;
}

/// `percpu_pick_next` dispatch path: pop one (under the rq lock), then
/// store(false, Release).
///
/// CRITICAL: the kernel orders heap.pop BEFORE in_queue.store(false), but
/// also runs `dequeue_set_pending` (sets on_cpu = ON_CPU_PENDING) between
/// the pop and the store.  We omit `dequeue_set_pending` from this model;
/// loom finds a race that the kernel's rescue path mitigates via the
/// on_cpu==ON_CPU_PENDING check.  See module-level comment.
fn percpu_pick_next(c: &Cpu, store_ord: Ordering) -> bool {
    let mut h = c.heap.lock().unwrap();
    if *h == 0 {
        return false;
    }
    *h -= 1;
    drop(h);
    c.in_queue.store(false, store_ord);
    true
}

/// rescue_orphaned_threads phantom-detect path.  Models scheduler.rs
/// ~5942-5990:
///
///   if in_queue && !rq_contains_tid(&rq, tid) {
///       in_queue.store(false, Release);
///       percpu_enqueue(tid);   // -> swap(true), push under lock
///   }
fn rescue_phantom(c: &Cpu, load_ord: Ordering, store_ord: Ordering, swap_ord: Ordering) {
    let inq = c.in_queue.load(load_ord);
    if !inq {
        return;
    }
    let phantom = {
        let h = c.heap.lock().unwrap();
        let p = *h == 0;
        let inq_now = c.in_queue.load(load_ord);
        drop(h);
        p && inq_now
    };
    if !phantom {
        return;
    }
    c.in_queue.store(false, store_ord);
    if c.in_queue.swap(true, swap_ord) {
        return;
    }
    let mut h = c.heap.lock().unwrap();
    *h += 1;
}

fn one_run_with(load_ord: Ordering, store_ord: Ordering, swap_ord: Ordering) {
    let c = Arc::new(Cpu::new());

    // Seed: the thread is enqueued.  This is the realistic precondition —
    // rescue only fires for in_queue=true candidates; dispatch only runs
    // for non-empty queues; wake fires when wake_thread is called.
    {
        let mut h = c.heap.lock().unwrap();
        *h = 1;
    }
    c.in_queue.store(true, store_ord);

    // Three concurrent paths.  We run W on the main thread (one fewer
    // loom thread = far fewer interleavings) and D, R in spawned threads.
    let cd = c.clone();
    let cr = c.clone();
    let d = thread::spawn(move || {
        percpu_pick_next(&cd, store_ord);
    });
    let r = thread::spawn(move || rescue_phantom(&cr, load_ord, store_ord, swap_ord));
    percpu_enqueue(&c, swap_ord); // W on main thread

    d.join().unwrap();
    r.join().unwrap();

    // Quiescent invariant: in_queue iff heap_member > 0, AND heap_member <= 1.
    let h = *c.heap.lock().unwrap();
    let inq = c.in_queue.load(Ordering::Acquire);
    assert!(h <= 1, "double-enqueue: heap={}", h);
    assert_eq!(
        inq,
        h > 0,
        "in_queue/heap inconsistent: in_queue={} heap={}",
        inq, h,
    );
}

fn one_run() {
    one_run_with(Ordering::Acquire, Ordering::Release, Ordering::AcqRel);
}

fn one_run_seqcst() {
    one_run_with(Ordering::SeqCst, Ordering::SeqCst, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SeqCst control: with global ordering, the in_queue ↔ heap relation
    /// is decided by program order alone.  This test FAILS with the
    /// current dispatch-vs-rescue interleaving — see the module-level
    /// comment.  Smallest failing interleaving (logged by an
    /// instrumented run):
    ///
    ///   W: swap -> prev=true (no-op)
    ///   D: lock heap, h=1, pop to 0
    ///   R: load in_queue=true; phantom-check h=0, inq_now=true (D hasn't
    ///      stored false yet) -> phantom!
    ///   R: store(false); swap(true) -> prev=false -> push h=0->1
    ///   D: store(false)   <-- TARDY; clobbers R's flag
    ///
    /// Final state: in_queue=false, heap=1.  Lost wake.
    #[test]
    fn runqueue_protocol_seqcst() {
        loom::model(one_run_seqcst);
    }

    /// Faithful kernel orderings.  Same race surface as the SeqCst variant
    /// since the lock-protected pop already serializes; the orderings on
    /// in_queue alone don't add new interleavings.
    #[test]
    fn runqueue_protocol() {
        loom::model(one_run);
    }
}
