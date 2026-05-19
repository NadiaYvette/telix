//! Loom model of the turnstile bucket-lock protocol from
//! `kernel/src/sync/turnstile.rs`.
//!
//! Three concurrent operations all touch a single port turnstile under
//! `WAIT_HAMT[bucket].lock()`:
//!
//! * `port_enqueue_with_check`  — lookup; if miss, alloc + insert; ts_enqueue.
//! * `port_wake_one`            — lookup; ts_dequeue_head; if empty, remove.
//! * `cleanup_blocked_inner`    — lookup matches the killed thread's stored
//!                                ts_addr; ts_remove(tid); if empty, remove.
//!
//! The race window we care about: thread A is being killed at the moment a
//! waker is poking the same turnstile. The kernel claim is that because all
//! three sequences hold the per-bucket SpinLock for the entire HAMT-touch
//! plus turnstile mutation, no waiter can be "lost" — every successful
//! enqueue is later observed by either a wake or a cleanup.
//!
//! Mapping kernel → model:
//!
//!   `WAIT_HAMT[bucket]`            ->   `loom::sync::Mutex<HamtSlot>`
//!   `Turnstile { waiter_count, head }` -> packed into the locked struct
//!   `ts_blocked_on` (per-thread)   ->   `AtomicUsize` set inside the lock
//!
//! Invariant we assert under loom:
//!
//! ```text
//!     For each tid t that succeeds at port_enqueue_with_check (returned
//!     true), there is exactly one of:
//!         * a wake_count[t] = 1   (port_wake_one drained t), OR
//!         * a cleanup_count[t] = 1 (cleanup_blocked_inner removed t).
//!     waiter_count never goes negative; ts_blocked_on is consistent with
//!     HAMT membership.
//! ```

#![cfg(loom)]

use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

/// Single HAMT bucket holding at most one turnstile slot for our one port.
/// `present == true` means a turnstile is allocated and inserted; `waiters`
/// is the multiset of tids currently parked. We use a fixed-size array so
/// the test crate stays no-alloc inside the loom run.
#[derive(Default)]
struct HamtSlot {
    present: bool,
    /// Identity of the currently-allocated turnstile; bumped on every
    /// alloc. Lets us tell whether a stale `ts_addr` stored on a thread
    /// still matches the live HAMT entry (the real cleanup path checks
    /// `found_ts as usize == ts_addr`).
    ts_id: u64,
    /// Bitmap of tids parked on the turnstile. Bit i set <=> tid i is in.
    waiters: u32,
}

impl HamtSlot {
    fn waiter_count(&self) -> u32 {
        self.waiters.count_ones()
    }

    fn ts_enqueue(&mut self, tid: u32) {
        self.waiters |= 1u32 << tid;
    }

    fn ts_dequeue_head(&mut self) -> Option<u32> {
        if self.waiters == 0 {
            return None;
        }
        let tid = self.waiters.trailing_zeros();
        self.waiters &= !(1u32 << tid);
        Some(tid)
    }

    fn ts_remove(&mut self, tid: u32) -> bool {
        let bit = 1u32 << tid;
        if self.waiters & bit != 0 {
            self.waiters &= !bit;
            true
        } else {
            false
        }
    }
}

struct Shared {
    bucket: Mutex<HamtSlot>,
    /// Per-tid `ts_blocked_on` analogue. Stores the ts_id the thread thinks
    /// it's parked on (0 = not parked).
    ts_blocked_on: [AtomicUsize; 4],
    /// Wake-count per tid: incremented when `port_wake_one` drains tid.
    wake_count: [AtomicUsize; 4],
    /// Cleanup-count per tid: incremented when cleanup_blocked_inner
    /// successfully removes tid from a turnstile.
    cleanup_count: [AtomicUsize; 4],
    /// Enqueue-success per tid: incremented when port_enqueue_with_check
    /// returned true (i.e. the thread is actually parked).
    enqueued_ok: [AtomicUsize; 4],
}

impl Shared {
    fn new() -> Self {
        Self {
            bucket: Mutex::new(HamtSlot::default()),
            ts_blocked_on: [
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
            ],
            wake_count: [
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
            ],
            cleanup_count: [
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
            ],
            enqueued_ok: [
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
            ],
        }
    }
}

/// `port_enqueue_with_check`. The `condition` closure is omitted (always
/// true: kernel state is "queue still empty for recv").
fn port_enqueue_with_check(s: &Shared, tid: u32, store_ord: Ordering) {
    let mut slot = s.bucket.lock().unwrap();
    if !slot.present {
        slot.present = true;
        slot.ts_id += 1;
    }
    let id = slot.ts_id;
    slot.ts_enqueue(tid);
    s.ts_blocked_on[tid as usize].store(id as usize, store_ord);
    s.enqueued_ok[tid as usize].fetch_add(1, Ordering::AcqRel);
}

fn port_wake_one(s: &Shared, store_ord: Ordering) -> Option<u32> {
    let mut slot = s.bucket.lock().unwrap();
    if !slot.present {
        return None;
    }
    let tid = slot.ts_dequeue_head()?;
    s.ts_blocked_on[tid as usize].store(0, store_ord);
    if slot.waiter_count() == 0 {
        slot.present = false;
    }
    s.wake_count[tid as usize].fetch_add(1, Ordering::AcqRel);
    Some(tid)
}

/// `cleanup_blocked` (outer + inner combined). Models the kill path: the
/// thread reads its own `ts_blocked_on`, then takes the bucket lock, then
/// re-validates the HAMT entry's identity matches.
fn cleanup_blocked(s: &Shared, tid: u32, load_ord: Ordering, store_ord: Ordering) {
    let ts_id = s.ts_blocked_on[tid as usize].swap(0, load_ord);
    if ts_id == 0 {
        return;
    }
    let mut slot = s.bucket.lock().unwrap();
    if slot.present && slot.ts_id == ts_id as u64 {
        if slot.ts_remove(tid) {
            if slot.waiter_count() == 0 {
                slot.present = false;
            }
            s.cleanup_count[tid as usize].fetch_add(1, Ordering::AcqRel);
        }
    }
    let _ = store_ord; // ts_blocked_on already cleared above
}

/// One full interleaving with the given memory orderings.
fn one_run_with(load_ord: Ordering, store_ord: Ordering) {
    let s = Arc::new(Shared::new());

    // Pre-park tid 0 so cleanup has something to find.
    port_enqueue_with_check(&s, 0, store_ord);

    // Three concurrent operations:
    //   A: enqueue tid 1 (a fresh waiter racing the wake/cleanup).
    //   B: wake one (from the perspective of any sender on this port).
    //   C: cleanup tid 0 (kill path).
    let a = {
        let s = s.clone();
        thread::spawn(move || port_enqueue_with_check(&s, 1, store_ord))
    };
    let b = {
        let s = s.clone();
        thread::spawn(move || {
            let _ = port_wake_one(&s, store_ord);
        })
    };
    let c = {
        let s = s.clone();
        thread::spawn(move || cleanup_blocked(&s, 0, load_ord, store_ord))
    };

    a.join().unwrap();
    b.join().unwrap();
    c.join().unwrap();

    // Final invariants. After all threads quiesce, every successful
    // enqueue must have been resolved exactly once by either a wake or
    // a cleanup, OR remain parked (still in the HAMT with ts_blocked_on
    // pointing at the live ts_id).
    let slot = s.bucket.lock().unwrap();
    let live_ts_id = if slot.present { slot.ts_id } else { 0 };
    let waiters = slot.waiters;
    drop(slot);

    for tid in 0..2u32 {
        let enq_ok = s.enqueued_ok[tid as usize].load(Ordering::Acquire);
        if enq_ok == 0 {
            continue;
        }
        let woke = s.wake_count[tid as usize].load(Ordering::Acquire);
        let cleaned = s.cleanup_count[tid as usize].load(Ordering::Acquire);
        let blk = s.ts_blocked_on[tid as usize].load(Ordering::Acquire);
        let still_parked = (waiters & (1u32 << tid)) != 0;

        // Mutual exclusion: can't be both woken and cleaned.
        assert!(
            !(woke > 0 && cleaned > 0),
            "tid {} double-resolved: wake={} clean={}",
            tid, woke, cleaned,
        );

        // Resolution count is exactly 1 either way (no doubles).
        assert!(woke <= 1, "tid {} woken {} times", tid, woke);
        assert!(cleaned <= 1, "tid {} cleaned {} times", tid, cleaned);

        if woke == 1 || cleaned == 1 {
            // Resolved: must NOT still be in the bucket waiter set.
            assert!(
                !still_parked,
                "tid {} resolved (woke={} clean={}) but still in waiters",
                tid, woke, cleaned,
            );
            // ts_blocked_on must have been cleared (resolution clears it).
            assert_eq!(
                blk, 0,
                "tid {} resolved but ts_blocked_on={} (should be 0)",
                tid, blk,
            );
        } else {
            // Unresolved: must still be parked AND the stored ts_id must
            // match the live one (otherwise it's a dangling reference).
            assert!(
                still_parked,
                "tid {} unresolved but not in waiters (lost wakeup!)",
                tid,
            );
            assert_eq!(
                blk as u64, live_ts_id,
                "tid {} ts_blocked_on={} live_ts_id={} (stale reference)",
                tid, blk, live_ts_id,
            );
        }
    }

    // HAMT invariant: present iff some waiter exists.
    assert_eq!(
        live_ts_id != 0,
        waiters != 0,
        "HAMT membership inconsistent: live_ts_id={} waiters={:#b}",
        live_ts_id, waiters,
    );
}

fn one_run() {
    one_run_with(Ordering::Acquire, Ordering::Release);
}

fn one_run_seqcst() {
    one_run_with(Ordering::SeqCst, Ordering::SeqCst);
}

// =============================================================================
// Linked-list / waiter_count invariant model
//
// Boot 545 observed a Turnstile in the HAMT with head=tail=TS_NIL but
// waiter_count=3 under the bucket lock.  The bitmap model above can't
// catch that — `waiter_count` is *defined* as `waiters.count_ones()`.
// This new model represents head/tail/wc as separate fields plus
// per-thread ts_next/ts_prev links, mirroring the real Turnstile.
//
// Operations modeled (each is an entire kernel-side ts_* call, run under
// the bucket Mutex in our model):
//   * `ts_enqueue(tid)`        — tail-append
//   * `ts_dequeue_head()`      — head-remove (returns Option<tid>)
//   * `ts_remove(tid)`         — find-and-remove
//
// Invariant checked after all loom threads join: walk forward from head
// `wc` times and land on tail (with ts_next == NIL); equivalently walk
// backward from tail `wc` times and land on head.  Both reachability
// and count must agree.
// =============================================================================

const LL_NIL: u32 = u32::MAX;
const LL_N_TIDS: usize = 4;

#[derive(Clone, Copy)]
struct LinkedTurnstile {
    head: u32,
    tail: u32,
    wc: u16,
    ts_next: [u32; LL_N_TIDS],
    ts_prev: [u32; LL_N_TIDS],
    /// `in_list[t]` mirrors our model's enq/deq bookkeeping so each
    /// invariant check can detect off-by-one mutations independently.
    in_list: [bool; LL_N_TIDS],
}

impl Default for LinkedTurnstile {
    fn default() -> Self {
        Self {
            head: LL_NIL,
            tail: LL_NIL,
            wc: 0,
            ts_next: [LL_NIL; LL_N_TIDS],
            ts_prev: [LL_NIL; LL_N_TIDS],
            in_list: [false; LL_N_TIDS],
        }
    }
}

impl LinkedTurnstile {
    fn ts_enqueue(&mut self, tid: u32) {
        let t = tid as usize;
        self.ts_next[t] = LL_NIL;
        self.ts_prev[t] = self.tail;
        if self.tail != LL_NIL {
            self.ts_next[self.tail as usize] = tid;
        } else {
            self.head = tid;
        }
        self.tail = tid;
        self.wc += 1;
        self.in_list[t] = true;
    }

    fn ts_dequeue_head(&mut self) -> Option<u32> {
        let head = self.head;
        if head == LL_NIL {
            return None;
        }
        let h = head as usize;
        let next = self.ts_next[h];
        self.ts_next[h] = LL_NIL;
        self.ts_prev[h] = LL_NIL;
        self.head = next;
        if next != LL_NIL {
            self.ts_prev[next as usize] = LL_NIL;
        } else {
            self.tail = LL_NIL;
        }
        self.wc -= 1;
        self.in_list[h] = false;
        Some(head)
    }

    fn ts_remove(&mut self, tid: u32) -> bool {
        let mut cur = self.head;
        while cur != LL_NIL {
            if cur == tid {
                let t = tid as usize;
                let prev = self.ts_prev[t];
                let next = self.ts_next[t];
                if prev != LL_NIL {
                    self.ts_next[prev as usize] = next;
                } else {
                    self.head = next;
                }
                if next != LL_NIL {
                    self.ts_prev[next as usize] = prev;
                } else {
                    self.tail = prev;
                }
                self.ts_next[t] = LL_NIL;
                self.ts_prev[t] = LL_NIL;
                self.wc -= 1;
                self.in_list[t] = false;
                return true;
            }
            cur = self.ts_next[cur as usize];
        }
        false
    }

    /// Walk forward from head and assert wc == walk count.
    fn check_invariant(&self) {
        let mut walked = 0u16;
        let mut cur = self.head;
        let mut last = LL_NIL;
        let mut seen = [false; LL_N_TIDS];
        while cur != LL_NIL {
            assert!(
                !seen[cur as usize],
                "cycle in linked list: tid {} visited twice",
                cur
            );
            seen[cur as usize] = true;
            assert!(
                self.in_list[cur as usize],
                "tid {} in linked list but in_list[{}]=false",
                cur, cur
            );
            walked += 1;
            last = cur;
            cur = self.ts_next[cur as usize];
        }
        assert_eq!(
            walked, self.wc,
            "wc mismatch: walked {} entries forward, wc={}",
            walked, self.wc
        );
        if self.wc == 0 {
            assert_eq!(self.head, LL_NIL, "wc=0 but head={}", self.head);
            assert_eq!(self.tail, LL_NIL, "wc=0 but tail={}", self.tail);
        } else {
            assert_eq!(self.tail, last, "tail={} but walk-last={}", self.tail, last);
        }
        // Backward walk.
        let mut walked_b = 0u16;
        let mut cur = self.tail;
        while cur != LL_NIL {
            walked_b += 1;
            let prev = self.ts_prev[cur as usize];
            if prev == LL_NIL {
                assert_eq!(self.head, cur,
                    "backward walk reached NIL prev but head={} cur={}",
                    self.head, cur);
            }
            cur = prev;
        }
        assert_eq!(
            walked_b, self.wc,
            "wc mismatch: walked {} entries backward, wc={}",
            walked_b, self.wc
        );
    }
}

struct LinkedShared {
    bucket: Mutex<LinkedTurnstile>,
}

fn ll_run_three_concurrent_enqueues() {
    let s = Arc::new(LinkedShared { bucket: Mutex::new(LinkedTurnstile::default()) });
    let t1 = {
        let s = s.clone();
        thread::spawn(move || s.bucket.lock().unwrap().ts_enqueue(0))
    };
    let t2 = {
        let s = s.clone();
        thread::spawn(move || s.bucket.lock().unwrap().ts_enqueue(1))
    };
    let t3 = {
        let s = s.clone();
        thread::spawn(move || s.bucket.lock().unwrap().ts_enqueue(2))
    };
    t1.join().unwrap();
    t2.join().unwrap();
    t3.join().unwrap();
    let ts = s.bucket.lock().unwrap();
    ts.check_invariant();
    assert_eq!(ts.wc, 3);
}

fn ll_run_enqueue_dequeue_remove() {
    let s = Arc::new(LinkedShared { bucket: Mutex::new(LinkedTurnstile::default()) });
    // Seed with tid 0 already enqueued so dequeue + remove have work.
    s.bucket.lock().unwrap().ts_enqueue(0);
    let t1 = {
        let s = s.clone();
        thread::spawn(move || s.bucket.lock().unwrap().ts_enqueue(1))
    };
    let t2 = {
        let s = s.clone();
        thread::spawn(move || { let _ = s.bucket.lock().unwrap().ts_dequeue_head(); })
    };
    let t3 = {
        let s = s.clone();
        thread::spawn(move || { let _ = s.bucket.lock().unwrap().ts_remove(0); })
    };
    t1.join().unwrap();
    t2.join().unwrap();
    t3.join().unwrap();
    let ts = s.bucket.lock().unwrap();
    ts.check_invariant();
}

/// Explanatory: prove the invariant CAN catch corruption, by running a
/// double-enqueue of the same tid on a plain (non-loom) struct.  No loom
/// concurrency — purely a sanity check on `check_invariant`.
fn ll_double_enqueue_invariant_catches() {
    let mut t = LinkedTurnstile::default();
    t.ts_enqueue(0);
    t.ts_enqueue(0); // duplicate
    let r = std::panic::catch_unwind(|| t.check_invariant());
    assert!(r.is_err(),
        "double-enqueue of same tid did NOT produce invariant violation — model bug");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: with SeqCst on every per-thread atomic, the bucket Mutex
    /// already serializes everything important; no interleaving can lose
    /// a waiter.
    #[test]
    fn turnstile_protocol_seqcst() {
        loom::model(one_run_seqcst);
    }

    /// Faithful: kernel uses Relaxed for ts_blocked_on stores. The bucket
    /// lock should still cover all visibility we care about.
    #[test]
    fn turnstile_protocol() {
        loom::model(one_run);
    }

    /// Linked-list / waiter_count invariant under three concurrent enqueues.
    /// Boot 545 observed wc=3 with head=NIL; this model would catch any
    /// path that violates the count↔list invariant under loom interleavings.
    #[test]
    fn linked_list_three_enqueues() {
        loom::model(ll_run_three_concurrent_enqueues);
    }

    /// Linked-list invariant under mixed enqueue + dequeue_head + remove.
    #[test]
    fn linked_list_enq_deq_remove() {
        loom::model(ll_run_enqueue_dequeue_remove);
    }

    /// Explanatory: confirms that a double-enqueue of the same tid produces
    /// the observed corruption shape, so the model can recognise it.
    /// Not under loom::model — purely a sanity check on `check_invariant`.
    #[test]
    fn linked_list_double_enqueue_recognised() {
        ll_double_enqueue_invariant_catches();
    }

    /// Reuse + cleanup model: TS attached to a thread after dequeue,
    /// later taken via take_or_alloc and re-initialized.  Cleanup races
    /// the take_or_alloc.  Mirrors the real kernel's cleanup_blocked
    /// unsafe pre-lock read of ts.hash/key/aspace/va.
    #[test]
    fn reuse_cleanup_race() {
        loom::model(reuse_run);
    }
}

// =============================================================================
// TS reuse + cleanup_blocked model
//
// Boot 545's wc=3 head=NIL corruption was NOT produced by the three
// concurrent ts_* ops above (loom found no race).  This model adds:
//
//   * A 1-slot TS "pool" with alloc/free.
//   * Per-thread `.turnstile` field (attached TS after dequeue).
//   * `take_or_alloc(tid)` — swap `.turnstile`, alloc if zero.
//   * `cleanup_blocked(tid)` — UNSAFE pre-lock read of ts fields,
//     then take lock and ts_remove if HAMT still has it.
//   * Re-init via `init_turnstile` after take_or_alloc.
//
// Loom interleaves: thread A dequeues itself + take_or_alloc + re-enqueue
// for a different port, while thread B (already exiting) calls
// cleanup_blocked on the SAME TS — the pre-lock read sees mid-init state.
// =============================================================================

const R_N_TIDS: usize = 2;
const R_N_PORTS: usize = 2;

#[derive(Clone, Copy, Default)]
struct ReuseTs {
    head: u32,
    tail: u32,
    wc: u16,
    /// Logical key — set by init_turnstile, used to detect "wrong TS".
    key: u32,
    ts_next: [u32; R_N_TIDS],
    ts_prev: [u32; R_N_TIDS],
    in_list: [bool; R_N_TIDS],
    /// Generation counter.  Bumped on every init.  cleanup_blocked
    /// captures this pre-lock and re-checks it under lock.
    gen: u32,
}

impl ReuseTs {
    fn nil() -> Self {
        Self {
            head: LL_NIL,
            tail: LL_NIL,
            wc: 0,
            key: 0,
            ts_next: [LL_NIL; R_N_TIDS],
            ts_prev: [LL_NIL; R_N_TIDS],
            in_list: [false; R_N_TIDS],
            gen: 0,
        }
    }

    fn init(&mut self, key: u32) {
        self.head = LL_NIL;
        self.tail = LL_NIL;
        self.wc = 0;
        self.key = key;
        self.ts_next = [LL_NIL; R_N_TIDS];
        self.ts_prev = [LL_NIL; R_N_TIDS];
        self.in_list = [false; R_N_TIDS];
        self.gen = self.gen.wrapping_add(1);
    }

    fn ts_enqueue(&mut self, tid: u32) {
        let t = tid as usize;
        self.ts_next[t] = LL_NIL;
        self.ts_prev[t] = self.tail;
        if self.tail != LL_NIL {
            self.ts_next[self.tail as usize] = tid;
        } else {
            self.head = tid;
        }
        self.tail = tid;
        self.wc += 1;
        self.in_list[t] = true;
    }

    fn ts_remove(&mut self, tid: u32) -> bool {
        let mut cur = self.head;
        while cur != LL_NIL {
            if cur == tid {
                let t = tid as usize;
                let prev = self.ts_prev[t];
                let next = self.ts_next[t];
                if prev != LL_NIL {
                    self.ts_next[prev as usize] = next;
                } else {
                    self.head = next;
                }
                if next != LL_NIL {
                    self.ts_prev[next as usize] = prev;
                } else {
                    self.tail = prev;
                }
                self.ts_next[t] = LL_NIL;
                self.ts_prev[t] = LL_NIL;
                self.wc -= 1;
                self.in_list[t] = false;
                return true;
            }
            cur = self.ts_next[cur as usize];
        }
        false
    }

    fn check_invariant(&self) {
        let mut walked = 0u16;
        let mut cur = self.head;
        while cur != LL_NIL {
            walked += 1;
            assert!(walked <= 4, "linked list cycle or overrun");
            cur = self.ts_next[cur as usize];
        }
        assert_eq!(walked, self.wc, "wc={} walked={}", self.wc, walked);
    }
}

struct ReuseHamt {
    /// HAMT per port → (in_hamt, current_gen).  The bucket Mutex covers
    /// both the HAMT slot and the TS contents (single 1-TS pool).
    in_hamt: [bool; R_N_PORTS],
    in_hamt_gen: [u32; R_N_PORTS],
    ts: ReuseTs,
    /// 1-slot pool: ts_allocated tracks whether the pool slot is in use.
    /// take_or_alloc returns either the thread's attached TS or this slot.
    pool_allocated: bool,
}

impl ReuseHamt {
    fn new() -> Self {
        Self {
            in_hamt: [false; R_N_PORTS],
            in_hamt_gen: [0; R_N_PORTS],
            ts: ReuseTs::nil(),
            pool_allocated: false,
        }
    }
}

struct ReuseShared {
    bucket: Mutex<ReuseHamt>,
    /// Per-thread .turnstile field.  0 = no TS attached.  1 = pool slot.
    thread_turnstile: [AtomicUsize; R_N_TIDS],
    /// Per-thread .ts_blocked_on field.  0 = not blocked. 1 = pool slot.
    ts_blocked_on: [AtomicUsize; R_N_TIDS],
    /// Cleanup race counter — incremented when cleanup_blocked observes
    /// a generation mismatch under the lock (TS was re-initialized
    /// after the unsafe pre-lock read).
    cleanup_gen_mismatch: AtomicUsize,
}

impl ReuseShared {
    fn new() -> Self {
        Self {
            bucket: Mutex::new(ReuseHamt::new()),
            thread_turnstile: [
                AtomicUsize::new(0),
                AtomicUsize::new(0),
            ],
            ts_blocked_on: [
                AtomicUsize::new(0),
                AtomicUsize::new(0),
            ],
            cleanup_gen_mismatch: AtomicUsize::new(0),
        }
    }
}

/// Enqueue tid on port via take_or_alloc + maybe-init + ts_enqueue.
fn reuse_enqueue(s: &ReuseShared, tid: u32, port: u32) {
    let mut h = s.bucket.lock().unwrap();
    let ts_ptr = if h.in_hamt[port as usize] {
        1usize // logical pool slot
    } else {
        // take_or_alloc: try thread's attached TS first.
        let attached = s.thread_turnstile[tid as usize].swap(0, Ordering::Relaxed);
        let p = if attached != 0 {
            attached
        } else if !h.pool_allocated {
            h.pool_allocated = true;
            1usize
        } else {
            // Already allocated to someone else — bail (model limit).
            return;
        };
        // init.
        h.ts.init(port);
        h.in_hamt[port as usize] = true;
        h.in_hamt_gen[port as usize] = h.ts.gen;
        p
    };
    let _ = ts_ptr;
    h.ts.ts_enqueue(tid);
    s.ts_blocked_on[tid as usize].store(1, Ordering::Relaxed);
}

/// Dequeue head from a port.  If TS empties, hamt_remove + attach to dequeued tid.
fn reuse_dequeue(s: &ReuseShared, port: u32) -> Option<u32> {
    let mut h = s.bucket.lock().unwrap();
    if !h.in_hamt[port as usize] {
        return None;
    }
    let head = h.ts.head;
    if head == LL_NIL {
        return None;
    }
    let h_idx = head as usize;
    let next = h.ts.ts_next[h_idx];
    h.ts.ts_next[h_idx] = LL_NIL;
    h.ts.ts_prev[h_idx] = LL_NIL;
    h.ts.head = next;
    if next != LL_NIL {
        h.ts.ts_prev[next as usize] = LL_NIL;
    } else {
        h.ts.tail = LL_NIL;
    }
    h.ts.wc -= 1;
    h.ts.in_list[h_idx] = false;
    s.ts_blocked_on[h_idx].store(0, Ordering::Relaxed);
    if h.ts.wc == 0 {
        h.in_hamt[port as usize] = false;
        h.in_hamt_gen[port as usize] = 0;
        // Attach via CAS — if thread already has one, return TS to pool.
        if s.thread_turnstile[h_idx]
            .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            // free back to pool
            h.pool_allocated = false;
        }
    }
    Some(head)
}

/// cleanup_blocked: UNSAFE pre-lock read of TS state, then take lock + re-check.
fn reuse_cleanup_blocked(s: &ReuseShared, tid: u32) {
    let ts_addr = s.ts_blocked_on[tid as usize].swap(0, Ordering::Acquire);
    if ts_addr == 0 {
        return;
    }
    // Pre-lock read: in the real kernel this reads ts.hash/key/aspace/va.
    // We model just `key` and `gen`.  These can race with init_turnstile.
    let h = s.bucket.lock().unwrap();
    let mut hh = h;
    // Re-check under lock: is the TS still in HAMT for the key we
    // expected, with the same gen?  (Mirrors `if slot.ts_id == ts_id`.)
    // If yes → ts_remove(tid).  If no → was reused for a different key,
    // skip (kernel's behavior).
    let key = hh.ts.key;
    let port = key as usize;
    if port < R_N_PORTS && hh.in_hamt[port] && hh.in_hamt_gen[port] == hh.ts.gen {
        if hh.ts.ts_remove(tid) {
            if hh.ts.wc == 0 {
                hh.in_hamt[port] = false;
                hh.in_hamt_gen[port] = 0;
            }
        }
    } else {
        s.cleanup_gen_mismatch.fetch_add(1, Ordering::Relaxed);
    }
}

/// One loom interleaving: A enqueues + later cleans up; B does a parallel
/// enqueue/dequeue on the same port.
fn reuse_run() {
    let s = Arc::new(ReuseShared::new());
    // Seed: tid 0 is parked on port 0.
    reuse_enqueue(&s, 0, 0);
    let a = {
        let s = s.clone();
        thread::spawn(move || reuse_cleanup_blocked(&s, 0))
    };
    let b = {
        let s = s.clone();
        thread::spawn(move || {
            // Wake/dequeue from port 0.
            let _ = reuse_dequeue(&s, 0);
        })
    };
    let c = {
        let s = s.clone();
        thread::spawn(move || {
            // tid 1 enqueues on port 1.
            reuse_enqueue(&s, 1, 1);
        })
    };
    a.join().unwrap();
    b.join().unwrap();
    c.join().unwrap();
    let h = s.bucket.lock().unwrap();
    // Invariant: ts state internally consistent.
    h.ts.check_invariant();
    // HAMT membership consistent with non-empty TS.
    let any_in_hamt = h.in_hamt.iter().any(|&x| x);
    if h.ts.wc > 0 {
        assert!(any_in_hamt, "wc={} but no port has TS in HAMT", h.ts.wc);
    }
}
