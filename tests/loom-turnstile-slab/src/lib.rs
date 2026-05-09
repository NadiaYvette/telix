//! Loom model of the **turnstile slab-recycle race** in
//! `kernel/src/sync/turnstile.rs`.
//!
//! Two paths interact with each thread's per-thread turnstile cache slot
//! (`Thread::turnstile: AtomicUsize`, thread.rs:134):
//!
//!   * Wake/dequeue (`port_wake_one`, turnstile.rs:880-942; same tail in
//!     `port_dequeue_one`, turnstile.rs:985-1017): under bucket lock,
//!     pop last waiter -> hamt_remove -> `compare_exchange(0, ts_ptr,
//!     Relaxed, Relaxed)` into woken thread's cache; on CAS failure,
//!     `free_turnstile(ts_ptr)`.
//!
//!   * Take/alloc (`take_or_alloc_turnstile(tid)`, turnstile.rs:378-385):
//!     `thread_ref(tid).turnstile.swap(0, Relaxed)`; reuse if non-zero,
//!     else `slab::alloc`.  The swap is **not** under the bucket lock.
//!
//! Because slab::alloc can re-hand-out a freshly-freed address, an
//! interleaving between these two paths can in principle produce two
//! threads with live references to the same slab.  This crate hunts
//! that interleaving with two loom threads.
//!
//! NOT modeled: multiple buckets/ports, priority bits, head/tail list,
//! full park/wake (covered by loom-park-state, loom-turnstile).

#![cfg(loom)]

use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

/// Address of the *recyclable* slab — the one we hunt the race for.
const SLAB_ADDR: usize = 0xDEAD_BEEF;
/// Distinct address for fresh allocs while SLAB_ADDR is still in use,
/// modeling the kernel slab handing out a different free chunk.
const SLAB_ADDR_FRESH: usize = 0xCAFE_F00D;

/// Two-slot slab pool that recycles SLAB_ADDR only after it's freed.
/// If alloc'd while SLAB_ADDR is in_use, hands out SLAB_ADDR_FRESH
/// instead — faithful to the kernel slab (free chunks recycled,
/// in-use chunks not).
struct SlabPool {
    /// Live owners of SLAB_ADDR.  Must stay <= 1 at all times.
    live_owners: AtomicUsize,
    /// Bumped on each SLAB_ADDR alloc; detects stale references.
    gen: AtomicUsize,
    /// True while SLAB_ADDR is currently allocated.
    in_use: AtomicBool,
    /// SLAB_ADDR payload `Turnstile{ key_type, va, waiter_count }`
    /// guarded (in real kernel) by the bucket lock.
    payload: Mutex<SlabPayload>,
    /// Diagnostic: count of alloc fall-backs to SLAB_ADDR_FRESH.
    fresh_allocs: AtomicUsize,
}

#[derive(Default, Clone, Copy)]
struct SlabPayload {
    /// Generation that wrote these fields; used to detect torn reads.
    gen: usize,
    key_type: u8,
    va: usize,
    waiter_count: u32,
}

impl SlabPool {
    fn new() -> Self {
        Self {
            live_owners: AtomicUsize::new(0),
            gen: AtomicUsize::new(0),
            in_use: AtomicBool::new(false),
            payload: Mutex::new(SlabPayload::default()),
            fresh_allocs: AtomicUsize::new(0),
        }
    }

    /// Models `slab::alloc(TS_SLAB_SIZE)` + zero-init (turnstile.rs:355).
    /// Returns SLAB_ADDR if currently free, else SLAB_ADDR_FRESH.
    fn alloc(&self) -> usize {
        if self
            .in_use
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.live_owners.fetch_add(1, Ordering::AcqRel);
            let g = self.gen.fetch_add(1, Ordering::AcqRel) + 1;
            // Zero-init like alloc_turnstile does.
            let mut p = self.payload.lock().unwrap();
            *p = SlabPayload {
                gen: g,
                ..SlabPayload::default()
            };
            SLAB_ADDR
        } else {
            self.fresh_allocs.fetch_add(1, Ordering::AcqRel);
            SLAB_ADDR_FRESH
        }
    }

    fn free(&self, addr: usize) {
        // SLAB_ADDR_FRESH frees are untracked — only SLAB_ADDR matters.
        if addr == SLAB_ADDR {
            self.live_owners.fetch_sub(1, Ordering::AcqRel);
            self.in_use.store(false, Ordering::Release);
        }
    }
}

/// `WAIT_HAMT[bucket]` collapsed to a single slot for a single port.
#[derive(Default, Clone, Copy)]
struct HamtSlot {
    present: bool,
    /// `*mut Turnstile` advertised to the HAMT (0 if !present).
    ts_addr: usize,
    /// Generation snapshot at insert; detects stale pointers post-recycle.
    ts_gen: usize,
}

struct Shared {
    pool: SlabPool,
    bucket: Mutex<HamtSlot>,
    /// Analogue of `Thread::turnstile` for the woken thread (A).  In the
    /// real kernel `take_or_alloc(tid)` is normally called for tid==self;
    /// modeling another thread doing it for A.cache stresses the slot's
    /// AtomicUsize semantics.
    cache_a: AtomicUsize,
    /// Snapshot of `live_owners` worst case across the run.
    max_live_owners: AtomicUsize,
    // Diagnostic counters.
    free_calls: AtomicUsize,
    cas_succ: AtomicUsize,
    take_returned_nonzero: AtomicUsize,
}

impl Shared {
    fn new() -> Self {
        Self {
            pool: SlabPool::new(),
            bucket: Mutex::new(HamtSlot::default()),
            cache_a: AtomicUsize::new(0),
            free_calls: AtomicUsize::new(0),
            cas_succ: AtomicUsize::new(0),
            take_returned_nonzero: AtomicUsize::new(0),
            max_live_owners: AtomicUsize::new(0),
        }
    }

    fn observe_live_owners(&self) {
        let cur = self.pool.live_owners.load(Ordering::Acquire);
        let mut prev = self.max_live_owners.load(Ordering::Acquire);
        while cur > prev {
            match self.max_live_owners.compare_exchange(
                prev,
                cur,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(p) => prev = p,
            }
        }
    }
}

/// `port_wake_one` tail (turnstile.rs:919-944): lock bucket -> lookup ->
/// dequeue head -> if waiter_count==0, hamt_remove + CAS-into-cache or
/// free.  Drop bucket lock.
fn wake_path(s: &Shared, cas_ord: Ordering) {
    let mut slot = s.bucket.lock().unwrap();
    if !slot.present {
        return;
    }
    let ts_addr = slot.ts_addr;
    let _ts_gen = slot.ts_gen;
    {
        let mut p = s.pool.payload.lock().unwrap();
        if p.waiter_count == 0 {
            // No waiter to wake — would have early-returned in real
            // kernel ("no waiters").  Drop the lock untouched.
            return;
        }
        p.waiter_count -= 1;
    }
    // Mirror turnstile.rs:933 — empty turnstile, hamt_remove.
    let removed_payload_empty = {
        let p = s.pool.payload.lock().unwrap();
        p.waiter_count == 0
    };
    if removed_payload_empty {
        // hamt_remove
        *slot = HamtSlot::default();
        // CAS-or-free.  This is the race surface.
        let cas_res = s
            .cache_a
            .compare_exchange(0, ts_addr, cas_ord, cas_ord);
        if cas_res.is_ok() {
            s.cas_succ.fetch_add(1, Ordering::AcqRel);
            // Slab is now logically owned by A's cache slot.  Pool
            // still considers it allocated (live_owners stays).
        } else {
            s.free_calls.fetch_add(1, Ordering::AcqRel);
            s.pool.free(ts_addr);
        }
    }
    s.observe_live_owners();
    drop(slot);
}

/// `take_or_alloc_turnstile(A)` (turnstile.rs:378-385) + init_turnstile
/// + hamt_insert + ts_enqueue (turnstile.rs:893-905).  The swap on
/// A.cache is NOT under the bucket lock; the rest is.  hamt_insert
/// collision -> free + bail (turnstile.rs:894-897).
fn take_and_enqueue_path(s: &Shared, swap_ord: Ordering, port_id: usize) {
    let addr = s.cache_a.swap(0, swap_ord);
    let (ts_addr, _was_alloc) = if addr != 0 {
        s.take_returned_nonzero.fetch_add(1, Ordering::AcqRel);
        (addr, false)
    } else {
        (s.pool.alloc(), true)
    };
    s.observe_live_owners();

    // Now write through ts_addr — the slab fields.  In a kernel bug
    // path this races with the wake_path's read of waiter_count above.
    // We only write the SLAB_ADDR payload if that's actually the slab
    // we got back; SLAB_ADDR_FRESH lives in a different slab chunk we
    // don't track payload-wise.
    if ts_addr == SLAB_ADDR {
        let mut p = s.pool.payload.lock().unwrap();
        // init_turnstile zeros and writes new key.
        p.key_type = 1;
        p.va = port_id;
        p.waiter_count = 0;
        let g = s.pool.gen.fetch_add(1, Ordering::AcqRel) + 1;
        p.gen = g;
    }

    let mut slot = s.bucket.lock().unwrap();
    if slot.present {
        // hamt_insert collision — kernel frees and bails.
        s.free_calls.fetch_add(1, Ordering::AcqRel);
        s.pool.free(ts_addr);
        s.observe_live_owners();
        return;
    }
    slot.present = true;
    slot.ts_addr = ts_addr;
    slot.ts_gen = s.pool.gen.load(Ordering::Acquire);
    // ts_enqueue (only meaningful for SLAB_ADDR — the recyclable slab).
    if ts_addr == SLAB_ADDR {
        let mut p = s.pool.payload.lock().unwrap();
        p.waiter_count += 1;
        drop(p);
    }
    drop(slot);
    s.observe_live_owners();
}

/// Pre-state: HAMT holds T (A is parked, waiter_count=1); A.cache=0
/// (T was lent out to the HAMT, not cached on A).  Two loom threads:
/// W runs the wake_path; R runs take_and_enqueue_path on a fresh port.
fn one_run_with(cas_ord: Ordering, swap_ord: Ordering) {
    let s = Arc::new(Shared::new());

    // Seed: pretend a previous take_or_alloc allocated T and parked A
    // on it.  Slab is in-use, HAMT holds it, A is the sole waiter.
    let t_addr = s.pool.alloc();
    {
        let mut p = s.pool.payload.lock().unwrap();
        p.key_type = 1;
        p.va = 0xAAAA;
        p.waiter_count = 1;
    }
    {
        let mut slot = s.bucket.lock().unwrap();
        slot.present = true;
        slot.ts_addr = t_addr;
        slot.ts_gen = s.pool.gen.load(Ordering::Acquire);
    }

    let s_w = s.clone();
    let s_r = s.clone();

    let w = thread::spawn(move || wake_path(&s_w, cas_ord));
    let r = thread::spawn(move || take_and_enqueue_path(&s_r, swap_ord, 0xBBBB));

    w.join().unwrap();
    r.join().unwrap();

    // ----- Final invariants -----

    // (1) The slab is never simultaneously held by two distinct users.
    //     Worst observed live_owners must be <= 1.
    let max_owners = s.max_live_owners.load(Ordering::Acquire);
    assert!(
        max_owners <= 1,
        "slab-recycle aliasing: max live_owners = {} (expected <= 1)",
        max_owners,
    );

    // (2) Pool accounting for the recyclable slab (SLAB_ADDR only).
    //     SLAB_ADDR is held by exactly one of: A.cache, HAMT slot, or
    //     "freed" (in_use==false).  Never two of those at once.
    let cur_owners = s.pool.live_owners.load(Ordering::Acquire);
    let cache_addr = s.cache_a.load(Ordering::Acquire);
    let cache_holds_slab = (cache_addr == SLAB_ADDR) as usize;
    let (hamt_present, hamt_addr) = {
        let slot = s.bucket.lock().unwrap();
        (slot.present, slot.ts_addr)
    };
    let hamt_holds_slab = (hamt_present && hamt_addr == SLAB_ADDR) as usize;
    let in_use = s.pool.in_use.load(Ordering::Acquire);

    if in_use {
        assert_eq!(
            cur_owners, 1,
            "pool in_use but live_owners={} (cache_slab={} hamt_slab={})",
            cur_owners, cache_holds_slab, hamt_holds_slab,
        );
        assert_eq!(
            cache_holds_slab + hamt_holds_slab,
            1,
            "pool in_use but cache_slab+hamt_slab = {}+{} (must == 1) \
             (cache_addr={:#x} hamt_addr={:#x})",
            cache_holds_slab, hamt_holds_slab, cache_addr, hamt_addr,
        );
    } else {
        assert_eq!(
            cur_owners, 0,
            "pool not in_use but live_owners={}",
            cur_owners,
        );
        assert_eq!(
            cache_holds_slab, 0,
            "pool not in_use but A.cache holds SLAB_ADDR",
        );
        assert_eq!(
            hamt_holds_slab, 0,
            "pool not in_use but HAMT still claims SLAB_ADDR",
        );
    }

    // (3) HAMT consistency for SLAB_ADDR.  If SLAB_ADDR has waiters,
    //     either the HAMT slot or A.cache must reference it.  Holding
    //     a turnstile with waiter_count>0 in A.cache (a dormant
    //     turnstile no waker can find) would be the user's reported
    //     "ts_blocked_on != 0 but port_dequeue_one returns None"
    //     symptom — assert that doesn't happen.
    let payload = *s.pool.payload.lock().unwrap();
    if in_use && payload.waiter_count > 0 {
        assert!(
            hamt_present && hamt_addr == SLAB_ADDR,
            "lost-wakeup: SLAB_ADDR has {} waiter(s) but HAMT does not \
             hold it (hamt_present={} hamt_addr={:#x} cache_addr={:#x})",
            payload.waiter_count, hamt_present, hamt_addr, cache_addr,
        );
    }

    // (4) Frees never outnumber allocs.  (live_owners is signed-ish —
    //     a wraparound here would surface as a huge usize.)
    assert!(
        cur_owners < (isize::MAX as usize),
        "live_owners wrapped (=> double-free) — cur={}",
        cur_owners,
    );
}

fn one_run() {
    // Faithful kernel orderings: cache CAS Relaxed, swap Relaxed.
    one_run_with(Ordering::Relaxed, Ordering::Relaxed);
}

fn one_run_seqcst() {
    one_run_with(Ordering::SeqCst, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Control: SeqCst on swap+CAS — failures here indicate a
    /// model/protocol bug, not a memory-ordering bug.
    #[test]
    fn slab_recycle_seqcst() {
        loom::model(one_run_seqcst);
    }

    /// Faithful: kernel uses Relaxed on both Thread::turnstile.swap
    /// (`take_or_alloc_turnstile`) and the cache-slot compare_exchange
    /// (`port_wake_one` / `port_dequeue_one`).
    #[test]
    fn slab_recycle_real() {
        loom::model(one_run);
    }
}
