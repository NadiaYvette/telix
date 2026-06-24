//! H14 perf #4 — background-preload LIB_CACHE slot-allocation race — loom model.
//!
//! Backgrounding `lib_cache_eager_populate` (docs/h14-perf-repertoire.md #4) makes
//! `lib_cache_lookup_or_alloc` CONCURRENT for the first time: the background preload
//! thread and the main-thread `handle_mmap` both call it for the same initramfs
//! handle.  Today it is LOCK-FREE (`linux_srv.rs:4512`) — scan-for-existing then
//! scan-for-free-and-claim with no mutual exclusion — safe only because mmap is
//! main-thread-only (`__NR_MMAP` not in `is_worker_safe_syscall`) and the preload
//! runs single-threaded before the dispatch loop.
//!
//!   INVARIANT: at most ONE cache slot is ever allocated for a given handle.
//!
//! `lockfree_alloc_double_allocates` (#[should_panic]) — two concurrent callers for
//! one handle each pass the "no existing slot" scan before either claims, then claim
//! two DIFFERENT free slots → two slots for one handle (wasted backing region + the
//! second mmap fills/serves a separate copy → cache incoherent).
//!
//! `locked_alloc_is_unique` — a Mutex (the Phase-B TicketSpinLock idiom) around the
//! whole scan+claim makes `lookup_or_alloc` atomic → exactly one slot per handle
//! under every interleaving.  This is the #4 fix.

#![cfg(loom)]

use loom::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

/// Two slots — the minimum that can expose a double-alloc (each racer claims a
/// distinct free slot for the same handle).
const N: usize = 2;

/// The shared initramfs handle both callers race to cache.
const H: u64 = 0x11b;

/// One filled "word" of a chunk's backing bytes (0 = pre-fill).
const FILLED: u32 = 0xA5A5_A5A5;

struct Slot {
    in_use: AtomicBool,
    handle: AtomicU64,
}
impl Slot {
    fn new() -> Self {
        Slot { in_use: AtomicBool::new(false), handle: AtomicU64::new(0) }
    }
}

struct Cache {
    slots: [Slot; N],
    lock: Mutex<()>,
}
impl Cache {
    fn new() -> Self {
        Cache { slots: [Slot::new(), Slot::new()], lock: Mutex::new(()) }
    }

    /// Current kernel shape (linux_srv.rs:4512): scan for an existing slot, then
    /// scan for a free slot and claim it — NO mutual exclusion.  The window
    /// between "no existing slot found" and "claim a free slot" is the race.
    fn lookup_or_alloc_lockfree(&self, handle: u64) -> Option<usize> {
        for i in 0..N {
            if self.slots[i].in_use.load(Ordering::Acquire)
                && self.slots[i].handle.load(Ordering::Acquire) == handle
            {
                return Some(i);
            }
        }
        for i in 0..N {
            if !self.slots[i].in_use.load(Ordering::Acquire) {
                // RACE WINDOW: a concurrent caller can also have observed no
                // existing slot and be about to claim a *different* free slot
                // for the same handle.
                self.slots[i].handle.store(handle, Ordering::Release);
                self.slots[i].in_use.store(true, Ordering::Release);
                return Some(i);
            }
        }
        None
    }

    /// #4 fix: a Mutex around the entire scan+claim (the Phase-B TicketSpinLock
    /// idiom — a LIB_CACHE_LOCK) makes the operation atomic, so a second caller
    /// for the same handle always observes the first caller's claim.
    fn lookup_or_alloc_locked(&self, handle: u64) -> Option<usize> {
        let _g = self.lock.lock().unwrap();
        for i in 0..N {
            if self.slots[i].in_use.load(Ordering::Relaxed)
                && self.slots[i].handle.load(Ordering::Relaxed) == handle
            {
                return Some(i);
            }
        }
        for i in 0..N {
            if !self.slots[i].in_use.load(Ordering::Relaxed) {
                self.slots[i].handle.store(handle, Ordering::Relaxed);
                self.slots[i].in_use.store(true, Ordering::Relaxed);
                return Some(i);
            }
        }
        None
    }
}

fn count_slots_for(c: &Cache, handle: u64) -> usize {
    (0..N)
        .filter(|&i| {
            c.slots[i].in_use.load(Ordering::Acquire)
                && c.slots[i].handle.load(Ordering::Acquire) == handle
        })
        .count()
}

/// preload thread ‖ main-thread handle_mmap, both `lookup_or_alloc(H)`.
fn run(locked: bool) {
    let c = Arc::new(Cache::new());
    let (c1, c2) = (c.clone(), c.clone());

    let t1 = thread::spawn(move || {
        if locked { c1.lookup_or_alloc_locked(H) } else { c1.lookup_or_alloc_lockfree(H) }
    });
    let t2 = thread::spawn(move || {
        if locked { c2.lookup_or_alloc_locked(H) } else { c2.lookup_or_alloc_lockfree(H) }
    });
    t1.join().unwrap();
    t2.join().unwrap();

    let n = count_slots_for(&c, H);
    assert!(n == 1, "handle allocated {} slots (double-alloc) — expected exactly 1", n);
}

/// Part B's other race: once the slot is unique (the lock above), the backgrounded
/// preload thread AND the main-thread on-demand fill may fill the SAME chunk at
/// once.  Both fetch the same immutable initramfs bytes (identical), write them to
/// the backing region, then set the chunk's `chunks_cached` bit Release; a consumer
/// Acquire-checks the bit before reading.
///
///   INVARIANT: a consumer that observes the bit set reads FILLED content, for
///   every interleaving of the two writers.
///
/// This is the publication that makes the **benign idempotent double-write** safe:
/// identical data ⇒ no torn *value*, and the Release/Acquire publishes a complete
/// write. (The byte-level "no torn read on identical aligned stores" is an x86
/// property argued separately; the per-chunk fetch is merely doubled, not wrong —
/// a future per-chunk claim removes that waste.)
fn run_concurrent_fill() {
    let content = Arc::new(AtomicU32::new(0));
    let cached = Arc::new(AtomicBool::new(false));
    let (cf1, bf1) = (content.clone(), cached.clone());
    let (cf2, bf2) = (content.clone(), cached.clone());
    let (cr, br) = (content.clone(), cached.clone());

    let f1 = thread::spawn(move || {
        cf1.store(FILLED, Ordering::Relaxed);
        bf1.store(true, Ordering::Release);
    });
    let f2 = thread::spawn(move || {
        cf2.store(FILLED, Ordering::Relaxed);
        bf2.store(true, Ordering::Release);
    });
    let r = thread::spawn(move || {
        if br.load(Ordering::Acquire) {
            assert_eq!(
                cr.load(Ordering::Relaxed),
                FILLED,
                "consumer observed chunks_cached set but read a torn/pre-fill chunk",
            );
        }
    });
    f1.join().unwrap();
    f2.join().unwrap();
    r.join().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cost of concurrency: the lock-free scan+claim lets two callers each claim a
    /// distinct free slot for the same handle.
    #[test]
    #[should_panic(expected = "double-alloc")]
    fn lockfree_alloc_double_allocates() {
        loom::model(|| run(false));
    }

    /// #4 fix: the Mutex serializes scan+claim → exactly one slot per handle.
    #[test]
    fn locked_alloc_is_unique() {
        loom::model(|| run(true));
    }

    /// Part B: two concurrent fillers of one chunk (preload thread ‖ main on-demand)
    /// publish a complete chunk to a consumer under every interleaving.
    #[test]
    fn concurrent_identical_fill_publishes() {
        loom::model(run_concurrent_fill);
    }
}
