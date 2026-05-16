//! Loom model of `kernel/src/mm/phys.rs`'s lock-free bitmap+fc CAS
//! dance for `chunk_alloc_one` and `chunk_free_one`.
//!
//! Real chunk state in phys.rs is a packed u64 with multiple fields,
//! but the concurrent-correctness invariant lives in the BITMAP-MODE
//! subset: a bitmap u64 (per-bit free flag) and the chunk's `fc`
//! field, plus the global free count.  We model just those three and
//! the operations that touch them:
//!
//!   alloc():
//!     loop {
//!       bmp = bitmap.load()
//!       if bmp == 0 { return None; }
//!       bit = lowest set bit of bmp
//!       new_bmp = bmp & !(1 << bit)
//!       if !cas_bitmap(bmp, new_bmp) { continue; }    // retry
//!       // ── decrement fc (loop until success, but break if cur_fc==0) ──
//!       loop {
//!         cur = fc.load()
//!         if cur == 0 { break; }                       // defensive
//!         if cas_fc(cur, cur-1) { break; }             // happy
//!       }
//!       global.fetch_sub(1)
//!       return Some(bit)
//!     }
//!
//!   free(bit):
//!     loop {
//!       bmp = bitmap.load()
//!       if bmp & (1 << bit) != 0 { return Err(DoubleFree); }  // check
//!       new_bmp = bmp | (1 << bit)
//!       if !cas_bitmap(bmp, new_bmp) { continue; }    // retry
//!       // ── increment fc (capped at 63 per commit 90bd1ce) ──
//!       loop {
//!         cur = fc.load()
//!         if cur >= 63 { break; }                      // cap
//!         if cas_fc(cur, cur+1) { break; }             // happy
//!       }
//!       global.fetch_add(1)
//!       return Ok(())
//!     }
//!
//! Invariants at quiescence (all threads joined):
//!   I1. bitmap.count_ones() == fc
//!   I2. global == fc (single chunk → sum of fcs is just fc)
//!   I3. No two successful allocs returned the same bit-index
//!   I4. Frees against bits already set returned DoubleFree
//!
//! Things deliberately NOT modeled:
//!   * Inline mode (separate code path; covered by Verus round-trip)
//!   * fc==63→64 transition (mode-switch logic; needs the full state word)
//!   * Multi-chunk paths (this is a single chunk)
//!   * Per-CPU reservations (out-of-band; tested elsewhere)

#![cfg(loom)]

use loom::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

struct Chunk {
    bitmap: AtomicU64,
    fc: AtomicU32,
    global: AtomicU32, // single-chunk global count
    // Set of page-indices currently held by callers — guarded by
    // a Mutex so threads can compare-and-insert their allocated bit
    // without losing it to a concurrent allocator.  This is the
    // "no double-alloc" invariant tracker.
    holders: Mutex<u64>, // bitmap of held bits
}

impl Chunk {
    fn new(initial_bitmap: u64) -> Self {
        let fc = initial_bitmap.count_ones();
        Self {
            bitmap: AtomicU64::new(initial_bitmap),
            fc: AtomicU32::new(fc),
            global: AtomicU32::new(fc),
            holders: Mutex::new(0),
        }
    }
}

#[derive(Debug, PartialEq)]
enum FreeErr {
    DoubleFree,
}

/// Model `chunk_alloc_one`'s bitmap-mode path.  Returns Some(bit) on
/// success or None if the bitmap is exhausted.  Records the bit in the
/// `holders` set so the test can assert no two callers got the same one.
fn alloc(c: &Chunk) -> Option<u32> {
    // bitmap CAS loop
    let bit;
    loop {
        let bmp = c.bitmap.load(Ordering::Acquire);
        if bmp == 0 {
            return None;
        }
        let b = bmp.trailing_zeros();
        let new_bmp = bmp & !(1u64 << b);
        if c
            .bitmap
            .compare_exchange(bmp, new_bmp, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            bit = b;
            break;
        }
        // CAS failed; retry
    }

    // Claim the bit in the holders set (must be atomic with the bitmap
    // CAS in the sense that no other allocator will pick this bit —
    // which the bitmap CAS already ensures).  We just record for the
    // double-alloc check.
    {
        let mut h = c.holders.lock().unwrap();
        let mask = 1u64 << bit;
        assert!(
            *h & mask == 0,
            "double-alloc: bit {} already held by another caller",
            bit
        );
        *h |= mask;
    }

    // fc decrement loop (cur_fc==0 defensive break, per phys.rs current
    // behaviour at the time of this model)
    loop {
        let cur = c.fc.load(Ordering::Acquire);
        if cur == 0 {
            break;
        }
        if c.fc
            .compare_exchange(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
    }
    c.global.fetch_sub(1, Ordering::AcqRel);
    Some(bit)
}

/// Model `chunk_free_one`'s bitmap-mode path with the double-free
/// detection (commit c525ce0).
fn free(c: &Chunk, bit: u32) -> Result<(), FreeErr> {
    // Clear the holders set entry first.  If we never held this bit,
    // that's the caller's bug (real-world: client freed a page they
    // didn't allocate).  We don't model that — assume callers free
    // only their own allocations OR test the dedicated double-free
    // scenario by NOT clearing holders.
    let mask = 1u64 << bit;
    {
        let mut h = c.holders.lock().unwrap();
        if *h & mask == 0 {
            // Bit not held — caller is doing a bogus free.  The
            // bitmap-CAS will catch the "already set" case as
            // DoubleFree; otherwise we just proceed as if the caller
            // is correct (the kernel can't tell ownership at this
            // level anyway).
        } else {
            *h &= !mask;
        }
    }

    // bitmap CAS loop with double-free detection
    loop {
        let bmp = c.bitmap.load(Ordering::Acquire);
        if bmp & mask != 0 {
            // Bit already set → page is already "free".  This is
            // the double-free signal the kernel logs.
            return Err(FreeErr::DoubleFree);
        }
        let new_bmp = bmp | mask;
        if c
            .bitmap
            .compare_exchange(bmp, new_bmp, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
        // CAS failed; retry
    }

    // fc increment loop (capped at 63 per commit 90bd1ce)
    loop {
        let cur = c.fc.load(Ordering::Acquire);
        if cur >= 63 {
            break;
        }
        if c.fc
            .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
    }
    c.global.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

/// Quiescent-state invariant check.  All threads have joined; verify
/// the chunk's accounting matches reality.
fn check_invariants(c: &Chunk) {
    let bmp = c.bitmap.load(Ordering::Acquire);
    let fc = c.fc.load(Ordering::Acquire);
    let global = c.global.load(Ordering::Acquire);
    let holders = *c.holders.lock().unwrap();

    let bmp_set = bmp.count_ones();
    // I1: bitmap bits set == fc
    assert_eq!(
        bmp_set, fc,
        "I1 violated: bitmap.count_ones()={} != fc={}",
        bmp_set, fc
    );
    // I2: global == fc (single chunk)
    assert_eq!(
        global, fc,
        "I2 violated: global={} != fc={}",
        global, fc
    );
    // I3-ish: holders and bitmap are disjoint
    assert_eq!(
        bmp & holders, 0,
        "I3 violated: bit in both bitmap and holders (bmp={:b} holders={:b})",
        bmp, holders
    );
    // Conservation: bmp_set + holders.count_ones() == initial_bits
    // (we don't track initial here; caller does end-to-end check)
}

// ─────────────────────────────────────────────────────────────────────
// Test scenarios
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Two threads concurrently allocate from a chunk with 2 bits free.
    /// At end: bitmap=0, fc=0, global=0, both holders are distinct.
    #[test]
    fn two_concurrent_allocs() {
        loom::model(|| {
            let c = Arc::new(Chunk::new(0b11)); // bits 0, 1 free
            let ca = c.clone();
            let cb = c.clone();
            let ta = thread::spawn(move || alloc(&ca));
            let tb = thread::spawn(move || alloc(&cb));
            let ra = ta.join().unwrap();
            let rb = tb.join().unwrap();
            // Both should succeed since bitmap has 2 set bits.
            assert!(ra.is_some(), "thread A alloc failed");
            assert!(rb.is_some(), "thread B alloc failed");
            assert_ne!(ra, rb, "double-alloc: both got bit {:?}", ra);
            check_invariants(&c);
        });
    }

    /// 1 alloc + 1 free interleaving.  Start with bit 0 free + bit 5
    /// "held" (we manually pre-record it).  Alloc takes bit 0; free
    /// returns bit 5.  At end: bitmap = {0,5}, fc=2, global=2.
    #[test]
    fn alloc_and_free_interleaved() {
        loom::model(|| {
            let c = Arc::new(Chunk::new(0b1)); // bit 0 free
            // Pre-record bit 5 as held by an imaginary "previous caller".
            *c.holders.lock().unwrap() |= 1 << 5;

            let ca = c.clone();
            let cf = c.clone();
            let ta = thread::spawn(move || alloc(&ca));
            let tf = thread::spawn(move || free(&cf, 5));
            let ra = ta.join().unwrap();
            let rf = tf.join().unwrap();

            assert_eq!(ra, Some(0), "alloc should return bit 0");
            assert_eq!(rf, Ok(()), "free should succeed");

            let bmp = c.bitmap.load(Ordering::Acquire);
            assert_eq!(
                bmp & 0b1, 0,
                "bit 0 should be cleared by alloc, bmp={:b}",
                bmp
            );
            assert_eq!(
                bmp & (1 << 5),
                1 << 5,
                "bit 5 should be set by free, bmp={:b}",
                bmp
            );
            check_invariants(&c);
        });
    }

    /// Two frees of the same bit.  One should succeed, the other
    /// should return DoubleFree.  This is the c525ce0 fix's invariant.
    #[test]
    fn double_free_detected() {
        loom::model(|| {
            let c = Arc::new(Chunk::new(0)); // empty bitmap (chunk fully allocated)
            // Pre-record bit 3 as held (so first free's holders-clear matches).
            // Second free will see holders empty for bit 3 (still proceeds to
            // bitmap CAS check, which catches it).
            *c.holders.lock().unwrap() |= 1 << 3;

            let cf1 = c.clone();
            let cf2 = c.clone();
            let t1 = thread::spawn(move || free(&cf1, 3));
            let t2 = thread::spawn(move || free(&cf2, 3));
            let r1 = t1.join().unwrap();
            let r2 = t2.join().unwrap();

            // Exactly one should succeed, the other must report DoubleFree.
            let oks = [r1.is_ok(), r2.is_ok()].iter().filter(|&&x| x).count();
            let errs = [&r1, &r2].iter().filter(|r| **r == &Err(FreeErr::DoubleFree)).count();
            assert_eq!(oks, 1, "exactly one free should succeed: r1={:?} r2={:?}", r1, r2);
            assert_eq!(errs, 1, "exactly one should be DoubleFree: r1={:?} r2={:?}", r1, r2);

            let bmp = c.bitmap.load(Ordering::Acquire);
            assert_eq!(bmp, 1 << 3, "only bit 3 should be set: bmp={:b}", bmp);
            check_invariants(&c);
        });
    }
}
