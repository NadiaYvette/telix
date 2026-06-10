//! #228 alloc/free compression workload — hold-time variant.
//!
//! Each hammer kthread allocates a batch of N pages, fills each with a
//! per-(cpu, generation, page_idx, offset) sentinel, then *holds* the
//! batch (yielding for `hold_ticks` schedule ticks so peer Phase 4-5
//! churn has time to interfere), then verifies every word of every
//! page, then frees them all and starts a new generation.
//!
//! The hold phase is critical: the v1 hammer (tight alloc → write →
//! read → free) did 9000+ ops in 60 s with 0 mismatches on rv64 SMP=4
//! because the race window was too short to overlap with peer
//! consumers.  The real #228 surface is alloc → spawn-as-kstack →
//! peer double-issue scribbles it during init.  Holding 8 pages each
//! for ~100 ms compresses that window aggressively without starving
//! the rest of the system.
//!
//! Output:
//!   HAMMER-STAT every 100 batches
//!   HAMMER-MISMATCH immediately on any sentinel disagreement, with
//!     full (page_idx, offset_word, want, got) so addr2line of the
//!     "got" value can identify the writer.
//!
//! Spawned by `start_hammers(n)` if the kernel cmdline carries
//! `alloc_hammer=N` (N = number of hammer kthreads to spawn).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::mm::page::PhysAddr;
use crate::mm::phys;
use crate::sched::smp;

/// How many pages each hammer holds at once.  Larger = wider race
/// window but lower throughput.  Mixed orders below so the hammer
/// exercises both alloc_page (single) and alloc_pages(order=1) paths
/// — the second writer that triggers #228 may be path-sensitive.
const HOLD_PAGES: usize = 16;

/// Inner spin-cycles between batches.  ~10 ms wallclock under TCG.
const HOLD_SPINS: u32 = 10_000_000;

/// Total batches across all hammers, for the HAMMER-STAT periodic emit.
static BATCHES_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Total pages written + verified across all hammers (for ops/s).
static PAGES_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Total mismatches across all hammers.
static MISMATCH_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Sentinel for a (cpu, generation, page_idx, offset_word) tuple.
///
/// Bit layout (u64):
///   [63:48]   cpu          (16 bits — way more than enough)
///   [47:32]   page_idx     (16 bits — covers HOLD_PAGES <= 65535)
///   [31:16]   offset_word  (16 bits — covers 65536 words = 512 KiB pages)
///   [15:0]    generation          (16 bits, wraps per kthread)
///
/// Any mismatch's (cpu, page_idx, offset_word, generation) immediately
/// localises *which* slot got scribbled and what the writer wrote.
#[inline(always)]
fn sentinel(cpu: u64, generation: u64, page_idx: usize, offset_word: usize) -> u64 {
    (cpu << 48)
        | ((page_idx as u64 & 0xFFFF) << 32)
        | ((offset_word as u64 & 0xFFFF) << 16)
        | (generation & 0xFFFF)
}

/// One hammer kthread.  Outer loop: alloc HOLD_PAGES → fill → hold →
/// verify → free.  CPU + generation form the per-batch identity.
fn hammer_kthread() -> ! {
    let cpu = smp::cpu_id() as u64;
    let mut generation: u64 = 0;
    let mut pages: [Option<PhysAddr>; HOLD_PAGES] = [None; HOLD_PAGES];

    loop {
        generation = generation.wrapping_add(1);
        let words_per_page = crate::mm::page::page_size() / 8;

        // 1. Allocate the batch.  Mix orders 0 and 1 so the hammer
        //    exercises both the inline-mode chunk path (small allocs)
        //    and the bitmap-mode chunk path (larger).  Tracked
        //    separately as `orders[i]` so the verify and free passes
        //    know what to clean up.
        let mut allocated = 0;
        let mut orders = [0usize; HOLD_PAGES];
        for i in 0..HOLD_PAGES {
            // Mix orders 0, 1, 4: kstacks are 1 MiB = order=4 at
            // 64 KiB pages, and zero_daemon's kstack is consistently
            // the #228 victim.  If the bug is path-sensitive on
            // multi-page contig allocs, this catches it.
            let order = match i % 3 {
                0 => 0,
                1 => 1,
                _ => 4,
            };
            let result = if order == 0 {
                phys::alloc_page()
            } else {
                phys::alloc_pages(order)
            };
            match result {
                Some(pa) => {
                    pages[i] = Some(pa);
                    orders[i] = order;
                    allocated += 1;
                }
                None => break, // allocator empty — proceed with what we got
            }
        }
        if allocated == 0 {
            // Allocator wholly empty — back off and retry.
            for _ in 0..HOLD_SPINS {
                core::hint::spin_loop();
            }
            continue;
        }

        // 2. Fill each allocation with its per-word sentinel.  For
        //    order=1 we have 2 pages contiguous; fill both.
        for i in 0..allocated {
            let pa = pages[i].unwrap();
            let total_words = words_per_page << orders[i];
            let page = pa.as_usize() as *mut u64;
            unsafe {
                for w in 0..total_words {
                    let s = sentinel(cpu, generation, i, w);
                    core::ptr::write_volatile(page.add(w), s);
                }
            }
        }

        // 3. Hold — spin a while so peer consumers get scheduling time
        //    against the held pages.  Spin (not block) because we want
        //    the pages held WHILE other CPUs run; blocking would make
        //    this thread relinquish entirely and the pages-held window
        //    would close immediately on free.
        for _ in 0..HOLD_SPINS {
            core::hint::spin_loop();
        }

        // 4. Verify every word of every page.  This is where we catch
        //    #228 — a peer double-issued one of our PAs and scribbled
        //    it during the hold.
        for i in 0..allocated {
            let pa = pages[i].unwrap();
            let total_words = words_per_page << orders[i];
            let page = pa.as_usize() as *mut u64;
            unsafe {
                for w in 0..total_words {
                    let want = sentinel(cpu, generation, i, w);
                    let got = core::ptr::read_volatile(page.add(w));
                    if got != want {
                        MISMATCH_TOTAL.fetch_add(1, Ordering::Relaxed);
                        crate::println!(
                            "HAMMER-MISMATCH: cpu={} generation={} pa={:#x} page_idx={} word_off={} want={:#x} got={:#x}",
                            cpu, generation, pa.as_usize(), i, w, want, got,
                        );
                        // Don't break — keep scanning this page so we
                        // see the *shape* of the corruption (which
                        // words were hit) for forensics.
                    }
                }
            }
        }
        PAGES_TOTAL.fetch_add(allocated as u64, Ordering::Relaxed);

        // 5. Free the batch.  Use free_pages for orders > 0.
        for i in 0..allocated {
            if let Some(pa) = pages[i].take() {
                if orders[i] == 0 {
                    phys::free_page(pa);
                } else {
                    phys::free_pages(pa, orders[i]);
                }
            }
        }

        let batches = BATCHES_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        if batches % 100 == 0 {
            crate::println!(
                "HAMMER-STAT: batches={} pages={} mismatch={} cpu={} generation={}",
                batches,
                PAGES_TOTAL.load(Ordering::Relaxed),
                MISMATCH_TOTAL.load(Ordering::Relaxed),
                cpu, generation,
            );
        }
    }
}

/// Spawn `n` hammer kthreads, one bound to each CPU if possible.
/// Called from main.rs init after the scheduler is up.
pub fn start_hammers(n: usize) {
    if n == 0 {
        return;
    }
    crate::println!(
        "[#228 hammer] starting {} hold-time kthreads, hold={} pages × {} spins",
        n, HOLD_PAGES, HOLD_SPINS,
    );
    for _ in 0..n {
        let _ = crate::sched::spawn(hammer_kthread, 200, 5);
    }
}

// ===== Persistent variant ============================================
//
// The cycle hammer's alloc → fill → hold → verify → free never caught
// #228 because the bug surface is path-specific to kstack-allocated
// PAs that stay allocated.  This variant mimics that lifecycle: each
// kthread allocates PERSISTENT_CHUNKS order=4 (kstack-sized) chunks
// at startup, fills them with the same sentinel, then loops
// forever verifying.  Never frees.
//
// Memory cost: PERSISTENT_CHUNKS (8) × 2^PERSISTENT_ORDER (16) ×
// page_size (64 KiB) = 8 MiB per kthread.  With 4 kthreads = 32 MiB,
// well within the 256 MiB QEMU RAM budget.
//
// Verify pass scans every word of every chunk; expected to be the
// long pole, but order=4 × 8 = 128 pages × 8 K words = 1 M words per
// pass, ~milliseconds on KVM, ~seconds on TCG.  Mismatch fires
// immediately on first divergence with full (cpu, chunk_idx,
// word_off, want, got) for forensics.

const PERSISTENT_CHUNKS: usize = 8;
const PERSISTENT_ORDER: usize = 4;
const PERSISTENT_SPINS: u32 = 5_000_000;

fn persistent_hammer_kthread() -> ! {
    let cpu = smp::cpu_id() as u64;
    let mut chunks: [Option<PhysAddr>; PERSISTENT_CHUNKS] = [None; PERSISTENT_CHUNKS];
    let words_per_chunk = (crate::mm::page::page_size() / 8) << PERSISTENT_ORDER;

    // Phase 1: allocate + fill.  Done once.
    let mut allocated = 0;
    for i in 0..PERSISTENT_CHUNKS {
        match phys::alloc_pages(PERSISTENT_ORDER) {
            Some(pa) => {
                chunks[i] = Some(pa);
                let p = pa.as_usize() as *mut u64;
                unsafe {
                    for w in 0..words_per_chunk {
                        // generation=0 baseline so verify can use the same.
                        let s = sentinel(cpu, 0, i, w);
                        core::ptr::write_volatile(p.add(w), s);
                    }
                }
                allocated += 1;
            }
            None => {
                crate::println!(
                    "[#228 persistent-hammer] cpu={} OOM at chunk {}/{}",
                    cpu, i, PERSISTENT_CHUNKS,
                );
                break;
            }
        }
    }
    crate::println!(
        "[#228 persistent-hammer] cpu={} allocated {}/{} order-{} chunks ({} MiB)",
        cpu, allocated, PERSISTENT_CHUNKS, PERSISTENT_ORDER,
        (allocated * words_per_chunk * 8) >> 20,
    );

    // Phase 2: verify forever.
    let mut pass: u64 = 0;
    loop {
        pass += 1;

        // Spin between passes so other CPUs get their work done.
        for _ in 0..PERSISTENT_SPINS {
            core::hint::spin_loop();
        }

        let mut pass_mismatches: u64 = 0;
        for i in 0..allocated {
            if let Some(pa) = chunks[i] {
                let p = pa.as_usize() as *mut u64;
                unsafe {
                    for w in 0..words_per_chunk {
                        let want = sentinel(cpu, 0, i, w);
                        let got = core::ptr::read_volatile(p.add(w));
                        if got != want {
                            pass_mismatches += 1;
                            MISMATCH_TOTAL.fetch_add(1, Ordering::Relaxed);
                            crate::println!(
                                "PERSISTENT-MISMATCH: cpu={} pass={} pa={:#x} chunk_idx={} word_off={} want={:#x} got={:#x}",
                                cpu, pass, pa.as_usize(), i, w, want, got,
                            );
                        }
                    }
                }
            }
        }

        if pass % 10 == 0 || pass_mismatches > 0 {
            crate::println!(
                "PERSISTENT-PASS: cpu={} pass={} mismatch_this_pass={} mismatch_total={}",
                cpu, pass, pass_mismatches, MISMATCH_TOTAL.load(Ordering::Relaxed),
            );
        }
    }
}

/// Spawn `n` PERSISTENT hammer kthreads.  Each holds PERSISTENT_CHUNKS
/// order=4 allocations forever and verifies their integrity in a loop.
pub fn start_persistent_hammers(n: usize) {
    if n == 0 {
        return;
    }
    crate::println!(
        "[#228 persistent-hammer] starting {} kthreads, {} order-{} chunks each",
        n, PERSISTENT_CHUNKS, PERSISTENT_ORDER,
    );
    for _ in 0..n {
        let _ = crate::sched::spawn(persistent_hammer_kthread, 200, 5);
    }
}
