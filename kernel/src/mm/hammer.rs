//! #228 alloc/free compression workload.
//!
//! Hammer-thread that allocates a page, writes a per-(cpu, iter)
//! sentinel pattern, immediately re-reads, compares, and frees.  Any
//! mismatch = the phys allocator double-issued this PA to a peer that
//! scribbled it between the write and the re-read.
//!
//! Spawned by `start_hammers(n)` if the kernel cmdline carries
//! `alloc_hammer=N` (N = number of hammer kthreads to spawn).  Each
//! kthread runs at low priority (200) so it doesn't starve real work,
//! but with a small quantum (5 ms) so it gets frequent cycles.
//!
//! Output: every 1000 iterations a HAMMER-STAT line, immediately on
//! mismatch a HAMMER-MISMATCH line with all the bytes printed in hex
//! for downstream diff against the expected sentinel.
//!
//! Goal: compress the natural Phase 4-5 race window (~40% rate at
//! 60 s on riscv64 SMP=4) to 100% within a fraction of a second.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::mm::phys;
use crate::sched::smp;

/// Total iterations across all hammers, for the HAMMER-STAT periodic emit.
static OPS_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Total mismatches across all hammers.
static MISMATCH_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Sentinel-write target bytes that the reader sees instead.  Useful
/// for printing a short summary in the periodic stat.
static LAST_MISMATCH_GOT: AtomicU64 = AtomicU64::new(0);
static LAST_MISMATCH_WANT: AtomicU64 = AtomicU64::new(0);

/// One hammer kthread.  Loops forever: alloc → write sentinel →
/// re-read → compare → free.  CPU + iter form the sentinel pattern so
/// we can attribute who clobbered what.
fn hammer_kthread() -> ! {
    let cpu = smp::cpu_id() as u64;
    let mut iter: u64 = 0;
    loop {
        iter = iter.wrapping_add(1);
        let pa = match phys::alloc_page() {
            Some(p) => p,
            None => {
                // Allocator empty — block briefly and retry.
                for _ in 0..1000 {
                    core::hint::spin_loop();
                }
                continue;
            }
        };

        // Sentinel pattern: 8-byte word repeated through the page.
        // High 32 bits = cpu, low 32 bits = iter.  Easy to attribute on
        // mismatch: dump the pattern, look at the high half to identify
        // which CPU's hammer is the victim, low half = iter count.
        let sentinel: u64 = (cpu << 32) | (iter & 0xFFFF_FFFF);

        let page = pa.as_usize() as *mut u64;
        let words = crate::mm::page::page_size() / 8;

        // Write sentinel across the page.
        unsafe {
            for i in 0..words {
                core::ptr::write_volatile(page.add(i), sentinel);
            }
        }

        // Re-read the first 4 words and compare.  Reading the whole
        // page on every iter would dominate runtime; 4 words is enough
        // to catch a smashed page since corruption hits page-aligned
        // chunks (kstacks, slab slabs).
        let mut mismatch = false;
        unsafe {
            for i in 0..4 {
                let got = core::ptr::read_volatile(page.add(i));
                if got != sentinel {
                    mismatch = true;
                    LAST_MISMATCH_GOT.store(got, Ordering::Relaxed);
                    LAST_MISMATCH_WANT.store(sentinel, Ordering::Relaxed);
                    break;
                }
            }
        }

        if mismatch {
            MISMATCH_TOTAL.fetch_add(1, Ordering::Relaxed);
            // Emit immediately — these are gold.
            crate::println!(
                "HAMMER-MISMATCH: cpu={} iter={} pa={:#x} sentinel_want={:#x} sentinel_got={:#x}",
                cpu, iter, pa.as_usize(),
                sentinel,
                LAST_MISMATCH_GOT.load(Ordering::Relaxed),
            );
        }

        // Free.
        phys::free_page(pa);

        let ops = OPS_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        if ops % 1000 == 0 {
            crate::println!(
                "HAMMER-STAT: ops={} mismatch={} last_want={:#x} last_got={:#x}",
                ops,
                MISMATCH_TOTAL.load(Ordering::Relaxed),
                LAST_MISMATCH_WANT.load(Ordering::Relaxed),
                LAST_MISMATCH_GOT.load(Ordering::Relaxed),
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
    crate::println!("[#228 hammer] starting {} alloc/free hammer kthreads", n);
    for _ in 0..n {
        let _ = crate::sched::spawn(hammer_kthread, 200, 5);
    }
}
