//! kswapd — background page reclaim daemon.
//!
//! A kernel thread that wakes when free pages drop below a low watermark,
//! scans address spaces with WSCLOCK until free pages exceed the high
//! watermark, then blocks again. Modeled after Linux's kswapd but much
//! simpler: single-threaded, no NUMA awareness, no priority boosting.

use super::aspace;
use super::phys;
use super::wsclock;
use crate::sched::thread::BlockReason;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// kswapd thread ID. Set once at daemon startup.
static KSWAPD_TID: AtomicU32 = AtomicU32::new(u32::MAX);

/// Set to true once kswapd has started. Prevents wake attempts before
/// the thread is running.
static KSWAPD_RUNNING: AtomicBool = AtomicBool::new(false);

/// Low watermark: wake kswapd when free pages drop to this fraction of
/// total. Default: 1/16 of total pages. Public so phys.rs can reference it.
pub const LOW_WATERMARK_SHIFT: usize = 4; // 1/16

/// High watermark: kswapd stops reclaiming when free pages exceed this.
/// Default: 1/8 of total pages.
const HIGH_WATERMARK_SHIFT: usize = 3; // 1/8

/// Maximum allocation pages to reclaim per WSCLOCK scan pass per aspace.
const PAGES_PER_SCAN: usize = 16;

/// Compute the low watermark (free page count at which kswapd wakes).
fn low_watermark() -> usize {
    let (total, _) = phys::stats();
    total >> LOW_WATERMARK_SHIFT
}

/// Compute the high watermark (free page count at which kswapd sleeps).
fn high_watermark() -> usize {
    let (total, _) = phys::stats();
    total >> HIGH_WATERMARK_SHIFT
}

/// Wake kswapd if it's running. Called from `phys::alloc_page()` when
/// free pages drop below the low watermark.
pub fn wake_if_needed() {
    if !KSWAPD_RUNNING.load(Ordering::Relaxed) {
        return;
    }
    let tid = KSWAPD_TID.load(Ordering::Relaxed);
    if tid != u32::MAX {
        crate::sched::wake_thread(tid);
    }
}

/// Returns true if free pages are below the low watermark.
#[inline]
pub fn is_low() -> bool {
    let (_, free) = phys::stats();
    free < low_watermark()
}

/// kswapd kernel thread entry point.
pub fn kswapd() -> ! {
    let tid = crate::sched::current_thread_id();
    KSWAPD_TID.store(tid, Ordering::Relaxed);
    KSWAPD_RUNNING.store(true, Ordering::Release);

    crate::println!("  [kswapd] started (tid={})", tid);

    // Round-robin index into the aspace registry.
    let mut rr_idx: usize = 0;

    loop {
        let (_, free) = phys::stats();
        let hi = high_watermark();

        if free >= hi {
            // Enough free pages — block until woken.
            crate::sched::clear_wakeup_flag(tid);
            // Re-check after clearing to avoid lost wakeup.
            let (_, free2) = phys::stats();
            if free2 >= hi {
                crate::sched::block_current(BlockReason::Kswapd);
                continue;
            }
        }

        // Below high watermark — scan address spaces to reclaim pages.
        let snapshot = aspace::active_aspace_ids();
        if snapshot.is_empty() {
            // No user aspaces to reclaim from. Yield and retry.
            let my_tid = crate::sched::current_thread_id();
            crate::sched::scheduler::set_yield_asap(my_tid);
            crate::sched::scheduler::arch_wait_for_irq();
            continue;
        }

        // Scan one aspace per iteration (round-robin) to spread pressure.
        rr_idx = rr_idx % snapshot.len;
        let aspace_id = snapshot.ids[rr_idx];
        rr_idx += 1;

        let result = wsclock::scan(aspace_id, PAGES_PER_SCAN);
        if result.pages_freed > 0 {
            super::stats::KSWAPD_RECLAIMED
                .fetch_add(result.pages_freed as u64, Ordering::Relaxed);
        }
        // #160 working-set tracking: feed observed access-bit count
        // back into the per-aspace EWMA estimate.  Used by sys_spawn
        // admission control.
        super::aspace::update_working_set(aspace_id, result.pages_referenced as u32);
        super::stats::KSWAPD_SCANS.fetch_add(1, Ordering::Relaxed);
    }
}
