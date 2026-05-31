//! Background page pre-zeroing pool.
//!
//! A low-priority kernel thread zeroes dirty pages from the buddy allocator
//! and pushes them onto a fixed-size stack. `alloc_zeroed_page()` pops from
//! the pool, allowing the fault handler to skip per-sub-page zeroing when
//! the entire 64 KiB allocation page is already zero.

use super::page::{self, PhysAddr};
use super::phys;
use super::stats;
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicU32, Ordering};

/// Maximum number of pre-zeroed pages in the pool (64 × 64 KiB = 4 MiB).
const POOL_CAPACITY: usize = 64;

/// Wake the daemon when pool drops below this level.
const WAKE_WATERMARK: usize = POOL_CAPACITY / 2;

struct ZeroPoolInner {
    stack: [usize; POOL_CAPACITY],
    count: usize,
}

impl ZeroPoolInner {
    const fn new() -> Self {
        Self {
            stack: [0; POOL_CAPACITY],
            count: 0,
        }
    }
}

static POOL: SpinLock<ZeroPoolInner> = SpinLock::new(ZeroPoolInner::new());
static DAEMON_TID: AtomicU32 = AtomicU32::new(u32::MAX);

/// Pop a pre-zeroed page from the pool. Returns `None` if empty.
pub fn alloc_zeroed_page() -> Option<PhysAddr> {
    let mut pool = POOL.lock();
    if pool.count == 0 {
        return None;
    }
    pool.count -= 1;
    let pa = pool.stack[pool.count];
    let below_watermark = pool.count < WAKE_WATERMARK;
    drop(pool);

    stats::PAGES_PREZEROED.fetch_add(1, Ordering::Relaxed);

    // Wake daemon if pool is getting low.
    if below_watermark {
        let tid = DAEMON_TID.load(Ordering::Relaxed);
        if tid != u32::MAX {
            crate::sched::wake_thread(tid);
        }
    }

    Some(PhysAddr::new(pa))
}

/// Current number of pages in the pool.
#[allow(dead_code)]
pub fn pool_count() -> usize {
    POOL.lock().count
}

/// Background zero daemon — kernel thread entry point.
///
/// Continuously allocates dirty pages, zeroes them (without holding any lock),
/// and pushes them into the pool. Blocks when the pool is full or OOM.
pub fn zero_daemon() -> ! {
    let tid = crate::sched::current_thread_id();
    DAEMON_TID.store(tid, Ordering::Relaxed);

    loop {
        // Check if pool is full.
        let is_full = {
            let pool = POOL.lock();
            pool.count >= POOL_CAPACITY
        };

        if is_full {
            crate::sched::clear_wakeup_flag(tid);
            // Re-check after clearing flag to avoid lost wakeup.
            let still_full = {
                let pool = POOL.lock();
                pool.count >= POOL_CAPACITY
            };
            if still_full {
                crate::sched::block_current(crate::sched::thread::BlockReason::ZeroPool);
            }
            continue;
        }

        // Allocate a dirty page from the buddy allocator.
        let pa = match phys::alloc_page() {
            Some(pa) => pa,
            None => {
                // OOM — block and retry later.
                crate::sched::clear_wakeup_flag(tid);
                crate::sched::block_current(crate::sched::thread::BlockReason::ZeroPool);
                continue;
            }
        };

        // #208 BAD-frame fix: the phys allocator occasionally hands out
        // a PA that's currently in use as a kstack page (KSTACK_PA_OWNER
        // says so, but the buddy allocator doesn't know).  Writing 0x00
        // (ANON_POISON_BYTE) via identity VA scribbles the kstack's
        // iretq frame → BAD frame with CS=SS=RIP=0 → crash family for
        // tid=4 (zero_daemon itself) and tid=34 (init).  Boot
        // 11amfsq2203 reproduced this with 34 PA-ALIAS hits.
        //
        // Defensive fix: if the alloc landed in a kstack slot, skip
        // the zero AND skip pushing the page into the pool.  The page
        // is intentionally leaked from zero_daemon's perspective — we
        // never decrement nor pool it, so the buddy allocator's count
        // remains decremented and the in-use kstack stays intact.
        // Per-boot leak observed in 2203 = 34 × 64 KiB = ~2 MiB.
        // Acceptable trade-off until the phys allocator double-issue
        // is root-caused; the corruption is fatal, the leak is not.
        if crate::sched::scheduler::pa_in_kstack_slot(pa.as_usize()) {
            static SKIP_LOG: AtomicU32 = AtomicU32::new(0);
            let n = SKIP_LOG.fetch_add(1, Ordering::Relaxed);
            if n < 32 {
                crate::println!(
                    "ZERO-DAEMON-SKIP-KSTACK: pa={:#x} n={}",
                    pa.as_usize(),
                    n,
                );
                // First few skips: dump the phys allocator event ring
                // filtered to this PA's chunk so we can see the race
                // that let kstack + zero_daemon both think they own
                // this page.  chunk_idx = pa / (64 pages * page_size).
                if n < 4 {
                    let chunk_size = 64 * crate::mm::page::page_size();
                    let chunk_idx = pa.as_usize() / chunk_size;
                    super::phys::dump_evt_ring_for_chunk(chunk_idx);
                }
            }
            // Drop the PhysAddr without write_bytes / pool / free —
            // intentional leak (see comment above).
            let _ = pa;
            continue;
        }

        // Fill the full page with poison (0xCD) instead of zero. This
        // is the expensive part and happens WITHOUT holding any lock.
        // Pool clients are user-page allocators (mm::fault, personality
        // mmap) — see mm::ANON_POISON_BYTE.
        unsafe {
            core::ptr::write_bytes(
                crate::mm::page::phys_to_kva(pa.as_usize()) as *mut u8,
                crate::mm::ANON_POISON_BYTE,
                page::page_size(),
            );
        }

        // Push the zeroed page into the pool.
        let mut pool = POOL.lock();
        let idx = pool.count;
        if idx < POOL_CAPACITY {
            pool.stack[idx] = pa.as_usize();
            pool.count = idx + 1;
        } else {
            // Race: pool filled while we were zeroing. Return page.
            drop(pool);
            phys::free_page(pa);
        }
    }
}
