//! Background page pre-zeroing pool.
//!
//! A low-priority kernel thread zeroes dirty pages from the buddy allocator
//! and pushes them onto a fixed-size stack. `alloc_zeroed_page()` pops from
//! the pool, allowing the fault handler to skip per-sub-page zeroing when
//! the entire 64 KiB allocation page is already zero.

use super::page::{PhysAddr, PAGE_SIZE};
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
                crate::sched::block_current(
                    crate::sched::thread::BlockReason::ZeroPool,
                );
            }
            continue;
        }

        // Allocate a dirty page from the buddy allocator.
        let pa = match phys::alloc_page() {
            Some(pa) => pa,
            None => {
                // OOM — block and retry later.
                crate::sched::clear_wakeup_flag(tid);
                crate::sched::block_current(
                    crate::sched::thread::BlockReason::ZeroPool,
                );
                continue;
            }
        };

        // Zero the full PAGE_SIZE page. This is the expensive part and
        // happens WITHOUT holding any lock.
        unsafe {
            core::ptr::write_bytes(pa.as_usize() as *mut u8, 0, PAGE_SIZE);
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
