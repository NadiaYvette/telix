//! VM statistics counters.

use core::sync::atomic::{AtomicU64, Ordering};

pub static MAJOR_FAULTS: AtomicU64 = AtomicU64::new(0);
pub static MINOR_FAULTS: AtomicU64 = AtomicU64::new(0);
pub static PAGES_ZEROED: AtomicU64 = AtomicU64::new(0);
pub static PTES_INSTALLED: AtomicU64 = AtomicU64::new(0);
pub static PTES_REMOVED: AtomicU64 = AtomicU64::new(0);
pub static PAGES_RECLAIMED: AtomicU64 = AtomicU64::new(0);
pub static WSCLOCK_SCANS: AtomicU64 = AtomicU64::new(0);
pub static CONTIGUOUS_PROMOTIONS: AtomicU64 = AtomicU64::new(0);
pub static COW_FAULTS: AtomicU64 = AtomicU64::new(0);
pub static COW_PAGES_COPIED: AtomicU64 = AtomicU64::new(0);
pub static SUPERPAGE_PROMOTIONS: AtomicU64 = AtomicU64::new(0);
pub static SUPERPAGE_DEMOTIONS: AtomicU64 = AtomicU64::new(0);
pub static PAGES_PREZEROED: AtomicU64 = AtomicU64::new(0);
pub static PAGER_FAULTS: AtomicU64 = AtomicU64::new(0);
pub static RESERVATION_CONSOLIDATIONS: AtomicU64 = AtomicU64::new(0);
pub static WSCLOCK_RESERVATION_SKIPS: AtomicU64 = AtomicU64::new(0);
pub static POOL_ALLOCS: AtomicU64 = AtomicU64::new(0);
pub static POOL_CREATES: AtomicU64 = AtomicU64::new(0);
pub static PT_TABLES_SHARED: AtomicU64 = AtomicU64::new(0);
pub static PT_COW_BREAKS: AtomicU64 = AtomicU64::new(0);
pub static KSWAPD_SCANS: AtomicU64 = AtomicU64::new(0);
pub static KSWAPD_RECLAIMED: AtomicU64 = AtomicU64::new(0);
pub static SWAP_SLOTS_DUPED: AtomicU64 = AtomicU64::new(0);
/// #164 Number of balance-set whole-process evictions (suspend_task
/// triggers fired by sys_spawn admission or kswapd starvation).
pub static BALANCE_SET_EVICTS: AtomicU64 = AtomicU64::new(0);
/// #164 Total threads transitioned to SuspendedMemPressure across all
/// balance-set evictions.
pub static BALANCE_SET_SUSPENDED: AtomicU64 = AtomicU64::new(0);
/// #164 Number of admission gate refusals (after balance-set evict
/// failed to free enough headroom).
pub static ADMISSION_REFUSALS: AtomicU64 = AtomicU64::new(0);
/// #164 Number of admission gate recoveries (balance-set evict freed
/// enough memory to satisfy the spawn).
pub static ADMISSION_RECOVERIES: AtomicU64 = AtomicU64::new(0);

pub fn print() {
    crate::println!("  VM stats:");
    crate::println!(
        "    Major faults:  {}",
        MAJOR_FAULTS.load(Ordering::Relaxed)
    );
    crate::println!(
        "    Minor faults:  {}",
        MINOR_FAULTS.load(Ordering::Relaxed)
    );
    crate::println!(
        "    Pages zeroed:  {}",
        PAGES_ZEROED.load(Ordering::Relaxed)
    );
    crate::println!(
        "    PTEs installed: {}",
        PTES_INSTALLED.load(Ordering::Relaxed)
    );
    crate::println!(
        "    PTEs removed:  {}",
        PTES_REMOVED.load(Ordering::Relaxed)
    );
    crate::println!(
        "    Pages reclaimed: {}",
        PAGES_RECLAIMED.load(Ordering::Relaxed)
    );
    crate::println!(
        "    WSCLOCK scans: {}",
        WSCLOCK_SCANS.load(Ordering::Relaxed)
    );
    crate::println!(
        "    Contiguous PTE promotions: {}",
        CONTIGUOUS_PROMOTIONS.load(Ordering::Relaxed)
    );
    crate::println!("    COW faults:    {}", COW_FAULTS.load(Ordering::Relaxed));
    crate::println!(
        "    COW pages copied: {}",
        COW_PAGES_COPIED.load(Ordering::Relaxed)
    );
    crate::println!(
        "    Superpage promotions: {}",
        SUPERPAGE_PROMOTIONS.load(Ordering::Relaxed)
    );
    crate::println!(
        "    Superpage demotions: {}",
        SUPERPAGE_DEMOTIONS.load(Ordering::Relaxed)
    );
    crate::println!(
        "    Pages pre-zeroed:  {}",
        PAGES_PREZEROED.load(Ordering::Relaxed)
    );
    crate::println!(
        "    Pager faults:  {}",
        PAGER_FAULTS.load(Ordering::Relaxed)
    );
    crate::println!(
        "    Reservation consolidations: {}",
        RESERVATION_CONSOLIDATIONS.load(Ordering::Relaxed)
    );
    crate::println!(
        "    WSCLOCK reservation skips: {}",
        WSCLOCK_RESERVATION_SKIPS.load(Ordering::Relaxed)
    );
    crate::println!(
        "    COW pool creates: {}",
        POOL_CREATES.load(Ordering::Relaxed)
    );
    crate::println!(
        "    COW pool allocs:  {}",
        POOL_ALLOCS.load(Ordering::Relaxed)
    );
    crate::println!(
        "    PT tables shared: {}",
        PT_TABLES_SHARED.load(Ordering::Relaxed)
    );
    crate::println!(
        "    PT COW breaks:    {}",
        PT_COW_BREAKS.load(Ordering::Relaxed)
    );
    crate::println!(
        "    kswapd scans:  {}",
        KSWAPD_SCANS.load(Ordering::Relaxed)
    );
    crate::println!(
        "    kswapd reclaimed: {}",
        KSWAPD_RECLAIMED.load(Ordering::Relaxed)
    );
    crate::println!(
        "    Swap slots duped: {}",
        SWAP_SLOTS_DUPED.load(Ordering::Relaxed)
    );
    crate::println!(
        "    Balance-set evictions: {}  (threads suspended total: {})",
        BALANCE_SET_EVICTS.load(Ordering::Relaxed),
        BALANCE_SET_SUSPENDED.load(Ordering::Relaxed),
    );
    crate::println!(
        "    Admission gate: refusals={}  recoveries={}",
        ADMISSION_REFUSALS.load(Ordering::Relaxed),
        ADMISSION_RECOVERIES.load(Ordering::Relaxed),
    );
}
