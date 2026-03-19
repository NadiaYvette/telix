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

pub fn print() {
    crate::println!("  VM stats:");
    crate::println!("    Major faults:  {}", MAJOR_FAULTS.load(Ordering::Relaxed));
    crate::println!("    Minor faults:  {}", MINOR_FAULTS.load(Ordering::Relaxed));
    crate::println!("    Pages zeroed:  {}", PAGES_ZEROED.load(Ordering::Relaxed));
    crate::println!("    PTEs installed: {}", PTES_INSTALLED.load(Ordering::Relaxed));
    crate::println!("    PTEs removed:  {}", PTES_REMOVED.load(Ordering::Relaxed));
    crate::println!("    Pages reclaimed: {}", PAGES_RECLAIMED.load(Ordering::Relaxed));
    crate::println!("    WSCLOCK scans: {}", WSCLOCK_SCANS.load(Ordering::Relaxed));
    crate::println!("    Contiguous PTE promotions: {}", CONTIGUOUS_PROMOTIONS.load(Ordering::Relaxed));
    crate::println!("    COW faults:    {}", COW_FAULTS.load(Ordering::Relaxed));
    crate::println!("    COW pages copied: {}", COW_PAGES_COPIED.load(Ordering::Relaxed));
    crate::println!("    Superpage promotions: {}", SUPERPAGE_PROMOTIONS.load(Ordering::Relaxed));
    crate::println!("    Superpage demotions: {}", SUPERPAGE_DEMOTIONS.load(Ordering::Relaxed));
}
