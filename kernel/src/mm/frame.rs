//! Physical frame reference counting for COW (copy-on-write) support.
//!
//! A global table indexed by page frame number (PFN) tracks how many
//! address spaces share each physical allocation page. Refcount 1 means
//! exclusively owned; refcount > 1 means COW-shared.
//!
//! The table is sized at boot from actual RAM — no compile-time cap.
//! `phys::init()` carves it from the start of usable memory and calls
//! `init_table()` to install the pointer.
//!
//! All operations are lock-free using AtomicU32 per-PFN refcounts.

use super::page::{PhysAddr, PAGE_SHIFT};
use core::sync::atomic::{AtomicU32, Ordering};

/// Boot-time configuration: set once in `init_table()`, read-only after.
/// Safety: written once at boot (single-threaded BSP), then immutable.
static mut REFCOUNTS: *const AtomicU32 = core::ptr::null();
static mut REFCOUNT_COUNT: usize = 0;
static mut REFCOUNT_BASE: usize = 0;

/// Compute PFN from a physical address.
#[inline]
fn pfn(pa: PhysAddr) -> usize {
    (pa.as_usize() - unsafe { REFCOUNT_BASE }) >> PAGE_SHIFT
}

/// Get a reference to the AtomicU32 for a PFN, or None if out of range.
#[inline]
fn slot(pa: PhysAddr) -> Option<&'static AtomicU32> {
    let idx = pfn(pa);
    if idx < unsafe { REFCOUNT_COUNT } {
        Some(unsafe { &*REFCOUNTS.add(idx) })
    } else {
        None
    }
}

/// Install the boot-time-carved refcount table.
/// Called from `phys::init()` after carving metadata from RAM.
///
/// `ptr`: pointer to zeroed array, reinterpreted as AtomicU32.
///        Must be 4-byte aligned and have `count` entries.
/// `count`: number of physical pages (= total_pages from phys allocator).
/// `base`: base physical address of managed RAM.
///
/// Safety: must be called exactly once, from the BSP, before any other
/// function in this module.
pub fn init_table(ptr: *mut u8, count: usize, base: usize) {
    unsafe {
        REFCOUNTS = ptr as *const AtomicU32;
        REFCOUNT_COUNT = count;
        REFCOUNT_BASE = base;
    }
}

/// Set the reference count for a physical page.
pub fn set_ref(pa: PhysAddr, count: u16) {
    if let Some(s) = slot(pa) {
        s.store(count as u32, Ordering::Release);
    }
}

/// Increment the reference count. Returns the new count.
pub fn inc_ref(pa: PhysAddr) -> u16 {
    match slot(pa) {
        Some(s) => {
            // Saturating add via CAS loop.
            let prev = s.fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                Some(v.saturating_add(1))
            }).unwrap_or(0);
            (prev.saturating_add(1)) as u16
        }
        None => 1,
    }
}

/// Decrement the reference count. Returns the new count.
/// Caller should free the page if this returns 0.
pub fn dec_ref(pa: PhysAddr) -> u16 {
    match slot(pa) {
        Some(s) => {
            let prev = s.fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                if v > 0 { Some(v - 1) } else { Some(0) }
            }).unwrap_or(0);
            (if prev > 0 { prev - 1 } else { 0 }) as u16
        }
        None => 0,
    }
}

/// Compare-and-swap the reference count. Returns Ok(old) on success,
/// Err(actual) if the current value didn't match `expected`.
/// Used for lazy refcount initialization at COW fault time.
pub fn cas_ref(pa: PhysAddr, expected: u16, new: u16) -> Result<u16, u16> {
    match slot(pa) {
        Some(s) => {
            match s.compare_exchange(
                expected as u32,
                new as u32,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(old) => Ok(old as u16),
                Err(actual) => Err(actual as u16),
            }
        }
        None => Err(0),
    }
}

/// Get the current reference count.
pub fn get_ref(pa: PhysAddr) -> u16 {
    match slot(pa) {
        Some(s) => s.load(Ordering::Acquire) as u16,
        None => 0,
    }
}
