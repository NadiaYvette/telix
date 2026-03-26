//! Physical frame reference counting for COW (copy-on-write) support.
//!
//! A global table indexed by page frame number (PFN) tracks how many
//! address spaces share each physical allocation page. Refcount 1 means
//! exclusively owned; refcount > 1 means COW-shared.
//!
//! The table is sized at boot from actual RAM — no compile-time cap.
//! `phys::init()` carves it from the start of usable memory and calls
//! `init_table()` to install the pointer.

use super::page::{PhysAddr, PAGE_SHIFT};
use crate::sync::SpinLock;

struct FrameTable {
    /// Boot-time-carved refcount array. Null until init_table().
    refcounts: *mut u16,
    /// Number of entries (= total physical pages managed by the allocator).
    count: usize,
    /// Base physical address of managed RAM (for PFN calculation).
    base: usize,
}

// Safety: refcounts pointer is set once at boot (single-threaded) and
// then only accessed under the FRAME_TABLE spinlock.
unsafe impl Send for FrameTable {}

impl FrameTable {
    const fn new() -> Self {
        Self {
            refcounts: core::ptr::null_mut(),
            count: 0,
            base: 0,
        }
    }

    fn pfn(&self, pa: PhysAddr) -> usize {
        (pa.as_usize() - self.base) >> PAGE_SHIFT
    }
}

static FRAME_TABLE: SpinLock<FrameTable> = SpinLock::new(FrameTable::new());

/// Install the boot-time-carved refcount table.
/// Called from `phys::init()` after carving metadata from RAM.
///
/// `ptr`: pointer to zeroed u16 array of `count` entries.
/// `count`: number of physical pages (= total_pages from phys allocator).
/// `base`: base physical address of managed RAM.
pub fn init_table(ptr: *mut u16, count: usize, base: usize) {
    let mut ft = FRAME_TABLE.lock();
    ft.refcounts = ptr;
    ft.count = count;
    ft.base = base;
}

/// Set the reference count for a physical page.
pub fn set_ref(pa: PhysAddr, count: u16) {
    let mut ft = FRAME_TABLE.lock();
    let pfn = ft.pfn(pa);
    if pfn < ft.count {
        unsafe { *ft.refcounts.add(pfn) = count; }
    }
}

/// Increment the reference count. Returns the new count.
pub fn inc_ref(pa: PhysAddr) -> u16 {
    let mut ft = FRAME_TABLE.lock();
    let pfn = ft.pfn(pa);
    if pfn < ft.count {
        unsafe {
            let r = &mut *ft.refcounts.add(pfn);
            *r = r.saturating_add(1);
            *r
        }
    } else {
        1
    }
}

/// Decrement the reference count. Returns the new count.
/// Caller should free the page if this returns 0.
pub fn dec_ref(pa: PhysAddr) -> u16 {
    let mut ft = FRAME_TABLE.lock();
    let pfn = ft.pfn(pa);
    if pfn < ft.count {
        unsafe {
            let r = &mut *ft.refcounts.add(pfn);
            if *r > 0 {
                *r -= 1;
            }
            *r
        }
    } else {
        0
    }
}

/// Get the current reference count.
pub fn get_ref(pa: PhysAddr) -> u16 {
    let ft = FRAME_TABLE.lock();
    let pfn = ft.pfn(pa);
    if pfn < ft.count {
        unsafe { *ft.refcounts.add(pfn) }
    } else {
        0
    }
}
