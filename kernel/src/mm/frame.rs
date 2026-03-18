//! Physical frame reference counting for COW (copy-on-write) support.
//!
//! A global table indexed by page frame number (PFN) tracks how many
//! address spaces share each physical allocation page. Refcount 1 means
//! exclusively owned; refcount > 1 means COW-shared.

use super::page::{PhysAddr, PAGE_SHIFT};
use crate::sync::SpinLock;

/// Maximum frames we track (matches phys allocator MAX_PAGES).
const MAX_FRAMES: usize = 8192;

struct FrameTable {
    refcounts: [u16; MAX_FRAMES],
    base: usize,
}

impl FrameTable {
    const fn new() -> Self {
        Self {
            refcounts: [0; MAX_FRAMES],
            base: 0,
        }
    }

    fn pfn(&self, pa: PhysAddr) -> usize {
        (pa.as_usize() - self.base) >> PAGE_SHIFT
    }
}

static FRAME_TABLE: SpinLock<FrameTable> = SpinLock::new(FrameTable::new());

/// Initialize the frame table base address (call after phys::init).
pub fn init(base: usize) {
    FRAME_TABLE.lock().base = base;
}

/// Set the reference count for a physical page.
pub fn set_ref(pa: PhysAddr, count: u16) {
    let mut ft = FRAME_TABLE.lock();
    let pfn = ft.pfn(pa);
    if pfn < MAX_FRAMES {
        ft.refcounts[pfn] = count;
    }
}

/// Increment the reference count. Returns the new count.
pub fn inc_ref(pa: PhysAddr) -> u16 {
    let mut ft = FRAME_TABLE.lock();
    let pfn = ft.pfn(pa);
    if pfn < MAX_FRAMES {
        ft.refcounts[pfn] = ft.refcounts[pfn].saturating_add(1);
        ft.refcounts[pfn]
    } else {
        1
    }
}

/// Decrement the reference count. Returns the new count.
/// Caller should free the page if this returns 0.
pub fn dec_ref(pa: PhysAddr) -> u16 {
    let mut ft = FRAME_TABLE.lock();
    let pfn = ft.pfn(pa);
    if pfn < MAX_FRAMES && ft.refcounts[pfn] > 0 {
        ft.refcounts[pfn] -= 1;
        ft.refcounts[pfn]
    } else {
        0
    }
}

/// Get the current reference count.
pub fn get_ref(pa: PhysAddr) -> u16 {
    let ft = FRAME_TABLE.lock();
    let pfn = ft.pfn(pa);
    if pfn < MAX_FRAMES {
        ft.refcounts[pfn]
    } else {
        0
    }
}
