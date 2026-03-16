//! Physical memory allocator — buddy system operating in PAGE_SIZE granules.
//!
//! This is a simple bitmap-based buddy allocator. Order 0 = one PAGE_SIZE page (64 KiB).
//! Maximum order supports up to 2^MAX_ORDER pages in a single block.
//!
//! The allocator uses a static bitmap stored in BSS. The bitmap tracks free/allocated
//! state for each PAGE_SIZE-aligned page in the managed physical address range.

use super::page::{PhysAddr, PAGE_SIZE, PAGE_SHIFT};

/// Maximum buddy order. Order N block = 2^N contiguous pages.
/// Order 10 = 1024 pages = 64 MiB at 64 KiB page size.
const MAX_ORDER: usize = 11;

/// Maximum number of pages we can track. At 64 KiB PAGE_SIZE, 8192 pages = 512 MiB.
const MAX_PAGES: usize = 8192;

/// Per-order free list implemented as a simple array-based stack.
/// Each entry is a page frame number (PFN) relative to the allocator's base.
const MAX_FREE_ENTRIES: usize = MAX_PAGES;

struct FreeList {
    entries: [u32; MAX_FREE_ENTRIES],
    count: usize,
}

impl FreeList {
    const fn new() -> Self {
        Self {
            entries: [0; MAX_FREE_ENTRIES],
            count: 0,
        }
    }

    fn push(&mut self, pfn: u32) {
        if self.count < MAX_FREE_ENTRIES {
            self.entries[self.count] = pfn;
            self.count += 1;
        }
    }

    fn pop(&mut self) -> Option<u32> {
        if self.count > 0 {
            self.count -= 1;
            Some(self.entries[self.count])
        } else {
            None
        }
    }

    fn remove(&mut self, pfn: u32) -> bool {
        for i in 0..self.count {
            if self.entries[i] == pfn {
                self.count -= 1;
                self.entries[i] = self.entries[self.count];
                return true;
            }
        }
        false
    }
}

/// Bitmap tracking allocated pages (1 = allocated, 0 = free).
struct Bitmap {
    bits: [u64; MAX_PAGES / 64],
}

impl Bitmap {
    const fn new() -> Self {
        // All bits set = all allocated (conservative default).
        Self {
            bits: [u64::MAX; MAX_PAGES / 64],
        }
    }

    fn set(&mut self, idx: usize) {
        self.bits[idx / 64] |= 1u64 << (idx % 64);
    }

    fn clear(&mut self, idx: usize) {
        self.bits[idx / 64] &= !(1u64 << (idx % 64));
    }

    fn is_set(&self, idx: usize) -> bool {
        self.bits[idx / 64] & (1u64 << (idx % 64)) != 0
    }
}

/// The physical memory allocator.
pub struct PhysAllocator {
    base: usize,       // Physical base address of managed region
    total_pages: usize, // Total pages in managed region
    free_pages: usize,  // Current free page count
    free_lists: [FreeList; MAX_ORDER + 1],
    bitmap: Bitmap,     // Tracks allocated state per page
}

impl PhysAllocator {
    const fn new() -> Self {
        Self {
            base: 0,
            total_pages: 0,
            free_pages: 0,
            free_lists: [
                FreeList::new(), FreeList::new(), FreeList::new(), FreeList::new(),
                FreeList::new(), FreeList::new(), FreeList::new(), FreeList::new(),
                FreeList::new(), FreeList::new(), FreeList::new(), FreeList::new(),
            ],
            bitmap: Bitmap::new(),
        }
    }

    /// Initialize the allocator with a single contiguous physical memory region.
    /// `start` and `end` are physical addresses; they will be aligned to PAGE_SIZE.
    fn init(&mut self, start: PhysAddr, end: PhysAddr) {
        let start_aligned = start.align_up(PAGE_SIZE);
        let end_aligned = end.align_down(PAGE_SIZE);

        if end_aligned.as_usize() <= start_aligned.as_usize() {
            return;
        }

        self.base = start_aligned.as_usize();
        self.total_pages = (end_aligned.as_usize() - start_aligned.as_usize()) >> PAGE_SHIFT;

        if self.total_pages > MAX_PAGES {
            self.total_pages = MAX_PAGES;
        }

        // Mark all managed pages as free in bitmap.
        for i in 0..self.total_pages {
            self.bitmap.clear(i);
        }

        // Add pages as largest possible buddy blocks.
        let mut pfn = 0u32;
        let mut remaining = self.total_pages;
        while remaining > 0 {
            // Find the largest order block that fits and is properly aligned.
            let mut order = MAX_ORDER;
            while order > 0 {
                let block_pages = 1 << order;
                if block_pages <= remaining && (pfn as usize % block_pages) == 0 {
                    break;
                }
                order -= 1;
            }
            let block_pages = 1usize << order;
            self.free_lists[order].push(pfn);
            self.free_pages += block_pages;
            pfn += block_pages as u32;
            remaining -= block_pages;
        }
    }

    /// Mark a range of physical addresses as reserved (not available for allocation).
    fn reserve_range(&mut self, start: PhysAddr, end: PhysAddr) {
        let start_pfn = if start.as_usize() <= self.base {
            0
        } else {
            (start.as_usize() - self.base) >> PAGE_SHIFT
        };
        let end_pfn = if end.as_usize() <= self.base {
            return;
        } else {
            ((end.as_usize() - self.base + PAGE_SIZE - 1) >> PAGE_SHIFT).min(self.total_pages)
        };

        for pfn in start_pfn..end_pfn {
            if !self.bitmap.is_set(pfn) {
                self.bitmap.set(pfn);
                self.free_pages -= 1;
                // Remove from free lists (expensive but only done at boot).
                self.remove_from_free_lists(pfn as u32);
            }
        }
    }

    /// Remove a single page from whatever free list block contains it.
    /// This splits larger blocks as needed.
    fn remove_from_free_lists(&mut self, target_pfn: u32) {
        for order in 0..=MAX_ORDER {
            let block_pages = 1u32 << order;
            let block_start = target_pfn & !(block_pages - 1);
            if self.free_lists[order].remove(block_start) {
                // Found and removed a block of this order containing target_pfn.
                // Re-add the remaining parts as smaller blocks.
                // Split: the block [block_start, block_start + block_pages) without target_pfn.
                self.split_and_readd(block_start, order, target_pfn);
                return;
            }
        }
    }

    /// After removing a block of `order` starting at `block_start`,
    /// re-add all sub-blocks except the one containing `except_pfn`.
    fn split_and_readd(&mut self, block_start: u32, order: usize, except_pfn: u32) {
        if order == 0 {
            return; // Nothing to split.
        }
        let half = 1u32 << (order - 1);
        let (first_half, second_half) = (block_start, block_start + half);

        if except_pfn < second_half {
            // except_pfn is in first half; re-add second half intact.
            self.free_lists[order - 1].push(second_half);
            // Recurse into first half.
            self.split_and_readd(first_half, order - 1, except_pfn);
        } else {
            // except_pfn is in second half; re-add first half intact.
            self.free_lists[order - 1].push(first_half);
            // Recurse into second half.
            self.split_and_readd(second_half, order - 1, except_pfn);
        }
    }

    /// Allocate a block of 2^order contiguous pages. Returns the physical address.
    fn alloc(&mut self, order: usize) -> Option<PhysAddr> {
        // Find a free block of sufficient order.
        for current_order in order..=MAX_ORDER {
            if let Some(pfn) = self.free_lists[current_order].pop() {
                // Split down to the requested order.
                let mut split_order = current_order;
                let split_pfn = pfn;
                while split_order > order {
                    split_order -= 1;
                    let buddy_pfn = split_pfn + (1u32 << split_order);
                    self.free_lists[split_order].push(buddy_pfn);
                    // split_pfn stays the same (we keep the lower half).
                }

                // Mark pages as allocated.
                let block_pages = 1usize << order;
                for i in 0..block_pages {
                    self.bitmap.set(pfn as usize + i);
                }
                self.free_pages -= block_pages;

                let addr = self.base + ((pfn as usize) << PAGE_SHIFT);
                return Some(PhysAddr::new(addr));
            }
        }
        None
    }

    /// Free a block of 2^order contiguous pages at the given physical address.
    fn free(&mut self, addr: PhysAddr, order: usize) {
        let pfn = ((addr.as_usize() - self.base) >> PAGE_SHIFT) as u32;

        // Mark pages as free.
        let block_pages = 1usize << order;
        for i in 0..block_pages {
            self.bitmap.clear(pfn as usize + i);
        }
        self.free_pages += block_pages;

        // Coalesce with buddies.
        let mut current_pfn = pfn;
        let mut current_order = order;
        while current_order < MAX_ORDER {
            let buddy_pfn = current_pfn ^ (1u32 << current_order);
            // Check if buddy is entirely free.
            if (buddy_pfn as usize + (1 << current_order)) > self.total_pages {
                break;
            }
            let buddy_free = (0..(1usize << current_order))
                .all(|i| !self.bitmap.is_set(buddy_pfn as usize + i));
            if !buddy_free {
                break;
            }
            // Remove buddy from its free list.
            if !self.free_lists[current_order].remove(buddy_pfn) {
                break; // Buddy not in free list at this order.
            }
            // Merge: the combined block starts at the lower of the two.
            current_pfn = current_pfn.min(buddy_pfn);
            current_order += 1;
        }

        self.free_lists[current_order].push(current_pfn);
    }
}

// Global allocator instance using UnsafeCell for interior mutability.
use core::cell::UnsafeCell;

struct GlobalAllocator(UnsafeCell<PhysAllocator>);

// Safety: we only access the allocator from a single core during init, and later
// with interrupts disabled (or behind a spinlock when SMP is added).
unsafe impl Sync for GlobalAllocator {}

static ALLOCATOR: GlobalAllocator = GlobalAllocator(UnsafeCell::new(PhysAllocator::new()));

fn with_allocator<T>(f: impl FnOnce(&mut PhysAllocator) -> T) -> T {
    // Safety: single-threaded access during boot; will add spinlock for SMP.
    unsafe { f(&mut *ALLOCATOR.0.get()) }
}

/// Initialize the physical memory allocator.
/// Called from boot code with memory region info.
pub fn init(ram_start: usize, ram_end: usize, kernel_start: usize, kernel_end: usize) {
    with_allocator(|alloc| {
        alloc.init(PhysAddr::new(ram_start), PhysAddr::new(ram_end));
        alloc.reserve_range(PhysAddr::new(kernel_start), PhysAddr::new(kernel_end));
    });

    let (total, free) = stats();
    crate::println!(
        "  Physical memory: {} pages total, {} pages free ({} KiB / {} KiB)",
        total, free,
        free * (PAGE_SIZE / 1024),
        total * (PAGE_SIZE / 1024),
    );
}

/// Allocate a single page (order 0). Returns physical address.
pub fn alloc_page() -> Option<PhysAddr> {
    with_allocator(|alloc| alloc.alloc(0))
}

/// Allocate a block of 2^order pages. Returns physical address.
#[allow(dead_code)]
pub fn alloc_pages(order: usize) -> Option<PhysAddr> {
    with_allocator(|alloc| alloc.alloc(order))
}

/// Free a single page (order 0).
pub fn free_page(addr: PhysAddr) {
    with_allocator(|alloc| alloc.free(addr, 0))
}

/// Free a block of 2^order pages.
#[allow(dead_code)]
pub fn free_pages(addr: PhysAddr, order: usize) {
    with_allocator(|alloc| alloc.free(addr, order))
}

/// Get (total_pages, free_pages).
pub fn stats() -> (usize, usize) {
    with_allocator(|alloc| (alloc.total_pages, alloc.free_pages))
}
