//! PagedArray<T>: a growable, page-backed array with O(1) indexed access.
//!
//! Storage is allocated one physical page at a time via `phys::alloc_page()`.
//! The page directory is inline in the struct (512 bytes on 64-bit), so
//! no heap allocation is needed for the directory itself.
//!
//! Items are zero-initialized when pages are allocated. Items are never
//! moved once placed — growing adds new pages without disturbing existing ones.

use super::page::PAGE_SIZE;
use super::phys;

/// Maximum number of backing pages in the directory.
const DIR_CAPACITY: usize = 64;

/// A growable array backed by physical pages.
///
/// Capacity = DIR_CAPACITY × (PAGE_SIZE / size_of::<T>()).
/// At 64 KiB pages and 32-byte items: 64 × 2048 = 131 072 items.
pub struct PagedArray<T> {
    /// Page directory: each non-null entry points to a page of T items.
    dir: [*mut T; DIR_CAPACITY],
    /// Number of pages currently allocated.
    num_pages: usize,
    _marker: core::marker::PhantomData<T>,
}

// Safety: page pointers are plain physical addresses. Items are accessed
// under caller-provided synchronization (locks or single-threaded init).
unsafe impl<T: Send> Send for PagedArray<T> {}
unsafe impl<T: Send> Sync for PagedArray<T> {}

impl<T> PagedArray<T> {
    /// Items that fit in a single page.
    pub const ITEMS_PER_PAGE: usize = PAGE_SIZE / core::mem::size_of::<T>();

    /// Create an empty PagedArray. No pages are allocated until first use.
    pub const fn new() -> Self {
        Self {
            dir: [core::ptr::null_mut(); DIR_CAPACITY],
            num_pages: 0,
            _marker: core::marker::PhantomData,
        }
    }

    /// Current capacity (items addressable without growing).
    #[inline]
    pub fn capacity(&self) -> usize {
        self.num_pages * Self::ITEMS_PER_PAGE
    }

    /// Ensure capacity for at least `needed` items. Allocates pages as needed.
    /// Returns false on OOM or directory full.
    pub fn ensure_capacity(&mut self, needed: usize) -> bool {
        while self.capacity() < needed {
            if self.num_pages >= DIR_CAPACITY {
                return false;
            }
            let page = match phys::alloc_page() {
                Some(pa) => pa.as_usize() as *mut T,
                None => return false,
            };
            // Zero-initialize the new page.
            unsafe {
                core::ptr::write_bytes(page as *mut u8, 0, PAGE_SIZE);
            }
            self.dir[self.num_pages] = page;
            self.num_pages += 1;
        }
        true
    }

    /// Get a reference to item at `idx`.
    ///
    /// # Safety contract
    /// Caller must ensure `idx < capacity()`.
    #[inline]
    pub fn get(&self, idx: usize) -> &T {
        let page = idx / Self::ITEMS_PER_PAGE;
        let offset = idx % Self::ITEMS_PER_PAGE;
        unsafe { &*self.dir[page].add(offset) }
    }

    /// Get a mutable reference to item at `idx`.
    ///
    /// # Safety contract
    /// Caller must ensure `idx < capacity()`.
    #[inline]
    pub fn get_mut(&mut self, idx: usize) -> &mut T {
        let page = idx / Self::ITEMS_PER_PAGE;
        let offset = idx % Self::ITEMS_PER_PAGE;
        unsafe { &mut *self.dir[page].add(offset) }
    }
}
