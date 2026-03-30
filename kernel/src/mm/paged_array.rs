//! PagedArray<T>: a growable, page-backed array with O(1) indexed access.
//!
//! Storage is allocated one physical page at a time via `phys::alloc_page()`.
//! The page directory is itself page-allocated on first use, giving
//! PAGE_SIZE / size_of::<*mut T>() directory slots — no fixed capacity constant.
//!
//! Items are zero-initialized when pages are allocated. Items are never
//! moved once placed — growing adds new pages without disturbing existing ones.

use super::page::{self, MAX_PAGE_SIZE};
use super::phys;

/// A growable array backed by physical pages.
///
/// Capacity = dir_capacity × ITEMS_PER_PAGE.
/// At 64 KiB pages and 8-byte pointers the directory holds 8192 entries,
/// giving 8192 × (PAGE_SIZE / size_of::<T>()) maximum items.
pub struct PagedArray<T> {
    /// Page directory: page-allocated on first use. Each non-null entry
    /// points to a page of T items.
    dir: *mut *mut T,
    /// Number of directory slots available (0 until first ensure_capacity).
    dir_capacity: usize,
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
    /// Items per page (runtime, based on boot-configured page size).
    #[inline]
    pub fn items_per_page() -> usize {
        page::page_size() / core::mem::size_of::<T>()
    }

    /// Directory slots per directory page (runtime).
    #[inline]
    fn dir_slots() -> usize {
        page::page_size() / core::mem::size_of::<*mut T>()
    }

    /// Create an empty PagedArray. No pages are allocated until first use.
    pub const fn new() -> Self {
        Self {
            dir: core::ptr::null_mut(),
            dir_capacity: 0,
            num_pages: 0,
            _marker: core::marker::PhantomData,
        }
    }

    /// Current capacity (items addressable without growing).
    #[inline]
    pub fn capacity(&self) -> usize {
        self.num_pages * Self::items_per_page()
    }

    /// Ensure capacity for at least `needed` items. Allocates pages as needed.
    /// Returns false on OOM or directory full.
    pub fn ensure_capacity(&mut self, needed: usize) -> bool {
        // Allocate directory page on first use.
        if self.dir.is_null() && needed > 0 {
            let page = match phys::alloc_page() {
                Some(pa) => pa.as_usize() as *mut *mut T,
                None => return false,
            };
            unsafe {
                core::ptr::write_bytes(page as *mut u8, 0, page::page_size());
            }
            self.dir = page;
            self.dir_capacity = Self::dir_slots();
        }

        while self.capacity() < needed {
            if self.num_pages >= self.dir_capacity {
                return false;
            }
            let page = match phys::alloc_page() {
                Some(pa) => pa.as_usize() as *mut T,
                None => return false,
            };
            // Zero-initialize the new page.
            unsafe {
                core::ptr::write_bytes(page as *mut u8, 0, page::page_size());
                *self.dir.add(self.num_pages) = page;
            }
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
        let ipp = Self::items_per_page();
        let page = idx / ipp;
        let offset = idx % ipp;
        unsafe { &*(*self.dir.add(page)).add(offset) }
    }

    /// Get a mutable reference to item at `idx`.
    ///
    /// # Safety contract
    /// Caller must ensure `idx < capacity()`.
    #[inline]
    pub fn get_mut(&mut self, idx: usize) -> &mut T {
        let ipp = Self::items_per_page();
        let page = idx / ipp;
        let offset = idx % ipp;
        unsafe { &mut *(*self.dir.add(page)).add(offset) }
    }
}
