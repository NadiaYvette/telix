//! Shared page table tracking — per-ForkGroup hash tables.
//!
//! When page table nodes are shared between address spaces (via COW fork),
//! refcounts are tracked per-ForkGroup (not globally). Each ForkGroup owns
//! a slab-allocated PtShareTable mapping PT page PA → refcount.
//!
//! ForkGroup is reference-counted: created at first fork, shared by all
//! members of the fork family, freed when the last member exits.

use crate::sync::SpinLock;
use super::page::{PAGE_SIZE, PhysAddr};
use super::stats;
use core::sync::atomic::{AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// Bucket layout
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct Bucket {
    /// Physical address of the shared PT page (0 = empty slot).
    pt_pa: usize,
    /// Reference count (number of address spaces referencing this PT page).
    refcount: u16,
    _pad: [u8; 6],
}

const BUCKET_SIZE: usize = core::mem::size_of::<Bucket>(); // 16 bytes
const BUCKETS_PER_PAGE: usize = PAGE_SIZE / BUCKET_SIZE;

impl Bucket {
    const fn empty() -> Self {
        Self {
            pt_pa: 0,
            refcount: 0,
            _pad: [0; 6],
        }
    }

    fn is_empty(&self) -> bool {
        self.pt_pa == 0
    }
}

// ---------------------------------------------------------------------------
// Hash table
// ---------------------------------------------------------------------------

/// Open-addressing hash table mapping PT page PA → refcount.
pub struct PtShareTable {
    buckets: *mut Bucket,
    capacity: usize,
    count: usize,
}

// Safety: buckets pointer is only accessed under the owning ForkGroup's lock.
unsafe impl Send for PtShareTable {}

impl PtShareTable {
    pub const fn new() -> Self {
        Self {
            buckets: core::ptr::null_mut(),
            capacity: 0,
            count: 0,
        }
    }

    /// Ensure the table has been allocated. Returns false on OOM.
    fn ensure_allocated(&mut self) -> bool {
        if !self.buckets.is_null() {
            return true;
        }
        let page = match super::phys::alloc_page() {
            Some(p) => p,
            None => return false,
        };
        unsafe {
            core::ptr::write_bytes(page.as_usize() as *mut u8, 0, PAGE_SIZE);
        }
        self.buckets = page.as_usize() as *mut Bucket;
        self.capacity = BUCKETS_PER_PAGE;
        true
    }

    /// Hash a physical address to a bucket index.
    #[inline]
    fn hash(pa: usize, cap: usize) -> usize {
        // PT page PAs are PAGE_SIZE-aligned. Shift down and mix.
        let key = pa >> 12;
        // Fibonacci hashing.
        let h = key.wrapping_mul(0x9E3779B97F4A7C15);
        h & (cap - 1)
    }

    /// Find the bucket for `pa`, or the first empty bucket in the probe chain.
    fn find_or_empty(&self, pa: usize) -> usize {
        let mut idx = Self::hash(pa, self.capacity);
        loop {
            let b = unsafe { &*self.buckets.add(idx) };
            if b.is_empty() || b.pt_pa == pa {
                return idx;
            }
            idx = (idx + 1) & (self.capacity - 1);
        }
    }

    /// Find the bucket for `pa`, or None if not present.
    fn find(&self, pa: usize) -> Option<usize> {
        if self.buckets.is_null() || self.count == 0 {
            return None;
        }
        let mut idx = Self::hash(pa, self.capacity);
        loop {
            let b = unsafe { &*self.buckets.add(idx) };
            if b.is_empty() {
                return None;
            }
            if b.pt_pa == pa {
                return Some(idx);
            }
            idx = (idx + 1) & (self.capacity - 1);
        }
    }

    /// Grow the table by doubling capacity and rehashing.
    fn grow(&mut self) -> bool {
        let new_cap = if self.capacity == 0 {
            BUCKETS_PER_PAGE
        } else {
            self.capacity * 2
        };
        let new_pages = (new_cap * BUCKET_SIZE + PAGE_SIZE - 1) / PAGE_SIZE;

        // Allocate new backing pages.
        let first_page = match super::phys::alloc_page() {
            Some(p) => p.as_usize(),
            None => return false,
        };
        unsafe {
            core::ptr::write_bytes(first_page as *mut u8, 0, PAGE_SIZE);
        }

        // For multi-page tables, allocate contiguous pages.
        if new_pages > 1 {
            // Use alloc_pages for contiguous allocation.
            let order = {
                let mut o = 0;
                let mut n = new_pages;
                while n > 1 {
                    n >>= 1;
                    o += 1;
                }
                o
            };
            // Free the single page we just allocated and get a contiguous block.
            super::phys::free_page(PhysAddr::new(first_page));
            let block = match super::phys::alloc_pages(order) {
                Some(p) => p.as_usize(),
                None => return false,
            };
            unsafe {
                core::ptr::write_bytes(block as *mut u8, 0, new_pages * PAGE_SIZE);
            }
            let new_buckets = block as *mut Bucket;
            self.rehash_into(new_buckets, new_cap);
            return true;
        }

        let new_buckets = first_page as *mut Bucket;
        self.rehash_into(new_buckets, new_cap);
        true
    }

    /// Rehash all entries into a new bucket array, then swap.
    fn rehash_into(&mut self, new_buckets: *mut Bucket, new_cap: usize) {
        let old_buckets = self.buckets;
        let old_cap = self.capacity;

        for i in 0..old_cap {
            let b = unsafe { &*old_buckets.add(i) };
            if !b.is_empty() {
                let mut idx = Self::hash(b.pt_pa, new_cap);
                loop {
                    let nb = unsafe { &mut *new_buckets.add(idx) };
                    if nb.is_empty() {
                        *nb = *b;
                        break;
                    }
                    idx = (idx + 1) & (new_cap - 1);
                }
            }
        }

        // Free old backing.
        if !old_buckets.is_null() {
            let old_pages = (old_cap * BUCKET_SIZE + PAGE_SIZE - 1) / PAGE_SIZE;
            if old_pages == 1 {
                super::phys::free_page(PhysAddr::new(old_buckets as usize));
            } else {
                let order = {
                    let mut o = 0;
                    let mut n = old_pages;
                    while n > 1 {
                        n >>= 1;
                        o += 1;
                    }
                    o
                };
                super::phys::free_pages(PhysAddr::new(old_buckets as usize), order);
            }
        }

        self.buckets = new_buckets;
        self.capacity = new_cap;
    }

    /// Insert or increment refcount for a PT page.
    /// If the page has no entry, creates one with refcount = 2.
    /// If it already has an entry, increments refcount.
    pub fn share(&mut self, pa: usize) -> u16 {
        if !self.ensure_allocated() {
            return 0; // OOM
        }

        // Check load factor before insert.
        if self.count * 4 >= self.capacity * 3 {
            if !self.grow() {
                return 0; // OOM
            }
        }

        let idx = self.find_or_empty(pa);
        let b = unsafe { &mut *self.buckets.add(idx) };
        if b.is_empty() {
            b.pt_pa = pa;
            b.refcount = 2;
            self.count += 1;
            2
        } else {
            b.refcount += 1;
            b.refcount
        }
    }

    /// Decrement refcount. Returns new refcount.
    /// Removes the entry when refcount drops to 1 (no longer shared).
    pub fn unshare(&mut self, pa: usize) -> u16 {
        let idx = match self.find(pa) {
            Some(i) => i,
            None => return 0, // not tracked
        };
        let b = unsafe { &mut *self.buckets.add(idx) };
        if b.refcount <= 1 {
            // Remove entry.
            self.remove_at(idx);
            return 0;
        }
        b.refcount -= 1;
        if b.refcount <= 1 {
            let rc = b.refcount;
            self.remove_at(idx);
            rc
        } else {
            b.refcount
        }
    }

    /// Remove entry at `idx` and fixup the probe chain.
    fn remove_at(&mut self, idx: usize) {
        unsafe {
            *self.buckets.add(idx) = Bucket::empty();
        }
        self.count -= 1;

        // Rehash entries in the same probe chain that may have been
        // displaced past the removed slot.
        let mut i = (idx + 1) & (self.capacity - 1);
        loop {
            let b = unsafe { &*self.buckets.add(i) };
            if b.is_empty() {
                break;
            }
            let entry = *b;
            unsafe {
                *self.buckets.add(i) = Bucket::empty();
            }
            self.count -= 1;
            // Re-insert.
            let new_idx = self.find_or_empty(entry.pt_pa);
            unsafe {
                *self.buckets.add(new_idx) = entry;
            }
            self.count += 1;
            i = (i + 1) & (self.capacity - 1);
        }
    }

    /// Check if a PT page is shared (refcount > 1).
    #[allow(dead_code)]
    pub fn is_shared(&self, pa: usize) -> bool {
        match self.find(pa) {
            Some(idx) => unsafe { (*self.buckets.add(idx)).refcount > 1 },
            None => false,
        }
    }

    /// Free the hash table's backing pages.
    fn drop_backing(&mut self) {
        if self.buckets.is_null() {
            return;
        }
        let pages = (self.capacity * BUCKET_SIZE + PAGE_SIZE - 1) / PAGE_SIZE;
        if pages == 1 {
            super::phys::free_page(PhysAddr::new(self.buckets as usize));
        } else {
            let order = {
                let mut o = 0;
                let mut n = pages;
                while n > 1 {
                    n >>= 1;
                    o += 1;
                }
                o
            };
            super::phys::free_pages(PhysAddr::new(self.buckets as usize), order);
        }
        self.buckets = core::ptr::null_mut();
        self.capacity = 0;
        self.count = 0;
    }
}

// ---------------------------------------------------------------------------
// ForkGroup — per-fork-family PT sharing scope
// ---------------------------------------------------------------------------

/// Slab size for ForkGroup allocations (fits SpinLock<PtShareTable> + refcount).
const FORK_GROUP_SLAB_SIZE: usize = 64;

/// A fork group tracks shared page table nodes among a family of address spaces
/// created by fork(). Each member references the same ForkGroup. The hash table
/// inside tracks PA → refcount for shared PT pages.
///
/// Slab-allocated, reference-counted. Created on first fork, freed when the
/// last member exits.
#[repr(C)]
pub struct ForkGroup {
    table: SpinLock<PtShareTable>,
    refcount: AtomicU32,
}

// Safety: ForkGroup is accessed via raw pointer, protected by its internal lock.
unsafe impl Send for ForkGroup {}
unsafe impl Sync for ForkGroup {}

impl ForkGroup {
    /// Allocate a new ForkGroup with refcount = 1.
    pub fn create() -> *mut ForkGroup {
        let pa = match super::slab::alloc(FORK_GROUP_SLAB_SIZE) {
            Some(p) => p,
            None => return core::ptr::null_mut(),
        };
        let ptr = pa.as_usize() as *mut ForkGroup;
        unsafe {
            core::ptr::write(
                ptr,
                ForkGroup {
                    table: SpinLock::new(PtShareTable::new()),
                    refcount: AtomicU32::new(1),
                },
            );
        }
        ptr
    }

    /// Increment the reference count (new fork member joins).
    #[inline]
    pub fn acquire(fg: *mut ForkGroup) {
        debug_assert!(!fg.is_null());
        unsafe {
            (*fg).refcount.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Decrement the reference count. Frees backing when it reaches 0.
    pub fn release(fg: *mut ForkGroup) {
        if fg.is_null() {
            return;
        }
        let old = unsafe { (*fg).refcount.fetch_sub(1, Ordering::Release) };
        if old == 1 {
            // Last reference — free hash table backing and slab entry.
            core::sync::atomic::fence(Ordering::Acquire);
            unsafe {
                (*fg).table.lock().drop_backing();
            }
            super::slab::free(PhysAddr::new(fg as usize), FORK_GROUP_SLAB_SIZE);
        }
    }

    /// Mark a PT page as shared within this fork group.
    /// Sets refcount to 2 on first share, increments after.
    #[inline]
    pub fn share(fg: *mut ForkGroup, pa: usize) -> u16 {
        debug_assert!(!fg.is_null());
        let rc = unsafe { (*fg).table.lock().share(pa) };
        if rc == 2 {
            stats::PT_TABLES_SHARED.fetch_add(1, Ordering::Relaxed);
        }
        rc
    }

    /// Decrement a shared PT page's refcount within this fork group.
    /// Entry is removed when refcount drops to 1 (exclusively owned).
    /// Returns 0 if the page was not tracked.
    #[inline]
    pub fn unshare(fg: *mut ForkGroup, pa: usize) -> u16 {
        debug_assert!(!fg.is_null());
        unsafe { (*fg).table.lock().unshare(pa) }
    }
}
