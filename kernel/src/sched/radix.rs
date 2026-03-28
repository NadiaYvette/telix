//! Two-level radix page table for lockless entity pointer lookup.
//!
//! L0: one allocation page of atomic pointers to L1 pages.
//! L1: allocation pages of atomic pointers to entities (Task*/Thread*),
//!     allocated on demand.
//!
//! Entries per page = PAGE_SIZE / 8 (RADIX_FANOUT).
//! Two-level capacity = RADIX_FANOUT² (67M at 64K pages, 4M at 16K).
//!
//! Lookup is 2 atomic loads (L0 → L1 → entity), both from pages that
//! are cache-hot on active CPUs. Growth is append-only: L1 pages are
//! allocated under the caller's serializing lock and never freed.

use crate::mm::page::PAGE_SIZE;
use crate::mm::phys;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

/// Number of pointer entries per allocation page.
pub const RADIX_FANOUT: usize = PAGE_SIZE / core::mem::size_of::<usize>();

/// Two-level radix page table. Type-erased (stores `*mut u8`).
/// Callers cast to/from the concrete entity type.
pub struct RadixTable {
    /// Pointer to the L0 page: an array of RADIX_FANOUT AtomicPtr<u8>,
    /// where each entry points to an L1 page (or is null).
    l0: AtomicPtr<AtomicPtr<u8>>,
}

impl RadixTable {
    /// Create an uninitialized table. Call `init()` before first use.
    pub const fn new() -> Self {
        Self {
            l0: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// Allocate the L0 page. Must be called once during kernel init,
    /// before any concurrent access.
    pub fn init(&self) {
        let pa = phys::alloc_page().expect("radix L0 alloc");
        let p = pa.as_usize() as *mut u8;
        unsafe {
            ptr::write_bytes(p, 0, PAGE_SIZE);
        }
        self.l0.store(p as *mut AtomicPtr<u8>, Ordering::Release);
    }

    /// Look up entry by ID. Returns raw entity pointer (null if unset).
    /// Lockless — uses Acquire ordering on both levels.
    #[inline]
    pub fn get(&self, id: u32) -> *mut u8 {
        let l0 = self.l0.load(Ordering::Acquire);
        if l0.is_null() {
            return ptr::null_mut();
        }

        let l0_idx = (id as usize) / RADIX_FANOUT;
        let l1_idx = (id as usize) % RADIX_FANOUT;

        if l0_idx >= RADIX_FANOUT {
            return ptr::null_mut();
        }

        // Load L1 page pointer from L0.
        let l1_page = unsafe { &*l0.add(l0_idx) }.load(Ordering::Acquire);
        if l1_page.is_null() {
            return ptr::null_mut();
        }

        // Load entity pointer from L1.
        let l1 = l1_page as *const AtomicPtr<u8>;
        unsafe { &*l1.add(l1_idx) }.load(Ordering::Acquire)
    }

    /// Store an entity pointer by ID. Caller must have called `ensure_l1(id)`
    /// first (under a serializing lock). Uses Release ordering.
    #[inline]
    pub fn set(&self, id: u32, val: *mut u8) {
        let l0 = self.l0.load(Ordering::Relaxed);
        let l0_idx = (id as usize) / RADIX_FANOUT;
        let l1_idx = (id as usize) % RADIX_FANOUT;

        let l1_page = unsafe { &*l0.add(l0_idx) }.load(Ordering::Relaxed);
        let l1 = l1_page as *const AtomicPtr<u8>;
        unsafe { &*l1.add(l1_idx) }.store(val, Ordering::Release);
    }

    /// Ensure the L1 page covering `id` exists. Allocates if needed.
    /// Call under a lock that serializes entity ID allocation.
    /// Returns false if allocation fails or ID is out of range.
    pub fn ensure_l1(&self, id: u32) -> bool {
        let l0 = self.l0.load(Ordering::Relaxed);
        if l0.is_null() {
            return false;
        }

        let l0_idx = (id as usize) / RADIX_FANOUT;
        if l0_idx >= RADIX_FANOUT {
            return false;
        }

        let entry = unsafe { &*l0.add(l0_idx) };
        if !entry.load(Ordering::Relaxed).is_null() {
            return true; // L1 page already exists.
        }

        // Allocate and zero a new L1 page.
        let pa = match phys::alloc_page() {
            Some(p) => p,
            None => return false,
        };
        let p = pa.as_usize() as *mut u8;
        unsafe {
            ptr::write_bytes(p, 0, PAGE_SIZE);
        }
        entry.store(p, Ordering::Release);
        true
    }

    /// Maximum entity ID supported by this two-level table.
    #[inline]
    pub const fn capacity() -> usize {
        RADIX_FANOUT * RADIX_FANOUT
    }
}

// Safety: All access is through atomic operations.
unsafe impl Send for RadixTable {}
unsafe impl Sync for RadixTable {}
