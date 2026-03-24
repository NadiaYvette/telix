//! PageVec — a tiered dynamic array for physical page addresses.
//!
//! Replaces the fixed `phys_pages: [usize; 256]` (2 KiB) in MemObject with
//! a structure that uses inline storage for small objects (stacks, small ELF
//! segments) and slab-allocated buffers for larger ones.
//!
//! Tiers:
//! - Inline: capacity <= 4 entries (32 bytes, stored in-struct)
//! - Slab 64:  capacity 5..=8   (64-byte slab allocation)
//! - Slab 128: capacity 9..=16  (128-byte slab allocation)
//! - Slab 256: capacity 17..=32 (256-byte slab allocation)
//! - Slab 512: capacity 33..=64 (512-byte slab allocation)
//! - Slab 2048: capacity 65..=256 (2048-byte slab allocation)
//! - Full page: capacity > 256  (dedicated phys page, up to PAGE_SIZE/8 entries)

use super::page::{PhysAddr, PAGE_SIZE};

/// Maximum entries stored directly in the struct.
const INLINE_CAP: usize = 4;

/// A tiered dynamic array of physical page addresses.
pub struct PageVec {
    /// Physical address of heap buffer, or 0 if using inline storage.
    heap_ptr: usize,
    /// Allocated capacity in entries.
    capacity: u16,
    /// Inline storage for small objects.
    inline: [usize; INLINE_CAP],
}

impl PageVec {
    /// Create an empty PageVec with no capacity.
    pub const fn empty() -> Self {
        Self {
            heap_ptr: 0,
            capacity: 0,
            inline: [0; INLINE_CAP],
        }
    }

    /// Allocate a PageVec with the given capacity, all entries zeroed.
    /// Returns None if heap allocation fails for capacity > INLINE_CAP.
    pub fn with_capacity(cap: usize) -> Option<Self> {
        if cap <= INLINE_CAP {
            return Some(Self {
                heap_ptr: 0,
                capacity: cap as u16,
                inline: [0; INLINE_CAP],
            });
        }

        let rounded = rounded_heap_cap(cap);
        let slab_size = rounded * core::mem::size_of::<usize>();
        let pa = if slab_size <= 2048 {
            super::slab::alloc(slab_size)?
        } else {
            // Full page allocation.
            super::phys::alloc_page()?
        };

        // Zero the buffer.
        unsafe {
            core::ptr::write_bytes(pa.as_usize() as *mut u8, 0, slab_size.min(PAGE_SIZE));
        }

        Some(Self {
            heap_ptr: pa.as_usize(),
            capacity: rounded as u16,
            inline: [0; INLINE_CAP],
        })
    }

    /// Current capacity in entries.
    pub fn capacity(&self) -> usize {
        self.capacity as usize
    }

    /// Get the value at `idx`. Panics if out of bounds.
    #[inline]
    pub fn get(&self, idx: usize) -> usize {
        debug_assert!(idx < self.capacity as usize, "PageVec::get out of bounds");
        if self.heap_ptr == 0 {
            self.inline[idx]
        } else {
            unsafe { *((self.heap_ptr + idx * core::mem::size_of::<usize>()) as *const usize) }
        }
    }

    /// Set the value at `idx`. Panics if out of bounds.
    #[inline]
    pub fn set(&mut self, idx: usize, val: usize) {
        debug_assert!(idx < self.capacity as usize, "PageVec::set out of bounds");
        if self.heap_ptr == 0 {
            self.inline[idx] = val;
        } else {
            unsafe { *((self.heap_ptr + idx * core::mem::size_of::<usize>()) as *mut usize) = val; }
        }
    }

    /// Return a slice over the first `len` entries.
    pub fn as_slice(&self, len: usize) -> &[usize] {
        let actual = len.min(self.capacity as usize);
        if self.heap_ptr == 0 {
            &self.inline[..actual]
        } else {
            unsafe { core::slice::from_raw_parts(self.heap_ptr as *const usize, actual) }
        }
    }

    /// Check if any of the first `len` entries equals `val`.
    pub fn contains(&self, len: usize, val: usize) -> bool {
        self.as_slice(len).contains(&val)
    }

    /// Zero all entries up to `len`.
    pub fn clear(&mut self, len: usize) {
        let actual = len.min(self.capacity as usize);
        if self.heap_ptr == 0 {
            for i in 0..actual {
                self.inline[i] = 0;
            }
        } else {
            unsafe {
                core::ptr::write_bytes(
                    self.heap_ptr as *mut u8,
                    0,
                    actual * core::mem::size_of::<usize>(),
                );
            }
        }
    }

    /// Copy entries from `src` (first `len` entries).
    /// Both PageVecs must have capacity >= len.
    pub fn copy_from(&mut self, src: &PageVec, len: usize) {
        for i in 0..len {
            self.set(i, src.get(i));
        }
    }

    /// Clone this PageVec (allocate a new heap buffer if needed).
    /// Returns None if allocation fails.
    pub fn clone_with_len(&self, len: usize) -> Option<Self> {
        let mut new = Self::with_capacity(self.capacity as usize)?;
        new.copy_from(self, len);
        Some(new)
    }

    /// Free the heap buffer (if any). Must be called before dropping.
    /// After this call, the PageVec is empty and must not be used.
    pub fn free_heap(&mut self) {
        if self.heap_ptr != 0 {
            let slab_size = self.capacity as usize * core::mem::size_of::<usize>();
            if slab_size <= 2048 {
                super::slab::free(PhysAddr::new(self.heap_ptr), slab_size);
            } else {
                // Full page — free to phys allocator.
                let page_base = self.heap_ptr & !(PAGE_SIZE - 1);
                super::phys::free_page(PhysAddr::new(page_base));
            }
            self.heap_ptr = 0;
        }
        self.capacity = 0;
    }

    /// Grow capacity to at least `new_cap`. Preserves existing entries up to `len`.
    /// Returns true on success.
    pub fn grow(&mut self, new_cap: usize, len: usize) -> bool {
        if new_cap <= self.capacity as usize {
            return true;
        }
        let mut new = match Self::with_capacity(new_cap) {
            Some(v) => v,
            None => return false,
        };
        new.copy_from(self, len);
        self.free_heap();
        *self = new;
        true
    }
}

/// Round up to the next slab-aligned capacity.
fn rounded_heap_cap(needed: usize) -> usize {
    if needed <= 8 { 8 }
    else if needed <= 16 { 16 }
    else if needed <= 32 { 32 }
    else if needed <= 64 { 64 }
    else if needed <= 256 { 256 }
    else {
        // Round up to PAGE_SIZE / sizeof(usize) = PAGE_SIZE / 8.
        let entries_per_page = PAGE_SIZE / core::mem::size_of::<usize>();
        ((needed + entries_per_page - 1) / entries_per_page) * entries_per_page
    }
}
