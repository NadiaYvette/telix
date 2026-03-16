//! Slab allocator — fixed-size object caches backed by PAGE_SIZE pages.
//!
//! Each `SlabCache` manages objects of a single size. A page is divided into
//! a header (at the start of the page) and object slots. Free objects are
//! tracked via an embedded free list (the first `usize` of each free slot
//! stores the index of the next free slot, or `NONE`).
//!
//! This is a simple single-page-per-slab design: each page is one slab.

use super::page::{PhysAddr, PAGE_SIZE};
use super::phys;

const NONE: u16 = u16::MAX;

/// Maximum number of pages (slabs) a single cache can use.
const MAX_SLABS: usize = 64;

/// Per-page slab header, stored at the start of each slab page.
/// Must be kept small so it doesn't eat too much of the usable space.
#[repr(C)]
struct SlabHeader {
    free_head: u16,  // Index of first free object, or NONE
    in_use: u16,     // Number of allocated objects
    capacity: u16,   // Total object slots in this slab
    _pad: u16,
}

/// A cache of fixed-size objects.
pub struct SlabCache {
    obj_size: usize,        // Size of each object (rounded up to align)
    obj_align: usize,       // Alignment of each object
    slab_pages: [usize; MAX_SLABS], // Physical addresses of slab pages (0 = empty)
    slab_count: usize,      // Number of active slabs
    objs_per_slab: usize,   // Objects per slab page
    data_offset: usize,     // Byte offset from page start to first object
}

impl SlabCache {
    /// Create a new slab cache for objects of `size` bytes with `align` alignment.
    /// `align` must be a power of 2 and >= size_of::<usize>().
    pub const fn new(size: usize, align: usize) -> Self {
        let obj_align = if align < core::mem::size_of::<usize>() {
            core::mem::size_of::<usize>()
        } else {
            align
        };
        // Round object size up to alignment, minimum usize (for free list pointer).
        let min_size = core::mem::size_of::<usize>();
        let obj_size = if size < min_size {
            min_size
        } else {
            (size + obj_align - 1) & !(obj_align - 1)
        };

        // Header at start of page, then objects after alignment.
        let header_size = core::mem::size_of::<SlabHeader>();
        let data_offset = (header_size + obj_align - 1) & !(obj_align - 1);
        let usable = PAGE_SIZE - data_offset;
        let objs_per_slab = usable / obj_size;

        Self {
            obj_size,
            obj_align,
            slab_pages: [0; MAX_SLABS],
            slab_count: 0,
            objs_per_slab,
            data_offset,
        }
    }

    /// Allocate one object from this cache. Returns a physical address, or None if OOM.
    pub fn alloc(&mut self) -> Option<PhysAddr> {
        // Try existing slabs with free objects.
        for i in 0..self.slab_count {
            let page_addr = self.slab_pages[i];
            let header = unsafe { &mut *(page_addr as *mut SlabHeader) };
            if header.free_head != NONE {
                return Some(self.alloc_from_slab(page_addr, header));
            }
        }

        // All slabs full (or none exist) — allocate a new page.
        if self.slab_count >= MAX_SLABS {
            return None;
        }
        let page = phys::alloc_page()?;
        let page_addr = page.as_usize();
        self.slab_pages[self.slab_count] = page_addr;
        self.slab_count += 1;

        // Initialize the slab.
        self.init_slab(page_addr);

        let header = unsafe { &mut *(page_addr as *mut SlabHeader) };
        Some(self.alloc_from_slab(page_addr, header))
    }

    /// Free an object back to this cache.
    pub fn free(&mut self, addr: PhysAddr) {
        let addr_val = addr.as_usize();
        // Find which slab this object belongs to.
        let page_base = addr_val & !(PAGE_SIZE - 1);

        for i in 0..self.slab_count {
            if self.slab_pages[i] == page_base {
                let header = unsafe { &mut *(page_base as *mut SlabHeader) };
                let obj_index = (addr_val - page_base - self.data_offset) / self.obj_size;

                // Push onto free list.
                let obj_ptr = (page_base + self.data_offset + obj_index * self.obj_size) as *mut u16;
                unsafe { *obj_ptr = header.free_head };
                header.free_head = obj_index as u16;
                header.in_use -= 1;

                // If slab is completely empty, optionally return page to buddy allocator.
                if header.in_use == 0 && self.slab_count > 1 {
                    phys::free_page(PhysAddr::new(page_base));
                    // Remove from slab list by swapping with last.
                    self.slab_count -= 1;
                    self.slab_pages[i] = self.slab_pages[self.slab_count];
                    self.slab_pages[self.slab_count] = 0;
                }
                return;
            }
        }
    }

    /// Initialize a freshly allocated slab page.
    fn init_slab(&self, page_addr: usize) {
        // Zero the header.
        let header = unsafe { &mut *(page_addr as *mut SlabHeader) };
        header.in_use = 0;
        header.capacity = self.objs_per_slab as u16;

        // Build free list: each free slot points to the next.
        let base = page_addr + self.data_offset;
        for i in 0..self.objs_per_slab {
            let slot = (base + i * self.obj_size) as *mut u16;
            let next = if i + 1 < self.objs_per_slab {
                (i + 1) as u16
            } else {
                NONE
            };
            unsafe { *slot = next };
        }
        header.free_head = 0;
    }

    /// Allocate from a slab with known free objects.
    fn alloc_from_slab(&self, page_addr: usize, header: &mut SlabHeader) -> PhysAddr {
        let index = header.free_head as usize;
        let obj_addr = page_addr + self.data_offset + index * self.obj_size;

        // Advance free list.
        let next = unsafe { *(obj_addr as *const u16) };
        header.free_head = next;
        header.in_use += 1;

        PhysAddr::new(obj_addr)
    }

    /// Number of objects currently allocated across all slabs.
    #[allow(dead_code)]
    pub fn allocated(&self) -> usize {
        let mut total = 0;
        for i in 0..self.slab_count {
            let header = unsafe { &*(self.slab_pages[i] as *const SlabHeader) };
            total += header.in_use as usize;
        }
        total
    }
}

// --- Global slab caches for common kernel object sizes ---

use crate::sync::SpinLock;

static CACHE_64: SpinLock<SlabCache> = SpinLock::new(SlabCache::new(64, 64));
static CACHE_128: SpinLock<SlabCache> = SpinLock::new(SlabCache::new(128, 64));
static CACHE_256: SpinLock<SlabCache> = SpinLock::new(SlabCache::new(256, 64));
static CACHE_512: SpinLock<SlabCache> = SpinLock::new(SlabCache::new(512, 64));

fn cache_for_size(size: usize) -> Option<&'static SpinLock<SlabCache>> {
    if size <= 64 {
        Some(&CACHE_64)
    } else if size <= 128 {
        Some(&CACHE_128)
    } else if size <= 256 {
        Some(&CACHE_256)
    } else if size <= 512 {
        Some(&CACHE_512)
    } else {
        None
    }
}

/// Allocate an object of `size` bytes from the appropriate slab cache.
pub fn alloc(size: usize) -> Option<PhysAddr> {
    let cache = cache_for_size(size)?;
    cache.lock().alloc()
}

/// Free an object of `size` bytes back to the appropriate slab cache.
pub fn free(addr: PhysAddr, size: usize) {
    if let Some(cache) = cache_for_size(size) {
        cache.lock().free(addr);
    }
}

/// Print slab allocator statistics.
pub fn print_stats() {
    let sizes = [64, 128, 256, 512];
    let caches: [&SpinLock<SlabCache>; 4] = [&CACHE_64, &CACHE_128, &CACHE_256, &CACHE_512];

    crate::println!("  Slab allocator caches:");
    for (size, cache) in sizes.iter().zip(caches.iter()) {
        let c = cache.lock();
        crate::println!(
            "    {}-byte: {} slabs, {} objects/slab",
            size, c.slab_count, c.objs_per_slab,
        );
    }
}
