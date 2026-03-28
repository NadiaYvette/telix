//! Slab allocator — fixed-size object caches backed by PAGE_SIZE pages.
//!
//! Each `SlabCache` manages objects of a single size. A page is divided into
//! a header (at the start of the page) and object slots. Free objects are
//! tracked via an embedded free list (the first `usize` of each free slot
//! stores the index of the next free slot, or `NONE`).
//!
//! This is a simple single-page-per-slab design: each page is one slab.
//! The slab page directory is itself page-allocated on first use, giving
//! PAGE_SIZE / size_of::<usize>() directory slots — no fixed capacity constant.
//!
//! A per-CPU magazine layer sits above the global caches to reduce lock
//! contention. Each CPU has a pair of magazines (loaded + backup) per size
//! class. The fast path (alloc/free) operates with IRQs disabled and no
//! lock. The global lock is only touched every ~MAG_CAPACITY operations.

use super::page::{PAGE_SIZE, PhysAddr};
use super::phys;

const NONE: u16 = u16::MAX;

/// Per-page slab header, stored at the start of each slab page.
/// Must be kept small so it doesn't eat too much of the usable space.
#[repr(C)]
struct SlabHeader {
    free_head: u16, // Index of first free object, or NONE
    in_use: u16,    // Number of allocated objects
    capacity: u16,  // Total object slots in this slab
    _pad: u16,
}

/// A cache of fixed-size objects.
pub struct SlabCache {
    obj_size: usize, // Size of each object (rounded up to align)
    #[allow(dead_code)]
    obj_align: usize, // Alignment of each object
    slab_dir: *mut usize, // Page-allocated directory of slab page addresses (0 = empty slot)
    slab_dir_cap: usize, // Number of directory slots available
    slab_count: usize, // Number of active slabs
    objs_per_slab: usize, // Objects per slab page
    data_offset: usize, // Byte offset from page start to first object
}

// Safety: slab_dir is a physical address pointer, accessed under SpinLock.
unsafe impl Send for SlabCache {}

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
            slab_dir: core::ptr::null_mut(),
            slab_dir_cap: 0,
            slab_count: 0,
            objs_per_slab,
            data_offset,
        }
    }

    /// Ensure the slab directory page is allocated. Returns false on OOM.
    fn ensure_dir(&mut self) -> bool {
        if self.slab_dir.is_null() {
            let page = match phys::alloc_page() {
                Some(pa) => pa.as_usize() as *mut usize,
                None => return false,
            };
            unsafe {
                core::ptr::write_bytes(page as *mut u8, 0, PAGE_SIZE);
            }
            self.slab_dir = page;
            self.slab_dir_cap = PAGE_SIZE / core::mem::size_of::<usize>();
        }
        true
    }

    /// Read the slab page address at directory index `idx`.
    #[inline]
    fn slab_page(&self, idx: usize) -> usize {
        unsafe { *self.slab_dir.add(idx) }
    }

    /// Write a slab page address at directory index `idx`.
    #[inline]
    fn set_slab_page(&mut self, idx: usize, addr: usize) {
        unsafe {
            *self.slab_dir.add(idx) = addr;
        }
    }

    /// Allocate one object from this cache. Returns a physical address, or None if OOM.
    pub fn alloc(&mut self) -> Option<PhysAddr> {
        if !self.ensure_dir() {
            return None;
        }

        // Try existing slabs with free objects.
        for i in 0..self.slab_count {
            let page_addr = self.slab_page(i);
            let header = unsafe { &mut *(page_addr as *mut SlabHeader) };
            if header.free_head != NONE {
                return Some(self.alloc_from_slab(page_addr, header));
            }
        }

        // All slabs full (or none exist) — allocate a new page.
        if self.slab_count >= self.slab_dir_cap {
            return None;
        }
        let page = phys::alloc_page()?;
        let page_addr = page.as_usize();
        self.set_slab_page(self.slab_count, page_addr);
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
            if self.slab_page(i) == page_base {
                let header = unsafe { &mut *(page_base as *mut SlabHeader) };
                let obj_index = (addr_val - page_base - self.data_offset) / self.obj_size;

                // Push onto free list.
                let obj_ptr =
                    (page_base + self.data_offset + obj_index * self.obj_size) as *mut u16;
                unsafe { *obj_ptr = header.free_head };
                header.free_head = obj_index as u16;
                header.in_use -= 1;

                // If slab is completely empty, optionally return page to buddy allocator.
                if header.in_use == 0 && self.slab_count > 1 {
                    phys::free_page(PhysAddr::new(page_base));
                    // Remove from slab list by swapping with last.
                    self.slab_count -= 1;
                    let last = self.slab_page(self.slab_count);
                    self.set_slab_page(i, last);
                    self.set_slab_page(self.slab_count, 0);
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
            let header = unsafe { &*(self.slab_page(i) as *const SlabHeader) };
            total += header.in_use as usize;
        }
        total
    }
}

// --- Per-CPU magazine layer ---

use crate::sched::smp::MAX_CPUS;

/// Magazine capacity. Reduced for very high CPU counts to limit .bss usage.
#[cfg(any(feature = "max_cpus_1024", feature = "max_cpus_4096"))]
const MAG_CAPACITY: usize = 16;
#[cfg(not(any(feature = "max_cpus_1024", feature = "max_cpus_4096")))]
const MAG_CAPACITY: usize = 32;

const NUM_CACHES: usize = 5;

/// A fixed-size stack of object physical addresses.
#[repr(C)]
struct Magazine {
    count: u16,
    objs: [usize; MAG_CAPACITY],
}

impl Magazine {
    const fn empty() -> Self {
        Self {
            count: 0,
            objs: [0; MAG_CAPACITY],
        }
    }

    #[inline]
    fn push(&mut self, addr: usize) {
        self.objs[self.count as usize] = addr;
        self.count += 1;
    }

    #[inline]
    fn pop(&mut self) -> usize {
        self.count -= 1;
        self.objs[self.count as usize]
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[inline]
    fn is_full(&self) -> bool {
        self.count as usize >= MAG_CAPACITY
    }
}

/// A pair of magazines: loaded (primary) and backup (secondary).
#[repr(C)]
struct MagazinePair {
    loaded: Magazine,
    backup: Magazine,
}

impl MagazinePair {
    const fn empty() -> Self {
        Self {
            loaded: Magazine::empty(),
            backup: Magazine::empty(),
        }
    }
}

/// Per-CPU, per-cache magazine pairs.
/// Indexed as CPU_MAGAZINES[cpu][cache_index].
/// Safety: accessed only with IRQs disabled from the owning CPU.
static mut CPU_MAGAZINES: [[MagazinePair; NUM_CACHES]; MAX_CPUS] = {
    const PAIR: MagazinePair = MagazinePair::empty();
    const ROW: [MagazinePair; NUM_CACHES] = [PAIR; NUM_CACHES];
    [ROW; MAX_CPUS]
};

// --- Global slab caches for common kernel object sizes ---

use crate::sync::SpinLock;

static CACHE_64: SpinLock<SlabCache> = SpinLock::new(SlabCache::new(64, 64));
static CACHE_128: SpinLock<SlabCache> = SpinLock::new(SlabCache::new(128, 64));
static CACHE_256: SpinLock<SlabCache> = SpinLock::new(SlabCache::new(256, 64));
static CACHE_512: SpinLock<SlabCache> = SpinLock::new(SlabCache::new(512, 64));
static CACHE_2048: SpinLock<SlabCache> = SpinLock::new(SlabCache::new(2048, 64));

/// Map size → cache index (0..4).
#[inline]
fn cache_index(size: usize) -> Option<usize> {
    if size <= 64 {
        Some(0)
    } else if size <= 128 {
        Some(1)
    } else if size <= 256 {
        Some(2)
    } else if size <= 512 {
        Some(3)
    } else if size <= 2048 {
        Some(4)
    } else {
        None
    }
}

/// Map cache index → global SpinLock<SlabCache>.
#[inline]
fn cache_by_index(idx: usize) -> &'static SpinLock<SlabCache> {
    match idx {
        0 => &CACHE_64,
        1 => &CACHE_128,
        2 => &CACHE_256,
        3 => &CACHE_512,
        4 => &CACHE_2048,
        _ => unreachable!(),
    }
}

fn cache_for_size(size: usize) -> Option<&'static SpinLock<SlabCache>> {
    cache_index(size).map(cache_by_index)
}

/// Allocate an object of `size` bytes from the appropriate slab cache.
/// Uses per-CPU magazine fast path when possible.
pub fn alloc(size: usize) -> Option<PhysAddr> {
    let idx = match cache_index(size) {
        Some(i) => i,
        None => return None,
    };

    // Disable IRQs for per-CPU magazine access.
    let saved = crate::sync::spinlock::arch_disable_irqs();
    let cpu = crate::sched::smp::cpu_id() as usize;

    let mag = unsafe { &mut CPU_MAGAZINES[cpu][idx] };

    // Fast path 1: pop from loaded magazine.
    if !mag.loaded.is_empty() {
        let addr = mag.loaded.pop();
        crate::sync::spinlock::arch_restore_irqs(saved);
        return Some(PhysAddr::new(addr));
    }

    // Fast path 2: swap loaded ↔ backup, then pop.
    if !mag.backup.is_empty() {
        core::mem::swap(&mut mag.loaded, &mut mag.backup);
        let addr = mag.loaded.pop();
        crate::sync::spinlock::arch_restore_irqs(saved);
        return Some(PhysAddr::new(addr));
    }

    // Slow path: refill loaded magazine from global cache under lock.
    crate::sync::spinlock::arch_restore_irqs(saved);

    let cache = cache_by_index(idx);
    let mut guard = cache.lock();
    // Batch-allocate up to MAG_CAPACITY objects.
    // Re-read cpu_id: we may have migrated while IRQs were enabled.
    let saved2 = crate::sync::spinlock::arch_disable_irqs();
    let cpu = crate::sched::smp::cpu_id() as usize;
    let mag = unsafe { &mut CPU_MAGAZINES[cpu][idx] };
    while (mag.loaded.count as usize) < MAG_CAPACITY {
        match guard.alloc() {
            Some(pa) => mag.loaded.push(pa.as_usize()),
            None => break,
        }
    }
    drop(guard);

    if !mag.loaded.is_empty() {
        let addr = mag.loaded.pop();
        crate::sync::spinlock::arch_restore_irqs(saved2);
        Some(PhysAddr::new(addr))
    } else {
        crate::sync::spinlock::arch_restore_irqs(saved2);
        None
    }
}

/// Free an object of `size` bytes back to the appropriate slab cache.
/// Uses per-CPU magazine fast path when possible.
pub fn free(addr: PhysAddr, size: usize) {
    let idx = match cache_index(size) {
        Some(i) => i,
        None => return,
    };

    let saved = crate::sync::spinlock::arch_disable_irqs();
    let cpu = crate::sched::smp::cpu_id() as usize;
    let mag = unsafe { &mut CPU_MAGAZINES[cpu][idx] };

    // Fast path 1: push to loaded magazine.
    if !mag.loaded.is_full() {
        mag.loaded.push(addr.as_usize());
        crate::sync::spinlock::arch_restore_irqs(saved);
        return;
    }

    // Fast path 2: swap loaded ↔ backup, then push.
    if !mag.backup.is_full() {
        core::mem::swap(&mut mag.loaded, &mut mag.backup);
        mag.loaded.push(addr.as_usize());
        crate::sync::spinlock::arch_restore_irqs(saved);
        return;
    }

    // Slow path: flush backup to global cache, then swap and push.
    // Collect backup contents while IRQs disabled, then release IRQs for lock.
    let mut flush_buf = [0usize; MAG_CAPACITY];
    let flush_count = mag.backup.count as usize;
    flush_buf[..flush_count].copy_from_slice(&mag.backup.objs[..flush_count]);
    mag.backup.count = 0;

    // Swap: loaded (full) becomes backup, backup (now empty) becomes loaded.
    core::mem::swap(&mut mag.loaded, &mut mag.backup);
    mag.loaded.push(addr.as_usize());
    crate::sync::spinlock::arch_restore_irqs(saved);

    // Flush collected objects to global cache under lock.
    let cache = cache_by_index(idx);
    let mut guard = cache.lock();
    for i in 0..flush_count {
        guard.free(PhysAddr::new(flush_buf[i]));
    }
}

/// Drain all magazines for a CPU (call on hotplug offline).
pub fn drain_cpu(cpu: u32) {
    let cpu = cpu as usize;
    if cpu >= MAX_CPUS {
        return;
    }

    for idx in 0..NUM_CACHES {
        let cache = cache_by_index(idx);
        let mut guard = cache.lock();

        let mag = unsafe { &mut CPU_MAGAZINES[cpu][idx] };
        // Drain loaded.
        while !mag.loaded.is_empty() {
            let addr = mag.loaded.pop();
            guard.free(PhysAddr::new(addr));
        }
        // Drain backup.
        while !mag.backup.is_empty() {
            let addr = mag.backup.pop();
            guard.free(PhysAddr::new(addr));
        }
    }
}

/// Print slab allocator statistics.
pub fn print_stats() {
    let sizes = [64, 128, 256, 512, 2048];
    let caches: [&SpinLock<SlabCache>; 5] =
        [&CACHE_64, &CACHE_128, &CACHE_256, &CACHE_512, &CACHE_2048];

    crate::println!("  Slab allocator caches:");
    for (i, (size, cache)) in sizes.iter().zip(caches.iter()).enumerate() {
        let c = cache.lock();
        // Count objects cached in magazines across all CPUs.
        let mut mag_cached = 0usize;
        for cpu in 0..MAX_CPUS {
            let mag = unsafe { &CPU_MAGAZINES[cpu][i] };
            mag_cached += mag.loaded.count as usize + mag.backup.count as usize;
        }
        crate::println!(
            "    {}-byte: {} slabs, {} objects/slab, {} in magazines",
            size,
            c.slab_count,
            c.objs_per_slab,
            mag_cached,
        );
    }
}
