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

use super::page::{self, PAGE_SIZE, PhysAddr};
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

    /// Recalculate objs_per_slab based on the runtime page size.
    /// Must be called after `page::init_runtime_page_size()` if the runtime
    /// page size differs from the compile-time default.
    pub fn reinit_for_page_size(&mut self) {
        let ps = page::page_size();
        let usable = ps - self.data_offset;
        self.objs_per_slab = usable / self.obj_size;
    }

    /// Ensure the slab directory page is allocated. Returns false on OOM.
    fn ensure_dir(&mut self) -> bool {
        if self.slab_dir.is_null() {
            // #235 Phase 2b: slab_dir is a kva pointer (PHYS_DIRECT_MAP);
            // the *values* stored in slots remain PAs.
            let page = match phys::alloc_page() {
                Some(pa) => crate::mm::page::phys_to_kva(pa.as_usize()) as *mut usize,
                None => return false,
            };
            unsafe {
                core::ptr::write_bytes(page as *mut u8, 0, page::page_size());
            }
            self.slab_dir = page;
            self.slab_dir_cap = page::page_size() / core::mem::size_of::<usize>();
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
            let header = unsafe {
                &mut *(crate::mm::page::phys_to_kva(page_addr) as *mut SlabHeader)
            };
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

        let header = unsafe {
            &mut *(crate::mm::page::phys_to_kva(page_addr) as *mut SlabHeader)
        };
        Some(self.alloc_from_slab(page_addr, header))
    }

    /// Free an object back to this cache.
    pub fn free(&mut self, addr: PhysAddr) {
        let addr_val = addr.as_usize();
        // Find which slab this object belongs to.
        let page_base = addr_val & !(page::page_size() - 1);

        for i in 0..self.slab_count {
            if self.slab_page(i) == page_base {
                let header = unsafe {
                    &mut *(crate::mm::page::phys_to_kva(page_base) as *mut SlabHeader)
                };
                let obj_index = (addr_val - page_base - self.data_offset) / self.obj_size;

                // Sanity: obj_index must be within the page's object capacity.
                if obj_index >= self.objs_per_slab {
                    panic!(
                        "slab::free corruption: addr={:#x} page={:#x} obj_index={} > capacity={} obj_size={}",
                        addr_val, page_base, obj_index, self.objs_per_slab, self.obj_size
                    );
                }

                // Pre-write check: header.free_head should already be a
                // valid index (NONE or < objs_per_slab). If it isn't, the
                // header has been corrupted between this free and the
                // previous alloc/free on this page — i.e., something
                // outside the slab module is writing into the slab page
                // (most likely use-after-free of an object that was on
                // the free list).
                if header.free_head != NONE && (header.free_head as usize) >= self.objs_per_slab {
                    panic!(
                        "slab::free entry corruption: page={:#x} obj_size={} free_head={} > capacity={} (about to free addr={:#x} idx={})",
                        page_base, self.obj_size, header.free_head, self.objs_per_slab, addr_val, obj_index
                    );
                }

                // Push onto free list (deref via direct-map VA).
                let obj_ptr = (crate::mm::page::phys_to_kva(page_base)
                    + self.data_offset
                    + obj_index * self.obj_size) as *mut u16;
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
        // #235 Phase 2b: page_addr is a PA; dereference via PHYS_DIRECT_MAP.
        let page_va = crate::mm::page::phys_to_kva(page_addr);
        let header = unsafe { &mut *(page_va as *mut SlabHeader) };
        header.in_use = 0;
        header.capacity = self.objs_per_slab as u16;

        // Build free list: each free slot points to the next.
        let base = page_va + self.data_offset;
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
        // Bounds: free_head MUST be a valid object index. If it isn't, the
        // free list has been corrupted (e.g., by a stale write into a freed
        // slot). Panic loudly rather than walk into garbage.
        if index >= self.objs_per_slab {
            panic!(
                "slab corruption: page={:#x} obj_size={} free_head={} > capacity={}",
                page_addr, self.obj_size, index, self.objs_per_slab
            );
        }
        let obj_addr = page_addr + self.data_offset + index * self.obj_size;

        // Advance free list (read via direct-map VA).
        let next = unsafe {
            *(crate::mm::page::phys_to_kva(obj_addr) as *const u16)
        };
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

use crate::sched::smp;
use core::sync::atomic::{AtomicPtr, Ordering};

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
        // #235 C2h: surface where the corrupted Magazine lives + what
        // its neighborhood looks like.  The original \`self.objs[count]\`
        // panic gives only the bad index, not the victim address.
        if self.count == 0 || self.count as usize > MAG_CAPACITY {
            let va = self as *const _ as usize;
            let pa_guess = crate::mm::page::kva_to_phys(va);
            crate::println!(
                "SLAB-MAG-CORRUPT: va={:p} pa~={:#x} count={} obj0={:#x} obj31={:#x}",
                self as *const _,
                pa_guess,
                self.count,
                self.objs[0],
                self.objs[31],
            );
            panic!(
                "Magazine corruption: count={} > MAG_CAPACITY={}",
                self.count, MAG_CAPACITY
            );
        }
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
/// Stored in a dynamic per-CPU slice installed by `init_dynamic_percpu`
/// from `smp::init_dynamic_percpu` after `phys::init`. Each entry is a row
/// of `NUM_CACHES` magazine pairs. The all-zero pattern (from
/// `alloc_static_slice`) matches `MagazinePair::empty()`, so no explicit
/// initialization is needed.
///
/// Safety: accessed only with IRQs disabled from the owning CPU.
static CPU_MAGAZINES_PTR: AtomicPtr<[MagazinePair; NUM_CACHES]> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn cpu_magazine_row(cpu: usize) -> *mut [MagazinePair; NUM_CACHES] {
    let base = CPU_MAGAZINES_PTR.load(Ordering::Relaxed);
    debug_assert!(!base.is_null(), "CPU_MAGAZINES not init");
    debug_assert!(cpu < smp::num_cpus());
    unsafe { base.add(cpu) }
}

/// Allocate and install the dynamic per-CPU magazine slice. Called from
/// `smp::init_dynamic_percpu` after `phys::init`. Slabs are unused before
/// this point — early kernel allocations go through `phys::alloc_pages`
/// directly — so the global caches remain authoritative until installed.
pub(crate) fn init_dynamic_percpu() {
    let n = smp::num_cpus();
    unsafe {
        let s = crate::mm::phys::alloc_static_slice::<[MagazinePair; NUM_CACHES]>(n);
        CPU_MAGAZINES_PTR.store(s.as_mut_ptr(), Ordering::Release);
        // #228 probe: register the magazine slice's PA range with
        // the phys allocator so any subsequent alloc_pages return
        // that lands inside it panics on the spot (double-issue
        // smoking gun for the C2h corruption capture).
        let va = s.as_mut_ptr() as usize;
        let pa = crate::mm::page::kva_to_phys(va);
        let bytes = n * core::mem::size_of::<[MagazinePair; NUM_CACHES]>();
        crate::mm::phys::register_no_realloc_range(pa, pa + bytes, "slab_magazines");
    }
}

// --- Global slab caches for common kernel object sizes ---

use crate::sync::SpinLock;

static CACHE_64: SpinLock<SlabCache> = SpinLock::new(SlabCache::new(64, 64));
static CACHE_128: SpinLock<SlabCache> = SpinLock::new(SlabCache::new(128, 64));
static CACHE_256: SpinLock<SlabCache> = SpinLock::new(SlabCache::new(256, 64));
static CACHE_512: SpinLock<SlabCache> = SpinLock::new(SlabCache::new(512, 64));
static CACHE_2048: SpinLock<SlabCache> = SpinLock::new(SlabCache::new(2048, 64));

/// Reinitialize all slab caches for the runtime page size.
/// Must be called once after `page::init_runtime_page_size()` and before
/// any slab allocations, if the runtime page size differs from compile-time.
pub fn reinit_for_page_size() {
    CACHE_64.lock().reinit_for_page_size();
    CACHE_128.lock().reinit_for_page_size();
    CACHE_256.lock().reinit_for_page_size();
    CACHE_512.lock().reinit_for_page_size();
    CACHE_2048.lock().reinit_for_page_size();
}

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

#[allow(dead_code)]
fn cache_for_size(size: usize) -> Option<&'static SpinLock<SlabCache>> {
    cache_index(size).map(cache_by_index)
}

/// Walk every slab page in every cache and panic if any page's free_head
/// is out of range. Caught a real corruption (RcuBatch overflowing into a
/// neighboring slab page when BATCH_CAP was sized for MAX_PAGE_SIZE rather
/// than the runtime page size). Kept as a permanent invariant check —
/// O(slab_count) per call, only used by diagnostic harnesses.
pub fn debug_check_all_caches(label: &str) {
    fn check_one(label: &str, name: &str, cache: &SpinLock<SlabCache>) {
        let guard = cache.lock();
        for i in 0..guard.slab_count {
            let page = guard.slab_page(i);
            if page == 0 {
                continue;
            }
            let header = unsafe { &*(page as *const SlabHeader) };
            let fh = header.free_head;
            let in_use = header.in_use;
            let cap_field = header.capacity;
            let obj_size = guard.obj_size;
            let cap = guard.objs_per_slab;
            if fh != NONE && (fh as usize) >= cap {
                // Dump first 32 bytes of the page to identify the corrupting writer.
                let bytes: [u8; 32] = unsafe { core::ptr::read(page as *const [u8; 32]) };
                // Count duplicate slab_dir entries for this page.
                let mut dup_count = 0;
                for j in 0..guard.slab_count {
                    if guard.slab_page(j) == page { dup_count += 1; }
                }
                drop(guard);
                crate::println!(
                    "[{}] slab corruption {}: page={:#x} obj_size={} free_head={} > cap={} (header.in_use={} header.cap={} slab_dir_dup={})",
                    label, name, page, obj_size, fh, cap, in_use, cap_field, dup_count
                );
                crate::println!(
                    "  page[0..32]={:02x?}", bytes
                );
                panic!("slab corruption detected");
            }
        }
    }
    check_one(label, "CACHE_64", &CACHE_64);
    check_one(label, "CACHE_128", &CACHE_128);
    check_one(label, "CACHE_256", &CACHE_256);
    check_one(label, "CACHE_512", &CACHE_512);
    check_one(label, "CACHE_2048", &CACHE_2048);
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
    // #235 C2g probe: surface bogus cpu_id (LAPIC read) before it
    // walks off the per-CPU magazine array.
    assert!(
        cpu < smp::num_cpus(),
        "slab::alloc cpu={} >= num_cpus={}",
        cpu,
        smp::num_cpus()
    );

    let mag = unsafe { &mut (*cpu_magazine_row(cpu))[idx] };

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
    let mag = unsafe { &mut (*cpu_magazine_row(cpu))[idx] };
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
    assert!(
        cpu < smp::num_cpus(),
        "slab::free cpu={} >= num_cpus={}",
        cpu,
        smp::num_cpus()
    );
    let mag = unsafe { &mut (*cpu_magazine_row(cpu))[idx] };

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
    // Clamp count defensively: if magazine state has been corrupted
    // (#208 family), use 0 rather than panic on out-of-bounds slice.
    // This lets the primary failure print before we'd otherwise mask it.
    let flush_count = (mag.backup.count as usize).min(MAG_CAPACITY);
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
    if cpu >= smp::num_cpus() {
        return;
    }

    for idx in 0..NUM_CACHES {
        let cache = cache_by_index(idx);
        let mut guard = cache.lock();

        let mag = unsafe { &mut (*cpu_magazine_row(cpu))[idx] };
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
        for cpu in 0..smp::num_cpus() {
            let mag = unsafe { &(*cpu_magazine_row(cpu))[i] };
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
