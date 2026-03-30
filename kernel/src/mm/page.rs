//! Page size constants and address types.
//!
//! PAGE_SIZE/PAGE_SHIFT are compile-time constants (needed for array sizes, const fns).
//! For boot-time configurable page size, use `page_size()` / `page_shift()` which
//! read from boot configuration when `page_mmushift` was set on the command line.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Hardware MMU page size (4 KiB on all supported architectures).
pub const MMUPAGE_SIZE: usize = 4096;
#[allow(dead_code)]
pub const MMUPAGE_SHIFT: usize = 12;

/// Maximum allocation page size (256 KiB). Used for array sizing so that a
/// single binary can handle any boot-time page_mmushift value (0–6).
pub const MAX_PAGE_SIZE: usize = 262144;
pub const MAX_PAGE_SHIFT: usize = 18;

/// Compile-time default allocation page size (selected via cargo features).
/// Used for array sizing and const contexts. Runtime code should prefer
/// `page_size()` / `page_shift()` which respect the boot-time configuration.
#[cfg(feature = "page_size_16k")]
pub const PAGE_SIZE: usize = 16384;
#[cfg(feature = "page_size_16k")]
pub const PAGE_SHIFT: usize = 14;

#[cfg(feature = "page_size_64k")]
pub const PAGE_SIZE: usize = 65536;
#[cfg(feature = "page_size_64k")]
pub const PAGE_SHIFT: usize = 16;

#[cfg(feature = "page_size_128k")]
pub const PAGE_SIZE: usize = 131072;
#[cfg(feature = "page_size_128k")]
pub const PAGE_SHIFT: usize = 17;

#[cfg(feature = "page_size_256k")]
pub const PAGE_SIZE: usize = 262144;
#[cfg(feature = "page_size_256k")]
pub const PAGE_SHIFT: usize = 18;

/// Number of MMU pages per allocation page (compile-time default).
pub const PAGE_MMUCOUNT: usize = PAGE_SIZE / MMUPAGE_SIZE;

/// Shift from MMU-page index to allocation-page index (compile-time default).
#[allow(dead_code)]
pub const PAGE_MMUSHIFT: usize = PAGE_SHIFT - MMUPAGE_SHIFT;

// ---------------------------------------------------------------------------
// Runtime page size (boot-time configurable)
// ---------------------------------------------------------------------------

/// Runtime page size, initialized from boot command line before phys::init().
/// Zero means "not yet initialized" — page_size() falls back to compile-time default.
static RUNTIME_PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);
static RUNTIME_PAGE_SHIFT: AtomicUsize = AtomicUsize::new(0);
static RUNTIME_PAGE_MMUCOUNT: AtomicUsize = AtomicUsize::new(0);

/// Initialize runtime page size from boot-configured mmushift.
/// Called once during early boot, after command line parsing, before phys::init().
pub fn init_runtime_page_size(mmushift: u8) {
    let shift = MMUPAGE_SHIFT + mmushift as usize;
    let size = MMUPAGE_SIZE << mmushift;
    let mmucount = 1usize << mmushift;
    RUNTIME_PAGE_SIZE.store(size, Ordering::Release);
    RUNTIME_PAGE_SHIFT.store(shift, Ordering::Release);
    RUNTIME_PAGE_MMUCOUNT.store(mmucount, Ordering::Release);
}

/// Runtime allocation page size. Returns the boot-configured value if set,
/// otherwise falls back to the compile-time default.
#[inline]
pub fn page_size() -> usize {
    let v = RUNTIME_PAGE_SIZE.load(Ordering::Relaxed);
    if v != 0 { v } else { PAGE_SIZE }
}

/// Runtime allocation page shift (log2 of page_size()).
#[inline]
pub fn page_shift() -> usize {
    let v = RUNTIME_PAGE_SHIFT.load(Ordering::Relaxed);
    if v != 0 { v } else { PAGE_SHIFT }
}

/// Runtime MMU pages per allocation page.
#[inline]
pub fn page_mmucount() -> usize {
    let v = RUNTIME_PAGE_MMUCOUNT.load(Ordering::Relaxed);
    if v != 0 { v } else { PAGE_MMUCOUNT }
}

// ---------------------------------------------------------------------------
// Superpage (large page) level table — architecture-dependent
// ---------------------------------------------------------------------------

/// Description of a single hardware superpage size.
#[derive(Clone, Copy)]
pub struct SuperpageLevel {
    /// Total size in bytes (e.g., 2 MiB = 0x20_0000).
    pub size: usize,
    /// log2(size).
    pub shift: u32,
    /// The radix page table level at which this superpage is installed.
    pub pt_level: u32,
}

impl SuperpageLevel {
    /// Number of allocation pages per superpage at this level.
    pub const fn alloc_pages(&self) -> usize {
        self.size / PAGE_SIZE
    }

    /// Number of MMU pages per superpage at this level.
    pub const fn mmu_pages(&self) -> usize {
        self.size / MMUPAGE_SIZE
    }

    /// Alignment mask: `addr & align_mask()` gives the offset within this superpage.
    pub const fn align_mask(&self) -> usize {
        self.size - 1
    }

    /// Align a virtual or physical address down to this superpage boundary.
    pub const fn align_down(&self, addr: usize) -> usize {
        addr & !self.align_mask()
    }
}

/// Per-architecture superpage level table, ordered smallest to largest.
/// Does not include the AArch64 contiguous hint (handled separately).
#[cfg(target_arch = "x86_64")]
pub const SUPERPAGE_LEVELS: &[SuperpageLevel] = &[
    SuperpageLevel { size: 2 << 20, shift: 21, pt_level: 2 },        // 2 MiB (PD large page)
    SuperpageLevel { size: 1 << 30, shift: 30, pt_level: 1 },        // 1 GiB (PDPT large page)
];

#[cfg(target_arch = "aarch64")]
pub const SUPERPAGE_LEVELS: &[SuperpageLevel] = &[
    SuperpageLevel { size: 2 << 20, shift: 21, pt_level: 2 },        // 2 MiB (L2 block)
    SuperpageLevel { size: 1 << 30, shift: 30, pt_level: 1 },        // 1 GiB (L1 block)
];

#[cfg(target_arch = "riscv64")]
pub const SUPERPAGE_LEVELS: &[SuperpageLevel] = &[
    SuperpageLevel { size: 2 << 20, shift: 21, pt_level: 1 },        // 2 MiB (Sv39 megapage)
    SuperpageLevel { size: 1 << 30, shift: 30, pt_level: 0 },        // 1 GiB (Sv39 gigapage)
];

#[cfg(target_arch = "loongarch64")]
pub const SUPERPAGE_LEVELS: &[SuperpageLevel] = &[
    SuperpageLevel { size: 2 << 20, shift: 21, pt_level: 2 },        // 2 MiB (PMD huge page)
    SuperpageLevel { size: 1 << 30, shift: 30, pt_level: 1 },        // 1 GiB (PUD huge page)
];

#[cfg(target_arch = "mips64")]
pub const SUPERPAGE_LEVELS: &[SuperpageLevel] = &[
    SuperpageLevel { size: 2 << 20, shift: 21, pt_level: 1 },        // 2 MiB (PMD superpage)
    SuperpageLevel { size: 1 << 30, shift: 30, pt_level: 0 },        // 1 GiB (PGD superpage)
];

// ---------------------------------------------------------------------------
// Backward-compatible aliases — refer to smallest superpage level (index 0).
// Existing code uses these; new code should prefer SUPERPAGE_LEVELS directly.
// ---------------------------------------------------------------------------

/// Smallest superpage size for this architecture (2 MiB on aarch64/x86_64/riscv64).
pub const SUPERPAGE_SIZE: usize = SUPERPAGE_LEVELS[0].size;
#[allow(dead_code)]
pub const SUPERPAGE_SHIFT: usize = SUPERPAGE_LEVELS[0].shift as usize;

/// Number of allocation pages in one superpage (smallest level).
pub const SUPERPAGE_ALLOC_PAGES: usize = SUPERPAGE_SIZE / PAGE_SIZE;

/// Number of MMU pages in one superpage (smallest level).
pub const SUPERPAGE_MMU_PAGES: usize = SUPERPAGE_SIZE / MMUPAGE_SIZE;

/// Alignment mask for the smallest superpage level.
pub const SUPERPAGE_ALIGN_MASK: usize = SUPERPAGE_SIZE - 1;

/// Physical address (wrapper for type safety).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysAddr(pub usize);

impl PhysAddr {
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Align up to the given alignment.
    pub const fn align_up(self, align: usize) -> Self {
        Self((self.0 + align - 1) & !(align - 1))
    }

    /// Align down to the given alignment.
    pub const fn align_down(self, align: usize) -> Self {
        Self(self.0 & !(align - 1))
    }

    /// Page number (index of the allocation page containing this address).
    #[allow(dead_code)]
    pub const fn page_number(self) -> usize {
        self.0 >> PAGE_SHIFT
    }
}

impl core::fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PhysAddr({:#x})", self.0)
    }
}
