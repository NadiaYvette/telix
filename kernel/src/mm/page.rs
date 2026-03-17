//! Page size constants and address types.

/// Hardware MMU page size (4 KiB on all supported architectures).
pub const MMUPAGE_SIZE: usize = 4096;
#[allow(dead_code)]
pub const MMUPAGE_SHIFT: usize = 12;

/// Allocation page size: configurable multiple of MMUPAGE_SIZE.
/// Selected at compile time via cargo features.
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

/// Number of MMU pages per allocation page.
pub const PAGE_MMUCOUNT: usize = PAGE_SIZE / MMUPAGE_SIZE;

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
