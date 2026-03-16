//! Page size constants and address types.

/// Hardware MMU page size (4 KiB on AArch64).
pub const MMUPAGE_SIZE: usize = 4096;
pub const MMUPAGE_SHIFT: usize = 12;

/// Allocation page size: configurable multiple of MMUPAGE_SIZE.
/// 64 KiB = 16 MMU pages. This is the minimum allocation unit for the physical allocator.
pub const PAGE_SIZE: usize = 65536;
pub const PAGE_SHIFT: usize = 16;

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
    pub const fn page_number(self) -> usize {
        self.0 >> PAGE_SHIFT
    }
}

impl core::fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PhysAddr({:#x})", self.0)
    }
}
