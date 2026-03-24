//! Virtual Memory Area (VMA) — describes a contiguous virtual address range
//! within an address space, backed by a memory object.

use super::page::{MMUPAGE_SIZE, PAGE_MMUCOUNT, PAGE_SIZE};

/// Maximum VMAs per address space.
#[allow(dead_code)]
pub const MAX_VMAS: usize = 32;

/// VMA protection flags.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum VmaProt {
    ReadOnly = 0,
    ReadWrite = 1,
    ReadExec = 2,
    ReadWriteExec = 3,
    None = 4,
}

impl VmaProt {
    #[allow(dead_code)]
    pub fn readable(self) -> bool { !matches!(self, Self::None) }
    pub fn writable(self) -> bool { matches!(self, Self::ReadWrite | Self::ReadWriteExec) }
    pub fn executable(self) -> bool { matches!(self, Self::ReadExec | Self::ReadWriteExec) }
}

/// A virtual memory area within an address space.
///
/// The ABI is MMUPAGE_SIZE-oriented: `va_start`, `va_len`, and `object_offset`
/// are all expressed in MMUPAGE_SIZE granularity. The allocation unit
/// (PAGE_SIZE = MMUPAGE_SIZE << PAGE_MMUSHIFT) is an internal detail that
/// the kernel adapts to when indexing backing memory objects.
pub struct Vma {
    /// Base virtual address (MMUPAGE_SIZE-aligned).
    pub va_start: usize,
    /// Length in bytes (MMUPAGE_SIZE-aligned).
    pub va_len: usize,
    /// Protection.
    pub prot: VmaProt,
    /// Backing memory object ID.
    pub object_id: u32,
    /// Offset into the memory object (in MMUPAGE_SIZE units).
    pub object_offset: u32,
    /// Whether this VMA slot is in use.
    pub active: bool,
}

impl Vma {
    pub const fn empty() -> Self {
        Self {
            va_start: 0,
            va_len: 0,
            prot: VmaProt::ReadWrite,
            object_id: 0,
            object_offset: 0,
            active: false,
        }
    }

    /// Number of allocation pages spanned by this VMA (ceiling).
    pub fn page_count(&self) -> usize {
        (self.va_len + PAGE_SIZE - 1) / PAGE_SIZE
    }

    /// Number of MMU pages in this VMA.
    pub fn mmu_page_count(&self) -> usize {
        self.va_len / MMUPAGE_SIZE
    }

    /// Check if a virtual address falls within this VMA.
    pub fn contains(&self, va: usize) -> bool {
        va >= self.va_start && va < self.va_start + self.va_len
    }

    /// Compute the MMU page index within this VMA for a virtual address.
    pub fn mmu_index_of(&self, va: usize) -> usize {
        (va - self.va_start) / MMUPAGE_SIZE
    }

    /// Compute the VMA-local allocation page index for a virtual address.
    #[allow(dead_code)]
    pub fn page_index_of(&self, va: usize) -> usize {
        (va - self.va_start) / PAGE_SIZE
    }

    // --- Object-space helpers ---
    // These translate VMA-local MMU indices to the backing object's allocation
    // page indices, accounting for object_offset being in MMUPAGE_SIZE units.

    /// Allocation page index in the backing object for a VMA-local `mmu_idx`.
    pub fn obj_page_index(&self, mmu_idx: usize) -> usize {
        (self.object_offset as usize + mmu_idx) / PAGE_MMUCOUNT
    }

    /// MMU page offset within the allocation page for a VMA-local `mmu_idx`.
    pub fn mmu_offset_in_page(&self, mmu_idx: usize) -> usize {
        (self.object_offset as usize + mmu_idx) % PAGE_MMUCOUNT
    }

    /// Range of VMA-local MMU indices that share the same allocation page
    /// as `mmu_idx`. Returns `(start, end)` where the range is `[start, end)`.
    pub fn alloc_page_mmu_range(&self, mmu_idx: usize) -> (usize, usize) {
        let obj_mmu = self.object_offset as usize + mmu_idx;
        let page_base = obj_mmu - (obj_mmu % PAGE_MMUCOUNT);
        let start = page_base.saturating_sub(self.object_offset as usize);
        let end = (page_base + PAGE_MMUCOUNT - self.object_offset as usize)
            .min(self.mmu_page_count());
        (start, end)
    }
}
