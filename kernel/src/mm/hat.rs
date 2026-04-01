//! Hardware Address Translation (HAT) abstraction layer.
//!
//! This module provides the architecture-independent interface for all
//! page table operations. Generic kernel code calls functions here
//! rather than dispatching to arch modules with `#[cfg]` wrappers.
//!
//! All functions compile down to direct calls into the single active
//! arch backend — no trait objects, no runtime dispatch.

use super::ptshare::ForkGroup;
use super::vma::{Vma, VmaProt};
use crate::arch::platform::mm as arch_mm;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const USER_RWX_FLAGS: u64 = arch_mm::USER_RWX_FLAGS;
pub const USER_RW_FLAGS: u64 = arch_mm::USER_RW_FLAGS;
pub const USER_RO_FLAGS: u64 = arch_mm::USER_RO_FLAGS;
pub const PTE_SW_ZEROED: u64 = arch_mm::PTE_SW_ZEROED;

// ---------------------------------------------------------------------------
// Page table lifecycle
// ---------------------------------------------------------------------------

/// Allocate a new user page table, returning its physical root address.
#[inline]
pub fn create_user_page_table() -> Option<usize> {
    arch_mm::create_user_page_table()
}

/// Recursively free all page table pages in the tree rooted at `root`.
/// `fg` is the ForkGroup for shared PT tracking (may be null).
#[inline]
pub fn free_page_table_tree(root: usize, fg: *mut ForkGroup) {
    arch_mm::free_page_table_tree(root, fg);
}

/// Ensure the walk path for `va` contains no shared page table markers.
/// COW-breaks shared nodes top-down. Returns `false` only on OOM.
/// `fg` is the ForkGroup owning the shared PT refcounts (may be null).
#[inline]
pub fn ensure_path_unshared(root: usize, va: usize, fg: *mut ForkGroup) -> bool {
    arch_mm::ensure_path_unshared(root, va, fg)
}

/// Share page table entries between parent and child at fork time.
/// Converts shared entries to not-present markers in both roots.
/// `fg` is the ForkGroup that will track the shared PT refcounts.
#[inline]
pub fn clone_shared_tables(parent_root: usize, child_root: usize, fg: *mut ForkGroup) {
    arch_mm::clone_shared_tables(parent_root, child_root, fg);
}

/// Switch to a different page table (write CR3 / TTBR0 / satp).
#[inline]
pub fn switch_page_table(root: usize) {
    arch_mm::switch_page_table(root);
}

/// Return the kernel boot page table root.
#[inline]
pub fn boot_page_table_root() -> usize {
    arch_mm::boot_page_table_root()
}

/// Return the kernel page table root (differs from boot root on RISC-V;
/// identical on other architectures).
#[inline]
pub fn kernel_pt_root() -> usize {
    #[cfg(target_arch = "riscv64")]
    {
        arch_mm::kernel_pt_root()
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        boot_page_table_root()
    }
}

// ---------------------------------------------------------------------------
// Single MMU page operations
// ---------------------------------------------------------------------------

/// Map a single 4K MMU page at `va` to physical address `pa` with `flags`.
#[inline]
pub fn map_single_mmupage(root: usize, va: usize, pa: usize, flags: u64) -> bool {
    arch_mm::map_single_mmupage(root, va, pa, flags)
}

/// Unmap a single 4K MMU page, returning the old physical address.
#[allow(dead_code)]
#[inline]
pub fn unmap_single_mmupage(root: usize, va: usize) -> usize {
    arch_mm::unmap_single_mmupage(root, va)
}

/// Read the raw leaf PTE for a virtual address.
#[inline]
pub fn read_pte(root: usize, va: usize) -> u64 {
    arch_mm::read_pte(root, va)
}

/// Clear a PTE entirely — both valid and software bits.
#[inline]
pub fn clear_pte(root: usize, va: usize) {
    arch_mm::clear_pte(root, va);
}

/// Evict a 4K MMU page: clear valid bit but preserve SW_ZEROED hint.
#[inline]
pub fn evict_mmupage(root: usize, va: usize) -> usize {
    arch_mm::evict_mmupage(root, va)
}

/// Walk page table and return physical address, or None if unmapped.
#[inline]
pub fn translate_va(root: usize, va: usize) -> Option<usize> {
    arch_mm::translate_va(root, va)
}

/// Read and atomically clear the hardware reference/accessed bit.
#[inline]
pub fn read_and_clear_ref_bit(root: usize, va: usize) -> bool {
    arch_mm::read_and_clear_ref_bit(root, va)
}

/// Downgrade a writable PTE to read-only (for COW).
#[inline]
pub fn downgrade_pte_readonly(root: usize, va: usize) -> bool {
    arch_mm::downgrade_pte_readonly(root, va)
}

/// Update PTE flags in-place (for mprotect), preserving the physical address.
#[inline]
pub fn update_pte_flags(root: usize, va: usize, new_flags: u64) -> bool {
    arch_mm::update_pte_flags(root, va, new_flags)
}

// ---------------------------------------------------------------------------
// Superpage operations
// ---------------------------------------------------------------------------

/// Install a 2 MiB superpage mapping (backward-compatible).
#[inline]
pub fn install_superpage(root: usize, va: usize, pa: usize, flags: u64) -> bool {
    arch_mm::install_superpage(root, va, pa, flags)
}

/// Check if `va` is mapped as a superpage, returning the base PA if so (backward-compatible).
#[inline]
pub fn is_superpage(root: usize, va: usize) -> Option<usize> {
    arch_mm::is_superpage(root, va)
}

/// Demote a superpage back to 512 individual 4K PTEs (backward-compatible).
#[inline]
pub fn demote_superpage(root: usize, va: usize, flags: u64) -> bool {
    arch_mm::demote_superpage(root, va, flags)
}

/// Install a superpage mapping at the given level.
#[inline]
pub fn install_superpage_at_level(
    root: usize,
    va: usize,
    pa: usize,
    flags: u64,
    level: &super::page::SuperpageLevel,
) -> bool {
    arch_mm::install_superpage_at_level(root, va, pa, flags, level)
}

/// Check if `va` is mapped as a superpage at the given level, returning the base PA.
#[inline]
pub fn is_superpage_at_level(
    root: usize,
    va: usize,
    level: &super::page::SuperpageLevel,
) -> Option<usize> {
    arch_mm::is_superpage_at_level(root, va, level)
}

/// Demote a superpage at the given level to the next smaller level's entries.
#[inline]
pub fn demote_superpage_at_level(
    root: usize,
    va: usize,
    flags: u64,
    level: &super::page::SuperpageLevel,
) -> bool {
    arch_mm::demote_superpage_at_level(root, va, flags, level)
}

/// Try AArch64 contiguous hint promotion (no-op on other architectures).
#[inline]
pub fn try_contiguous_promotion(root: usize, va: usize, group_count: usize) -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        arch_mm::try_contiguous_promotion(root, va, group_count)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (root, va, group_count);
        false
    }
}

// ---------------------------------------------------------------------------
// Bulk mapping
// ---------------------------------------------------------------------------

/// Map a contiguous range of user pages.
#[inline]
#[allow(dead_code)]
pub fn map_user_pages(
    root: usize,
    virt: usize,
    phys: usize,
    size: usize,
    flags: u64,
) -> Option<()> {
    arch_mm::map_user_pages(root, virt, phys, size, flags)
}

// ---------------------------------------------------------------------------
// PTE query helpers
// ---------------------------------------------------------------------------

/// Check if a PTE has the valid/present bit set (bit 0 on all architectures).
#[inline]
pub fn pte_is_present(pte: u64) -> bool {
    pte & 1 != 0
}

/// Check if a PTE has the SW_ZEROED hint bit set.
#[inline]
pub fn pte_has_sw_zeroed(pte: u64) -> bool {
    pte & PTE_SW_ZEROED != 0
}

/// Return the architecture-specific SW_ZEROED bit value.
#[inline]
pub fn sw_zeroed_bit() -> u64 {
    PTE_SW_ZEROED
}

// ---------------------------------------------------------------------------
// VMA protection → PTE flags mapping
// ---------------------------------------------------------------------------

/// Map a VmaProt to architecture-specific PTE flags (without SW_ZEROED).
#[inline]
pub fn pte_flags_for_prot(prot: VmaProt) -> u64 {
    match prot {
        VmaProt::ReadOnly => USER_RO_FLAGS,
        VmaProt::ReadWrite => USER_RW_FLAGS,
        VmaProt::ReadExec | VmaProt::ReadWriteExec => USER_RWX_FLAGS,
        VmaProt::None => 0,
    }
}

/// Get PTE flags for a VMA (without SW_ZEROED).
#[inline]
pub fn pte_flags_for_vma(vma: &Vma) -> u64 {
    pte_flags_for_prot(vma.prot)
}

/// Get PTE flags for a VMA, with SW_ZEROED included.
#[inline]
pub fn pte_flags_for_vma_zeroed(vma: &Vma) -> u64 {
    pte_flags_for_prot(vma.prot) | PTE_SW_ZEROED
}
