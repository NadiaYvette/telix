//! Memory grants — zero-copy page sharing between address spaces.
//!
//! A grant maps physical pages from a source VMA into a destination
//! address space, creating a shared mapping backed by the same memory object.

use super::aspace::{self, ASpaceId};
use super::object;
use super::page::{PAGE_SIZE, PAGE_MMUCOUNT, MMUPAGE_SIZE};
use super::vma::VmaProt;

/// Error returned by grant operations.
#[derive(Debug)]
pub enum GrantError {
    /// Source VMA not found at the given address.
    NoSourceVma,
    /// Source pages not yet allocated (no physical backing).
    NoBackingPage,
    /// Failed to create destination VMA.
    DestMapFailed,
    /// Failed to install PTEs in destination.
    #[allow(dead_code)]
    PteFailed,
}

/// Grant `page_count` allocation pages from one address space to another.
///
/// The source pages must already be backed by physical memory (allocated).
/// The destination gets a shared VMA backed by the same memory object.
/// PTEs are eagerly installed for all allocated pages.
pub fn grant_pages(
    src_aspace: ASpaceId,
    src_va: usize,
    dst_aspace: ASpaceId,
    dst_va: usize,
    page_count: usize,
    readonly: bool,
) -> Result<(), GrantError> {
    // Step 1: Look up the source VMA and collect its object ID + offset + phys pages.
    let (obj_id, obj_mmu_offset, phys_pages) = aspace::with_aspace(src_aspace, |aspace| {
        let vma = aspace.find_vma(src_va).ok_or(GrantError::NoSourceVma)?;
        let mmu_idx_start = vma.mmu_index_of(src_va);
        let mut pages = [0usize; 256];
        for i in 0..page_count {
            let obj_page = vma.obj_page_index(mmu_idx_start + i * PAGE_MMUCOUNT);
            let pa = object::with_object(vma.object_id, |obj| {
                obj.get_page(obj_page).map(|p| p.as_usize())
            });
            pages[i] = pa.ok_or(GrantError::NoBackingPage)?;
        }
        // object_offset for destination in MMUPAGE_SIZE units.
        let dst_obj_offset = vma.object_offset + mmu_idx_start as u32;
        Ok((vma.object_id, dst_obj_offset, pages))
    })?;

    // Step 2: Register the mapping in the object.
    object::with_object(obj_id, |obj| {
        obj.add_mapping(dst_aspace, dst_va);
    });

    // Step 3: Create a shared VMA in the destination address space.
    aspace::with_aspace(dst_aspace, |aspace| {
        let prot = if readonly { VmaProt::ReadOnly } else { VmaProt::ReadWrite };
        let va_len = page_count * PAGE_SIZE;
        let vma = aspace.vmas.insert(dst_va, va_len, prot, obj_id, obj_mmu_offset)
            .ok_or(GrantError::DestMapFailed)?;

        // Step 4: Install PTEs for all MMU pages that have physical backing.
        let pt_root = aspace.page_table_root;
        let flags = if readonly { user_ro_flags() } else { user_rw_flags() };

        for page_i in 0..page_count {
            let pa_base = phys_pages[page_i];
            if pa_base == 0 {
                continue;
            }
            for mmu_i in 0..PAGE_MMUCOUNT {
                let mmu_idx = page_i * PAGE_MMUCOUNT + mmu_i;
                let va = dst_va + mmu_idx * MMUPAGE_SIZE;
                let pa = pa_base + mmu_i * MMUPAGE_SIZE;
                map_single_mmupage(pt_root, va, pa, flags | sw_zeroed_bit());
            }
        }

        Ok(())
    })
}

/// Revoke a grant: unmap all PTEs and remove the VMA from the destination.
pub fn revoke_grant(dst_aspace: ASpaceId, dst_va: usize) {
    aspace::with_aspace(dst_aspace, |aspace| {
        let pt_root = aspace.page_table_root;
        if let Some(vma) = aspace.find_vma(dst_va) {
            let obj_id = vma.object_id;
            let mmu_count = vma.mmu_page_count();
            let va_start = vma.va_start;
            // Unmap all PTEs.
            for mmu_idx in 0..mmu_count {
                let va = va_start + mmu_idx * MMUPAGE_SIZE;
                clear_pte(pt_root, va);
            }
            // Remove the mapping record from the object.
            object::with_object(obj_id, |obj| {
                obj.remove_mapping(dst_aspace, va_start);
            });
        }
        // Remove the VMA from the tree.
        aspace.vmas.remove(dst_va);
    });
}

// Architecture-specific wrappers.

fn map_single_mmupage(pt_root: usize, va: usize, pa: usize, flags: u64) -> bool {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::map_single_mmupage(pt_root, va, pa, flags) }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::map_single_mmupage(pt_root, va, pa, flags) }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::map_single_mmupage(pt_root, va, pa, flags) }
}

fn clear_pte(pt_root: usize, va: usize) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::clear_pte(pt_root, va); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::clear_pte(pt_root, va); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::clear_pte(pt_root, va); }
}

fn sw_zeroed_bit() -> u64 {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::PTE_SW_ZEROED }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::PTE_SW_ZEROED }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::PTE_SW_ZEROED }
}

fn user_ro_flags() -> u64 {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::USER_RO_FLAGS }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::USER_RO_FLAGS }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::USER_RO_FLAGS }
}

fn user_rw_flags() -> u64 {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::USER_RW_FLAGS }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::USER_RW_FLAGS }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::USER_RW_FLAGS }
}
