//! Memory grants — zero-copy page sharing between address spaces.
//!
//! A grant maps physical pages from a source VMA into a destination
//! address space, creating a shared mapping backed by the same memory object.

use super::aspace::{self, ASpaceId};
use super::object;
use super::page::{self, MMUPAGE_SIZE};
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
    /// Source or destination address space was deallocated between the
    /// caller obtaining the ID and grant_pages running.  Surfaces under
    /// concurrent process teardown / IPC reply teardown — e.g. a
    /// short-lived child that exits before the granter's IPC reply is
    /// delivered (project_aspace_lifecycle_race.md).
    AspaceGone,
}

/// Grant `mmu_page_count` MMU pages from one address space to another.
///
/// The source pages must already be backed by physical memory (allocated).
/// The destination gets a shared VMA backed by the same memory object.
/// PTEs are eagerly installed for the requested MMU pages — and *only* those
/// pages.  Earlier versions installed `page_mmucount()` PTEs per allocation
/// page (16 for 64 KiB pages), which caused overlapping installs across
/// neighbouring 4 KiB grant_va values to silently overwrite each other's
/// PTEs (project_grant_pages_phys_mismatch.md).
pub fn grant_pages(
    src_aspace: ASpaceId,
    src_va: usize,
    dst_aspace: ASpaceId,
    dst_va: usize,
    mmu_page_count: usize,
    readonly: bool,
) -> Result<(), GrantError> {
    let pmc = page::page_mmucount();

    // Step 1: Look up the source VMA and collect its object ID + offset + phys pages.
    // The granted range may start at any sub-page offset within the granter's
    // first alloc page when (object_offset + mmu_idx_start) % pmc != 0 — typical
    // for non-PAGE-aligned VMAs (e.g. ELF segments at MMU-aligned but not
    // PAGE-aligned addresses) or for src_va that isn't vma.va_start.  Capture
    // that residue `r` so step 4 can compute correct sub-page indices into the
    // collected phys_pages list.  Without `r`, unaligned grants silently mapped
    // the destination onto sub-pages r positions earlier than intended.
    let (obj_id, obj_mmu_offset, phys_pages, r) = aspace::with_aspace_mut(src_aspace, |aspace| {
        let vma = aspace.find_vma(src_va).ok_or(GrantError::NoSourceVma)?;
        let mmu_idx_start = vma.mmu_index_of(src_va);
        let r = (vma.object_offset as usize + mmu_idx_start) % pmc;
        // Number of alloc pages spanning the granted range — must include the
        // leading partial alloc page when r > 0.
        let alloc_page_count = (r + mmu_page_count + pmc - 1) / pmc;
        let mut pages = [0usize; 256];
        for i in 0..alloc_page_count {
            let obj_page = vma.obj_page_index(mmu_idx_start + i * pmc);
            let pa = object::with_object(vma.object_id, |obj| {
                obj.get_page(obj_page).map(|p| p.as_usize())
            });
            pages[i] = pa.ok_or(GrantError::NoBackingPage)?;
        }
        // object_offset for destination in MMUPAGE_SIZE units.
        let dst_obj_offset = vma.object_offset + mmu_idx_start as u32;
        Ok((vma.object_id, dst_obj_offset, pages, r))
    })
    .ok_or(GrantError::AspaceGone)??;

    // Step 2: Register the mapping in the object.
    object::with_object(obj_id, |obj| {
        obj.add_mapping(dst_aspace, dst_va);
    });

    // Step 3: Create a shared VMA in the destination address space.
    aspace::with_aspace_mut(dst_aspace, |aspace| {
        let prot = if readonly {
            VmaProt::ReadOnly
        } else {
            VmaProt::ReadWrite
        };
        // VMA covers exactly the requested MMU range, not a rounded-up
        // alloc-page multiple — neighbouring grants must not overlap.
        let va_len = mmu_page_count * MMUPAGE_SIZE;
        let _vma = aspace
            .vmas
            .insert(dst_va, va_len, prot, obj_id, obj_mmu_offset)
            .ok_or(GrantError::DestMapFailed)?;

        // Step 4: Install PTEs ONLY for the requested MMU pages.
        let pt_root = aspace.page_table_root;
        let flags = if readonly {
            user_ro_flags()
        } else {
            user_rw_flags()
        };

        for mmu_idx in 0..mmu_page_count {
            // Apply source-residue `r` so phys_pages[page_i] indexes the list
            // correctly: phys_pages[0] holds the alloc page that contains the
            // granter's first MMU page at sub-index r, NOT at sub-index 0.
            let off = r + mmu_idx;
            let page_i = off / pmc;
            let mmu_i = off % pmc;
            let pa_base = phys_pages[page_i];
            if pa_base == 0 {
                continue;
            }
            let va = dst_va + mmu_idx * MMUPAGE_SIZE;
            let pa = pa_base + mmu_i * MMUPAGE_SIZE;
            map_single_mmupage(pt_root, va, pa, flags | sw_zeroed_bit());
        }

        Ok(())
    })
    .ok_or(GrantError::AspaceGone)?
}

/// Revoke a grant: unmap all PTEs and remove the VMA from the destination.
///
/// Silently no-ops if the destination address space has been deallocated
/// (the grant is already invisibly gone — there's nothing to revoke).
pub fn revoke_grant(dst_aspace: ASpaceId, dst_va: usize) {
    let _ = aspace::with_aspace_mut(dst_aspace, |aspace| {
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
            // Use try_with_object: the source may have already destroyed
            // this object if the granting process exited first.
            object::try_with_object(obj_id, |obj| {
                obj.remove_mapping(dst_aspace, va_start);
            });
        }
        // Remove the VMA from the tree.
        aspace.vmas.remove(dst_va);
    });
}

// Architecture-specific wrappers — delegated to HAT.

use super::hat;

fn map_single_mmupage(pt_root: usize, va: usize, pa: usize, flags: u64) -> bool {
    hat::map_single_mmupage(pt_root, va, pa, flags)
}

fn clear_pte(pt_root: usize, va: usize) {
    hat::clear_pte(pt_root, va);
}

fn sw_zeroed_bit() -> u64 {
    hat::sw_zeroed_bit()
}

fn user_ro_flags() -> u64 {
    hat::USER_RO_FLAGS
}

fn user_rw_flags() -> u64 {
    hat::USER_RW_FLAGS
}
