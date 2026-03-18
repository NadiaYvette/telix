//! Architecture-independent page fault handler.
//!
//! When a page fault occurs in userspace, the arch-specific exception handler
//! extracts the fault address and type, then calls `handle_page_fault`.
//! This module resolves the faulting VMA, allocates physical memory if needed,
//! zeros the specific 4K MMU page, and installs its PTE.

use super::aspace::{self, ASpaceId};
use super::object;
use super::page::MMUPAGE_SIZE;
use super::stats;
use core::sync::atomic::Ordering;

/// Type of page fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultType {
    Read,
    Write,
    Exec,
}

/// Result of handling a page fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultResult {
    /// Fault handled successfully.
    #[allow(dead_code)]
    Handled,
    /// Major fault: had to allocate and zero a new page.
    HandledMajor,
    /// Minor fault: page was resident, just reinstalled PTE.
    HandledMinor,
    /// COW fault: copied a shared page to make it writable.
    #[allow(dead_code)]
    HandledCOW,
    /// Fault could not be handled (bad address, permission error, etc.).
    Failed,
}

/// Handle a page fault from userspace.
///
/// `aspace_id`: the address space of the faulting task.
/// `fault_addr`: the virtual address that caused the fault.
/// `fault_type`: whether it was a read, write, or exec fault.
///
/// Returns the fault result.
pub fn handle_page_fault(
    aspace_id: ASpaceId,
    fault_addr: usize,
    fault_type: FaultType,
) -> FaultResult {
    aspace::with_aspace(aspace_id, |aspace| {
        let pt_root = aspace.page_table_root;

        // Find the VMA containing the faulting address.
        let vma = match aspace.find_vma_mut(fault_addr) {
            Some(v) => v,
            None => return FaultResult::Failed,
        };

        // Check permissions.
        match fault_type {
            FaultType::Write if !vma.prot.writable() => return FaultResult::Failed,
            FaultType::Exec if !vma.prot.executable() => return FaultResult::Failed,
            _ => {}
        }

        // Compute indices.
        let mmu_idx = vma.mmu_index_of(fault_addr);
        let obj_page_idx = vma.obj_page_index(mmu_idx);
        let obj_id = vma.object_id;

        // COW fault check: VMA is writable, page has PTE installed, but we got
        // a write fault. This means the PTE is read-only due to COW sharing.
        if fault_type == FaultType::Write && vma.prot.writable() && vma.is_installed(mmu_idx) {
            return handle_cow_fault(pt_root, vma, obj_id, obj_page_idx, mmu_idx, fault_addr);
        }

        // Check if this is a minor fault (page is resident but PTE was removed).
        if vma.is_zeroed(mmu_idx) && !vma.is_installed(mmu_idx) {
            // The MMU page was previously zeroed but its PTE was cleared (by WSCLOCK).
            // The underlying allocation page should still be resident.
            let pa = object::with_object(obj_id, |obj| obj.get_page(obj_page_idx));
            if let Some(pa) = pa {
                let mmu_pa = pa.as_usize() + vma.mmu_offset_in_page(mmu_idx) * MMUPAGE_SIZE;
                let va_aligned = fault_addr & !(MMUPAGE_SIZE - 1);
                let flags = pte_flags_for_vma(vma);
                install_pte(pt_root, va_aligned, mmu_pa, flags);
                vma.set_installed(mmu_idx);
                try_contiguous_promotion(pt_root, vma, mmu_idx);
                stats::MINOR_FAULTS.fetch_add(1, Ordering::Relaxed);
                return FaultResult::HandledMinor;
            }
            // Page was freed — fall through to major fault.
        }

        // Major fault: need to allocate/zero the page.
        let pa = object::with_object(obj_id, |obj| obj.ensure_page(obj_page_idx));
        let pa = match pa {
            Some(pa) => pa,
            None => return FaultResult::Failed, // OOM
        };

        // Zero just the specific 4K MMU sub-page within the allocation page.
        let mmu_pa = pa.as_usize() + vma.mmu_offset_in_page(mmu_idx) * MMUPAGE_SIZE;

        if !vma.is_zeroed(mmu_idx) {
            unsafe {
                core::ptr::write_bytes(mmu_pa as *mut u8, 0, MMUPAGE_SIZE);
            }
            vma.set_zeroed(mmu_idx);
            stats::PAGES_ZEROED.fetch_add(1, Ordering::Relaxed);
        }

        // Install the PTE.
        let va_aligned = fault_addr & !(MMUPAGE_SIZE - 1);
        let flags = pte_flags_for_vma(vma);
        install_pte(pt_root, va_aligned, mmu_pa, flags);
        vma.set_installed(mmu_idx);
        try_contiguous_promotion(pt_root, vma, mmu_idx);
        stats::MAJOR_FAULTS.fetch_add(1, Ordering::Relaxed);
        stats::PTES_INSTALLED.fetch_add(1, Ordering::Relaxed);
        FaultResult::HandledMajor
    })
}

/// Get architecture-specific PTE flags for a VMA.
fn pte_flags_for_vma(vma: &super::vma::Vma) -> u64 {
    use super::vma::VmaProt;
    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::mm;
        match vma.prot {
            VmaProt::ReadOnly => mm::USER_RO_FLAGS,
            VmaProt::ReadWrite => mm::USER_RW_FLAGS,
            VmaProt::ReadExec => mm::USER_RWX_FLAGS, // RX needs execute (no UXN)
            VmaProt::ReadWriteExec => mm::USER_RWX_FLAGS,
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        use crate::arch::riscv64::mm;
        match vma.prot {
            VmaProt::ReadOnly => mm::USER_RO_FLAGS,
            VmaProt::ReadWrite => mm::USER_RW_FLAGS,
            VmaProt::ReadExec => mm::USER_RWX_FLAGS,
            VmaProt::ReadWriteExec => mm::USER_RWX_FLAGS,
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        use crate::arch::x86_64::mm;
        match vma.prot {
            VmaProt::ReadOnly => mm::USER_RO_FLAGS,
            VmaProt::ReadWrite => mm::USER_RW_FLAGS,
            VmaProt::ReadExec => mm::USER_RWX_FLAGS,
            VmaProt::ReadWriteExec => mm::USER_RWX_FLAGS,
        }
    }
}

/// Try to promote a contiguous group of PTEs (AArch64 only).
/// AArch64 contiguous hint groups 16 consecutive 4K L3 PTEs (64K).
/// Checks if all 16 MMU pages in the 64K-aligned group are installed.
fn try_contiguous_promotion(pt_root: usize, vma: &super::vma::Vma, mmu_idx: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        const CONTIG_GROUP: usize = 16; // 16 × 4K = 64K, fixed by AArch64 architecture
        // Compute the start of the 64K-aligned contiguous group.
        let group_start = mmu_idx - (mmu_idx % CONTIG_GROUP);
        // Ensure the entire group falls within this VMA.
        if group_start + CONTIG_GROUP > vma.mmu_page_count() {
            return;
        }
        // Count how many in this group are installed.
        let mut count = 0;
        for i in 0..CONTIG_GROUP {
            if vma.is_installed(group_start + i) {
                count += 1;
            }
        }
        let va_in_group = vma.va_start + group_start * MMUPAGE_SIZE;
        if crate::arch::aarch64::mm::try_contiguous_promotion(pt_root, va_in_group, count) {
            stats::CONTIGUOUS_PROMOTIONS.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (pt_root, vma, mmu_idx);
    }
}

/// Handle a COW (copy-on-write) fault.
///
/// The page is installed (PTE present) but read-only due to sharing.
/// If refcount == 1, just upgrade the PTE to writable.
/// If refcount > 1, copy the page and install the copy as writable.
fn handle_cow_fault(
    pt_root: usize,
    vma: &mut super::vma::Vma,
    obj_id: u32,
    obj_page_idx: usize,
    mmu_idx: usize,
    fault_addr: usize,
) -> FaultResult {
    use super::page::{PhysAddr, PAGE_SIZE, MMUPAGE_SIZE, PAGE_MMUCOUNT};

    let pa = object::with_object(obj_id, |obj| obj.get_page(obj_page_idx));
    let old_pa = match pa {
        Some(pa) => pa,
        None => return FaultResult::Failed,
    };

    let refcount = super::frame::get_ref(old_pa);

    if refcount <= 1 {
        // Exclusively owned — just upgrade PTE to writable.
        let mmu_pa = old_pa.as_usize() + vma.mmu_offset_in_page(mmu_idx) * MMUPAGE_SIZE;
        let va_aligned = fault_addr & !(MMUPAGE_SIZE - 1);
        let flags = pte_flags_for_vma(vma);
        install_pte(pt_root, va_aligned, mmu_pa, flags);
        stats::COW_FAULTS.fetch_add(1, Ordering::Relaxed);
        return FaultResult::HandledCOW;
    }

    // Shared page — allocate a new page, copy, replace.
    let new_pa = match super::phys::alloc_page() {
        Some(pa) => pa,
        None => return FaultResult::Failed, // OOM
    };
    super::frame::set_ref(new_pa, 1);

    // Copy the entire allocation page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            old_pa.as_usize() as *const u8,
            new_pa.as_usize() as *mut u8,
            PAGE_SIZE,
        );
    }

    // Decrement old page's refcount.
    if super::frame::dec_ref(old_pa) == 0 {
        super::phys::free_page(old_pa);
    }

    // Update the object to point to the new page.
    object::with_object(obj_id, |obj| {
        obj.phys_pages[obj_page_idx] = new_pa.as_usize();
    });

    // Reinstall PTEs for all MMU pages in this allocation page that are installed.
    let (ap_start, ap_end) = vma.alloc_page_mmu_range(mmu_idx);
    let flags = pte_flags_for_vma(vma);
    for i in ap_start..ap_end {
        if vma.is_installed(i) {
            let mmu_pa = new_pa.as_usize() + vma.mmu_offset_in_page(i) * MMUPAGE_SIZE;
            let va = vma.va_start + i * MMUPAGE_SIZE;
            install_pte(pt_root, va, mmu_pa, flags);
        }
    }

    stats::COW_FAULTS.fetch_add(1, Ordering::Relaxed);
    stats::COW_PAGES_COPIED.fetch_add(1, Ordering::Relaxed);
    FaultResult::HandledCOW
}

/// Install a PTE via the arch-specific function.
fn install_pte(pt_root: usize, va: usize, pa: usize, flags: u64) {
    #[cfg(target_arch = "aarch64")]
    {
        crate::arch::aarch64::mm::map_single_mmupage(pt_root, va, pa, flags);
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::arch::riscv64::mm::map_single_mmupage(pt_root, va, pa, flags);
    }
    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::x86_64::mm::map_single_mmupage(pt_root, va, pa, flags);
    }
}
