//! Architecture-independent page fault handler.
//!
//! When a page fault occurs in userspace, the arch-specific exception handler
//! extracts the fault address and type, then calls `handle_page_fault`.
//! This module resolves the faulting VMA, allocates physical memory if needed,
//! zeros the specific 4K MMU page, and installs its PTE.

use super::aspace::{self, ASpaceId};
use super::object;
use super::page::{MMUPAGE_SIZE, PAGE_MMUCOUNT};
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
        let page_idx = vma.page_index_of(fault_addr);
        let obj_page_idx = vma.object_offset as usize + page_idx;
        let obj_id = vma.object_id;

        // Check if this is a minor fault (page is resident but PTE was removed).
        if vma.is_zeroed(mmu_idx) && !vma.is_installed(mmu_idx) {
            // The MMU page was previously zeroed but its PTE was cleared (by WSCLOCK).
            // The underlying allocation page should still be resident.
            let pa = object::with_object(obj_id, |obj| obj.get_page(obj_page_idx));
            if let Some(pa) = pa {
                let mmu_offset_in_page = mmu_idx % PAGE_MMUCOUNT;
                let mmu_pa = pa.as_usize() + mmu_offset_in_page * MMUPAGE_SIZE;
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
        let mmu_offset_in_page = mmu_idx % PAGE_MMUCOUNT;
        let mmu_pa = pa.as_usize() + mmu_offset_in_page * MMUPAGE_SIZE;

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
