//! Architecture-independent page fault handler.
//!
//! When a page fault occurs in userspace, the arch-specific exception handler
//! extracts the fault address and type, then calls `handle_page_fault`.
//! This module resolves the faulting VMA, allocates physical memory if needed,
//! zeros the specific 4K MMU page, and installs its PTE.
//!
//! The PTE itself is the authority for installed/zeroed state:
//! - PTE valid bit set → page is installed (mapped)
//! - PTE SW_ZEROED bit set → page content has been initialized
//! These replace the per-VMA installed/zeroed bitmaps.

use super::aspace::{self, ASpaceId};
use super::object;
use super::page::{
    MMUPAGE_SIZE, PAGE_SIZE, PAGE_MMUCOUNT,
    SUPERPAGE_SIZE, SUPERPAGE_ALLOC_PAGES, SUPERPAGE_MMU_PAGES, SUPERPAGE_ALIGN_MASK,
};
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
    /// Pager-backed VMA: page allocated, fault recorded, needs pager thread.
    NeedPager { token: u32 },
}

// ---------------------------------------------------------------------------
// Architecture-dispatch PTE query helpers
// ---------------------------------------------------------------------------

/// Read the raw leaf PTE for a VA.
pub fn read_pte_dispatch(pt_root: usize, va: usize) -> u64 {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::read_pte(pt_root, va) }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::read_pte(pt_root, va) }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::read_pte(pt_root, va) }
}

/// Check if a PTE has the valid/present bit set.
pub fn pte_is_present(pte: u64) -> bool {
    pte & 1 != 0 // Bit 0 = Valid/Present on all three architectures
}

/// Check if a PTE has the SW_ZEROED hint bit set.
pub fn pte_has_sw_zeroed(pte: u64) -> bool {
    #[cfg(target_arch = "aarch64")]
    { pte & crate::arch::aarch64::mm::PTE_SW_ZEROED != 0 }
    #[cfg(target_arch = "riscv64")]
    { pte & crate::arch::riscv64::mm::PTE_SW_ZEROED != 0 }
    #[cfg(target_arch = "x86_64")]
    { pte & crate::arch::x86_64::mm::PTE_SW_ZEROED != 0 }
}

/// Return the architecture-specific SW_ZEROED bit value.
pub fn sw_zeroed_bit() -> u64 {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::PTE_SW_ZEROED }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::PTE_SW_ZEROED }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::PTE_SW_ZEROED }
}

/// Evict a 4K MMU page: clear valid bit but preserve SW_ZEROED hint (arch dispatch).
pub fn evict_mmupage_dispatch(pt_root: usize, va: usize) -> usize {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::evict_mmupage(pt_root, va) }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::evict_mmupage(pt_root, va) }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::evict_mmupage(pt_root, va) }
}

/// Clear a PTE entirely — both valid and SW bits (arch dispatch).
pub fn clear_pte_dispatch(pt_root: usize, va: usize) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::clear_pte(pt_root, va); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::clear_pte(pt_root, va); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::clear_pte(pt_root, va); }
}

/// Count installed (present) PTEs in a VMA by walking the page table.
pub fn count_installed_ptes(pt_root: usize, vma: &super::vma::Vma) -> usize {
    let mut count = 0;
    for i in 0..vma.mmu_page_count() {
        let va = vma.va_start + i * MMUPAGE_SIZE;
        if pte_is_present(read_pte_dispatch(pt_root, va)) {
            count += 1;
        }
    }
    count
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
        let va_aligned = fault_addr & !(MMUPAGE_SIZE - 1);

        // Read current PTE state.
        let pte = read_pte_dispatch(pt_root, va_aligned);
        let is_present = pte_is_present(pte);
        let is_zeroed = pte_has_sw_zeroed(pte);

        // Pager-backed VMA: allocate page, record fault, return NeedPager.
        let obj_type = object::with_object(obj_id, |obj| obj.obj_type);
        if obj_type == super::object::ObjectType::Pager {
            let (pa, _) = match object::with_object(obj_id, |obj| obj.ensure_page(obj_page_idx)) {
                Some(r) => r,
                None => return FaultResult::Failed,
            };
            let (file_handle, file_base) = object::with_object(obj_id, |obj| {
                (obj.file_handle, obj.file_base_offset)
            });
            let file_offset = file_base + (obj_page_idx as u64) * (PAGE_SIZE as u64);
            let fault_va = va_aligned;
            let token = match super::pager::record_fault(super::pager::PagerFaultInfo {
                aspace_id,
                thread_id: crate::sched::scheduler::current_thread_id(),
                fault_va,
                phys_addr: pa.as_usize(),
                obj_page_idx,
                obj_id,
                mmu_idx,
                vma_va: vma.va_start,
                file_handle,
                file_offset,
            }) {
                Some(t) => t,
                None => return FaultResult::Failed,
            };
            return FaultResult::NeedPager { token };
        }

        // COW fault check: VMA is writable, PTE is present (but read-only due to COW),
        // and we got a write fault.
        if fault_type == FaultType::Write && vma.prot.writable() && is_present {
            return handle_cow_fault(pt_root, vma, obj_id, obj_page_idx, mmu_idx, fault_addr);
        }

        // Check if this is a minor fault (page content valid but PTE was evicted).
        if is_zeroed && !is_present {
            // SW_ZEROED hint is set but PTE not valid → page was evicted by WSCLOCK.
            // The underlying allocation page should still be resident.
            let pa = object::with_object(obj_id, |obj| obj.get_page(obj_page_idx));
            if let Some(pa) = pa {
                let mmu_pa = pa.as_usize() + vma.mmu_offset_in_page(mmu_idx) * MMUPAGE_SIZE;
                let flags = pte_flags_for_vma(vma) | sw_zeroed_bit();
                install_pte(pt_root, va_aligned, mmu_pa, flags);
                try_contiguous_promotion(pt_root, vma, mmu_idx);
                try_superpage_promotion(pt_root, vma, obj_id, mmu_idx);
                stats::MINOR_FAULTS.fetch_add(1, Ordering::Relaxed);
                return FaultResult::HandledMinor;
            }
            // Page was freed — fall through to major fault.
        }

        // Major fault: need to allocate/zero the page.
        let (pa, pre_zeroed) = match object::with_object(obj_id, |obj| obj.ensure_page(obj_page_idx)) {
            Some(result) => result,
            None => return FaultResult::Failed, // OOM
        };

        // Zero just the specific 4K MMU sub-page within the allocation page.
        let mmu_pa = pa.as_usize() + vma.mmu_offset_in_page(mmu_idx) * MMUPAGE_SIZE;

        if pre_zeroed {
            // Entire PAGE_SIZE page is already zero. Mark all MMU sub-pages as zeroed
            // by setting SW_ZEROED hint on their PTE slots (non-valid entries).
            let (ap_start, ap_end) = vma.alloc_page_mmu_range(mmu_idx);
            for i in ap_start..ap_end {
                if i != mmu_idx {
                    let sub_va = vma.va_start + i * MMUPAGE_SIZE;
                    let sub_pte = read_pte_dispatch(pt_root, sub_va);
                    if !pte_has_sw_zeroed(sub_pte) {
                        // Set SW_ZEROED hint on a not-yet-installed PTE slot.
                        // We write just the SW_ZEROED bit (no valid bit) so the
                        // hardware ignores it but we remember the page is zeroed.
                        set_sw_zeroed_hint(pt_root, sub_va);
                    }
                }
            }
        } else if !is_zeroed {
            unsafe {
                core::ptr::write_bytes(mmu_pa as *mut u8, 0, MMUPAGE_SIZE);
            }
            stats::PAGES_ZEROED.fetch_add(1, Ordering::Relaxed);
        }

        // Install the PTE with SW_ZEROED flag.
        let flags = pte_flags_for_vma(vma) | sw_zeroed_bit();
        install_pte(pt_root, va_aligned, mmu_pa, flags);
        try_contiguous_promotion(pt_root, vma, mmu_idx);
        try_superpage_promotion(pt_root, vma, obj_id, mmu_idx);
        stats::MAJOR_FAULTS.fetch_add(1, Ordering::Relaxed);
        stats::PTES_INSTALLED.fetch_add(1, Ordering::Relaxed);
        FaultResult::HandledMajor
    })
}

/// Public version of pte_flags_for_vma (for WSCLOCK demotion).
pub fn pte_flags_for_vma_pub(vma: &super::vma::Vma) -> u64 {
    pte_flags_for_vma(vma) | sw_zeroed_bit()
}

/// Get architecture-specific PTE flags for a VMA (without SW_ZEROED).
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
            VmaProt::None => 0,
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
            VmaProt::None => 0,
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
            VmaProt::None => 0,
        }
    }
}

/// Try to promote a contiguous group of PTEs (AArch64 only).
/// Checks if all 16 MMU pages in the 64K-aligned group have present PTEs.
fn try_contiguous_promotion(pt_root: usize, vma: &super::vma::Vma, mmu_idx: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        const CONTIG_GROUP: usize = 16;
        let group_start = mmu_idx - (mmu_idx % CONTIG_GROUP);
        if group_start + CONTIG_GROUP > vma.mmu_page_count() {
            return;
        }
        let mut count = 0;
        for i in 0..CONTIG_GROUP {
            let va = vma.va_start + (group_start + i) * MMUPAGE_SIZE;
            if pte_is_present(read_pte_dispatch(pt_root, va)) {
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

/// Try to promote a superpage-aligned region to a superpage.
/// Checks if all MMU pages in the group have present PTEs.
fn try_superpage_promotion(
    pt_root: usize,
    vma: &mut super::vma::Vma,
    obj_id: u64,
    mmu_idx: usize,
) {
    let mmu_count = vma.mmu_page_count();
    if mmu_count < SUPERPAGE_MMU_PAGES {
        return;
    }

    let va_offset_in_vma = mmu_idx * MMUPAGE_SIZE;
    let vma_base = vma.va_start;
    let abs_va = vma_base + va_offset_in_vma;
    let super_va = abs_va & !(SUPERPAGE_ALIGN_MASK);
    if super_va < vma_base || super_va + (SUPERPAGE_MMU_PAGES * MMUPAGE_SIZE) > vma_base + vma.va_len {
        return;
    }

    let group_mmu_start = (super_va - vma_base) / MMUPAGE_SIZE;

    // Check all MMU pages in the group are present by walking PTEs.
    for i in 0..SUPERPAGE_MMU_PAGES {
        let va = vma_base + (group_mmu_start + i) * MMUPAGE_SIZE;
        if !pte_is_present(read_pte_dispatch(pt_root, va)) {
            return;
        }
    }

    // Check: all allocation pages must be allocated and not COW-shared.
    let obj_page_base = vma.obj_page_index(group_mmu_start);
    let (can_promote, cow_group_port) = object::with_object(obj_id, |obj| {
        for p in 0..SUPERPAGE_ALLOC_PAGES {
            let idx = obj_page_base + p;
            if idx >= obj.page_count as usize {
                return (false, 0);
            }
            if obj.pages.get(idx) == 0 {
                return (false, 0);
            }
        }
        (true, obj.cow_group_port)
    });
    if !can_promote {
        return;
    }
    // Check no page in the range is COW-shared.
    if cow_group_port != 0 {
        let super_base = obj_page_base as u32;
        for p in 0..SUPERPAGE_ALLOC_PAGES {
            if super::cowgroup::is_page_shared_in_group(
                cow_group_port, obj_id, super_base, p,
            ) {
                return;
            }
        }
    } else {
        for p in 0..SUPERPAGE_ALLOC_PAGES {
            if object::is_page_shared(obj_id, obj_page_base + p) {
                return;
            }
        }
    }

    let already_contiguous = object::with_object(obj_id, |obj| {
        let first_pa = obj.pages.get(obj_page_base);
        if first_pa & SUPERPAGE_ALIGN_MASK != 0 {
            return false;
        }
        for p in 1..SUPERPAGE_ALLOC_PAGES {
            if obj.pages.get(obj_page_base + p) != first_pa + p * PAGE_SIZE {
                return false;
            }
        }
        true
    });

    if already_contiguous {
        let base_pa = object::with_object(obj_id, |obj| obj.pages.get(obj_page_base));
        let flags = pte_flags_for_vma(vma) | sw_zeroed_bit();

        if install_superpage(pt_root, super_va, base_pa, flags) {
            stats::SUPERPAGE_PROMOTIONS.fetch_add(1, Ordering::Relaxed);
        }
        return;
    }

    let new_block = match alloc_superpage_aligned() {
        Some(pa) => pa,
        None => return,
    };

    object::with_object(obj_id, |obj| {
        for p in 0..SUPERPAGE_ALLOC_PAGES {
            let old_pa = obj.pages.get(obj_page_base + p);
            let new_pa = new_block.as_usize() + p * PAGE_SIZE;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    old_pa as *const u8,
                    new_pa as *mut u8,
                    PAGE_SIZE,
                );
            }
        }
    });

    object::with_object(obj_id, |obj| {
        for p in 0..SUPERPAGE_ALLOC_PAGES {
            let old_pa = super::page::PhysAddr::new(obj.pages.get(obj_page_base + p));
            super::phys::free_page(old_pa);
        }
    });

    object::with_object(obj_id, |obj| {
        for p in 0..SUPERPAGE_ALLOC_PAGES {
            let new_pa = new_block.as_usize() + p * PAGE_SIZE;
            obj.pages.set(obj_page_base + p, new_pa);
        }
    });

    let flags = pte_flags_for_vma(vma) | sw_zeroed_bit();
    if install_superpage(pt_root, super_va, new_block.as_usize(), flags) {
        stats::SUPERPAGE_PROMOTIONS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Public entry point for superpage promotion after eager mapping.
pub fn try_superpage_promotion_eager(
    pt_root: usize,
    vma: &mut super::vma::Vma,
    obj_id: u64,
) {
    let mmu_count = vma.mmu_page_count();
    if mmu_count < SUPERPAGE_MMU_PAGES {
        return;
    }

    let vma_base = vma.va_start;
    let first_super = (vma_base + SUPERPAGE_ALIGN_MASK) & !SUPERPAGE_ALIGN_MASK;
    let vma_end = vma_base + vma.va_len;

    let mut super_va = first_super;
    while super_va + SUPERPAGE_MMU_PAGES * MMUPAGE_SIZE <= vma_end {
        let group_mmu_start = (super_va - vma_base) / MMUPAGE_SIZE;
        try_superpage_promotion(pt_root, vma, obj_id, group_mmu_start);
        super_va += SUPERPAGE_MMU_PAGES * MMUPAGE_SIZE;
    }
}

fn super_alloc_order() -> usize {
    let mut order = 0;
    let mut n = SUPERPAGE_ALLOC_PAGES;
    while n > 1 {
        n >>= 1;
        order += 1;
    }
    order
}

/// Allocate a superpage-aligned contiguous physical region.
/// Returns the base PhysAddr of SUPERPAGE_ALLOC_PAGES contiguous pages,
/// aligned to SUPERPAGE_SIZE. Returns None on failure.
pub fn alloc_superpage_aligned() -> Option<super::page::PhysAddr> {
    use super::page::PhysAddr;

    let order5 = super_alloc_order();

    if let Some(pa) = super::phys::alloc_pages(order5) {
        if pa.as_usize() & SUPERPAGE_ALIGN_MASK == 0 {
            return Some(pa);
        }
        super::phys::free_pages(pa, order5);
    }

    for order in (order5 + 1)..=11 {
        let large = match super::phys::alloc_pages(order) {
            Some(pa) => pa,
            None => continue,
        };
        let large_pa = large.as_usize();
        let large_pages = 1usize << order;

        let aligned_pa = (large_pa + SUPERPAGE_ALIGN_MASK) & !SUPERPAGE_ALIGN_MASK;
        if aligned_pa == large_pa && large_pages >= SUPERPAGE_ALLOC_PAGES {
            let excess = large_pages - SUPERPAGE_ALLOC_PAGES;
            if excess > 0 {
                free_pages_range(
                    PhysAddr::new(large_pa + SUPERPAGE_ALLOC_PAGES * PAGE_SIZE),
                    excess,
                );
            }
            return Some(PhysAddr::new(large_pa));
        }

        let offset_pages = (aligned_pa - large_pa) / PAGE_SIZE;
        let end_page = offset_pages + SUPERPAGE_ALLOC_PAGES;
        if end_page <= large_pages {
            if offset_pages > 0 {
                free_pages_range(PhysAddr::new(large_pa), offset_pages);
            }
            let suffix = large_pages - end_page;
            if suffix > 0 {
                free_pages_range(
                    PhysAddr::new(aligned_pa + SUPERPAGE_ALLOC_PAGES * PAGE_SIZE),
                    suffix,
                );
            }
            return Some(PhysAddr::new(aligned_pa));
        }

        super::phys::free_pages(large, order);
    }
    None
}

/// Free `count` contiguous allocation pages starting at `pa`.
pub fn free_pages_range(pa: super::page::PhysAddr, count: usize) {
    for i in 0..count {
        super::phys::free_page(super::page::PhysAddr::new(pa.as_usize() + i * PAGE_SIZE));
    }
}

fn install_superpage(pt_root: usize, va: usize, pa: usize, flags: u64) -> bool {
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::install_superpage(pt_root, va, pa, flags) }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::install_superpage(pt_root, va, pa, flags) }
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::install_superpage(pt_root, va, pa, flags) }
}

/// Check if a VA is mapped as a superpage (arch dispatch).
pub fn is_superpage_mapped(pt_root: usize, va: usize) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::is_superpage(pt_root, va) }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::is_superpage(pt_root, va) }
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::is_superpage(pt_root, va) }
}

/// Demote a superpage back to base PTEs (arch dispatch).
/// Includes SW_ZEROED in the demoted PTEs since superpage pages are initialized.
pub fn demote_superpage(pt_root: usize, va: usize, flags: u64) -> bool {
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::demote_superpage(pt_root, va, flags) }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::demote_superpage(pt_root, va, flags) }
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::demote_superpage(pt_root, va, flags) }
}

/// Handle a COW (copy-on-write) fault.
///
/// Tries the reservation path first (superpage-aligned contiguous destination)
/// if the object is in a COW sharing group. Falls back to single-page
/// allocation if the reservation cannot be created.
fn handle_cow_fault(
    pt_root: usize,
    vma: &mut super::vma::Vma,
    obj_id: u64,
    obj_page_idx: usize,
    mmu_idx: usize,
    fault_addr: usize,
) -> FaultResult {
    use super::page::{PAGE_SIZE, MMUPAGE_SIZE};
    use super::cowgroup;

    // Read old PA and group port from the object.
    let (old_pa, cow_group_port) = match object::with_object(obj_id, |obj| {
        obj.get_page(obj_page_idx).map(|pa| (pa, obj.cow_group_port))
    }) {
        Some(pair) => pair,
        None => return FaultResult::Failed,
    };

    let shared = if cow_group_port != 0 {
        let super_base = (obj_page_idx & !(SUPERPAGE_ALLOC_PAGES - 1)) as u32;
        let slot = obj_page_idx - super_base as usize;
        super::cowgroup::is_page_shared_in_group(cow_group_port, obj_id, super_base, slot)
    } else {
        object::is_page_shared(obj_id, obj_page_idx)
    };

    if !shared {
        // Exclusively owned — just upgrade PTE to writable.
        let mmu_pa = old_pa.as_usize() + vma.mmu_offset_in_page(mmu_idx) * MMUPAGE_SIZE;
        let va_aligned = fault_addr & !(MMUPAGE_SIZE - 1);
        let flags = pte_flags_for_vma(vma) | sw_zeroed_bit();
        install_pte(pt_root, va_aligned, mmu_pa, flags);
        stats::COW_FAULTS.fetch_add(1, Ordering::Relaxed);
        return FaultResult::HandledCOW;
    }

    // Shared page — need to copy. Try reservation path first.
    let new_pa = if cow_group_port != 0 {
        let super_base = (obj_page_idx & !(SUPERPAGE_ALLOC_PAGES - 1)) as u32;
        let slot = obj_page_idx - super_base as usize;
        // Compute page_count for this extent (may be smaller at object tail).
        let obj_page_count = object::with_object(obj_id, |obj| obj.page_count as usize);
        let extent_end = (super_base as usize + SUPERPAGE_ALLOC_PAGES).min(obj_page_count);
        let page_count = (extent_end - super_base as usize) as u8;

        match cowgroup::find_or_create_reservation(
            cow_group_port, obj_id, super_base, page_count, slot,
        ) {
            Some(rs) if !rs.already_copied => {
                // Copy into the reserved slot.
                let dest = rs.dest_page_pa;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        old_pa.as_usize() as *const u8,
                        dest as *mut u8,
                        PAGE_SIZE,
                    );
                }
                cowgroup::mark_copied(cow_group_port, obj_id, super_base, slot);
                super::page::PhysAddr::new(dest)
            }
            Some(rs) => {
                // Already copied (race or re-fault) — use existing destination.
                super::page::PhysAddr::new(rs.dest_page_pa)
            }
            None => {
                // Reservation failed — fall back to single-page allocation.
                match super::phys::alloc_page() {
                    Some(pa) => {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                old_pa.as_usize() as *const u8,
                                pa.as_usize() as *mut u8,
                                PAGE_SIZE,
                            );
                        }
                        pa
                    }
                    None => return FaultResult::Failed,
                }
            }
        }
    } else {
        // No COW group — single-page allocation (non-fork COW or pager).
        match super::phys::alloc_page() {
            Some(pa) => {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        old_pa.as_usize() as *const u8,
                        pa.as_usize() as *mut u8,
                        PAGE_SIZE,
                    );
                }
                pa
            }
            None => return FaultResult::Failed,
        }
    };

    // Update object's page vector.
    object::with_object(obj_id, |obj| {
        obj.pages.set(obj_page_idx, new_pa.as_usize());
    });

    // Release old page's share — this object no longer references it.
    let remaining = super::frame::dec_ref(old_pa);
    if remaining == 0 {
        super::phys::free_page(old_pa);
    }

    // Reinstall PTEs for all present MMU pages in this allocation page.
    let (ap_start, ap_end) = vma.alloc_page_mmu_range(mmu_idx);
    let flags = pte_flags_for_vma(vma) | sw_zeroed_bit();
    for i in ap_start..ap_end {
        let va = vma.va_start + i * MMUPAGE_SIZE;
        if pte_is_present(read_pte_dispatch(pt_root, va)) {
            let mmu_pa = new_pa.as_usize() + vma.mmu_offset_in_page(i) * MMUPAGE_SIZE;
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

/// Set SW_ZEROED hint on a not-yet-installed PTE slot.
/// Writes just the SW_ZEROED bit (no valid bit) so hardware ignores it.
/// Must create intermediate page table levels if needed.
fn set_sw_zeroed_hint(pt_root: usize, va: usize) {
    // We reuse map_single_mmupage with PA=0 and only the SW_ZEROED flag.
    // Since valid bit is not set, hardware won't use the PA.
    // Actually, map_single_mmupage always sets valid. Instead, we need to
    // install then immediately evict. Simpler: just write the hint directly.
    // But we need intermediate tables to exist. The simplest safe approach:
    // install a dummy PTE and then replace it with just SW_ZEROED.
    //
    // For now, skip this optimization — the zeroed hint for sibling sub-pages
    // within a pre-zeroed allocation page will be set when they fault in.
    // This is slightly less optimal but functionally correct.
    let _ = (pt_root, va);
}
