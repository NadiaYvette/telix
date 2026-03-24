//! Architecture-independent page fault handler.
//!
//! When a page fault occurs in userspace, the arch-specific exception handler
//! extracts the fault address and type, then calls `handle_page_fault`.
//! This module resolves the faulting VMA, allocates physical memory if needed,
//! zeros the specific 4K MMU page, and installs its PTE.

use super::aspace::{self, ASpaceId};
use super::object;
use super::page::{MMUPAGE_SIZE, PAGE_SIZE, PAGE_MMUCOUNT};
use super::stats;
use core::sync::atomic::Ordering;

/// Number of allocation pages in a 2 MiB superpage.
const SUPER_ALLOC_PAGES: usize = (2 * 1024 * 1024) / PAGE_SIZE;
/// Number of MMU pages in a 2 MiB superpage.
const SUPER_MMU_PAGES: usize = 512; // 2 MiB / 4 KiB

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
            let fault_va = fault_addr & !(MMUPAGE_SIZE - 1);
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
            // Entire PAGE_SIZE page is already zero. Mark all MMU sub-pages as zeroed.
            let (ap_start, ap_end) = vma.alloc_page_mmu_range(mmu_idx);
            for i in ap_start..ap_end {
                vma.set_zeroed(i);
            }
        } else if !vma.is_zeroed(mmu_idx) {
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
        try_superpage_promotion(pt_root, vma, obj_id, mmu_idx);
        stats::MAJOR_FAULTS.fetch_add(1, Ordering::Relaxed);
        stats::PTES_INSTALLED.fetch_add(1, Ordering::Relaxed);
        FaultResult::HandledMajor
    })
}

/// Public version of pte_flags_for_vma (for WSCLOCK demotion).
pub fn pte_flags_for_vma_pub(vma: &super::vma::Vma) -> u64 {
    pte_flags_for_vma(vma)
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

/// Try to promote a 2 MiB-aligned region to a superpage.
///
/// After installing a PTE, checks if the surrounding 2 MiB-aligned group of
/// allocation pages is fully populated and exclusively owned (refcount == 1).
/// If so, migrates to a physically contiguous 2 MiB block and installs a
/// single superpage PTE, reducing TLB pressure from 512 entries to 1.
fn try_superpage_promotion(
    pt_root: usize,
    vma: &mut super::vma::Vma,
    obj_id: u32,
    mmu_idx: usize,
) {
    // VMA must span at least SUPER_MMU_PAGES MMU pages.
    let mmu_count = vma.mmu_page_count();
    if mmu_count < SUPER_MMU_PAGES {
        return;
    }

    // Compute the 2 MiB-aligned group of MMU pages within this VMA.
    // The VA must be 2 MiB-aligned for the superpage.
    let va_offset_in_vma = mmu_idx * MMUPAGE_SIZE;
    let vma_base = vma.va_start;
    let abs_va = vma_base + va_offset_in_vma;
    let super_va = abs_va & !(0x1FFFFF); // 2 MiB-aligned
    if super_va < vma_base || super_va + (SUPER_MMU_PAGES * MMUPAGE_SIZE) > vma_base + vma.va_len {
        return; // 2 MiB range doesn't fit within VMA.
    }

    let group_mmu_start = (super_va - vma_base) / MMUPAGE_SIZE;

    // Check all MMU pages in the group are installed.
    for i in 0..SUPER_MMU_PAGES {
        if !vma.is_installed(group_mmu_start + i) {
            return;
        }
    }

    // Check: all allocation pages in the group must be allocated and not COW-shared.
    let obj_page_base = vma.obj_page_index(group_mmu_start);
    let can_promote = object::with_object(obj_id, |obj| {
        for p in 0..SUPER_ALLOC_PAGES {
            let idx = obj_page_base + p;
            if idx >= obj.page_count as usize {
                return false;
            }
            if obj.phys_pages[idx] == 0 {
                return false;
            }
        }
        true
    });
    // Also verify none of these pages are COW-shared.
    if can_promote {
        for p in 0..SUPER_ALLOC_PAGES {
            if object::is_page_shared(obj_id, obj_page_base + p) {
                return;
            }
        }
    }
    if !can_promote {
        return;
    }

    // Check if pages are already contiguous and 2 MiB-aligned.
    let already_contiguous = object::with_object(obj_id, |obj| {
        let first_pa = obj.phys_pages[obj_page_base];
        if first_pa & 0x1FFFFF != 0 {
            return false; // Not 2 MiB-aligned.
        }
        for p in 1..SUPER_ALLOC_PAGES {
            if obj.phys_pages[obj_page_base + p] != first_pa + p * PAGE_SIZE {
                return false;
            }
        }
        true
    });

    if already_contiguous {
        // Already contiguous — just install superpage PTE.
        let base_pa = object::with_object(obj_id, |obj| obj.phys_pages[obj_page_base]);
        let flags = pte_flags_for_vma(vma);

        if install_superpage(pt_root, super_va, base_pa, flags) {
            stats::SUPERPAGE_PROMOTIONS.fetch_add(1, Ordering::Relaxed);
        }
        return;
    }

    // Migration path: allocate a physically contiguous, 2 MiB-aligned block.
    let new_block = match alloc_2m_aligned() {
        Some(pa) => pa,
        None => return,
    };

    // Copy old pages into the contiguous block.
    object::with_object(obj_id, |obj| {
        for p in 0..SUPER_ALLOC_PAGES {
            let old_pa = obj.phys_pages[obj_page_base + p];
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

    // Free old pages (exclusively owned — verified by can_promote check above).
    object::with_object(obj_id, |obj| {
        for p in 0..SUPER_ALLOC_PAGES {
            let old_pa = super::page::PhysAddr::new(obj.phys_pages[obj_page_base + p]);
            super::phys::free_page(old_pa);
        }
    });

    // Update object to point to new contiguous pages.
    object::with_object(obj_id, |obj| {
        for p in 0..SUPER_ALLOC_PAGES {
            let new_pa = new_block.as_usize() + p * PAGE_SIZE;
            obj.phys_pages[obj_page_base + p] = new_pa;
        }
    });

    // Install superpage PTE.
    let flags = pte_flags_for_vma(vma);
    if install_superpage(pt_root, super_va, new_block.as_usize(), flags) {
        stats::SUPERPAGE_PROMOTIONS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Public entry point for superpage promotion after eager mapping.
/// Scans the VMA for 2 MiB-aligned regions that can be promoted.
pub fn try_superpage_promotion_eager(
    pt_root: usize,
    vma: &mut super::vma::Vma,
    obj_id: u32,
) {
    let mmu_count = vma.mmu_page_count();
    if mmu_count < SUPER_MMU_PAGES {
        return;
    }

    // Scan for each 2 MiB-aligned region within the VMA.
    let vma_base = vma.va_start;
    // Find the first 2 MiB-aligned VA at or after vma_base.
    let first_super = (vma_base + 0x1FFFFF) & !0x1FFFFF;
    let vma_end = vma_base + vma.va_len;

    let mut super_va = first_super;
    while super_va + SUPER_MMU_PAGES * MMUPAGE_SIZE <= vma_end {
        let group_mmu_start = (super_va - vma_base) / MMUPAGE_SIZE;
        try_superpage_promotion(pt_root, vma, obj_id, group_mmu_start);
        super_va += SUPER_MMU_PAGES * MMUPAGE_SIZE;
    }
}

/// Compute the buddy allocator order for a 2 MiB superpage block.
fn super_alloc_order() -> usize {
    let mut order = 0;
    let mut n = SUPER_ALLOC_PAGES;
    while n > 1 {
        n >>= 1;
        order += 1;
    }
    order
}

/// Allocate SUPER_ALLOC_PAGES contiguous pages with 2 MiB physical alignment.
///
/// Strategy: allocate a block large enough to contain a 2 MiB-aligned
/// SUPER_ALLOC_PAGES sub-block. Free the excess pages at both ends.
fn alloc_2m_aligned() -> Option<super::page::PhysAddr> {
    use super::page::PhysAddr;

    let order5 = super_alloc_order();

    // Try order-5 first — if base happens to be 2 MiB-aligned, this works.
    if let Some(pa) = super::phys::alloc_pages(order5) {
        if pa.as_usize() & 0x1FFFFF == 0 {
            return Some(pa);
        }
        super::phys::free_pages(pa, order5);
    }

    // Try progressively larger allocations until we find one containing
    // a 2 MiB-aligned SUPER_ALLOC_PAGES sub-range.
    for order in (order5 + 1)..=11 {
        let large = match super::phys::alloc_pages(order) {
            Some(pa) => pa,
            None => continue,
        };
        let large_pa = large.as_usize();
        let large_pages = 1usize << order;

        // Find the 2 MiB-aligned start within this block.
        let aligned_pa = (large_pa + 0x1FFFFF) & !0x1FFFFF;
        if aligned_pa == large_pa && large_pages >= SUPER_ALLOC_PAGES {
            // Block itself is aligned.
            // Free excess at the end.
            let excess = large_pages - SUPER_ALLOC_PAGES;
            if excess > 0 {
                free_pages_range(
                    PhysAddr::new(large_pa + SUPER_ALLOC_PAGES * PAGE_SIZE),
                    excess,
                );
            }
            return Some(PhysAddr::new(large_pa));
        }

        let offset_pages = (aligned_pa - large_pa) / PAGE_SIZE;
        let end_page = offset_pages + SUPER_ALLOC_PAGES;
        if end_page <= large_pages {
            // Found aligned sub-range. Free prefix and suffix.
            if offset_pages > 0 {
                free_pages_range(PhysAddr::new(large_pa), offset_pages);
            }
            let suffix = large_pages - end_page;
            if suffix > 0 {
                free_pages_range(
                    PhysAddr::new(aligned_pa + SUPER_ALLOC_PAGES * PAGE_SIZE),
                    suffix,
                );
            }
            return Some(PhysAddr::new(aligned_pa));
        }

        // Block too small to contain aligned sub-range. Free and try larger.
        super::phys::free_pages(large, order);
    }
    None
}

/// Free `count` contiguous pages starting at `pa`, one page at a time.
fn free_pages_range(pa: super::page::PhysAddr, count: usize) {
    for i in 0..count {
        super::phys::free_page(super::page::PhysAddr::new(pa.as_usize() + i * PAGE_SIZE));
    }
}

/// Install a 2 MiB superpage PTE (arch dispatch).
fn install_superpage(pt_root: usize, va: usize, pa: usize, flags: u64) -> bool {
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::install_superpage(pt_root, va, pa, flags) }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::install_superpage(pt_root, va, pa, flags) }
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::install_superpage(pt_root, va, pa, flags) }
}

/// Check if a VA is mapped as a 2 MiB superpage (arch dispatch).
pub fn is_superpage_mapped(pt_root: usize, va: usize) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::is_superpage(pt_root, va) }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::is_superpage(pt_root, va) }
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::is_superpage(pt_root, va) }
}

/// Demote a 2 MiB superpage back to 512 × 4K PTEs (arch dispatch).
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

    let shared = object::is_page_shared(obj_id, obj_page_idx);

    if !shared {
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

    // Copy the entire allocation page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            old_pa.as_usize() as *const u8,
            new_pa.as_usize() as *mut u8,
            PAGE_SIZE,
        );
    }

    // Update the object to point to the new (private) page.
    // The old PA remains referenced by the sibling object(s).
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
