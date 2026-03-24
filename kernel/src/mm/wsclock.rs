//! WSCLOCK page reclaim algorithm.
//!
//! Per-address-space clock hand advances through VMAs' MMU pages via the
//! VMA B+ tree's leaf sibling pointers. For each installed PTE, reads and
//! clears the hardware reference bit. Unreferenced pages have their PTEs
//! evicted (preserving SW_ZEROED hint). When all MMU pages in an allocation
//! page are unmapped, the physical page is freed.

use super::aspace::{self, ASpaceId};
use super::fault;
use super::object;
use super::page::MMUPAGE_SIZE;
use super::stats;
use core::sync::atomic::Ordering;

/// Result of a WSCLOCK scan pass.
pub struct ScanResult {
    pub pages_scanned: usize,
    pub ptes_cleared: usize,
    pub pages_freed: usize,
}

/// Run the WSCLOCK scan on the given address space, trying to reclaim
/// up to `target_pages` allocation pages.
pub fn scan(aspace_id: ASpaceId, target_pages: usize) -> ScanResult {
    stats::WSCLOCK_SCANS.fetch_add(1, Ordering::Relaxed);

    aspace::with_aspace(aspace_id, |aspace| {
        let pt_root = aspace.page_table_root;
        let mut hand = aspace.clock_hand;
        let mut result = ScanResult {
            pages_scanned: 0,
            ptes_cleared: 0,
            pages_freed: 0,
        };

        let total_mmu_pages = aspace.vmas.total_mmu_pages();
        if total_mmu_pages == 0 {
            return result;
        }

        // Ensure cursor is valid.
        hand.validate(&aspace.vmas);

        let max_scan = total_mmu_pages;
        let mut scanned = 0;

        while result.pages_freed < target_pages && scanned < max_scan {
            let vma = match hand.current_vma() {
                Some(v) => v,
                None => break,
            };

            let mmu_count = vma.mmu_page_count();
            let mmu_idx = hand.mmu_page_offset;

            if mmu_idx < mmu_count {
                let va = vma.va_start + mmu_idx * MMUPAGE_SIZE;
                let pte = fault::read_pte_dispatch(pt_root, va);

                if fault::pte_is_present(pte) {
                    result.pages_scanned += 1;
                    scanned += 1;

                    // If this VA is part of a superpage, demote it first.
                    let super_va = va & !(0x1FFFFF); // 2 MiB-aligned
                    if fault::is_superpage_mapped(pt_root, super_va).is_some() {
                        let flags = fault::pte_flags_for_vma_pub(vma);
                        fault::demote_superpage(pt_root, super_va, flags);
                        stats::SUPERPAGE_DEMOTIONS.fetch_add(1, Ordering::Relaxed);
                    }

                    let referenced = read_and_clear_ref_bit(pt_root, va);

                    if !referenced {
                        // Evict: clear valid bit but preserve SW_ZEROED hint.
                        evict_mmupage(pt_root, va);
                        result.ptes_cleared += 1;
                        stats::PTES_REMOVED.fetch_add(1, Ordering::Relaxed);

                        // Check if all MMU pages in this allocation page are now unmapped.
                        let (ap_start, ap_end) = vma.alloc_page_mmu_range(mmu_idx);
                        let mut all_unmapped = true;
                        for i in ap_start..ap_end {
                            let check_va = vma.va_start + i * MMUPAGE_SIZE;
                            if fault::pte_is_present(fault::read_pte_dispatch(pt_root, check_va)) {
                                all_unmapped = false;
                                break;
                            }
                        }

                        if all_unmapped {
                            let obj_page_idx = vma.obj_page_index(mmu_idx);
                            let obj_id = vma.object_id;
                            object::release_page(obj_id, obj_page_idx);
                            // Clear SW_ZEROED hints since the physical page is freed.
                            for i in ap_start..ap_end {
                                let clear_va = vma.va_start + i * MMUPAGE_SIZE;
                                clear_pte(pt_root, clear_va);
                            }
                            result.pages_freed += 1;
                            stats::PAGES_RECLAIMED.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                } else {
                    scanned += 1;
                }
            } else {
                scanned += 1;
            }

            // Advance the clock hand.
            hand.mmu_page_offset += 1;
            if hand.mmu_page_offset >= mmu_count {
                hand.advance_vma(&aspace.vmas);
            }
        }

        aspace.clock_hand = hand;
        result
    })
}

// Architecture-specific wrappers.

fn read_and_clear_ref_bit(pt_root: usize, va: usize) -> bool {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::read_and_clear_ref_bit(pt_root, va) }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::read_and_clear_ref_bit(pt_root, va) }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::read_and_clear_ref_bit(pt_root, va) }
}

fn evict_mmupage(pt_root: usize, va: usize) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::evict_mmupage(pt_root, va); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::evict_mmupage(pt_root, va); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::evict_mmupage(pt_root, va); }
}

fn clear_pte(pt_root: usize, va: usize) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::clear_pte(pt_root, va); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::clear_pte(pt_root, va); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::clear_pte(pt_root, va); }
}
