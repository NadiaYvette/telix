//! WSCLOCK page reclaim algorithm.
//!
//! Per-address-space clock hand advances through VMAs' MMU pages via the
//! VMA B+ tree's leaf sibling pointers. For each installed PTE, reads and
//! clears the hardware reference bit. Unreferenced pages have their PTEs
//! removed (making future accesses cause minor faults). When all MMU pages
//! in an allocation page are unmapped, the physical page is freed.

use super::aspace::{self, ASpaceId};
use super::object;
use super::page::{MMUPAGE_SIZE, PAGE_MMUCOUNT};
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

            if mmu_idx < mmu_count && vma.is_installed(mmu_idx) {
                result.pages_scanned += 1;
                scanned += 1;

                let va = vma.va_start + mmu_idx * MMUPAGE_SIZE;
                let referenced = read_and_clear_ref_bit(pt_root, va);

                if !referenced {
                    unmap_pte(pt_root, va);
                    vma.clear_installed(mmu_idx);
                    result.ptes_cleared += 1;
                    stats::PTES_REMOVED.fetch_add(1, Ordering::Relaxed);

                    // Check if all MMU pages in this allocation page are now unmapped.
                    let alloc_page_start = mmu_idx - (mmu_idx % PAGE_MMUCOUNT);
                    let mut all_unmapped = true;
                    for i in 0..PAGE_MMUCOUNT {
                        if vma.is_installed(alloc_page_start + i) {
                            all_unmapped = false;
                            break;
                        }
                    }

                    if all_unmapped {
                        let page_idx = alloc_page_start / PAGE_MMUCOUNT;
                        let obj_page_idx = vma.object_offset as usize + page_idx;
                        let obj_id = vma.object_id;
                        object::with_object(obj_id, |obj| {
                            if let Some(pa) = obj.get_page(obj_page_idx) {
                                super::phys::free_page(pa);
                                obj.phys_pages[obj_page_idx] = 0;
                            }
                        });
                        for i in 0..PAGE_MMUCOUNT {
                            vma.clear_zeroed(alloc_page_start + i);
                        }
                        result.pages_freed += 1;
                        stats::PAGES_RECLAIMED.fetch_add(1, Ordering::Relaxed);
                    }
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

fn unmap_pte(pt_root: usize, va: usize) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::unmap_single_mmupage(pt_root, va); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::unmap_single_mmupage(pt_root, va); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::unmap_single_mmupage(pt_root, va); }
}
