//! WSCLOCK page reclaim algorithm.
//!
//! Per-address-space clock hand advances through VMAs' MMU pages.
//! For each installed PTE, reads and clears the hardware reference bit.
//! Unreferenced pages have their PTEs removed (making future accesses
//! cause minor faults). When all MMU pages in an allocation page are
//! unmapped, the physical page is freed.

use super::aspace::{self, ASpaceId, ClockHand};
use super::object;
use super::page::{MMUPAGE_SIZE, PAGE_MMUCOUNT, PAGE_SIZE};
use super::stats;
use super::vma::Vma;
use core::sync::atomic::Ordering;

/// Result of a WSCLOCK scan pass.
pub struct ScanResult {
    pub pages_scanned: usize,
    pub ptes_cleared: usize,
    pub pages_freed: usize,
}

/// Run the WSCLOCK scan on the given address space, trying to reclaim
/// up to `target_pages` allocation pages.
///
/// Returns statistics about the scan.
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

        // Scan at most all MMU pages across all VMAs to avoid infinite looping.
        let total_mmu_pages = count_total_mmu_pages(&aspace.vmas);
        if total_mmu_pages == 0 {
            return result;
        }
        let max_scan = total_mmu_pages;
        let mut scanned = 0;

        while result.pages_freed < target_pages && scanned < max_scan {
            // Find next active VMA starting from hand position.
            let (vma_idx, vma_mmu_count) = match find_active_vma(&aspace.vmas, hand.vma_idx) {
                Some(v) => v,
                None => break, // No active VMAs
            };

            // If we wrapped to a different VMA, reset offset.
            if vma_idx != hand.vma_idx {
                hand.vma_idx = vma_idx;
                hand.mmu_page_offset = 0;
            }

            let vma = &mut aspace.vmas[vma_idx];
            let mmu_idx = hand.mmu_page_offset;

            if mmu_idx < vma_mmu_count && vma.is_installed(mmu_idx) {
                result.pages_scanned += 1;
                scanned += 1;

                let va = vma.va_start + mmu_idx * MMUPAGE_SIZE;
                let referenced = read_and_clear_ref_bit(pt_root, va);

                if !referenced {
                    // Unreferenced — unmap the PTE.
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
                        // Free the physical page.
                        let page_idx = alloc_page_start / PAGE_MMUCOUNT;
                        let obj_page_idx = vma.object_offset as usize + page_idx;
                        let obj_id = vma.object_id;
                        object::with_object(obj_id, |obj| {
                            if let Some(pa) = obj.get_page(obj_page_idx) {
                                super::phys::free_page(pa);
                                obj.phys_pages[obj_page_idx] = 0;
                            }
                        });
                        // Clear zeroed bits for this allocation page's MMU pages.
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
            if hand.mmu_page_offset >= vma_mmu_count {
                hand.mmu_page_offset = 0;
                hand.vma_idx = next_vma_idx(&aspace.vmas, vma_idx);
            }
        }

        aspace.clock_hand = hand;
        result
    })
}

/// Count total MMU pages across all active VMAs.
fn count_total_mmu_pages(vmas: &[Vma]) -> usize {
    let mut total = 0;
    for vma in vmas {
        if vma.active {
            total += vma.mmu_page_count();
        }
    }
    total
}

/// Find the next active VMA starting from `start_idx` (wrapping around).
/// Returns (vma_index, mmu_page_count).
fn find_active_vma(vmas: &[Vma], start_idx: usize) -> Option<(usize, usize)> {
    let len = vmas.len();
    for offset in 0..len {
        let idx = (start_idx + offset) % len;
        if vmas[idx].active {
            return Some((idx, vmas[idx].mmu_page_count()));
        }
    }
    None
}

/// Get the index of the next VMA after `current` (wrapping).
fn next_vma_idx(vmas: &[Vma], current: usize) -> usize {
    let len = vmas.len();
    for offset in 1..=len {
        let idx = (current + offset) % len;
        if vmas[idx].active {
            return idx;
        }
    }
    current // Only one active VMA
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
