//! LoongArch64 MMU and page table operations.

use crate::mm::page::SuperpageLevel;
use crate::mm::radix_pt::PteFormat;

// ---------------------------------------------------------------------------
// PTE format
// ---------------------------------------------------------------------------

const PTE_V: u64 = 1 << 0;    // Valid
const PTE_D: u64 = 1 << 1;    // Dirty
const PTE_PLV_USER: u64 = 3 << 2;  // PLV=3 (user mode)
const PTE_MAT_CC: u64 = 1 << 4;    // Coherent Cached
const PTE_G: u64 = 1 << 6;    // Global
const PTE_HUGE: u64 = 1 << 6; // Huge page marker in directory entries

const PFN_MASK: u64 = 0x000F_FFFF_FFFF_F000;

pub const PTE_SW_ZEROED: u64 = 1 << 7;
pub const USER_RWX_FLAGS: u64 = PTE_V | PTE_D | PTE_PLV_USER | PTE_MAT_CC;
pub const USER_RW_FLAGS: u64 = PTE_V | PTE_D | PTE_PLV_USER | PTE_MAT_CC;
pub const USER_RO_FLAGS: u64 = PTE_V | PTE_PLV_USER | PTE_MAT_CC;

// ---------------------------------------------------------------------------
// PteFormat
// ---------------------------------------------------------------------------

pub struct LoongArchPte;

impl PteFormat for LoongArchPte {
    const LEVELS: usize = 4;

    fn va_index(va: usize, level: usize) -> usize {
        const SHIFTS: [usize; 4] = [39, 30, 21, 12];
        (va >> SHIFTS[level]) & 0x1FF
    }

    fn is_valid(entry: u64) -> bool {
        entry & PTE_V != 0
    }

    fn is_table(entry: u64) -> bool {
        // Directory entries pointing to sub-tables: V=1, HUGE=0
        entry & PTE_HUGE == 0
    }

    fn table_pa(entry: u64) -> usize {
        (entry & PFN_MASK) as usize
    }

    fn leaf_pa(entry: u64) -> usize {
        (entry & PFN_MASK) as usize
    }

    fn make_table_entry(table_pa: usize) -> u64 {
        (table_pa as u64 & PFN_MASK) | PTE_V
    }

    fn tlb_invalidate(va: usize) {
        // INVTLB op=0 (invalidate all) for now.
        // TODO: use targeted invalidation (op=0x5 by VA).
        let _ = va;
        unsafe {
            core::arch::asm!("invtlb 0, $zero, $zero");
        }
    }
}

// ---------------------------------------------------------------------------
// HAT interface stubs
// ---------------------------------------------------------------------------

pub fn setup_tables() -> Option<usize> {
    // TODO: create initial page table, configure DMW, PWCL/PWCH
    Some(0)
}

pub fn enable_mmu(_root: usize) {
    // TODO: set CRMD.PG=1, DA=0, configure PGDL
}

pub fn create_user_page_table() -> Option<usize> {
    todo!("loongarch64: create_user_page_table")
}

pub fn free_page_table_tree(_root: usize) {
    todo!("loongarch64: free_page_table_tree")
}

pub fn switch_page_table(_root: usize) {
    todo!("loongarch64: switch_page_table")
}

pub fn boot_page_table_root() -> usize {
    0 // TODO
}

pub fn map_single_mmupage(_root: usize, _va: usize, _pa: usize, _flags: u64) -> bool {
    todo!("loongarch64: map_single_mmupage")
}

pub fn unmap_single_mmupage(_root: usize, _va: usize) -> usize {
    todo!("loongarch64: unmap_single_mmupage")
}

pub fn read_pte(_root: usize, _va: usize) -> u64 {
    todo!("loongarch64: read_pte")
}

pub fn translate_va(_root: usize, _va: usize) -> Option<usize> {
    todo!("loongarch64: translate_va")
}

pub fn evict_mmupage(_root: usize, _va: usize) -> usize {
    todo!("loongarch64: evict_mmupage")
}

pub fn clear_pte(_root: usize, _va: usize) {
    todo!("loongarch64: clear_pte")
}

pub fn read_and_clear_ref_bit(_root: usize, _va: usize) -> bool {
    todo!("loongarch64: read_and_clear_ref_bit")
}

pub fn downgrade_pte_readonly(_root: usize, _va: usize) -> bool {
    todo!("loongarch64: downgrade_pte_readonly")
}

pub fn update_pte_flags(_root: usize, _va: usize, _flags: u64) -> bool {
    todo!("loongarch64: update_pte_flags")
}

pub fn map_user_pages(
    _root: usize, _virt: usize, _phys: usize, _size: usize, _flags: u64,
) -> Option<()> {
    todo!("loongarch64: map_user_pages")
}

pub fn install_superpage(_root: usize, _va: usize, _pa: usize, _flags: u64) -> bool {
    todo!("loongarch64: install_superpage")
}

pub fn is_superpage(_root: usize, _va: usize) -> Option<usize> {
    todo!("loongarch64: is_superpage")
}

pub fn demote_superpage(_root: usize, _va: usize, _flags: u64) -> bool {
    todo!("loongarch64: demote_superpage")
}

pub fn install_superpage_at_level(
    _root: usize, _va: usize, _pa: usize, _flags: u64, _level: &SuperpageLevel,
) -> bool {
    todo!("loongarch64: install_superpage_at_level")
}

pub fn is_superpage_at_level(
    _root: usize, _va: usize, _level: &SuperpageLevel,
) -> Option<usize> {
    todo!("loongarch64: is_superpage_at_level")
}

pub fn demote_superpage_at_level(
    _root: usize, _va: usize, _flags: u64, _level: &SuperpageLevel,
) -> bool {
    todo!("loongarch64: demote_superpage_at_level")
}

pub fn pte_is_present(pte: u64) -> bool {
    pte & PTE_V != 0
}

pub fn pte_has_sw_zeroed(pte: u64) -> bool {
    pte & PTE_SW_ZEROED != 0
}

pub fn sw_zeroed_bit() -> u64 {
    PTE_SW_ZEROED
}
