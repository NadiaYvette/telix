//! MIPS64 software page table and TLB operations.
//!
//! MIPS64 has no hardware page table walker — the OS handles TLB Refill
//! exceptions manually. We use a 3-level radix page table (like Sv39)
//! as a software data structure.

use crate::mm::page::SuperpageLevel;
use crate::mm::radix_pt::PteFormat;

// ---------------------------------------------------------------------------
// PTE format (software-defined — never loaded into HW directly)
// ---------------------------------------------------------------------------

const PTE_G: u64 = 1 << 3;     // Global
const PTE_V: u64 = 1 << 4;     // Valid
const PTE_D: u64 = 1 << 5;     // Dirty (writable)
const PTE_C_MASK: u64 = 7 << 6; // Cache coherency
const PTE_C_CC: u64 = 3 << 6;  // Cacheable coherent
const PTE_SW_REF: u64 = 1 << 11; // Software reference bit (for WSCLOCK)

const PFN_MASK: u64 = 0x000F_FFFF_FFFF_F000;

pub const PTE_SW_ZEROED: u64 = 1 << 10;
pub const USER_RWX_FLAGS: u64 = PTE_V | PTE_D | PTE_C_CC;
pub const USER_RW_FLAGS: u64 = PTE_V | PTE_D | PTE_C_CC;
pub const USER_RO_FLAGS: u64 = PTE_V | PTE_C_CC;

// ---------------------------------------------------------------------------
// PteFormat
// ---------------------------------------------------------------------------

pub struct Mips64Pte;

impl PteFormat for Mips64Pte {
    const LEVELS: usize = 3; // PGD → PMD → PTE (like Sv39)

    fn va_index(va: usize, level: usize) -> usize {
        const SHIFTS: [usize; 3] = [30, 21, 12];
        (va >> SHIFTS[level]) & 0x1FF
    }

    fn is_valid(entry: u64) -> bool {
        entry & PTE_V != 0
    }

    fn is_table(entry: u64) -> bool {
        // Non-leaf entries: V=1, D=0 (directory convention)
        entry & PTE_D == 0
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
        // Software TLB: invalidate by probing and writing invalid entry.
        let _ = va;
        // TODO: TLBP + TLBWI with invalid entry, or full flush via loop.
    }
}

// ---------------------------------------------------------------------------
// HAT interface stubs
// ---------------------------------------------------------------------------

pub fn setup_tables() -> Option<usize> {
    // TODO: allocate root page table, pack ASID
    Some(0)
}

pub fn enable_mmu(_root: usize) {
    // MIPS64: no "enable" step — TLB is always active.
    // Configure Status register, set KScratch0 = packed root.
}

pub fn create_user_page_table() -> Option<usize> {
    todo!("mips64: create_user_page_table")
}

pub fn free_page_table_tree(_root: usize) {
    todo!("mips64: free_page_table_tree")
}

pub fn switch_page_table(_root: usize) {
    todo!("mips64: switch_page_table")
}

pub fn boot_page_table_root() -> usize {
    0 // TODO
}

pub fn map_single_mmupage(_root: usize, _va: usize, _pa: usize, _flags: u64) -> bool {
    todo!("mips64: map_single_mmupage")
}

pub fn unmap_single_mmupage(_root: usize, _va: usize) -> usize {
    todo!("mips64: unmap_single_mmupage")
}

pub fn read_pte(_root: usize, _va: usize) -> u64 {
    todo!("mips64: read_pte")
}

pub fn translate_va(_root: usize, _va: usize) -> Option<usize> {
    todo!("mips64: translate_va")
}

pub fn evict_mmupage(_root: usize, _va: usize) -> usize {
    todo!("mips64: evict_mmupage")
}

pub fn clear_pte(_root: usize, _va: usize) {
    todo!("mips64: clear_pte")
}

pub fn read_and_clear_ref_bit(_root: usize, _va: usize) -> bool {
    todo!("mips64: read_and_clear_ref_bit")
}

pub fn downgrade_pte_readonly(_root: usize, _va: usize) -> bool {
    todo!("mips64: downgrade_pte_readonly")
}

pub fn update_pte_flags(_root: usize, _va: usize, _flags: u64) -> bool {
    todo!("mips64: update_pte_flags")
}

pub fn map_user_pages(
    _root: usize, _virt: usize, _phys: usize, _size: usize, _flags: u64,
) -> Option<()> {
    todo!("mips64: map_user_pages")
}

pub fn install_superpage(_root: usize, _va: usize, _pa: usize, _flags: u64) -> bool {
    todo!("mips64: install_superpage")
}

pub fn is_superpage(_root: usize, _va: usize) -> Option<usize> {
    todo!("mips64: is_superpage")
}

pub fn demote_superpage(_root: usize, _va: usize, _flags: u64) -> bool {
    todo!("mips64: demote_superpage")
}

pub fn install_superpage_at_level(
    _root: usize, _va: usize, _pa: usize, _flags: u64, _level: &SuperpageLevel,
) -> bool {
    todo!("mips64: install_superpage_at_level")
}

pub fn is_superpage_at_level(
    _root: usize, _va: usize, _level: &SuperpageLevel,
) -> Option<usize> {
    todo!("mips64: is_superpage_at_level")
}

pub fn demote_superpage_at_level(
    _root: usize, _va: usize, _flags: u64, _level: &SuperpageLevel,
) -> bool {
    todo!("mips64: demote_superpage_at_level")
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
