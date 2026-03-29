//! LoongArch64 MMU and page table operations.
//!
//! Uses 4-level page tables (PGD/PUD/PMD/PTE) with 4 KiB pages.
//! Kernel uses DMW (Direct Mapped Windows) — no kernel page table entries needed.
//! User pages are mapped via 4K leaf entries.

use crate::mm::page::SuperpageLevel;
use crate::mm::radix_pt::{self, PteFormat};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Kernel page table root, set by BSP after enable_mmu.
static KERNEL_PT_ROOT: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// PTE format
// ---------------------------------------------------------------------------

const PTE_V: u64 = 1 << 0;          // Valid
const PTE_D: u64 = 1 << 1;          // Dirty (writable)
const PTE_PLV_USER: u64 = 3 << 2;   // PLV=3 (user mode)
const PTE_MAT_CC: u64 = 1 << 4;     // Coherent Cached
const PTE_G: u64 = 1 << 6;          // Global
const PTE_HUGE: u64 = 1 << 6;       // Huge page marker (same bit as G)
const PTE_NR: u64 = 1 << 61;        // No-Read (LoongArch RPLV extension)
const PTE_SW_REF: u64 = 1 << 8;     // Software reference bit (for WSCLOCK)

const PFN_SHIFT: u32 = 12;
const PFN_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Software-defined bit: page content has been initialized (zeroed/filled).
pub const PTE_SW_ZEROED: u64 = 1 << 7;

const MMU_PAGE_SIZE: usize = 4096;

/// User page flags. SW_REF set on initial map so WSCLOCK sees page as referenced.
pub const USER_RWX_FLAGS: u64 = PTE_V | PTE_D | PTE_PLV_USER | PTE_MAT_CC | PTE_SW_REF;
pub const USER_RW_FLAGS: u64 = PTE_V | PTE_D | PTE_PLV_USER | PTE_MAT_CC | PTE_NR | PTE_SW_REF;
pub const USER_RO_FLAGS: u64 = PTE_V | PTE_PLV_USER | PTE_MAT_CC | PTE_NR | PTE_SW_REF;

/// Create a leaf PTE from a physical address and flags.
#[inline]
fn pte_leaf(phys: usize, flags: u64) -> u64 {
    (phys as u64 & PFN_MASK) | flags
}

/// Create a non-leaf PTE pointing to a next-level table.
#[inline]
fn pte_table(phys: usize) -> u64 {
    (phys as u64 & PFN_MASK) | PTE_V
}

/// Allocate a zero-filled 4K page for a page table.
fn alloc_table() -> Option<usize> {
    let page = crate::mm::phys::alloc_page()?;
    let addr = page.as_usize();
    unsafe {
        core::ptr::write_bytes(addr as *mut u8, 0, MMU_PAGE_SIZE);
    }
    Some(addr)
}

// ---------------------------------------------------------------------------
// PteFormat
// ---------------------------------------------------------------------------

pub struct LoongArchPte;

impl PteFormat for LoongArchPte {
    const LEVELS: usize = 4;

    #[inline]
    fn va_index(va: usize, level: usize) -> usize {
        const SHIFTS: [usize; 4] = [39, 30, 21, 12];
        (va >> SHIFTS[level]) & 0x1FF
    }

    #[inline]
    fn is_valid(entry: u64) -> bool {
        entry & PTE_V != 0
    }

    #[inline]
    fn is_table(entry: u64) -> bool {
        // Directory entries pointing to sub-tables: V=1, HUGE=0
        // At leaf level, entries have HUGE=0 too but that's fine — the
        // generic walker only calls is_table at non-leaf levels.
        entry & PTE_HUGE == 0
    }

    #[inline]
    fn table_pa(entry: u64) -> usize {
        (entry & PFN_MASK) as usize
    }

    #[inline]
    fn leaf_pa(entry: u64) -> usize {
        (entry & PFN_MASK) as usize
    }

    #[inline]
    fn make_table_entry(table_pa: usize) -> u64 {
        pte_table(table_pa)
    }

    #[inline]
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
// Page table lifecycle
// ---------------------------------------------------------------------------

/// Set up a page table root for user mappings.
/// LoongArch64 kernel uses DMW (Direct Mapped Windows) — no kernel entries in PT.
pub fn setup_tables() -> Option<usize> {
    let root = alloc_table()?;
    Some(root)
}

/// Configure DMW windows and enable paging.
pub fn enable_mmu(root: usize) {
    // DMW0: cached window 0x9000... → PA (for kernel code/data)
    // DMW1: uncached window 0x8000... → PA (for MMIO)
    // TODO: actually configure CSR.DMW0/DMW1, CRMD.PG=1, PGDL, PWCL/PWCH
    // For now this is a stub — tests run with direct PA access.
    KERNEL_PT_ROOT.store(root, Ordering::Release);
}

/// Allocate a fresh user page table.
pub fn create_user_page_table() -> Option<usize> {
    setup_tables()
}

/// Return the kernel page table root.
pub fn boot_page_table_root() -> usize {
    KERNEL_PT_ROOT.load(Ordering::Acquire)
}

/// Switch to a different page table.
pub fn switch_page_table(_root: usize) {
    // TODO: write CSR.PGDL, invtlb
}

/// Free all intermediate page table pages in the tree rooted at `root`.
pub fn free_page_table_tree(root_addr: usize) {
    let root = root_addr as *const u64;
    unsafe {
        for i in 0..512 {
            let entry = *root.add(i);
            if entry & PTE_V != 0 && LoongArchPte::is_table(entry) {
                let l1 = (entry & PFN_MASK) as usize;
                free_subtree_l1(l1);
                crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(l1));
            }
        }
    }
    crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(root_addr));
}

/// Free L2 and L3 tables under an L1 table.
unsafe fn free_subtree_l1(l1: usize) {
    let table = l1 as *const u64;
    for i in 0..512 {
        let entry = unsafe { *table.add(i) };
        if entry & PTE_V != 0 && LoongArchPte::is_table(entry) {
            let l2 = (entry & PFN_MASK) as usize;
            free_subtree_l2(l2);
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(l2));
        }
    }
}

/// Free L3 (leaf) tables under an L2 table.
unsafe fn free_subtree_l2(l2: usize) {
    let table = l2 as *const u64;
    for i in 0..512 {
        let entry = unsafe { *table.add(i) };
        if entry & PTE_V != 0 && LoongArchPte::is_table(entry) {
            let l3 = (entry & PFN_MASK) as usize;
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(l3));
        }
    }
}

// ---------------------------------------------------------------------------
// Per-MMU-page operations for demand paging
// ---------------------------------------------------------------------------

pub fn map_single_mmupage(root: usize, va: usize, pa: usize, flags: u64) -> bool {
    let slot = match radix_pt::walk_or_create::<LoongArchPte>(root, va) {
        Some(s) => s,
        None => return false,
    };
    unsafe {
        *slot = pte_leaf(pa, flags);
    }
    LoongArchPte::tlb_invalidate(va);
    true
}

pub fn unmap_single_mmupage(root: usize, va: usize) -> usize {
    let slot = match radix_pt::walk_to_leaf::<LoongArchPte>(root, va) {
        Some(s) => s,
        None => return 0,
    };
    let entry = unsafe { *slot };
    if entry & PTE_V == 0 {
        return 0;
    }
    let pa = (entry & PFN_MASK) as usize;
    unsafe {
        *slot = 0;
    }
    LoongArchPte::tlb_invalidate(va);
    pa
}

pub fn read_pte(root: usize, va: usize) -> u64 {
    match radix_pt::walk_to_leaf::<LoongArchPte>(root, va) {
        Some(slot) => unsafe { *slot },
        None => 0,
    }
}

pub fn evict_mmupage(root: usize, va: usize) -> usize {
    let slot = match radix_pt::walk_to_leaf::<LoongArchPte>(root, va) {
        Some(s) => s,
        None => return 0,
    };
    let entry = unsafe { *slot };
    if entry & PTE_V == 0 {
        return 0;
    }
    let pa = (entry & PFN_MASK) as usize;
    unsafe {
        *slot = entry & PTE_SW_ZEROED;
    }
    LoongArchPte::tlb_invalidate(va);
    pa
}

pub fn clear_pte(root: usize, va: usize) {
    let slot = match radix_pt::walk_to_leaf::<LoongArchPte>(root, va) {
        Some(s) => s,
        None => return,
    };
    let entry = unsafe { *slot };
    if entry != 0 {
        unsafe {
            *slot = 0;
        }
        LoongArchPte::tlb_invalidate(va);
    }
}

pub fn read_and_clear_ref_bit(root: usize, va: usize) -> bool {
    // LoongArch: use software reference bit (PTE_SW_REF).
    // Set on initial map and by TLB refill handler (future).
    // WSCLOCK clears it; if still clear on next scan, page is unreferenced.
    let slot = match radix_pt::walk_to_leaf::<LoongArchPte>(root, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { *slot };
    if entry & PTE_V == 0 {
        return false;
    }
    let referenced = (entry & PTE_SW_REF) != 0;
    if referenced {
        unsafe {
            *slot = entry & !PTE_SW_REF;
        }
        LoongArchPte::tlb_invalidate(va);
    }
    referenced
}

pub fn translate_va(root: usize, va: usize) -> Option<usize> {
    let slot = radix_pt::walk_to_leaf::<LoongArchPte>(root, va)?;
    let entry = unsafe { *slot };
    if entry & PTE_V == 0 {
        return None;
    }
    let pa = (entry & PFN_MASK) as usize;
    Some(pa | (va & 0xFFF))
}

pub fn downgrade_pte_readonly(root: usize, va: usize) -> bool {
    let slot = match radix_pt::walk_to_leaf::<LoongArchPte>(root, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { *slot };
    if entry & PTE_V == 0 {
        return false;
    }
    // Clear Dirty bit to make read-only.
    unsafe {
        *slot = entry & !PTE_D;
    }
    LoongArchPte::tlb_invalidate(va);
    true
}

pub fn update_pte_flags(root: usize, va: usize, new_flags: u64) -> bool {
    let slot = match radix_pt::walk_to_leaf::<LoongArchPte>(root, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { *slot };
    if entry & PTE_V == 0 {
        return false;
    }
    let pa_and_sw = (entry & PFN_MASK) | (entry & PTE_SW_ZEROED);
    unsafe {
        *slot = pa_and_sw | new_flags;
    }
    LoongArchPte::tlb_invalidate(va);
    true
}

pub fn map_user_pages(
    root: usize, virt: usize, phys: usize, size: usize, flags: u64,
) -> Option<()> {
    let num_pages = (size + MMU_PAGE_SIZE - 1) / MMU_PAGE_SIZE;
    for i in 0..num_pages {
        let va = virt + i * MMU_PAGE_SIZE;
        let pa = phys + i * MMU_PAGE_SIZE;
        let slot = radix_pt::walk_or_create::<LoongArchPte>(root, va)?;
        unsafe {
            *slot = pte_leaf(pa, flags);
        }
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Superpage operations
// ---------------------------------------------------------------------------

pub fn install_superpage(root: usize, va: usize, pa: usize, flags: u64) -> bool {
    install_superpage_at_level(root, va, pa, flags, &crate::mm::page::SUPERPAGE_LEVELS[0])
}

pub fn is_superpage(root: usize, va: usize) -> Option<usize> {
    is_superpage_at_level(root, va, &crate::mm::page::SUPERPAGE_LEVELS[0])
}

pub fn demote_superpage(root: usize, va: usize, flags: u64) -> bool {
    demote_superpage_at_level(root, va, flags, &crate::mm::page::SUPERPAGE_LEVELS[0])
}

pub fn install_superpage_at_level(
    root: usize, va: usize, pa: usize, flags: u64, level: &SuperpageLevel,
) -> bool {
    debug_assert!(va & level.align_mask() == 0);
    debug_assert!(pa & level.align_mask() == 0);

    let slot = match radix_pt::walk_or_create_to_level::<LoongArchPte>(
        root, va, level.pt_level as usize,
    ) {
        Some(s) => s,
        None => return false,
    };

    let old_entry = unsafe { *slot };
    if old_entry & PTE_V != 0 && LoongArchPte::is_table(old_entry) {
        let table_addr = (old_entry & PFN_MASK) as usize;
        crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(table_addr));
    }

    unsafe {
        *slot = pte_leaf(pa, flags | PTE_HUGE);
    }
    LoongArchPte::tlb_invalidate(va);
    true
}

pub fn is_superpage_at_level(
    root: usize, va: usize, level: &SuperpageLevel,
) -> Option<usize> {
    let slot = radix_pt::walk_to_level_slot::<LoongArchPte>(
        root, va, level.pt_level as usize,
    )?;
    let entry = unsafe { *slot };
    if entry & PTE_V != 0 && !LoongArchPte::is_table(entry) {
        let pa = (entry & PFN_MASK) as usize & !level.align_mask();
        Some(pa)
    } else {
        None
    }
}

pub fn demote_superpage_at_level(
    root: usize, va: usize, flags: u64, level: &SuperpageLevel,
) -> bool {
    let slot = match radix_pt::walk_to_level_slot::<LoongArchPte>(
        root, va, level.pt_level as usize,
    ) {
        Some(s) => s,
        None => return false,
    };

    let entry = unsafe { *slot };
    if entry & PTE_V == 0 || LoongArchPte::is_table(entry) {
        return false;
    }

    let base_pa = (entry & PFN_MASK) as usize & !level.align_mask();
    let sub_size = level.size / 512;

    let new_table = match alloc_table() {
        Some(t) => t,
        None => return false,
    };
    let table_ptr = new_table as *mut u64;

    for i in 0..512usize {
        let pa = base_pa + i * sub_size;
        unsafe {
            *table_ptr.add(i) = pte_leaf(pa, flags);
        }
    }

    unsafe {
        *slot = pte_table(new_table);
    }
    LoongArchPte::tlb_invalidate(va);
    true
}

// ---------------------------------------------------------------------------
// PTE query helpers
// ---------------------------------------------------------------------------

pub fn pte_is_present(pte: u64) -> bool {
    pte & PTE_V != 0
}

pub fn pte_has_sw_zeroed(pte: u64) -> bool {
    pte & PTE_SW_ZEROED != 0
}

pub fn sw_zeroed_bit() -> u64 {
    PTE_SW_ZEROED
}
