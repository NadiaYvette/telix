//! MIPS64 software page table and TLB operations.
//!
//! MIPS64 has no hardware page table walker — the OS handles TLB Refill
//! exceptions manually. We use a 3-level radix page table (like Sv39)
//! as a software data structure.
//!
//! Kernel runs in KSEG0 (0xFFFF_FFFF_8000_0000) — no kernel page table
//! entries needed. User mappings only.

use crate::mm::page::SuperpageLevel;
use crate::mm::radix_pt::{self, PteFormat};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Kernel page table root, set by BSP after enable_mmu.
static KERNEL_PT_ROOT: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// PTE format (software-defined)
// ---------------------------------------------------------------------------

const PTE_V: u64 = 1 << 0;       // Valid
const PTE_D: u64 = 1 << 1;       // Dirty (writable)
const PTE_C_CC: u64 = 3 << 2;    // Cache coherency (Cacheable Coherent)
const PTE_SW_REF: u64 = 1 << 11; // Software reference bit (for WSCLOCK)

const PFN_MASK: u64 = 0xFFFF_FFFF_FFFF_F000;

/// Software-defined bit: page content has been initialized.
pub const PTE_SW_ZEROED: u64 = 1 << 10;
/// Software-defined bit: shared page table marker (not-present entry).
/// Same bit as PTE_SW_REF but orthogonal — shared markers have V=0.
const PTE_SHARED: u64 = 1 << 11;

const MMU_PAGE_SIZE: usize = 4096;

/// User page flags. SW_REF set on initial map so WSCLOCK sees page as referenced.
pub const USER_RWX_FLAGS: u64 = PTE_V | PTE_D | PTE_C_CC | PTE_SW_REF;
pub const USER_RW_FLAGS: u64 = PTE_V | PTE_D | PTE_C_CC | PTE_SW_REF;
pub const USER_RO_FLAGS: u64 = PTE_V | PTE_C_CC | PTE_SW_REF;

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

pub struct Mips64Pte;

impl PteFormat for Mips64Pte {
    const LEVELS: usize = 3; // PGD → PMD → PTE (like Sv39)

    #[inline]
    fn va_index(va: usize, level: usize) -> usize {
        const SHIFTS: [usize; 3] = [30, 21, 12];
        (va >> SHIFTS[level]) & 0x1FF
    }

    #[inline]
    fn is_valid(entry: u64) -> bool {
        entry & PTE_V != 0
    }

    #[inline]
    fn is_table(entry: u64) -> bool {
        // Non-leaf entries: V=1, D=0 (directory convention).
        // Leaf entries always have D or other flags set beyond just V.
        entry & PTE_D == 0 && entry & PTE_C_CC == 0
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
    fn tlb_invalidate(_va: usize) {
        // Software TLB: no hardware invalidation needed for page table
        // changes — the TLB refill handler reads the software page table
        // on every miss. We'd need TLBP+TLBWI for entries already in TLB.
        // For correctness with stale TLB entries, do a full flush.
        // TODO: targeted invalidation.
    }

    #[inline]
    fn make_shared_entry(table_pa: usize) -> u64 {
        (table_pa as u64 & PFN_MASK) | PTE_SHARED
    }

    #[inline]
    fn is_shared_entry(entry: u64) -> bool {
        entry & PTE_V == 0 && entry & PTE_SHARED != 0
    }

    #[inline]
    fn shared_entry_pa(entry: u64) -> usize {
        (entry & PFN_MASK) as usize
    }

    #[inline]
    fn make_readonly(entry: u64) -> u64 {
        entry & !PTE_D
    }
}

// ---------------------------------------------------------------------------
// Shared page table support
// ---------------------------------------------------------------------------

/// Ensure the walk path for `va` contains no shared markers (COW-break).
#[inline]
pub fn ensure_path_unshared(root: usize, va: usize) -> bool {
    radix_pt::ensure_path_unshared::<Mips64Pte>(root, va)
}

/// Recursively free a page table subtree, handling shared markers.
pub fn free_shared_user_subtree(table_pa: usize, level: usize) {
    radix_pt::free_shared_subtree::<Mips64Pte>(table_pa, level);
}

/// Share page table entries between parent and child at fork time.
///
/// On MIPS64: kernel uses KSEG0, no kernel entries in user PT.
/// Share all valid table entries at root level.
pub fn clone_shared_tables(parent_root: usize, child_root: usize) {
    use crate::mm::ptshare;

    let parent = parent_root as *mut u64;
    let child = child_root as *mut u64;

    for i in 0..512 {
        let entry = unsafe { *parent.add(i) };
        if Mips64Pte::is_valid(entry) && Mips64Pte::is_table(entry) {
            let sub_pa = Mips64Pte::table_pa(entry);
            ptshare::share(sub_pa);
            let shared = Mips64Pte::make_shared_entry(sub_pa);
            unsafe {
                *parent.add(i) = shared;
                *child.add(i) = shared;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Page table lifecycle
// ---------------------------------------------------------------------------

/// Set up a page table root for user mappings.
/// MIPS64 kernel uses KSEG0 — no kernel entries in PT.
pub fn setup_tables() -> Option<usize> {
    let root = alloc_table()?;
    Some(root)
}

/// Configure TLB and store kernel root.
pub fn enable_mmu(root: usize) {
    // MIPS64: TLB is always active. No "enable" step.
    // Store kernel root for KScratch0 / context switches.
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
    // TODO: write KScratch0 with packed root+ASID, flush TLB
}

/// Free all intermediate page table pages in the tree.
pub fn free_page_table_tree(root_addr: usize) {
    use crate::mm::{ptshare, page::PhysAddr};

    let root = root_addr as *const u64;
    unsafe {
        for i in 0..512 {
            let entry = *root.add(i);
            if Mips64Pte::is_shared_entry(entry) {
                let sub_pa = Mips64Pte::shared_entry_pa(entry);
                let rc = ptshare::unshare(sub_pa);
                if rc == 0 {
                    free_shared_user_subtree(sub_pa, 1);
                    crate::mm::phys::free_page(PhysAddr::new(sub_pa));
                }
            } else if Mips64Pte::is_valid(entry) && Mips64Pte::is_table(entry) {
                let l1 = Mips64Pte::table_pa(entry);
                free_shared_user_subtree(l1, 1);
                crate::mm::phys::free_page(PhysAddr::new(l1));
            }
        }
    }
    crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(root_addr));
}

// ---------------------------------------------------------------------------
// Per-MMU-page operations for demand paging
// ---------------------------------------------------------------------------

pub fn map_single_mmupage(root: usize, va: usize, pa: usize, flags: u64) -> bool {
    let slot = match radix_pt::walk_or_create::<Mips64Pte>(root, va) {
        Some(s) => s,
        None => return false,
    };
    unsafe {
        *slot = pte_leaf(pa, flags);
    }
    Mips64Pte::tlb_invalidate(va);
    true
}

pub fn unmap_single_mmupage(root: usize, va: usize) -> usize {
    let slot = match radix_pt::walk_to_leaf::<Mips64Pte>(root, va) {
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
    Mips64Pte::tlb_invalidate(va);
    pa
}

pub fn read_pte(root: usize, va: usize) -> u64 {
    match radix_pt::walk_to_leaf::<Mips64Pte>(root, va) {
        Some(slot) => unsafe { *slot },
        None => 0,
    }
}

pub fn evict_mmupage(root: usize, va: usize) -> usize {
    let slot = match radix_pt::walk_to_leaf::<Mips64Pte>(root, va) {
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
    Mips64Pte::tlb_invalidate(va);
    pa
}

pub fn clear_pte(root: usize, va: usize) {
    let slot = match radix_pt::walk_to_leaf::<Mips64Pte>(root, va) {
        Some(s) => s,
        None => return,
    };
    let entry = unsafe { *slot };
    if entry != 0 {
        unsafe {
            *slot = 0;
        }
        Mips64Pte::tlb_invalidate(va);
    }
}

pub fn read_and_clear_ref_bit(root: usize, va: usize) -> bool {
    // MIPS64 uses a software reference bit set by TLB refill handler.
    let slot = match radix_pt::walk_to_leaf::<Mips64Pte>(root, va) {
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
        Mips64Pte::tlb_invalidate(va);
    }
    referenced
}

pub fn translate_va(root: usize, va: usize) -> Option<usize> {
    let slot = radix_pt::walk_to_leaf::<Mips64Pte>(root, va)?;
    let entry = unsafe { *slot };
    if entry & PTE_V == 0 {
        return None;
    }
    let pa = (entry & PFN_MASK) as usize;
    Some(pa | (va & 0xFFF))
}

pub fn downgrade_pte_readonly(root: usize, va: usize) -> bool {
    let slot = match radix_pt::walk_to_leaf::<Mips64Pte>(root, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { *slot };
    if entry & PTE_V == 0 {
        return false;
    }
    unsafe {
        *slot = entry & !PTE_D;
    }
    Mips64Pte::tlb_invalidate(va);
    true
}

pub fn update_pte_flags(root: usize, va: usize, new_flags: u64) -> bool {
    let slot = match radix_pt::walk_to_leaf::<Mips64Pte>(root, va) {
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
    Mips64Pte::tlb_invalidate(va);
    true
}

pub fn map_user_pages(
    root: usize, virt: usize, phys: usize, size: usize, flags: u64,
) -> Option<()> {
    let num_pages = (size + MMU_PAGE_SIZE - 1) / MMU_PAGE_SIZE;
    for i in 0..num_pages {
        let va = virt + i * MMU_PAGE_SIZE;
        let pa = phys + i * MMU_PAGE_SIZE;
        let slot = radix_pt::walk_or_create::<Mips64Pte>(root, va)?;
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

    let slot = match radix_pt::walk_or_create_to_level::<Mips64Pte>(
        root, va, level.pt_level as usize,
    ) {
        Some(s) => s,
        None => return false,
    };

    let old_entry = unsafe { *slot };
    if old_entry & PTE_V != 0 && Mips64Pte::is_table(old_entry) {
        let table_addr = (old_entry & PFN_MASK) as usize;
        crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(table_addr));
    }

    unsafe {
        *slot = pte_leaf(pa, flags);
    }
    Mips64Pte::tlb_invalidate(va);
    true
}

pub fn is_superpage_at_level(
    root: usize, va: usize, level: &SuperpageLevel,
) -> Option<usize> {
    let slot = radix_pt::walk_to_level_slot::<Mips64Pte>(
        root, va, level.pt_level as usize,
    )?;
    let entry = unsafe { *slot };
    if entry & PTE_V != 0 && !Mips64Pte::is_table(entry) {
        let pa = (entry & PFN_MASK) as usize & !level.align_mask();
        Some(pa)
    } else {
        None
    }
}

pub fn demote_superpage_at_level(
    root: usize, va: usize, flags: u64, level: &SuperpageLevel,
) -> bool {
    let slot = match radix_pt::walk_to_level_slot::<Mips64Pte>(
        root, va, level.pt_level as usize,
    ) {
        Some(s) => s,
        None => return false,
    };

    let entry = unsafe { *slot };
    if entry & PTE_V == 0 || Mips64Pte::is_table(entry) {
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
    Mips64Pte::tlb_invalidate(va);
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
