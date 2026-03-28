//! RISC-V Sv39 MMU setup — identity-mapped kernel + user page tables.
//!
//! Uses 3-level page tables (Sv39) with 4 KiB pages.
//! Kernel is identity-mapped via 1 GiB gigapages.
//! User pages are mapped at arbitrary VAs via 4K leaf entries.

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::mm::radix_pt::{self, PteFormat};

/// Kernel page table root, set by BSP after enable_mmu.
static KERNEL_PT_ROOT: AtomicUsize = AtomicUsize::new(0);

/// Get the kernel page table root address.
pub fn kernel_pt_root() -> usize {
    KERNEL_PT_ROOT.load(Ordering::Acquire)
}

/// Sv39 PTE flags.
const PTE_V: u64 = 1 << 0; // Valid
const PTE_R: u64 = 1 << 1; // Read
const PTE_W: u64 = 1 << 2; // Write
const PTE_X: u64 = 1 << 3; // Execute
const PTE_U: u64 = 1 << 4; // User-accessible
const PTE_G: u64 = 1 << 5; // Global
const PTE_A: u64 = 1 << 6; // Accessed
const PTE_D: u64 = 1 << 7; // Dirty
/// Software-defined bit: page content has been initialized (zeroed/filled).
/// Bits [63:54] are reserved for supervisor software in Sv39.
pub const PTE_SW_ZEROED: u64 = 1 << 54;

const MMU_PAGE_SIZE: usize = 4096;

/// Kernel gigapage: RWX, global, accessed, dirty.
const KERN_GIGA: u64 = PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D | PTE_G;
/// Device gigapage: RW only, global.
const DEV_GIGA: u64 = PTE_V | PTE_R | PTE_W | PTE_A | PTE_D | PTE_G;

/// User page flags (public for main.rs).
pub const USER_RWX_FLAGS: u64 = PTE_V | PTE_R | PTE_W | PTE_X | PTE_U | PTE_A | PTE_D;
pub const USER_RW_FLAGS: u64 = PTE_V | PTE_R | PTE_W | PTE_U | PTE_A | PTE_D;
pub const USER_RO_FLAGS: u64 = PTE_V | PTE_R | PTE_U | PTE_A;

/// Create a leaf PTE from a physical address and flags.
fn pte_leaf(phys: usize, flags: u64) -> u64 {
    (((phys >> 12) as u64) << 10) | flags
}

/// Create a non-leaf PTE pointing to a next-level table.
fn pte_table(phys: usize) -> u64 {
    (((phys >> 12) as u64) << 10) | PTE_V
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

/// Set up Sv39 root page table with identity-mapped kernel regions.
///
/// Layout:
///   root[0] = 1 GiB gigapage at 0x0000_0000 (devices: UART, PLIC, CLINT)
///   root[2] = 1 GiB gigapage at 0x8000_0000 (RAM)
///
/// User mappings are added via `map_user_pages`.
pub fn setup_tables() -> Option<usize> {
    let root = alloc_table()?;
    let root_table = root as *mut u64;

    unsafe {
        // root[0]: device memory at 0x0 (1 GiB, RW, no execute, no user).
        *root_table.add(0) = pte_leaf(0x0000_0000, DEV_GIGA);

        // root[2]: RAM at 0x8000_0000 (1 GiB, RWX, no user).
        *root_table.add(2) = pte_leaf(0x8000_0000, KERN_GIGA);
    }

    Some(root)
}

/// Allocate a fresh user page table (alias for setup_tables).
pub fn create_user_page_table() -> Option<usize> {
    setup_tables()
}

/// Add user 4K page mappings to an existing root table.
#[allow(dead_code)]
pub fn map_user_pages(
    root: usize,
    virt: usize,
    phys: usize,
    size: usize,
    flags: u64,
) -> Option<()> {
    let num_pages = (size + MMU_PAGE_SIZE - 1) / MMU_PAGE_SIZE;

    for i in 0..num_pages {
        let va = virt + i * MMU_PAGE_SIZE;
        let pa = phys + i * MMU_PAGE_SIZE;

        let slot = radix_pt::walk_or_create::<Sv39Pte>(root, va)?;
        unsafe {
            *slot = pte_leaf(pa, flags);
        }
    }
    Some(())
}

// ---------------------------------------------------------------------------
// PteFormat implementation for the generic radix walker
// ---------------------------------------------------------------------------

pub struct Sv39Pte;

impl PteFormat for Sv39Pte {
    const LEVELS: usize = 3;

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
        // In Sv39, a non-leaf entry has V=1 and R=W=X=0.
        entry & (PTE_R | PTE_W | PTE_X) == 0
    }

    #[inline]
    fn table_pa(entry: u64) -> usize {
        ((entry >> 10) << 12) as usize
    }

    #[inline]
    fn leaf_pa(entry: u64) -> usize {
        ((entry >> 10) << 12) as usize
    }

    #[inline]
    fn make_table_entry(table_pa: usize) -> u64 {
        pte_table(table_pa)
    }

    #[inline]
    fn tlb_invalidate(va: usize) {
        unsafe {
            core::arch::asm!("sfence.vma {}, zero", in(reg) va);
        }
    }
}

// ---------------------------------------------------------------------------
// Per-MMU-page operations for demand paging
// ---------------------------------------------------------------------------

/// Map a single 4K MMU page at `va` to physical address `pa` with given flags.
pub fn map_single_mmupage(root: usize, va: usize, pa: usize, flags: u64) -> bool {
    let slot = match radix_pt::walk_or_create::<Sv39Pte>(root, va) {
        Some(s) => s,
        None => return false,
    };
    unsafe {
        *slot = pte_leaf(pa, flags);
    }
    Sv39Pte::tlb_invalidate(va);
    true
}

/// Unmap a single 4K MMU page at `va`. Returns the old physical address, or 0.
pub fn unmap_single_mmupage(root: usize, va: usize) -> usize {
    let slot = match radix_pt::walk_to_leaf::<Sv39Pte>(root, va) {
        Some(s) => s,
        None => return 0,
    };
    let entry = unsafe { *slot };
    if entry & PTE_V == 0 {
        return 0;
    }
    let pa = ((entry >> 10) << 12) as usize;
    unsafe {
        *slot = 0;
    }
    Sv39Pte::tlb_invalidate(va);
    pa
}

/// Read the raw leaf PTE for a VA. Returns 0 if any level is missing.
pub fn read_pte(root: usize, va: usize) -> u64 {
    match radix_pt::walk_to_leaf::<Sv39Pte>(root, va) {
        Some(slot) => unsafe { *slot },
        None => 0,
    }
}

/// Evict a 4K MMU page: clear Valid bit but preserve PTE_SW_ZEROED hint.
/// Returns old PA, or 0. Used by WSCLOCK.
pub fn evict_mmupage(root: usize, va: usize) -> usize {
    let slot = match radix_pt::walk_to_leaf::<Sv39Pte>(root, va) {
        Some(s) => s,
        None => return 0,
    };
    let entry = unsafe { *slot };
    if entry & PTE_V == 0 { return 0; }
    let pa = ((entry >> 10) << 12) as usize;
    unsafe {
        *slot = entry & PTE_SW_ZEROED;
    }
    Sv39Pte::tlb_invalidate(va);
    pa
}

/// Clear a PTE entirely (valid + SW bits). Used for madvise_dontneed and cleanup.
pub fn clear_pte(root: usize, va: usize) {
    let slot = match radix_pt::walk_to_leaf::<Sv39Pte>(root, va) {
        Some(s) => s,
        None => return,
    };
    let entry = unsafe { *slot };
    if entry != 0 {
        unsafe { *slot = 0; }
        Sv39Pte::tlb_invalidate(va);
    }
}

/// Read and clear the Accessed bit for the PTE at `va`.
/// Returns true if the page was referenced.
pub fn read_and_clear_ref_bit(root: usize, va: usize) -> bool {
    let slot = match radix_pt::walk_to_leaf::<Sv39Pte>(root, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { *slot };
    if entry & PTE_V == 0 {
        return false;
    }
    let referenced = (entry & PTE_A) != 0;
    if referenced {
        unsafe {
            *slot = entry & !PTE_A;
        }
        Sv39Pte::tlb_invalidate(va);
    }
    referenced
}

/// Translate a user VA to a physical address by walking the Sv39 page table.
/// Returns None if the page is not mapped.
pub fn translate_va(root: usize, va: usize) -> Option<usize> {
    let slot = radix_pt::walk_to_leaf::<Sv39Pte>(root, va)?;
    let entry = unsafe { *slot };
    if entry & PTE_V == 0 {
        return None;
    }
    let pa = ((entry >> 10) << 12) as usize;
    Some(pa | (va & 0xFFF))
}

/// Downgrade a single 4K PTE from writable to read-only (for COW).
/// Returns true if the PTE was present and downgraded.
pub fn downgrade_pte_readonly(root: usize, va: usize) -> bool {
    let slot = match radix_pt::walk_to_leaf::<Sv39Pte>(root, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { *slot };
    if entry & PTE_V == 0 {
        return false;
    }
    unsafe {
        *slot = entry & !PTE_W;
    }
    Sv39Pte::tlb_invalidate(va);
    true
}

/// Update the flags of an existing 4K PTE, keeping the physical address.
/// Returns true if the PTE was present and updated.
pub fn update_pte_flags(root: usize, va: usize, new_flags: u64) -> bool {
    let slot = match radix_pt::walk_to_leaf::<Sv39Pte>(root, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { *slot };
    if entry & PTE_V == 0 {
        return false;
    }
    let ppn = entry & !0x3FF; // Keep PPN bits (10..53), clear flag bits (0..9)
    unsafe {
        *slot = ppn | new_flags;
    }
    Sv39Pte::tlb_invalidate(va);
    true
}

/// Install a 2 MiB megapage at `va` (must be 2 MiB-aligned) backed by `pa` (must be 2 MiB-aligned).
/// In Sv39, a megapage is a leaf entry at L1 level (vpn1).
pub fn install_superpage(root: usize, va: usize, pa: usize, flags: u64) -> bool {
    const SUPER_SIZE: usize = 2 * 1024 * 1024;
    debug_assert!(va & (SUPER_SIZE - 1) == 0);
    debug_assert!(pa & (SUPER_SIZE - 1) == 0);

    let slot = match radix_pt::walk_or_create_to_super::<Sv39Pte>(root, va) {
        Some(s) => s,
        None => return false,
    };

    let old_entry = unsafe { *slot };

    // If there was an L0 table (non-leaf, valid), free it.
    if old_entry & PTE_V != 0 && old_entry & (PTE_R | PTE_W | PTE_X) == 0 {
        let l0_addr = ((old_entry >> 10) << 12) as usize;
        crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(l0_addr));
    }

    // Install megapage leaf entry at L1.
    unsafe {
        *slot = pte_leaf(pa, flags);
    }
    Sv39Pte::tlb_invalidate(va);
    true
}

/// Check if `va` is mapped as a 2 MiB megapage (leaf at L1 level).
pub fn is_superpage(root: usize, va: usize) -> Option<usize> {
    let slot = radix_pt::walk_to_super_slot::<Sv39Pte>(root, va)?;
    let entry = unsafe { *slot };
    if entry & PTE_V != 0 && entry & (PTE_R | PTE_W | PTE_X) != 0 {
        // Leaf at L1 = megapage.
        let pa = ((entry >> 10) << 12) as usize;
        // For megapages, PA[20:0] must be 0 (2 MiB-aligned).
        Some(pa & !0x1FFFFF)
    } else {
        None
    }
}

/// Demote a 2 MiB megapage back to 512 individual 4K PTEs.
pub fn demote_superpage(root: usize, va: usize, flags: u64) -> bool {
    let slot = match radix_pt::walk_to_super_slot::<Sv39Pte>(root, va) {
        Some(s) => s,
        None => return false,
    };

    let entry = unsafe { *slot };
    if entry & PTE_V == 0 || entry & (PTE_R | PTE_W | PTE_X) == 0 {
        return false; // Not a megapage leaf.
    }

    let base_pa = (((entry >> 10) << 12) as usize) & !0x1FFFFF;

    // Allocate an L0 table.
    let l0 = match alloc_table() {
        Some(t) => t,
        None => return false,
    };
    let l0_table = l0 as *mut u64;

    // Fill 512 entries.
    for i in 0..512 {
        let pa = base_pa + i * MMU_PAGE_SIZE;
        unsafe {
            *l0_table.add(i) = pte_leaf(pa, flags);
        }
    }

    // Replace L1 entry with non-leaf pointer to L0.
    unsafe {
        *slot = pte_table(l0);
    }
    Sv39Pte::tlb_invalidate(va);
    true
}

/// Return the kernel page table root (for switching back during exit).
pub fn boot_page_table_root() -> usize {
    KERNEL_PT_ROOT.load(Ordering::Acquire)
}

/// Free all intermediate page table pages for a user page table.
/// Does NOT free leaf physical pages (those are freed by aspace::destroy).
/// Sv39: root → L1 → L0 (leaf). Kernel gigapages at root[0] and root[2]
/// are leaf entries (not tables), so they are automatically skipped.
pub fn free_page_table_tree(root_addr: usize) {
    let root = root_addr as *const u64;
    unsafe {
        for i in 0..512 {
            let entry = *root.add(i);
            if entry & PTE_V != 0 && entry & (PTE_R | PTE_W | PTE_X) == 0 {
                // Non-leaf: this is an L1 table pointer.
                let l1 = ((entry >> 10) << 12) as usize;
                free_sv39_l1(l1);
                crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(l1));
            }
            // Leaf entries (gigapages) are kernel entries — skip.
        }
    }
    crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(root_addr));
}

/// Free L0 (leaf) tables under an Sv39 L1 table.
unsafe fn free_sv39_l1(l1: usize) {
    let table = l1 as *const u64;
    for i in 0..512 {
        let entry = unsafe { *table.add(i) };
        if entry & PTE_V != 0 && entry & (PTE_R | PTE_W | PTE_X) == 0 {
            // Non-leaf: L0 table pointer.
            let l0 = ((entry >> 10) << 12) as usize;
            // L0 is a leaf table — just free it.
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(l0));
        }
    }
}

/// Switch the page table to a different Sv39 root.
/// Used on context switch between tasks with different address spaces.
pub fn switch_page_table(root: usize) {
    let ppn = (root >> 12) as u64;
    let satp = (8u64 << 60) | ppn;
    unsafe {
        core::arch::asm!(
            "sfence.vma",
            "csrw satp, {satp}",
            "sfence.vma",
            satp = in(reg) satp,
        );
    }
}

/// Enable Sv39 paging by writing the satp CSR.
pub fn enable_mmu(root: usize) {
    let ppn = (root >> 12) as u64;
    let satp = (8u64 << 60) | ppn; // Mode 8 = Sv39
    unsafe {
        core::arch::asm!(
            "csrw satp, {}",
            "sfence.vma",
            in(reg) satp,
        );
    }
    KERNEL_PT_ROOT.store(root, Ordering::Release);
}

/// Enable MMU on a secondary hart using the BSP's page table root.
pub fn enable_mmu_secondary() {
    let root = KERNEL_PT_ROOT.load(Ordering::Acquire);
    assert!(root != 0, "BSP must enable MMU before secondaries");
    let ppn = (root >> 12) as u64;
    let satp = (8u64 << 60) | ppn;
    unsafe {
        core::arch::asm!(
            "csrw satp, {}",
            "sfence.vma",
            in(reg) satp,
        );
    }
}
