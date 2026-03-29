//! x86-64 page table management for userspace support.
//!
//! The boot code (boot.S) already sets up identity-mapped 1 GiB pages
//! for 0-4 GiB in the boot PML4. This module adds user page mappings
//! to the existing page table hierarchy.
//!
//! User pages are placed at PML4 index 1+ (VA >= 0x80_0000_0000) to
//! avoid conflicting with the kernel's 1 GiB page entries.

/// x86-64 page table entry flags.
const PTE_P: u64 = 1 << 0; // Present
const PTE_RW: u64 = 1 << 1; // Read/Write
const PTE_US: u64 = 1 << 2; // User/Supervisor
const PTE_PS: u64 = 1 << 7; // Page Size (2M/1G large page)
const PTE_NX: u64 = 1u64 << 63; // No Execute
/// Software-defined bit: page content has been initialized (zeroed/filled).
/// AVL bit 9 (bits 9-11 are available to software in x86-64 PTEs).
pub const PTE_SW_ZEROED: u64 = 1 << 9;
/// Software-defined bit: shared page table marker (not-present entry).
const PTE_SHARED: u64 = 1 << 11;

const MMU_PAGE_SIZE: usize = 4096;

/// Boot PML4 address, saved during init so create_user_page_table always
/// copies from the original kernel page table (not the current CR3 which
/// may be a user process's page table during sys_spawn).
static BOOT_PML4: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

use crate::mm::radix_pt::{self, PteFormat};

/// User page flags (public for main.rs).
pub const USER_RWX_FLAGS: u64 = PTE_P | PTE_RW | PTE_US;
pub const USER_RW_FLAGS: u64 = PTE_P | PTE_RW | PTE_US | PTE_NX;
pub const USER_RO_FLAGS: u64 = PTE_P | PTE_US | PTE_NX; // No PTE_RW = read-only

/// Allocate a zero-filled 4K page for a page table.
fn alloc_table() -> Option<usize> {
    let page = crate::mm::phys::alloc_page()?;
    let addr = page.as_usize();
    unsafe {
        core::ptr::write_bytes(addr as *mut u8, 0, MMU_PAGE_SIZE);
    }
    Some(addr)
}

/// Get the current PML4 from CR3. The kernel already has identity-mapped
/// page tables set up by boot.S.
pub fn setup_tables() -> Option<usize> {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3);
    }
    let pml4 = (cr3 & !0xFFF) as usize;
    // Save boot PML4 for create_user_page_table.
    BOOT_PML4.store(pml4, core::sync::atomic::Ordering::Release);
    Some(pml4)
}

/// Add user 4K page mappings to the existing PML4.
///
/// Non-leaf entries are created with U/S=1 so the CPU allows user-mode
/// page walks through the hierarchy.
#[allow(dead_code)]
pub fn map_user_pages(
    pml4: usize,
    virt: usize,
    phys: usize,
    size: usize,
    flags: u64,
) -> Option<()> {
    let num_pages = (size + MMU_PAGE_SIZE - 1) / MMU_PAGE_SIZE;

    for i in 0..num_pages {
        let va = virt + i * MMU_PAGE_SIZE;
        let pa = phys + i * MMU_PAGE_SIZE;

        let slot = radix_pt::walk_or_create::<X86Pte>(pml4, va)?;
        unsafe {
            *slot = (pa as u64 & !0xFFF) | flags;
        }
    }
    Some(())
}

// ---------------------------------------------------------------------------
// PteFormat implementation for the generic radix walker
// ---------------------------------------------------------------------------

pub struct X86Pte;

impl crate::mm::radix_pt::PteFormat for X86Pte {
    const LEVELS: usize = 4;

    #[inline]
    fn va_index(va: usize, level: usize) -> usize {
        const SHIFTS: [usize; 4] = [39, 30, 21, 12];
        (va >> SHIFTS[level]) & 0x1FF
    }

    #[inline]
    fn is_valid(entry: u64) -> bool {
        entry & PTE_P != 0
    }

    #[inline]
    fn is_table(entry: u64) -> bool {
        // In x86-64, a non-leaf entry has P=1 and PS=0.
        entry & PTE_PS == 0
    }

    #[inline]
    fn table_pa(entry: u64) -> usize {
        (entry & 0x000F_FFFF_FFFF_F000) as usize
    }

    #[inline]
    fn leaf_pa(entry: u64) -> usize {
        (entry & 0x000F_FFFF_FFFF_F000) as usize
    }

    #[inline]
    fn make_table_entry(table_pa: usize) -> u64 {
        (table_pa as u64) | PTE_P | PTE_RW | PTE_US
    }

    #[inline]
    fn tlb_invalidate(va: usize) {
        unsafe {
            core::arch::asm!("invlpg [{}]", in(reg) va);
        }
    }

    #[inline]
    fn make_shared_entry(table_pa: usize) -> u64 {
        // Not present (P=0), PTE_SHARED set, PA encoded.
        (table_pa as u64 & 0x000F_FFFF_FFFF_F000) | PTE_SHARED
    }

    #[inline]
    fn is_shared_entry(entry: u64) -> bool {
        entry & PTE_P == 0 && entry & PTE_SHARED != 0
    }

    #[inline]
    fn shared_entry_pa(entry: u64) -> usize {
        (entry & 0x000F_FFFF_FFFF_F000) as usize
    }

    #[inline]
    fn make_readonly(entry: u64) -> u64 {
        entry & !PTE_RW
    }
}

// ---------------------------------------------------------------------------
// Shared page table support
// ---------------------------------------------------------------------------

/// Ensure the walk path for `va` contains no shared markers (COW-break).
#[inline]
pub fn ensure_path_unshared(root: usize, va: usize, fg: *mut crate::mm::ptshare::ForkGroup) -> bool {
    radix_pt::ensure_path_unshared::<X86Pte>(root, va, fg)
}

/// Recursively free a page table subtree, handling shared markers.
pub fn free_shared_user_subtree(table_pa: usize, level: usize, fg: *mut crate::mm::ptshare::ForkGroup) {
    radix_pt::free_shared_subtree::<X86Pte>(table_pa, level, fg);
}

/// Share page table entries between parent and child at fork time.
///
/// On x86-64:
/// - PML4[0] → PDPT: entries 0-3 are kernel gigapages (skip), 4+ are user (share).
/// - PML4[1..512]: share entire entries (all user).
pub fn clone_shared_tables(parent_root: usize, child_root: usize, fg: *mut crate::mm::ptshare::ForkGroup) {
    use crate::mm::ptshare::ForkGroup;

    let parent_pml4 = parent_root as *mut u64;
    let child_pml4 = child_root as *mut u64;

    // PML4[0]: both have deep-copied PDPTs. Share PDPT[4+] (user entries).
    let parent_e0 = unsafe { *parent_pml4 };
    let child_e0 = unsafe { *child_pml4 };
    if X86Pte::is_valid(parent_e0)
        && X86Pte::is_table(parent_e0)
        && X86Pte::is_valid(child_e0)
        && X86Pte::is_table(child_e0)
    {
        let parent_pdpt = X86Pte::table_pa(parent_e0) as *mut u64;
        let child_pdpt = X86Pte::table_pa(child_e0) as *mut u64;
        for i in 4..512 {
            let entry = unsafe { *parent_pdpt.add(i) };
            if X86Pte::is_valid(entry) && X86Pte::is_table(entry) {
                let sub_pa = X86Pte::table_pa(entry);
                ForkGroup::share(fg, sub_pa);
                let shared = X86Pte::make_shared_entry(sub_pa);
                unsafe {
                    *parent_pdpt.add(i) = shared;
                    *child_pdpt.add(i) = shared;
                }
            }
        }
    }

    // PML4[1..512]: share directly (all user).
    for i in 1..512 {
        let entry = unsafe { *parent_pml4.add(i) };
        if X86Pte::is_valid(entry) && X86Pte::is_table(entry) {
            let sub_pa = X86Pte::table_pa(entry);
            ForkGroup::share(fg, sub_pa);
            let shared = X86Pte::make_shared_entry(sub_pa);
            unsafe {
                *parent_pml4.add(i) = shared;
                *child_pml4.add(i) = shared;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-MMU-page operations for demand paging
// ---------------------------------------------------------------------------

/// x86-64 PTE Accessed bit.
const PTE_A: u64 = 1 << 5;

/// Map a single 4K MMU page at `va` to physical address `pa` with given flags.
pub fn map_single_mmupage(pml4: usize, va: usize, pa: usize, flags: u64) -> bool {
    let slot = match radix_pt::walk_or_create::<X86Pte>(pml4, va) {
        Some(s) => s,
        None => return false,
    };
    unsafe {
        *slot = (pa as u64 & !0xFFF) | flags;
    }
    X86Pte::tlb_invalidate(va);
    true
}

/// Unmap a single 4K MMU page at `va`. Returns the old physical address, or 0.
pub fn unmap_single_mmupage(pml4: usize, va: usize) -> usize {
    let slot = match radix_pt::walk_to_leaf::<X86Pte>(pml4, va) {
        Some(s) => s,
        None => return 0,
    };
    let entry = unsafe { *slot };
    if entry & PTE_P == 0 {
        return 0;
    }
    let pa = X86Pte::leaf_pa(entry);
    unsafe {
        *slot = 0;
    }
    X86Pte::tlb_invalidate(va);
    pa
}

/// Read the raw leaf PTE for a VA. Returns 0 if any level is missing.
pub fn read_pte(pml4: usize, va: usize) -> u64 {
    match radix_pt::walk_to_leaf::<X86Pte>(pml4, va) {
        Some(slot) => unsafe { *slot },
        None => 0,
    }
}

/// Evict a 4K MMU page: clear Present bit but preserve PTE_SW_ZEROED hint.
/// Returns old PA, or 0. Used by WSCLOCK.
pub fn evict_mmupage(pml4: usize, va: usize) -> usize {
    let slot = match radix_pt::walk_to_leaf::<X86Pte>(pml4, va) {
        Some(s) => s,
        None => return 0,
    };
    let entry = unsafe { *slot };
    if entry & PTE_P == 0 {
        return 0;
    }
    let pa = X86Pte::leaf_pa(entry);
    unsafe {
        *slot = entry & PTE_SW_ZEROED;
    }
    X86Pte::tlb_invalidate(va);
    pa
}

/// Clear a PTE entirely (valid + SW bits). Used for madvise_dontneed and cleanup.
pub fn clear_pte(pml4: usize, va: usize) {
    let slot = match radix_pt::walk_to_leaf::<X86Pte>(pml4, va) {
        Some(s) => s,
        None => return,
    };
    let entry = unsafe { *slot };
    if entry != 0 {
        unsafe {
            *slot = 0;
        }
        X86Pte::tlb_invalidate(va);
    }
}

/// Read and clear the Accessed bit for the PTE at `va`.
/// Returns true if the page was referenced.
pub fn read_and_clear_ref_bit(pml4: usize, va: usize) -> bool {
    let slot = match radix_pt::walk_to_leaf::<X86Pte>(pml4, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { *slot };
    if entry & PTE_P == 0 {
        return false;
    }
    let referenced = (entry & PTE_A) != 0;
    if referenced {
        unsafe {
            *slot = entry & !PTE_A;
        }
        X86Pte::tlb_invalidate(va);
    }
    referenced
}

/// Translate a user VA to a physical address by walking the x86-64 page table.
/// Returns None if the page is not mapped.
pub fn translate_va(pml4: usize, va: usize) -> Option<usize> {
    let slot = radix_pt::walk_to_leaf::<X86Pte>(pml4, va)?;
    let entry = unsafe { *slot };
    if entry & PTE_P == 0 {
        return None;
    }
    let pa = X86Pte::leaf_pa(entry);
    Some(pa | (va & 0xFFF))
}

/// Create a new PML4 for a user process, copying the kernel's identity-mapped
/// entries from the boot page table. Returns the physical address of the new PML4.
///
/// The boot PML4[0] points to a shared PDPT containing 1 GiB gigapages.
/// We must deep-copy this PDPT so that user page table walks (which call
/// get_or_create_table on PDPT entries) don't modify the shared boot PDPT
/// and corrupt other address spaces.
pub fn create_user_page_table() -> Option<usize> {
    // Use the saved boot PML4 (not current CR3, which may be a user page table).
    let boot_pml4_addr = BOOT_PML4.load(core::sync::atomic::Ordering::Acquire);
    if boot_pml4_addr == 0 {
        return None;
    }

    // Allocate a fresh PML4.
    let new_pml4 = alloc_table()?;

    unsafe {
        let src = boot_pml4_addr as *const u64;
        let dst = new_pml4 as *mut u64;

        // Deep-copy PML4[0]: allocate a new PDPT and copy all 512 entries.
        // This gives each process its own PDPT so user mappings in the
        // lower 512 GiB region don't collide with the boot tables.
        let boot_pml4_0 = *src.add(0);
        if boot_pml4_0 & PTE_P != 0 {
            let boot_pdpt = (boot_pml4_0 & 0x000F_FFFF_FFFF_F000) as usize;
            let new_pdpt = alloc_table()?;
            core::ptr::copy_nonoverlapping(boot_pdpt as *const u64, new_pdpt as *mut u64, 512);
            // Point new PML4[0] to the copied PDPT.
            // Add U/S so the CPU allows user-mode page table walks to the PDPT.
            // Kernel gigapages at PDPT[0-3] are safe: they lack U/S, so user
            // code still can't access kernel memory.
            *dst.add(0) = (new_pdpt as u64) | PTE_P | PTE_RW | PTE_US;
        }

        // Copy PML4[1..4] directly (these don't typically have user mappings).
        for i in 1..4 {
            *dst.add(i) = *src.add(i);
        }
    }

    Some(new_pml4)
}

/// Switch the page table to a different PML4.
/// Used on context switch between tasks with different address spaces.
pub fn switch_page_table(root: usize) {
    unsafe {
        core::arch::asm!(
            "mov cr3, {root}",
            root = in(reg) root as u64,
        );
    }
}

/// Return the boot PML4 physical address (for switching back during exit).
pub fn boot_page_table_root() -> usize {
    BOOT_PML4.load(core::sync::atomic::Ordering::Acquire)
}

/// Free all intermediate page table pages for a user page table.
/// Does NOT free leaf physical pages (those are freed by aspace::destroy).
/// Skips kernel-range entries (PML4[1..3] point to shared boot tables).
pub fn free_page_table_tree(root: usize, fg: *mut crate::mm::ptshare::ForkGroup) {
    use crate::mm::{ptshare::ForkGroup, page::PhysAddr};

    let pml4 = root as *const u64;
    unsafe {
        // PML4[0] was deep-copied (its own PDPT). Free with shared-aware logic.
        // Kernel gigapages at PDPT[0-3] are skipped (is_table = false).
        let entry0 = *pml4.add(0);
        if entry0 & PTE_P != 0 && entry0 & PTE_PS == 0 {
            let pdpt = (entry0 & 0x000F_FFFF_FFFF_F000) as usize;
            free_shared_user_subtree(pdpt, 1, fg);
            crate::mm::phys::free_page(PhysAddr::new(pdpt));
        }
        // PML4[1..3] are shared with boot — do NOT free.
        // PML4[4..511]: user-range entries — may be shared markers.
        for i in 4..512 {
            let entry = *pml4.add(i);
            if X86Pte::is_shared_entry(entry) {
                let sub_pa = X86Pte::shared_entry_pa(entry);
                let rc = ForkGroup::unshare(fg, sub_pa);
                if rc == 0 {
                    free_shared_user_subtree(sub_pa, 1, fg);
                    crate::mm::phys::free_page(PhysAddr::new(sub_pa));
                }
            } else if entry & PTE_P != 0 && entry & PTE_PS == 0 {
                let pdpt = (entry & 0x000F_FFFF_FFFF_F000) as usize;
                free_shared_user_subtree(pdpt, 1, fg);
                crate::mm::phys::free_page(PhysAddr::new(pdpt));
            }
        }
    }
    // Free the PML4 itself.
    crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(root));
}

/// Downgrade a single 4K PTE from writable to read-only (for COW).
/// Returns true if the PTE was present and downgraded.
pub fn downgrade_pte_readonly(pml4: usize, va: usize) -> bool {
    let slot = match radix_pt::walk_to_leaf::<X86Pte>(pml4, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { *slot };
    if entry & PTE_P == 0 {
        return false;
    }
    // Clear the RW bit to make read-only.
    unsafe {
        *slot = entry & !PTE_RW;
    }
    X86Pte::tlb_invalidate(va);
    true
}

/// Update the flags of an existing 4K PTE, keeping the physical address.
/// Returns true if the PTE was present and updated.
pub fn update_pte_flags(pml4: usize, va: usize, new_flags: u64) -> bool {
    let slot = match radix_pt::walk_to_leaf::<X86Pte>(pml4, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { *slot };
    if entry & PTE_P == 0 {
        return false;
    }
    let pa_and_sw = entry & (0x000F_FFFF_FFFF_F000 | PTE_SW_ZEROED);
    unsafe {
        *slot = pa_and_sw | new_flags;
    }
    X86Pte::tlb_invalidate(va);
    true
}

/// Install a 2 MiB superpage at `va` (must be 2 MiB-aligned) backed by `pa` (must be 2 MiB-aligned).
/// Replaces the PD entry with a large page entry (PTE_PS). Frees the old PT page if one existed.
pub fn install_superpage(pml4: usize, va: usize, pa: usize, flags: u64) -> bool {
    const SUPER_SIZE: usize = 2 * 1024 * 1024; // 2 MiB
    debug_assert!(va & (SUPER_SIZE - 1) == 0);
    debug_assert!(pa & (SUPER_SIZE - 1) == 0);

    let slot = match radix_pt::walk_or_create_to_super::<X86Pte>(pml4, va) {
        Some(s) => s,
        None => return false,
    };

    let old_entry = unsafe { *slot };

    // If there was a PT (non-PS, present), free it.
    if old_entry & PTE_P != 0 && old_entry & PTE_PS == 0 {
        let pt_addr = X86Pte::table_pa(old_entry);
        crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(pt_addr));
    }

    // Install 2 MiB large page entry.
    unsafe {
        *slot = (pa as u64 & !0x1FFFFF) | flags | PTE_PS;
    }
    X86Pte::tlb_invalidate(va);
    true
}

/// Check if `va` is mapped as a 2 MiB superpage. Returns (is_super, pa) if so.
pub fn is_superpage(pml4: usize, va: usize) -> Option<usize> {
    let slot = radix_pt::walk_to_super_slot::<X86Pte>(pml4, va)?;
    let entry = unsafe { *slot };
    if entry & PTE_P != 0 && entry & PTE_PS != 0 {
        let pa = (entry & 0x000F_FFFF_FFE0_0000) as usize; // Mask to 2 MiB alignment
        Some(pa)
    } else {
        None
    }
}

/// Demote a 2 MiB superpage back to 512 individual 4K PTEs.
/// Allocates a new PT page, fills it with 512 entries pointing to the
/// contiguous physical pages, and replaces the PD entry.
pub fn demote_superpage(pml4: usize, va: usize, flags: u64) -> bool {
    let slot = match radix_pt::walk_to_super_slot::<X86Pte>(pml4, va) {
        Some(s) => s,
        None => return false,
    };

    let entry = unsafe { *slot };
    if entry & PTE_P == 0 || entry & PTE_PS == 0 {
        return false; // Not a superpage.
    }

    let base_pa = (entry & 0x000F_FFFF_FFE0_0000) as usize;

    // Allocate a PT page.
    let pt = match alloc_table() {
        Some(t) => t,
        None => return false,
    };
    let pt_table = pt as *mut u64;

    // Fill 512 entries.
    for i in 0..512 {
        let pa = base_pa + i * MMU_PAGE_SIZE;
        unsafe {
            *pt_table.add(i) = (pa as u64 & !0xFFF) | flags;
        }
    }

    // Replace PD entry with table pointer.
    unsafe {
        *slot = X86Pte::make_table_entry(pt);
    }
    X86Pte::tlb_invalidate(va);
    true
}

// ---------------------------------------------------------------------------
// Level-parameterized superpage operations
// ---------------------------------------------------------------------------

use crate::mm::page::SuperpageLevel;

/// Install a superpage at an arbitrary level.
pub fn install_superpage_at_level(
    pml4: usize,
    va: usize,
    pa: usize,
    flags: u64,
    level: &SuperpageLevel,
) -> bool {
    debug_assert!(va & level.align_mask() == 0);
    debug_assert!(pa & level.align_mask() == 0);

    let slot = match radix_pt::walk_or_create_to_level::<X86Pte>(
        pml4,
        va,
        level.pt_level as usize,
    ) {
        Some(s) => s,
        None => return false,
    };

    let old_entry = unsafe { *slot };

    // If the old entry was a table pointer, free the sub-table.
    if old_entry & PTE_P != 0 && old_entry & PTE_PS == 0 {
        let table_addr = X86Pte::table_pa(old_entry);
        crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(table_addr));
    }

    let pa_mask = !(level.align_mask() as u64);
    unsafe {
        *slot = (pa as u64 & pa_mask) | flags | PTE_PS;
    }
    X86Pte::tlb_invalidate(va);
    true
}

/// Check if `va` is mapped as a superpage at the given level.
pub fn is_superpage_at_level(
    pml4: usize,
    va: usize,
    level: &SuperpageLevel,
) -> Option<usize> {
    let slot =
        radix_pt::walk_to_level_slot::<X86Pte>(pml4, va, level.pt_level as usize)?;
    let entry = unsafe { *slot };
    if entry & PTE_P != 0 && entry & PTE_PS != 0 {
        let pa = (entry & 0x000F_FFFF_FFFF_F000) as usize & !level.align_mask();
        Some(pa)
    } else {
        None
    }
}

/// Demote a superpage at the given level into 512 entries at the next level down.
/// If the next level is the leaf level, produces 4K PTEs (no PTE_PS).
/// Otherwise, produces block descriptors (PTE_PS set) at the sub-level.
pub fn demote_superpage_at_level(
    pml4: usize,
    va: usize,
    flags: u64,
    level: &SuperpageLevel,
) -> bool {
    let slot = match radix_pt::walk_to_level_slot::<X86Pte>(
        pml4,
        va,
        level.pt_level as usize,
    ) {
        Some(s) => s,
        None => return false,
    };

    let entry = unsafe { *slot };
    if entry & PTE_P == 0 || entry & PTE_PS == 0 {
        return false;
    }

    let base_pa = (entry & 0x000F_FFFF_FFFF_F000) as usize & !level.align_mask();
    let sub_size = level.size / 512;
    let sub_is_leaf = (level.pt_level as usize + 1) == X86Pte::LEVELS - 1;

    let new_table = match alloc_table() {
        Some(t) => t,
        None => return false,
    };
    let table_ptr = new_table as *mut u64;

    for i in 0..512usize {
        let pa = base_pa + i * sub_size;
        let sub_entry = if sub_is_leaf {
            (pa as u64 & !0xFFF) | flags
        } else {
            let sub_mask = !(sub_size as u64 - 1);
            (pa as u64 & sub_mask) | flags | PTE_PS
        };
        unsafe {
            *table_ptr.add(i) = sub_entry;
        }
    }

    unsafe {
        *slot = X86Pte::make_table_entry(new_table);
    }
    X86Pte::tlb_invalidate(va);
    true
}

/// Reload CR3 to flush the TLB after page table changes.
pub fn enable_mmu(pml4: usize) {
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) pml4 as u64,
        );
    }
}
