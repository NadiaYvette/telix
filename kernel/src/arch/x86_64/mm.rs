//! x86-64 page table management for userspace support.
//!
//! The boot code (boot.S) already sets up identity-mapped 1 GiB pages
//! for 0-4 GiB in the boot PML4. This module adds user page mappings
//! to the existing page table hierarchy.
//!
//! User pages are placed at PML4 index 1+ (VA >= 0x80_0000_0000) to
//! avoid conflicting with the kernel's 1 GiB page entries.

/// x86-64 page table entry flags.
const PTE_P: u64 = 1 << 0;       // Present
const PTE_RW: u64 = 1 << 1;      // Read/Write
const PTE_US: u64 = 1 << 2;      // User/Supervisor
const PTE_PS: u64 = 1 << 7;      // Page Size (2M/1G large page)
const PTE_NX: u64 = 1u64 << 63;  // No Execute

const MMU_PAGE_SIZE: usize = 4096;

/// Boot PML4 address, saved during init so create_user_page_table always
/// copies from the original kernel page table (not the current CR3 which
/// may be a user process's page table during sys_spawn).
static BOOT_PML4: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

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
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3); }
    let pml4 = (cr3 & !0xFFF) as usize;
    // Save boot PML4 for create_user_page_table.
    BOOT_PML4.store(pml4, core::sync::atomic::Ordering::Release);
    Some(pml4)
}

/// Add user 4K page mappings to the existing PML4.
///
/// Non-leaf entries are created with U/S=1 so the CPU allows user-mode
/// page walks through the hierarchy.
pub fn map_user_pages(
    pml4: usize,
    virt: usize,
    phys: usize,
    size: usize,
    flags: u64,
) -> Option<()> {
    let pml4_table = pml4 as *mut u64;
    let num_pages = (size + MMU_PAGE_SIZE - 1) / MMU_PAGE_SIZE;

    for i in 0..num_pages {
        let va = virt + i * MMU_PAGE_SIZE;
        let pa = phys + i * MMU_PAGE_SIZE;

        let pml4_idx = (va >> 39) & 0x1FF;
        let pdpt_idx = (va >> 30) & 0x1FF;
        let pd_idx = (va >> 21) & 0x1FF;
        let pt_idx = (va >> 12) & 0x1FF;

        let pdpt = get_or_create_table(pml4_table, pml4_idx)?;
        let pd = get_or_create_table(pdpt, pdpt_idx)?;
        let pt = get_or_create_table(pd, pd_idx)?;

        unsafe {
            *pt.add(pt_idx) = (pa as u64 & !0xFFF) | flags;
        }
    }
    Some(())
}

/// Get or create a next-level page table at the given index.
fn get_or_create_table(table: *mut u64, index: usize) -> Option<*mut u64> {
    let entry = unsafe { *table.add(index) };
    if entry & PTE_P != 0 {
        if entry & PTE_PS != 0 {
            // Large page — cannot subdivide.
            return None;
        }
        let next = (entry & 0x000F_FFFF_FFFF_F000) as usize;
        Some(next as *mut u64)
    } else {
        let next = alloc_table()?;
        unsafe {
            // Non-leaf entries need P + RW + US for user page walks.
            *table.add(index) = (next as u64) | PTE_P | PTE_RW | PTE_US;
        }
        Some(next as *mut u64)
    }
}

// ---------------------------------------------------------------------------
// Per-MMU-page operations for demand paging
// ---------------------------------------------------------------------------

/// x86-64 PTE Accessed bit.
const PTE_A: u64 = 1 << 5;

/// Map a single 4K MMU page at `va` to physical address `pa` with given flags.
pub fn map_single_mmupage(pml4: usize, va: usize, pa: usize, flags: u64) -> bool {
    let pml4_table = pml4 as *mut u64;
    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx = (va >> 21) & 0x1FF;
    let pt_idx = (va >> 12) & 0x1FF;

    let pdpt = match get_or_create_table(pml4_table, pml4_idx) {
        Some(t) => t,
        None => return false,
    };
    let pd = match get_or_create_table(pdpt, pdpt_idx) {
        Some(t) => t,
        None => return false,
    };
    let pt = match get_or_create_table(pd, pd_idx) {
        Some(t) => t,
        None => return false,
    };

    unsafe {
        *pt.add(pt_idx) = (pa as u64 & !0xFFF) | flags;
    }
    // invlpg
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) va);
    }
    true
}

/// Unmap a single 4K MMU page at `va`. Returns the old physical address, or 0.
pub fn unmap_single_mmupage(pml4: usize, va: usize) -> usize {
    let pml4_table = pml4 as *mut u64;
    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx = (va >> 21) & 0x1FF;
    let pt_idx = (va >> 12) & 0x1FF;

    let pdpt = match walk_table(pml4_table, pml4_idx) {
        Some(t) => t,
        None => return 0,
    };
    let pd = match walk_table(pdpt, pdpt_idx) {
        Some(t) => t,
        None => return 0,
    };
    let pt = match walk_table(pd, pd_idx) {
        Some(t) => t,
        None => return 0,
    };

    let entry = unsafe { *pt.add(pt_idx) };
    if entry & PTE_P == 0 {
        return 0;
    }
    let pa = (entry & 0x000F_FFFF_FFFF_F000) as usize;
    unsafe {
        *pt.add(pt_idx) = 0;
    }
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) va);
    }
    pa
}

/// Read and clear the Accessed bit for the PTE at `va`.
/// Returns true if the page was referenced.
pub fn read_and_clear_ref_bit(pml4: usize, va: usize) -> bool {
    let pml4_table = pml4 as *mut u64;
    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx = (va >> 21) & 0x1FF;
    let pt_idx = (va >> 12) & 0x1FF;

    let pdpt = match walk_table(pml4_table, pml4_idx) {
        Some(t) => t,
        None => return false,
    };
    let pd = match walk_table(pdpt, pdpt_idx) {
        Some(t) => t,
        None => return false,
    };
    let pt = match walk_table(pd, pd_idx) {
        Some(t) => t,
        None => return false,
    };

    let entry = unsafe { *pt.add(pt_idx) };
    if entry & PTE_P == 0 {
        return false;
    }
    let referenced = (entry & PTE_A) != 0;
    if referenced {
        unsafe {
            *pt.add(pt_idx) = entry & !PTE_A;
        }
        unsafe {
            core::arch::asm!("invlpg [{}]", in(reg) va);
        }
    }
    referenced
}

/// Walk an existing non-leaf table entry. Returns next-level table pointer or None.
fn walk_table(table: *mut u64, index: usize) -> Option<*mut u64> {
    let entry = unsafe { *table.add(index) };
    if entry & PTE_P != 0 && entry & PTE_PS == 0 {
        let next = (entry & 0x000F_FFFF_FFFF_F000) as usize;
        Some(next as *mut u64)
    } else {
        None
    }
}

/// Translate a user VA to a physical address by walking the x86-64 page table.
/// Returns None if the page is not mapped.
pub fn translate_va(pml4: usize, va: usize) -> Option<usize> {
    let pml4_table = pml4 as *mut u64;
    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx = (va >> 21) & 0x1FF;
    let pt_idx = (va >> 12) & 0x1FF;

    let pdpt = walk_table(pml4_table, pml4_idx)?;
    let pd = walk_table(pdpt, pdpt_idx)?;
    let pt = walk_table(pd, pd_idx)?;
    let entry = unsafe { *pt.add(pt_idx) };
    if entry & PTE_P == 0 {
        return None;
    }
    let pa = (entry & 0x000F_FFFF_FFFF_F000) as usize;
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
            core::ptr::copy_nonoverlapping(
                boot_pdpt as *const u64,
                new_pdpt as *mut u64,
                512,
            );
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
pub fn free_page_table_tree(root: usize) {
    let pml4 = root as *const u64;
    unsafe {
        // PML4[0] was deep-copied (its own PDPT). Recurse and free it.
        let entry0 = *pml4.add(0);
        if entry0 & PTE_P != 0 && entry0 & PTE_PS == 0 {
            let pdpt = (entry0 & 0x000F_FFFF_FFFF_F000) as usize;
            free_pdpt_user(pdpt);
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(pdpt));
        }
        // PML4[1..3] are shared with boot — do NOT free.
        // PML4[4..511]: user-range entries (if any).
        for i in 4..512 {
            let entry = *pml4.add(i);
            if entry & PTE_P != 0 && entry & PTE_PS == 0 {
                let pdpt = (entry & 0x000F_FFFF_FFFF_F000) as usize;
                free_pdpt_user(pdpt);
                crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(pdpt));
            }
        }
    }
    // Free the PML4 itself.
    crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(root));
}

/// Free all sub-tables under a PDPT, skipping gigapage (PS) entries.
unsafe fn free_pdpt_user(pdpt: usize) {
    let table = pdpt as *const u64;
    for i in 0..512 {
        let entry = *table.add(i);
        if entry & PTE_P != 0 && entry & PTE_PS == 0 {
            let pd = (entry & 0x000F_FFFF_FFFF_F000) as usize;
            free_pd_user(pd);
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(pd));
        }
    }
}

/// Free all sub-tables under a PD, skipping large page (PS) entries.
unsafe fn free_pd_user(pd: usize) {
    let table = pd as *const u64;
    for i in 0..512 {
        let entry = *table.add(i);
        if entry & PTE_P != 0 && entry & PTE_PS == 0 {
            let pt = (entry & 0x000F_FFFF_FFFF_F000) as usize;
            // PT is a leaf table — just free it (leaf PTEs point to user pages,
            // which are freed by aspace::destroy, not here).
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(pt));
        }
    }
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
