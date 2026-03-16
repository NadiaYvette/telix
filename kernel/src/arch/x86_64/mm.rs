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

/// User page flags (public for main.rs).
pub const USER_RWX_FLAGS: u64 = PTE_P | PTE_RW | PTE_US;
pub const USER_RW_FLAGS: u64 = PTE_P | PTE_RW | PTE_US | PTE_NX;

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
    Some((cr3 & !0xFFF) as usize)
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

/// Reload CR3 to flush the TLB after page table changes.
pub fn enable_mmu(pml4: usize) {
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) pml4 as u64,
        );
    }
}
