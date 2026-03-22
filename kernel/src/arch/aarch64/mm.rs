//! AArch64 MMU setup — identity-mapped kernel + user page tables.
//!
//! Uses 4 KiB MMU granule with 4-level page tables (48-bit VA).
//! Both kernel (identity-mapped) and user mappings go through TTBR0,
//! since the kernel runs at 0x4008_0000 (low VA space).

use core::sync::atomic::{AtomicUsize, Ordering};

/// Kernel page table root (L0), set by BSP after enable_mmu.
/// Used by secondary CPUs to enable their MMU with the same identity mapping.
static KERNEL_PT_ROOT: AtomicUsize = AtomicUsize::new(0);

/// Page table entry flags.
const PT_VALID: u64 = 1 << 0;
const PT_TABLE: u64 = 1 << 1;     // Non-leaf: next-level table
const PT_PAGE: u64 = 1 << 1;      // Level 3: 4K page
const PT_AF: u64 = 1 << 10;       // Access flag
const PT_SH_INNER: u64 = 3 << 8;  // Inner shareable
const PT_AP_RW_EL1: u64 = 0 << 6; // EL1 RW, EL0 no access
const PT_AP_RW_ALL: u64 = 1 << 6; // EL1 RW, EL0 RW
const PT_UXN: u64 = 1 << 54;      // Unprivileged execute-never
const PT_PXN: u64 = 1 << 53;      // Privileged execute-never
const PT_CONTIGUOUS: u64 = 1 << 52; // Contiguous hint (16 × 4K = 64K group)
const PT_ATTR_IDX_0: u64 = 0 << 2; // MAIR index 0 (normal memory)
const PT_ATTR_IDX_1: u64 = 1 << 2; // MAIR index 1 (device memory)

/// Standard flags.
const KERN_BLOCK: u64 = PT_VALID | PT_AF | PT_SH_INNER | PT_AP_RW_EL1 | PT_ATTR_IDX_0 | PT_UXN;
const DEV_BLOCK: u64 = PT_VALID | PT_AF | PT_AP_RW_EL1 | PT_ATTR_IDX_1 | PT_UXN | PT_PXN;
const USER_PAGE: u64 = PT_VALID | PT_PAGE | PT_AF | PT_SH_INNER | PT_AP_RW_ALL | PT_ATTR_IDX_0;

const MMU_PAGE_SIZE: usize = 4096;

/// Allocate a zero-filled 4K page for a page table from the buddy allocator.
fn alloc_table() -> Option<usize> {
    let page = crate::mm::phys::alloc_page()?;
    let addr = page.as_usize();
    unsafe {
        core::ptr::write_bytes(addr as *mut u8, 0, MMU_PAGE_SIZE);
    }
    Some(addr)
}

/// Set up a single TTBR0 page table that identity-maps the kernel/device
/// regions AND maps user virtual addresses.
///
/// Kernel identity mapping (via 2 MiB blocks):
///   0x0000_0000 - 0x3FFF_FFFF: Device memory (1 GiB, UART + GIC)
///   0x4000_0000 - 0x4FFF_FFFF: RAM (256 MiB)
///
/// User mappings are added afterwards via `map_user_pages`.
pub fn setup_tables() -> Option<usize> {
    let l0 = alloc_table()?;
    let l1 = alloc_table()?;
    let l0_table = l0 as *mut u64;
    let l1_table = l1 as *mut u64;

    // L0[0] → L1 table (covers first 512 GiB of VA space).
    unsafe {
        *l0_table = (l1 as u64) | PT_VALID | PT_TABLE;
    }

    // L1[0]: 1 GiB block for device memory at 0x0000_0000.
    unsafe {
        *l1_table = 0x0000_0000u64 | DEV_BLOCK;
    }

    // L1[1]: L2 table for 0x4000_0000 - 0x7FFF_FFFF (RAM region).
    let l2 = alloc_table()?;
    let l2_table = l2 as *mut u64;
    unsafe {
        *l1_table.add(1) = (l2 as u64) | PT_VALID | PT_TABLE;
    }

    // Map 128 × 2 MiB blocks = 256 MiB of RAM starting at 0x4000_0000.
    for i in 0..128 {
        let phys = 0x4000_0000u64 + (i as u64) * 0x20_0000;
        unsafe {
            *l2_table.add(i) = phys | KERN_BLOCK;
        }
    }

    Some(l0)
}

/// Add user 4K page mappings to an existing L0 table.
#[allow(dead_code)]
pub fn map_user_pages(
    l0: usize,
    virt: usize,
    phys: usize,
    size: usize,
    flags: u64,
) -> Option<()> {
    let l0_table = l0 as *mut u64;
    let num_pages = (size + MMU_PAGE_SIZE - 1) / MMU_PAGE_SIZE;

    for i in 0..num_pages {
        let va = virt + i * MMU_PAGE_SIZE;
        let pa = phys + i * MMU_PAGE_SIZE;

        let l0_idx = (va >> 39) & 0x1FF;
        let l1_idx = (va >> 30) & 0x1FF;
        let l2_idx = (va >> 21) & 0x1FF;
        let l3_idx = (va >> 12) & 0x1FF;

        let l1 = get_or_create_table(l0_table, l0_idx)?;
        let l2 = get_or_create_table(l1, l1_idx)?;
        let l3 = get_or_create_table(l2, l2_idx)?;

        unsafe {
            *l3.add(l3_idx) = (pa as u64) | flags;
        }
    }
    Some(())
}

/// Public user page flags for use from main.rs.
pub const USER_RWX_FLAGS: u64 = USER_PAGE;
pub const USER_RW_FLAGS: u64 = USER_PAGE | PT_UXN;
/// Read-only user page: AP = 11 (EL1 RO, EL0 RO), no execute.
const PT_AP_RO_ALL: u64 = 3 << 6;
pub const USER_RO_FLAGS: u64 = PT_VALID | PT_PAGE | PT_AF | PT_SH_INNER | PT_AP_RO_ALL | PT_ATTR_IDX_0 | PT_UXN;

/// Get or create a next-level table at the given index.
fn get_or_create_table(table: *mut u64, index: usize) -> Option<*mut u64> {
    let entry = unsafe { *table.add(index) };
    if entry & PT_VALID != 0 && entry & PT_TABLE != 0 {
        let next = (entry & 0x0000_FFFF_FFFF_F000) as usize;
        Some(next as *mut u64)
    } else if entry & PT_VALID != 0 {
        // It's a block descriptor — can't create a table here.
        None
    } else {
        let next = alloc_table()?;
        unsafe {
            *table.add(index) = (next as u64) | PT_VALID | PT_TABLE;
        }
        Some(next as *mut u64)
    }
}

// ---------------------------------------------------------------------------
// Per-MMU-page operations for demand paging
// ---------------------------------------------------------------------------

/// Map a single 4K MMU page at `va` to physical address `pa` with given flags.
/// Creates intermediate table entries as needed. Invalidates TLB for the VA.
pub fn map_single_mmupage(l0: usize, va: usize, pa: usize, flags: u64) -> bool {
    let l0_table = l0 as *mut u64;
    let l0_idx = (va >> 39) & 0x1FF;
    let l1_idx = (va >> 30) & 0x1FF;
    let l2_idx = (va >> 21) & 0x1FF;
    let l3_idx = (va >> 12) & 0x1FF;

    let l1 = match get_or_create_table(l0_table, l0_idx) {
        Some(t) => t,
        None => return false,
    };
    let l2 = match get_or_create_table(l1, l1_idx) {
        Some(t) => t,
        None => return false,
    };
    let l3 = match get_or_create_table(l2, l2_idx) {
        Some(t) => t,
        None => return false,
    };

    unsafe {
        *l3.add(l3_idx) = (pa as u64) | flags;
    }
    // TLB invalidate for this VA (inner-shareable).
    unsafe {
        let va_shifted = (va >> 12) as u64;
        core::arch::asm!("tlbi vale1is, {}", in(reg) va_shifted);
        core::arch::asm!("dsb ish");
        core::arch::asm!("isb");
    }
    true
}

/// Unmap a single 4K MMU page at `va`. Returns the old physical address, or 0 if not mapped.
pub fn unmap_single_mmupage(l0: usize, va: usize) -> usize {
    let l0_table = l0 as *mut u64;
    let l0_idx = (va >> 39) & 0x1FF;
    let l1_idx = (va >> 30) & 0x1FF;
    let l2_idx = (va >> 21) & 0x1FF;
    let l3_idx = (va >> 12) & 0x1FF;

    // Walk down — if any level is missing, the page isn't mapped.
    let l1 = match walk_table(l0_table, l0_idx) {
        Some(t) => t,
        None => return 0,
    };
    let l2 = match walk_table(l1, l1_idx) {
        Some(t) => t,
        None => return 0,
    };
    let l3 = match walk_table(l2, l2_idx) {
        Some(t) => t,
        None => return 0,
    };

    let entry = unsafe { *l3.add(l3_idx) };
    if entry & PT_VALID == 0 {
        return 0;
    }
    let pa = (entry & 0x0000_FFFF_FFFF_F000) as usize;
    unsafe {
        *l3.add(l3_idx) = 0;
    }
    // TLB invalidate.
    unsafe {
        let va_shifted = (va >> 12) as u64;
        core::arch::asm!("tlbi vale1is, {}", in(reg) va_shifted);
        core::arch::asm!("dsb ish");
        core::arch::asm!("isb");
    }
    pa
}

/// Read and clear the Access Flag (AF) for the PTE at `va`.
/// Returns true if AF was set (page was referenced).
pub fn read_and_clear_ref_bit(l0: usize, va: usize) -> bool {
    let l0_table = l0 as *mut u64;
    let l0_idx = (va >> 39) & 0x1FF;
    let l1_idx = (va >> 30) & 0x1FF;
    let l2_idx = (va >> 21) & 0x1FF;
    let l3_idx = (va >> 12) & 0x1FF;

    let l1 = match walk_table(l0_table, l0_idx) {
        Some(t) => t,
        None => return false,
    };
    let l2 = match walk_table(l1, l1_idx) {
        Some(t) => t,
        None => return false,
    };
    let l3 = match walk_table(l2, l2_idx) {
        Some(t) => t,
        None => return false,
    };

    let entry = unsafe { *l3.add(l3_idx) };
    if entry & PT_VALID == 0 {
        return false;
    }
    let referenced = (entry & PT_AF) != 0;
    if referenced {
        // Clear AF.
        unsafe {
            *l3.add(l3_idx) = entry & !PT_AF;
        }
        // TLB invalidate so the CPU will set AF again on next access.
        unsafe {
            let va_shifted = (va >> 12) as u64;
            core::arch::asm!("tlbi vale1is, {}", in(reg) va_shifted);
            core::arch::asm!("dsb ish");
            core::arch::asm!("isb");
        }
    }
    referenced
}

/// Walk an existing table entry (no creation). Returns next-level table pointer or None.
fn walk_table(table: *mut u64, index: usize) -> Option<*mut u64> {
    let entry = unsafe { *table.add(index) };
    if entry & PT_VALID != 0 && entry & PT_TABLE != 0 {
        let next = (entry & 0x0000_FFFF_FFFF_F000) as usize;
        Some(next as *mut u64)
    } else {
        None
    }
}

/// Translate a user VA to a physical address by walking the page table.
/// Returns None if the page is not mapped.
pub fn translate_va(l0: usize, va: usize) -> Option<usize> {
    let l0_table = l0 as *mut u64;
    let l0_idx = (va >> 39) & 0x1FF;
    let l1 = walk_table(l0_table, l0_idx)?;
    let l1_idx = (va >> 30) & 0x1FF;
    let l2 = walk_table(l1, l1_idx)?;
    let l2_idx = (va >> 21) & 0x1FF;
    let l3 = walk_table(l2, l2_idx)?;
    let l3_idx = (va >> 12) & 0x1FF;
    let entry = unsafe { *l3.add(l3_idx) };
    if entry & PT_VALID == 0 {
        return None;
    }
    let pa = (entry & 0x0000_FFFF_FFFF_F000) as usize;
    Some(pa | (va & 0xFFF))
}

/// Read the raw L3 PTE for a VA. Returns 0 if any level is missing.
#[allow(dead_code)]
pub fn read_pte(l0: usize, va: usize) -> u64 {
    let l0_table = l0 as *mut u64;
    let l0_idx = (va >> 39) & 0x1FF;
    let l1 = match walk_table(l0_table, l0_idx) { Some(t) => t, None => return 0 };
    let l1_idx = (va >> 30) & 0x1FF;
    let l2 = match walk_table(l1, l1_idx) { Some(t) => t, None => return 0 };
    let l2_idx = (va >> 21) & 0x1FF;
    let l3 = match walk_table(l2, l2_idx) { Some(t) => t, None => return 0 };
    let l3_idx = (va >> 12) & 0x1FF;
    unsafe { *l3.add(l3_idx) }
}

/// Number of contiguous L3 PTEs in a contiguous group (16 × 4K = 64K).
const CONTIGUOUS_GROUP_SIZE: usize = 16;

/// Try to promote a contiguous group of 16 4K PTEs to use the contiguous hint.
/// `l0`: page table root. `va`: any VA within the group. `group_count`: how many
/// of the 16 entries in the group are installed (from VMA bitmap).
/// Returns true if promotion was applied.
pub fn try_contiguous_promotion(l0: usize, va: usize, group_count: usize) -> bool {
    if group_count != CONTIGUOUS_GROUP_SIZE {
        return false;
    }

    // Align VA down to 64K boundary (the contiguous group boundary).
    let group_va = va & !(CONTIGUOUS_GROUP_SIZE * MMU_PAGE_SIZE - 1);

    let l0_table = l0 as *mut u64;
    let l0_idx = (group_va >> 39) & 0x1FF;
    let l1_idx = (group_va >> 30) & 0x1FF;
    let l2_idx = (group_va >> 21) & 0x1FF;
    let l3_base_idx = (group_va >> 12) & 0x1FF;

    // Walk to L3 table (read-only, no creation).
    let l1 = match walk_table(l0_table, l0_idx) {
        Some(t) => t,
        None => return false,
    };
    let l2 = match walk_table(l1, l1_idx) {
        Some(t) => t,
        None => return false,
    };
    let l3 = match walk_table(l2, l2_idx) {
        Some(t) => t,
        None => return false,
    };

    // Verify all 16 PTEs are valid and don't already have the contiguous bit.
    for i in 0..CONTIGUOUS_GROUP_SIZE {
        let entry = unsafe { *l3.add(l3_base_idx + i) };
        if entry & PT_VALID == 0 {
            return false;
        }
    }

    // Check if already promoted.
    let first = unsafe { *l3.add(l3_base_idx) };
    if first & PT_CONTIGUOUS != 0 {
        return false;
    }

    // Set the contiguous bit on all 16 PTEs.
    for i in 0..CONTIGUOUS_GROUP_SIZE {
        unsafe {
            let entry = *l3.add(l3_base_idx + i);
            *l3.add(l3_base_idx + i) = entry | PT_CONTIGUOUS;
        }
    }

    // TLB invalidate the entire group.
    for i in 0..CONTIGUOUS_GROUP_SIZE {
        let entry_va = group_va + i * MMU_PAGE_SIZE;
        unsafe {
            let va_shifted = (entry_va >> 12) as u64;
            core::arch::asm!("tlbi vale1is, {}", in(reg) va_shifted);
        }
    }
    unsafe {
        core::arch::asm!("dsb ish");
        core::arch::asm!("isb");
    }

    true
}

/// Downgrade a single 4K PTE from writable to read-only (for COW).
/// Returns true if the PTE was present and downgraded.
pub fn downgrade_pte_readonly(l0: usize, va: usize) -> bool {
    let l0_table = l0 as *mut u64;
    let l0_idx = (va >> 39) & 0x1FF;
    let l1_idx = (va >> 30) & 0x1FF;
    let l2_idx = (va >> 21) & 0x1FF;
    let l3_idx = (va >> 12) & 0x1FF;

    let l1 = match walk_table(l0_table, l0_idx) {
        Some(t) => t,
        None => return false,
    };
    let l2 = match walk_table(l1, l1_idx) {
        Some(t) => t,
        None => return false,
    };
    let l3 = match walk_table(l2, l2_idx) {
        Some(t) => t,
        None => return false,
    };

    let entry = unsafe { *l3.add(l3_idx) };
    if entry & PT_VALID == 0 {
        return false;
    }
    // Set AP[2] (bit 7) to make read-only: AP=11 means EL1/EL0 read-only.
    unsafe {
        *l3.add(l3_idx) = entry | (1 << 7);
    }
    // TLB invalidate.
    unsafe {
        let va_shifted = (va >> 12) as u64;
        core::arch::asm!("tlbi vale1is, {}", in(reg) va_shifted);
        core::arch::asm!("dsb ish");
        core::arch::asm!("isb");
    }
    true
}

/// Update the flags of an existing 4K PTE, keeping the physical address.
/// Returns true if the PTE was present and updated.
pub fn update_pte_flags(l0: usize, va: usize, new_flags: u64) -> bool {
    let l0_table = l0 as *mut u64;
    let l0_idx = (va >> 39) & 0x1FF;
    let l1_idx = (va >> 30) & 0x1FF;
    let l2_idx = (va >> 21) & 0x1FF;
    let l3_idx = (va >> 12) & 0x1FF;

    let l1 = match walk_table(l0_table, l0_idx) {
        Some(t) => t,
        None => return false,
    };
    let l2 = match walk_table(l1, l1_idx) {
        Some(t) => t,
        None => return false,
    };
    let l3 = match walk_table(l2, l2_idx) {
        Some(t) => t,
        None => return false,
    };

    let entry = unsafe { *l3.add(l3_idx) };
    if entry & PT_VALID == 0 {
        return false;
    }
    let pa = entry & 0x0000_FFFF_FFFF_F000;
    unsafe {
        *l3.add(l3_idx) = pa | new_flags;
    }
    unsafe {
        let va_shifted = (va >> 12) as u64;
        core::arch::asm!("tlbi vale1is, {}", in(reg) va_shifted);
        core::arch::asm!("dsb ish");
        core::arch::asm!("isb");
    }
    true
}

// ---------------------------------------------------------------------------
// 2 MiB superpage (L2 block descriptor) operations
// ---------------------------------------------------------------------------

/// Install a 2 MiB block descriptor at L2 for the given VA.
/// `flags` are L3-style PTE flags; bit 1 (PT_PAGE/PT_TABLE) is cleared
/// for the block descriptor. If an L3 table currently occupies the slot,
/// it is freed.
pub fn install_superpage(l0: usize, va: usize, pa: usize, flags: u64) -> bool {
    const SUPER_SIZE: usize = 2 * 1024 * 1024;
    debug_assert!(va & (SUPER_SIZE - 1) == 0);
    debug_assert!(pa & (SUPER_SIZE - 1) == 0);

    let l0_table = l0 as *mut u64;
    let l0_idx = (va >> 39) & 0x1FF;
    let l1_idx = (va >> 30) & 0x1FF;
    let l2_idx = (va >> 21) & 0x1FF;

    let l1 = match get_or_create_table(l0_table, l0_idx) {
        Some(t) => t,
        None => return false,
    };
    let l2 = match get_or_create_table(l1, l1_idx) {
        Some(t) => t,
        None => return false,
    };

    let old_entry = unsafe { *l2.add(l2_idx) };

    // If there was an L3 table (table descriptor), free it.
    if old_entry & PT_VALID != 0 && old_entry & PT_TABLE != 0 {
        let l3_addr = (old_entry & 0x0000_FFFF_FFFF_F000) as usize;
        crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(l3_addr));
    }

    // Block descriptor: bit[1:0] = 01 (valid, not table).
    // Strip PT_PAGE/PT_TABLE (bit 1) from flags, keep everything else.
    let block_flags = (flags & !0x2) | PT_VALID;
    unsafe {
        *l2.add(l2_idx) = (pa as u64 & !0x1FFFFF) | block_flags;
    }

    // TLB invalidate the entire 2 MiB range.
    for i in 0..512 {
        let entry_va = va + i * MMU_PAGE_SIZE;
        unsafe {
            let va_shifted = (entry_va >> 12) as u64;
            core::arch::asm!("tlbi vale1is, {}", in(reg) va_shifted);
        }
    }
    unsafe {
        core::arch::asm!("dsb ish", "isb");
    }
    true
}

/// Check if `va` is mapped as a 2 MiB block at L2.
/// Returns the base physical address if so.
pub fn is_superpage(l0: usize, va: usize) -> Option<usize> {
    let l0_table = l0 as *mut u64;
    let l0_idx = (va >> 39) & 0x1FF;
    let l1_idx = (va >> 30) & 0x1FF;
    let l2_idx = (va >> 21) & 0x1FF;

    let l1 = walk_table(l0_table, l0_idx)?;
    let l2 = walk_table(l1, l1_idx)?;
    let entry = unsafe { *l2.add(l2_idx) };
    // Block descriptor: valid (bit 0) but NOT table (bit 1 clear).
    if entry & PT_VALID != 0 && entry & PT_TABLE == 0 {
        let pa = (entry & 0x0000_FFFF_FFE0_0000) as usize;
        Some(pa)
    } else {
        None
    }
}

/// Demote a 2 MiB block descriptor back to 512 individual 4K L3 PTEs.
/// Allocates a new L3 table, fills it with page entries, and replaces
/// the L2 block with a table descriptor.
pub fn demote_superpage(l0: usize, va: usize, flags: u64) -> bool {
    let l0_table = l0 as *mut u64;
    let l0_idx = (va >> 39) & 0x1FF;
    let l1_idx = (va >> 30) & 0x1FF;
    let l2_idx = (va >> 21) & 0x1FF;

    let l1 = match walk_table(l0_table, l0_idx) {
        Some(t) => t,
        None => return false,
    };
    let l2 = match walk_table(l1, l1_idx) {
        Some(t) => t,
        None => return false,
    };

    let entry = unsafe { *l2.add(l2_idx) };
    // Must be a valid block (bit 0 set, bit 1 clear).
    if entry & PT_VALID == 0 || entry & PT_TABLE != 0 {
        return false;
    }

    let base_pa = (entry & 0x0000_FFFF_FFE0_0000) as usize;

    // Allocate L3 table.
    let l3 = match alloc_table() {
        Some(t) => t,
        None => return false,
    };
    let l3_table = l3 as *mut u64;

    // Fill 512 × 4K page entries.
    for i in 0..512 {
        let pa = base_pa + i * MMU_PAGE_SIZE;
        unsafe {
            *l3_table.add(i) = (pa as u64) | flags;
        }
    }

    // Replace L2 block with table descriptor pointing to L3.
    unsafe {
        *l2.add(l2_idx) = (l3 as u64) | PT_VALID | PT_TABLE;
    }

    // TLB invalidate the 2 MiB range.
    for i in 0..512 {
        let entry_va = va + i * MMU_PAGE_SIZE;
        unsafe {
            let va_shifted = (entry_va >> 12) as u64;
            core::arch::asm!("tlbi vale1is, {}", in(reg) va_shifted);
        }
    }
    unsafe {
        core::arch::asm!("dsb ish", "isb");
    }
    true
}

/// Return the kernel page table root (for switching back during exit).
pub fn boot_page_table_root() -> usize {
    KERNEL_PT_ROOT.load(Ordering::Acquire)
}

/// Free all intermediate page table pages for a user page table.
/// Does NOT free leaf physical pages (those are freed by aspace::destroy).
/// The L0 has one entry (L0[0]) pointing to an L1 that contains kernel
/// block entries (L1[0], L1[1]) and user table entries (L1[2+]).
/// We only recurse into user table entries.
pub fn free_page_table_tree(root: usize) {
    let l0 = root as *const u64;
    unsafe {
        let entry0 = *l0.add(0);
        if entry0 & PT_VALID != 0 && entry0 & PT_TABLE != 0 {
            let l1 = (entry0 & 0x0000_FFFF_FFFF_F000) as usize;
            free_l1_user(l1);
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(l1));
        }
        // L0[1..511]: if any user tables exist at higher L0 indices, free them too.
        for i in 1..512 {
            let entry = *l0.add(i);
            if entry & PT_VALID != 0 && entry & PT_TABLE != 0 {
                let l1 = (entry & 0x0000_FFFF_FFFF_F000) as usize;
                free_l1_user(l1);
                crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(l1));
            }
        }
    }
    crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(root));
}

/// Free L2/L3 tables under an L1. Skip block descriptors (kernel entries).
unsafe fn free_l1_user(l1: usize) {
    let table = l1 as *const u64;
    for i in 0..512 {
        let entry = unsafe { *table.add(i) };
        // Only recurse into table descriptors, not blocks.
        if entry & PT_VALID != 0 && entry & PT_TABLE != 0 {
            // Check if this is an L1 block (1 GiB) — block descriptors have bit 1 clear.
            // Actually, for L1 entries, bit 1 == 1 means table, bit 1 == 0 means block.
            let l2 = (entry & 0x0000_FFFF_FFFF_F000) as usize;
            unsafe { free_l2_user(l2) };
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(l2));
        }
    }
}

/// Free L3 tables under an L2. Skip block descriptors (2 MiB kernel entries).
unsafe fn free_l2_user(l2: usize) {
    let table = l2 as *const u64;
    for i in 0..512 {
        let entry = unsafe { *table.add(i) };
        if entry & PT_VALID != 0 && entry & PT_TABLE != 0 {
            let l3 = (entry & 0x0000_FFFF_FFFF_F000) as usize;
            // L3 is a leaf table — just free it.
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(l3));
        }
    }
}

/// Switch the user page table to a different L0 root.
/// Used on context switch between tasks with different address spaces.
pub fn switch_page_table(root: usize) {
    unsafe {
        core::arch::asm!(
            "msr ttbr0_el1, {root}",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            root = in(reg) root as u64,
        );
    }
}

/// Enable the MMU with the given L0 page table in TTBR0.
pub fn enable_mmu(l0: usize) {
    unsafe {
        // MAIR: Attr0 = 0xFF (normal WB), Attr1 = 0x00 (device-nGnRnE).
        let mair: u64 = 0x00FF;
        core::arch::asm!("msr mair_el1, {}", in(reg) mair);

        // TCR_EL1: 48-bit VA, 4K granule, 40-bit PA.
        let tcr: u64 = (16 << 0)      // T0SZ = 16 (48-bit VA for TTBR0)
            | (0b00 << 14)             // TG0 = 4K
            | (0b010 << 32)            // IPS = 40-bit PA
            | (0b01 << 8)              // IRGN0 = WB WA
            | (0b01 << 10)             // ORGN0 = WB WA
            | (0b11 << 12)             // SH0 = Inner shareable
            | (1u64 << 23);            // EPD1 = 1 (disable TTBR1 walks)
        core::arch::asm!("msr tcr_el1, {}", in(reg) tcr);

        // Set TTBR0_EL1.
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) l0 as u64);

        // Barriers.
        core::arch::asm!("dsb ish");
        core::arch::asm!("isb");

        // Enable MMU.
        let mut sctlr: u64;
        core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr);
        sctlr |= 1 << 0;   // M: MMU enable
        sctlr |= 1 << 2;   // C: data cache enable
        sctlr |= 1 << 12;  // I: instruction cache enable
        core::arch::asm!("msr sctlr_el1, {}", in(reg) sctlr);
        core::arch::asm!("isb");
    }
    KERNEL_PT_ROOT.store(l0, Ordering::Release);
}

/// Enable MMU on a secondary CPU using the BSP's kernel page table.
/// Must be called early in secondary CPU init, before any non-identity-mapped access.
pub fn enable_mmu_secondary() {
    let l0 = KERNEL_PT_ROOT.load(Ordering::Acquire);
    assert!(l0 != 0, "BSP must enable MMU before secondaries");
    enable_mmu(l0);
}
