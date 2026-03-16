//! AArch64 MMU setup — identity-mapped kernel + user page tables.
//!
//! Uses 4 KiB MMU granule with 4-level page tables (48-bit VA).
//! Both kernel (identity-mapped) and user mappings go through TTBR0,
//! since the kernel runs at 0x4008_0000 (low VA space).

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
}
