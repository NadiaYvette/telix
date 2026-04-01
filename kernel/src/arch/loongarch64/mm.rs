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
/// Software-defined bit: shared page table marker (not-present entry).
const PTE_SHARED: u64 = 1 << 11;

const MMU_PAGE_SIZE: usize = 4096;

/// Read a page table entry via inline asm to prevent miscompilation.
#[inline(always)]
unsafe fn pte_read(ptr: *const u64) -> u64 {
    let val: u64;
    core::arch::asm!(
        "ld.d {val}, {ptr}, 0",
        ptr = in(reg) ptr,
        val = out(reg) val,
        options(nostack, preserves_flags, readonly),
    );
    val
}

/// Write a page table entry via inline asm + dbar to prevent miscompilation.
#[inline(always)]
unsafe fn pte_write(ptr: *mut u64, val: u64) {
    core::arch::asm!(
        "st.d {val}, {ptr}, 0",
        "dbar 0",
        ptr = in(reg) ptr,
        val = in(reg) val,
        options(nostack, preserves_flags),
    );
}

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
/// On LoongArch, directory entries must NOT have bit 0 set — the hardware
/// `lddir` instruction interprets bit 0 as the huge-page marker.
#[inline]
fn pte_table(phys: usize) -> u64 {
    phys as u64 & PFN_MASK
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
        // LoongArch uses bit 0 for V (leaf) but also HUGE (directory).
        // Directory entries don't set bit 0 (to avoid confusing the hardware
        // lddir instruction which treats bit 0 as the huge-page marker).
        // So validity = either PTE_V set (leaf) OR non-zero PA (directory).
        entry != 0
    }

    #[inline]
    fn is_table(entry: u64) -> bool {
        // Directory entries: non-zero, bit 0 (HUGE) = 0.
        // Leaf entries also have HUGE=0, but the generic walker only calls
        // is_table at non-leaf levels.
        entry != 0 && entry & PTE_HUGE == 0
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
            // dbar ensures all prior stores (page table writes) are globally
            // visible before flushing TLB, so the hardware walker sees them.
            core::arch::asm!("dbar 0", "invtlb 0, $zero, $zero");
        }
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
pub fn ensure_path_unshared(root: usize, va: usize, fg: *mut crate::mm::ptshare::ForkGroup) -> bool {
    radix_pt::ensure_path_unshared::<LoongArchPte>(root, va, fg)
}

/// Recursively free a page table subtree, handling shared markers.
pub fn free_shared_user_subtree(table_pa: usize, level: usize, fg: *mut crate::mm::ptshare::ForkGroup) {
    radix_pt::free_shared_subtree::<LoongArchPte>(table_pa, level, fg);
}

/// Share page table entries between parent and child at fork time.
///
/// On LoongArch64: kernel uses DMW, no kernel entries in user PT.
/// Share all valid table entries at root level.
pub fn clone_shared_tables(parent_root: usize, child_root: usize, fg: *mut crate::mm::ptshare::ForkGroup) {
    use crate::mm::ptshare::ForkGroup;

    let parent = parent_root as *mut u64;
    let child = child_root as *mut u64;

    for i in 0..512 {
        let entry = unsafe { pte_read(parent.add(i)) };
        if LoongArchPte::is_valid(entry) && LoongArchPte::is_table(entry) {
            let sub_pa = LoongArchPte::table_pa(entry);
            ForkGroup::share(fg, sub_pa);
            let shared = LoongArchPte::make_shared_entry(sub_pa);
            unsafe {
                pte_write(parent.add(i), shared);
                pte_write(child.add(i), shared);
            }
        } else if LoongArchPte::is_shared_entry(entry) {
            let sub_pa = LoongArchPte::shared_entry_pa(entry);
            ForkGroup::share(fg, sub_pa);
            unsafe {
                pte_write(child.add(i), entry);
            }
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

/// Configure DMW windows, page walk controller, TLB refill, and enable paging.
pub fn enable_mmu(root: usize) {
    KERNEL_PT_ROOT.store(root, Ordering::Release);

    // Read current CRMD for diagnostics.
    let crmd: u64;
    unsafe { core::arch::asm!("csrrd {}, 0x0", out(reg) crmd) };
    crate::println!(
        "  CRMD at enable_mmu: {:#x} (DA={}, PG={}, PLV={})",
        crmd,
        (crmd >> 3) & 1,
        (crmd >> 4) & 1,
        crmd & 3
    );

    unsafe {
        // Configure DMW0: 0x9000_xxxx → PA, cached (MAT=1), PLV0 only.
        let dmw0: u64 = (0x9000u64 << 48) | (1u64 << 4) | 1;
        core::arch::asm!("csrwr {}, 0x180", in(reg) dmw0);

        // Configure DMW1: 0x8000_xxxx → PA, uncached (MAT=0), PLV0 only.
        let dmw1: u64 = (0x8000u64 << 48) | 1;
        core::arch::asm!("csrwr {}, 0x181", in(reg) dmw1);

        // Configure page walk controller for 4-level 4K page tables.
        // PWCL layout: PTbase[4:0], PTwidth[9:5], Dir1base[14:10], Dir1width[19:15],
        //              Dir2base[24:20], Dir2width[29:25]
        // PWCH layout: Dir3base[5:0], Dir3width[11:6]
        let pwcl: u64 = 12 | (9 << 5) | (21 << 10) | (9 << 15) | (30 << 20) | (9 << 25);
        core::arch::asm!("csrwr {}, 0x1C", in(reg) pwcl);

        let pwch: u64 = 39 | (9 << 6);
        core::arch::asm!("csrwr {}, 0x1D", in(reg) pwch);

        // STLBPS = 12 (4K page size, log2).
        core::arch::asm!("csrwr {}, 0x1E", in(reg) 12u64);

        // Set PGDL (user page table root — low VA region).
        core::arch::asm!("csrwr {}, 0x19", in(reg) root as u64);
        // Set PGDH (kernel PT — not used with DMW, but set for completeness).
        core::arch::asm!("csrwr {}, 0x1A", in(reg) root as u64);

        // Install TLB refill handler.
        core::arch::asm!(
            "la.pcrel {tmp}, _tlb_refill",
            "csrwr {tmp}, 0x88",  // CSR.TLBRENTRY
            tmp = out(reg) _,
        );

        // Configure DMW2: identity-map low PAs (VSEG=0x0), cached, PLV0 only.
        // The kernel binary is linked at 0x9000... but QEMU loads it at low PAs
        // and all runtime addresses (PC-relative) resolve to low PAs. DMW2 keeps
        // these accessible after the DA→PG switch. PLV0-only so it doesn't
        // interfere with user-space TLB lookups.
        let dmw2: u64 = (0x0000u64 << 48) | (1u64 << 4) | 1; // MAT=CC, PLV0
        core::arch::asm!("csrwr {}, 0x182", in(reg) dmw2); // CSR.DMW2

        // If already in PG mode (firmware set it up), just flush TLB.
        if crmd & (1 << 4) != 0 {
            core::arch::asm!("invtlb 0, $zero, $zero");
            return;
        }

        // Switch from DA mode to PG mode.
        // After this write, instruction fetch and data access use DMW/TLB.
        // DMW2 (VSEG=0) covers our current low-PA code and stack, so
        // execution continues seamlessly — no jump or SP rebase needed.
        let new_crmd: u64 = (1 << 4)  // PG=1
                          | (crmd & (1 << 2)); // preserve IE
        core::arch::asm!("csrwr {}, 0x0", in(reg) new_crmd);

        // Flush any stale TLB entries from firmware.
        core::arch::asm!("invtlb 0, $r0, $r0");
    }
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
pub fn switch_page_table(root: usize) {
    unsafe {
        // dbar ensures all prior stores are visible before switching PT root.
        core::arch::asm!("dbar 0");
        core::arch::asm!("csrwr {}, 0x19", in(reg) root as u64); // CSR.PGDL
        // Flush user TLB entries (type 4 = flush non-global entries).
        core::arch::asm!("invtlb 4, $zero, $zero");
    }
}

/// Free all intermediate page table pages in the tree rooted at `root`.
pub fn free_page_table_tree(root_addr: usize, fg: *mut crate::mm::ptshare::ForkGroup) {
    use crate::mm::{ptshare::ForkGroup, page::PhysAddr};

    let root = root_addr as *const u64;
    unsafe {
        for i in 0..512 {
            let entry = *root.add(i);
            if LoongArchPte::is_shared_entry(entry) {
                let sub_pa = LoongArchPte::shared_entry_pa(entry);
                let rc = ForkGroup::unshare(fg, sub_pa);
                if rc == 0 {
                    free_shared_user_subtree(sub_pa, 1, fg);
                    crate::mm::phys::free_page(PhysAddr::new(sub_pa));
                }
            } else if LoongArchPte::is_valid(entry) && LoongArchPte::is_table(entry) {
                let l1 = LoongArchPte::table_pa(entry);
                free_shared_user_subtree(l1, 1, fg);
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
    let slot = match radix_pt::walk_or_create::<LoongArchPte>(root, va) {
        Some(s) => s,
        None => return false,
    };
    unsafe {
        pte_write(slot, pte_leaf(pa, flags));
    }
    LoongArchPte::tlb_invalidate(va);
    true
}

pub fn unmap_single_mmupage(root: usize, va: usize) -> usize {
    let slot = match radix_pt::walk_to_leaf::<LoongArchPte>(root, va) {
        Some(s) => s,
        None => return 0,
    };
    let entry = unsafe { pte_read(slot) };
    if entry & PTE_V == 0 {
        return 0;
    }
    let pa = (entry & PFN_MASK) as usize;
    unsafe {
        pte_write(slot, 0);
    }
    LoongArchPte::tlb_invalidate(va);
    pa
}

pub fn read_pte(root: usize, va: usize) -> u64 {
    match radix_pt::walk_to_leaf::<LoongArchPte>(root, va) {
        Some(slot) => unsafe { pte_read(slot) },
        None => 0,
    }
}

pub fn evict_mmupage(root: usize, va: usize) -> usize {
    let slot = match radix_pt::walk_to_leaf::<LoongArchPte>(root, va) {
        Some(s) => s,
        None => return 0,
    };
    let entry = unsafe { pte_read(slot) };
    if entry & PTE_V == 0 {
        return 0;
    }
    let pa = (entry & PFN_MASK) as usize;
    unsafe {
        pte_write(slot, entry & PTE_SW_ZEROED);
    }
    LoongArchPte::tlb_invalidate(va);
    pa
}

pub fn clear_pte(root: usize, va: usize) {
    let slot = match radix_pt::walk_to_leaf::<LoongArchPte>(root, va) {
        Some(s) => s,
        None => return,
    };
    let entry = unsafe { pte_read(slot) };
    if entry != 0 {
        unsafe {
            pte_write(slot, 0);
        }
        LoongArchPte::tlb_invalidate(va);
    }
}

pub fn read_and_clear_ref_bit(root: usize, va: usize) -> bool {
    let slot = match radix_pt::walk_to_leaf::<LoongArchPte>(root, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { pte_read(slot) };
    if entry & PTE_V == 0 {
        return false;
    }
    let referenced = (entry & PTE_SW_REF) != 0;
    if referenced {
        unsafe {
            pte_write(slot, entry & !PTE_SW_REF);
        }
        LoongArchPte::tlb_invalidate(va);
    }
    referenced
}

pub fn translate_va(root: usize, va: usize) -> Option<usize> {
    let slot = radix_pt::walk_to_leaf::<LoongArchPte>(root, va)?;
    let entry = unsafe { pte_read(slot) };
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
    let entry = unsafe { pte_read(slot) };
    if entry & PTE_V == 0 {
        return false;
    }
    unsafe {
        pte_write(slot, entry & !PTE_D);
    }
    LoongArchPte::tlb_invalidate(va);
    true
}

pub fn update_pte_flags(root: usize, va: usize, new_flags: u64) -> bool {
    let slot = match radix_pt::walk_to_leaf::<LoongArchPte>(root, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { pte_read(slot) };
    if entry & PTE_V == 0 {
        return false;
    }
    let pa_and_sw = (entry & PFN_MASK) | (entry & PTE_SW_ZEROED);
    unsafe {
        pte_write(slot, pa_and_sw | new_flags);
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
            pte_write(slot, pte_leaf(pa, flags));
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

    let old_entry = unsafe { pte_read(slot) };
    if old_entry & PTE_V != 0 && LoongArchPte::is_table(old_entry) {
        let table_addr = (old_entry & PFN_MASK) as usize;
        crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(table_addr));
    }

    unsafe {
        pte_write(slot, pte_leaf(pa, flags | PTE_HUGE));
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
    let entry = unsafe { pte_read(slot) };
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

    let entry = unsafe { pte_read(slot) };
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
            pte_write(table_ptr.add(i), pte_leaf(pa, flags));
        }
    }

    unsafe {
        pte_write(slot, pte_table(new_table));
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
