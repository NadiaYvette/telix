//! AArch64 MMU setup — identity-mapped kernel + user page tables.
//!
//! Uses 4 KiB MMU granule with 4-level page tables (48-bit VA).
//! Both kernel (identity-mapped) and user mappings go through TTBR0,
//! since the kernel runs at 0x4008_0000 (low VA space).

use crate::mm::radix_pt::{self, PteFormat};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Kernel page table root (L0), set by BSP after enable_mmu.
/// Used by secondary CPUs to enable their MMU with the same identity mapping.
static KERNEL_PT_ROOT: AtomicUsize = AtomicUsize::new(0);

/// Page table entry flags.
const PT_VALID: u64 = 1 << 0;
const PT_TABLE: u64 = 1 << 1; // Non-leaf: next-level table
const PT_PAGE: u64 = 1 << 1; // Level 3: 4K page
const PT_AF: u64 = 1 << 10; // Access flag
const PT_SH_INNER: u64 = 3 << 8; // Inner shareable
const PT_AP_RW_EL1: u64 = 0 << 6; // EL1 RW, EL0 no access
const PT_AP_RW_ALL: u64 = 1 << 6; // EL1 RW, EL0 RW
const PT_UXN: u64 = 1 << 54; // Unprivileged execute-never
const PT_PXN: u64 = 1 << 53; // Privileged execute-never
const PT_CONTIGUOUS: u64 = 1 << 52; // Contiguous hint (16 × 4K = 64K group)
/// Software-defined bit: page content has been initialized (zeroed/filled).
/// Stored in bits [58:55] which are reserved for software use.
pub const PTE_SW_ZEROED: u64 = 1 << 55;
/// Software-defined bit: shared page table marker (not-present entry).
const PTE_SHARED: u64 = 1 << 11;
const PT_ATTR_IDX_0: u64 = 0 << 2; // MAIR index 0 (normal memory)
const PT_ATTR_IDX_1: u64 = 1 << 2; // MAIR index 1 (device memory)

/// Standard flags.
const KERN_BLOCK: u64 = PT_VALID | PT_AF | PT_SH_INNER | PT_AP_RW_EL1 | PT_ATTR_IDX_0 | PT_UXN;
const DEV_BLOCK: u64 = PT_VALID | PT_AF | PT_AP_RW_EL1 | PT_ATTR_IDX_1 | PT_UXN | PT_PXN;
const USER_PAGE: u64 = PT_VALID | PT_PAGE | PT_AF | PT_SH_INNER | PT_AP_RW_ALL | PT_ATTR_IDX_0;

const MMU_PAGE_SIZE: usize = 4096;
const PA_MASK: u64 = 0x0000_FFFF_FFFF_F000;

// ============================================================================
// SLAB_THREAD_REGION (#260 step 2: per-Thread VA window with guard pages).
//
// Sits in L1[3] of the kernel's TTBR0 L0 sub-tree — VA 0xC000_0000 onwards,
// the next 1 GiB after the 2 GiB RAM identity map.  Every aspace's L0
// (kernel + every user PT created via setup_tables) installs the SAME
// physical L2 sub-tree at L1[3], so Thread VA windows are visible from
// every active context — matching x86_64's SLAB_THREAD_REGION semantics
// (which on x86 are reachable from every cr3 because they live in the
// PML4 kernel half).
//
// Each Thread gets a 16 KiB VA window with one 4 KiB phys page mapped
// at the TOP and 12 KiB of unmapped guard below.  A stray write to a
// Thread struct's address from unrelated kernel code (e.g., extent-tree
// pointer arithmetic landing in the slab region) faults instead of
// silently scribbling a sibling Thread.
//
// Step 1 (commit 09cb0d4) gave each Thread its own dedicated 4 KiB phys
// page; this step adds the unmapped-guard layout around that page so
// stray writes near it also fault.
// ============================================================================

/// VA base of the SLAB_THREAD_REGION (3 GiB; covered by L1[3]).
pub const SLAB_THREAD_REGION_BASE: u64 = 0xC000_0000;

/// Size of each Thread's VA window (16 KiB): 4 KiB mapped at top + 12 KiB guard.
pub const SLAB_THREAD_WINDOW_SIZE: u64 = 16 * 1024;

/// Shared L2 sub-tree PA covering SLAB_THREAD_REGION's 1 GiB L1 slot.
/// Allocated on the first setup_tables() call; reused by subsequent calls
/// so every aspace's L1[3] points at the same physical L2.
static SHARED_SLAB_THREAD_L2_PA: AtomicUsize = AtomicUsize::new(0);

/// Bump-pointer cursor for SLAB_THREAD_REGION VA windows.  Skip the first
/// window so `base + offset` doesn't collide with code that treats
/// null-ish VAs specially.
static SLAB_THREAD_VA_NEXT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(SLAB_THREAD_REGION_BASE + SLAB_THREAD_WINDOW_SIZE);

/// Serializes concurrent calls to `map_slab_thread_window`.  Needed
/// because `radix_pt::walk_or_create` has a race: two CPUs both reading
/// an L2 slot as 0, both allocating a fresh L3 table, both writing the
/// L2 slot — one CPU's L3 is lost AND its leaf writes go to a now-
/// orphaned table.  Surface = intermittent `Translation fault level
/// 2/3` on Thread VAs that should be mapped.  Lock-around fixes
/// trivially since map_single_mmupage is fast.
static MAP_LOCK: crate::sync::spinlock::SpinLock<()> =
    crate::sync::spinlock::SpinLock::new(());

/// Reserve the next 16 KiB VA window in SLAB_THREAD_REGION.  Returns the
/// VA base (low address).  The Thread struct lives in the TOP 4 KiB;
/// the bottom 12 KiB stays unmapped (guard).
#[inline]
pub fn alloc_slab_thread_va_window() -> u64 {
    SLAB_THREAD_VA_NEXT.fetch_add(
        SLAB_THREAD_WINDOW_SIZE,
        core::sync::atomic::Ordering::Relaxed,
    )
}

/// Map a single 4 KiB phys page at the TOP of a SLAB_THREAD_REGION VA
/// window.  Returns the VA of the mapped page.  Uses the kernel's L0
/// (which has L1[3] → SHARED_SLAB_THREAD_L2); the mapping is visible
/// from every aspace because every aspace's L1[3] points at the same L2.
pub fn map_slab_thread_window(va_window_base: u64, pa: usize) -> Option<u64> {
    let kernel_l0 = KERNEL_PT_ROOT.load(Ordering::Acquire);
    if kernel_l0 == 0 {
        return None;
    }
    let va = va_window_base + SLAB_THREAD_WINDOW_SIZE - MMU_PAGE_SIZE as u64;
    let flags = PT_VALID | PT_PAGE | PT_AF | PT_SH_INNER | PT_AP_RW_EL1
        | PT_ATTR_IDX_0 | PT_UXN | PT_PXN;
    let _guard = MAP_LOCK.lock();
    if !map_single_mmupage(kernel_l0, va as usize, pa, flags) {
        return None;
    }
    Some(va)
}

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
///   0x4000_0000 - 0xBFFF_FFFF: RAM (2 GiB, covers QEMU virt -m 2G)
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

    // L1[1..3]: identity-map 2 GiB of RAM (0x4000_0000 - 0xBFFF_FFFF)
    // via per-1 GiB L2 tables of 2 MiB blocks.  Without this, allocator
    // returns past 0x5000_0000 fault EL1 Data Abort in memset (#246
    // residual surfaced after Phase 4 progress).
    for gib in 0..2 {
        let l2 = alloc_table()?;
        let l2_table = l2 as *mut u64;
        unsafe {
            *l1_table.add(1 + gib) = (l2 as u64) | PT_VALID | PT_TABLE;
        }
        let l1_base = 0x4000_0000u64 + (gib as u64) * 0x4000_0000;
        for i in 0..512 {
            let phys = l1_base + (i as u64) * 0x20_0000;
            unsafe {
                *l2_table.add(i) = phys | KERN_BLOCK;
            }
        }
    }

    // L1[3]: SLAB_THREAD_REGION shared L2 sub-tree (1 GiB at VA 0xC000_0000).
    // Allocate the L2 on first call (BSP MMU bring-up); reuse across all
    // subsequent setup_tables calls so every aspace's L1[3] points at the
    // same physical L2.  This is what makes the per-Thread VA windows
    // visible from every active TTBR0 context.
    let shared_l2_pa = {
        let existing = SHARED_SLAB_THREAD_L2_PA.load(Ordering::Acquire);
        if existing != 0 {
            existing
        } else {
            let new_l2 = alloc_table()?;
            match SHARED_SLAB_THREAD_L2_PA.compare_exchange(
                0,
                new_l2,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => new_l2,
                Err(winning) => {
                    // Lost the init race; the page we allocated leaks (rare,
                    // happens at most once per boot since CAS only fires
                    // when racing setup_tables on different CPUs).
                    winning
                }
            }
        }
    };
    unsafe {
        *l1_table.add(3) = (shared_l2_pa as u64) | PT_VALID | PT_TABLE;
    }

    Some(l0)
}

/// Allocate a fresh user page table (alias for setup_tables).
pub fn create_user_page_table() -> Option<usize> {
    setup_tables()
}

/// Add user 4K page mappings to an existing L0 table.
#[allow(dead_code)]
pub fn map_user_pages(l0: usize, virt: usize, phys: usize, size: usize, flags: u64) -> Option<()> {
    let num_pages = (size + MMU_PAGE_SIZE - 1) / MMU_PAGE_SIZE;

    for i in 0..num_pages {
        let va = virt + i * MMU_PAGE_SIZE;
        let pa = phys + i * MMU_PAGE_SIZE;

        let slot = radix_pt::walk_or_create::<Aarch64Pte>(l0, va)?;
        unsafe {
            *slot = (pa as u64) | flags;
        }
    }
    Some(())
}

/// Public user page flags for use from main.rs.
pub const USER_RWX_FLAGS: u64 = USER_PAGE;
pub const USER_RW_FLAGS: u64 = USER_PAGE | PT_UXN;
/// Read-only user page: AP = 11 (EL1 RO, EL0 RO), no execute.
const PT_AP_RO_ALL: u64 = 3 << 6;
pub const USER_RO_FLAGS: u64 =
    PT_VALID | PT_PAGE | PT_AF | PT_SH_INNER | PT_AP_RO_ALL | PT_ATTR_IDX_0 | PT_UXN;
/// R-X (executable, NOT writable): AP_RO_ALL, no UXN.  W^X for .text.
pub const USER_RX_FLAGS: u64 =
    PT_VALID | PT_PAGE | PT_AF | PT_SH_INNER | PT_AP_RO_ALL | PT_ATTR_IDX_0;

// ---------------------------------------------------------------------------
// PteFormat implementation for the generic radix walker
// ---------------------------------------------------------------------------

pub struct Aarch64Pte;

impl crate::mm::radix_pt::PteFormat for Aarch64Pte {
    const LEVELS: usize = 4;

    #[inline]
    fn va_index(va: usize, level: usize) -> usize {
        const SHIFTS: [usize; 4] = [39, 30, 21, 12];
        (va >> SHIFTS[level]) & 0x1FF
    }

    #[inline]
    fn is_valid(entry: u64) -> bool {
        entry & PT_VALID != 0
    }

    #[inline]
    fn is_table(entry: u64) -> bool {
        entry & PT_TABLE != 0
    }

    #[inline]
    fn table_pa(entry: u64) -> usize {
        (entry & 0x0000_FFFF_FFFF_F000) as usize
    }

    #[inline]
    fn leaf_pa(entry: u64) -> usize {
        (entry & 0x0000_FFFF_FFFF_F000) as usize
    }

    #[inline]
    fn make_table_entry(table_pa: usize) -> u64 {
        (table_pa as u64) | PT_VALID | PT_TABLE
    }

    #[inline]
    fn tlb_invalidate(va: usize) {
        unsafe {
            let va_shifted = (va >> 12) as u64;
            core::arch::asm!("tlbi vale1is, {}", in(reg) va_shifted);
            core::arch::asm!("dsb ish");
            core::arch::asm!("isb");
        }
    }

    #[inline]
    fn make_shared_entry(table_pa: usize) -> u64 {
        (table_pa as u64 & PA_MASK) | PTE_SHARED
    }

    #[inline]
    fn is_shared_entry(entry: u64) -> bool {
        entry & PT_VALID == 0 && entry & PTE_SHARED != 0
    }

    #[inline]
    fn shared_entry_pa(entry: u64) -> usize {
        (entry & PA_MASK) as usize
    }

    #[inline]
    fn make_readonly(entry: u64) -> u64 {
        // Set AP[2] (bit 7) — makes both EL1 and EL0 read-only.
        entry | (1 << 7)
    }
}

// ---------------------------------------------------------------------------
// Shared page table support
// ---------------------------------------------------------------------------

/// Ensure the walk path for `va` contains no shared markers (COW-break).
#[inline]
pub fn ensure_path_unshared(root: usize, va: usize, fg: *mut crate::mm::ptshare::ForkGroup) -> bool {
    radix_pt::ensure_path_unshared::<Aarch64Pte>(root, va, fg)
}

/// Recursively free a page table subtree, handling shared markers.
pub fn free_shared_user_subtree(table_pa: usize, level: usize, fg: *mut crate::mm::ptshare::ForkGroup) {
    radix_pt::free_shared_subtree::<Aarch64Pte>(table_pa, level, fg);
}

/// Share page table entries between parent and child at fork time.
///
/// On AArch64: L0[0] → L1 table has kernel/device blocks at L1[0-1]
/// and user table entries at L1[2+]. Share L1[2+].
pub fn clone_shared_tables(parent_root: usize, child_root: usize, fg: *mut crate::mm::ptshare::ForkGroup) {
    use crate::mm::ptshare::ForkGroup;

    let parent_l0_0 = unsafe { *(parent_root as *const u64) };
    let child_l0_0 = unsafe { *(child_root as *const u64) };

    if !Aarch64Pte::is_valid(parent_l0_0)
        || !Aarch64Pte::is_table(parent_l0_0)
        || !Aarch64Pte::is_valid(child_l0_0)
        || !Aarch64Pte::is_table(child_l0_0)
    {
        return;
    }

    let parent_l1 = Aarch64Pte::table_pa(parent_l0_0) as *mut u64;
    let child_l1 = Aarch64Pte::table_pa(child_l0_0) as *mut u64;

    // Slot map (see setup_tables): L1[0]=device block, L1[1..2]=RAM-identity
    // L2s, L1[3]=globally-shared SLAB_THREAD L2.  All of L1[0..=3] are
    // kernel/shared and the child already has them from
    // create_user_page_table(); COW-sharing them here would treat kernel
    // RAM as COW (L1[1..2]) or hand the globally-shared Thread L2 to the
    // fork group's refcount (L1[3]) — the #261 bug via the fork path.
    // Share only true-user slots L1[4..].
    for i in 4..512 {
        let entry = unsafe { *parent_l1.add(i) };
        if Aarch64Pte::is_valid(entry) && Aarch64Pte::is_table(entry) {
            let sub_pa = Aarch64Pte::table_pa(entry);
            ForkGroup::share(fg, sub_pa);
            let shared = Aarch64Pte::make_shared_entry(sub_pa);
            unsafe {
                *parent_l1.add(i) = shared;
                *child_l1.add(i) = shared;
            }
        } else if Aarch64Pte::is_shared_entry(entry) {
            let sub_pa = Aarch64Pte::shared_entry_pa(entry);
            ForkGroup::share(fg, sub_pa);
            unsafe {
                *child_l1.add(i) = entry;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-MMU-page operations for demand paging
// ---------------------------------------------------------------------------

/// Map a single 4K MMU page at `va` to physical address `pa` with given flags.
/// Creates intermediate table entries as needed. Invalidates TLB for the VA.
pub fn map_single_mmupage(l0: usize, va: usize, pa: usize, flags: u64) -> bool {
    let slot = match radix_pt::walk_or_create::<Aarch64Pte>(l0, va) {
        Some(s) => s,
        None => return false,
    };
    unsafe {
        *slot = (pa as u64) | flags;
    }
    Aarch64Pte::tlb_invalidate(va);
    true
}

/// Unmap a single 4K MMU page at `va`. Returns the old physical address, or 0 if not mapped.
#[allow(dead_code)]
pub fn unmap_single_mmupage(l0: usize, va: usize) -> usize {
    let slot = match radix_pt::walk_to_leaf::<Aarch64Pte>(l0, va) {
        Some(s) => s,
        None => return 0,
    };
    let entry = unsafe { *slot };
    if entry & PT_VALID == 0 {
        return 0;
    }
    let pa = (entry & PA_MASK) as usize;
    unsafe {
        *slot = 0;
    }
    Aarch64Pte::tlb_invalidate(va);
    pa
}

/// Evict a 4K MMU page: clear valid bit but preserve PTE_SW_ZEROED hint.
/// Returns the old physical address, or 0 if not mapped. Used by WSCLOCK.
pub fn evict_mmupage(l0: usize, va: usize) -> usize {
    let slot = match radix_pt::walk_to_leaf::<Aarch64Pte>(l0, va) {
        Some(s) => s,
        None => return 0,
    };
    let entry = unsafe { *slot };
    if entry & PT_VALID == 0 {
        return 0;
    }
    let pa = (entry & PA_MASK) as usize;
    unsafe {
        *slot = entry & PTE_SW_ZEROED;
    }
    Aarch64Pte::tlb_invalidate(va);
    pa
}

/// Clear a PTE entirely (valid + SW bits). Used for madvise_dontneed and cleanup.
pub fn clear_pte(l0: usize, va: usize) {
    let slot = match radix_pt::walk_to_leaf::<Aarch64Pte>(l0, va) {
        Some(s) => s,
        None => return,
    };
    let entry = unsafe { *slot };
    if entry != 0 {
        unsafe {
            *slot = 0;
        }
        Aarch64Pte::tlb_invalidate(va);
    }
}

/// Read and clear the Access Flag (AF) for the PTE at `va`.
/// Returns true if AF was set (page was referenced).
pub fn read_and_clear_ref_bit(l0: usize, va: usize) -> bool {
    let slot = match radix_pt::walk_to_leaf::<Aarch64Pte>(l0, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { *slot };
    if entry & PT_VALID == 0 {
        return false;
    }
    let referenced = (entry & PT_AF) != 0;
    if referenced {
        unsafe {
            *slot = entry & !PT_AF;
        }
        Aarch64Pte::tlb_invalidate(va);
    }
    referenced
}

/// Translate a user VA to a physical address by walking the page table.
/// Returns None if the page is not mapped.
pub fn translate_va(l0: usize, va: usize) -> Option<usize> {
    let slot = radix_pt::walk_to_leaf::<Aarch64Pte>(l0, va)?;
    let entry = unsafe { *slot };
    if entry & PT_VALID == 0 {
        return None;
    }
    let pa = (entry & PA_MASK) as usize;
    Some(pa | (va & 0xFFF))
}

/// Read the raw L3 PTE for a VA. Returns 0 if any level is missing.
#[allow(dead_code)]
pub fn read_pte(l0: usize, va: usize) -> u64 {
    match radix_pt::walk_to_leaf::<Aarch64Pte>(l0, va) {
        Some(slot) => unsafe { *slot },
        None => 0,
    }
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

    // Walk to the first slot in the L3 table for this group.
    let first_slot = match radix_pt::walk_to_leaf::<Aarch64Pte>(l0, group_va) {
        Some(s) => s,
        None => return false,
    };

    // Verify all 16 PTEs are valid and don't already have the contiguous bit.
    for i in 0..CONTIGUOUS_GROUP_SIZE {
        let entry = unsafe { *first_slot.add(i) };
        if entry & PT_VALID == 0 {
            return false;
        }
    }

    // Check if already promoted.
    let first = unsafe { *first_slot };
    if first & PT_CONTIGUOUS != 0 {
        return false;
    }

    // Set the contiguous bit on all 16 PTEs.
    for i in 0..CONTIGUOUS_GROUP_SIZE {
        unsafe {
            let entry = *first_slot.add(i);
            *first_slot.add(i) = entry | PT_CONTIGUOUS;
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
    let slot = match radix_pt::walk_to_leaf::<Aarch64Pte>(l0, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { *slot };
    if entry & PT_VALID == 0 {
        return false;
    }
    // Set AP[2] (bit 7) to make read-only: AP=11 means EL1/EL0 read-only.
    unsafe {
        *slot = entry | (1 << 7);
    }
    Aarch64Pte::tlb_invalidate(va);
    true
}

/// Update the flags of an existing 4K PTE, keeping the physical address.
/// Returns true if the PTE was present and updated.
pub fn update_pte_flags(l0: usize, va: usize, new_flags: u64) -> bool {
    let slot = match radix_pt::walk_to_leaf::<Aarch64Pte>(l0, va) {
        Some(s) => s,
        None => return false,
    };
    let entry = unsafe { *slot };
    if entry & PT_VALID == 0 {
        return false;
    }
    let pa_and_sw = entry & (PA_MASK | PTE_SW_ZEROED);
    unsafe {
        *slot = pa_and_sw | new_flags;
    }
    Aarch64Pte::tlb_invalidate(va);
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

    let slot = match radix_pt::walk_or_create_to_super::<Aarch64Pte>(l0, va) {
        Some(s) => s,
        None => return false,
    };

    let old_entry = unsafe { *slot };

    // If there was an L3 table (table descriptor), free it.
    if old_entry & PT_VALID != 0 && old_entry & PT_TABLE != 0 {
        let l3_addr = (old_entry & PA_MASK) as usize;
        crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(l3_addr));
    }

    // Block descriptor: bit[1:0] = 01 (valid, not table).
    // Strip PT_PAGE/PT_TABLE (bit 1) from flags, keep everything else.
    let block_flags = (flags & !0x2) | PT_VALID;
    unsafe {
        *slot = (pa as u64 & !0x1FFFFF) | block_flags;
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
    let slot = radix_pt::walk_to_super_slot::<Aarch64Pte>(l0, va)?;
    let entry = unsafe { *slot };
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
    let slot = match radix_pt::walk_to_super_slot::<Aarch64Pte>(l0, va) {
        Some(s) => s,
        None => return false,
    };

    let entry = unsafe { *slot };
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
        *slot = (l3 as u64) | PT_VALID | PT_TABLE;
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

// ---------------------------------------------------------------------------
// Level-parameterized superpage operations
// ---------------------------------------------------------------------------

use crate::mm::page::SuperpageLevel;

/// Install a block descriptor at an arbitrary page table level.
pub fn install_superpage_at_level(
    l0: usize,
    va: usize,
    pa: usize,
    flags: u64,
    level: &SuperpageLevel,
) -> bool {
    debug_assert!(va & level.align_mask() == 0);
    debug_assert!(pa & level.align_mask() == 0);

    let slot = match radix_pt::walk_or_create_to_level::<Aarch64Pte>(
        l0,
        va,
        level.pt_level as usize,
    ) {
        Some(s) => s,
        None => return false,
    };

    let old_entry = unsafe { *slot };

    // If the old entry was a table pointer, free the sub-table.
    if old_entry & PT_VALID != 0 && old_entry & PT_TABLE != 0 {
        let table_addr = (old_entry & PA_MASK) as usize;
        crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(table_addr));
    }

    // Block descriptor: valid, NOT table (bit 1 clear).
    let block_flags = (flags & !0x2) | PT_VALID;
    let pa_mask = !(level.align_mask() as u64);
    unsafe {
        *slot = (pa as u64 & pa_mask) | block_flags;
    }

    // TLB invalidate — one per sub-page of the block.
    let mmu_count = level.mmu_pages();
    for i in 0..mmu_count {
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

/// Check if `va` is mapped as a block descriptor at the given level.
pub fn is_superpage_at_level(
    l0: usize,
    va: usize,
    level: &SuperpageLevel,
) -> Option<usize> {
    let slot =
        radix_pt::walk_to_level_slot::<Aarch64Pte>(l0, va, level.pt_level as usize)?;
    let entry = unsafe { *slot };
    if entry & PT_VALID != 0 && entry & PT_TABLE == 0 {
        let pa = (entry & PA_MASK) as usize & !level.align_mask();
        Some(pa)
    } else {
        None
    }
}

/// Demote a block descriptor at the given level into 512 entries one level down.
/// If demoting to L3 (leaf level), produces page entries (bit 1 set).
/// Otherwise, produces block descriptors (bit 1 clear).
pub fn demote_superpage_at_level(
    l0: usize,
    va: usize,
    flags: u64,
    level: &SuperpageLevel,
) -> bool {
    let slot = match radix_pt::walk_to_level_slot::<Aarch64Pte>(
        l0,
        va,
        level.pt_level as usize,
    ) {
        Some(s) => s,
        None => return false,
    };

    let entry = unsafe { *slot };
    if entry & PT_VALID == 0 || entry & PT_TABLE != 0 {
        return false;
    }

    let base_pa = (entry & PA_MASK) as usize & !level.align_mask();
    let sub_size = level.size / 512;
    let sub_is_leaf = (level.pt_level as usize + 1) == Aarch64Pte::LEVELS - 1;

    let new_table = match alloc_table() {
        Some(t) => t,
        None => return false,
    };
    let table_ptr = new_table as *mut u64;

    for i in 0..512usize {
        let pa = base_pa + i * sub_size;
        let sub_entry = if sub_is_leaf {
            // L3 page entry: bit 1 (PT_PAGE) set.
            (pa as u64) | flags
        } else {
            // Block descriptor: bit 1 clear.
            let block_flags = (flags & !0x2) | PT_VALID;
            let sub_mask = !(sub_size as u64 - 1);
            (pa as u64 & sub_mask) | block_flags
        };
        unsafe {
            *table_ptr.add(i) = sub_entry;
        }
    }

    // Replace block with table pointer.
    unsafe {
        *slot = (new_table as u64) | PT_VALID | PT_TABLE;
    }

    // TLB invalidate the full range.
    let mmu_count = level.mmu_pages();
    for i in 0..mmu_count {
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
pub fn free_page_table_tree(root: usize, fg: *mut crate::mm::ptshare::ForkGroup) {
    use crate::mm::page::PhysAddr;

    let l0 = root as *const u64;
    unsafe {
        // L0[0] → per-process L1 table.  Slot map (see setup_tables):
        //   L1[0]    device 1 GiB block (not a table — skipped naturally)
        //   L1[1..2] per-process RAM-identity L2 tables (2 MiB blocks;
        //            the L2 table pages are per-process, freeing them is
        //            correct and the block leaves are never freed)
        //   L1[3]    GLOBALLY-SHARED SLAB_THREAD_REGION L2
        //            (SHARED_SLAB_THREAD_L2_PA) — installed identically in
        //            every aspace by setup_tables(); MUST NOT be freed.
        //   L1[4..]  user mappings (processes load at VA 0x1_0000_0000+)
        //
        // #261: freeing L1[3]'s subtree on aspace teardown returns the
        // shared L2 + its L3 leaf tables to the allocator; the next
        // allocation reuses them, unmapping every live Thread's
        // 0xC000_0000+ VA window, after which the scheduler takes EL1
        // translation-level-3 Data Aborts dereferencing Thread structs.
        // Detach the slot before the recursive free so the shared L2 is
        // never descended into or freed (twin of x86 PML4[507..] fix).
        let entry0 = *l0.add(0);
        if entry0 & PT_VALID != 0 && entry0 & PT_TABLE != 0 {
            let l1 = (entry0 & PA_MASK) as usize;
            let l1p = l1 as *mut u64;
            *l1p.add(3) = 0;
            free_shared_user_subtree(l1, 1, fg);
            crate::mm::phys::free_page(PhysAddr::new(l1));
        }
        // L0[1..511]: if any tables exist, free them too.
        for i in 1..512 {
            let entry = *l0.add(i);
            if entry & PT_VALID != 0 && entry & PT_TABLE != 0 {
                let l1 = (entry & PA_MASK) as usize;
                free_shared_user_subtree(l1, 1, fg);
                crate::mm::phys::free_page(PhysAddr::new(l1));
            }
        }
    }
    crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(root));
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
            | (1u64 << 23); // EPD1 = 1 (disable TTBR1 walks)
        core::arch::asm!("msr tcr_el1, {}", in(reg) tcr);

        // Set TTBR0_EL1.
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) l0 as u64);

        // Barriers.
        core::arch::asm!("dsb ish");
        core::arch::asm!("isb");

        // Enable MMU.
        let mut sctlr: u64;
        core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr);
        sctlr |= 1 << 0; // M: MMU enable
        sctlr |= 1 << 2; // C: data cache enable
        sctlr |= 1 << 12; // I: instruction cache enable
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
