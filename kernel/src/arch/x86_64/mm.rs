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

// =========================================================================
// #208 VA-isolation regions (docs/slab-pt-va-isolation.md, Phase 1).
//
// Each region is a top-level PML4 entry reserved by boot.S, pointing at
// an empty PDPT.  Phase 1 just establishes the slots; later phases route
// allocations into these VA ranges with sparse per-object windows that
// produce unmapped guard gaps for free.
//
// PML4 slot 511 = kernel text/data/bss (existing)
// PML4 slot 510 = PT_REGION              (page tables)
// PML4 slot 509 = SLAB_REGION            (slab caches)
// PML4 slot 508 = KSTACK_REGION          (kernel thread stacks)
// PML4 slot 507 = PHYS_DIRECT_MAP        (offset-mapped raw phys)
// =========================================================================

/// VA base of PT_REGION (PML4[510]).
pub const PT_REGION_BASE: u64 = 0xFFFF_FF00_0000_0000;

/// VA base of SLAB_REGION (PML4[509]).
pub const SLAB_REGION_BASE: u64 = 0xFFFF_FE80_0000_0000;

/// VA base of KSTACK_REGION (PML4[508]).
pub const KSTACK_REGION_BASE: u64 = 0xFFFF_FE00_0000_0000;

/// VA base of PHYS_DIRECT_MAP (PML4[507]).
pub const PHYS_DIRECT_MAP_BASE: u64 = 0xFFFF_FD80_0000_0000;

/// Size of one PML4 slot's coverage (512 GiB).
pub const PML4_SLOT_SIZE: u64 = 1 << 39;

/// VA window allocated per kernel thread stack within KSTACK_REGION.
/// 2 MiB per kstack, with only the top 128 KiB phys-backed and the rest
/// unmapped (guard).  Stack grows downward from window_base + 2 MiB
/// toward window_base; any push past window_base + (2 MiB - 128 KiB)
/// faults on the unmapped guard.
pub const KSTACK_WINDOW_SIZE: u64 = 1 << 21;

/// Phase 2: convert a physical address to its PHYS_DIRECT_MAP virtual
/// address.  Use this when you need a kernel-mode pointer to a specific
/// phys page that isn't accessible via the identity map (PML4[0]) —
/// e.g., when PML4[0] is eventually unmapped to enforce VA/phys
/// separation per the slab-pt-va-isolation design.
#[inline]
pub fn phys_to_kva(pa: usize) -> usize {
    PHYS_DIRECT_MAP_BASE as usize + pa
}

/// Phase 2: convert a PHYS_DIRECT_MAP virtual address back to its
/// physical address.  Inverse of `phys_to_kva`.  Caller must ensure
/// `va` lies within PHYS_DIRECT_MAP_BASE..(PHYS_DIRECT_MAP_BASE + 4 GiB).
#[inline]
pub fn kva_to_phys(va: usize) -> usize {
    debug_assert!(va >= PHYS_DIRECT_MAP_BASE as usize);
    va - PHYS_DIRECT_MAP_BASE as usize
}

// =========================================================================
// Phase 5a: KSTACK_REGION VA window allocator + mapper.
//
// Each kernel thread stack gets a 2 MiB VA window within KSTACK_REGION.
// Only the top `kstack_size_bytes` of the window (typically 128 KiB =
// 2 × 64 KiB pages) is phys-backed; the rest is unmapped VA, acting as
// a guard zone.  Stack underflow / overflow into the guard generates
// a page fault, naming the source RIP — catches the residual #208
// kstack-mutation bug class that survives Fix D.
//
// Phase 5a (this commit) installs only the infrastructure: bump-pointer
// VA allocator + map_kstack_window helper.  No allocator migration yet
// — alloc_kstack_zeroed continues to return PhysAddr (used as
// identity-mapped pointer).  Phase 5b migrates callers to use VA.
// =========================================================================

/// Bump-pointer cursor for KSTACK_REGION VA windows.  Starts at the
/// region base + one window (skip the first window so VA=0 + offset
/// doesn't collide with any code that treats null-ish VAs specially).
static KSTACK_VA_NEXT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(KSTACK_REGION_BASE + KSTACK_WINDOW_SIZE);

// =========================================================================
// Phase 4 (slab-pt-va-isolation doc): SLAB_THREAD_REGION sub-allocator.
//
// Each Thread struct gets its own 16 KiB VA window within SLAB_REGION,
// with one 4 KiB phys page mapped at the TOP and 12 KiB of unmapped
// guard below.  A stray write to a Thread struct's address from
// unrelated kernel code (e.g., extent-tree pointer arithmetic landing
// in the slab region) faults instead of silently scribbling a sibling
// Thread.  Per-instance isolation is the goal — sharing a 4 KiB slab
// page between 4 Threads (as the legacy slab cache did) doesn't catch
// within-slab cross-Thread scribbles.
// =========================================================================

/// Size of each Thread's VA window in SLAB_THREAD_REGION (16 KiB).
/// 4 KiB mapped at the top + 12 KiB guard below.
pub const SLAB_THREAD_WINDOW_SIZE: u64 = 16 * 1024;

/// Bump-pointer cursor for SLAB_THREAD_REGION VA windows.
static SLAB_THREAD_VA_NEXT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(SLAB_REGION_BASE + SLAB_THREAD_WINDOW_SIZE);

/// Reserve the next SLAB_THREAD_WINDOW_SIZE VA window in SLAB_REGION.
/// Returns the VA base of the window (low address).  The Thread struct
/// itself lives in the TOP 4 KiB; bytes 0..(WINDOW - 4 KiB) are guard.
#[inline]
pub fn alloc_slab_thread_va_window() -> u64 {
    SLAB_THREAD_VA_NEXT.fetch_add(
        SLAB_THREAD_WINDOW_SIZE,
        core::sync::atomic::Ordering::Relaxed,
    )
}

/// Map a single 4 KiB phys page at the TOP of a SLAB_THREAD_REGION VA
/// window.  Returns the VA of the mapped page (i.e., `va_window_base +
/// SLAB_THREAD_WINDOW_SIZE - 4 KiB`).  The rest of the window stays
/// unmapped — stray accesses to "near-Thread" addresses fault.
pub fn map_slab_thread_window(
    pml4: usize,
    va_window_base: u64,
    pa: usize,
) -> Option<u64> {
    let va = va_window_base + SLAB_THREAD_WINDOW_SIZE - MMU_PAGE_SIZE as u64;
    let flags = PTE_P | PTE_RW | PTE_NX;
    if !map_single_mmupage(pml4, va as usize, pa, flags) {
        return None;
    }
    Some(va)
}

/// Reserve the next 2 MiB VA window in KSTACK_REGION.  Returns the
/// VA base of the window.  Bumps the cursor atomically — safe under
/// concurrent allocation.
#[inline]
pub fn alloc_kstack_va_window() -> u64 {
    KSTACK_VA_NEXT.fetch_add(KSTACK_WINDOW_SIZE, core::sync::atomic::Ordering::Relaxed)
}

/// Map the top `num_mmu_pages` of a kstack VA window to phys page
/// `pa_base`.  The remainder of the window (below the mapped pages)
/// stays unmapped — guard zone catches stack underflow.
///
/// Returns the VA of the kstack TOP (highest address, one past the
/// last byte of mapped memory).  This is the value to write to TSS
/// RSP0 and the value `stack_base + kstack_size` should equal once
/// Phase 5b migrates the allocator.
///
/// pml4 = the current PML4 to map into (typically boot_pml4).
pub fn map_kstack_window(
    pml4: usize,
    va_window_base: u64,
    pa_base: usize,
    num_mmu_pages: usize,
) -> Option<u64> {
    let kstack_byte_size = num_mmu_pages * MMU_PAGE_SIZE;
    let va_kstack_base = va_window_base + KSTACK_WINDOW_SIZE - kstack_byte_size as u64;
    for i in 0..num_mmu_pages {
        let va = va_kstack_base + (i * MMU_PAGE_SIZE) as u64;
        let pa = pa_base + i * MMU_PAGE_SIZE;
        // Kernel-only mapping: P + RW + NX (data, not code).
        let flags = PTE_P | PTE_RW | PTE_NX;
        if !map_single_mmupage(pml4, va as usize, pa, flags) {
            // Roll back partial mappings.  Best-effort; under OOM the
            // caller will see None and abort.
            for j in 0..i {
                let va_j = va_kstack_base + (j * MMU_PAGE_SIZE) as u64;
                unmap_single_mmupage(pml4, va_j as usize);
            }
            return None;
        }
    }
    // Verify mapping: walk the PT for each page and confirm PTE_P set.
    // Catches silent partial-map failures (PDPT/PD/PT alloc returning the
    // same slot, etc.).
    let mut bad_idx: i32 = -1;
    let mut bad_pte: u64 = 0;
    for i in 0..num_mmu_pages {
        let va = va_kstack_base + (i * MMU_PAGE_SIZE) as u64;
        let pte = read_pte(pml4, va as usize);
        if pte & PTE_P == 0 {
            bad_idx = i as i32;
            bad_pte = pte;
            break;
        }
    }
    if bad_idx >= 0 {
        crate::println!(
            "MAP-KSTACK-VERIFY-FAIL: pml4={:#x} va_window={:#x} pa_base={:#x} num={} bad_idx={} bad_pte={:#x}",
            pml4, va_window_base, pa_base, num_mmu_pages, bad_idx, bad_pte,
        );
    }
    Some(va_kstack_base + kstack_byte_size as u64)
}

use crate::mm::radix_pt::{self, PteFormat};

/// User page flags (public for main.rs).
pub const USER_RWX_FLAGS: u64 = PTE_P | PTE_RW | PTE_US;
/// R-X (executable, NOT writable).  Distinct from RWX so .text segments
/// from ELF PT_LOAD with prot=R+X get true W^X — writes to .text fault.
pub const USER_RX_FLAGS: u64 = PTE_P | PTE_US; // No PTE_RW, no PTE_NX
pub const USER_RW_FLAGS: u64 = PTE_P | PTE_RW | PTE_US | PTE_NX;
pub const USER_RO_FLAGS: u64 = PTE_P | PTE_US | PTE_NX; // No PTE_RW = read-only

/// Treat a PA as a `*mut u64` PT pointer via the PHYS_DIRECT_MAP.
/// #235 Phase 4g (Piece C1): PT-walk dereferences used to go through
/// PML4[0] identity (low PA mapped 1:1 to low VA).  Routing through
/// phys_to_kva makes the walker survive the PML4[0] unmap.
#[inline]
fn pt_kva(pa: usize) -> *mut u64 {
    phys_to_kva(pa) as *mut u64
}

/// Allocate a zero-filled 4K page for a page table.
fn alloc_table() -> Option<usize> {
    let page = crate::mm::phys::alloc_page()?;
    let addr = page.as_usize();
    unsafe {
        // Zero via direct-map kva so this still works after PML4[0] unmap.
        core::ptr::write_bytes(
            phys_to_kva(addr) as *mut u8,
            0,
            MMU_PAGE_SIZE,
        );
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

    let parent_pml4 = pt_kva(parent_root);
    let child_pml4 = pt_kva(child_root);

    // PML4[0]: both have deep-copied PDPTs. Share PDPT[4+] (user entries).
    let parent_e0 = unsafe { *parent_pml4 };
    let child_e0 = unsafe { *child_pml4 };

    if X86Pte::is_valid(parent_e0)
        && X86Pte::is_table(parent_e0)
        && X86Pte::is_valid(child_e0)
        && X86Pte::is_table(child_e0)
    {
        let parent_pdpt = pt_kva(X86Pte::table_pa(parent_e0));
        let child_pdpt = pt_kva(X86Pte::table_pa(child_e0));
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
            } else if X86Pte::is_shared_entry(entry) {
                // Already shared from a prior fork — include in child and bump refcount.
                let sub_pa = X86Pte::shared_entry_pa(entry);
                ForkGroup::share(fg, sub_pa);
                unsafe {
                    *child_pdpt.add(i) = entry;
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
        } else if X86Pte::is_shared_entry(entry) {
            let sub_pa = X86Pte::shared_entry_pa(entry);
            ForkGroup::share(fg, sub_pa);
            unsafe {
                *child_pml4.add(i) = entry;
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

/// #233 (2) write-protect / unprotect helper.  Flips the PTE_RW bit on
/// the 4 KiB MMU page containing `va`.  Used to catch any-CPU writers
/// to specific kstack slots via #PF.  Returns true if successful.
pub fn set_pte_writable(pml4: usize, va: usize, writable: bool) -> bool {
    let slot = match radix_pt::walk_to_leaf::<X86Pte>(pml4, va) {
        Some(s) => s,
        None => return false,
    };
    unsafe {
        let entry = *slot;
        if entry & PTE_P == 0 {
            return false;
        }
        let new_entry = if writable {
            entry | PTE_RW
        } else {
            entry & !PTE_RW
        };
        *slot = new_entry;
    }
    X86Pte::tlb_invalidate(va);
    true
}

/// #233 (3) write-protect the 4 KiB MMU page backing `pa` via its
/// PHYS_DIRECT_MAP alias.  Demotes any 1 GiB or 2 MiB superpage along
/// the PML4[507] path so the leaf PTE for the watched page can hold a
/// dedicated PTE_RW=0 bit.  Sibling pages remain writable.
///
/// Used by the kstack WPROT probe to catch writers that bypass the
/// per-thread KSTACK_REGION VA window by going via direct-map PAs
/// (or the legacy PML4[0] identity, whose RAM overlaps direct-map).
///
/// Returns true if the leaf is now RW=0.  TLB is invalidated locally;
/// callers should ensure no peer CPU has a stale gigapage TLB entry for
/// this VA (arming during early boot is safe — APs haven't started).
pub fn wprot_4k_via_direct_map(pml4: usize, pa: usize) -> bool {
    use crate::mm::page::SUPERPAGE_LEVELS;
    let two_mib = &SUPERPAGE_LEVELS[0]; // 2 MiB (PD)
    let one_gib = &SUPERPAGE_LEVELS[1]; // 1 GiB (PDPT)
    let dm_va = phys_to_kva(pa & !0xFFF);
    let demote_flags = PTE_P | PTE_RW | PTE_NX;
    if is_superpage_at_level(pml4, dm_va, one_gib).is_some()
        && !demote_superpage_at_level(pml4, dm_va, demote_flags, one_gib)
    {
        return false;
    }
    if is_superpage_at_level(pml4, dm_va, two_mib).is_some()
        && !demote_superpage_at_level(pml4, dm_va, demote_flags, two_mib)
    {
        return false;
    }
    let ok = set_pte_writable(pml4, dm_va, false);
    if ok {
        // Cross-CPU shootdown: peer CPUs may have cached the 1 GiB
        // gigapage entry covering this PA range.  Force them to drop
        // non-global TLB entries so the new RW=0 leaf takes effect.
        super::lapic::broadcast_tlb_flush();
    }
    ok
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

/// Walk the x86-64 PT for `va` and return whether the leaf entry is
/// present and writable from user-mode.  Cheap defensive check —
/// userspace servers can validate caller-supplied addresses before
/// dereferencing.  Used by SYS_VA_WRITABLE.
pub fn va_writable(pml4: usize, va: usize) -> bool {
    let mut table = pt_kva(pml4);
    for level in 0..X86Pte::LEVELS {
        let idx = X86Pte::va_index(va, level);
        let entry = unsafe { *table.add(idx) };
        if entry & PTE_P == 0 {
            return false;
        }
        let is_leaf = level == X86Pte::LEVELS - 1;
        let is_block = !is_leaf && (entry & PTE_PS) != 0;
        if is_leaf || is_block {
            // PTE_RW bit set + PTE_US set (user-accessible).  PTE_NX
            // is fine for a writable check; we don't care about
            // execute.
            return (entry & PTE_RW) != 0 && (entry & PTE_US) != 0;
        }
        table = pt_kva(X86Pte::table_pa(entry));
    }
    false
}

/// Translate a user VA to a physical address by walking the x86-64 page table.
/// Returns None if the page is not mapped.
pub fn translate_va(pml4: usize, va: usize) -> Option<usize> {
    // Walk the tables one level at a time so we catch superpages that
    // the strict walk_to_leaf can't see.  x86-64 allows a 2 MiB block
    // at PD level (level 2) and a 1 GiB block at PDPT level (level 1);
    // the kernel's zero-fill fault handler installs a 2 MiB superpage
    // on aligned ranges when it's cheaper than 512 individual PTEs,
    // and the previous walk_to_leaf-based translate_va returned None
    // the moment it hit one.  That made every DRM dumb-buffer mmap
    // that crossed a 2 MiB boundary fail with ENOMEM.
    let mut table = pt_kva(pml4);
    for level in 0..X86Pte::LEVELS {
        let idx = X86Pte::va_index(va, level);
        let entry = unsafe { *table.add(idx) };
        if entry & PTE_P == 0 {
            return None;
        }
        // Leaf (last level) always contains the PA.  Intermediate entries
        // with PTE_PS set (page size) are superpage terminators — combine
        // their base PA with the low-bit offset for the level.
        let is_leaf = level == X86Pte::LEVELS - 1;
        let is_block = !is_leaf && (entry & PTE_PS) != 0;
        if is_leaf || is_block {
            // Mask: for a leaf (4 KiB) the offset is 12 bits; for a PD
            // superpage (2 MiB) it's 21 bits; for a PDPT superpage
            // (1 GiB) it's 30 bits.  X86Pte::LEVELS == 4, so level=3 is
            // leaf (12), level=2 is 2 MiB (21), level=1 is 1 GiB (30).
            let offset_bits = match level {
                3 => 12,
                2 => 21,
                1 => 30,
                _ => return None, // PML4 superpage doesn't exist on x86-64.
            };
            let frame_mask = !((1usize << offset_bits) - 1);
            let pa = (entry as usize) & frame_mask & 0x000F_FFFF_FFFF_FFFF;
            return Some(pa | (va & ((1usize << offset_bits) - 1)));
        }
        table = pt_kva(X86Pte::table_pa(entry));
    }
    None
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
        let src = pt_kva(boot_pml4_addr) as *const u64;
        let dst = pt_kva(new_pml4);

        // Deep-copy PML4[0]: allocate a new PDPT and copy all 512 entries.
        // This gives each process its own PDPT so user mappings in the
        // lower 512 GiB region don't collide with the boot tables.
        let boot_pml4_0 = *src.add(0);
        if boot_pml4_0 & PTE_P != 0 {
            let boot_pdpt = (boot_pml4_0 & 0x000F_FFFF_FFFF_F000) as usize;
            let new_pdpt = alloc_table()?;
            core::ptr::copy_nonoverlapping(
                pt_kva(boot_pdpt) as *const u64,
                pt_kva(new_pdpt),
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

        // #208 Phase 5b: copy the VA-isolation region PML4 entries
        // (KSTACK_REGION/SLAB_REGION/PT_REGION/PHYS_DIRECT_MAP) so user
        // PTs can also reach them.  Required because the kernel runs on
        // the user task's CR3 (no PT switch on syscall entry), so any
        // kernel access to these regions must be mapped in the user PT.
        for i in 507..=510 {
            *dst.add(i) = *src.add(i);
        }
        // #208 higher-half follow-on: copy PML4[511] (kernel high-half VMA).
        // With the higher-half kernel layout (boot.S:80, linker.ld:6), kernel
        // text and data live at 0xFFFFFFFF80000000+, mapped via PML4[511] →
        // boot_pdpt_hi.  Without this copy, a userspace task's page table
        // omits the kernel high-half — the first time CPU runs kernel code
        // on that task's CR3 (i.e. any syscall, IRQ, or context-switch
        // dispatch into kernel), instruction fetch faults at the kernel
        // high-half RIP → #PF → #DF (no IST except for #DF, and #DF handler
        // RIP is also high-half) → triple fault.  Captured in
        // qemu-int-11amfsq1012.log: #DB → #PF (CR2=RIP=0xffffffff80105af2)
        // → check_exception old=0x8 new=0xe → Triple fault.
        //
        // Boot.S only ever writes PML4[0] (low identity) and PML4[511]
        // (high-half kernel) plus 1..4 shallow copy; copying [511] is
        // sufficient to restore kernel reachability from user tasks.
        *dst.add(511) = *src.add(511);
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

    let pml4 = pt_kva(root) as *const u64;
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
        // PML4[4..507]: user-range entries — may be shared markers.
        // PML4[507..=511] are shallow-copied from boot_pml4 (VA-isolation
        // regions + high-half kernel: PHYS_DIRECT_MAP / KSTACK_REGION /
        // SLAB_REGION / PT_REGION / kernel high-half).  Their PDPTs live
        // in BSS and are shared across every CR3 — freeing them returns
        // boot_pdpt_kstack et al. to the phys allocator, which then hands
        // them out as fresh pages and the new owner zeroes them, wiping
        // every other CR3's PDPT chain for those regions and causing
        // spurious kstack-VA #PFs (pml4_e+pdpt_e valid, pd_e=0).
        for i in 4..507 {
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
    let pt_table = pt_kva(pt);

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
    let table_ptr = pt_kva(new_table);

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
