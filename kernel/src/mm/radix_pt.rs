//! Generic radix page table walker library.
//!
//! Provides shared walking logic for architectures with multi-level
//! radix translation tables (x86-64 4-level, AArch64 4-level, RISC-V Sv39 3-level).
//!
//! Architecture-specific modules implement the [`PteFormat`] trait and call
//! the generic walker functions, avoiding duplicated walk loops.
//!
//! Architectures with inverted page tables or software-managed TLBs can
//! implement the HAT API directly without using this library.

use crate::mm::ptshare::ForkGroup;

/// Trait describing one architecture's radix page table entry format.
///
/// Implementors provide constants and methods that parameterize the
/// generic walker. The compiler monomorphizes each walker call per
/// architecture, so there is zero runtime dispatch overhead.
pub trait PteFormat {
    /// Number of page table levels (3 for Sv39, 4 for AArch64/x86-64).
    const LEVELS: usize;

    /// Extract the table index from a virtual address for a given level.
    /// Level 0 is the root (highest bits), level LEVELS-1 is the leaf.
    fn va_index(va: usize, level: usize) -> usize;

    /// Check if a PTE is valid/present.
    fn is_valid(entry: u64) -> bool;

    /// Check if a valid entry at a non-leaf level is a table pointer
    /// (as opposed to a block/superpage descriptor).
    fn is_table(entry: u64) -> bool;

    /// Extract the physical address of the next-level table from a table PTE.
    fn table_pa(entry: u64) -> usize;

    /// Extract the physical address from a leaf PTE (4K page).
    #[allow(dead_code)]
    fn leaf_pa(entry: u64) -> usize;

    /// Construct a non-leaf (table pointer) PTE from a child table's PA.
    fn make_table_entry(table_pa: usize) -> u64;

    /// Invalidate the TLB for a single virtual address.
    fn tlb_invalidate(va: usize);

    // -- Shared page table support --

    /// Create a not-present shared table marker encoding the PA of a shared table.
    fn make_shared_entry(table_pa: usize) -> u64;

    /// Check if a not-present entry is a shared table marker.
    fn is_shared_entry(entry: u64) -> bool;

    /// Extract the table PA from a shared table marker.
    fn shared_entry_pa(entry: u64) -> usize;

    /// Make a PTE read-only by clearing the write permission bit.
    /// Returns the entry unchanged if already read-only or not present.
    fn make_readonly(entry: u64) -> u64;
}

// -------------------------------------------------------------------------
// Read-only walkers
// -------------------------------------------------------------------------

/// Walk to the leaf PTE slot for `va`, returning a pointer to it.
/// Returns `None` if any intermediate level is missing (not present).
/// Follows shared markers transparently (read-only traversal).
/// Does NOT check whether the leaf PTE itself is valid.
#[inline]
pub fn walk_to_leaf<F: PteFormat>(root: usize, va: usize) -> Option<*mut u64> {
    let mut table = root as *mut u64;
    // Walk through non-leaf levels (0 .. LEVELS-2).
    for level in 0..F::LEVELS - 1 {
        let idx = F::va_index(va, level);
        let entry = unsafe { *table.add(idx) };
        if F::is_valid(entry) {
            if !F::is_table(entry) {
                // Block/superpage at this level — no leaf-level PTE exists.
                return None;
            }
            table = F::table_pa(entry) as *mut u64;
        } else if F::is_shared_entry(entry) {
            table = F::shared_entry_pa(entry) as *mut u64;
        } else {
            return None;
        }
    }
    let leaf_idx = F::va_index(va, F::LEVELS - 1);
    Some(unsafe { table.add(leaf_idx) })
}

/// Walk to the PTE slot at `target_level` for `va`.
/// Returns `None` if any intermediate level above `target_level` is missing
/// or occupied by a block descriptor. Follows shared markers transparently.
#[inline]
pub fn walk_to_level_slot<F: PteFormat>(
    root: usize,
    va: usize,
    target_level: usize,
) -> Option<*mut u64> {
    let mut table = root as *mut u64;
    for level in 0..target_level {
        let idx = F::va_index(va, level);
        let entry = unsafe { *table.add(idx) };
        if F::is_valid(entry) {
            if !F::is_table(entry) {
                return None;
            }
            table = F::table_pa(entry) as *mut u64;
        } else if F::is_shared_entry(entry) {
            table = F::shared_entry_pa(entry) as *mut u64;
        } else {
            return None;
        }
    }
    let idx = F::va_index(va, target_level);
    Some(unsafe { table.add(idx) })
}

/// Walk to the PTE slot at the smallest superpage level (LEVELS-2) for `va`.
/// Backward-compatible wrapper around [`walk_to_level_slot`].
#[inline]
pub fn walk_to_super_slot<F: PteFormat>(root: usize, va: usize) -> Option<*mut u64> {
    if F::LEVELS < 2 {
        return None;
    }
    walk_to_level_slot::<F>(root, va, F::LEVELS - 2)
}

// -------------------------------------------------------------------------
// Allocating walkers
// -------------------------------------------------------------------------

/// Walk to the leaf PTE slot, allocating intermediate table pages as needed.
/// Returns `None` if allocation fails, a superpage blocks the path, or a
/// shared marker is encountered (caller must `ensure_path_unshared` first).
#[inline]
pub fn walk_or_create<F: PteFormat>(root: usize, va: usize) -> Option<*mut u64> {
    let mut table = root as *mut u64;
    for level in 0..F::LEVELS - 1 {
        let idx = F::va_index(va, level);
        let entry = unsafe { *table.add(idx) };
        if F::is_valid(entry) {
            if !F::is_table(entry) {
                // Block descriptor — cannot subdivide.
                return None;
            }
            table = F::table_pa(entry) as *mut u64;
        } else if F::is_shared_entry(entry) {
            // Shared marker — caller should have called ensure_path_unshared.
            return None;
        } else {
            // Allocate a new table page.
            let new_table = alloc_table()?;
            unsafe {
                *table.add(idx) = F::make_table_entry(new_table);
            }
            table = new_table as *mut u64;
        }
    }
    let leaf_idx = F::va_index(va, F::LEVELS - 1);
    Some(unsafe { table.add(leaf_idx) })
}

/// Walk to the PTE slot at `target_level`, allocating intermediate tables.
/// Returns `None` if allocation fails, a higher-level block exists, or a
/// shared marker is encountered (caller must `ensure_path_unshared` first).
#[inline]
pub fn walk_or_create_to_level<F: PteFormat>(
    root: usize,
    va: usize,
    target_level: usize,
) -> Option<*mut u64> {
    let mut table = root as *mut u64;
    for level in 0..target_level {
        let idx = F::va_index(va, level);
        let entry = unsafe { *table.add(idx) };
        if F::is_valid(entry) {
            if !F::is_table(entry) {
                return None;
            }
            table = F::table_pa(entry) as *mut u64;
        } else if F::is_shared_entry(entry) {
            // Shared marker — caller should have called ensure_path_unshared.
            return None;
        } else {
            let new_table = alloc_table()?;
            unsafe {
                *table.add(idx) = F::make_table_entry(new_table);
            }
            table = new_table as *mut u64;
        }
    }
    let idx = F::va_index(va, target_level);
    Some(unsafe { table.add(idx) })
}

/// Walk to the smallest superpage level (LEVELS-2), allocating intermediate tables.
/// Backward-compatible wrapper around [`walk_or_create_to_level`].
#[inline]
pub fn walk_or_create_to_super<F: PteFormat>(root: usize, va: usize) -> Option<*mut u64> {
    if F::LEVELS < 2 {
        return None;
    }
    walk_or_create_to_level::<F>(root, va, F::LEVELS - 2)
}

// -------------------------------------------------------------------------
// Shared page table COW operations
// -------------------------------------------------------------------------

/// COW-break a shared page table node.
///
/// Decrements the refcount on `old_pa` via the ForkGroup. If it was the last
/// shared reference (refcount drops to 0 / not tracked), returns `old_pa` for
/// re-adoption without copying. Otherwise, allocates a copy and processes
/// sub-entries:
/// - Intermediate tables: share sub-table PAs and convert to shared markers
/// - Leaf tables: downgrade writable PTEs to read-only for per-page COW
///
/// `level` is the level of the entry pointing to `old_pa` (i.e., entries
/// inside `old_pa` are at level+1).
fn cow_break_table<F: PteFormat>(
    old_pa: usize,
    level: usize,
    fg: *mut ForkGroup,
) -> Option<usize> {
    use crate::mm::stats;
    use core::sync::atomic::Ordering;

    let remaining = ForkGroup::unshare(fg, old_pa);
    if remaining == 0 {
        // Exclusively ours (or untracked). Re-adopt without copying.
        return Some(old_pa);
    }

    // Still shared by others — must copy.
    let new_pa = alloc_table()?;
    unsafe {
        core::ptr::copy_nonoverlapping(
            old_pa as *const u8,
            new_pa as *mut u8,
            MMU_PAGE_SIZE,
        );
    }

    stats::PT_COW_BREAKS.fetch_add(1, Ordering::Relaxed);

    let new_table = new_pa as *mut u64;
    let child_level = level + 1;

    if child_level < F::LEVELS - 1 {
        // Broken table is intermediate — entries point to further tables.
        for i in 0..ENTRIES_PER_TABLE {
            let entry = unsafe { *new_table.add(i) };
            if F::is_valid(entry) {
                if F::is_table(entry) {
                    // Sub-table referenced by both old and new copies.
                    let sub_pa = F::table_pa(entry);
                    ForkGroup::share(fg, sub_pa);
                    unsafe {
                        *new_table.add(i) = F::make_shared_entry(sub_pa);
                    }
                } else {
                    // Superpage/block: downgrade to read-only for COW.
                    unsafe {
                        *new_table.add(i) = F::make_readonly(entry);
                    }
                }
            }
            // Shared markers and empty entries: unchanged.
        }
    } else {
        // Broken table is a leaf — entries are data page PTEs.
        for i in 0..ENTRIES_PER_TABLE {
            let entry = unsafe { *new_table.add(i) };
            if F::is_valid(entry) {
                unsafe {
                    *new_table.add(i) = F::make_readonly(entry);
                }
            }
        }
    }

    Some(new_pa)
}

/// Ensure the entire walk path from root to the leaf level for `va` contains
/// no shared markers. COW-breaks each shared node encountered top-down.
/// `fg` is the ForkGroup owning the shared PT refcounts (may be null if the
/// address space has never forked — in that case, no shared markers exist).
/// Returns `false` only on OOM.
pub fn ensure_path_unshared<F: PteFormat>(
    root: usize,
    va: usize,
    fg: *mut ForkGroup,
) -> bool {
    if fg.is_null() {
        return true; // Never forked, no shared markers possible.
    }
    let mut table = root as *mut u64;
    for level in 0..F::LEVELS - 1 {
        let idx = F::va_index(va, level);
        let entry = unsafe { *table.add(idx) };
        if F::is_shared_entry(entry) {
            let old_pa = F::shared_entry_pa(entry);
            let new_pa = match cow_break_table::<F>(old_pa, level, fg) {
                Some(pa) => pa,
                None => return false,
            };
            unsafe {
                *table.add(idx) = F::make_table_entry(new_pa);
            }
            table = new_pa as *mut u64;
        } else if F::is_valid(entry) {
            if !F::is_table(entry) {
                // Block/superpage — path ends here.
                return true;
            }
            table = F::table_pa(entry) as *mut u64;
        } else {
            // Not present, not shared — nothing mapped.
            return true;
        }
    }
    true
}

/// Recursively free a page table subtree, handling shared markers.
///
/// For shared markers: decrements refcount via the ForkGroup. Only recurses
/// + frees when the last reference is dropped.
/// For non-shared sub-tables: recurses and frees unconditionally.
/// Leaf-level data pages are NOT freed here (aspace::destroy handles those).
///
/// `level` is the level of `table_pa` itself (entries inside are at level+1).
/// `fg` may be null if the address space was never forked.
pub fn free_shared_subtree<F: PteFormat>(
    table_pa: usize,
    level: usize,
    fg: *mut ForkGroup,
) {
    let child_level = level + 1;
    if child_level >= F::LEVELS {
        // At or past leaf level — data pages freed elsewhere.
        return;
    }

    let table = table_pa as *const u64;

    for i in 0..ENTRIES_PER_TABLE {
        let entry = unsafe { *table.add(i) };
        if F::is_shared_entry(entry) {
            let sub_pa = F::shared_entry_pa(entry);
            let rc = if fg.is_null() { 0 } else { ForkGroup::unshare(fg, sub_pa) };
            if rc == 0 {
                // Last reference — recursively free sub-entries, then the page.
                if child_level < F::LEVELS - 1 {
                    free_shared_subtree::<F>(sub_pa, child_level, fg);
                }
                crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(sub_pa));
            }
        } else if F::is_valid(entry) && F::is_table(entry) {
            // Non-shared sub-table — recurse into intermediates, then free.
            let sub_pa = F::table_pa(entry);
            if child_level < F::LEVELS - 1 {
                free_shared_subtree::<F>(sub_pa, child_level, fg);
            }
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(sub_pa));
        }
        // Leaf PTEs (data pages) and empty entries: skip.
    }
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

const MMU_PAGE_SIZE: usize = 4096;
const ENTRIES_PER_TABLE: usize = MMU_PAGE_SIZE / 8;

/// Allocate a zeroed 4K page for a page table.
fn alloc_table() -> Option<usize> {
    let page = crate::mm::phys::alloc_page()?;
    let addr = page.as_usize();
    unsafe {
        core::ptr::write_bytes(addr as *mut u8, 0, MMU_PAGE_SIZE);
    }
    Some(addr)
}
