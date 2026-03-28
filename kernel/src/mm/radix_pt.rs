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
    fn leaf_pa(entry: u64) -> usize;

    /// Construct a non-leaf (table pointer) PTE from a child table's PA.
    fn make_table_entry(table_pa: usize) -> u64;

    /// Invalidate the TLB for a single virtual address.
    fn tlb_invalidate(va: usize);
}

// -------------------------------------------------------------------------
// Read-only walkers
// -------------------------------------------------------------------------

/// Walk to the leaf PTE slot for `va`, returning a pointer to it.
/// Returns `None` if any intermediate level is missing (not present).
/// Does NOT check whether the leaf PTE itself is valid.
#[inline]
pub fn walk_to_leaf<F: PteFormat>(root: usize, va: usize) -> Option<*mut u64> {
    let mut table = root as *mut u64;
    // Walk through non-leaf levels (0 .. LEVELS-2).
    for level in 0..F::LEVELS - 1 {
        let idx = F::va_index(va, level);
        let entry = unsafe { *table.add(idx) };
        if !F::is_valid(entry) {
            return None;
        }
        if !F::is_table(entry) {
            // Block/superpage at this level — no leaf-level PTE exists.
            return None;
        }
        table = F::table_pa(entry) as *mut u64;
    }
    let leaf_idx = F::va_index(va, F::LEVELS - 1);
    Some(unsafe { table.add(leaf_idx) })
}

/// Walk to the PTE slot at the superpage level (level LEVELS-2) for `va`.
/// Used for checking / installing superpages (2 MiB blocks).
/// Returns `None` if intermediate levels above it are missing.
#[inline]
pub fn walk_to_super_slot<F: PteFormat>(root: usize, va: usize) -> Option<*mut u64> {
    if F::LEVELS < 2 {
        return None;
    }
    let mut table = root as *mut u64;
    let super_level = F::LEVELS - 2;
    // Walk through levels 0 .. LEVELS-3.
    for level in 0..super_level {
        let idx = F::va_index(va, level);
        let entry = unsafe { *table.add(idx) };
        if !F::is_valid(entry) {
            return None;
        }
        if !F::is_table(entry) {
            return None;
        }
        table = F::table_pa(entry) as *mut u64;
    }
    let idx = F::va_index(va, super_level);
    Some(unsafe { table.add(idx) })
}

// -------------------------------------------------------------------------
// Allocating walkers
// -------------------------------------------------------------------------

/// Walk to the leaf PTE slot, allocating intermediate table pages as needed.
/// Returns `None` only if allocation fails or a superpage blocks the path.
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

/// Walk to the superpage-level PTE slot, allocating intermediate tables.
/// Returns `None` only if allocation fails or a higher-level block exists.
#[inline]
pub fn walk_or_create_to_super<F: PteFormat>(root: usize, va: usize) -> Option<*mut u64> {
    if F::LEVELS < 2 {
        return None;
    }
    let mut table = root as *mut u64;
    let super_level = F::LEVELS - 2;
    for level in 0..super_level {
        let idx = F::va_index(va, level);
        let entry = unsafe { *table.add(idx) };
        if F::is_valid(entry) {
            if !F::is_table(entry) {
                return None;
            }
            table = F::table_pa(entry) as *mut u64;
        } else {
            let new_table = alloc_table()?;
            unsafe {
                *table.add(idx) = F::make_table_entry(new_table);
            }
            table = new_table as *mut u64;
        }
    }
    let idx = F::va_index(va, super_level);
    Some(unsafe { table.add(idx) })
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

const MMU_PAGE_SIZE: usize = 4096;

/// Allocate a zeroed 4K page for a page table.
fn alloc_table() -> Option<usize> {
    let page = crate::mm::phys::alloc_page()?;
    let addr = page.as_usize();
    unsafe {
        core::ptr::write_bytes(addr as *mut u8, 0, MMU_PAGE_SIZE);
    }
    Some(addr)
}
