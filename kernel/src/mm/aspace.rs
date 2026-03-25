//! Address space — per-task virtual memory management.
//!
//! Each address space owns a page table root and a B+ tree of VMAs.
//! The WSCLOCK clock hand (VmaCursor) is also stored here.
//!
//! The address space table is an ART (Adaptive Radix Tree) mapping monotonic
//! ASpaceIds to slab-allocated entries, with no fixed upper limit.
//!
//! Locking: each address space has its own SpinLock, so operations on
//! different address spaces never contend. The global ASPACE_TABLE lock
//! serializes only entry creation, destruction, and lookup (held briefly).
//! Lock ordering: ASPACE_TABLE → per-entry SpinLock.

use super::object::{self};
use super::page::PhysAddr;
use super::vma::{Vma, VmaProt};
use super::vmatree::{VmaCursor, VmaTree};
use crate::ipc::art::Art;
use crate::mm::slab;
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicU32, Ordering};

/// Slab size for ASpaceEntry allocations.
const ASPACE_SLAB_SIZE: usize = 128;

/// Address space ID type.
pub type ASpaceId = u32;

/// Heap VA base: 8 GiB (above ELF load at 4 GiB, below stack).
pub const HEAP_VA_BASE: usize = 0x2_0000_0000;

/// MAP_FIXED_NOREPLACE: fail instead of replacing existing mappings.
pub const MAP_FIXED_NOREPLACE: u64 = 0x100000;

/// Simple xorshift64 PRNG for ASLR.
fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// An address space.
pub struct AddressSpace {
    /// Physical address of the page table root (L0/PML4/root table).
    pub page_table_root: usize,
    /// VMAs in this address space (B+ tree keyed by VA interval).
    pub vmas: VmaTree,
    /// WSCLOCK clock hand.
    pub clock_hand: VmaCursor,
    /// Address space ID.
    pub id: ASpaceId,
    /// Bump pointer for heap VA allocation.
    pub heap_next: usize,
    /// PRNG state for ASLR.
    pub prng_state: u64,
}

impl AddressSpace {
    const fn empty() -> Self {
        Self {
            page_table_root: 0,
            vmas: VmaTree::new(),
            clock_hand: VmaCursor::new(),
            id: 0,
            heap_next: HEAP_VA_BASE,
            prng_state: 0,
        }
    }

    /// Map an anonymous region into this address space.
    /// Returns a mutable reference to the new VMA on success.
    pub fn map_anon(
        &mut self,
        va_start: usize,
        page_count: usize,
        prot: VmaProt,
    ) -> Option<&mut Vma> {
        // Create the backing memory object.
        let obj_id = object::create_anon(page_count as u16)?;

        // Register the mapping in the object.
        object::with_object(obj_id, |obj| {
            obj.add_mapping(self.id, va_start);
        });

        // Insert into the VMA tree.
        let va_len = page_count * super::page::PAGE_SIZE;
        match self.vmas.insert(va_start, va_len, prot, obj_id, 0) {
            Some(vma) => Some(vma),
            None => {
                // OOM — clean up.
                object::destroy(obj_id);
                None
            }
        }
    }

    /// Check if a VA range overlaps any existing VMA.
    pub fn overlaps_vma(&self, va_start: usize, len: usize) -> bool {
        let mut it = self.vmas.iter();
        while let Some(vma) = it.next() {
            if vma.active {
                let vma_end = vma.va_start + vma.va_len;
                let range_end = va_start + len;
                if va_start < vma_end && range_end > vma.va_start {
                    return true;
                }
            }
        }
        false
    }

    /// Allocate `page_count` pages of heap VA space with ASLR.
    pub fn alloc_heap_va(&mut self, page_count: usize) -> usize {
        let va = self.heap_next;
        self.heap_next += page_count * super::page::PAGE_SIZE;
        va
    }

    /// Generate a random ASLR offset (in pages, 0..max_pages).
    pub fn random_pages(&mut self, max_pages: usize) -> usize {
        if self.prng_state == 0 || max_pages == 0 {
            return 0;
        }
        (xorshift64(&mut self.prng_state) as usize) % max_pages
    }

    /// Find the VMA containing `va` and return a mutable reference.
    pub fn find_vma_mut(&mut self, va: usize) -> Option<&mut Vma> {
        self.vmas.find_mut(va)
    }

    /// Find the VMA containing `va` (immutable).
    pub fn find_vma(&self, va: usize) -> Option<&Vma> {
        self.vmas.find(va)
    }

    /// MADV_DONTNEED: clear PTEs in [va_start, va_end).
    /// VMAs stay mapped — next access triggers zero-fill page fault.
    pub fn madvise_dontneed(&mut self, va_start: usize, va_end: usize) {
        let pt_root = self.page_table_root;
        let mmu_size = super::page::MMUPAGE_SIZE;
        let mut va = va_start & !(mmu_size - 1);
        while va < va_end {
            if self.vmas.find(va).is_some() {
                super::fault::clear_pte_dispatch(pt_root, va);
            }
            va += mmu_size;
        }
    }
}

// ---------------------------------------------------------------------------
// ART-backed address space table
// ---------------------------------------------------------------------------

/// A slab-allocated entry in the address space table.
#[repr(C)]
struct ASpaceEntry {
    /// Per-aspace pager waiter thread ID (0 = none). Accessed atomically
    /// without holding the per-aspace lock.
    pager_waiter: AtomicU32,
    /// The actual address space data, protected by a per-entry lock.
    inner: SpinLock<AddressSpace>,
}

struct ASpaceTable {
    art: Art,
    next_id: ASpaceId,
}

impl ASpaceTable {
    const fn new() -> Self {
        Self {
            art: Art::new(),
            next_id: 1,
        }
    }

    fn get(&self, id: ASpaceId) -> Option<*const ASpaceEntry> {
        let val = self.art.lookup(id as u64)?;
        Some(val as *const ASpaceEntry)
    }
}

static ASPACE_TABLE: SpinLock<ASpaceTable> = SpinLock::new(ASpaceTable::new());

/// Allocate a new ASpaceEntry from slab.
fn alloc_entry() -> Option<*mut ASpaceEntry> {
    let pa = slab::alloc(ASPACE_SLAB_SIZE)?;
    let p = pa.as_usize() as *mut ASpaceEntry;
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, ASPACE_SLAB_SIZE);
    }
    Some(p)
}

/// Free an ASpaceEntry back to slab.
fn free_entry(ptr: *mut ASpaceEntry) {
    slab::free(PhysAddr::new(ptr as usize), ASPACE_SLAB_SIZE);
}

// ---------------------------------------------------------------------------
// Per-aspace locking
// ---------------------------------------------------------------------------

/// Lock an address space by ID. Acquires the table lock briefly to find the
/// entry, then locks the per-entry SpinLock, then releases the table lock.
fn lock_aspace(id: ASpaceId) -> Option<crate::sync::SpinLockGuard<'static, AddressSpace>> {
    let table = ASPACE_TABLE.lock();
    let entry_ptr = table.get(id)?;
    // SAFETY: entry is slab-allocated and valid as long as it's in the ART.
    // We hold the table lock, so nobody can remove it from the ART yet.
    let guard = unsafe { (*entry_ptr).inner.lock() };
    drop(table);
    // Double-check ID under lock (entry could have been recycled).
    if guard.id != id {
        return None;
    }
    Some(guard)
}

/// Access an address space by ID within a closure. Panics if not found.
pub fn with_aspace<F, R>(id: ASpaceId, f: F) -> R
where
    F: FnOnce(&mut AddressSpace) -> R,
{
    let mut guard = lock_aspace(id).unwrap_or_else(|| panic!("aspace {} not found", id));
    f(&mut guard)
}

/// Access an address space by ID with a mutable closure. Returns None if not found.
pub fn with_aspace_mut<R>(id: ASpaceId, f: impl FnOnce(&mut AddressSpace) -> R) -> Option<R> {
    let mut guard = lock_aspace(id)?;
    Some(f(&mut guard))
}

// ---------------------------------------------------------------------------
// Pager waiter helpers (accessed without per-aspace lock)
// ---------------------------------------------------------------------------

/// Atomically take (read and clear) the pager waiter thread ID for an aspace.
pub fn take_pager_waiter(id: ASpaceId) -> u32 {
    let table = ASPACE_TABLE.lock();
    match table.get(id) {
        Some(entry_ptr) => {
            let entry = unsafe { &*entry_ptr };
            entry.pager_waiter.swap(0, Ordering::Relaxed)
        }
        None => 0,
    }
}

/// Set the pager waiter thread ID for an aspace.
pub fn set_pager_waiter(id: ASpaceId, tid: u32) {
    let table = ASPACE_TABLE.lock();
    if let Some(entry_ptr) = table.get(id) {
        let entry = unsafe { &*entry_ptr };
        entry.pager_waiter.store(tid, Ordering::Relaxed);
    }
}

/// Clear the pager waiter thread ID for an aspace.
pub fn clear_pager_waiter(id: ASpaceId) {
    set_pager_waiter(id, 0);
}

// ---------------------------------------------------------------------------
// Create / Destroy / Reset
// ---------------------------------------------------------------------------

/// Read a timer/cycle counter for PRNG seeding.
fn seed_from_timer() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let val: u64;
        unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) val); }
        val
    }
    #[cfg(target_arch = "riscv64")]
    {
        let val: u64;
        unsafe { core::arch::asm!("rdcycle {}", out(reg) val); }
        val
    }
    #[cfg(target_arch = "x86_64")]
    {
        let lo: u32;
        let hi: u32;
        unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi); }
        ((hi as u64) << 32) | (lo as u64)
    }
}

fn seed_aspace(space: &mut AddressSpace) {
    let seed = seed_from_timer() ^ (space.id as u64).wrapping_mul(0x9e3779b97f4a7c15);
    space.prng_state = if seed == 0 { 1 } else { seed };
    let offset_pages = (xorshift64(&mut space.prng_state) as usize) % 256;
    space.heap_next = HEAP_VA_BASE + offset_pages * super::page::PAGE_SIZE;
}

/// Create a new address space with the given page table root.
pub fn create(page_table_root: usize) -> Option<ASpaceId> {
    let ptr = alloc_entry()?;

    let mut table = ASPACE_TABLE.lock();
    let id = table.next_id;
    table.next_id += 1;

    unsafe {
        (*ptr).pager_waiter = AtomicU32::new(0);
        let mut space = AddressSpace::empty();
        space.id = id;
        space.page_table_root = page_table_root;
        space.clock_hand = VmaCursor::new();
        seed_aspace(&mut space);
        core::ptr::write(&mut (*ptr).inner, SpinLock::new(space));
    }

    if !table.art.insert(id as u64, ptr as usize) {
        drop(table);
        free_entry(ptr);
        return None;
    }

    Some(id)
}

/// Destroy an address space.
pub fn destroy(id: ASpaceId) {
    // Step 1: Remove from ART (holds table lock briefly).
    let entry_ptr = {
        let mut table = ASPACE_TABLE.lock();
        let ptr = match table.get(id) {
            Some(p) => p as *mut ASpaceEntry,
            None => return,
        };
        table.art.remove(id as u64);
        ptr
    }; // table lock released

    // Step 2: Lock entry and clean up. No new lookups can find this entry
    // (removed from ART). Any existing holder must release before we proceed.
    let mut guard = unsafe { (*entry_ptr).inner.lock() };

    // Destroy backing objects for all VMAs.
    {
        let mut it = guard.vmas.iter();
        while let Some(vma) = it.next() {
            if vma.active {
                object::destroy(vma.object_id);
            }
        }
    }
    guard.vmas.clear();
    drop(guard);

    // Step 3: Free slab.
    free_entry(entry_ptr);
}

/// Reset an address space for execve: destroy all VMAs and backing objects,
/// install a fresh page table, re-seed PRNG. The entry stays in the ART.
pub fn reset(id: ASpaceId, new_pt_root: usize) {
    let mut guard = match lock_aspace(id) {
        Some(g) => g,
        None => return,
    };
    let space = &mut *guard;
    let old_pt_root = space.page_table_root;

    // Destroy backing objects. No need to unmap individual PTEs — the entire
    // old page table tree will be freed below and switch_page_table flushes TLB.
    {
        let mut it = space.vmas.iter();
        while let Some(vma) = it.next() {
            if vma.active {
                object::with_object(vma.object_id, |obj| {
                    obj.remove_mapping(id, vma.va_start);
                });
                object::destroy(vma.object_id);
            }
        }
    }
    space.vmas.clear();
    space.page_table_root = new_pt_root;
    space.clock_hand = VmaCursor::new();
    seed_aspace(space);

    drop(guard);

    if old_pt_root != 0 {
        free_page_table_tree(old_pt_root);
    }
}

// ---------------------------------------------------------------------------
// Unmap
// ---------------------------------------------------------------------------

/// Unmap an anonymous region from an address space.
/// Unmaps PTEs, removes VMA, destroys backing object.
pub fn unmap_anon(id: ASpaceId, va: usize) -> bool {
    let mut guard = match lock_aspace(id) {
        Some(g) => g,
        None => return false,
    };
    let space = &mut *guard;
    let pt_root = space.page_table_root;

    let info = if let Some(vma) = space.find_vma(va) {
        let obj_id = vma.object_id;
        let va_start = vma.va_start;
        let mmu_count = vma.mmu_page_count();

        demote_superpages_for_vma(pt_root, vma);

        for mmu_idx in 0..mmu_count {
            let mmu_va = va_start + mmu_idx * super::page::MMUPAGE_SIZE;
            super::fault::clear_pte_dispatch(pt_root, mmu_va);
        }
        object::with_object(obj_id, |obj| {
            obj.remove_mapping(id, va_start);
        });
        Some((va_start, obj_id))
    } else {
        None
    };

    if let Some((va_start, obj_id)) = info {
        space.vmas.remove(va_start);
        let remaining = object::with_object(obj_id, |obj| obj.mapping_count());
        if remaining == 0 {
            object::destroy(obj_id);
        }
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// COW Fork
// ---------------------------------------------------------------------------

/// Clone an address space for COW fork.
/// Creates a new address space sharing all physical pages with the parent.
/// All writable PTEs are downgraded to read-only in both parent and child.
/// Returns (child_aspace_id, child_page_table_root).
pub fn clone_for_cow(parent_id: ASpaceId) -> Option<(ASpaceId, usize)> {
    let child_pt = create_user_page_table()?;

    // Step 1: Lock parent, snapshot VMA info.
    struct VmaInfo {
        va_start: usize,
        va_len: usize,
        prot: VmaProt,
        object_id: u32,
        object_offset: u32,
    }
    let mut vma_infos: [Option<VmaInfo>; 32] = {
        const NONE: Option<VmaInfo> = None;
        [NONE; 32]
    };
    let mut vma_count = 0;
    let parent_pt;
    let parent_heap;

    {
        let guard = lock_aspace(parent_id)?;
        parent_pt = guard.page_table_root;
        parent_heap = guard.heap_next;
        let mut it = guard.vmas.iter();
        while let Some(vma) = it.next() {
            if !vma.active || vma_count >= 32 { continue; }
            vma_infos[vma_count] = Some(VmaInfo {
                va_start: vma.va_start,
                va_len: vma.va_len,
                prot: vma.prot,
                object_id: vma.object_id,
                object_offset: vma.object_offset,
            });
            vma_count += 1;
        }
    } // parent lock dropped

    // Step 2: Create child entry in ART.
    let child_id;
    let child_entry_ptr;
    {
        let child_ptr = match alloc_entry() {
            Some(p) => p,
            None => {
                free_page_table_tree(child_pt);
                return None;
            }
        };

        let mut table = ASPACE_TABLE.lock();
        child_id = table.next_id;
        table.next_id += 1;

        unsafe {
            (*child_ptr).pager_waiter = AtomicU32::new(0);
            let mut space = AddressSpace::empty();
            space.id = child_id;
            space.page_table_root = child_pt;
            space.clock_hand = VmaCursor::new();
            seed_aspace(&mut space);
            space.heap_next = parent_heap;
            core::ptr::write(&mut (*child_ptr).inner, SpinLock::new(space));
        }

        if !table.art.insert(child_id as u64, child_ptr as usize) {
            drop(table);
            free_entry(child_ptr);
            free_page_table_tree(child_pt);
            return None;
        }

        child_entry_ptr = child_ptr;
    }

    // Step 3: Clone objects (no aspace lock held — only OBJ_TABLE lock).
    let mut new_obj_ids: [u32; 32] = [0; 32];

    for i in 0..vma_count {
        if let Some(ref info) = vma_infos[i] {
            match object::clone_for_cow(info.object_id) {
                Some(new_id) => {
                    object::with_object(new_id, |obj| {
                        obj.add_mapping(child_id, info.va_start);
                    });
                    new_obj_ids[i] = new_id;
                }
                None => {
                    // OOM — clean up.
                    for j in 0..i {
                        object::destroy(new_obj_ids[j]);
                    }
                    // Remove child from ART and free.
                    {
                        let mut table = ASPACE_TABLE.lock();
                        table.art.remove(child_id as u64);
                    }
                    free_entry(child_entry_ptr);
                    free_page_table_tree(child_pt);
                    return None;
                }
            }
        }
    }

    // Step 4: Lock child, insert VMAs and install child PTEs.
    {
        let mut child_guard = unsafe { (*child_entry_ptr).inner.lock() };
        let sw_z = super::fault::sw_zeroed_bit();

        for i in 0..vma_count {
            if let Some(ref info) = vma_infos[i] {
                child_guard.vmas.insert(
                    info.va_start, info.va_len, info.prot,
                    new_obj_ids[i], info.object_offset,
                );

                // Install child PTEs by walking parent's page table.
                let mmu_count = info.va_len / super::page::MMUPAGE_SIZE;
                for mmu_idx in 0..mmu_count {
                    let va = info.va_start + mmu_idx * super::page::MMUPAGE_SIZE;
                    let pte = super::fault::read_pte_dispatch(parent_pt, va);
                    if super::fault::pte_is_present(pte) {
                        if let Some(pa) = translate_va(parent_pt, va) {
                            let pa_page = pa & !(super::page::MMUPAGE_SIZE - 1);
                            let flags = if info.prot.writable() {
                                ro_flags_for_prot(info.prot)
                            } else {
                                rw_flags_for_prot(info.prot)
                            };
                            map_single_mmupage(child_pt, va, pa_page, flags | sw_z);
                        }
                    }
                }
            }
        }
    } // child lock dropped

    // Step 5: Lock parent, downgrade writable PTEs.
    {
        let _parent_guard = lock_aspace(parent_id);
        for i in 0..vma_count {
            if let Some(ref info) = vma_infos[i] {
                if info.prot.writable() {
                    let mmu_count = info.va_len / super::page::MMUPAGE_SIZE;

                    demote_superpages_in_range(parent_pt, info.va_start, mmu_count, info.prot);

                    for mmu_idx in 0..mmu_count {
                        let va = info.va_start + mmu_idx * super::page::MMUPAGE_SIZE;
                        let pte = super::fault::read_pte_dispatch(parent_pt, va);
                        if super::fault::pte_is_present(pte) {
                            downgrade_pte_readonly(parent_pt, va);
                            downgrade_pte_readonly(child_pt, va);
                        }
                    }
                }
            }
        }
    } // parent lock dropped

    Some((child_id, child_pt))
}

// ---------------------------------------------------------------------------
// mprotect
// ---------------------------------------------------------------------------

/// Change the protection of a virtual address range within an address space.
/// `addr` and `len` must be MMUPAGE_SIZE-aligned. Handles VMA splitting.
pub fn mprotect(id: ASpaceId, addr: usize, len: usize, new_prot: VmaProt) -> bool {
    use super::page::MMUPAGE_SIZE;

    if addr % MMUPAGE_SIZE != 0 || len % MMUPAGE_SIZE != 0 || len == 0 {
        return false;
    }

    let mut guard = match lock_aspace(id) {
        Some(g) => g,
        None => return false,
    };
    let space = &mut *guard;
    let pt_root = space.page_table_root;
    let end = addr + len;

    // Split at `addr` if it falls in the middle of a VMA.
    if let Some(vma) = space.vmas.find(addr) {
        if vma.va_start < addr {
            let split_at = addr;
            let orig_start = vma.va_start;
            let orig_len = vma.va_len;
            let orig_prot = vma.prot;
            let orig_obj = vma.object_id;
            let orig_off = vma.object_offset;
            let left_mmu = (split_at - orig_start) / MMUPAGE_SIZE;

            space.vmas.remove(orig_start);
            let left_len = split_at - orig_start;
            let right_len = orig_len - left_len;
            let right_off = orig_off + (left_mmu as u32);

            super::object::with_object(orig_obj, |obj| {
                obj.add_mapping(id, split_at);
            });

            space.vmas.insert(orig_start, left_len, orig_prot, orig_obj, orig_off);
            space.vmas.insert(split_at, right_len, orig_prot, orig_obj, right_off);
        }
    }

    // Split at `end` if it falls in the middle of a VMA.
    if let Some(vma) = space.vmas.find(end.saturating_sub(1)) {
        let vma_end = vma.va_start + vma.va_len;
        if end < vma_end && end > vma.va_start {
            let split_at = end;
            let orig_start = vma.va_start;
            let orig_len = vma.va_len;
            let orig_prot = vma.prot;
            let orig_obj = vma.object_id;
            let orig_off = vma.object_offset;
            let left_mmu = (split_at - orig_start) / MMUPAGE_SIZE;

            space.vmas.remove(orig_start);
            let left_len = split_at - orig_start;
            let right_len = orig_len - left_len;
            let right_off = orig_off + (left_mmu as u32);

            super::object::with_object(orig_obj, |obj| {
                obj.add_mapping(id, split_at);
            });

            space.vmas.insert(orig_start, left_len, orig_prot, orig_obj, orig_off);
            space.vmas.insert(split_at, right_len, orig_prot, orig_obj, right_off);
        }
    }

    // Update protection on all VMAs fully within [addr, end).
    let mut it = space.vmas.iter();
    while let Some(vma) = it.next() {
        if !vma.active { continue; }
        if vma.va_start >= end { break; }
        let vma_end = vma.va_start + vma.va_len;
        if vma_end <= addr { continue; }

        if vma.va_start >= addr && vma_end <= end {
            let old_prot = vma.prot;
            vma.prot = new_prot;

            if old_prot != new_prot {
                let new_flags = rw_flags_for_prot(new_prot);
                let mmu_count = vma.mmu_page_count();

                demote_superpages_in_range(pt_root, vma.va_start, mmu_count, old_prot);

                for mmu_idx in 0..mmu_count {
                    let mmu_va = vma.va_start + mmu_idx * super::page::MMUPAGE_SIZE;
                    let pte = super::fault::read_pte_dispatch(pt_root, mmu_va);
                    if super::fault::pte_is_present(pte) {
                        update_pte_flags(pt_root, mmu_va, new_flags);
                    }
                }
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// mremap
// ---------------------------------------------------------------------------

/// Remap (resize) an anonymous mapping. Supports grow and shrink.
pub fn mremap(id: ASpaceId, old_addr: usize, old_len: usize, new_len: usize) -> usize {
    use super::page::{MMUPAGE_SIZE, PAGE_SIZE};

    if old_addr % MMUPAGE_SIZE != 0 || old_len % MMUPAGE_SIZE != 0
        || new_len % MMUPAGE_SIZE != 0 || new_len == 0
    {
        return 0;
    }

    let mut guard = match lock_aspace(id) {
        Some(g) => g,
        None => return 0,
    };
    let space = &mut *guard;
    let pt_root = space.page_table_root;

    let vma = match space.find_vma_mut(old_addr) {
        Some(v) => v,
        None => return 0,
    };

    if vma.va_start != old_addr || vma.va_len != old_len {
        return 0;
    }

    if new_len == old_len {
        return old_addr;
    }

    if new_len < old_len {
        // Shrink.
        let old_mmu = old_len / MMUPAGE_SIZE;
        let new_mmu = new_len / MMUPAGE_SIZE;

        demote_superpages_for_vma_range(pt_root, vma, new_mmu, old_mmu);

        for mmu_idx in new_mmu..old_mmu {
            let mmu_va = old_addr + mmu_idx * MMUPAGE_SIZE;
            super::fault::clear_pte_dispatch(pt_root, mmu_va);
        }

        vma.va_len = new_len;

        let new_page_count = (new_len + PAGE_SIZE - 1) / PAGE_SIZE;
        let old_page_count = (old_len + PAGE_SIZE - 1) / PAGE_SIZE;
        let obj_id = vma.object_id;

        if new_page_count < old_page_count {
            for p in new_page_count..old_page_count {
                super::object::release_page(obj_id, p);
            }
            super::object::with_object(obj_id, |obj| {
                obj.page_count = new_page_count as u16;
            });
        }

        return old_addr;
    }

    // Grow.
    let new_page_count = (new_len + super::page::PAGE_SIZE - 1) / super::page::PAGE_SIZE;
    let obj_id = vma.object_id;

    let can_grow = super::object::with_object(obj_id, |obj| {
        if new_page_count <= obj.pages.capacity() {
            true
        } else {
            obj.pages.grow(new_page_count, obj.page_count as usize)
        }
    });
    if !can_grow {
        return 0;
    }

    // Check no overlapping VMA in growth region.
    let growth_start = old_addr + old_len;
    let growth_end = old_addr + new_len;
    let mut overlap = false;
    {
        let mut it = space.vmas.iter();
        while let Some(v) = it.next() {
            if !v.active { continue; }
            if v.va_start == old_addr { continue; }
            let v_end = v.va_start + v.va_len;
            if v.va_start < growth_end && v_end > growth_start {
                overlap = true;
                break;
            }
        }
    }
    if overlap {
        return 0;
    }

    let vma = space.find_vma_mut(old_addr).unwrap();
    vma.va_len = new_len;
    super::object::with_object(obj_id, |obj| {
        if (new_page_count as u16) > obj.page_count {
            obj.page_count = new_page_count as u16;
        }
    });

    old_addr
}

// ---------------------------------------------------------------------------
// Helpers — superpage demotion
// ---------------------------------------------------------------------------

/// Demote all superpages covering a VMA's range.
fn demote_superpages_for_vma(pt_root: usize, vma: &Vma) {
    let mmu_count = vma.mmu_page_count();
    let super_size = 2 * 1024 * 1024;
    let flags = super::fault::pte_flags_for_vma_pub(vma);
    let mut m = 0;
    while m < mmu_count {
        let mmu_va = vma.va_start + m * super::page::MMUPAGE_SIZE;
        let super_va = mmu_va & !(super_size - 1);
        if super::fault::is_superpage_mapped(pt_root, super_va).is_some() {
            super::fault::demote_superpage(pt_root, super_va, flags);
        }
        let next = ((super_va + super_size) - vma.va_start) / super::page::MMUPAGE_SIZE;
        m = if next > m { next } else { m + (super_size / super::page::MMUPAGE_SIZE) };
    }
}

/// Demote superpages in a sub-range of a VMA (for mremap shrink).
fn demote_superpages_for_vma_range(pt_root: usize, vma: &Vma, start_mmu: usize, end_mmu: usize) {
    let super_size = 2 * 1024 * 1024;
    let flags = super::fault::pte_flags_for_vma_pub(vma);
    let va_start = vma.va_start;
    let mut m = start_mmu;
    while m < end_mmu {
        let mmu_va = va_start + m * super::page::MMUPAGE_SIZE;
        let super_va = mmu_va & !(super_size - 1);
        if super::fault::is_superpage_mapped(pt_root, super_va).is_some() {
            super::fault::demote_superpage(pt_root, super_va, flags);
        }
        let next = ((super_va + super_size) - va_start) / super::page::MMUPAGE_SIZE;
        m = if next > m { next } else { m + (super_size / super::page::MMUPAGE_SIZE) };
    }
}

/// Demote superpages in a range given by (va_start, mmu_count, prot).
fn demote_superpages_in_range(pt_root: usize, va_start: usize, mmu_count: usize, prot: VmaProt) {
    let super_size = 2 * 1024 * 1024;
    let super_mmu = super_size / super::page::MMUPAGE_SIZE;
    let flags = rw_flags_for_prot(prot);
    let mut m = 0;
    while m < mmu_count {
        let va = va_start + m * super::page::MMUPAGE_SIZE;
        let super_va = va & !(super_size - 1);
        if super::fault::is_superpage_mapped(pt_root, super_va).is_some() {
            super::fault::demote_superpage(pt_root, super_va, flags);
            super::stats::SUPERPAGE_DEMOTIONS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        let next_super = ((super_va + super_size) - va_start) / super::page::MMUPAGE_SIZE;
        m = if next_super > m { next_super } else { m + super_mmu };
    }
}

// ---------------------------------------------------------------------------
// Architecture dispatch wrappers
// ---------------------------------------------------------------------------

fn ro_flags_for_prot(_prot: VmaProt) -> u64 {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::USER_RO_FLAGS }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::USER_RO_FLAGS }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::USER_RO_FLAGS }
}

fn rw_flags_for_prot(prot: VmaProt) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::mm;
        match prot {
            VmaProt::ReadOnly => mm::USER_RO_FLAGS,
            VmaProt::ReadWrite => mm::USER_RW_FLAGS,
            VmaProt::ReadExec => mm::USER_RWX_FLAGS,
            VmaProt::ReadWriteExec => mm::USER_RWX_FLAGS,
            VmaProt::None => 0,
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        use crate::arch::riscv64::mm;
        match prot {
            VmaProt::ReadOnly => mm::USER_RO_FLAGS,
            VmaProt::ReadWrite => mm::USER_RW_FLAGS,
            VmaProt::ReadExec => mm::USER_RWX_FLAGS,
            VmaProt::ReadWriteExec => mm::USER_RWX_FLAGS,
            VmaProt::None => 0,
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        use crate::arch::x86_64::mm;
        match prot {
            VmaProt::ReadOnly => mm::USER_RO_FLAGS,
            VmaProt::ReadWrite => mm::USER_RW_FLAGS,
            VmaProt::ReadExec => mm::USER_RWX_FLAGS,
            VmaProt::ReadWriteExec => mm::USER_RWX_FLAGS,
            VmaProt::None => 0,
        }
    }
}

fn create_user_page_table() -> Option<usize> {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::setup_tables() }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::setup_tables() }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::create_user_page_table() }
}

fn free_page_table_tree(root: usize) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::free_page_table_tree(root); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::free_page_table_tree(root); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::free_page_table_tree(root); }
}

fn downgrade_pte_readonly(pt_root: usize, va: usize) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::downgrade_pte_readonly(pt_root, va); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::downgrade_pte_readonly(pt_root, va); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::downgrade_pte_readonly(pt_root, va); }
}

fn translate_va(pt_root: usize, va: usize) -> Option<usize> {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::translate_va(pt_root, va) }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::translate_va(pt_root, va) }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::translate_va(pt_root, va) }
}

fn map_single_mmupage(pt_root: usize, va: usize, pa: usize, flags: u64) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::map_single_mmupage(pt_root, va, pa, flags); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::map_single_mmupage(pt_root, va, pa, flags); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::map_single_mmupage(pt_root, va, pa, flags); }
}

fn update_pte_flags(pt_root: usize, va: usize, flags: u64) {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::mm::update_pte_flags(pt_root, va, flags); }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::mm::update_pte_flags(pt_root, va, flags); }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::mm::update_pte_flags(pt_root, va, flags); }
}
