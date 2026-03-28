//! Address space — per-task virtual memory management.
//!
//! Each address space owns a page table root and a B+ tree of VMAs.
//! The WSCLOCK clock hand (VmaCursor) is also stored here.
//!
//! Each address space is port-referenced: an `ASpaceId` is a kernel-held
//! port ID (u64). Lookup is lock-free via `port_kernel_data()` → entry
//! pointer through RCU-protected PORT_ART.
//!
//! Locking: each address space has its own SpinLock. Operations on
//! different address spaces never contend. No global lock.

use super::object::{self};
use super::page::PhysAddr;
use super::vma::{Vma, VmaProt};
use super::vmatree::{VmaCursor, VmaTree};
use crate::mm::slab;
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicU32, Ordering};

/// Slab size for ASpaceEntry allocations.
const ASPACE_SLAB_SIZE: usize = 128;

/// Address space ID type — a kernel-held port ID (u64).
/// Value 0 means "no address space" (kernel task).
pub type ASpaceId = u64;

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
// Port-referenced address space entries
// ---------------------------------------------------------------------------

/// A slab-allocated entry in the address space table.
#[repr(C)]
struct ASpaceEntry {
    /// Kernel-held port ID for this address space.
    port_id: u64,
    /// Per-aspace pager waiter thread ID (0 = none). Accessed atomically
    /// without holding the per-aspace lock.
    pager_waiter: AtomicU32,
    /// The actual address space data, protected by a per-entry lock.
    inner: SpinLock<AddressSpace>,
}

/// Monotonic ID counter for debugging (not used for lookup).
static NEXT_ASPACE_SEQ: AtomicU32 = AtomicU32::new(1);

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

/// Kernel port handler for address spaces (stub — not used for IPC).
fn aspace_port_handler(
    _port_id: crate::ipc::port::PortId,
    _user_data: usize,
    _msg: &crate::ipc::Message,
) -> crate::ipc::Message {
    crate::ipc::Message::empty()
}

/// Resolve an ASpaceId (port_id) to the entry pointer. Lock-free via RCU.
#[inline]
fn resolve_entry(id: ASpaceId) -> Option<*const ASpaceEntry> {
    if id == 0 { return None; }
    let ptr = crate::ipc::port::port_kernel_data(id)?;
    Some(ptr as *const ASpaceEntry)
}

// ---------------------------------------------------------------------------
// Per-aspace locking
// ---------------------------------------------------------------------------

/// Lock an address space by port_id. Resolves via PORT_ART (lock-free RCU),
/// then locks the per-entry SpinLock.
fn lock_aspace(id: ASpaceId) -> Option<crate::sync::SpinLockGuard<'static, AddressSpace>> {
    let entry_ptr = resolve_entry(id)?;
    // SAFETY: entry is slab-allocated and valid as long as the port exists.
    // Port destruction uses RCU deferred free, so in-flight lookups are safe.
    let guard = unsafe { (*entry_ptr).inner.lock() };
    // Validate entry is still live (id != 0 after destruction).
    if guard.id == 0 {
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
/// Fully lock-free: resolves via PORT_ART, accesses AtomicU32 directly.
pub fn take_pager_waiter(id: ASpaceId) -> u32 {
    match resolve_entry(id) {
        Some(entry_ptr) => {
            let entry = unsafe { &*entry_ptr };
            entry.pager_waiter.swap(0, Ordering::Relaxed)
        }
        None => 0,
    }
}

/// Set the pager waiter thread ID for an aspace. Lock-free.
pub fn set_pager_waiter(id: ASpaceId, tid: u32) {
    if let Some(entry_ptr) = resolve_entry(id) {
        let entry = unsafe { &*entry_ptr };
        entry.pager_waiter.store(tid, Ordering::Relaxed);
    }
}

/// Clear the pager waiter thread ID for an aspace. Lock-free.
pub fn clear_pager_waiter(id: ASpaceId) {
    set_pager_waiter(id, 0);
}

// ---------------------------------------------------------------------------
// Create / Destroy / Reset
// ---------------------------------------------------------------------------

/// Read a timer/cycle counter for PRNG seeding.
fn seed_from_timer() -> u64 {
    crate::arch::timer::read_cycles()
}

fn seed_aspace(space: &mut AddressSpace) {
    let seed = seed_from_timer() ^ (space.id as u64).wrapping_mul(0x9e3779b97f4a7c15);
    space.prng_state = if seed == 0 { 1 } else { seed };
    let offset_pages = (xorshift64(&mut space.prng_state) as usize) % 256;
    space.heap_next = HEAP_VA_BASE + offset_pages * super::page::PAGE_SIZE;
}

/// Create a new address space with the given page table root.
/// Returns the port_id (ASpaceId) for the new address space.
pub fn create(page_table_root: usize) -> Option<ASpaceId> {
    let ptr = alloc_entry()?;

    let seq = NEXT_ASPACE_SEQ.fetch_add(1, Ordering::Relaxed);

    // Create a kernel-held port with user_data = entry pointer.
    let port_id = match crate::ipc::port::create_kernel_port(
        aspace_port_handler,
        ptr as usize,
    ) {
        Some(p) => p,
        None => {
            free_entry(ptr);
            return None;
        }
    };

    unsafe {
        (*ptr).port_id = port_id;
        (*ptr).pager_waiter = AtomicU32::new(0);
        let mut space = AddressSpace::empty();
        space.id = port_id;
        space.page_table_root = page_table_root;
        space.clock_hand = VmaCursor::new();
        seed_aspace(&mut space);
        core::ptr::write(&mut (*ptr).inner, SpinLock::new(space));
    }

    let _ = seq; // debug sequence number, unused for now
    Some(port_id)
}

/// Destroy an address space.
pub fn destroy(id: ASpaceId) {
    // Step 1: Resolve entry pointer.
    let entry_ptr = match resolve_entry(id) {
        Some(p) => p as *mut ASpaceEntry,
        None => return,
    };

    // Step 2: Lock entry and clean up.
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
    // Mark as dead so concurrent lock_aspace() sees id=0.
    guard.id = 0;
    drop(guard);

    // Step 3: Destroy the port (removes from PORT_ART, wakes waiters).
    crate::ipc::port::destroy(id);

    // Step 4: Defer-free the slab entry after RCU grace period.
    crate::sync::rcu::rcu_defer_free(entry_ptr as usize, rcu_free_aspace_callback);
}

/// RCU callback to free a slab-allocated ASpaceEntry.
fn rcu_free_aspace_callback(ptr: usize) {
    free_entry(ptr as *mut ASpaceEntry);
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
                // Use try_with_object: grant VMAs may reference objects
                // owned by another process that already exited.
                object::try_with_object(vma.object_id, |obj| {
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
        object::try_with_object(obj_id, |obj| {
            obj.remove_mapping(id, va_start);
        });
        Some((va_start, obj_id))
    } else {
        None
    };

    if let Some((va_start, obj_id)) = info {
        space.vmas.remove(va_start);
        let remaining = object::try_with_object(obj_id, |obj| obj.mapping_count())
            .unwrap_or(0);
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

    // Step 1: Lock parent, snapshot VMA info into a page-allocated buffer.
    // Each entry holds the VMA snapshot plus the cloned object ID (filled in step 3).
    #[repr(C)]
    struct CowEntry {
        va_start: usize,
        va_len: usize,
        prot: VmaProt,
        object_id: u64,
        object_offset: u32,
        new_obj_id: u64,
    }
    const ENTRIES_PER_PAGE: usize = super::page::PAGE_SIZE / core::mem::size_of::<CowEntry>();

    let cow_page = super::phys::alloc_page()?;
    let cow_buf = cow_page.as_usize() as *mut CowEntry;
    unsafe { core::ptr::write_bytes(cow_buf as *mut u8, 0, super::page::PAGE_SIZE); }

    let mut vma_count = 0usize;
    let parent_pt;
    let parent_heap;

    {
        let guard = lock_aspace(parent_id)?;
        parent_pt = guard.page_table_root;
        parent_heap = guard.heap_next;
        let mut it = guard.vmas.iter();
        while let Some(vma) = it.next() {
            if !vma.active || vma_count >= ENTRIES_PER_PAGE { continue; }
            unsafe {
                let e = &mut *cow_buf.add(vma_count);
                e.va_start = vma.va_start;
                e.va_len = vma.va_len;
                e.prot = vma.prot;
                e.object_id = vma.object_id;
                e.object_offset = vma.object_offset;
                e.new_obj_id = 0;
            }
            vma_count += 1;
        }
    } // parent lock dropped

    // Step 2: Create child entry with port.
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

        let port_id = match crate::ipc::port::create_kernel_port(
            aspace_port_handler,
            child_ptr as usize,
        ) {
            Some(p) => p,
            None => {
                free_entry(child_ptr);
                free_page_table_tree(child_pt);
                return None;
            }
        };

        child_id = port_id;

        unsafe {
            (*child_ptr).port_id = port_id;
            (*child_ptr).pager_waiter = AtomicU32::new(0);
            let mut space = AddressSpace::empty();
            space.id = child_id;
            space.page_table_root = child_pt;
            space.clock_hand = VmaCursor::new();
            seed_aspace(&mut space);
            space.heap_next = parent_heap;
            core::ptr::write(&mut (*child_ptr).inner, SpinLock::new(space));
        }

        child_entry_ptr = child_ptr;
    }

    // Step 3: Clone objects (no aspace lock held — only OBJ_TABLE lock).
    for i in 0..vma_count {
        let info = unsafe { &mut *cow_buf.add(i) };
        match object::clone_for_cow(info.object_id) {
            Some(new_id) => {
                object::with_object(new_id, |obj| {
                    obj.add_mapping(child_id, info.va_start);
                });
                info.new_obj_id = new_id;
            }
            None => {
                // OOM — clean up.
                for j in 0..i {
                    let e = unsafe { &*cow_buf.add(j) };
                    object::destroy(e.new_obj_id);
                }
                // Destroy child port and free entry.
                crate::ipc::port::destroy(child_id);
                crate::sync::rcu::synchronize_rcu();
                free_entry(child_entry_ptr);
                free_page_table_tree(child_pt);
                super::phys::free_page(cow_page);
                return None;
            }
        }
    }

    // Step 4: Demote parent superpages, then install child PTEs and
    // downgrade both parent and child to read-only for COW.
    //
    // Superpage demotion must happen BEFORE walking parent L3 PTEs,
    // because translate_va/read_pte walk to L3 and return None/0 for
    // superpage block descriptors (which live at L2, not L3).
    {
        // First: demote all superpages in writable parent VMAs.
        for i in 0..vma_count {
            let info = unsafe { &*cow_buf.add(i) };
            if info.prot.writable() {
                let mmu_count = info.va_len / super::page::MMUPAGE_SIZE;
                demote_superpages_in_range(parent_pt, info.va_start, mmu_count, info.prot);
            }
        }

        // Now install child PTEs and downgrade parent PTEs — all L3 entries
        // are accessible since superpages have been demoted.
        let mut child_guard = unsafe { (*child_entry_ptr).inner.lock() };
        let sw_z = super::fault::sw_zeroed_bit();

        for i in 0..vma_count {
            let info = unsafe { &*cow_buf.add(i) };
            child_guard.vmas.insert(
                info.va_start, info.va_len, info.prot,
                info.new_obj_id, info.object_offset,
            );

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

                        // Downgrade parent PTE to read-only for COW.
                        if info.prot.writable() {
                            downgrade_pte_readonly(parent_pt, va);
                        }
                    }
                }
            }
        }
    } // child lock dropped

    // Free the snapshot buffer.
    super::phys::free_page(cow_page);

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
    use super::page::{MMUPAGE_SIZE, SUPERPAGE_SIZE, SUPERPAGE_ALIGN_MASK, SUPERPAGE_MMU_PAGES};
    let mmu_count = vma.mmu_page_count();
    let flags = super::fault::pte_flags_for_vma_pub(vma);
    let mut m = 0;
    while m < mmu_count {
        let mmu_va = vma.va_start + m * MMUPAGE_SIZE;
        let super_va = mmu_va & !SUPERPAGE_ALIGN_MASK;
        if super::fault::is_superpage_mapped(pt_root, super_va).is_some() {
            super::fault::demote_superpage(pt_root, super_va, flags);
        }
        let next = ((super_va + SUPERPAGE_SIZE) - vma.va_start) / MMUPAGE_SIZE;
        m = if next > m { next } else { m + SUPERPAGE_MMU_PAGES };
    }
}

/// Demote superpages in a sub-range of a VMA (for mremap shrink).
fn demote_superpages_for_vma_range(pt_root: usize, vma: &Vma, start_mmu: usize, end_mmu: usize) {
    use super::page::{MMUPAGE_SIZE, SUPERPAGE_SIZE, SUPERPAGE_ALIGN_MASK, SUPERPAGE_MMU_PAGES};
    let flags = super::fault::pte_flags_for_vma_pub(vma);
    let va_start = vma.va_start;
    let mut m = start_mmu;
    while m < end_mmu {
        let mmu_va = va_start + m * MMUPAGE_SIZE;
        let super_va = mmu_va & !SUPERPAGE_ALIGN_MASK;
        if super::fault::is_superpage_mapped(pt_root, super_va).is_some() {
            super::fault::demote_superpage(pt_root, super_va, flags);
        }
        let next = ((super_va + SUPERPAGE_SIZE) - va_start) / MMUPAGE_SIZE;
        m = if next > m { next } else { m + SUPERPAGE_MMU_PAGES };
    }
}

/// Demote superpages in a range given by (va_start, mmu_count, prot).
fn demote_superpages_in_range(pt_root: usize, va_start: usize, mmu_count: usize, prot: VmaProt) {
    use super::page::{MMUPAGE_SIZE, SUPERPAGE_SIZE, SUPERPAGE_ALIGN_MASK, SUPERPAGE_MMU_PAGES};
    let flags = rw_flags_for_prot(prot);
    let mut m = 0;
    while m < mmu_count {
        let va = va_start + m * MMUPAGE_SIZE;
        let super_va = va & !SUPERPAGE_ALIGN_MASK;
        if super::fault::is_superpage_mapped(pt_root, super_va).is_some() {
            super::fault::demote_superpage(pt_root, super_va, flags);
            super::stats::SUPERPAGE_DEMOTIONS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        let next_super = ((super_va + SUPERPAGE_SIZE) - va_start) / MMUPAGE_SIZE;
        m = if next_super > m { next_super } else { m + SUPERPAGE_MMU_PAGES };
    }
}

// ---------------------------------------------------------------------------
// Architecture dispatch wrappers
// ---------------------------------------------------------------------------

use super::hat;

fn ro_flags_for_prot(_prot: VmaProt) -> u64 {
    hat::USER_RO_FLAGS
}

fn rw_flags_for_prot(prot: VmaProt) -> u64 {
    hat::pte_flags_for_prot(prot)
}

fn create_user_page_table() -> Option<usize> {
    hat::create_user_page_table()
}

fn free_page_table_tree(root: usize) {
    hat::free_page_table_tree(root);
}

fn downgrade_pte_readonly(pt_root: usize, va: usize) {
    hat::downgrade_pte_readonly(pt_root, va);
}

fn translate_va(pt_root: usize, va: usize) -> Option<usize> {
    hat::translate_va(pt_root, va)
}

fn map_single_mmupage(pt_root: usize, va: usize, pa: usize, flags: u64) {
    hat::map_single_mmupage(pt_root, va, pa, flags);
}

fn update_pte_flags(pt_root: usize, va: usize, flags: u64) {
    hat::update_pte_flags(pt_root, va, flags);
}
