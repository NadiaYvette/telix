//! COW sharing groups — coordinate copy-on-write across forked memory objects.
//!
//! When an anonymous memory object is forked, the parent and child share the
//! same physical pages. A COW group tracks the set of objects that share a
//! common lineage and coordinates reservation-based COW breaking to preserve
//! superpage alignment.
//!
//! Groups are port-referenced: a `CowGroupId` is a kernel-held port ID (u64).
//! Resolution is lock-free via `port_kernel_data() → *const GroupEntry`.
//! Each entry has its own SpinLock for per-group serialization.
//!
//! ## Fork Epochs
//!
//! Each fork event creates an independent "epoch" that tracks pairwise sharing
//! between parent and child. An epoch records which pages the parent had at
//! fork time (`shared_mask`) and independently tracks which participant has
//! COW-broken since (`parent_copied_since`, `child_copied_since`). This allows
//! N>2 members without per-page refcounts.
//!
//! ## Reservations
//!
//! When a COW fault hits a page within a superpage-aligned range, the group
//! allocates a contiguous superpage-aligned physical destination region for
//! the faulting member. Subsequent COW faults within the same range fill
//! slots in the reservation instead of allocating scattered single pages.
//! This preserves physical contiguity for superpage re-promotion.

use super::page::{PAGE_SIZE, PhysAddr, SUPERPAGE_ALLOC_PAGES, SUPERPAGE_LEVELS};
use super::stats;
use core::sync::atomic::Ordering;
use crate::ipc::port::{self, PortId};
use crate::mm::slab;
use crate::sync::SpinLock;

/// Slab size for GroupEntry allocations (must be power of two ≥ actual size).
const GROUP_SLAB_SIZE: usize = 256;

/// Maximum sub-blocks in a higher-level reservation pool.
/// 1 GiB / 2 MiB = 512 sub-blocks → 512 bits = [u64; 8].
const POOL_BITMAP_WORDS: usize = 8;

/// Maximum inline members per group.
/// Covers parent + up to 7 children — sufficient for nearly all fork trees.
const MAX_MEMBERS: usize = 8;

/// Maximum fork epochs per group (one per fork event = MAX_MEMBERS - 1).
const MAX_EPOCHS: usize = 7;

/// Maximum reservations per extent (one per member that has COW-faulted
/// within that range).
const MAX_RESERVATIONS: usize = 8;

/// COW group ID type — a kernel-held port ID (u64).
pub type CowGroupId = u64;

// ---------------------------------------------------------------------------
// Reservation data structures
// ---------------------------------------------------------------------------

/// A single member's reservation within a GroupExtent.
/// Tracks the contiguous physical destination and which pages have been copied.
#[derive(Clone, Copy)]
struct MemberReservation {
    /// The object that owns this reservation.
    obj_id: u64,
    /// Physical base of the reserved destination region (superpage-aligned).
    dest_pa: usize,
    /// Bitmask: bit i set = allocation page i has been COW-copied into dest.
    /// Supports up to 64 allocation pages per superpage range.
    copied: u64,
}

impl MemberReservation {
    const fn empty() -> Self {
        Self {
            obj_id: 0,
            dest_pa: 0,
            copied: 0,
        }
    }
}

/// Per-fork-event sharing data within an extent.
///
/// Each epoch tracks independent pairwise sharing between a parent and child.
/// `shared_mask` captures which pages the parent had at fork time.
/// `parent_copied_since` / `child_copied_since` track COW breaks after the fork.
#[derive(Clone, Copy)]
struct EpochBitmasks {
    shared_mask: u64,
    parent_copied_since: u64,
    child_copied_since: u64,
}

impl EpochBitmasks {
    const fn empty() -> Self {
        Self {
            shared_mask: 0,
            parent_copied_since: 0,
            child_copied_since: 0,
        }
    }
}

/// A superpage-aligned range within a COW group that has active reservations.
#[derive(Clone, Copy)]
struct GroupExtent {
    /// Object-page-offset base (superpage-aligned within the object).
    obj_page_base: u32,
    /// Number of allocation pages in this extent. Usually SUPERPAGE_ALLOC_PAGES
    /// but may be smaller at the tail of an object.
    page_count: u8,
    /// Number of active epochs in this extent.
    epoch_count: u8,
    /// Number of active reservations.
    reservation_count: u8,
    _pad: u8,
    /// Per-fork-event sharing data.
    epochs: [EpochBitmasks; MAX_EPOCHS],
    /// Per-member reservations.
    reservations: [MemberReservation; MAX_RESERVATIONS],
}

impl GroupExtent {
    const fn empty() -> Self {
        Self {
            obj_page_base: 0,
            page_count: 0,
            epoch_count: 0,
            reservation_count: 0,
            _pad: 0,
            epochs: [EpochBitmasks::empty(); MAX_EPOCHS],
            reservations: [MemberReservation::empty(); MAX_RESERVATIONS],
        }
    }

    #[allow(dead_code)]
    fn is_active(&self) -> bool {
        self.page_count > 0
    }

    /// Find an existing reservation for `obj_id`, or None.
    fn find_reservation(&self, obj_id: u64) -> Option<usize> {
        for i in 0..self.reservation_count as usize {
            if self.reservations[i].obj_id == obj_id {
                return Some(i);
            }
        }
        None
    }

    /// Add a new reservation for `obj_id` with destination `dest_pa`.
    /// Returns the index, or None if full.
    fn add_reservation(&mut self, obj_id: u64, dest_pa: usize) -> Option<usize> {
        if self.reservation_count as usize >= MAX_RESERVATIONS {
            return None;
        }
        let idx = self.reservation_count as usize;
        self.reservations[idx] = MemberReservation {
            obj_id,
            dest_pa,
            copied: 0,
        };
        self.reservation_count += 1;
        Some(idx)
    }

    /// Remove a member's reservation, freeing unclaimed destination pages.
    fn remove_reservation(&mut self, obj_id: u64) {
        for i in 0..self.reservation_count as usize {
            if self.reservations[i].obj_id == obj_id {
                let r = &self.reservations[i];
                // Free unclaimed pages in the reserved destination region.
                // Skip if dest_pa is 0 (tracking-only reservation from mark_private).
                let dest_pa = r.dest_pa;
                let copied = r.copied;
                if dest_pa != 0 {
                    for slot in 0..self.page_count as usize {
                        if copied & (1u64 << slot) == 0 {
                            super::phys::free_page(PhysAddr::new(dest_pa + slot * PAGE_SIZE));
                        }
                    }
                }
                // Swap-remove.
                let last = self.reservation_count as usize - 1;
                self.reservations[i] = self.reservations[last];
                self.reservations[last] = MemberReservation::empty();
                self.reservation_count -= 1;
                return;
            }
        }
    }

    /// Check if a specific page slot has been COW-broken by `obj_id`
    /// (via reservation tracking).
    fn is_copied_by(&self, obj_id: u64, slot: usize) -> bool {
        if let Some(idx) = self.find_reservation(obj_id) {
            self.reservations[idx].copied & (1u64 << slot) != 0
        } else {
            false
        }
    }

    /// Add an epoch to this extent. Returns true on success.
    fn add_epoch(&mut self, shared_mask: u64) -> bool {
        if self.epoch_count as usize >= MAX_EPOCHS {
            return false;
        }
        let idx = self.epoch_count as usize;
        self.epochs[idx] = EpochBitmasks {
            shared_mask,
            parent_copied_since: 0,
            child_copied_since: 0,
        };
        self.epoch_count += 1;
        true
    }

    /// Remove epoch at index `ei` via swap-remove.
    fn remove_epoch(&mut self, ei: usize) {
        let last = self.epoch_count as usize - 1;
        self.epochs[ei] = self.epochs[last];
        self.epochs[last] = EpochBitmasks::empty();
        self.epoch_count -= 1;
    }

    /// Check if page at `slot` is shared for member at `member_idx` using
    /// epoch-based tracking.
    ///
    /// Returns true iff there EXISTS an epoch where:
    /// - member is a participant (parent or child)
    /// - shared_mask has the bit set
    /// - NEITHER participant has COW-broken since that epoch
    fn is_shared_for_member(
        &self,
        member_idx: u8,
        slot: usize,
        fork_parent: &[u8; MAX_EPOCHS],
        fork_child: &[u8; MAX_EPOCHS],
    ) -> bool {
        let bit = 1u64 << slot;
        for ei in 0..self.epoch_count as usize {
            let e = &self.epochs[ei];
            if e.shared_mask & bit == 0 {
                continue;
            }
            let pi = fork_parent[ei];
            let ci = fork_child[ei];
            if member_idx == pi || member_idx == ci {
                if e.parent_copied_since & bit == 0 && e.child_copied_since & bit == 0 {
                    return true;
                }
            }
        }
        false
    }

    /// Mark member's COW-break at `slot` in all participating epochs.
    /// Sets the appropriate copied_since bit.
    fn mark_epoch_copied(
        &mut self,
        member_idx: u8,
        slot: usize,
        fork_parent: &[u8; MAX_EPOCHS],
        fork_child: &[u8; MAX_EPOCHS],
    ) {
        let bit = 1u64 << slot;
        for ei in 0..self.epoch_count as usize {
            let e = &mut self.epochs[ei];
            if e.shared_mask & bit == 0 {
                continue;
            }
            let pi = fork_parent[ei];
            let ci = fork_child[ei];
            if member_idx == pi {
                e.parent_copied_since |= bit;
            } else if member_idx == ci {
                e.child_copied_since |= bit;
            }
        }
    }

    /// Conservative orphan check: can old PA at `slot` be freed?
    ///
    /// Returns true iff for EVERY epoch where shared_mask has the bit set,
    /// BOTH parent_copied_since and child_copied_since have the bit set.
    /// This means every pair that ever shared at this slot has both moved on.
    fn is_slot_orphaned(&self, slot: usize) -> bool {
        let bit = 1u64 << slot;
        for ei in 0..self.epoch_count as usize {
            let e = &self.epochs[ei];
            if e.shared_mask & bit == 0 {
                continue;
            }
            if e.parent_copied_since & bit == 0 || e.child_copied_since & bit == 0 {
                return false;
            }
        }
        true
    }

    /// For destroy: classify which pages member at `member_idx` can free.
    fn pages_to_free(
        &self,
        member_idx: u8,
        page_count: u8,
        fork_parent: &[u8; MAX_EPOCHS],
        fork_child: &[u8; MAX_EPOCHS],
    ) -> u64 {
        let mut free_mask: u64 = 0;
        for slot in 0..page_count as usize {
            let bit = 1u64 << slot;
            // Check if any epoch has this slot as shared for this member.
            let mut in_any_epoch = false;
            let mut all_copied = true; // member has COW-broken in all participating epochs
            for ei in 0..self.epoch_count as usize {
                let e = &self.epochs[ei];
                if e.shared_mask & bit == 0 {
                    continue;
                }
                let pi = fork_parent[ei];
                let ci = fork_child[ei];
                if member_idx == pi {
                    in_any_epoch = true;
                    if e.parent_copied_since & bit == 0 {
                        all_copied = false;
                    }
                } else if member_idx == ci {
                    in_any_epoch = true;
                    if e.child_copied_since & bit == 0 {
                        all_copied = false;
                    }
                }
            }

            if !in_any_epoch {
                // No epoch covers this slot for this member → post-fork private → free.
                free_mask |= bit;
            } else if all_copied {
                // Member COW-broke this slot in all participating epochs → private copy → free.
                free_mask |= bit;
            } else {
                // Member still references a shared PA. Check global orphan.
                if self.is_slot_orphaned(slot) {
                    free_mask |= bit;
                }
            }
        }
        free_mask
    }
}

/// Extents per page of the page-allocated extent array.
const EXTENTS_PER_PAGE: usize = PAGE_SIZE / core::mem::size_of::<GroupExtent>();

// ---------------------------------------------------------------------------
// Per-group state
// ---------------------------------------------------------------------------

/// Per-group state, protected by a SpinLock inside GroupEntry.
///
/// Member list is inline (64 bytes for 8 members). Extents are stored in
/// a page-allocated array (lazily allocated on first reservation).
///
/// Fork tree: `fork_parent[i]` / `fork_child[i]` record which member indices
/// participated in epoch `i`. These indices refer into `members[]`.
struct CowGroup {
    /// Member object IDs (port_ids of MemObjects in this group).
    members: [u64; MAX_MEMBERS],
    /// Number of active members.
    member_count: u8,
    /// Number of active fork epochs.
    epoch_count: u8,
    /// Number of active extents.
    extent_count: u8,
    /// Fork tree: parent member index for each epoch.
    fork_parent: [u8; MAX_EPOCHS],
    /// Fork tree: child member index for each epoch.
    fork_child: [u8; MAX_EPOCHS],
    /// Page-allocated extent array (null until first reservation).
    extents: *mut GroupExtent,
    /// Capacity of the extent array.
    extents_cap: u16,

    // -- Higher-level reservation pool --
    // When the first 2M reservation is allocated, we attempt to reserve an
    // entire higher-level block (e.g., 1 GiB) so that subsequent 2M
    // destinations for the same member land contiguously. This enables
    // eventual promotion to the higher superpage level.

    /// Physical base of the pool (higher-level-aligned), or 0 if none.
    pool_pa: usize,
    /// Object-page-aligned base of the higher-level region this pool covers.
    pool_obj_base: u32,
    /// Member obj_id that owns this pool.
    pool_owner: u64,
    /// Index into SUPERPAGE_LEVELS for the pool's level (e.g., 1 for 1 GiB).
    pool_level_idx: u8,
    /// Number of sub-blocks (level[idx-1].size) in this pool.
    pool_sub_count: u16,
    /// Bitmap of allocated sub-blocks.
    pool_bitmap: [u64; POOL_BITMAP_WORDS],
}

// Safety: extents pointer is allocated/freed under the per-group lock.
unsafe impl Send for CowGroup {}

impl CowGroup {
    const fn new() -> Self {
        Self {
            members: [0; MAX_MEMBERS],
            member_count: 0,
            epoch_count: 0,
            extent_count: 0,
            fork_parent: [0; MAX_EPOCHS],
            fork_child: [0; MAX_EPOCHS],
            extents: core::ptr::null_mut(),
            extents_cap: 0,
            pool_pa: 0,
            pool_obj_base: 0,
            pool_owner: 0,
            pool_level_idx: 0,
            pool_sub_count: 0,
            pool_bitmap: [0u64; POOL_BITMAP_WORDS],
        }
    }

    /// Ensure the extent backing page is allocated. Returns false on OOM.
    fn ensure_extents(&mut self) -> bool {
        if !self.extents.is_null() {
            return true;
        }
        let page = match super::phys::alloc_page() {
            Some(pa) => pa.as_usize() as *mut GroupExtent,
            None => return false,
        };
        unsafe {
            core::ptr::write_bytes(page as *mut u8, 0, PAGE_SIZE);
        }
        self.extents = page;
        self.extents_cap = EXTENTS_PER_PAGE as u16;
        true
    }

    // -- Pool helpers --

    /// Check if the pool is active and covers the given 2M range for the given owner.
    /// Returns the physical address for this sub-block if available.
    fn try_alloc_from_pool(&mut self, obj_id: u64, obj_page_base: u32) -> Option<PhysAddr> {
        if self.pool_pa == 0 || self.pool_owner != obj_id {
            return None;
        }
        if SUPERPAGE_LEVELS.len() < 2 {
            return None;
        }
        let sub_level = &SUPERPAGE_LEVELS[0]; // 2M sub-blocks
        let sub_alloc_pages = sub_level.alloc_pages();
        // Check that obj_page_base is within the pool's higher-level range.
        if obj_page_base < self.pool_obj_base {
            return None;
        }
        let offset_pages = (obj_page_base - self.pool_obj_base) as usize;
        if offset_pages % sub_alloc_pages != 0 {
            return None;
        }
        let sub_idx = offset_pages / sub_alloc_pages;
        if sub_idx >= self.pool_sub_count as usize {
            return None;
        }
        // Check bitmap: already allocated?
        let word = sub_idx / 64;
        let bit = sub_idx % 64;
        if self.pool_bitmap[word] & (1u64 << bit) != 0 {
            return None; // Already handed out.
        }
        // Mark as allocated.
        self.pool_bitmap[word] |= 1u64 << bit;
        let dest_pa = self.pool_pa + sub_idx * sub_level.size;
        stats::POOL_ALLOCS.fetch_add(1, Ordering::Relaxed);
        Some(PhysAddr::new(dest_pa))
    }

    /// Free all unallocated sub-blocks in the pool back to the physical allocator.
    fn free_pool(&mut self) {
        if self.pool_pa == 0 {
            return;
        }
        if SUPERPAGE_LEVELS.len() < 2 {
            return;
        }
        let sub_size = SUPERPAGE_LEVELS[0].size;
        for i in 0..self.pool_sub_count as usize {
            let word = i / 64;
            let bit = i % 64;
            if self.pool_bitmap[word] & (1u64 << bit) == 0 {
                // Not allocated — free this sub-block's pages.
                let base = self.pool_pa + i * sub_size;
                let pages = SUPERPAGE_LEVELS[0].alloc_pages();
                for p in 0..pages {
                    super::phys::free_page(PhysAddr::new(base + p * PAGE_SIZE));
                }
            }
        }
        self.pool_pa = 0;
        self.pool_obj_base = 0;
        self.pool_owner = 0;
        self.pool_level_idx = 0;
        self.pool_sub_count = 0;
        self.pool_bitmap = [0u64; POOL_BITMAP_WORDS];
    }

    /// Find the member index for `obj_id`, or None.
    fn member_index(&self, obj_id: u64) -> Option<u8> {
        for i in 0..self.member_count as usize {
            if self.members[i] == obj_id {
                return Some(i as u8);
            }
        }
        None
    }

    /// Add a member. Returns true on success, false if full.
    fn add_member(&mut self, obj_id: u64) -> bool {
        if self.member_count as usize >= MAX_MEMBERS {
            return false;
        }
        self.members[self.member_count as usize] = obj_id;
        self.member_count += 1;
        true
    }

    /// Remove a member. Handles epoch removal, member index fixup, and
    /// reservation cleanup in all extents. Returns the new member count.
    fn remove_member(&mut self, obj_id: u64) -> u8 {
        // Find member index before removal.
        let mi = match self.member_index(obj_id) {
            Some(i) => i,
            None => return self.member_count,
        };

        // Step 0: Free pool if this member owns it.
        if self.pool_owner == obj_id {
            self.free_pool();
        }

        // Step 1: Mark departure in all epochs where this member participates.
        // Set the member's copied_since bits to all-ones in participating epochs
        // so the orphan check can free PAs.
        for ei in 0..self.epoch_count as usize {
            for xi in 0..self.extent_count as usize {
                let ext = unsafe { &mut *self.extents.add(xi) };
                if ei < ext.epoch_count as usize {
                    let e = &mut ext.epochs[ei];
                    if self.fork_parent[ei] == mi {
                        e.parent_copied_since = e.shared_mask;
                    } else if self.fork_child[ei] == mi {
                        e.child_copied_since = e.shared_mask;
                    }
                }
            }
        }

        // Step 2: Remove all epochs where this member was a participant.
        // Use reverse iteration for swap-remove stability.
        let mut ei = self.epoch_count as usize;
        while ei > 0 {
            ei -= 1;
            if self.fork_parent[ei] == mi || self.fork_child[ei] == mi {
                // Swap-remove this epoch from CowGroup.
                let last = self.epoch_count as usize - 1;
                self.fork_parent[ei] = self.fork_parent[last];
                self.fork_child[ei] = self.fork_child[last];
                self.fork_parent[last] = 0;
                self.fork_child[last] = 0;
                self.epoch_count -= 1;

                // Swap-remove from each extent.
                for xi in 0..self.extent_count as usize {
                    let ext = unsafe { &mut *self.extents.add(xi) };
                    if ei < ext.epoch_count as usize {
                        ext.remove_epoch(ei);
                    }
                }
            }
        }

        // Step 3: Remove member from members[] via swap-remove.
        let last_mi = self.member_count as usize - 1;
        self.members[mi as usize] = self.members[last_mi];
        self.members[last_mi] = 0;
        self.member_count -= 1;

        // Step 4: Fix member indices in remaining epochs.
        // The member at `last_mi` was swapped into slot `mi`.
        if (mi as usize) < last_mi {
            for ei in 0..self.epoch_count as usize {
                if self.fork_parent[ei] == last_mi as u8 {
                    self.fork_parent[ei] = mi;
                }
                if self.fork_child[ei] == last_mi as u8 {
                    self.fork_child[ei] = mi;
                }
            }
        }

        // Step 5: Remove reservations for this member from all extents.
        for xi in 0..self.extent_count as usize {
            let ext = unsafe { &mut *self.extents.add(xi) };
            ext.remove_reservation(obj_id);
        }

        // Step 6: Clean up empty extents (no epochs and no reservations).
        let mut xi = 0;
        while xi < self.extent_count as usize {
            let ext = unsafe { &*self.extents.add(xi) };
            if ext.epoch_count == 0 && ext.reservation_count == 0 {
                let last = self.extent_count as usize - 1;
                if xi != last {
                    unsafe {
                        let last_ext = *self.extents.add(last);
                        *self.extents.add(xi) = last_ext;
                        core::ptr::write_bytes(
                            self.extents.add(last) as *mut u8,
                            0,
                            core::mem::size_of::<GroupExtent>(),
                        );
                    }
                }
                self.extent_count -= 1;
            } else {
                xi += 1;
            }
        }

        self.member_count
    }

    /// Find the extent covering `obj_page_base`, or None.
    fn find_extent(&self, obj_page_base: u32) -> Option<usize> {
        for i in 0..self.extent_count as usize {
            let ext = unsafe { &*self.extents.add(i) };
            if ext.obj_page_base == obj_page_base {
                return Some(i);
            }
        }
        None
    }

    /// Create a new extent. Returns the index, or None if full or OOM.
    /// Epochs must be added separately via `extent.add_epoch()`.
    fn create_extent(&mut self, obj_page_base: u32, page_count: u8) -> Option<usize> {
        if !self.ensure_extents() {
            return None;
        }
        if self.extent_count >= self.extents_cap as u8 {
            return None;
        }
        let idx = self.extent_count as usize;
        unsafe {
            let ext = &mut *self.extents.add(idx);
            *ext = GroupExtent::empty();
            ext.obj_page_base = obj_page_base;
            ext.page_count = page_count;
        }
        self.extent_count += 1;
        Some(idx)
    }

    /// Get a reference to an extent by index.
    fn extent(&self, idx: usize) -> &GroupExtent {
        unsafe { &*self.extents.add(idx) }
    }

    /// Get a mutable reference to an extent by index.
    fn extent_mut(&mut self, idx: usize) -> &mut GroupExtent {
        unsafe { &mut *self.extents.add(idx) }
    }

    /// Free the extent backing page, all unclaimed reservation pages, and pool.
    fn free_all_extents(&mut self) {
        self.free_pool();
        for ei in 0..self.extent_count as usize {
            let ext = unsafe { &*self.extents.add(ei) };
            for ri in 0..ext.reservation_count as usize {
                let r = &ext.reservations[ri];
                if r.dest_pa == 0 {
                    continue;
                } // tracking-only reservation
                for slot in 0..ext.page_count as usize {
                    if r.copied & (1u64 << slot) == 0 {
                        super::phys::free_page(PhysAddr::new(r.dest_pa + slot * PAGE_SIZE));
                    }
                }
            }
        }
        if !self.extents.is_null() {
            super::phys::free_page(PhysAddr::new(self.extents as usize));
            self.extents = core::ptr::null_mut();
            self.extents_cap = 0;
        }
        self.extent_count = 0;
    }
}

// ---------------------------------------------------------------------------
// Port-referenced group entries
// ---------------------------------------------------------------------------

/// A slab-allocated group entry, resolved lock-free via port_kernel_data.
struct GroupEntry {
    /// Kernel-held port for this group (used for resolution via PORT_ART).
    port_id: u64,
    /// Per-group lock protecting the CowGroup state.
    inner: SpinLock<CowGroup>,
}

/// Allocate a new GroupEntry from slab.
fn alloc_entry() -> Option<*mut GroupEntry> {
    let pa = slab::alloc(GROUP_SLAB_SIZE)?;
    let p = pa.as_usize() as *mut GroupEntry;
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, GROUP_SLAB_SIZE);
    }
    Some(p)
}

/// Free a GroupEntry back to slab.
fn free_entry(ptr: *mut GroupEntry) {
    slab::free(PhysAddr::new(ptr as usize), GROUP_SLAB_SIZE);
}

/// Resolve a CowGroupId (port_id) to the GroupEntry pointer. Lock-free via RCU.
#[inline]
fn resolve_entry(id: CowGroupId) -> Option<*const GroupEntry> {
    if id == 0 {
        return None;
    }
    let user_data = port::port_kernel_data(id)?;
    Some(user_data as *const GroupEntry)
}

/// Kernel port handler for COW groups (stub — not used for IPC).
fn group_port_handler(
    _port_id: PortId,
    _user_data: usize,
    _msg: &crate::ipc::Message,
) -> crate::ipc::Message {
    crate::ipc::Message::empty()
}

/// RCU callback to free a slab-allocated GroupEntry.
fn rcu_free_group_callback(ptr: usize) {
    free_entry(ptr as *mut GroupEntry);
}

// ---------------------------------------------------------------------------
// Public API — lifecycle
// ---------------------------------------------------------------------------

/// Create a new COW sharing group. Returns the group port_id.
pub fn create() -> Option<CowGroupId> {
    let ptr = alloc_entry()?;

    let port_id = match port::create_kernel_port(group_port_handler, ptr as usize) {
        Some(p) => p,
        None => {
            free_entry(ptr);
            return None;
        }
    };

    unsafe {
        (*ptr).port_id = port_id;
        core::ptr::write(&mut (*ptr).inner, SpinLock::new(CowGroup::new()));
    }

    Some(port_id)
}

/// Add a memory object to a COW group.
/// Returns true on success, false if the group is full or invalid.
pub fn add_member(group_id: CowGroupId, obj_id: u64) -> bool {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p,
        None => return false,
    };
    let mut guard = unsafe { (*entry_ptr).inner.lock() };
    guard.add_member(obj_id)
}

/// Remove a memory object from a COW group.
/// Frees unclaimed reservation pages for this member.
///
/// Returns `Some(survivor_obj_id)` if this removal left exactly one member
/// (the sole survivor now exclusively owns all its pages and should be
/// detached from the group). Returns `None` otherwise.
///
/// If this was the last member, the group is destroyed automatically.
pub fn remove_member(group_id: CowGroupId, obj_id: u64) -> Option<u64> {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p as *mut GroupEntry,
        None => return None,
    };

    let (remaining, survivor) = {
        let mut guard = unsafe { (*entry_ptr).inner.lock() };
        let remaining = guard.remove_member(obj_id);
        let survivor = if remaining == 1 {
            Some(guard.members[0])
        } else {
            None
        };
        (remaining, survivor)
    };

    if remaining == 0 {
        destroy(group_id);
        None
    } else if remaining == 1 {
        // Sole survivor — destroy the group (its reservations are no longer
        // needed since there's no one left to share with).
        destroy(group_id);
        survivor
    } else {
        None
    }
}

/// Destroy a COW group, freeing all resources.
/// Called automatically when the last member is removed.
fn destroy(group_id: CowGroupId) {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p as *mut GroupEntry,
        None => return,
    };

    {
        let mut guard = unsafe { (*entry_ptr).inner.lock() };
        guard.free_all_extents();
    }

    port::destroy(group_id);
    crate::sync::rcu::rcu_defer_free(entry_ptr as usize, rcu_free_group_callback);
}

// ---------------------------------------------------------------------------
// Public API — reservations
// ---------------------------------------------------------------------------

/// Result of finding or creating a reservation slot for a COW fault.
pub struct ReservationSlot {
    /// Physical address for this specific page within the reserved region.
    pub dest_page_pa: usize,
    /// True if this slot was already copied (no work needed).
    pub already_copied: bool,
}

/// Find or create a reservation for `obj_id` within the superpage-aligned
/// range starting at `obj_page_base`. On first call for a given extent,
/// allocates a superpage-aligned physical destination. On first call for
/// a given member within an extent, that member gets its own destination.
///
/// `page_count`: number of allocation pages in this range (usually
/// SUPERPAGE_ALLOC_PAGES, but may be smaller at object tail).
///
/// `slot`: the specific page index within the extent (0..page_count).
///
/// Returns the destination PA for the slot and whether it was already copied,
/// or None if allocation failed (caller should fall back to single-page COW).
pub fn find_or_create_reservation(
    group_id: CowGroupId,
    obj_id: u64,
    obj_page_base: u32,
    page_count: u8,
    slot: usize,
) -> Option<ReservationSlot> {
    let entry_ptr = resolve_entry(group_id)?;
    let mut guard = unsafe { (*entry_ptr).inner.lock() };

    // Find or create the extent for this superpage range.
    let ei = match guard.find_extent(obj_page_base) {
        Some(i) => i,
        None => {
            // Lazily-created extent during COW fault. Add all current epochs
            // with conservative all-ones shared_masks.
            let idx = match guard.create_extent(obj_page_base, page_count) {
                Some(i) => i,
                None => return None,
            };
            for _ in 0..guard.epoch_count {
                guard.extent_mut(idx).add_epoch(!0u64);
            }
            idx
        }
    };

    // Find or create this member's reservation within the extent.
    // A reservation may exist with dest_pa=0 (tracking-only, from mark_private).
    // In that case, allocate a real destination and upgrade it.
    let needs_alloc = match guard.extent(ei).find_reservation(obj_id) {
        Some(i) => guard.extent(ei).reservations[i].dest_pa == 0,
        None => true,
    };

    let ri = if needs_alloc {
        // Try pool allocation first (lock held — no drop needed).
        if let Some(pa) = guard.try_alloc_from_pool(obj_id, obj_page_base) {
            // Pool hit — lock still held, proceed to reservation creation.
            let dest_pa = pa;
            if let Some(i) = guard.extent(ei).find_reservation(obj_id) {
                if guard.extent(ei).reservations[i].dest_pa != 0 {
                    // Race: someone else filled it — pool page is wasted but
                    // bitmap already set, so it won't be double-freed.
                    let r = &guard.extent(ei).reservations[i];
                    let already_copied = r.copied & (1u64 << slot) != 0;
                    return Some(ReservationSlot {
                        dest_page_pa: r.dest_pa + slot * PAGE_SIZE,
                        already_copied,
                    });
                }
                // Upgrade tracking-only reservation.
                let old_copied = guard.extent(ei).reservations[i].copied;
                guard.extent_mut(ei).reservations[i].dest_pa = dest_pa.as_usize();
                for s in 0..guard.extent(ei).page_count as usize {
                    if old_copied & (1u64 << s) != 0 {
                        super::phys::free_page(PhysAddr::new(
                            dest_pa.as_usize() + s * PAGE_SIZE,
                        ));
                    }
                }
                i
            } else {
                match guard
                    .extent_mut(ei)
                    .add_reservation(obj_id, dest_pa.as_usize())
                {
                    Some(i) => i,
                    None => return None,
                }
            }
        } else {
            // Pool miss — drop lock, allocate, re-acquire.
            let want_pool = guard.pool_pa == 0 && SUPERPAGE_LEVELS.len() >= 2;
            drop(guard);

            // Phase 1: allocate outside the lock.
            let pool_block = if want_pool {
                super::fault::alloc_aligned_for_level(&SUPERPAGE_LEVELS[1])
            } else {
                None
            };
            // Always allocate a fallback 2M block if we couldn't get a pool block,
            // or as the independent allocation path.
            let independent = if pool_block.is_none() {
                Some(super::fault::alloc_superpage_aligned()?)
            } else {
                None
            };

            // Phase 2: re-acquire lock and try to use pool.
            guard = unsafe { (*entry_ptr).inner.lock() };

            let (dest_pa, from_pool) = if let Some(pool_pa) = pool_block {
                if guard.pool_pa == 0 {
                    // Set up the pool.
                    let sub_alloc = SUPERPAGE_LEVELS[0].alloc_pages();
                    let hi_alloc = SUPERPAGE_LEVELS[1].alloc_pages();
                    let hi_obj_base = obj_page_base & !((hi_alloc - 1) as u32);
                    guard.pool_pa = pool_pa.as_usize();
                    stats::POOL_CREATES.fetch_add(1, Ordering::Relaxed);
                    guard.pool_obj_base = hi_obj_base;
                    guard.pool_owner = obj_id;
                    guard.pool_level_idx = 1;
                    guard.pool_sub_count = (hi_alloc / sub_alloc) as u16;
                    guard.pool_bitmap = [0u64; POOL_BITMAP_WORDS];
                }
                match guard.try_alloc_from_pool(obj_id, obj_page_base) {
                    Some(pa) => {
                        // Pool created/existing and sub-block carved.
                        if guard.pool_pa != pool_pa.as_usize() {
                            // We created a pool but someone else's was used —
                            // free our block.
                            super::fault::free_pages_range(
                                pool_pa,
                                SUPERPAGE_LEVELS[1].alloc_pages(),
                            );
                        }
                        (pa, true)
                    }
                    None => {
                        // Pool doesn't cover this range — free pool block if
                        // we just created it (otherwise it was someone else's).
                        if guard.pool_pa == pool_pa.as_usize() {
                            guard.free_pool();
                        } else {
                            super::fault::free_pages_range(
                                pool_pa,
                                SUPERPAGE_LEVELS[1].alloc_pages(),
                            );
                        }
                        // Fall back to independent allocation.
                        drop(guard);
                        let fallback = super::fault::alloc_superpage_aligned()?;
                        guard = unsafe { (*entry_ptr).inner.lock() };
                        (fallback, false)
                    }
                }
            } else {
                (independent.unwrap(), false)
            };

            let ei = match guard.find_extent(obj_page_base) {
                Some(i) => i,
                None => {
                    if !from_pool {
                        super::fault::free_pages_range(dest_pa, SUPERPAGE_ALLOC_PAGES);
                    }
                    return None;
                }
            };

            // Check if someone else created/upgraded our reservation while unlocked.
            if let Some(i) = guard.extent(ei).find_reservation(obj_id) {
                if guard.extent(ei).reservations[i].dest_pa != 0 {
                    if !from_pool {
                        super::fault::free_pages_range(dest_pa, SUPERPAGE_ALLOC_PAGES);
                    }
                    let r = &guard.extent(ei).reservations[i];
                    let already_copied = r.copied & (1u64 << slot) != 0;
                    return Some(ReservationSlot {
                        dest_page_pa: r.dest_pa + slot * PAGE_SIZE,
                        already_copied,
                    });
                } else {
                    let old_copied = guard.extent(ei).reservations[i].copied;
                    guard.extent_mut(ei).reservations[i].dest_pa = dest_pa.as_usize();
                    for s in 0..guard.extent(ei).page_count as usize {
                        if old_copied & (1u64 << s) != 0 {
                            super::phys::free_page(PhysAddr::new(
                                dest_pa.as_usize() + s * PAGE_SIZE,
                            ));
                        }
                    }
                    i
                }
            } else {
                match guard
                    .extent_mut(ei)
                    .add_reservation(obj_id, dest_pa.as_usize())
                {
                    Some(i) => i,
                    None => {
                        if !from_pool {
                            super::fault::free_pages_range(dest_pa, SUPERPAGE_ALLOC_PAGES);
                        }
                        return None;
                    }
                }
            }
        }
    } else {
        guard.extent(ei).find_reservation(obj_id).unwrap()
    };

    let r = &guard.extent(ei).reservations[ri];
    let already_copied = r.copied & (1u64 << slot) != 0;
    let dest_page_pa = r.dest_pa + slot * PAGE_SIZE;

    Some(ReservationSlot {
        dest_page_pa,
        already_copied,
    })
}

/// Check whether a page is still shared from `obj_id`'s perspective.
///
/// Returns true if there exists an epoch where this member and its partner
/// both still reference the same original PA at this page offset.
///
/// If the group has no extent for this range (no COW faults have occurred
/// in this superpage range yet), all pages are shared with all other members.
pub fn is_page_shared_in_group(
    group_id: CowGroupId,
    obj_id: u64,
    obj_page_base: u32,
    slot: usize,
) -> bool {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p,
        None => return false,
    };
    let guard = unsafe { (*entry_ptr).inner.lock() };

    if guard.member_count <= 1 {
        return false;
    }

    let mi = match guard.member_index(obj_id) {
        Some(i) => i,
        None => return false,
    };

    let ei = match guard.find_extent(obj_page_base) {
        Some(i) => i,
        None => {
            // No extent yet — no COW breaks in this range.
            // All pages are shared with all other members.
            return true;
        }
    };

    guard
        .extent(ei)
        .is_shared_for_member(mi, slot, &guard.fork_parent, &guard.fork_child)
}

/// Check whether all originally-shared pages in a superpage range have
/// been COW-broken by `obj_id` (reservation is complete). If so, the
/// member's pages in this range are all contiguous in the reservation
/// destination and may be eligible for superpage promotion.
pub fn is_reservation_complete(group_id: CowGroupId, obj_id: u64, obj_page_base: u32) -> bool {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p,
        None => return false,
    };
    let guard = unsafe { (*entry_ptr).inner.lock() };

    if guard.member_count <= 1 {
        return true;
    }

    let mi = match guard.member_index(obj_id) {
        Some(i) => i,
        None => return false,
    };

    let ei = match guard.find_extent(obj_page_base) {
        Some(i) => i,
        None => return false,
    };
    let ext = guard.extent(ei);

    let ri = match ext.find_reservation(obj_id) {
        Some(i) => i,
        None => return false,
    };

    // Complete when every shared page has been COW-broken by this member.
    let copied = ext.reservations[ri].copied;
    for slot in 0..ext.page_count as usize {
        if ext.is_shared_for_member(mi, slot, &guard.fork_parent, &guard.fork_child)
            && (copied & (1u64 << slot) == 0)
        {
            return false;
        }
    }

    true
}

/// Reservation info returned by `get_reservation_info`.
pub struct ReservationInfo {
    /// Physical base of the reserved destination (superpage-aligned).
    pub dest_pa: usize,
    /// Bitmask of which slots have been COW-copied.
    #[allow(dead_code)]
    pub copied: u64,
    /// Number of allocation pages in this extent.
    pub page_count: u8,
}

/// Get the reservation info for a completed reservation. Returns the
/// destination PA, copied bitmap, and page count. This is used by the
/// consolidation path to relocate non-COW pages into the reservation
/// destination for superpage promotion.
///
/// Returns None if the reservation doesn't exist or isn't complete.
pub fn get_reservation_info(
    group_id: CowGroupId,
    obj_id: u64,
    obj_page_base: u32,
) -> Option<ReservationInfo> {
    let entry_ptr = resolve_entry(group_id)?;
    let guard = unsafe { (*entry_ptr).inner.lock() };

    let ei = guard.find_extent(obj_page_base)?;
    let ext = guard.extent(ei);
    let ri = ext.find_reservation(obj_id)?;
    let r = &ext.reservations[ri];

    Some(ReservationInfo {
        dest_pa: r.dest_pa,
        copied: r.copied,
        page_count: ext.page_count,
    })
}

/// Add a fork epoch to all extents (existing and newly created).
///
/// Called at fork time after the child is added to the group. Creates a new
/// epoch recording which pages the parent had at fork time. For each
/// superpage-aligned range, builds a `shared_mask` from `is_page_present`.
///
/// `parent_obj_id` / `child_obj_id`: the forking parent and new child.
/// `obj_page_count`: total allocation pages in the object.
/// `is_page_present(page_idx)`: returns true if parent has a physical page.
///
/// Only creates extents (metadata), not reservations (physical destinations).
pub fn add_fork_epoch_to_extents(
    group_id: CowGroupId,
    parent_obj_id: u64,
    child_obj_id: u64,
    obj_page_count: u16,
    is_page_present: impl Fn(usize) -> bool,
) {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p,
        None => return,
    };
    let mut guard = unsafe { (*entry_ptr).inner.lock() };

    // Record the epoch in the group's fork tree.
    let parent_mi = match guard.member_index(parent_obj_id) {
        Some(i) => i,
        None => return,
    };
    let child_mi = match guard.member_index(child_obj_id) {
        Some(i) => i,
        None => return,
    };
    if guard.epoch_count as usize >= MAX_EPOCHS {
        return; // Epoch capacity exhausted.
    }
    let epoch_idx = guard.epoch_count as usize;
    guard.fork_parent[epoch_idx] = parent_mi;
    guard.fork_child[epoch_idx] = child_mi;
    guard.epoch_count += 1;

    // Add epoch bitmasks to all existing and new extents.
    let total = obj_page_count as usize;
    let mut base = 0;
    while base + SUPERPAGE_ALLOC_PAGES <= total {
        // Build shared_mask: bit i set if page (base + i) is allocated.
        let mut mask: u64 = 0;
        for i in 0..SUPERPAGE_ALLOC_PAGES {
            if is_page_present(base + i) {
                mask |= 1u64 << i;
            }
        }

        let ei = match guard.find_extent(base as u32) {
            Some(i) => i,
            None => {
                match guard.create_extent(base as u32, SUPERPAGE_ALLOC_PAGES as u8) {
                    Some(i) => i,
                    None => break, // OOM or extent capacity — stop.
                }
            }
        };
        guard.extent_mut(ei).add_epoch(mask);

        base += SUPERPAGE_ALLOC_PAGES;
    }
}

/// Mark a page slot as COW-copied and release the original PA if orphaned.
///
/// Called after a COW fault copies a shared page. Sets the `copied` bit for
/// `obj_id` at `slot`, updates epoch tracking, then checks if the original
/// PA is orphaned (all epoch pairs have both-copied). If so, frees it.
///
/// Returns true if `old_pa` was freed (orphaned original).
pub fn mark_copied_and_release(
    group_id: CowGroupId,
    obj_id: u64,
    obj_page_base: u32,
    slot: usize,
    old_pa: super::page::PhysAddr,
) -> bool {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p,
        None => return false,
    };
    let mut guard = unsafe { (*entry_ptr).inner.lock() };

    let mi = match guard.member_index(obj_id) {
        Some(i) => i,
        None => return false,
    };

    let ei = match guard.find_extent(obj_page_base) {
        Some(i) => i,
        None => return false,
    };

    // Set copied bit in reservation. Create tracking-only if none exists.
    let ri = match guard.extent(ei).find_reservation(obj_id) {
        Some(i) => i,
        None => match guard.extent_mut(ei).add_reservation(obj_id, 0) {
            Some(i) => i,
            None => return false,
        },
    };
    let fp = guard.fork_parent;
    let fc = guard.fork_child;
    guard.extent_mut(ei).reservations[ri].copied |= 1u64 << slot;
    guard.extent_mut(ei).mark_epoch_copied(mi, slot, &fp, &fc);

    // Check if the original PA is now orphaned (all epoch pairs both-copied).
    if guard.extent(ei).is_slot_orphaned(slot) {
        drop(guard);
        super::phys::free_page(old_pa);
        return true;
    }

    false
}

/// Mark a page slot as privately allocated (post-fork demand-zero).
///
/// Called when a COW object allocates a new page via ensure_page (not through
/// a COW fault). Sets the `copied` bit and epoch tracking so the member is
/// correctly excluded from sharing queries for this slot.
///
/// Creates a tracking-only reservation (dest_pa=0) if the member has no
/// reservation in this extent yet.
pub fn mark_private(group_id: CowGroupId, obj_id: u64, obj_page_base: u32, slot: usize) {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p,
        None => return,
    };
    let mut guard = unsafe { (*entry_ptr).inner.lock() };

    let mi = match guard.member_index(obj_id) {
        Some(i) => i,
        None => return,
    };

    let ei = match guard.find_extent(obj_page_base) {
        Some(i) => i,
        None => return,
    };

    let ri = match guard.extent(ei).find_reservation(obj_id) {
        Some(i) => i,
        None => match guard.extent_mut(ei).add_reservation(obj_id, 0) {
            Some(i) => i,
            None => return,
        },
    };

    let fp = guard.fork_parent;
    let fc = guard.fork_child;
    guard.extent_mut(ei).reservations[ri].copied |= 1u64 << slot;
    guard.extent_mut(ei).mark_epoch_copied(mi, slot, &fp, &fc);
}

/// For a member being destroyed, determine which pages in a superpage range
/// should be freed. Returns a bitmask: bit i set = caller should free page i.
///
/// Uses epoch-based classification:
/// - Not in any epoch at this slot → post-fork private allocation → free
/// - Member COW-broke in all participating epochs → private COW copy → free
/// - Still shares in some epoch → check orphan status → free if all-both-copied
pub fn pages_to_free_on_destroy(
    group_id: CowGroupId,
    obj_id: u64,
    obj_page_base: u32,
    page_count: u8,
) -> u64 {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p,
        None => {
            // Group not found — treat all as exclusively owned.
            return (1u64 << page_count) - 1;
        }
    };
    let guard = unsafe { (*entry_ptr).inner.lock() };

    let mi = match guard.member_index(obj_id) {
        Some(i) => i,
        None => return (1u64 << page_count) - 1,
    };

    let ei = match guard.find_extent(obj_page_base) {
        Some(i) => i,
        None => {
            // No extent → conservatively don't free (other members may reference).
            return 0;
        }
    };

    guard
        .extent(ei)
        .pages_to_free(mi, page_count, &guard.fork_parent, &guard.fork_child)
}

/// Release a shared page from a COW group. Called by release_page when a
/// COW object's page is being unmapped/evicted.
///
/// Uses epoch-based tracking to determine whether the PA is a private copy
/// (free directly) or a shared original (mark departure, free if orphaned).
///
/// Returns true if the PA was freed.
pub fn release_shared_page(
    group_id: CowGroupId,
    obj_id: u64,
    obj_page_base: u32,
    slot: usize,
    pa: super::page::PhysAddr,
) -> bool {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p,
        None => {
            super::phys::free_page(pa);
            return true;
        }
    };
    let mut guard = unsafe { (*entry_ptr).inner.lock() };

    let mi = match guard.member_index(obj_id) {
        Some(i) => i,
        None => {
            // Not a member — treat as exclusively owned.
            drop(guard);
            super::phys::free_page(pa);
            return true;
        }
    };

    let ei = match guard.find_extent(obj_page_base) {
        Some(i) => i,
        None => {
            // No extent → shared original with no tracking. Don't free.
            return false;
        }
    };

    // Check if this member has COW-broken this slot (reservation copied bit).
    if guard.extent(ei).is_copied_by(obj_id, slot) {
        // Private COW copy → free directly.
        drop(guard);
        super::phys::free_page(pa);
        return true;
    }

    // Check via epochs: is this slot shared for this member?
    if !guard
        .extent(ei)
        .is_shared_for_member(mi, slot, &guard.fork_parent, &guard.fork_child)
    {
        // Not shared in any epoch → post-fork private allocation → free.
        drop(guard);
        super::phys::free_page(pa);
        return true;
    }

    // Shared original — mark departure in reservation + epoch tracking.
    let ri = match guard.extent(ei).find_reservation(obj_id) {
        Some(i) => i,
        None => match guard.extent_mut(ei).add_reservation(obj_id, 0) {
            Some(i) => i,
            None => return false,
        },
    };
    let fp = guard.fork_parent;
    let fc = guard.fork_child;
    guard.extent_mut(ei).reservations[ri].copied |= 1u64 << slot;
    guard.extent_mut(ei).mark_epoch_copied(mi, slot, &fp, &fc);

    // Check if the original PA is now orphaned.
    if guard.extent(ei).is_slot_orphaned(slot) {
        drop(guard);
        super::phys::free_page(pa);
        return true;
    }

    false
}
