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
//! ## Reservations
//!
//! When a COW fault hits a page within a superpage-aligned range, the group
//! allocates a contiguous superpage-aligned physical destination region for
//! the faulting member. Subsequent COW faults within the same range fill
//! slots in the reservation instead of allocating scattered single pages.
//! This preserves physical contiguity for superpage re-promotion.

use super::page::{PhysAddr, PAGE_SIZE, SUPERPAGE_ALLOC_PAGES};
use crate::ipc::port::{self, PortId};
use crate::mm::slab;
use crate::sync::SpinLock;

/// Slab size for GroupEntry allocations (must be power of two ≥ actual size).
const GROUP_SLAB_SIZE: usize = 128;

/// Maximum inline members per group.
/// Covers parent + up to 7 children — sufficient for nearly all fork trees.
const MAX_MEMBERS: usize = 8;

/// Maximum reservations per extent (one per member that has COW-faulted
/// within that range). Typically 2 (parent + one child); 4 handles cascading.
const MAX_RESERVATIONS: usize = 4;

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
        Self { obj_id: 0, dest_pa: 0, copied: 0 }
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
    /// Number of active reservations.
    reservation_count: u8,
    /// Bitmask of pages that were allocated at fork time. Bit i set means
    /// page i was present in the source PageVec when the COW clone happened.
    /// Pages with this bit clear are post-fork private allocations (or never
    /// allocated). Used to distinguish shared originals from private pages.
    shared_mask: u64,
    /// Per-member reservations.
    reservations: [MemberReservation; MAX_RESERVATIONS],
}

impl GroupExtent {
    const fn empty() -> Self {
        Self {
            obj_page_base: 0,
            page_count: 0,
            reservation_count: 0,
            shared_mask: 0,
            reservations: [MemberReservation::empty(); MAX_RESERVATIONS],
        }
    }

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
    /// Returns true if the extent has no reservations left.
    fn remove_reservation(&mut self, obj_id: u64) -> bool {
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
                            super::phys::free_page(PhysAddr::new(
                                dest_pa + slot * PAGE_SIZE,
                            ));
                        }
                    }
                }
                // Swap-remove.
                let last = self.reservation_count as usize - 1;
                self.reservations[i] = self.reservations[last];
                self.reservations[last] = MemberReservation::empty();
                self.reservation_count -= 1;
                return self.reservation_count == 0;
            }
        }
        false
    }

    /// Check if a specific page slot has been COW-broken by `obj_id`.
    fn is_copied_by(&self, obj_id: u64, slot: usize) -> bool {
        if let Some(idx) = self.find_reservation(obj_id) {
            self.reservations[idx].copied & (1u64 << slot) != 0
        } else {
            false
        }
    }

    /// Count how many members (other than `obj_id`) have NOT COW-broken
    /// page `slot`. These members still reference the original shared PA.
    fn other_sharers(&self, obj_id: u64, slot: usize, total_members: u8) -> u8 {
        // If this page wasn't shared at fork time, no original PA exists
        // to share. All pages at this slot are privately owned.
        if self.shared_mask & (1u64 << slot) == 0 {
            return 0;
        }
        // Start with total members minus self.
        let mut sharers = total_members - 1;
        // Subtract members that have COW-broken this page (they no longer
        // reference the original PA at this slot).
        for i in 0..self.reservation_count as usize {
            let r = &self.reservations[i];
            if r.obj_id != obj_id && r.copied & (1u64 << slot) != 0 {
                sharers = sharers.saturating_sub(1);
            }
        }
        sharers
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
struct CowGroup {
    /// Member object IDs (port_ids of MemObjects in this group).
    members: [u64; MAX_MEMBERS],
    /// Number of active members.
    member_count: u8,
    /// Number of active extents.
    extent_count: u8,
    /// True if this group uses per-page frame refcounts for lifetime tracking.
    /// Set when a cascading fork creates a 3+ member group. Groups created by
    /// a first fork (2 members) use extent shared_mask + copied bits instead.
    refcounted: bool,
    /// Page-allocated extent array (null until first reservation).
    extents: *mut GroupExtent,
    /// Capacity of the extent array.
    extents_cap: u16,
}

// Safety: extents pointer is allocated/freed under the per-group lock.
unsafe impl Send for CowGroup {}

impl CowGroup {
    const fn new() -> Self {
        Self {
            members: [0; MAX_MEMBERS],
            member_count: 0,
            extent_count: 0,
            refcounted: false,
            extents: core::ptr::null_mut(),
            extents_cap: 0,
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

    /// Add a member. Returns true on success, false if full.
    fn add_member(&mut self, obj_id: u64) -> bool {
        if self.member_count as usize >= MAX_MEMBERS {
            return false;
        }
        self.members[self.member_count as usize] = obj_id;
        self.member_count += 1;
        true
    }

    /// Remove a member. Frees their reservations in all extents.
    /// Returns the new member count.
    fn remove_member(&mut self, obj_id: u64) -> u8 {
        // Remove from member list.
        let mut found = false;
        for i in 0..self.member_count as usize {
            if self.members[i] == obj_id {
                let last = self.member_count as usize - 1;
                self.members[i] = self.members[last];
                self.members[last] = 0;
                self.member_count -= 1;
                found = true;
                break;
            }
        }
        if !found {
            return self.member_count;
        }

        // Remove reservations for this member from all extents.
        let mut i = 0;
        while i < self.extent_count as usize {
            let ext = unsafe { &mut *self.extents.add(i) };
            let no_reservations_left = ext.remove_reservation(obj_id);
            if no_reservations_left {
                // Remove empty extent (swap with last).
                let last = self.extent_count as usize - 1;
                if i != last {
                    unsafe {
                        let last_ext = *self.extents.add(last);
                        *self.extents.add(i) = last_ext;
                        core::ptr::write_bytes(self.extents.add(last) as *mut u8, 0,
                            core::mem::size_of::<GroupExtent>());
                    }
                }
                self.extent_count -= 1;
                // Don't increment i — re-check the swapped element.
            } else {
                i += 1;
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
    fn create_extent(&mut self, obj_page_base: u32, page_count: u8, shared_mask: u64) -> Option<usize> {
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
            ext.shared_mask = shared_mask;
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

    /// Free the extent backing page and all unclaimed reservation pages.
    fn free_all_extents(&mut self) {
        for ei in 0..self.extent_count as usize {
            let ext = unsafe { &*self.extents.add(ei) };
            for ri in 0..ext.reservation_count as usize {
                let r = &ext.reservations[ri];
                if r.dest_pa == 0 { continue; } // tracking-only reservation
                for slot in 0..ext.page_count as usize {
                    if r.copied & (1u64 << slot) == 0 {
                        super::phys::free_page(PhysAddr::new(
                            r.dest_pa + slot * PAGE_SIZE,
                        ));
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
    if id == 0 { return None; }
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
            // Lazily-created extent during COW fault: default shared_mask
            // to all-ones (conservative — page must have been shared).
            match guard.create_extent(obj_page_base, page_count, !0u64) {
                Some(i) => i,
                None => return None,
            }
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
        // Allocate a superpage-aligned destination for this member.
        // Drop the lock during the potentially slow allocator path.
        drop(guard);

        let dest_pa = super::fault::alloc_superpage_aligned()?;

        // Re-acquire and re-find (extent index may have shifted).
        guard = unsafe { (*entry_ptr).inner.lock() };
        let ei = match guard.find_extent(obj_page_base) {
            Some(i) => i,
            None => {
                // Extent was removed while unlocked — bail.
                super::fault::free_pages_range(dest_pa, SUPERPAGE_ALLOC_PAGES);
                return None;
            }
        };

        // Check if someone else created/upgraded our reservation while unlocked.
        if let Some(i) = guard.extent(ei).find_reservation(obj_id) {
            if guard.extent(ei).reservations[i].dest_pa != 0 {
                // Someone else allocated a destination — use theirs.
                super::fault::free_pages_range(dest_pa, SUPERPAGE_ALLOC_PAGES);
                let r = &guard.extent(ei).reservations[i];
                let already_copied = r.copied & (1u64 << slot) != 0;
                return Some(ReservationSlot {
                    dest_page_pa: r.dest_pa + slot * PAGE_SIZE,
                    already_copied,
                });
            } else {
                // Upgrade tracking-only reservation with real destination.
                // Slots already marked as "copied" (private allocations) have
                // no corresponding page in the destination — free those dest slots.
                let old_copied = guard.extent(ei).reservations[i].copied;
                guard.extent_mut(ei).reservations[i].dest_pa = dest_pa.as_usize();
                // Free destination pages for already-copied (private) slots.
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
            match guard.extent_mut(ei).add_reservation(obj_id, dest_pa.as_usize()) {
                Some(i) => i,
                None => {
                    super::fault::free_pages_range(dest_pa, SUPERPAGE_ALLOC_PAGES);
                    return None;
                }
            }
        }
    } else {
        guard.extent(ei).find_reservation(obj_id).unwrap()
    };

    let r = &guard.extent(ei).reservations[ri];
    let already_copied = r.copied & (1u64 << slot) != 0;
    let dest_page_pa = r.dest_pa + slot * PAGE_SIZE;

    Some(ReservationSlot { dest_page_pa, already_copied })
}

/// Check whether a page is still shared from `obj_id`'s perspective.
///
/// Returns true if other members in the group still reference the same
/// original PA at this page offset (i.e., they haven't COW-broken it).
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

    let ei = match guard.find_extent(obj_page_base) {
        Some(i) => i,
        None => {
            // No extent yet — no COW breaks in this range.
            // All pages are shared with all other members.
            return true;
        }
    };

    let ext = guard.extent(ei);

    // If this member has already COW-broken this slot, the page is private.
    if ext.is_copied_by(obj_id, slot) {
        return false;
    }

    // This member still references the original PA. Check if any other
    // member also still references it.
    ext.other_sharers(obj_id, slot, guard.member_count) > 0
}

/// Check whether all originally-shared pages in a superpage range have
/// been COW-broken by `obj_id` (reservation is complete). If so, the
/// member's pages in this range are all contiguous in the reservation
/// destination and may be eligible for superpage promotion.
pub fn is_reservation_complete(
    group_id: CowGroupId,
    obj_id: u64,
    obj_page_base: u32,
) -> bool {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p,
        None => return false,
    };
    let guard = unsafe { (*entry_ptr).inner.lock() };

    if guard.member_count <= 1 {
        return true;
    }

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
        if ext.other_sharers(obj_id, slot, guard.member_count) > 0
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

/// Pre-populate extents for all full superpage-aligned ranges, with shared_mask
/// populated from the source object's page presence. Called at fork time.
///
/// `is_page_present(page_idx)` returns true if the source object has a physical
/// page at `page_idx`. These bits become the extent's `shared_mask`, identifying
/// pages that were shared at fork time vs. post-fork private allocations.
///
/// Only creates extents (metadata), not reservations (physical destinations).
/// Reservations are still created lazily on first COW fault per member.
pub fn pre_populate_extents_with_mask(
    group_id: CowGroupId,
    obj_page_count: u16,
    is_page_present: impl Fn(usize) -> bool,
) {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p,
        None => return,
    };
    let mut guard = unsafe { (*entry_ptr).inner.lock() };

    let total = obj_page_count as usize;
    let mut base = 0;
    while base + SUPERPAGE_ALLOC_PAGES <= total {
        if guard.find_extent(base as u32).is_none() {
            // Build shared_mask: bit i set if page (base + i) is allocated.
            let mut mask: u64 = 0;
            for i in 0..SUPERPAGE_ALLOC_PAGES {
                if is_page_present(base + i) {
                    mask |= 1u64 << i;
                }
            }
            if guard.create_extent(base as u32, SUPERPAGE_ALLOC_PAGES as u8, mask).is_none() {
                break; // OOM or extent capacity — stop pre-populating.
            }
        }
        base += SUPERPAGE_ALLOC_PAGES;
    }
}

/// Query whether this group uses per-page frame refcounts for lifetime tracking.
/// Returns true for cascading-fork groups (3+ members), false for first-fork
/// groups (2 members) that use shared_mask + copied bits instead.
pub fn is_refcounted(group_id: CowGroupId) -> bool {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p,
        None => return false,
    };
    let guard = unsafe { (*entry_ptr).inner.lock() };
    guard.refcounted
}

/// Mark a group as refcounted (transitioning from shared_mask-based tracking).
/// Called when a cascading fork adds a 3rd+ member to an existing group.
pub fn set_refcounted(group_id: CowGroupId) {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p,
        None => return,
    };
    let mut guard = unsafe { (*entry_ptr).inner.lock() };
    guard.refcounted = true;
}

/// Mark a page slot as COW-copied and release the original PA if orphaned.
///
/// Called after a COW fault copies a shared page. Sets the `copied` bit for
/// `obj_id` at `slot`, then checks if all members have now COW-broken this
/// page. If so, the original PA is orphaned (no references remain) and is
/// freed.
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

    let ei = match guard.find_extent(obj_page_base) {
        Some(i) => i,
        None => return false,
    };

    // Set copied bit. Create tracking-only reservation if none exists.
    let ri = match guard.extent(ei).find_reservation(obj_id) {
        Some(i) => i,
        None => {
            match guard.extent_mut(ei).add_reservation(obj_id, 0) {
                Some(i) => i,
                None => {
                    // Can't track — conservatively don't free.
                    return false;
                }
            }
        }
    };
    guard.extent_mut(ei).reservations[ri].copied |= 1u64 << slot;

    // Check if the original PA is now orphaned.
    let ext = guard.extent(ei);
    if ext.other_sharers(obj_id, slot, guard.member_count) == 0 {
        // All other members have also COW-broken this slot.
        // The original PA is no longer referenced by anyone.
        drop(guard);
        super::phys::free_page(old_pa);
        return true;
    }

    false
}

/// Mark a page slot as privately allocated (post-fork demand-zero).
///
/// Called when a COW object allocates a new page via ensure_page (not through
/// a COW fault). Sets the `copied` bit so that `other_sharers` correctly
/// excludes this member for this slot — the member doesn't reference the
/// original shared PA.
///
/// Creates a tracking-only reservation (dest_pa=0) if the member has no
/// reservation in this extent yet.
pub fn mark_private(
    group_id: CowGroupId,
    obj_id: u64,
    obj_page_base: u32,
    slot: usize,
) {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p,
        None => return,
    };
    let mut guard = unsafe { (*entry_ptr).inner.lock() };

    let ei = match guard.find_extent(obj_page_base) {
        Some(i) => i,
        None => return,
    };

    let ri = match guard.extent(ei).find_reservation(obj_id) {
        Some(i) => i,
        None => {
            // Create tracking-only reservation (dest_pa=0).
            match guard.extent_mut(ei).add_reservation(obj_id, 0) {
                Some(i) => i,
                None => return,
            }
        }
    };

    guard.extent_mut(ei).reservations[ri].copied |= 1u64 << slot;
}

/// For a member being destroyed, determine which pages in a superpage range
/// should be freed. Returns a bitmask: bit i set = caller should free page i.
///
/// Classification per slot:
/// - shared_mask clear → post-fork private allocation → free
/// - shared_mask set, copied by this member → private COW copy → free
/// - shared_mask set, not copied, other_sharers == 0 → last reference → free
/// - shared_mask set, not copied, other_sharers > 0 → still referenced → keep
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

    let ei = match guard.find_extent(obj_page_base) {
        Some(i) => i,
        None => {
            // No extent → pre-populate didn't cover this range or was never
            // called. All pages in this range are shared originals with no
            // per-page tracking. Conservatively don't free (other members
            // may reference them).
            return 0;
        }
    };
    let ext = guard.extent(ei);

    let mut free_mask: u64 = 0;
    for slot in 0..page_count as usize {
        if ext.shared_mask & (1u64 << slot) == 0 {
            // Page wasn't shared at fork time → private allocation → free.
            free_mask |= 1u64 << slot;
        } else if ext.is_copied_by(obj_id, slot) {
            // Member COW-broke this page → private copy → free.
            free_mask |= 1u64 << slot;
        } else {
            // Member still references the original shared PA.
            if ext.other_sharers(obj_id, slot, guard.member_count) == 0 {
                // Last reference to the original → free.
                free_mask |= 1u64 << slot;
            }
            // else: other members still reference it → keep.
        }
    }

    free_mask
}

/// Release a shared page from a non-refcounted group. Called by release_page
/// when a COW object's page is being unmapped/evicted.
///
/// Determines whether the PA is a private copy (free directly) or a shared
/// original (mark departure, free if orphaned).
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

    let ei = match guard.find_extent(obj_page_base) {
        Some(i) => i,
        None => {
            // No extent → shared original with no tracking. Don't free.
            return false;
        }
    };

    let ext = guard.extent(ei);

    if ext.shared_mask & (1u64 << slot) == 0 {
        // Post-fork private allocation → free directly.
        drop(guard);
        super::phys::free_page(pa);
        return true;
    }

    if ext.is_copied_by(obj_id, slot) {
        // Private COW copy → free directly.
        drop(guard);
        super::phys::free_page(pa);
        return true;
    }

    // Shared original — mark departure and check if orphaned.
    let ri = match guard.extent(ei).find_reservation(obj_id) {
        Some(i) => i,
        None => {
            match guard.extent_mut(ei).add_reservation(obj_id, 0) {
                Some(i) => i,
                None => return false, // Can't track departure — leak to be safe.
            }
        }
    };
    guard.extent_mut(ei).reservations[ri].copied |= 1u64 << slot;

    // Re-read extent after mutation.
    let ext = guard.extent(ei);
    if ext.other_sharers(obj_id, slot, guard.member_count) == 0 {
        drop(guard);
        super::phys::free_page(pa);
        return true;
    }

    false
}
