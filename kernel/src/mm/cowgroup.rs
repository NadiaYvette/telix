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

use super::page::PhysAddr;
use crate::ipc::port::{self, PortId};
use crate::mm::slab;
use crate::sync::SpinLock;

/// Slab size for GroupEntry allocations (must be power of two ≥ actual size).
const GROUP_SLAB_SIZE: usize = 256;

/// Maximum inline members before we'd need overflow.
/// Covers parent + up to 7 children — sufficient for nearly all fork trees.
const MAX_MEMBERS: usize = 8;

/// COW group ID type — a kernel-held port ID (u64).
pub type CowGroupId = u64;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Per-group state, protected by a SpinLock inside GroupEntry.
struct CowGroup {
    /// Member object IDs (port_ids of MemObjects in this group).
    members: [u64; MAX_MEMBERS],
    /// Number of active members.
    member_count: u8,
    // Reservation extents will be added in Phase 4.
}

impl CowGroup {
    const fn new() -> Self {
        Self {
            members: [0; MAX_MEMBERS],
            member_count: 0,
        }
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

    /// Remove a member. Returns the new member count.
    fn remove_member(&mut self, obj_id: u64) -> u8 {
        for i in 0..self.member_count as usize {
            if self.members[i] == obj_id {
                // Swap with last to avoid shifting.
                let last = self.member_count as usize - 1;
                self.members[i] = self.members[last];
                self.members[last] = 0;
                self.member_count -= 1;
                return self.member_count;
            }
        }
        self.member_count
    }

    /// Check if an object is a member.
    #[allow(dead_code)]
    fn has_member(&self, obj_id: u64) -> bool {
        for i in 0..self.member_count as usize {
            if self.members[i] == obj_id {
                return true;
            }
        }
        false
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
// Public API
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
/// If this was the last member, the group is destroyed.
pub fn remove_member(group_id: CowGroupId, obj_id: u64) {
    let entry_ptr = match resolve_entry(group_id) {
        Some(p) => p as *mut GroupEntry,
        None => return,
    };

    let remaining = {
        let mut guard = unsafe { (*entry_ptr).inner.lock() };
        // Phase 4: free unclaimed reservation pages for this member here.
        guard.remove_member(obj_id)
    };

    if remaining == 0 {
        // Last member left — destroy the group.
        destroy(group_id);
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
        let _guard = unsafe { (*entry_ptr).inner.lock() };
        // Phase 4: free all unclaimed reservation pages here.
    }

    // Destroy the kernel port and defer-free the entry.
    port::destroy(group_id);
    crate::sync::rcu::rcu_defer_free(entry_ptr as usize, rcu_free_group_callback);
}

/// Access a COW group by ID within a closure, under per-group lock.
/// Returns None if the group doesn't exist.
#[allow(dead_code)]
pub fn with_group<F, R>(group_id: CowGroupId, f: F) -> Option<R>
where
    F: FnOnce(&mut CowGroup) -> R,
{
    let entry_ptr = resolve_entry(group_id)?;
    let mut guard = unsafe { (*entry_ptr).inner.lock() };
    Some(f(&mut *guard))
}
