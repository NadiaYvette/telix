pub mod capability;
pub mod capset;
pub mod cdt;
pub mod cnode;
pub mod space;

pub use capability::{CapType, Capability, Rights};
pub use cdt::Cdt;
pub use space::CapSpace;

use crate::ipc::port::port_local;
use crate::sched::task::Task;
use crate::sync::SpinLock;

/// Narrow lock protecting the global CDT (capability derivation tree).
/// Only held during CDT node allocation/linkage/revocation — much shorter
/// than the old CAP_SYSTEM lock that serialized all cap mutations.
pub static CDT_LOCK: SpinLock<Cdt> = SpinLock::new(Cdt::new());

/// Initialize the CDT. Called once at boot.
pub fn init() {
    CDT_LOCK.lock().init();
}

/// Load a task pointer from TASK_TABLE radix lookup.
#[inline]
fn task_ptr(task_id: u32) -> *mut Task {
    crate::sched::scheduler::TASK_TABLE.get(task_id) as *mut Task
}

/// Get a reference to a task. Caller must ensure task_id is valid.
#[inline]
unsafe fn task_ref(task_id: u32) -> &'static Task {
    unsafe { &*task_ptr(task_id) }
}

/// Get a mutable reference to a task's CapSpace.
/// Caller must hold the task's cap_lock.
#[inline]
fn task_capspace(task_id: u32) -> &'static mut CapSpace {
    let ptr = task_ptr(task_id);
    unsafe { &mut (*ptr).capspace }
}

/// Convert Rights to capset permission bits.
#[inline]
fn rights_to_perms(rights: Rights) -> u8 {
    let mut p: u8 = 0;
    if rights.contains(Rights::SEND) {
        p |= capset::PERM_SEND;
    }
    if rights.contains(Rights::RECV) {
        p |= capset::PERM_RECV;
    }
    if rights.contains(Rights::MANAGE) {
        p |= capset::PERM_MANAGE;
    }
    p
}

/// Fast lockless check: does task have the needed rights for this port?
#[inline]
pub fn has_port_cap_fast(task_id: u32, port_id: u64, needed: Rights) -> bool {
    if task_id == 0 {
        return true;
    }
    let ptr = task_ptr(task_id);
    if ptr.is_null() {
        return false;
    }
    let local = port_local(port_id);
    unsafe { &*ptr }.capset.has(local, rights_to_perms(needed))
}

/// Update capset after granting a port cap.
/// CapSet entries are AtomicU64 — no lock needed for the store,
/// but caller should hold the task's cap_lock for consistency.
fn capset_grant(task_id: u32, port_id: u64, rights: Rights) {
    let ptr = task_ptr(task_id);
    let local = port_local(port_id);
    unsafe { &*ptr }
        .capset
        .grant(local, rights_to_perms(rights));
    // Maintain recv_holder on the port.
    if rights.contains(Rights::RECV) {
        crate::ipc::port::set_recv_holder(port_id, task_id);
    }
}

/// Clear capset entry for a port.
fn capset_remove_port(task_id: u32, port_id: u64) {
    let ptr = task_ptr(task_id);
    let local = port_local(port_id);
    unsafe { &*ptr }.capset.remove(local);
    // Clear recv_holder if this task was the holder.
    if crate::ipc::port::get_recv_holder(port_id) == task_id {
        crate::ipc::port::set_recv_holder(port_id, u32::MAX);
    }
}

/// Reset all capset entries for a task (on task reset).
#[allow(dead_code)]
pub fn capset_reset(task_id: u32) {
    let ptr = task_ptr(task_id);
    if !ptr.is_null() {
        unsafe { &*ptr }.capset.reset();
    }
}

/// Copy capset from parent to child (for fork).
/// CapSet is AtomicU64 entries — safe without lock if child isn't running yet.
pub fn capset_copy(parent_task: u32, child_task: u32) {
    let parent_ptr = task_ptr(parent_task);
    let child_ptr = task_ptr(child_task);
    unsafe { &*child_ptr }
        .capset
        .copy_from(&unsafe { &*parent_ptr }.capset);
}

// ---------------------------------------------------------------------------
// Per-task locking helpers
// ---------------------------------------------------------------------------

/// Lock a task's cap_lock. Returns the guard.
#[inline]
fn lock_task_caps(task_id: u32) -> crate::sync::spinlock::SpinLockGuard<'static, ()> {
    unsafe { task_ref(task_id) }.cap_lock.lock()
}

// ---------------------------------------------------------------------------
// Public cap operations — handle locking internally
// ---------------------------------------------------------------------------

/// Grant a SEND cap for a port to a task. Returns slot index or None.
pub fn grant_send_cap(task_id: u32, port_id: u64) -> Option<usize> {
    let _task_guard = lock_task_caps(task_id);
    let space = task_capspace(task_id);
    if space
        .find_port_cap(port_id as usize, Rights::SEND)
        .is_some()
    {
        return Some(0);
    }
    let cap = Capability::new(CapType::Port, Rights::SEND, port_id as usize);
    let result = {
        let mut cdt = CDT_LOCK.lock();
        space.insert(cap, &mut *cdt)
    };
    if result.is_some() {
        capset_grant(task_id, port_id, Rights::SEND);
    }
    result
}

/// Grant a full (SEND|RECV|MANAGE) cap for a port to a task.
pub fn grant_full_port_cap(task_id: u32, port_id: u64) -> Option<usize> {
    let rights = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
    let _task_guard = lock_task_caps(task_id);
    let cap = Capability::new(CapType::Port, rights, port_id as usize);
    let result = {
        let mut cdt = CDT_LOCK.lock();
        task_capspace(task_id).insert(cap, &mut *cdt)
    };
    if result.is_some() {
        capset_grant(task_id, port_id, rights);
    }
    result
}

/// Grant a port cap with arbitrary rights to a task.
pub fn grant_port_cap(task_id: u32, port_id: u64, rights: Rights) -> Option<usize> {
    let _task_guard = lock_task_caps(task_id);
    let space = task_capspace(task_id);
    if space.find_port_cap(port_id as usize, rights).is_some() {
        return Some(0);
    }
    let cap = Capability::new(CapType::Port, rights, port_id as usize);
    let result = {
        let mut cdt = CDT_LOCK.lock();
        space.insert(cap, &mut *cdt)
    };
    if result.is_some() {
        capset_grant(task_id, port_id, rights);
    }
    result
}

/// Remove all caps for a port from a task, and clear capset.
pub fn remove_port_caps(task_id: u32, port_id: u64) {
    let _task_guard = lock_task_caps(task_id);
    task_capspace(task_id).remove_port_caps(port_id as usize);
    capset_remove_port(task_id, port_id);
}

/// Revoke all derived capabilities from a cap slot.
/// Returns the count of revoked capabilities.
pub fn revoke_slot(task_id: u32, slot: usize) -> usize {
    let _task_guard = lock_task_caps(task_id);
    let space = task_capspace(task_id);
    let mut cdt = CDT_LOCK.lock();
    space.revoke(slot, &mut *cdt)
}

/// Find the first task (other than `exclude_task`) that has RECV cap for `port_id`.
/// Uses the port's recv_holder field for O(1) lookup.
pub fn find_recv_task(port_id: u64, exclude_task: u32) -> Option<u32> {
    let holder = crate::ipc::port::get_recv_holder(port_id);
    if holder != u32::MAX && holder != exclude_task {
        Some(holder)
    } else {
        None
    }
}
