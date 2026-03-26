pub mod capability;
pub mod capset;
pub mod cnode;
pub mod cdt;
pub mod space;

pub use capability::{Capability, CapType, Rights};
pub use capset::CapSet;
pub use cdt::Cdt;
pub use space::CapSpace;

use crate::sync::SpinLock;
use crate::ipc::port::port_local;
use crate::sched::task::Task;
use core::sync::atomic::Ordering;

/// Load a task pointer from TASK_TABLE radix lookup.
#[inline]
fn task_ptr(task_id: u32) -> *mut Task {
    crate::sched::scheduler::TASK_TABLE.get(task_id) as *mut Task
}

/// Get a mutable reference to a task's CapSpace. Caller must hold CAP_SYSTEM lock.
#[inline]
fn task_capspace(task_id: u32) -> &'static mut CapSpace {
    let ptr = task_ptr(task_id);
    unsafe { &mut (*ptr).capspace }
}

/// Convert Rights to capset permission bits.
#[inline]
fn rights_to_perms(rights: Rights) -> u8 {
    let mut p: u8 = 0;
    if rights.contains(Rights::SEND) { p |= capset::PERM_SEND; }
    if rights.contains(Rights::RECV) { p |= capset::PERM_RECV; }
    if rights.contains(Rights::MANAGE) { p |= capset::PERM_MANAGE; }
    p
}

/// Fast lockless check: does task have the needed rights for this port?
#[inline]
pub fn has_port_cap_fast(task_id: u32, port_id: u64, needed: Rights) -> bool {
    if task_id == 0 { return true; }
    let ptr = task_ptr(task_id);
    if ptr.is_null() { return false; }
    let local = port_local(port_id);
    unsafe { &*ptr }.capset.has(local, rights_to_perms(needed))
}

/// Update capset after granting a port cap. Call under CAP_SYSTEM lock.
fn capset_grant(task_id: u32, port_id: u64, rights: Rights) {
    let ptr = task_ptr(task_id);
    let local = port_local(port_id);
    unsafe { &*ptr }.capset.grant(local, rights_to_perms(rights));
    // Maintain recv_holder on the port.
    if rights.contains(Rights::RECV) {
        crate::ipc::port::set_recv_holder(port_id, task_id);
    }
}

/// Clear capset entry for a port. Call under CAP_SYSTEM lock.
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
pub fn capset_reset(task_id: u32) {
    let ptr = task_ptr(task_id);
    if !ptr.is_null() {
        unsafe { &*ptr }.capset.reset();
    }
}

/// Copy capset from parent to child (for fork). Call under CAP_SYSTEM lock.
pub fn capset_copy(parent_task: u32, child_task: u32) {
    let parent_ptr = task_ptr(parent_task);
    let child_ptr = task_ptr(child_task);
    unsafe { &*child_ptr }.capset.copy_from(&unsafe { &*parent_ptr }.capset);
}

/// Global capability system: the CDT (capability derivation tree).
/// Per-task CapSpaces are now embedded in Task structs, accessed via TASK_TABLE.
pub struct CapSystem {
    pub cdt: Cdt,
}

impl CapSystem {
    pub const fn new() -> Self {
        Self {
            cdt: Cdt::new(),
        }
    }

    /// Initialize the CDT free list.
    pub fn init(&mut self) {
        self.cdt.init();
    }

    /// Grant a SEND cap for a port to a task. Returns slot index or None.
    pub fn grant_send_cap(&mut self, task_id: u32, port_id: u64) -> Option<usize> {
        let space = task_capspace(task_id);
        if space.find_port_cap(port_id as usize, Rights::SEND).is_some() {
            return Some(0);
        }
        let cap = Capability::new(CapType::Port, Rights::SEND, port_id as usize);
        let result = space.insert(cap, &mut self.cdt);
        if result.is_some() {
            capset_grant(task_id, port_id, Rights::SEND);
        }
        result
    }

    /// Grant a full (SEND|RECV|MANAGE) cap for a port to a task.
    pub fn grant_full_port_cap(&mut self, task_id: u32, port_id: u64) -> Option<usize> {
        let rights = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        let cap = Capability::new(CapType::Port, rights, port_id as usize);
        let result = task_capspace(task_id).insert(cap, &mut self.cdt);
        if result.is_some() {
            capset_grant(task_id, port_id, rights);
        }
        result
    }

    /// Grant a port cap with arbitrary rights to a task.
    pub fn grant_port_cap(&mut self, task_id: u32, port_id: u64, rights: Rights) -> Option<usize> {
        let space = task_capspace(task_id);
        if space.find_port_cap(port_id as usize, rights).is_some() {
            return Some(0);
        }
        let cap = Capability::new(CapType::Port, rights, port_id as usize);
        let result = space.insert(cap, &mut self.cdt);
        if result.is_some() {
            capset_grant(task_id, port_id, rights);
        }
        result
    }

    /// Remove all caps for a port from a task, and clear capset.
    pub fn remove_port_caps(&mut self, task_id: u32, port_id: u64) {
        task_capspace(task_id).remove_port_caps(port_id as usize);
        capset_remove_port(task_id, port_id);
    }
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

pub static CAP_SYSTEM: SpinLock<CapSystem> = SpinLock::new(CapSystem::new());
