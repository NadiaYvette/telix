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
use crate::sched::task::TASK_SLOTS;
use crate::ipc::port::port_local;

/// Per-task sparse capability sets for fast lockless cap checks.
/// Updated under CAP_SYSTEM lock, read locklessly via AtomicU64.
pub static CAPSETS: [CapSet; TASK_SLOTS] = [const { CapSet::new() }; TASK_SLOTS];

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
    let local = port_local(port_id);
    CAPSETS[task_id as usize].has(local, rights_to_perms(needed))
}

/// Update capset after granting a port cap. Call under CAP_SYSTEM lock.
fn capset_grant(task_id: u32, port_id: u64, rights: Rights) {
    let local = port_local(port_id);
    CAPSETS[task_id as usize].grant(local, rights_to_perms(rights));
    // Maintain recv_holder on the port.
    if rights.contains(Rights::RECV) {
        crate::ipc::port::set_recv_holder(port_id, task_id);
    }
}

/// Clear capset entry for a port. Call under CAP_SYSTEM lock.
fn capset_remove_port(task_id: u32, port_id: u64) {
    let local = port_local(port_id);
    CAPSETS[task_id as usize].remove(local);
    // Clear recv_holder if this task was the holder.
    if crate::ipc::port::get_recv_holder(port_id) == task_id {
        crate::ipc::port::set_recv_holder(port_id, u32::MAX);
    }
}

/// Reset all capset entries for a task (on task reset).
pub fn capset_reset(task_id: u32) {
    CAPSETS[task_id as usize].reset();
}

/// Copy capset from parent to child (for fork). Call under CAP_SYSTEM lock.
pub fn capset_copy(parent_task: u32, child_task: u32) {
    CAPSETS[child_task as usize].copy_from(&CAPSETS[parent_task as usize]);
}

/// Global capability system: per-task CapSpaces + the CDT.
pub struct CapSystem {
    pub cdt: Cdt,
    pub spaces: [CapSpace; TASK_SLOTS],
}

impl CapSystem {
    pub const fn new() -> Self {
        Self {
            cdt: Cdt::new(),
            spaces: [const { CapSpace::new(0) }; TASK_SLOTS],
        }
    }

    /// Initialize the CDT free list and reset all CapSpaces.
    pub fn init(&mut self) {
        self.cdt.init();
        for i in 0..TASK_SLOTS {
            self.spaces[i] = CapSpace::new(i as u32);
            capset_reset(i as u32);
        }
    }

    /// Grant a SEND cap for a port to a task. Returns slot index or None.
    pub fn grant_send_cap(&mut self, task_id: u32, port_id: u64) -> Option<usize> {
        if self.spaces[task_id as usize].find_port_cap(port_id as usize, Rights::SEND).is_some() {
            return Some(0);
        }
        let cap = Capability::new(CapType::Port, Rights::SEND, port_id as usize);
        let result = self.spaces[task_id as usize].insert(cap, &mut self.cdt);
        if result.is_some() {
            capset_grant(task_id, port_id, Rights::SEND);
        }
        result
    }

    /// Grant a full (SEND|RECV|MANAGE) cap for a port to a task.
    pub fn grant_full_port_cap(&mut self, task_id: u32, port_id: u64) -> Option<usize> {
        let rights = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        let cap = Capability::new(CapType::Port, rights, port_id as usize);
        let result = self.spaces[task_id as usize].insert(cap, &mut self.cdt);
        if result.is_some() {
            capset_grant(task_id, port_id, rights);
        }
        result
    }

    /// Grant a port cap with arbitrary rights to a task.
    pub fn grant_port_cap(&mut self, task_id: u32, port_id: u64, rights: Rights) -> Option<usize> {
        if self.spaces[task_id as usize].find_port_cap(port_id as usize, rights).is_some() {
            return Some(0);
        }
        let cap = Capability::new(CapType::Port, rights, port_id as usize);
        let result = self.spaces[task_id as usize].insert(cap, &mut self.cdt);
        if result.is_some() {
            capset_grant(task_id, port_id, rights);
        }
        result
    }

    /// Remove all caps for a port from a task, and clear capset.
    pub fn remove_port_caps(&mut self, task_id: u32, port_id: u64) {
        self.spaces[task_id as usize].remove_port_caps(port_id as usize);
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
