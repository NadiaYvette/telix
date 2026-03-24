pub mod capability;
pub mod cnode;
pub mod cdt;
pub mod space;

pub use capability::{Capability, CapType, Rights};
pub use cdt::Cdt;
pub use space::CapSpace;

use crate::sync::SpinLock;
use crate::sched::task::MAX_TASKS;
use crate::ipc::port::MAX_PORTS;
use core::sync::atomic::{AtomicU64, Ordering};

/// Number of u64 words needed to cover MAX_PORTS bits.
const BITMAP_WORDS: usize = (MAX_PORTS + 63) / 64;

/// Per-task lockless bitmaps for fast cap checks.
/// Bit i is set if the task holds the corresponding right for port i.
/// These are updated under CAP_SYSTEM lock but read locklessly.
pub static CAP_SEND: [[AtomicU64; BITMAP_WORDS]; MAX_TASKS] = {
    const WORD: AtomicU64 = AtomicU64::new(0);
    const ROW: [AtomicU64; BITMAP_WORDS] = [WORD; BITMAP_WORDS];
    [ROW; MAX_TASKS]
};
pub static CAP_RECV: [[AtomicU64; BITMAP_WORDS]; MAX_TASKS] = {
    const WORD: AtomicU64 = AtomicU64::new(0);
    const ROW: [AtomicU64; BITMAP_WORDS] = [WORD; BITMAP_WORDS];
    [ROW; MAX_TASKS]
};

/// Fast lockless check: does task have SEND/RECV cap for this port?
#[inline]
pub fn has_port_cap_fast(task_id: u32, port_id: u32, needed: Rights) -> bool {
    if task_id == 0 { return true; }
    let pid = port_id as usize;
    if pid >= MAX_PORTS { return false; }
    let word = pid / 64;
    let bit = pid % 64;
    let mask = 1u64 << bit;
    if needed.contains(Rights::SEND) && (CAP_SEND[task_id as usize][word].load(Ordering::Relaxed) & mask) == 0 {
        return false;
    }
    if needed.contains(Rights::RECV) && (CAP_RECV[task_id as usize][word].load(Ordering::Relaxed) & mask) == 0 {
        return false;
    }
    true
}

/// Update bitmaps after granting a port cap. Call under CAP_SYSTEM lock.
fn bitmap_grant(task_id: u32, port_id: u32, rights: Rights) {
    let pid = port_id as usize;
    if pid >= MAX_PORTS { return; }
    let word = pid / 64;
    let mask = 1u64 << (pid % 64);
    if rights.contains(Rights::SEND) {
        CAP_SEND[task_id as usize][word].fetch_or(mask, Ordering::Relaxed);
    }
    if rights.contains(Rights::RECV) {
        CAP_RECV[task_id as usize][word].fetch_or(mask, Ordering::Relaxed);
    }
}

/// Clear bitmap bits for a port. Call under CAP_SYSTEM lock after removing caps.
fn bitmap_remove_port(task_id: u32, port_id: u32) {
    let pid = port_id as usize;
    if pid >= MAX_PORTS { return; }
    let word = pid / 64;
    let mask = !(1u64 << (pid % 64));
    CAP_SEND[task_id as usize][word].fetch_and(mask, Ordering::Relaxed);
    CAP_RECV[task_id as usize][word].fetch_and(mask, Ordering::Relaxed);
}

/// Reset all bitmap bits for a task (on task reset).
pub fn bitmap_reset(task_id: u32) {
    for w in 0..BITMAP_WORDS {
        CAP_SEND[task_id as usize][w].store(0, Ordering::Relaxed);
        CAP_RECV[task_id as usize][w].store(0, Ordering::Relaxed);
    }
}

/// Global capability system: per-task CapSpaces + the CDT.
pub struct CapSystem {
    pub cdt: Cdt,
    pub spaces: [CapSpace; MAX_TASKS],
}

impl CapSystem {
    pub const fn new() -> Self {
        Self {
            cdt: Cdt::new(),
            spaces: [const { CapSpace::new(0) }; MAX_TASKS],
        }
    }

    /// Initialize the CDT free list and reset all CapSpaces.
    pub fn init(&mut self) {
        self.cdt.init();
        for i in 0..MAX_TASKS {
            self.spaces[i] = CapSpace::new(i as u32);
            bitmap_reset(i as u32);
        }
    }

    /// Grant a SEND cap for a port to a task. Returns slot index or None.
    pub fn grant_send_cap(&mut self, task_id: u32, port_id: u32) -> Option<usize> {
        // Don't grant if the task already has a SEND cap for this port.
        if self.spaces[task_id as usize].find_port_cap(port_id as usize, Rights::SEND).is_some() {
            return Some(0); // Already have it.
        }
        let cap = Capability::new(CapType::Port, Rights::SEND, port_id as usize);
        let result = self.spaces[task_id as usize].insert(cap, &mut self.cdt);
        if result.is_some() {
            bitmap_grant(task_id, port_id, Rights::SEND);
        }
        result
    }

    /// Grant a full (SEND|RECV|MANAGE) cap for a port to a task.
    pub fn grant_full_port_cap(&mut self, task_id: u32, port_id: u32) -> Option<usize> {
        let rights = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        let cap = Capability::new(CapType::Port, rights, port_id as usize);
        let result = self.spaces[task_id as usize].insert(cap, &mut self.cdt);
        if result.is_some() {
            bitmap_grant(task_id, port_id, rights);
        }
        result
    }

    /// Grant a port cap with arbitrary rights to a task.
    pub fn grant_port_cap(&mut self, task_id: u32, port_id: u32, rights: Rights) -> Option<usize> {
        // Skip if already has a cap with these rights.
        if self.spaces[task_id as usize].find_port_cap(port_id as usize, rights).is_some() {
            return Some(0);
        }
        let cap = Capability::new(CapType::Port, rights, port_id as usize);
        let result = self.spaces[task_id as usize].insert(cap, &mut self.cdt);
        if result.is_some() {
            bitmap_grant(task_id, port_id, rights);
        }
        result
    }

    /// Remove all caps for a port from a task, and clear bitmaps.
    pub fn remove_port_caps(&mut self, task_id: u32, port_id: u32) {
        self.spaces[task_id as usize].remove_port_caps(port_id as usize);
        bitmap_remove_port(task_id, port_id);
    }
}

/// Find the first task (other than `exclude_task`) that has RECV cap for `port_id`.
pub fn find_recv_task(port_id: u32, exclude_task: u32) -> Option<u32> {
    let pid = port_id as usize;
    if pid >= MAX_PORTS { return None; }
    let word = pid / 64;
    let mask = 1u64 << (pid % 64);
    for task_id in 0..MAX_TASKS as u32 {
        if task_id == exclude_task { continue; }
        if CAP_RECV[task_id as usize][word].load(Ordering::Relaxed) & mask != 0 {
            return Some(task_id);
        }
    }
    None
}

pub static CAP_SYSTEM: SpinLock<CapSystem> = SpinLock::new(CapSystem::new());
