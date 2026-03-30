//! Port set: multiplexed wait across multiple ports.
//!
//! A port set allows a server to wait for messages on any of several ports.
//! Both the set table and per-set port lists grow dynamically — no compile-time caps.

use super::message::Message;
use super::port::{self, PortId};
use crate::mm::page;
use crate::mm::paged_array::PagedArray;
use crate::mm::phys;
use crate::sched::thread::ThreadId;

pub type PortSetId = u32;

/// Ports per page in a port set's port list.
fn ports_per_page() -> usize {
    page::page_size() / core::mem::size_of::<PortId>()
}

/// A set of ports that can be waited on together.
pub struct PortSet {
    #[allow(dead_code)]
    pub id: PortSetId,
    pub active: bool,
    /// Page-allocated port list (lazily allocated on first add).
    ports: *mut PortId,
    ports_cap: usize,
    count: usize,
    /// Thread blocked in recv_blocking (if any).
    waiter: Option<ThreadId>,
}

// Safety: ports pointer is accessed only under PORT_SET_TABLE lock.
unsafe impl Send for PortSet {}

impl PortSet {
    pub const fn new(id: PortSetId) -> Self {
        Self {
            id,
            active: true,
            ports: core::ptr::null_mut(),
            ports_cap: 0,
            count: 0,
            waiter: None,
        }
    }

    /// Ensure the port list backing page is allocated.
    fn ensure_ports(&mut self) -> bool {
        if !self.ports.is_null() {
            return true;
        }
        let page = match phys::alloc_page() {
            Some(pa) => pa.as_usize() as *mut PortId,
            None => return false,
        };
        unsafe {
            core::ptr::write_bytes(page as *mut u8, 0, page::page_size());
        }
        self.ports = page;
        self.ports_cap = ports_per_page();
        true
    }

    /// Add a port to this set.
    pub fn add(&mut self, port_id: PortId) -> bool {
        if !self.ensure_ports() {
            return false;
        }
        if self.count < self.ports_cap {
            unsafe {
                *self.ports.add(self.count) = port_id;
            }
            self.count += 1;
            true
        } else {
            false
        }
    }

    /// Try to receive a message from any port in the set (non-blocking).
    /// Returns (port_id, message) on success.
    pub fn try_recv(&self) -> Option<(PortId, Message)> {
        for i in 0..self.count {
            let pid = unsafe { *self.ports.add(i) };
            if let Ok(msg) = port::recv_nb(pid) {
                return Some((pid, msg));
            }
        }
        None
    }
}

use crate::sync::SpinLock;

struct PortSetTable {
    sets: PagedArray<PortSet>,
    next_id: PortSetId,
}

impl PortSetTable {
    const fn new() -> Self {
        Self {
            sets: PagedArray::new(),
            next_id: 0,
        }
    }
}

static PORT_SET_TABLE: SpinLock<PortSetTable> = SpinLock::new(PortSetTable::new());

/// Create a new port set.
pub fn create() -> Option<PortSetId> {
    let mut table = PORT_SET_TABLE.lock();
    let id = table.next_id;
    if !table.sets.ensure_capacity(id as usize + 1) {
        return None;
    }
    *table.sets.get_mut(id as usize) = PortSet::new(id);
    table.next_id += 1;
    Some(id)
}

/// Add a port to a port set. Also tags the port with its set membership.
pub fn add_port(set_id: PortSetId, port_id: PortId) -> bool {
    let ok = {
        let mut table = PORT_SET_TABLE.lock();
        if (set_id as usize) < table.next_id as usize {
            table.sets.get_mut(set_id as usize).add(port_id)
        } else {
            false
        }
    };
    if ok {
        port::set_port_set(port_id, set_id);
    }
    ok
}

/// Try to receive from any port in a set (non-blocking).
#[allow(dead_code)]
pub fn recv(set_id: PortSetId) -> Option<(PortId, Message)> {
    let table = PORT_SET_TABLE.lock();
    if (set_id as usize) < table.next_id as usize {
        table.sets.get(set_id as usize).try_recv()
    } else {
        None
    }
}

/// Blocking receive from any port in a set.
/// Blocks the calling thread until a message is available.
pub fn recv_blocking(set_id: PortSetId) -> Option<(PortId, Message)> {
    use crate::sched::thread::BlockReason;
    // Reset priority to base on recv entry (priority inheritance protocol).
    let my_tid = crate::sched::current_thread_id();
    crate::sched::reset_priority(my_tid);
    loop {
        // First try a non-blocking recv (PORT_SET_TABLE lock held briefly).
        {
            let table = PORT_SET_TABLE.lock();
            if (set_id as usize) >= table.next_id as usize
                || !table.sets.get(set_id as usize).active
            {
                return None;
            }
            if let Some((port_id, msg)) = table.sets.get(set_id as usize).try_recv() {
                // Boost to sender's priority (priority inheritance).
                crate::sched::boost_priority(my_tid, msg.data[5] as u8);
                return Some((port_id, msg));
            }
        }

        // No message — register as waiter and block.
        {
            let mut table = PORT_SET_TABLE.lock();
            // Double-check: a message may have arrived between the two locks.
            if let Some((port_id, msg)) = table.sets.get(set_id as usize).try_recv() {
                crate::sched::boost_priority(my_tid, msg.data[5] as u8);
                return Some((port_id, msg));
            }
            let tid = crate::sched::current_thread_id();
            crate::sched::clear_wakeup_flag(tid);
            table.sets.get_mut(set_id as usize).waiter = Some(tid);
        }

        crate::sched::block_current(BlockReason::PortSetRecv(set_id));
        // Woken up — loop back to try_recv.
    }
}

/// Wake the thread blocked on a port set (called from port send path).
pub fn wake_set_waiter(set_id: u32) {
    let waiter = {
        let mut table = PORT_SET_TABLE.lock();
        if (set_id as usize) < table.next_id as usize {
            table.sets.get_mut(set_id as usize).waiter.take()
        } else {
            None
        }
    };
    if let Some(tid) = waiter {
        crate::sched::wake_thread(tid);
    }
}
