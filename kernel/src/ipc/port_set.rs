//! Port set: multiplexed wait across multiple ports.
//!
//! A port set allows a server to wait for messages on any of several ports.

use super::message::Message;
use super::port::{self, PortId};

pub type PortSetId = u32;

/// Maximum ports in a single port set.
const MAX_SET_PORTS: usize = 16;

/// A set of ports that can be waited on together.
pub struct PortSet {
    pub id: PortSetId,
    pub active: bool,
    ports: [PortId; MAX_SET_PORTS],
    count: usize,
}

impl PortSet {
    pub const fn new(id: PortSetId) -> Self {
        Self {
            id,
            active: true,
            ports: [0; MAX_SET_PORTS],
            count: 0,
        }
    }

    /// Add a port to this set.
    pub fn add(&mut self, port_id: PortId) -> bool {
        if self.count < MAX_SET_PORTS {
            self.ports[self.count] = port_id;
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
            let pid = self.ports[i];
            if let Ok(msg) = port::recv_nb(pid) {
                return Some((pid, msg));
            }
        }
        None
    }
}

/// Maximum number of port sets.
pub const MAX_PORT_SETS: usize = 16;

use crate::sync::SpinLock;

struct PortSetTable {
    sets: [PortSet; MAX_PORT_SETS],
    next_id: PortSetId,
}

impl PortSetTable {
    const fn new() -> Self {
        Self {
            sets: [const { PortSet::new(0) }; MAX_PORT_SETS],
            next_id: 0,
        }
    }
}

static PORT_SET_TABLE: SpinLock<PortSetTable> = SpinLock::new(PortSetTable::new());

/// Create a new port set.
pub fn create() -> Option<PortSetId> {
    let mut table = PORT_SET_TABLE.lock();
    let id = table.next_id;
    if id as usize >= MAX_PORT_SETS {
        return None;
    }
    table.sets[id as usize] = PortSet::new(id);
    table.next_id += 1;
    Some(id)
}

/// Add a port to a port set.
pub fn add_port(set_id: PortSetId, port_id: PortId) -> bool {
    let mut table = PORT_SET_TABLE.lock();
    if (set_id as usize) < MAX_PORT_SETS {
        table.sets[set_id as usize].add(port_id)
    } else {
        false
    }
}

/// Try to receive from any port in a set (non-blocking).
pub fn recv(set_id: PortSetId) -> Option<(PortId, Message)> {
    let table = PORT_SET_TABLE.lock();
    if (set_id as usize) < MAX_PORT_SETS {
        table.sets[set_id as usize].try_recv()
    } else {
        None
    }
}
