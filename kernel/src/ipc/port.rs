//! Port: a kernel-managed message queue.
//!
//! A port can receive messages from any holder of a send capability.
//! Messages are queued in a bounded buffer. Senders block if the queue
//! is full; receivers block if the queue is empty.

use super::message::Message;
use crate::sched::thread::ThreadId;

pub type PortId = u32;

/// Maximum messages queued per port.
const PORT_QUEUE_CAPACITY: usize = 16;

/// Maximum threads that can be blocked waiting on a port.
const MAX_WAITERS: usize = 8;

/// A port's message queue.
pub struct Port {
    pub id: PortId,
    pub active: bool,
    /// Circular buffer of queued messages.
    queue: [Message; PORT_QUEUE_CAPACITY],
    head: usize,
    tail: usize,
    len: usize,
    /// Threads blocked waiting to receive.
    recv_waiters: [ThreadId; MAX_WAITERS],
    recv_waiter_count: usize,
    /// Threads blocked waiting to send (queue full).
    send_waiters: [ThreadId; MAX_WAITERS],
    send_waiter_count: usize,
}

impl Port {
    pub const fn new(id: PortId) -> Self {
        Self {
            id,
            active: true,
            queue: [Message::empty(); PORT_QUEUE_CAPACITY],
            head: 0,
            tail: 0,
            len: 0,
            recv_waiters: [0; MAX_WAITERS],
            recv_waiter_count: 0,
            send_waiters: [0; MAX_WAITERS],
            send_waiter_count: 0,
        }
    }

    /// Try to enqueue a message. Returns Ok(Option<ThreadId>) where the
    /// Option is a receiver to wake up, or Err(msg) if the queue is full.
    pub fn try_send(&mut self, msg: Message) -> Result<Option<ThreadId>, Message> {
        if self.len >= PORT_QUEUE_CAPACITY {
            return Err(msg); // Queue full.
        }

        self.queue[self.tail] = msg;
        self.tail = (self.tail + 1) % PORT_QUEUE_CAPACITY;
        self.len += 1;

        // Wake up a blocked receiver if any.
        let wakeup = if self.recv_waiter_count > 0 {
            self.recv_waiter_count -= 1;
            Some(self.recv_waiters[self.recv_waiter_count])
        } else {
            None
        };

        Ok(wakeup)
    }

    /// Try to dequeue a message. Returns Ok(msg, Option<ThreadId>) where
    /// the Option is a sender to wake up, or Err(()) if the queue is empty.
    pub fn try_recv(&mut self) -> Result<(Message, Option<ThreadId>), ()> {
        if self.len == 0 {
            return Err(()); // Queue empty.
        }

        let msg = self.queue[self.head];
        self.head = (self.head + 1) % PORT_QUEUE_CAPACITY;
        self.len -= 1;

        // Wake up a blocked sender if any.
        let wakeup = if self.send_waiter_count > 0 {
            self.send_waiter_count -= 1;
            Some(self.send_waiters[self.send_waiter_count])
        } else {
            None
        };

        Ok((msg, wakeup))
    }

    /// Add a thread to the receive wait list.
    pub fn add_recv_waiter(&mut self, tid: ThreadId) -> bool {
        if self.recv_waiter_count < MAX_WAITERS {
            self.recv_waiters[self.recv_waiter_count] = tid;
            self.recv_waiter_count += 1;
            true
        } else {
            false
        }
    }

    /// Add a thread to the send wait list.
    pub fn add_send_waiter(&mut self, tid: ThreadId) -> bool {
        if self.send_waiter_count < MAX_WAITERS {
            self.send_waiters[self.send_waiter_count] = tid;
            self.send_waiter_count += 1;
            true
        } else {
            false
        }
    }

    /// Number of queued messages.
    #[allow(dead_code)]
    pub fn queued(&self) -> usize {
        self.len
    }
}

/// Maximum number of ports in the system.
pub const MAX_PORTS: usize = 64;

/// Global port table.
use crate::sync::SpinLock;

struct PortTable {
    ports: [Port; MAX_PORTS],
    next_id: PortId,
}

impl PortTable {
    const fn new() -> Self {
        Self {
            ports: [const { Port::new(0) }; MAX_PORTS],
            next_id: 0,
        }
    }
}

static PORT_TABLE: SpinLock<PortTable> = SpinLock::new(PortTable::new());

/// Create a new port. Returns its ID.
pub fn create() -> Option<PortId> {
    let mut table = PORT_TABLE.lock();
    let id = table.next_id;
    if id as usize >= MAX_PORTS {
        return None;
    }
    table.ports[id as usize] = Port::new(id);
    table.next_id += 1;
    Some(id)
}

/// Send a message to a port (non-blocking).
/// Returns Ok(()) on success, Err(msg) if the queue is full.
pub fn send(port_id: PortId, msg: Message) -> Result<(), Message> {
    let mut table = PORT_TABLE.lock();
    let port = &mut table.ports[port_id as usize];
    if !port.active {
        return Err(msg);
    }
    match port.try_send(msg) {
        Ok(_wakeup) => {
            // TODO: wake up blocked receiver thread via scheduler.
            Ok(())
        }
        Err(msg) => Err(msg),
    }
}

/// Receive a message from a port (non-blocking).
/// Returns Ok(msg) on success, Err(()) if empty.
pub fn recv(port_id: PortId) -> Result<Message, ()> {
    let mut table = PORT_TABLE.lock();
    let port = &mut table.ports[port_id as usize];
    if !port.active {
        return Err(());
    }
    match port.try_recv() {
        Ok((msg, _wakeup)) => {
            // TODO: wake up blocked sender thread.
            Ok(msg)
        }
        Err(()) => Err(()),
    }
}

/// Destroy a port.
#[allow(dead_code)]
pub fn destroy(port_id: PortId) {
    let mut table = PORT_TABLE.lock();
    if (port_id as usize) < MAX_PORTS {
        table.ports[port_id as usize].active = false;
    }
}
