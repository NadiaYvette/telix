//! Port: a kernel-managed message endpoint.
//!
//! A port can receive messages from any holder of a send capability.
//! Messages are queued in a bounded buffer. Senders block if the queue
//! is full; receivers block if the queue is empty.
//!
//! Port IDs are structured as `(node:16 | local:16)` to support future
//! network-transparent IPC. For single-node operation, node is always 0
//! and the PortId value equals the local index.

use super::message::Message;
use crate::sched::thread::ThreadId;
use crate::mm::page::PhysAddr;

pub type PortId = u32;

// --- PortId structure: top 16 bits = node, bottom 16 = local index ---

/// Extract the node portion of a PortId (top 16 bits). Currently always 0.
#[inline]
pub const fn port_node(id: PortId) -> u16 {
    (id >> 16) as u16
}

/// Extract the local port index (bottom 16 bits).
#[inline]
pub const fn port_local(id: PortId) -> u16 {
    id as u16
}

/// Construct a PortId from node and local index.
#[inline]
pub const fn make_port_id(node: u16, local: u16) -> PortId {
    ((node as u32) << 16) | (local as u32)
}

// --- Port queue: slab-allocated on demand ---

/// Maximum messages queued per port.
const PORT_QUEUE_CAPACITY: usize = 16;

/// Slab-allocated message queue. Size: 16 * 56 + 24 = 920 bytes → 2048-byte slab.
struct PortQueue {
    msgs: [Message; PORT_QUEUE_CAPACITY],
    head: usize,
    tail: usize,
    len: usize,
}

const PORT_QUEUE_SLAB_SIZE: usize = 2048;

impl PortQueue {
    fn init(ptr: *mut PortQueue) {
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<PortQueue>());
        }
    }

    fn enqueue(&mut self, msg: Message) -> bool {
        if self.len >= PORT_QUEUE_CAPACITY {
            return false;
        }
        self.msgs[self.tail] = msg;
        self.tail = (self.tail + 1) % PORT_QUEUE_CAPACITY;
        self.len += 1;
        true
    }

    fn dequeue(&mut self) -> Option<Message> {
        if self.len == 0 {
            return None;
        }
        let msg = self.msgs[self.head];
        self.head = (self.head + 1) % PORT_QUEUE_CAPACITY;
        self.len -= 1;
        Some(msg)
    }

    fn is_full(&self) -> bool {
        self.len >= PORT_QUEUE_CAPACITY
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Allocate a PortQueue from the slab allocator.
fn alloc_queue() -> Option<*mut PortQueue> {
    let pa = crate::mm::slab::alloc(PORT_QUEUE_SLAB_SIZE)?;
    let ptr = pa.as_usize() as *mut PortQueue;
    PortQueue::init(ptr);
    Some(ptr)
}

/// Free a PortQueue back to the slab allocator.
fn free_queue(ptr: *mut PortQueue) {
    crate::mm::slab::free(PhysAddr::new(ptr as usize), PORT_QUEUE_SLAB_SIZE);
}

// --- Port structure ---

/// Maximum threads that can be blocked waiting on a port.
const MAX_WAITERS: usize = 8;

/// Maximum number of ports in the system.
pub const MAX_PORTS: usize = 256;

/// A port endpoint.
pub struct Port {
    #[allow(dead_code)]
    pub id: PortId,
    pub active: bool,
    /// Pointer to slab-allocated message queue (0 = not yet allocated).
    /// Queue is allocated on first send, so kernel-held ports that handle
    /// faults synchronously never pay for the queue.
    queue_ptr: usize,
    /// Threads blocked waiting to receive.
    recv_waiters: [ThreadId; MAX_WAITERS],
    recv_waiter_count: usize,
    /// Threads blocked waiting to send (queue full).
    send_waiters: [ThreadId; MAX_WAITERS],
    send_waiter_count: usize,
    /// Port set this port belongs to (u32::MAX = none).
    pub port_set_id: u32,
    /// Task that created this port.
    pub creator_task: u32,
}

impl Port {
    pub const fn new(id: PortId) -> Self {
        Self {
            id,
            active: true,
            queue_ptr: 0,
            recv_waiters: [0; MAX_WAITERS],
            recv_waiter_count: 0,
            send_waiters: [0; MAX_WAITERS],
            send_waiter_count: 0,
            port_set_id: u32::MAX,
            creator_task: 0,
        }
    }

    /// Ensure the message queue is allocated. Returns false on OOM.
    fn ensure_queue(&mut self) -> bool {
        if self.queue_ptr != 0 {
            return true;
        }
        match alloc_queue() {
            Some(ptr) => {
                self.queue_ptr = ptr as usize;
                true
            }
            None => false,
        }
    }

    /// Get a reference to the queue, if allocated.
    fn queue(&self) -> Option<&PortQueue> {
        if self.queue_ptr == 0 { None } else { Some(unsafe { &*(self.queue_ptr as *const PortQueue) }) }
    }

    /// Get a mutable reference to the queue, if allocated.
    fn queue_mut(&mut self) -> Option<&mut PortQueue> {
        if self.queue_ptr == 0 { None } else { Some(unsafe { &mut *(self.queue_ptr as *mut PortQueue) }) }
    }

    /// Free the queue if allocated.
    fn free_queue(&mut self) {
        if self.queue_ptr != 0 {
            free_queue(self.queue_ptr as *mut PortQueue);
            self.queue_ptr = 0;
        }
    }

    /// Try to enqueue a message. Returns Ok((direct_wakeup, port_set_id)) where
    /// direct_wakeup is a receiver thread to wake, and port_set_id is the set
    /// to notify if no direct receiver exists. Err(msg) if queue is full or OOM.
    pub fn try_send(&mut self, msg: Message) -> Result<(Option<ThreadId>, u32), Message> {
        if !self.ensure_queue() {
            return Err(msg);
        }
        let q = self.queue_mut().unwrap();
        if !q.enqueue(msg) {
            return Err(msg);
        }

        // Wake up a blocked receiver if any.
        if self.recv_waiter_count > 0 {
            self.recv_waiter_count -= 1;
            Ok((Some(self.recv_waiters[self.recv_waiter_count]), u32::MAX))
        } else {
            // No direct receiver — notify port set if this port belongs to one.
            Ok((None, self.port_set_id))
        }
    }

    /// Try to dequeue a message. Returns Ok(msg, Option<ThreadId>) where
    /// the Option is a sender to wake up, or Err(()) if the queue is empty.
    pub fn try_recv(&mut self) -> Result<(Message, Option<ThreadId>), ()> {
        let q = match self.queue_mut() {
            Some(q) => q,
            None => return Err(()),
        };
        let msg = match q.dequeue() {
            Some(m) => m,
            None => return Err(()),
        };

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
        match self.queue() {
            Some(q) => q.len,
            None => 0,
        }
    }

    /// Whether the queue exists and is full.
    pub fn is_queue_full(&self) -> bool {
        match self.queue() {
            Some(q) => q.is_full(),
            None => false, // No queue yet — not full (first send will allocate)
        }
    }
}

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

/// Create a new port. Returns its ID (node=0, local=index).
pub fn create() -> Option<PortId> {
    let creator = crate::sched::current_task_id();
    let mut table = PORT_TABLE.lock();
    // First try the fast path: allocate from next_id.
    let id = table.next_id;
    if (id as usize) < MAX_PORTS {
        table.ports[id as usize] = Port::new(make_port_id(0, id as u16));
        table.ports[id as usize].creator_task = creator;
        table.next_id += 1;
        return Some(make_port_id(0, id as u16));
    }
    // Slow path: scan for a destroyed (inactive) port to reuse.
    for i in 0..MAX_PORTS {
        if !table.ports[i].active {
            let pid = make_port_id(0, i as u16);
            table.ports[i] = Port::new(pid);
            table.ports[i].creator_task = creator;
            return Some(pid);
        }
    }
    None
}

/// Get the creator task of a port, or None if port is inactive.
pub fn port_creator(port_id: PortId) -> Option<u32> {
    let local = port_local(port_id) as usize;
    let table = PORT_TABLE.lock();
    if local < MAX_PORTS && table.ports[local].active {
        Some(table.ports[local].creator_task)
    } else {
        None
    }
}

/// Send a message to a port (non-blocking).
/// Returns Ok(()) on success, Err(msg) if the queue is full.
pub fn send_nb(port_id: PortId, mut msg: Message) -> Result<(), Message> {
    // Stamp sender priority for priority inheritance.
    let tid = crate::sched::current_thread_id();
    msg.data[5] = crate::sched::thread_effective_priority(tid) as u64;
    let local = port_local(port_id) as usize;
    let mut table = PORT_TABLE.lock();
    if local >= MAX_PORTS {
        return Err(msg);
    }
    let port = &mut table.ports[local];
    if !port.active {
        return Err(msg);
    }
    match port.try_send(msg) {
        Ok((wakeup, set_id)) => {
            if let Some(waiter_tid) = wakeup {
                // Check if the waiter is parked (Blocked from recv_or_park).
                use crate::sched::thread::ThreadState;
                let is_parked = {
                    let sched = crate::sched::scheduler::SCHEDULER.lock();
                    sched.threads[waiter_tid as usize].state == ThreadState::Blocked
                };
                if is_parked {
                    // Dequeue the message we just queued — we'll inject it directly.
                    let dequeued = port.try_recv();
                    drop(table);
                    if let Ok((queued_msg, _)) = dequeued {
                        crate::syscall::handlers::deliver_to_parked_receiver(waiter_tid, &queued_msg);
                    }
                    crate::sched::scheduler::wake_parked_thread(waiter_tid);
                } else {
                    drop(table);
                    crate::sched::wake_thread(waiter_tid);
                }
            } else {
                drop(table);
                if set_id != u32::MAX {
                    super::port_set::wake_set_waiter(set_id);
                }
            }
            Ok(())
        }
        Err(msg) => {
            drop(table);
            Err(msg)
        },
    }
}

/// Receive a message from a port (non-blocking).
/// Returns Ok(msg) on success, Err(()) if empty.
pub fn recv_nb(port_id: PortId) -> Result<Message, ()> {
    let local = port_local(port_id) as usize;
    let mut table = PORT_TABLE.lock();
    if local >= MAX_PORTS {
        return Err(());
    }
    let port = &mut table.ports[local];
    if !port.active {
        return Err(());
    }
    match port.try_recv() {
        Ok((msg, wakeup)) => {
            drop(table);
            if let Some(tid) = wakeup {
                crate::sched::wake_thread(tid);
            }
            crate::sched::stats::IPC_RECVS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            crate::trace::trace_event(crate::trace::EVT_IPC_RECV, port_id, 0);
            Ok(msg)
        }
        Err(()) => Err(()),
    }
}

/// Send a message to a port (blocking).
/// Blocks if the queue is full until space is available.
pub fn send(port_id: PortId, mut msg: Message) -> Result<(), ()> {
    use crate::sched::thread::BlockReason;
    // Stamp sender priority for priority inheritance.
    let tid = crate::sched::current_thread_id();
    msg.data[5] = crate::sched::thread_effective_priority(tid) as u64;
    crate::sched::stats::IPC_SENDS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let local = port_local(port_id) as usize;
    let mut pending = msg;
    loop {
        let mut table = PORT_TABLE.lock();
        if local >= MAX_PORTS {
            return Err(());
        }
        let port = &mut table.ports[local];
        if !port.active {
            return Err(());
        }
        match port.try_send(pending) {
            Ok((wakeup, set_id)) => {
                if let Some(waiter_tid) = wakeup {
                    use crate::sched::thread::ThreadState;
                    let is_parked = {
                        let sched = crate::sched::scheduler::SCHEDULER.lock();
                        sched.threads[waiter_tid as usize].state == ThreadState::Blocked
                    };
                    if is_parked {
                        // Dequeue the message — inject directly into parked receiver.
                        let dequeued = port.try_recv();
                        drop(table);
                        if let Ok((queued_msg, _)) = dequeued {
                            crate::syscall::handlers::deliver_to_parked_receiver(waiter_tid, &queued_msg);
                        }
                        crate::sched::scheduler::wake_parked_thread(waiter_tid);
                    } else {
                        drop(table);
                        crate::sched::wake_thread(waiter_tid);
                    }
                } else {
                    drop(table);
                    if set_id != u32::MAX {
                        super::port_set::wake_set_waiter(set_id);
                    }
                }
                return Ok(());
            }
            Err(returned_msg) => {
                let tid = crate::sched::current_thread_id();
                crate::sched::clear_wakeup_flag(tid);
                port.add_send_waiter(tid);
                pending = returned_msg;
                drop(table);
                crate::sched::block_current(BlockReason::PortSend(port_id));
            }
        }
    }
}

/// Receive a message from a port (blocking).
/// Blocks if the queue is empty until a message arrives.
pub fn recv(port_id: PortId) -> Result<Message, ()> {
    use crate::sched::thread::BlockReason;
    let local = port_local(port_id) as usize;
    // Reset priority to base on recv entry (priority inheritance protocol).
    let my_tid = crate::sched::current_thread_id();
    crate::sched::reset_priority(my_tid);
    loop {
        let mut table = PORT_TABLE.lock();
        if local >= MAX_PORTS {
            return Err(());
        }
        let port = &mut table.ports[local];
        if !port.active {
            return Err(());
        }
        match port.try_recv() {
            Ok((msg, wakeup)) => {
                drop(table);
                if let Some(tid) = wakeup {
                    crate::sched::wake_thread(tid);
                }
                // Boost to sender's priority (priority inheritance).
                crate::sched::boost_priority(my_tid, msg.data[5] as u8);
                return Ok(msg);
            }
            Err(()) => {
                let tid = crate::sched::current_thread_id();
                crate::sched::clear_wakeup_flag(tid);
                port.add_recv_waiter(tid);
                drop(table);
                crate::sched::block_current(BlockReason::PortRecv(port_id));
            }
        }
    }
}

/// Set the port set membership for a port.
pub fn set_port_set(port_id: PortId, set_id: u32) {
    let local = port_local(port_id) as usize;
    let mut table = PORT_TABLE.lock();
    if local < MAX_PORTS {
        table.ports[local].port_set_id = set_id;
    }
}

/// Check if a port is active (for auto-grant heuristics).
pub fn port_is_active(port_id: PortId) -> bool {
    let local = port_local(port_id) as usize;
    let table = PORT_TABLE.lock();
    local < MAX_PORTS && table.ports[local].active
}

/// Destroy a port, freeing its message queue.
#[allow(dead_code)]
pub fn destroy(port_id: PortId) {
    let local = port_local(port_id) as usize;
    let mut table = PORT_TABLE.lock();
    if local < MAX_PORTS {
        table.ports[local].active = false;
        table.ports[local].free_queue();
    }
}

/// Result of a send with direct-transfer optimization.
pub enum SendDirectResult {
    /// Message was queued normally (or queued + spin-blocked waiter woken).
    Queued,
    /// A receiver was parked (Blocked) — message NOT queued. Caller must inject + wake/handoff.
    DirectTransfer(crate::sched::thread::ThreadId),
    /// Queue is full.
    Full,
    /// Port inactive or invalid.
    Error,
}

/// Try to send with direct-transfer optimization.
/// If a receiver is parked (Blocked state, from recv_or_park) on this port,
/// returns DirectTransfer(tid) without queueing the message. The caller is
/// responsible for injecting the message and waking/handing off to the receiver.
pub fn send_direct(port_id: PortId, msg: &mut Message) -> SendDirectResult {
    use crate::sched::thread::ThreadState;

    let tid = crate::sched::current_thread_id();
    msg.data[5] = crate::sched::thread_effective_priority(tid) as u64;
    crate::sched::stats::IPC_SENDS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    crate::trace::trace_event(crate::trace::EVT_IPC_SEND, port_id, 0);

    let local = port_local(port_id) as usize;
    let mut table = PORT_TABLE.lock();
    if local >= MAX_PORTS {
        return SendDirectResult::Error;
    }
    let port = &mut table.ports[local];
    if !port.active {
        return SendDirectResult::Error;
    }

    // Check for a parked (Blocked) receiver — direct transfer candidate.
    if port.recv_waiter_count > 0 {
        let waiter = port.recv_waiters[port.recv_waiter_count - 1];
        let is_parked = {
            let sched = crate::sched::scheduler::SCHEDULER.lock();
            sched.threads[waiter as usize].state == ThreadState::Blocked
        };
        if is_parked {
            port.recv_waiter_count -= 1;
            drop(table);
            return SendDirectResult::DirectTransfer(waiter);
        }
    }

    // No parked receiver — try to queue normally.
    match port.try_send(*msg) {
        Ok((wakeup, set_id)) => {
            drop(table);
            if let Some(waiter) = wakeup {
                crate::sched::wake_thread(waiter);
            } else if set_id != u32::MAX {
                super::port_set::wake_set_waiter(set_id);
            }
            SendDirectResult::Queued
        }
        Err(_) => {
            drop(table);
            SendDirectResult::Full
        }
    }
}

/// Try to receive from a port, or park the current thread as a waiter.
/// Returns Ok(msg) if a message was immediately available.
/// Returns Err(()) if the thread was parked (message will be injected by sender).
pub fn recv_or_park(port_id: PortId) -> Result<Message, ()> {
    use crate::sched::thread::BlockReason;
    let local = port_local(port_id) as usize;
    let my_tid = crate::sched::current_thread_id();
    crate::sched::reset_priority(my_tid);

    let mut table = PORT_TABLE.lock();
    if local >= MAX_PORTS {
        return Err(());
    }
    let port = &mut table.ports[local];
    if !port.active {
        return Err(());
    }

    match port.try_recv() {
        Ok((msg, wakeup)) => {
            drop(table);
            if let Some(tid) = wakeup {
                crate::sched::wake_thread(tid);
            }
            crate::sched::stats::IPC_RECVS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            crate::sched::boost_priority(my_tid, msg.data[5] as u8);
            Ok(msg)
        }
        Err(()) => {
            crate::sched::clear_wakeup_flag(my_tid);
            port.add_recv_waiter(my_tid);
            drop(table);
            // Park: thread goes off-CPU. Sender will inject message into our frame.
            crate::sched::scheduler::park_current_for_ipc(BlockReason::PortRecv(port_id));
            Err(())
        }
    }
}
