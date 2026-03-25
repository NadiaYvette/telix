//! Port: a kernel-managed message endpoint.
//!
//! A port can receive messages from any holder of a send capability.
//! Messages are queued in a bounded buffer. Senders block if the queue
//! is full; receivers block if the queue is empty.
//!
//! Port IDs are structured as `(node:20 | local:44)` to support future
//! network-transparent IPC. For single-node operation, node is always 0.
//! Ports are dynamically allocated via an Adaptive Radix Tree (ART),
//! with no fixed upper limit on the number of ports.

use super::art::Art;
use super::message::Message;
use crate::sched::thread::ThreadId;
use crate::mm::page::PhysAddr;

pub type PortId = u64;

// --- PortId structure: top 20 bits = node, bottom 44 = local index ---

/// Extract the node portion of a PortId (top 20 bits). Currently always 0.
#[inline]
pub const fn port_node(id: PortId) -> u32 {
    (id >> 44) as u32
}

/// Extract the local port index (bottom 44 bits).
#[inline]
pub const fn port_local(id: PortId) -> u64 {
    id & 0xFFF_FFFF_FFFF
}

/// Construct a PortId from node and local index.
#[inline]
pub const fn make_port_id(node: u32, local: u64) -> PortId {
    ((node as u64) << 44) | (local & 0xFFF_FFFF_FFFF)
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

    #[allow(dead_code)]
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

/// Slab size for Port allocation (~136 bytes, fits in 256-byte slab).
const PORT_SLAB_SIZE: usize = 256;

/// Kernel receive handler type. Called synchronously when a message is
/// sent to a kernel-held port. `user_data` is an opaque value set at
/// port creation (e.g., an object table index). Returns a reply message.
pub type KernelHandler = fn(PortId, usize, &Message) -> Message;

/// A port endpoint.
pub struct Port {
    #[allow(dead_code)]
    pub id: PortId,
    /// Pointer to slab-allocated message queue (0 = not yet allocated).
    /// Queue is allocated on first send, so kernel-held ports that handle
    /// faults synchronously never pay for the queue.
    queue_ptr: usize,
    /// Kernel receive handler (0 = none). When set, the kernel holds the
    /// receive right: sends invoke this handler synchronously instead of
    /// queueing, and no user-space thread can recv on this port.
    kernel_handler: usize,
    /// Opaque value passed to the kernel handler. Set at port creation.
    kernel_user_data: usize,
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
    /// Task holding the RECV cap (u32::MAX = none). Maintained on RECV grant/revoke.
    pub recv_holder: u32,
}

impl Port {
    pub const fn new(id: PortId) -> Self {
        Self {
            id,
            queue_ptr: 0,
            kernel_handler: 0,
            kernel_user_data: 0,
            recv_waiters: [0; MAX_WAITERS],
            recv_waiter_count: 0,
            send_waiters: [0; MAX_WAITERS],
            send_waiter_count: 0,
            port_set_id: u32::MAX,
            creator_task: 0,
            recv_holder: u32::MAX,
        }
    }

    /// Whether this port has a kernel receive handler.
    #[inline]
    pub fn is_kernel_held(&self) -> bool {
        self.kernel_handler != 0
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub fn is_queue_full(&self) -> bool {
        match self.queue() {
            Some(q) => q.is_full(),
            None => false, // No queue yet — not full (first send will allocate)
        }
    }
}

// --- Port slab allocation ---

/// Allocate a Port from the slab allocator.
fn alloc_port(id: PortId) -> Option<*mut Port> {
    let pa = crate::mm::slab::alloc(PORT_SLAB_SIZE)?;
    let ptr = pa.as_usize() as *mut Port;
    unsafe { core::ptr::write(ptr, Port::new(id)); }
    Some(ptr)
}

/// Free a Port and its queue back to the slab allocator.
fn free_port(ptr: *mut Port) {
    unsafe { (*ptr).free_queue(); }
    crate::mm::slab::free(PhysAddr::new(ptr as usize), PORT_SLAB_SIZE);
}

// --- ART-backed port table ---

use crate::sync::SpinLock;

struct PortTable {
    art: Art,
    next_id: u64,
}

impl PortTable {
    const fn new() -> Self {
        Self {
            art: Art::new(),
            next_id: 0,
        }
    }

    /// Look up a port by local ID. Returns a reference valid while lock is held.
    #[inline]
    fn get(&self, local: u64) -> Option<&Port> {
        let ptr = self.art.lookup(local)?;
        Some(unsafe { &*(ptr as *const Port) })
    }

    /// Mutable lookup by local ID.
    #[inline]
    fn get_mut(&mut self, local: u64) -> Option<&mut Port> {
        let ptr = self.art.lookup(local)?;
        Some(unsafe { &mut *(ptr as *mut Port) })
    }
}

static PORT_TABLE: SpinLock<PortTable> = SpinLock::new(PortTable::new());

/// Registered proxy port for network-transparent IPC. Non-local sends are
/// redirected to this port. 0 = no proxy registered.
pub static PROXY_PORT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Create a new port. Returns its ID (node=0, local=monotonic_counter).
pub fn create() -> Option<PortId> {
    let creator = crate::sched::current_task_id();
    let mut table = PORT_TABLE.lock();
    let local = table.next_id;
    table.next_id += 1;
    let pid = make_port_id(0, local);
    let ptr = alloc_port(pid)?;
    unsafe { (*ptr).creator_task = creator; }
    if !table.art.insert(local, ptr as usize) {
        free_port(ptr);
        return None;
    }
    Some(pid)
}

/// Get the creator task of a port, or None if port doesn't exist.
pub fn port_creator(port_id: PortId) -> Option<u32> {
    let local = port_local(port_id);
    let table = PORT_TABLE.lock();
    table.get(local).map(|p| p.creator_task)
}

/// Send a message to a port (non-blocking).
/// Returns Ok(()) on success, Err(msg) if the queue is full.
pub fn send_nb(port_id: PortId, mut msg: Message) -> Result<(), Message> {
    // Stamp sender priority for priority inheritance.
    let tid = crate::sched::current_thread_id();
    msg.data[5] = crate::sched::thread_effective_priority(tid) as u64;
    let local = port_local(port_id);
    let mut table = PORT_TABLE.lock();
    let port = match table.get_mut(local) {
        Some(p) => p,
        None => return Err(msg),
    };
    // Kernel-held port: invoke handler synchronously, no queue.
    if port.is_kernel_held() {
        let handler = port.kernel_handler;
        let udata = port.kernel_user_data;
        drop(table);
        let handler_fn: KernelHandler = unsafe { core::mem::transmute(handler) };
        let _reply = handler_fn(port_id, udata, &msg);
        return Ok(());
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
/// Returns Ok(msg) on success, Err(()) if empty or kernel-held.
pub fn recv_nb(port_id: PortId) -> Result<Message, ()> {
    let local = port_local(port_id);
    let mut table = PORT_TABLE.lock();
    let port = match table.get_mut(local) {
        Some(p) => p,
        None => return Err(()),
    };
    if port.is_kernel_held() {
        return Err(());
    }
    match port.try_recv() {
        Ok((msg, wakeup)) => {
            drop(table);
            if let Some(tid) = wakeup {
                crate::sched::wake_thread(tid);
            }
            crate::sched::stats::IPC_RECVS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            crate::trace::trace_event(crate::trace::EVT_IPC_RECV, port_id as u32, 0);
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
    let local = port_local(port_id);
    // Check for kernel handler before entering the loop.
    {
        let table = PORT_TABLE.lock();
        let port = match table.get(local) {
            Some(p) => p,
            None => return Err(()),
        };
        if port.is_kernel_held() {
            let handler = port.kernel_handler;
            let udata = port.kernel_user_data;
            drop(table);
            let handler_fn: KernelHandler = unsafe { core::mem::transmute(handler) };
            let _reply = handler_fn(port_id, udata, &msg);
            return Ok(());
        }
    }
    let mut pending = msg;
    loop {
        let mut table = PORT_TABLE.lock();
        let port = match table.get_mut(local) {
            Some(p) => p,
            None => return Err(()),
        };
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
    let local = port_local(port_id);
    // Reset priority to base on recv entry (priority inheritance protocol).
    let my_tid = crate::sched::current_thread_id();
    crate::sched::reset_priority(my_tid);
    loop {
        let mut table = PORT_TABLE.lock();
        let port = match table.get_mut(local) {
            Some(p) => p,
            None => return Err(()),
        };
        if port.is_kernel_held() {
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
    let local = port_local(port_id);
    let mut table = PORT_TABLE.lock();
    if let Some(port) = table.get_mut(local) {
        port.port_set_id = set_id;
    }
}

/// Check if a port exists (for auto-grant heuristics).
pub fn port_is_active(port_id: PortId) -> bool {
    let local = port_local(port_id);
    let table = PORT_TABLE.lock();
    table.get(local).is_some()
}

/// Set the recv_holder for a port (task that holds the RECV cap).
pub fn set_recv_holder(port_id: PortId, task_id: u32) {
    let local = port_local(port_id);
    let mut table = PORT_TABLE.lock();
    if let Some(port) = table.get_mut(local) {
        port.recv_holder = task_id;
    }
}

/// Get the recv_holder for a port. Returns u32::MAX if none.
pub fn get_recv_holder(port_id: PortId) -> u32 {
    let local = port_local(port_id);
    let table = PORT_TABLE.lock();
    match table.get(local) {
        Some(port) => port.recv_holder,
        None => u32::MAX,
    }
}

/// Destroy a port, removing it from the table and freeing all resources.
#[allow(dead_code)]
pub fn destroy(port_id: PortId) {
    let local = port_local(port_id);
    let mut table = PORT_TABLE.lock();
    if let Some(ptr) = table.art.remove(local) {
        drop(table);
        free_port(ptr as *mut Port);
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
    crate::trace::trace_event(crate::trace::EVT_IPC_SEND, port_id as u32, 0);

    let local = port_local(port_id);
    let mut table = PORT_TABLE.lock();
    let port = match table.get_mut(local) {
        Some(p) => p,
        None => return SendDirectResult::Error,
    };

    // Kernel-held port: invoke handler synchronously.
    if port.is_kernel_held() {
        let handler = port.kernel_handler;
        let udata = port.kernel_user_data;
        drop(table);
        let handler_fn: KernelHandler = unsafe { core::mem::transmute(handler) };
        let _reply = handler_fn(port_id, udata, msg);
        return SendDirectResult::Queued;
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
    let local = port_local(port_id);
    let my_tid = crate::sched::current_thread_id();
    crate::sched::reset_priority(my_tid);

    let mut table = PORT_TABLE.lock();
    let port = match table.get_mut(local) {
        Some(p) => p,
        None => return Err(()),
    };
    if port.is_kernel_held() {
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

// --- Kernel-held port API ---

/// Create a port with a kernel receive handler. The kernel holds the receive
/// right: sends invoke the handler synchronously, no message queue is allocated,
/// and user-space threads cannot recv on this port.
pub fn create_kernel_port(handler: KernelHandler, user_data: usize) -> Option<PortId> {
    let mut table = PORT_TABLE.lock();
    let local = table.next_id;
    table.next_id += 1;
    let pid = make_port_id(0, local);
    let ptr = alloc_port(pid)?;
    unsafe {
        (*ptr).creator_task = 0; // kernel
        (*ptr).kernel_handler = handler as usize;
        (*ptr).kernel_user_data = user_data;
    }
    if !table.art.insert(local, ptr as usize) {
        free_port(ptr);
        return None;
    }
    Some(pid)
}

/// Call a port's kernel handler directly (synchronous request-reply).
/// Returns Some(reply) if the port has a kernel handler, None otherwise.
#[allow(dead_code)]
pub fn call_kernel_handler(port_id: PortId, msg: &Message) -> Option<Message> {
    let local = port_local(port_id);
    let (handler, udata) = {
        let table = PORT_TABLE.lock();
        let port = table.get(local)?;
        if !port.is_kernel_held() { return None; }
        (port.kernel_handler, port.kernel_user_data)
    };
    // Lock released — safe to call handler.
    let handler_fn: KernelHandler = unsafe { core::mem::transmute(handler) };
    Some(handler_fn(port_id, udata, msg))
}

/// Check if a port has a kernel receive handler.
#[allow(dead_code)]
pub fn has_kernel_handler(port_id: PortId) -> bool {
    let local = port_local(port_id);
    let table = PORT_TABLE.lock();
    matches!(table.get(local), Some(p) if p.is_kernel_held())
}
