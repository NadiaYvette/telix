//! Port: a kernel-managed message endpoint.
//!
//! A port can receive messages from any holder of a send capability.
//! Messages are queued in a lock-free bounded MPSC buffer. Senders
//! block (via turnstile) if the queue is full; receivers block if
//! the queue is empty.
//!
//! Port IDs are structured as `(node:20 | local:44)` to support future
//! network-transparent IPC. For single-node operation, node is always 0.
//! Ports are dynamically allocated via an Adaptive Radix Tree (ART),
//! with no fixed upper limit on the number of ports.
//!
//! Concurrency model:
//!   - RCU-protected ART for lock-free port lookup (readers never block)
//!   - Lock-free MPSC queue for send/recv fast path
//!   - Turnstile HAMT for blocking waiters (lost-wakeup-free protocol)
//!   - ART_WRITE_LOCK serializes structural mutations (create/destroy/resize)

use super::art::{Art, ART_WRITE_LOCK};
use super::message::Message;
use crate::mm::page::PhysAddr;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

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

// ---------------------------------------------------------------------------
// Lock-free MPSC message queue
// ---------------------------------------------------------------------------
//
// Bounded ring buffer with CAS-claimed tail (multi-producer) and single-
// consumer head. Per-slot state byte (EMPTY/WRITING/READY) provides
// publish/consume ordering without ABA.
//
// Layout in memory (single contiguous slab or page allocation):
//   [MpscQueue header: 16 bytes]
//   [Messages: Message[capacity], each 56 bytes]
//   [Slot states: u8[capacity]]

const SLOT_EMPTY: u8 = 0;
const SLOT_READY: u8 = 2;

/// Default slab size for queue allocation.
const PORT_QUEUE_SLAB_SIZE: usize = 2048;

/// Lock-free bounded MPSC (multi-producer, single-consumer) message queue.
#[repr(C)]
struct MpscQueue {
    head: AtomicU32,     // consumer read position (monotonically increasing)
    tail: AtomicU32,     // producer claim position (CAS by senders)
    capacity: u32,       // power-of-2 slot count
    page_backed: bool,
    _pad: [u8; 3],
}

impl MpscQueue {
    /// Pointer to the message array (immediately after header).
    #[inline]
    fn msgs(&self) -> *mut Message {
        unsafe { (self as *const Self).add(1) as *mut Message }
    }

    /// Pointer to the slot state array (after messages).
    #[inline]
    fn slot_states(&self) -> *mut u8 {
        unsafe { self.msgs().add(self.capacity as usize) as *mut u8 }
    }

    /// Get an atomic reference to the state of slot `idx`.
    #[inline]
    fn slot_state(&self, idx: usize) -> &AtomicU8 {
        unsafe { &*(self.slot_states().add(idx) as *const AtomicU8) }
    }

    /// Enqueue a message (producer — multiple concurrent callers OK).
    /// Returns true on success, false if the queue is full.
    fn send(&self, msg: &Message) -> bool {
        loop {
            let t = self.tail.load(Ordering::Relaxed);
            let h = self.head.load(Ordering::Acquire);
            if t.wrapping_sub(h) >= self.capacity {
                return false; // full
            }
            // CAS to claim slot `t`.
            match self.tail.compare_exchange_weak(
                t,
                t.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let idx = (t as usize) & (self.capacity as usize - 1);
                    // Write message data.
                    unsafe { core::ptr::write(self.msgs().add(idx), *msg); }
                    // Publish: mark slot as READY (Release pairs with consumer's Acquire).
                    self.slot_state(idx).store(SLOT_READY, Ordering::Release);
                    return true;
                }
                Err(_) => continue, // another producer won, retry
            }
        }
    }

    /// Dequeue a message (consumer — single caller only, the recv_holder).
    /// Returns the message if one is ready, or None if the queue is empty.
    fn recv(&self) -> Option<Message> {
        let h = self.head.load(Ordering::Relaxed);
        let idx = (h as usize) & (self.capacity as usize - 1);
        // Check if slot is READY (Acquire pairs with producer's Release).
        if self.slot_state(idx).load(Ordering::Acquire) != SLOT_READY {
            return None;
        }
        let msg = unsafe { core::ptr::read(self.msgs().add(idx)) };
        // Mark slot as EMPTY (Release) so producers can reuse it.
        self.slot_state(idx).store(SLOT_EMPTY, Ordering::Release);
        // Advance head (Release so producers see the freed slot).
        self.head.store(h.wrapping_add(1), Ordering::Release);
        Some(msg)
    }

    /// Check if the queue is full.
    fn is_full(&self) -> bool {
        let t = self.tail.load(Ordering::Relaxed);
        let h = self.head.load(Ordering::Acquire);
        t.wrapping_sub(h) >= self.capacity
    }

    /// Check if the queue has no ready messages.
    fn is_empty(&self) -> bool {
        let h = self.head.load(Ordering::Relaxed);
        let idx = (h as usize) & (self.capacity as usize - 1);
        self.slot_state(idx).load(Ordering::Acquire) != SLOT_READY
    }
}

/// Compute MPSC queue capacity for a given allocation size.
/// Returns power-of-2 capacity, or 0 if too small.
const fn mpsc_capacity_for_size(alloc_size: usize) -> u32 {
    let header = core::mem::size_of::<MpscQueue>();
    if alloc_size <= header {
        return 0;
    }
    let remaining = alloc_size - header;
    let raw_cap = remaining / (core::mem::size_of::<Message>() + 1);
    if raw_cap == 0 {
        return 0;
    }
    // Round down to power of 2.
    1u32 << (31 - (raw_cap as u32).leading_zeros())
}

/// Allocate a default MPSC queue from the slab allocator.
fn alloc_mpsc_queue() -> Option<*mut MpscQueue> {
    let pa = crate::mm::slab::alloc(PORT_QUEUE_SLAB_SIZE)?;
    let ptr = pa.as_usize() as *mut MpscQueue;
    let cap = mpsc_capacity_for_size(PORT_QUEUE_SLAB_SIZE);
    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, PORT_QUEUE_SLAB_SIZE);
        (*ptr).capacity = cap;
        (*ptr).page_backed = false;
    }
    Some(ptr)
}

/// Allocate a page-backed MPSC queue.
fn alloc_mpsc_page_queue() -> Option<*mut MpscQueue> {
    let pa = crate::mm::phys::alloc_page()?;
    let ptr = pa.as_usize() as *mut MpscQueue;
    let cap = mpsc_capacity_for_size(crate::mm::page::PAGE_SIZE);
    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, crate::mm::page::PAGE_SIZE);
        (*ptr).capacity = cap;
        (*ptr).page_backed = true;
    }
    Some(ptr)
}

/// Free an MPSC queue (slab or page-backed).
fn free_mpsc_queue(ptr: *mut MpscQueue) {
    let page_backed = unsafe { (*ptr).page_backed };
    if page_backed {
        crate::mm::phys::free_page(PhysAddr::new(ptr as usize));
    } else {
        crate::mm::slab::free(PhysAddr::new(ptr as usize), PORT_QUEUE_SLAB_SIZE);
    }
}

// ---------------------------------------------------------------------------
// Port structure
// ---------------------------------------------------------------------------

/// Slab size for Port allocation.
const PORT_SLAB_SIZE: usize = 256;

/// Port ALIVE flag.
const PORT_ALIVE: u32 = 1;

/// Kernel receive handler type. Called synchronously when a message is
/// sent to a kernel-held port. `user_data` is an opaque value set at
/// port creation (e.g., an object table index). Returns a reply message.
pub type KernelHandler = fn(PortId, usize, &Message) -> Message;

/// A port endpoint. Accessed via RCU (lock-free reads) after ART lookup.
/// Fields that change concurrently use atomics; immutable-after-creation
/// fields use plain types.
pub struct Port {
    #[allow(dead_code)]
    pub id: PortId,
    /// MPSC queue pointer (0 for kernel-held ports).
    mpsc_ptr: usize,
    /// Kernel receive handler (0 = none).
    kernel_handler: usize,
    /// Opaque value passed to the kernel handler.
    kernel_user_data: usize,
    /// Port set this port belongs to (u32::MAX = none).
    pub port_set_id: AtomicU32,
    /// Task that created this port.
    pub creator_task: u32,
    /// Task holding the RECV cap (u32::MAX = none).
    pub recv_holder: AtomicU32,
    /// Port flags (PORT_ALIVE, etc.).
    flags: AtomicU32,
}

impl Port {
    /// Whether this port has a kernel receive handler.
    #[inline]
    pub fn is_kernel_held(&self) -> bool {
        self.kernel_handler != 0
    }

    /// Whether this port is alive (not destroyed).
    #[inline]
    fn is_alive(&self) -> bool {
        self.flags.load(Ordering::Acquire) & PORT_ALIVE != 0
    }

    /// Get a reference to the MPSC queue, if allocated.
    #[inline]
    fn mpsc(&self) -> Option<&MpscQueue> {
        if self.mpsc_ptr == 0 { None } else { Some(unsafe { &*(self.mpsc_ptr as *const MpscQueue) }) }
    }

    /// Current queue capacity (0 if no queue allocated).
    pub fn queue_capacity(&self) -> usize {
        match self.mpsc() {
            Some(q) => q.capacity as usize,
            None => 0,
        }
    }
}

/// Allocate a Port from the slab allocator with an MPSC queue.
fn alloc_port(id: PortId, with_queue: bool) -> Option<*mut Port> {
    let pa = crate::mm::slab::alloc(PORT_SLAB_SIZE)?;
    let ptr = pa.as_usize() as *mut Port;

    let mpsc = if with_queue {
        match alloc_mpsc_queue() {
            Some(q) => q as usize,
            None => {
                crate::mm::slab::free(pa, PORT_SLAB_SIZE);
                return None;
            }
        }
    } else {
        0
    };

    unsafe {
        core::ptr::write_bytes(ptr as *mut u8, 0, PORT_SLAB_SIZE);
        (*ptr).id = id;
        (*ptr).mpsc_ptr = mpsc;
        (*ptr).port_set_id = AtomicU32::new(u32::MAX);
        (*ptr).recv_holder = AtomicU32::new(u32::MAX);
        (*ptr).flags = AtomicU32::new(PORT_ALIVE);
    }
    Some(ptr)
}

/// Free a Port and its queue.
fn free_port(ptr: *mut Port) {
    let mpsc = unsafe { (*ptr).mpsc_ptr };
    if mpsc != 0 {
        free_mpsc_queue(mpsc as *mut MpscQueue);
    }
    crate::mm::slab::free(PhysAddr::new(ptr as usize), PORT_SLAB_SIZE);
}

// ---------------------------------------------------------------------------
// Global ART-backed port table (RCU-protected, lock-free reads)
// ---------------------------------------------------------------------------

/// Wrapper around Art providing interior mutability for global access.
/// Reads are lock-free (RCU). Writes require ART_WRITE_LOCK.
struct PortArt {
    inner: UnsafeCell<Art>,
}

unsafe impl Sync for PortArt {}

impl PortArt {
    const fn new() -> Self {
        Self { inner: UnsafeCell::new(Art::new()) }
    }

    /// Lock-free lookup by local port ID. Safe to call without any lock.
    #[inline]
    fn lookup(&self, local: u64) -> Option<&Port> {
        let ptr = unsafe { &*self.inner.get() }.lookup(local)?;
        Some(unsafe { &*(ptr as *const Port) })
    }

    /// Insert a port. Must hold ART_WRITE_LOCK.
    fn insert(&self, local: u64, ptr: *mut Port) -> bool {
        unsafe { &mut *self.inner.get() }.insert(local, ptr as usize)
    }

    /// Lookup returning a raw mutable pointer. Must hold ART_WRITE_LOCK.
    fn lookup_mut(&self, local: u64) -> Option<*mut Port> {
        unsafe { &*self.inner.get() }.lookup(local).map(|p| p as *mut Port)
    }

    /// Remove a port. Must hold ART_WRITE_LOCK. Returns port pointer.
    fn remove(&self, local: u64) -> Option<*mut Port> {
        unsafe { &mut *self.inner.get() }.remove(local).map(|p| p as *mut Port)
    }
}

static PORT_ART: PortArt = PortArt::new();

/// Monotonically increasing port ID counter.
static NEXT_PORT_ID: AtomicU64 = AtomicU64::new(0);

/// Registered proxy port for network-transparent IPC. Non-local sends are
/// redirected to this port. 0 = no proxy registered.
pub static PROXY_PORT: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Port lookup helper (RCU read, lock-free)
// ---------------------------------------------------------------------------

/// Look up a port by ID. Returns a reference valid for the current RCU
/// read-side critical section (i.e. the current syscall).
#[inline]
fn port_ref(port_id: PortId) -> Option<&'static Port> {
    let local = port_local(port_id);
    let port = PORT_ART.lookup(local)?;
    if port.is_alive() { Some(port) } else { None }
}

// ---------------------------------------------------------------------------
// Create / Destroy
// ---------------------------------------------------------------------------

/// Create a new port. Returns its ID (node=0, local=monotonic_counter).
pub fn create() -> Option<PortId> {
    let creator = crate::sched::current_task_id();
    let local = NEXT_PORT_ID.fetch_add(1, Ordering::Relaxed);
    let pid = make_port_id(0, local);
    let ptr = alloc_port(pid, true)?;
    unsafe { (*ptr).creator_task = creator; }

    let _wlock = ART_WRITE_LOCK.lock();
    if !PORT_ART.insert(local, ptr) {
        drop(_wlock);
        free_port(ptr);
        return None;
    }
    Some(pid)
}

/// Create a port with a kernel receive handler.
pub fn create_kernel_port(handler: KernelHandler, user_data: usize) -> Option<PortId> {
    let local = NEXT_PORT_ID.fetch_add(1, Ordering::Relaxed);
    let pid = make_port_id(0, local);
    // Kernel ports don't need a queue (handler invoked synchronously).
    let ptr = alloc_port(pid, false)?;
    unsafe {
        (*ptr).creator_task = 0;
        (*ptr).kernel_handler = handler as usize;
        (*ptr).kernel_user_data = user_data;
    }

    let _wlock = ART_WRITE_LOCK.lock();
    if !PORT_ART.insert(local, ptr) {
        drop(_wlock);
        free_port(ptr);
        return None;
    }
    Some(pid)
}

/// RCU callback to free a port and its queue.
fn rcu_free_port_callback(ptr: usize) {
    free_port(ptr as *mut Port);
}

/// Destroy a port, removing it from the table and freeing all resources.
/// Uses deferred free via RCU — the port memory is reclaimed after a grace
/// period, so this never blocks (safe to call before interrupts are enabled).
pub fn destroy(port_id: PortId) {
    use crate::sync::turnstile::{KEY_PORT_RECV, KEY_PORT_SEND};

    let local = port_local(port_id);

    // Remove from ART under write lock — new lookups will return None.
    let ptr = {
        let _wlock = ART_WRITE_LOCK.lock();
        match PORT_ART.remove(local) {
            Some(p) => p,
            None => return,
        }
    };

    // Mark as dead so in-flight readers get clean errors.
    unsafe { (*ptr).flags.store(0, Ordering::Release); }

    // Wake all blocked waiters (they will retry lookup and get None → error).
    crate::sync::turnstile::port_wake_all(port_id, KEY_PORT_RECV);
    crate::sync::turnstile::port_wake_all(port_id, crate::sync::turnstile::KEY_PORT_RECV_PARK);
    crate::sync::turnstile::port_wake_all(port_id, KEY_PORT_SEND);

    // Defer free via RCU — the port and its queue are freed after all
    // in-flight RCU readers have finished.
    crate::sync::rcu::rcu_defer_free(ptr as usize, rcu_free_port_callback);
}

// ---------------------------------------------------------------------------
// Read-only queries (lock-free via RCU)
// ---------------------------------------------------------------------------

/// Get the creator task of a port, or None if port doesn't exist.
pub fn port_creator(port_id: PortId) -> Option<u32> {
    port_ref(port_id).map(|p| p.creator_task)
}

/// Get the kernel_user_data of a kernel-held port.
pub fn port_kernel_data(port_id: PortId) -> Option<usize> {
    let p = port_ref(port_id)?;
    if p.is_kernel_held() { Some(p.kernel_user_data) } else { None }
}

/// Check if a port exists (for auto-grant heuristics).
pub fn port_is_active(port_id: PortId) -> bool {
    port_ref(port_id).is_some()
}

/// Check if a port has a kernel receive handler.
#[allow(dead_code)]
pub fn has_kernel_handler(port_id: PortId) -> bool {
    matches!(port_ref(port_id), Some(p) if p.is_kernel_held())
}

/// Get the recv_holder for a port. Returns u32::MAX if none.
pub fn get_recv_holder(port_id: PortId) -> u32 {
    match port_ref(port_id) {
        Some(port) => port.recv_holder.load(Ordering::Relaxed),
        None => u32::MAX,
    }
}

/// Current queue capacity (0 if no queue allocated).
pub fn queue_capacity(port_id: PortId) -> usize {
    match port_ref(port_id) {
        Some(port) => port.queue_capacity(),
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Mutation helpers (some need ART_WRITE_LOCK, some use atomics)
// ---------------------------------------------------------------------------

/// Set the port set membership for a port.
pub fn set_port_set(port_id: PortId, set_id: u32) {
    if let Some(port) = port_ref(port_id) {
        port.port_set_id.store(set_id, Ordering::Release);
    }
}

/// Set the recv_holder for a port (task that holds the RECV cap).
pub fn set_recv_holder(port_id: PortId, task_id: u32) {
    if let Some(port) = port_ref(port_id) {
        port.recv_holder.store(task_id, Ordering::Release);
    }
}

/// Resize a port's message queue. Allocates a page-backed queue,
/// drains old queue, swaps, waits for RCU grace period, frees old.
/// Returns true on success.
pub fn resize(port_id: PortId, new_capacity: usize) -> bool {
    let local = port_local(port_id);
    let max_page_cap = mpsc_capacity_for_size(crate::mm::page::PAGE_SIZE) as usize;
    if new_capacity > max_page_cap {
        return false;
    }

    let _wlock = ART_WRITE_LOCK.lock();
    let port_ptr = match PORT_ART.lookup_mut(local) {
        Some(p) => p,
        None => return false,
    };
    let port = unsafe { &*port_ptr };
    if !port.is_alive() || port.is_kernel_held() {
        return false;
    }

    let old_mpsc = port.mpsc_ptr;
    if old_mpsc != 0 {
        let old_q = unsafe { &*(old_mpsc as *const MpscQueue) };
        if old_q.page_backed && (old_q.capacity as usize) >= new_capacity {
            return true; // already large enough
        }
    }

    // Allocate new page-backed queue.
    let new_q = match alloc_mpsc_page_queue() {
        Some(q) => q,
        None => return false,
    };

    // Swap the pointer. Under ART_WRITE_LOCK, so no concurrent resize.
    unsafe { (*port_ptr).mpsc_ptr = new_q as usize; }

    drop(_wlock);

    // Wait for in-flight senders on the old queue to finish.
    if old_mpsc != 0 {
        crate::sync::rcu::synchronize_rcu();

        // Drain remaining messages from old queue into new queue.
        let old_q = unsafe { &*(old_mpsc as *const MpscQueue) };
        let new_ref = unsafe { &*new_q };
        while let Some(msg) = old_q.recv() {
            new_ref.send(&msg);
        }
        free_mpsc_queue(old_mpsc as *mut MpscQueue);
    }

    true
}

// ---------------------------------------------------------------------------
// Send API
// ---------------------------------------------------------------------------

/// Result of a send with direct-transfer optimization.
pub enum SendDirectResult {
    /// Message was queued normally (or queued + blocked waiter woken).
    Queued,
    /// A receiver was parked (Blocked) — message NOT queued. Caller must inject + wake.
    DirectTransfer(crate::sched::thread::ThreadId),
    /// Queue is full.
    Full,
    /// Port inactive or invalid.
    Error,
}

/// Internal: stamp sender priority and do an MPSC send + wake receiver.
/// Returns Ok(()) on success, Err(()) if queue full or port invalid.
fn do_send(port: &Port, msg: &Message) -> Result<(), ()> {
    use crate::sync::turnstile::{KEY_PORT_RECV, KEY_PORT_RECV_PARK};
    let q = match port.mpsc() {
        Some(q) => q,
        None => return Err(()),
    };
    if !q.send(msg) {
        return Err(());
    }
    // Wake a blocked receiver. Parked receivers (recv_or_park) need
    // wake_parked_thread; normal recv blockers need wake_thread.
    wake_recv_waiter(port.id);
    // Also notify port set.
    let set_id = port.port_set_id.load(Ordering::Relaxed);
    if set_id != u32::MAX {
        super::port_set::wake_set_waiter(set_id);
    }
    Ok(())
}

/// Wake one receiver blocked on a port. Uses the correct wake function
/// depending on whether the receiver is parked (recv_or_park, needs
/// wake_parked_thread + frame injection) or normally blocked (recv,
/// needs wake_thread for spin-wait).
fn wake_recv_waiter(port_id: PortId) {
    use crate::sync::turnstile::{KEY_PORT_RECV, KEY_PORT_RECV_PARK};
    // Try parked receivers first (they've been waiting longer / expect direct injection).
    if let Some(tid) = crate::sync::turnstile::port_dequeue_one(port_id, KEY_PORT_RECV_PARK) {

        // Parked receivers expect the message to be injected into their saved
        // exception frame (just like DirectTransfer). Dequeue from the MPSC
        // queue and inject before waking. The receiver is parked (not running),
        // so we are the sole consumer of the MPSC queue right now.
        if let Some(port) = port_ref(port_id) {
            if let Some(q) = port.mpsc() {
                if let Some(msg) = q.recv() {
                    crate::syscall::handlers::deliver_to_parked_receiver(tid, &msg);
                    // Wake a blocked sender now that we freed a queue slot.
                    crate::sync::turnstile::port_wake_one(port_id, crate::sync::turnstile::KEY_PORT_SEND);
                }
            }
        }
        crate::sched::scheduler::wake_parked_thread(tid);
        return;
    }
    // Then try normal recv blockers (spin-waiting via block_current).

    crate::sync::turnstile::port_wake_one(port_id, KEY_PORT_RECV);
}

/// Send a message to a port (non-blocking).
/// Returns Ok(()) on success, Err(msg) if the queue is full.
pub fn send_nb(port_id: PortId, mut msg: Message) -> Result<(), Message> {
    let tid = crate::sched::current_thread_id();
    msg.data[5] = crate::sched::thread_effective_priority(tid) as u64;
    let port = match port_ref(port_id) {
        Some(p) => p,
        None => return Err(msg),
    };
    // Kernel-held port: invoke handler synchronously.
    if port.is_kernel_held() {
        let handler_fn: KernelHandler = unsafe { core::mem::transmute(port.kernel_handler) };
        let _reply = handler_fn(port_id, port.kernel_user_data, &msg);
        return Ok(());
    }
    match do_send(port, &msg) {
        Ok(()) => Ok(()),
        Err(()) => Err(msg),
    }
}

/// Send a message to a port (blocking).
/// Blocks if the queue is full until space is available.
pub fn send(port_id: PortId, mut msg: Message) -> Result<(), ()> {
    use crate::sched::thread::BlockReason;
    use crate::sync::turnstile::KEY_PORT_SEND;

    let tid = crate::sched::current_thread_id();
    msg.data[5] = crate::sched::thread_effective_priority(tid) as u64;
    crate::sched::stats::IPC_SENDS.fetch_add(1, Ordering::Relaxed);

    // Check for kernel handler.
    {
        let port = match port_ref(port_id) {
            Some(p) => p,
            None => return Err(()),
        };
        if port.is_kernel_held() {
            let handler_fn: KernelHandler = unsafe { core::mem::transmute(port.kernel_handler) };
            let _reply = handler_fn(port_id, port.kernel_user_data, &msg);
            return Ok(());
        }
    }

    loop {
        let port = match port_ref(port_id) {
            Some(p) => p,
            None => return Err(()),
        };
        if do_send(port, &msg).is_ok() {
            return Ok(());
        }
        // Queue full — block on turnstile with lost-wakeup prevention.
        let enqueued = crate::sync::turnstile::port_enqueue_with_check(
            port_id,
            KEY_PORT_SEND,
            tid,
            || {
                // Re-check under HAMT bucket lock: still full?
                match port_ref(port_id) {
                    Some(p) => match p.mpsc() {
                        Some(q) => q.is_full(),
                        None => false, // port destroyed, don't block
                    },
                    None => false, // port gone
                }
            },
        );
        if enqueued {
            crate::sched::block_current(BlockReason::PortSend(port_id));
        }
        // Retry after wake.
    }
}

/// Try to send with direct-transfer optimization.
/// If a receiver is parked on this port, returns DirectTransfer(tid)
/// without queueing the message.
pub fn send_direct(port_id: PortId, msg: &mut Message) -> SendDirectResult {
    use crate::sync::turnstile::{KEY_PORT_RECV, KEY_PORT_RECV_PARK};

    let tid = crate::sched::current_thread_id();
    msg.data[5] = crate::sched::thread_effective_priority(tid) as u64;
    crate::sched::stats::IPC_SENDS.fetch_add(1, Ordering::Relaxed);
    crate::trace::trace_event(crate::trace::EVT_IPC_SEND, port_id as u32, 0);

    let port = match port_ref(port_id) {
        Some(p) => p,
        None => {
            return SendDirectResult::Error;
        }
    };

    // Kernel-held port: invoke handler synchronously.
    if port.is_kernel_held() {
        let handler_fn: KernelHandler = unsafe { core::mem::transmute(port.kernel_handler) };
        let _reply = handler_fn(port_id, port.kernel_user_data, msg);
        return SendDirectResult::Queued;
    }

    // Try to dequeue a parked receiver (from recv_or_park) for direct transfer.
    // Only KEY_PORT_RECV_PARK waiters are eligible — they expect message injection
    // into their frame, not via the queue.
    if let Some(waiter) = crate::sync::turnstile::port_dequeue_one(port_id, KEY_PORT_RECV_PARK) {

        return SendDirectResult::DirectTransfer(waiter);
    }

    // No parked receiver — try to queue normally.
    let q = match port.mpsc() {
        Some(q) => q,
        None => return SendDirectResult::Error,
    };
    if q.send(msg) {

        // Wake a blocked receiver (parked or normal).
        wake_recv_waiter(port_id);
        let set_id = port.port_set_id.load(Ordering::Relaxed);
        if set_id != u32::MAX {
            super::port_set::wake_set_waiter(set_id);
        }
        SendDirectResult::Queued
    } else {
        SendDirectResult::Full
    }
}

// ---------------------------------------------------------------------------
// Recv API
// ---------------------------------------------------------------------------

/// Receive a message from a port (non-blocking).
/// Returns Ok(msg) on success, Err(()) if empty or kernel-held.
pub fn recv_nb(port_id: PortId) -> Result<Message, ()> {
    let port = match port_ref(port_id) {
        Some(p) => p,
        None => return Err(()),
    };
    if port.is_kernel_held() {
        return Err(());
    }
    let q = match port.mpsc() {
        Some(q) => q,
        None => return Err(()),
    };
    match q.recv() {
        Some(msg) => {
            // Wake a blocked sender (queue was full, now has space).
            crate::sync::turnstile::port_wake_one(port_id, crate::sync::turnstile::KEY_PORT_SEND);
            crate::sched::stats::IPC_RECVS.fetch_add(1, Ordering::Relaxed);
            crate::trace::trace_event(crate::trace::EVT_IPC_RECV, port_id as u32, 0);
            Ok(msg)
        }
        None => Err(()),
    }
}

/// Receive a message from a port (blocking).
/// Blocks if the queue is empty until a message arrives.
pub fn recv(port_id: PortId) -> Result<Message, ()> {
    use crate::sched::thread::BlockReason;
    use crate::sync::turnstile::{KEY_PORT_RECV, KEY_PORT_SEND};

    let my_tid = crate::sched::current_thread_id();
    crate::sched::reset_priority(my_tid);

    loop {
        let port = match port_ref(port_id) {
            Some(p) => p,
            None => return Err(()),
        };
        if port.is_kernel_held() {
            return Err(());
        }
        let q = match port.mpsc() {
            Some(q) => q,
            None => return Err(()),
        };
        if let Some(msg) = q.recv() {
            // Wake a blocked sender.
            crate::sync::turnstile::port_wake_one(port_id, KEY_PORT_SEND);
            crate::sched::boost_priority(my_tid, msg.data[5] as u8);

            return Ok(msg);
        }

        // Queue empty — block on turnstile with lost-wakeup prevention.
        let enqueued = crate::sync::turnstile::port_enqueue_with_check(
            port_id,
            KEY_PORT_RECV,
            my_tid,
            || {
                // Re-check under HAMT bucket lock: still empty?
                match port_ref(port_id) {
                    Some(p) => match p.mpsc() {
                        Some(q2) => q2.is_empty(),
                        None => false,
                    },
                    None => false,
                }
            },
        );
        if enqueued {
            crate::sched::block_current(BlockReason::PortRecv(port_id));
        } else {
        }
    }
}

/// Try to receive from a port, or park the current thread as a waiter.
/// Returns Ok(msg) if a message was immediately available.
/// Returns Err(()) if the thread was parked (message will be injected by sender).
pub fn recv_or_park(port_id: PortId) -> Result<Message, ()> {
    use crate::sched::thread::BlockReason;
    use crate::sync::turnstile::{KEY_PORT_RECV_PARK, KEY_PORT_SEND};

    let my_tid = crate::sched::current_thread_id();
    crate::sched::reset_priority(my_tid);

    let port = match port_ref(port_id) {
        Some(p) => p,
        None => return Err(()),
    };
    if port.is_kernel_held() {
        return Err(());
    }
    let q = match port.mpsc() {
        Some(q) => q,
        None => return Err(()),
    };
    if let Some(msg) = q.recv() {
        crate::sync::turnstile::port_wake_one(port_id, KEY_PORT_SEND);
        crate::sched::stats::IPC_RECVS.fetch_add(1, Ordering::Relaxed);
        crate::sched::boost_priority(my_tid, msg.data[5] as u8);
        return Ok(msg);
    }

    // Park: enqueue as parked receiver with lost-wakeup check, then go off-CPU.
    // Uses KEY_PORT_RECV_PARK so send_direct can distinguish parked receivers
    // (eligible for direct message injection) from normal recv blockers.
    let enqueued = crate::sync::turnstile::port_enqueue_with_check(
        port_id,
        KEY_PORT_RECV_PARK,
        my_tid,
        || {
            // Re-check: still empty?
            match port_ref(port_id) {
                Some(p) => match p.mpsc() {
                    Some(q2) => q2.is_empty(),
                    None => false,
                },
                None => false,
            }
        },
    );
    if enqueued {
        crate::sched::scheduler::park_current_for_ipc(BlockReason::PortRecv(port_id));
        Err(())
    } else {
        // Condition changed (message arrived) — retry recv.
        if let Some(msg) = q.recv() {
            crate::sync::turnstile::port_wake_one(port_id, KEY_PORT_SEND);
            crate::sched::stats::IPC_RECVS.fetch_add(1, Ordering::Relaxed);
            crate::sched::boost_priority(my_tid, msg.data[5] as u8);
            Ok(msg)
        } else {
            Err(())
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel-held port API
// ---------------------------------------------------------------------------

/// Call a port's kernel handler directly (synchronous request-reply).
#[allow(dead_code)]
pub fn call_kernel_handler(port_id: PortId, msg: &Message) -> Option<Message> {
    let port = port_ref(port_id)?;
    if !port.is_kernel_held() { return None; }
    let handler_fn: KernelHandler = unsafe { core::mem::transmute(port.kernel_handler) };
    Some(handler_fn(port_id, port.kernel_user_data, msg))
}
