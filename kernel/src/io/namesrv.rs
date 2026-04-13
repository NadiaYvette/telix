//! Service registry — maps service names to IPC port IDs.
//!
//! Implemented as kernel-internal functions called directly from syscall
//! handlers (`SYS_SVC_REGISTER`, `SYS_SVC_LOOKUP`). This replaces the
//! previous design where a kernel thread processed IPC messages — that
//! approach was fragile because the reply-port dance could lose wakeups
//! and hang callers indefinitely.
//!
//! Blocking lookups (`SVC_LOOKUP_WAIT` flag) park the calling thread and
//! wake it when the requested service registers. No ephemeral reply ports,
//! no message queues, no scheduling-order sensitivity.

use crate::mm::paged_array::PagedArray;
use crate::sched::thread::BlockReason;
use crate::sync::SpinLock;

const MAX_SVC_NAME: usize = 24;

struct ServiceEntry {
    name: [u8; MAX_SVC_NAME],
    name_len: usize,
    port_id: u64,
    active: bool,
}

impl ServiceEntry {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_SVC_NAME],
            name_len: 0,
            port_id: 0,
            active: false,
        }
    }
}

/// A thread blocked in `SYS_SVC_LOOKUP` with the `WAIT` flag.
struct SvcWaiter {
    name: [u8; MAX_SVC_NAME],
    name_len: usize,
    tid: u32,
    active: bool,
}

impl SvcWaiter {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_SVC_NAME],
            name_len: 0,
            tid: 0,
            active: false,
        }
    }
}

struct NameTable {
    entries: PagedArray<ServiceEntry>,
    count: usize,
    waiters: PagedArray<SvcWaiter>,
    waiter_count: usize,
}

impl NameTable {
    const fn new() -> Self {
        Self {
            entries: PagedArray::new(),
            count: 0,
            waiters: PagedArray::new(),
            waiter_count: 0,
        }
    }

    fn register(&mut self, name: &[u8], port_id: u64) -> bool {
        // Update if already registered.
        for i in 0..self.count {
            let e = self.entries.get(i);
            if e.active && e.name_len == name.len() && &e.name[..name.len()] == name {
                self.entries.get_mut(i).port_id = port_id;
                return true;
            }
        }
        if !self.entries.ensure_capacity(self.count + 1) {
            return false;
        }
        let e = self.entries.get_mut(self.count);
        *e = ServiceEntry::empty();
        let len = name.len().min(MAX_SVC_NAME);
        e.name[..len].copy_from_slice(&name[..len]);
        e.name_len = len;
        e.port_id = port_id;
        e.active = true;
        self.count += 1;
        true
    }

    fn lookup(&self, name: &[u8]) -> Option<u64> {
        for i in 0..self.count {
            let e = self.entries.get(i);
            if e.active && e.name_len == name.len() && &e.name[..name.len()] == name {
                return Some(e.port_id);
            }
        }
        None
    }

    /// Add a waiter for a service name. Returns true if added.
    fn add_waiter(&mut self, name: &[u8], tid: u32) -> bool {
        if !self.waiters.ensure_capacity(self.waiter_count + 1) {
            return false;
        }
        let w = self.waiters.get_mut(self.waiter_count);
        *w = SvcWaiter::empty();
        let len = name.len().min(MAX_SVC_NAME);
        w.name[..len].copy_from_slice(&name[..len]);
        w.name_len = len;
        w.tid = tid;
        w.active = true;
        self.waiter_count += 1;
        true
    }

    /// Collect thread IDs of waiters matching a service name, marking them inactive.
    /// Returns the number of waiters found (writes into `out`).
    fn drain_waiters(&mut self, name: &[u8], out: &mut [u32; 32]) -> usize {
        let mut n = 0;
        for i in 0..self.waiter_count {
            let w = self.waiters.get_mut(i);
            if w.active && w.name_len == name.len() && &w.name[..name.len()] == name {
                if n < 32 {
                    out[n] = w.tid;
                    n += 1;
                }
                w.active = false;
            }
        }
        n
    }
}

static TABLE: SpinLock<NameTable> = SpinLock::new(NameTable::new());

/// Register a service. Called from `SYS_SVC_REGISTER`.
///
/// Returns 0 on success, 1 on failure (table full).
/// Wakes any threads blocked in `svc_lookup(..., WAIT)` for this name.
pub fn svc_register(name: &[u8], port_id: u64) -> u64 {
    let mut wake_tids = [0u32; 32];
    let wake_count;

    {
        let mut table = TABLE.lock();
        if !table.register(name, port_id) {
            return 1;
        }
        wake_count = table.drain_waiters(name, &mut wake_tids);
    }
    // Drop the lock before waking — wake_thread may reschedule.

    // Grant SEND capability to each woken waiter's task.
    for i in 0..wake_count {
        let tid = wake_tids[i];
        let task_id = crate::sched::scheduler::thread_ref(tid).task_id;
        crate::cap::grant_send_cap(task_id, port_id);
        crate::sched::scheduler::wake_thread(tid);
    }

    if name.len() <= 16 {
        let mut buf = [0u8; 16];
        buf[..name.len()].copy_from_slice(name);
        crate::println!(
            "  [svc] registered {:?} on port {}",
            core::str::from_utf8(&buf[..name.len()]).unwrap_or("?"),
            port_id
        );
    }

    0
}

/// Look up a service by name. Called from `SYS_SVC_LOOKUP`.
///
/// If `wait` is true and the service is not yet registered, the calling
/// thread is parked until a matching `svc_register` arrives.
///
/// Returns the service port ID, or 0 if not found (and `wait` is false).
/// On success, grants SEND capability on the service port to the caller.
pub fn svc_lookup(name: &[u8], wait: bool) -> u64 {
    let tid = crate::sched::current_thread_id();
    let task_id = crate::sched::scheduler::current_task_id();

    loop {
        let mut table = TABLE.lock();
        if let Some(port_id) = table.lookup(name) {
            drop(table);
            crate::cap::grant_send_cap(task_id, port_id);
            return port_id;
        }
        if !wait {
            return 0;
        }
        // Park: add ourselves as a waiter, then block.
        if !table.add_waiter(name, tid) {
            return 0; // waiter table full — shouldn't happen
        }
        drop(table);

        crate::sched::block_current(BlockReason::SvcLookup);

        // Woken by svc_register — loop back to look up the port.
        // (We loop rather than trusting the waker because another thread
        // could have consumed the registration in a narrow race.)
    }
}
