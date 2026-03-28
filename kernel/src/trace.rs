//! Lightweight kernel event tracing ring buffer.
//!
//! When disabled (default), all `trace_event()` calls are no-ops (single
//! branch on an atomic bool, predicted not-taken). When enabled, events
//! are recorded into a fixed-size ring buffer readable from userspace
//! via `SYS_TRACE_READ`.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// A single trace entry. Must match `userlib::profile::TraceEntry` exactly.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct TraceEntry {
    pub timestamp: u64,
    pub arg0: u32,
    pub arg1: u32,
    pub event_type: u16,
    pub cpu: u8,
    pub tid: u8,
}

// Event type constants.
pub const EVT_CTX_SWITCH: u16 = 1;
pub const EVT_SYSCALL_ENTER: u16 = 2;
pub const EVT_SYSCALL_EXIT: u16 = 3;
pub const EVT_IPC_SEND: u16 = 4;
pub const EVT_IPC_RECV: u16 = 5;
#[allow(dead_code)]
pub const EVT_PAGE_FAULT: u16 = 6;

const TRACE_BUF_SIZE: usize = 4096;

static ENABLED: AtomicBool = AtomicBool::new(false);
static HEAD: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);

const EMPTY_ENTRY: TraceEntry = TraceEntry {
    timestamp: 0,
    arg0: 0,
    arg1: 0,
    event_type: 0,
    cpu: 0,
    tid: 0,
};
static mut BUFFER: [TraceEntry; TRACE_BUF_SIZE] = [EMPTY_ENTRY; TRACE_BUF_SIZE];

/// Record a trace event. No-op when tracing is disabled.
#[inline(always)]
pub fn trace_event(event_type: u16, arg0: u32, arg1: u32) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    trace_event_inner(event_type, arg0, arg1);
}

#[inline(never)]
fn trace_event_inner(event_type: u16, arg0: u32, arg1: u32) {
    let timestamp = read_cycles();
    let cpu = crate::sched::smp::cpu_id() as u8;
    let tid = crate::sched::current_thread_id() as u8;

    let idx = HEAD.fetch_add(1, Ordering::Relaxed) % TRACE_BUF_SIZE;
    COUNT.fetch_add(1, Ordering::Relaxed);

    unsafe {
        BUFFER[idx] = TraceEntry {
            timestamp,
            arg0,
            arg1,
            event_type,
            cpu,
            tid,
        };
    }
}

fn read_cycles() -> u64 {
    crate::arch::timer::read_cycles()
}

/// Control tracing: 0=disable, 1=enable, 2=clear+disable.
pub fn trace_ctrl(op: u64) -> u64 {
    match op {
        0 => {
            ENABLED.store(false, Ordering::Release);
            0
        }
        1 => {
            ENABLED.store(true, Ordering::Release);
            0
        }
        2 => {
            ENABLED.store(false, Ordering::Release);
            HEAD.store(0, Ordering::Release);
            COUNT.store(0, Ordering::Release);
            0
        }
        _ => u64::MAX,
    }
}

/// Read trace entries into a userspace buffer. Returns number of entries copied.
pub fn trace_read(pt_root: usize, user_buf: usize, max_entries: usize) -> u64 {
    let was_enabled = ENABLED.load(Ordering::Acquire);
    ENABLED.store(false, Ordering::Release);

    let total = COUNT.load(Ordering::Acquire);
    let head = HEAD.load(Ordering::Acquire);

    let available = total.min(TRACE_BUF_SIZE);
    let to_copy = available.min(max_entries);

    if to_copy == 0 {
        if was_enabled {
            ENABLED.store(true, Ordering::Release);
        }
        return 0;
    }

    let start = if total > TRACE_BUF_SIZE {
        head % TRACE_BUF_SIZE
    } else {
        0
    };

    let entry_size = core::mem::size_of::<TraceEntry>();
    for i in 0..to_copy {
        let buf_idx = (start + i) % TRACE_BUF_SIZE;
        let entry = unsafe { &BUFFER[buf_idx] };
        let src = entry as *const TraceEntry as *const u8;
        let src_slice = unsafe { core::slice::from_raw_parts(src, entry_size) };
        let dst_va = user_buf + i * entry_size;
        if !crate::syscall::handlers::copy_to_user(pt_root, dst_va, src_slice) {
            if was_enabled {
                ENABLED.store(true, Ordering::Release);
            }
            return i as u64;
        }
    }

    if was_enabled {
        ENABLED.store(true, Ordering::Release);
    }
    to_copy as u64
}
