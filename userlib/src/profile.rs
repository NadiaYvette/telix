//! Profiling helpers for Telix userspace.
//!
//! Named wrappers around SYS_VM_STATS for all kernel counters,
//! and control/readout functions for the kernel trace ring buffer.

use crate::arch;

const SYS_VM_STATS: u64 = 42;
const SYS_TRACE_CTRL: u64 = 50;
const SYS_TRACE_READ: u64 = 51;

// Stat index constants (must match kernel sys_vm_stats indices).
pub const STAT_SUPERPAGE_PROMOTIONS: u32 = 0;
pub const STAT_SUPERPAGE_DEMOTIONS: u32 = 1;
pub const STAT_MAJOR_FAULTS: u32 = 2;
pub const STAT_MINOR_FAULTS: u32 = 3;
pub const STAT_COSCHED_HITS: u32 = 4;
pub const STAT_PAGES_ZEROED: u32 = 5;
pub const STAT_PTES_INSTALLED: u32 = 6;
pub const STAT_PTES_REMOVED: u32 = 7;
pub const STAT_PAGES_RECLAIMED: u32 = 8;
pub const STAT_WSCLOCK_SCANS: u32 = 9;
pub const STAT_CONTIGUOUS_PROMOTIONS: u32 = 10;
pub const STAT_COW_FAULTS: u32 = 11;
pub const STAT_COW_PAGES_COPIED: u32 = 12;
pub const STAT_CONTEXT_SWITCHES: u32 = 13;
pub const STAT_SYSCALLS: u32 = 14;
pub const STAT_IPC_SENDS: u32 = 15;
pub const STAT_IPC_RECVS: u32 = 16;
pub const STAT_PAGES_PREZEROED: u32 = 17;

/// Read a kernel stat counter by index.
pub fn stat(which: u32) -> u64 {
    unsafe { arch::syscall1(SYS_VM_STATS, which as u64) }
}

/// A single trace entry. Must match kernel `trace::TraceEntry` exactly.
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

// Event type constants (must match kernel trace::EVT_*).
pub const EVT_CTX_SWITCH: u16 = 1;
pub const EVT_SYSCALL_ENTER: u16 = 2;
pub const EVT_SYSCALL_EXIT: u16 = 3;
pub const EVT_IPC_SEND: u16 = 4;
pub const EVT_IPC_RECV: u16 = 5;
pub const EVT_PAGE_FAULT: u16 = 6;

/// Enable kernel tracing.
pub fn trace_enable() {
    unsafe { arch::syscall1(SYS_TRACE_CTRL, 1); }
}

/// Disable kernel tracing.
pub fn trace_disable() {
    unsafe { arch::syscall1(SYS_TRACE_CTRL, 0); }
}

/// Clear the trace buffer and disable tracing.
pub fn trace_clear() {
    unsafe { arch::syscall1(SYS_TRACE_CTRL, 2); }
}

/// Read trace entries into the provided buffer. Returns entries read.
pub fn trace_read(buf: &mut [TraceEntry]) -> usize {
    unsafe {
        arch::syscall2(SYS_TRACE_READ, buf.as_mut_ptr() as u64, buf.len() as u64) as usize
    }
}
