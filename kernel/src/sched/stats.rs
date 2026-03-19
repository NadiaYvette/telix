//! Scheduler and IPC statistics counters.

use core::sync::atomic::AtomicU64;

pub static CONTEXT_SWITCHES: AtomicU64 = AtomicU64::new(0);
pub static SYSCALLS: AtomicU64 = AtomicU64::new(0);
pub static IPC_SENDS: AtomicU64 = AtomicU64::new(0);
pub static IPC_RECVS: AtomicU64 = AtomicU64::new(0);
