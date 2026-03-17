//! Safe syscall wrappers for Telix userspace.

use crate::arch;

// Syscall numbers (must match kernel/src/syscall/handlers.rs).
const SYS_DEBUG_PUTCHAR: u64 = 0;
const SYS_PORT_CREATE: u64 = 1;
const SYS_SEND: u64 = 3;
const SYS_SEND_NB: u64 = 9;
const SYS_RECV: u64 = 4;
const SYS_YIELD: u64 = 7;
const SYS_THREAD_ID: u64 = 8;
const SYS_EXIT: u64 = 11;
const SYS_SPAWN: u64 = 12;
const SYS_DEBUG_PUTS: u64 = 14;
const SYS_WAITPID: u64 = 15;

/// Print a single character to the debug console.
pub fn debug_putchar(ch: u8) {
    unsafe { arch::syscall1(SYS_DEBUG_PUTCHAR, ch as u64); }
}

/// Print a string to the debug console.
pub fn debug_puts(s: &[u8]) {
    unsafe { arch::syscall2(SYS_DEBUG_PUTS, s.as_ptr() as u64, s.len() as u64); }
}

/// Create a new IPC port. Returns port ID or u64::MAX on error.
pub fn port_create() -> u64 {
    unsafe { arch::syscall0(SYS_PORT_CREATE) }
}

/// Non-blocking send on a port.
pub fn send_nb(port: u32, tag: u64, d0: u64, d1: u64) -> u64 {
    unsafe { arch::syscall6(SYS_SEND_NB, port as u64, tag, d0, d1, 0, 0) }
}

/// Blocking send on a port.
pub fn send(port: u32, tag: u64, d0: u64, d1: u64, d2: u64, d3: u64) -> u64 {
    unsafe { arch::syscall6(SYS_SEND, port as u64, tag, d0, d1, d2, d3) }
}

/// Blocking receive on a port. Returns status only.
pub fn recv(port: u32) -> u64 {
    unsafe { arch::syscall1(SYS_RECV, port as u64) }
}

/// Yield the current time slice.
pub fn yield_now() {
    unsafe { arch::syscall0(SYS_YIELD); }
}

/// Get the current thread ID.
pub fn thread_id() -> u64 {
    unsafe { arch::syscall0(SYS_THREAD_ID) }
}

/// Terminate the current thread/process.
pub fn exit(code: u64) -> ! {
    unsafe { arch::syscall1(SYS_EXIT, code); }
    // Should never return, but loop just in case.
    loop { core::hint::spin_loop(); }
}

/// Spawn a new process from an ELF in initramfs.
/// Returns thread ID or u64::MAX on error.
pub fn spawn(name: &[u8], priority: u8) -> u64 {
    unsafe { arch::syscall3(SYS_SPAWN, name.as_ptr() as u64, name.len() as u64, priority as u64) }
}

/// Wait for a child thread to exit. Returns Some(exit_code) or None.
pub fn waitpid(child_tid: u64) -> Option<u64> {
    let r = unsafe { arch::syscall1(SYS_WAITPID, child_tid) };
    if r == u64::MAX { None } else { Some(r) }
}
