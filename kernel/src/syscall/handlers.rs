//! Syscall dispatch and handler implementations.
//!
//! Syscall ABI: number in x8, args in x0-x5, return value in x0.
//! Invoked via `svc #0` from EL0 (or EL1 for testing).

use crate::arch::aarch64::exception::ExceptionFrame;

// Syscall numbers.
pub const SYS_DEBUG_PUTCHAR: u64 = 0;
pub const SYS_PORT_CREATE: u64 = 1;
pub const SYS_PORT_DESTROY: u64 = 2;
pub const SYS_SEND: u64 = 3;
pub const SYS_RECV: u64 = 4;
pub const SYS_PORT_SET_CREATE: u64 = 5;
pub const SYS_PORT_SET_ADD: u64 = 6;
pub const SYS_YIELD: u64 = 7;
pub const SYS_THREAD_ID: u64 = 8;

/// Dispatch a syscall from an exception frame.
/// The frame is mutable so we can set the return value in x0.
pub fn dispatch(frame: &mut ExceptionFrame) {
    let nr = frame.regs[8]; // x8 = syscall number
    let a0 = frame.regs[0];
    let a1 = frame.regs[1];
    let a2 = frame.regs[2];
    let a3 = frame.regs[3];
    let a4 = frame.regs[4];
    let a5 = frame.regs[5];

    let result = match nr {
        SYS_DEBUG_PUTCHAR => sys_debug_putchar(a0),
        SYS_PORT_CREATE => sys_port_create(),
        SYS_PORT_DESTROY => sys_port_destroy(a0),
        SYS_SEND => sys_send(a0, a1, [a2, a3, a4, a5, 0, 0]),
        SYS_RECV => sys_recv(a0, frame),
        SYS_PORT_SET_CREATE => sys_port_set_create(),
        SYS_PORT_SET_ADD => sys_port_set_add(a0, a1),
        SYS_YIELD => sys_yield(),
        SYS_THREAD_ID => sys_thread_id(),
        _ => {
            crate::println!("Unknown syscall: {}", nr);
            u64::MAX // -1 as error
        }
    };

    frame.regs[0] = result; // Return value in x0.
}

fn sys_debug_putchar(ch: u64) -> u64 {
    crate::arch::aarch64::serial::putc(ch as u8);
    0
}

fn sys_port_create() -> u64 {
    match crate::ipc::port::create() {
        Some(id) => id as u64,
        None => u64::MAX,
    }
}

fn sys_port_destroy(port_id: u64) -> u64 {
    crate::ipc::port::destroy(port_id as u32);
    0
}

fn sys_send(port_id: u64, tag: u64, data: [u64; 6]) -> u64 {
    let msg = crate::ipc::Message::new(tag, data);
    match crate::ipc::port::send(port_id as u32, msg) {
        Ok(()) => 0,
        Err(_) => 1, // Queue full.
    }
}

fn sys_recv(port_id: u64, frame: &mut ExceptionFrame) -> u64 {
    match crate::ipc::port::recv(port_id as u32) {
        Ok(msg) => {
            // Return message data in x1-x7 via the frame.
            frame.regs[1] = msg.tag;
            frame.regs[2] = msg.data[0];
            frame.regs[3] = msg.data[1];
            frame.regs[4] = msg.data[2];
            frame.regs[5] = msg.data[3];
            frame.regs[6] = msg.data[4];
            frame.regs[7] = msg.data[5];
            0 // Success.
        }
        Err(()) => 1, // Queue empty.
    }
}

fn sys_port_set_create() -> u64 {
    match crate::ipc::port_set::create() {
        Some(id) => id as u64,
        None => u64::MAX,
    }
}

fn sys_port_set_add(set_id: u64, port_id: u64) -> u64 {
    if crate::ipc::port_set::add_port(set_id as u32, port_id as u32) {
        0
    } else {
        1
    }
}

fn sys_yield() -> u64 {
    // For now, just return — preemption via timer handles scheduling.
    0
}

fn sys_thread_id() -> u64 {
    crate::sched::scheduler::current_thread_id() as u64
}
