//! Syscall dispatch and handler implementations.
//!
//! Syscall ABI:
//!   AArch64: number in x8, args in x0-x5, return value in x0. Invoked via `svc #0`.
//!   RISC-V:  number in a7, args in a0-a5, return value in a0. Invoked via `ecall`.

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::exception::ExceptionFrame;

#[cfg(target_arch = "riscv64")]
use crate::arch::riscv64::trap::TrapFrame as ExceptionFrame;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::exception::ExceptionFrame;

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
pub const SYS_SEND_NB: u64 = 9;
pub const SYS_RECV_NB: u64 = 10;
pub const SYS_EXIT: u64 = 11;
pub const SYS_SPAWN: u64 = 12;
pub const SYS_DEBUG_PUTS: u64 = 14;
pub const SYS_WAITPID: u64 = 15;

/// Get syscall number from the frame (arch-specific register).
#[inline]
fn syscall_nr(frame: &ExceptionFrame) -> u64 {
    #[cfg(target_arch = "aarch64")]
    { frame.regs[8] } // x8
    #[cfg(target_arch = "riscv64")]
    { frame.regs[16] } // a7 = x17, stored at index 16 (x(i+1) where i=16 → x17)
    #[cfg(target_arch = "x86_64")]
    { frame.rax() } // rax = syscall number
}

/// Get syscall argument by index (0-5).
#[inline]
fn syscall_arg(frame: &ExceptionFrame, n: usize) -> u64 {
    #[cfg(target_arch = "aarch64")]
    { frame.regs[n] } // x0-x5
    #[cfg(target_arch = "riscv64")]
    { frame.regs[n + 9] } // a0-a5 = x10-x15, stored at indices 9..14 (x(i+1) where i=9 → x10)
    #[cfg(target_arch = "x86_64")]
    {
        // x86-64 syscall args: rdi, rsi, rdx, r10, r8, r9
        match n {
            0 => frame.rdi(),
            1 => frame.rsi(),
            2 => frame.rdx(),
            3 => frame.r10(),
            4 => frame.r8(),
            5 => frame.r9(),
            _ => 0,
        }
    }
}

/// Set the return value in the frame.
#[inline]
fn set_return(frame: &mut ExceptionFrame, val: u64) {
    #[cfg(target_arch = "aarch64")]
    { frame.regs[0] = val; } // x0
    #[cfg(target_arch = "riscv64")]
    { frame.regs[9] = val; } // a0 = x10, stored at index 9
    #[cfg(target_arch = "x86_64")]
    { frame.set_rax(val); } // rax = return value
}

/// Set additional return register (for recv).
#[inline]
fn set_reg(frame: &mut ExceptionFrame, reg: usize, val: u64) {
    #[cfg(target_arch = "aarch64")]
    { frame.regs[reg] = val; }
    #[cfg(target_arch = "riscv64")]
    {
        // Map aarch64 x1-x7 to riscv a1-a7 (x11-x17) = indices 10-16
        frame.regs[reg + 9] = val;
    }
    #[cfg(target_arch = "x86_64")]
    {
        // Map recv return registers: 1=rdi, 2=rsi, 3=rdx, 4=r10, 5=r8, 6=r9, 7=rbx
        match reg {
            1 => frame.set_rdi(val),
            2 => frame.set_rsi(val),
            3 => frame.set_rdx(val),
            4 => frame.set_r10(val),
            5 => frame.set_r8(val),
            6 => frame.set_r9(val),
            7 => frame.set_rbx(val),
            _ => {}
        }
    }
}

/// Dispatch a syscall from an exception frame.
/// The frame is mutable so we can set the return value.
pub fn dispatch(frame: &mut ExceptionFrame) {
    let nr = syscall_nr(frame);
    let a0 = syscall_arg(frame, 0);
    let a1 = syscall_arg(frame, 1);
    let a2 = syscall_arg(frame, 2);
    let a3 = syscall_arg(frame, 3);
    let a4 = syscall_arg(frame, 4);
    let a5 = syscall_arg(frame, 5);

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
        SYS_SEND_NB => sys_send_nb(a0, a1, [a2, a3, a4, a5, 0, 0]),
        SYS_RECV_NB => sys_recv_nb(a0, frame),
        SYS_EXIT => sys_exit(a0),
        SYS_SPAWN => sys_spawn(a0, a1, a2),
        SYS_DEBUG_PUTS => sys_debug_puts(a0, a1),
        SYS_WAITPID => sys_waitpid(a0),
        _ => {
            crate::println!("Unknown syscall: {}", nr);
            u64::MAX // -1 as error
        }
    };

    set_return(frame, result);
}

fn sys_debug_putchar(ch: u64) -> u64 {
    crate::arch::platform::serial::putc(ch as u8);
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
        Err(()) => 1,
    }
}

fn sys_send_nb(port_id: u64, tag: u64, data: [u64; 6]) -> u64 {
    let msg = crate::ipc::Message::new(tag, data);
    match crate::ipc::port::send_nb(port_id as u32, msg) {
        Ok(()) => 0,
        Err(_) => 1, // Queue full.
    }
}

fn sys_recv(port_id: u64, frame: &mut ExceptionFrame) -> u64 {
    match crate::ipc::port::recv(port_id as u32) {
        Ok(msg) => {
            set_reg(frame, 1, msg.tag);
            set_reg(frame, 2, msg.data[0]);
            set_reg(frame, 3, msg.data[1]);
            set_reg(frame, 4, msg.data[2]);
            set_reg(frame, 5, msg.data[3]);
            set_reg(frame, 6, msg.data[4]);
            set_reg(frame, 7, msg.data[5]);
            0
        }
        Err(()) => 1,
    }
}

fn sys_recv_nb(port_id: u64, frame: &mut ExceptionFrame) -> u64 {
    match crate::ipc::port::recv_nb(port_id as u32) {
        Ok(msg) => {
            set_reg(frame, 1, msg.tag);
            set_reg(frame, 2, msg.data[0]);
            set_reg(frame, 3, msg.data[1]);
            set_reg(frame, 4, msg.data[2]);
            set_reg(frame, 5, msg.data[3]);
            set_reg(frame, 6, msg.data[4]);
            set_reg(frame, 7, msg.data[5]);
            0
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

fn sys_exit(code: u64) -> u64 {
    crate::sched::scheduler::exit_current_thread(code as i32);
    // unreachable
}

fn sys_waitpid(child_tid: u64) -> u64 {
    match crate::sched::scheduler::waitpid(child_tid as u32) {
        Some(code) => code as u64,
        None => u64::MAX,
    }
}

fn sys_spawn(name_ptr: u64, name_len: u64, priority: u64) -> u64 {
    let pt_root = crate::sched::scheduler::current_page_table_root();
    let len = (name_len as usize).min(64);

    // Copy the filename from user memory.
    let mut buf = [0u8; 64];
    if !copy_from_user(pt_root, name_ptr as usize, &mut buf[..len]) {
        return u64::MAX;
    }

    let name = &buf[..len];
    match crate::sched::scheduler::spawn_user(name, priority as u8, 20) {
        Some(tid) => tid as u64,
        None => u64::MAX,
    }
}

fn sys_debug_puts(buf_ptr: u64, buf_len: u64) -> u64 {
    let pt_root = crate::sched::scheduler::current_page_table_root();
    let len = (buf_len as usize).min(256);
    let mut buf = [0u8; 256];
    if !copy_from_user(pt_root, buf_ptr as usize, &mut buf[..len]) {
        return u64::MAX;
    }
    for &ch in &buf[..len] {
        crate::arch::platform::serial::putc(ch);
    }
    0
}

/// Copy `dst.len()` bytes from user virtual address `user_va` into `dst`,
/// using the page table at `pt_root` to translate addresses.
fn copy_from_user(pt_root: usize, user_va: usize, dst: &mut [u8]) -> bool {
    if pt_root == 0 {
        // Kernel thread — direct access.
        unsafe {
            core::ptr::copy_nonoverlapping(user_va as *const u8, dst.as_mut_ptr(), dst.len());
        }
        return true;
    }

    let mut offset = 0;
    while offset < dst.len() {
        let va = user_va + offset;
        let pa = {
            #[cfg(target_arch = "aarch64")]
            { crate::arch::aarch64::mm::translate_va(pt_root, va) }
            #[cfg(target_arch = "riscv64")]
            { crate::arch::riscv64::mm::translate_va(pt_root, va) }
            #[cfg(target_arch = "x86_64")]
            { crate::arch::x86_64::mm::translate_va(pt_root, va) }
        };

        let pa = match pa {
            Some(pa) => pa,
            None => return false,
        };

        // Copy up to the end of this 4K page.
        let page_remaining = 4096 - (pa & 0xFFF);
        let to_copy = page_remaining.min(dst.len() - offset);
        unsafe {
            core::ptr::copy_nonoverlapping(
                pa as *const u8,
                dst.as_mut_ptr().add(offset),
                to_copy,
            );
        }
        offset += to_copy;
    }
    true
}
