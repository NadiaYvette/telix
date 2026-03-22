//! Syscall dispatch and handler implementations.
//!
//! Syscall ABI:
//!   AArch64: number in x8, args in x0-x5, return value in x0. Invoked via `svc #0`.
//!   RISC-V:  number in a7, args in a0-a5, return value in a0. Invoked via `ecall`.

#[cfg(target_arch = "aarch64")]
pub(crate) use crate::arch::aarch64::exception::ExceptionFrame;

#[cfg(target_arch = "riscv64")]
pub(crate) use crate::arch::riscv64::trap::TrapFrame as ExceptionFrame;

#[cfg(target_arch = "x86_64")]
pub(crate) use crate::arch::x86_64::exception::ExceptionFrame;

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
pub const SYS_MMAP_ANON: u64 = 16;
pub const SYS_MUNMAP: u64 = 17;
pub const SYS_GRANT_PAGES: u64 = 18;
pub const SYS_REVOKE: u64 = 19;
pub const SYS_ASPACE_ID: u64 = 20;
pub const SYS_GET_INITRAMFS_PORT: u64 = 21;
pub const SYS_PORT_SET_RECV: u64 = 22;
pub const SYS_NSRV_PORT: u64 = 23;
pub const SYS_MMAP_DEVICE: u64 = 24;
pub const SYS_VIRT_TO_PHYS: u64 = 25;
pub const SYS_IRQ_WAIT: u64 = 26;
pub const SYS_GETCHAR: u64 = 27;
pub const SYS_IOPORT: u64 = 28;
pub const SYS_SPAWN_ELF: u64 = 29;
pub const SYS_THREAD_CREATE: u64 = 30;
pub const SYS_THREAD_JOIN: u64 = 31;
pub const SYS_FUTEX_WAIT: u64 = 32;
pub const SYS_FUTEX_WAKE: u64 = 33;
pub const SYS_KILL: u64 = 34;
pub const SYS_GETPID: u64 = 35;
pub const SYS_GET_CYCLES: u64 = 36;
pub const SYS_GET_TIMER_FREQ: u64 = 37;
pub const SYS_SET_QUOTA: u64 = 38;
pub const SYS_FORK: u64 = 39;
pub const SYS_SEND_CAP: u64 = 40;
pub const SYS_CAP_REVOKE: u64 = 41;
pub const SYS_VM_STATS: u64 = 42;
pub const SYS_SA_REGISTER: u64 = 43;
pub const SYS_SA_WAIT: u64 = 44;
pub const SYS_SA_GETID: u64 = 45;
pub const SYS_COSCHED_SET: u64 = 46;
pub const SYS_SET_AFFINITY: u64 = 47;
pub const SYS_GET_AFFINITY: u64 = 48;
pub const SYS_CPU_TOPOLOGY: u64 = 49;
pub const SYS_TRACE_CTRL: u64 = 50;
pub const SYS_TRACE_READ: u64 = 51;
pub const SYS_CPU_HOTPLUG: u64 = 52;
pub const SYS_CPU_LOAD: u64 = 53;
pub const SYS_EXECVE: u64 = 54;
pub const SYS_SIGACTION: u64 = 55;
pub const SYS_SIGPROCMASK: u64 = 56;
pub const SYS_SIGRETURN: u64 = 57;
pub const SYS_KILL_SIG: u64 = 58;
pub const SYS_SIGPENDING: u64 = 59;
pub const SYS_MPROTECT: u64 = 60;
pub const SYS_MREMAP: u64 = 61;
pub const SYS_SETPGID: u64 = 62;
pub const SYS_GETPGID: u64 = 63;
pub const SYS_SETSID: u64 = 64;
pub const SYS_GETSID: u64 = 65;
pub const SYS_TCSETPGRP: u64 = 66;
pub const SYS_TCGETPGRP: u64 = 67;
pub const SYS_SET_CTTY: u64 = 68;
pub const SYS_CLOCK_GETTIME: u64 = 69;
pub const SYS_NANOSLEEP: u64 = 70;
pub const SYS_ALARM: u64 = 71;
pub const SYS_MMAP_FILE: u64 = 72;
pub const SYS_WAIT_FAULT: u64 = 73;
pub const SYS_FAULT_COMPLETE: u64 = 74;
pub const SYS_GETUID: u64 = 75;
pub const SYS_GETEUID: u64 = 76;
pub const SYS_GETGID: u64 = 77;
pub const SYS_GETEGID: u64 = 78;
pub const SYS_SETUID: u64 = 79;
pub const SYS_SETGID: u64 = 80;
pub const SYS_SETGROUPS: u64 = 81;
pub const SYS_GETGROUPS: u64 = 82;
pub const SYS_WAIT4: u64 = 83;
pub const SYS_GETRLIMIT: u64 = 84;
pub const SYS_SETRLIMIT: u64 = 85;
pub const SYS_PRLIMIT: u64 = 86;
pub const SYS_YIELD_BLOCK: u64 = 87;

/// Error code: capability check failed.
const ECAP: u64 = 2;

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
pub(crate) fn set_return(frame: &mut ExceptionFrame, val: u64) {
    #[cfg(target_arch = "aarch64")]
    { frame.regs[0] = val; } // x0
    #[cfg(target_arch = "riscv64")]
    { frame.regs[9] = val; } // a0 = x10, stored at index 9
    #[cfg(target_arch = "x86_64")]
    { frame.set_rax(val); } // rax = return value
}

/// Set additional return register (for recv).
#[inline]
pub(crate) fn set_reg(frame: &mut ExceptionFrame, reg: usize, val: u64) {
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

    crate::sched::stats::SYSCALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    crate::trace::trace_event(crate::trace::EVT_SYSCALL_ENTER, nr as u32, 0);

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
        SYS_SPAWN => sys_spawn(a0, a1, a2, a3),
        SYS_DEBUG_PUTS => sys_debug_puts(a0, a1),
        SYS_WAITPID => sys_waitpid(a0),
        SYS_MMAP_ANON => sys_mmap_anon(a0, a1, a2),
        SYS_MUNMAP => sys_munmap(a0),
        SYS_GRANT_PAGES => sys_grant_pages(a0, a1, a2, a3, a4),
        SYS_REVOKE => sys_revoke(a0, a1),
        SYS_ASPACE_ID => sys_aspace_id(),
        SYS_GET_INITRAMFS_PORT => sys_get_initramfs_port(),
        SYS_PORT_SET_RECV => sys_port_set_recv(a0, frame),
        SYS_NSRV_PORT => sys_nsrv_port(),
        SYS_MMAP_DEVICE => sys_mmap_device(a0, a1),
        SYS_VIRT_TO_PHYS => sys_virt_to_phys(a0),
        SYS_IRQ_WAIT => sys_irq_wait(a0, a1),
        SYS_GETCHAR => sys_getchar(),
        SYS_IOPORT => sys_ioport(a0, a1, a2),
        SYS_SPAWN_ELF => sys_spawn_elf(a0, a1, a2, a3),
        SYS_THREAD_CREATE => sys_thread_create(a0, a1, a2),
        SYS_THREAD_JOIN => sys_thread_join(a0),
        SYS_FUTEX_WAIT => crate::sync::futex::futex_wait(a0 as usize, a1 as u32),
        SYS_FUTEX_WAKE => crate::sync::futex::futex_wake(a0 as usize, a1 as u32),
        SYS_KILL => sys_kill(a0),
        SYS_GETPID => sys_getpid(),
        SYS_GET_CYCLES => sys_get_cycles(),
        SYS_GET_TIMER_FREQ => sys_get_timer_freq(),
        SYS_SET_QUOTA => sys_set_quota(a0, a1, a2),
        SYS_FORK => crate::sched::scheduler::fork_current(),
        SYS_SEND_CAP => sys_send_cap(a0, a1, a2, a3, a4, a5),
        SYS_CAP_REVOKE => sys_cap_revoke(a0),
        SYS_VM_STATS => sys_vm_stats(a0),
        SYS_SA_REGISTER => { crate::sched::sa_register(); 0 }
        SYS_SA_WAIT => crate::sched::sa_wait(),
        SYS_SA_GETID => crate::sched::sa_getid(),
        SYS_COSCHED_SET => { crate::sched::cosched_set(a0 as u32); 0 }
        SYS_SET_AFFINITY => sys_set_affinity(a0, a1),
        SYS_GET_AFFINITY => crate::sched::get_affinity(a0 as u32),
        SYS_CPU_TOPOLOGY => sys_cpu_topology(a0),
        SYS_TRACE_CTRL => crate::trace::trace_ctrl(a0),
        SYS_TRACE_READ => {
            let pt_root = crate::sched::scheduler::current_page_table_root();
            crate::trace::trace_read(pt_root, a0 as usize, a1 as usize)
        }
        SYS_CPU_HOTPLUG => sys_cpu_hotplug(a0, a1),
        SYS_CPU_LOAD => sys_cpu_load(a0),
        SYS_EXECVE => {
            // execve completely replaces the frame — bypass set_return.
            sys_execve(a0, a1, frame);
            return;
        }
        SYS_SIGACTION => sys_sigaction(a0, a1, a2, a3),
        SYS_SIGPROCMASK => sys_sigprocmask(a0, a1),
        SYS_SIGRETURN => {
            // sigreturn restores the saved frame — bypass set_return.
            sys_sigreturn(frame);
            return;
        }
        SYS_KILL_SIG => sys_kill_sig(a0, a1),
        SYS_SIGPENDING => crate::sched::get_signal_pending(),
        SYS_MPROTECT => sys_mprotect(a0, a1, a2),
        SYS_MREMAP => sys_mremap(a0, a1, a2),
        SYS_SETPGID => {
            // User passes thread_id (from fork); convert to task_id. 0 = self.
            let pid = if a0 != 0 { crate::sched::thread_task_id(a0 as u32) } else { 0 };
            let pgid = if a1 != 0 { crate::sched::thread_task_id(a1 as u32) } else { 0 };
            crate::sched::setpgid(pid, pgid)
        },
        SYS_GETPGID => {
            let pid = if a0 != 0 { crate::sched::thread_task_id(a0 as u32) } else { 0 };
            crate::sched::getpgid(pid)
        },
        SYS_SETSID => crate::sched::setsid(),
        SYS_GETSID => {
            let pid = if a0 != 0 { crate::sched::thread_task_id(a0 as u32) } else { 0 };
            crate::sched::getsid(pid)
        },
        SYS_TCSETPGRP => crate::sched::tcsetpgrp(a0 as u32),
        SYS_TCGETPGRP => crate::sched::tcgetpgrp(),
        SYS_SET_CTTY => crate::sched::set_ctty(a0 as u32),
        SYS_CLOCK_GETTIME => sys_clock_gettime(a0),
        SYS_NANOSLEEP => sys_nanosleep(a0),
        SYS_ALARM => crate::sched::alarm(a0, a1),
        SYS_MMAP_FILE => sys_mmap_file(a0, a1, a2, a3, a4, a5),
        SYS_WAIT_FAULT => {
            sys_wait_fault(frame);
            return;
        }
        SYS_FAULT_COMPLETE => sys_fault_complete(a0, a1, a2),
        SYS_GETUID => sys_getuid(),
        SYS_GETEUID => sys_geteuid(),
        SYS_GETGID => sys_getgid(),
        SYS_GETEGID => sys_getegid(),
        SYS_SETUID => sys_setuid(a0),
        SYS_SETGID => sys_setgid(a0),
        SYS_SETGROUPS => sys_setgroups(a0, a1),
        SYS_GETGROUPS => sys_getgroups(a0, a1),
        SYS_WAIT4 => sys_wait4(a0, a1, frame),
        SYS_GETRLIMIT => sys_getrlimit(a0, frame),
        SYS_SETRLIMIT => sys_setrlimit(a0, a1, a2),
        SYS_PRLIMIT => sys_prlimit(a0, a1, a2, a3, frame),
        SYS_YIELD_BLOCK => sys_yield_block(),
        _ => {
            crate::println!("Unknown syscall: {}", nr);
            u64::MAX // -1 as error
        }
    };

    crate::trace::trace_event(crate::trace::EVT_SYSCALL_EXIT, nr as u32, result as u32);
    set_return(frame, result);

    // Check if this thread was killed — terminate before returning to userspace.
    let tid = crate::sched::scheduler::current_thread_id();
    if crate::sched::scheduler::is_killed(tid) {
        crate::sched::scheduler::exit_current_thread(-9);
    }

    // Deliver pending signals before returning to userspace (user tasks only).
    if crate::sched::scheduler::current_aspace_id() != 0 {
        deliver_pending_signals(frame);
    }
}

/// Inject a received message into a parked thread's saved exception frame.
/// Called by sender after direct-transfer from send_direct().
fn inject_recv_into_frame(receiver_tid: u32, msg: &crate::ipc::Message) {
    let sp = crate::sched::scheduler::thread_saved_sp(receiver_tid);
    let frame = unsafe { &mut *(sp as *mut ExceptionFrame) };
    set_return(frame, 0); // recv returns 0 = success
    set_reg(frame, 1, msg.tag);
    set_reg(frame, 2, msg.data[0]);
    set_reg(frame, 3, msg.data[1]);
    set_reg(frame, 4, msg.data[2]);
    set_reg(frame, 5, msg.data[3]);
    set_reg(frame, 6, msg.data[4]);
    set_reg(frame, 7, msg.data[5]);
}

/// Deliver a message to a parked (Blocked) receiver thread by injecting it into
/// the thread's saved exception frame. Also handles auto-grant caps and priority
/// inheritance. Called from port::send/send_nb when the old queue path wakes a
/// parked receiver.
pub(crate) fn deliver_to_parked_receiver(receiver_tid: u32, msg: &crate::ipc::Message) {
    inject_recv_into_frame(receiver_tid, msg);
    let receiver_task = crate::sched::scheduler::thread_task_id(receiver_tid);
    auto_grant_reply_caps(receiver_task, msg);
    crate::sched::boost_priority(receiver_tid, msg.data[5] as u8);
}

/// Check if the current task has a port capability with the needed rights.
/// Uses lockless bitmap for SEND/RECV checks (fast path).
/// Falls back to CAP_SYSTEM lock for MANAGE checks.
/// Task 0 (kernel) bypasses all checks.
#[inline]
fn check_port_cap(port_id: u32, needed: crate::cap::Rights) -> bool {
    let task_id = crate::sched::current_task_id();
    if task_id == 0 { return true; }
    // Fast path: SEND and RECV are tracked in lockless bitmaps.
    if !crate::cap::has_port_cap_fast(task_id, port_id, needed) {
        return false;
    }
    // MANAGE requires the slow path (rare — only port_destroy).
    if needed.contains(crate::cap::Rights::MANAGE) {
        let caps = crate::cap::CAP_SYSTEM.lock();
        return caps.spaces[task_id as usize].find_port_cap(port_id as usize, needed).is_some();
    }
    true
}

/// Auto-grant SEND caps for active port IDs found in message data words
/// to the receiving task. Only checks high-32 and low-32 of each word,
/// plus bits 16-47 (for protocols that pack port IDs at offset 16).
fn auto_grant_reply_caps(task_id: u32, msg: &crate::ipc::Message) {
    if task_id == 0 { return; }
    let max = crate::ipc::port::MAX_PORTS as u32;
    // Collect unique candidate port IDs that we don't already have SEND caps for.
    let mut candidates = [u32::MAX; 18];
    let mut count = 0usize;
    for i in 0..6 {
        let word = msg.data[i];
        for shift in [0u32, 16, 32] {
            let val = (word >> shift) as u32;
            if val > 0 && val < max {
                // Fast bitmap check — skip if we already have SEND cap.
                if crate::cap::has_port_cap_fast(task_id, val, crate::cap::Rights::SEND) {
                    continue;
                }
                let mut dup = false;
                for j in 0..count {
                    if candidates[j] == val { dup = true; break; }
                }
                if !dup && count < 18 {
                    candidates[count] = val;
                    count += 1;
                }
            }
        }
    }
    if count == 0 { return; }
    // Filter by port_is_active BEFORE locking CAP_SYSTEM (lock ordering).
    let mut active_count = 0usize;
    for i in 0..count {
        if crate::ipc::port::port_is_active(candidates[i]) {
            candidates[active_count] = candidates[i];
            active_count += 1;
        }
    }
    if active_count == 0 { return; }
    let mut caps = crate::cap::CAP_SYSTEM.lock();
    for i in 0..active_count {
        caps.grant_send_cap(task_id, candidates[i]);
    }
}

fn sys_debug_putchar(ch: u64) -> u64 {
    crate::arch::platform::serial::putc(ch as u8);
    0
}

fn sys_port_create() -> u64 {
    let task_id = crate::sched::current_task_id();
    // Check resource quota.
    if task_id != 0 {
        let sched = crate::sched::scheduler::SCHEDULER.lock();
        let task = &sched.tasks[task_id as usize];
        if task.cur_ports >= task.max_ports {
            return u64::MAX;
        }
        drop(sched);
    }
    match crate::ipc::port::create() {
        Some(id) => {
            // Grant full port cap (SEND|RECV|MANAGE) to creator.
            if task_id != 0 {
                let mut caps = crate::cap::CAP_SYSTEM.lock();
                caps.grant_full_port_cap(task_id, id);
            }
            // Increment port quota counter.
            if task_id != 0 {
                let mut sched = crate::sched::scheduler::SCHEDULER.lock();
                sched.tasks[task_id as usize].cur_ports += 1;
            }
            id as u64
        }
        None => u64::MAX,
    }
}

fn sys_port_destroy(port_id: u64) -> u64 {
    if !check_port_cap(port_id as u32, crate::cap::Rights::MANAGE) {
        return ECAP;
    }
    crate::ipc::port::destroy(port_id as u32);
    // Remove port caps from caller's CSpace.
    let task_id = crate::sched::current_task_id();
    if task_id != 0 {
        let mut caps = crate::cap::CAP_SYSTEM.lock();
        caps.remove_port_caps(task_id, port_id as u32);
        drop(caps);
        // Decrement port quota counter.
        let mut sched = crate::sched::scheduler::SCHEDULER.lock();
        if sched.tasks[task_id as usize].cur_ports > 0 {
            sched.tasks[task_id as usize].cur_ports -= 1;
        }
    }
    0
}

fn sys_send(port_id: u64, tag: u64, data: [u64; 6]) -> u64 {
    if !check_port_cap(port_id as u32, crate::cap::Rights::SEND) {
        return ECAP;
    }
    let mut msg = crate::ipc::Message::new(tag, data);

    match crate::ipc::port::send_direct(port_id as u32, &mut msg) {
        crate::ipc::port::SendDirectResult::DirectTransfer(receiver_tid) => {
            // L4-style direct handoff: inject message and switch to receiver.
            let receiver_task = crate::sched::scheduler::thread_task_id(receiver_tid);
            auto_grant_reply_caps(receiver_task, &msg);
            inject_recv_into_frame(receiver_tid, &msg);
            crate::sched::boost_priority(receiver_tid, msg.data[5] as u8);
            // Handoff: donate our quantum to receiver, switch immediately.
            crate::sched::scheduler::handoff_to(receiver_tid);
            0
        }
        crate::ipc::port::SendDirectResult::Queued => 0,
        crate::ipc::port::SendDirectResult::Full => {
            // Queue full — fall back to blocking send (spin-blocks until space).
            match crate::ipc::port::send(port_id as u32, msg) {
                Ok(()) => 0,
                Err(()) => 1,
            }
        }
        crate::ipc::port::SendDirectResult::Error => 1,
    }
}

fn sys_send_nb(port_id: u64, tag: u64, data: [u64; 6]) -> u64 {
    if !check_port_cap(port_id as u32, crate::cap::Rights::SEND) {
        return ECAP;
    }
    let mut msg = crate::ipc::Message::new(tag, data);

    match crate::ipc::port::send_direct(port_id as u32, &mut msg) {
        crate::ipc::port::SendDirectResult::DirectTransfer(receiver_tid) => {
            // Direct transfer: inject message into parked receiver's frame and wake.
            let receiver_task = crate::sched::scheduler::thread_task_id(receiver_tid);
            auto_grant_reply_caps(receiver_task, &msg);
            inject_recv_into_frame(receiver_tid, &msg);
            crate::sched::boost_priority(receiver_tid, msg.data[5] as u8);
            crate::sched::scheduler::wake_parked_thread(receiver_tid);
            0
        }
        crate::ipc::port::SendDirectResult::Queued => 0,
        crate::ipc::port::SendDirectResult::Full => 1,
        crate::ipc::port::SendDirectResult::Error => 1,
    }
}

fn sys_recv(port_id: u64, frame: &mut ExceptionFrame) -> u64 {
    if !check_port_cap(port_id as u32, crate::cap::Rights::RECV) {
        return ECAP;
    }
    match crate::ipc::port::recv_or_park(port_id as u32) {
        Ok(msg) => {
            // Message was immediately available from the queue.
            let task_id = crate::sched::current_task_id();
            auto_grant_reply_caps(task_id, &msg);
            set_reg(frame, 1, msg.tag);
            set_reg(frame, 2, msg.data[0]);
            set_reg(frame, 3, msg.data[1]);
            set_reg(frame, 4, msg.data[2]);
            set_reg(frame, 5, msg.data[3]);
            set_reg(frame, 6, msg.data[4]);
            set_reg(frame, 7, msg.data[5]);
            0
        }
        Err(()) => {
            // Thread was parked. A sender will inject the message directly into
            // our saved exception frame and wake us. When we resume, our frame
            // already has the return values set. Return 0 as placeholder (will
            // be overwritten by inject_recv_into_frame before we actually run).
            0
        }
    }
}

fn sys_recv_nb(port_id: u64, frame: &mut ExceptionFrame) -> u64 {
    if !check_port_cap(port_id as u32, crate::cap::Rights::RECV) {
        return ECAP;
    }
    match crate::ipc::port::recv_nb(port_id as u32) {
        Ok(msg) => {
            let task_id = crate::sched::current_task_id();
            auto_grant_reply_caps(task_id, &msg);
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
    if !check_port_cap(port_id as u32, crate::cap::Rights::RECV) {
        return ECAP;
    }
    if crate::ipc::port_set::add_port(set_id as u32, port_id as u32) {
        0
    } else {
        1
    }
}

fn sys_yield() -> u64 {
    // Set YIELD_ASAP so the next timer tick will preempt us immediately.
    let tid = crate::sched::current_thread_id();
    crate::sched::scheduler::set_yield_asap(tid);
    0
}

/// Like sys_yield but waits for the next interrupt (WFI/HLT).
/// Use when the caller has no work and wants to sleep until preempted.
fn sys_yield_block() -> u64 {
    let tid = crate::sched::current_thread_id();
    crate::sched::scheduler::set_yield_asap(tid);
    let saved = crate::sched::scheduler::arch_irq_save_enable();
    crate::sched::scheduler::arch_wait_for_irq();
    crate::sched::scheduler::arch_irq_restore(saved);
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

fn sys_kill(tid: u64) -> u64 {
    if crate::sched::scheduler::kill_task(tid as u32) { 0 } else { u64::MAX }
}

fn sys_getpid() -> u64 {
    crate::sched::scheduler::current_task_id() as u64
}

fn sys_get_cycles() -> u64 {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::timer::counter() }
    #[cfg(target_arch = "riscv64")]
    { crate::arch::riscv64::trap::read_time() }
    #[cfg(target_arch = "x86_64")]
    { crate::arch::x86_64::timer::rdtsc() }
}

fn sys_get_timer_freq() -> u64 {
    #[cfg(target_arch = "aarch64")]
    { crate::arch::aarch64::timer::cntfrq() }
    #[cfg(target_arch = "riscv64")]
    { 10_000_000 } // QEMU virt timebase
    #[cfg(target_arch = "x86_64")]
    { 1_000_000_000 } // approximate RDTSC freq on QEMU
}

fn sys_spawn(name_ptr: u64, name_len: u64, priority: u64, arg0: u64) -> u64 {
    // Enforce RLIMIT_NPROC: count active tasks owned by the same uid.
    {
        let sched = crate::sched::scheduler::SCHEDULER.lock();
        let task_id = crate::sched::current_task_id();
        let uid = sched.tasks[task_id as usize].uid;
        let nproc_limit = sched.tasks[task_id as usize]
            .rlimits[crate::sched::task::RLIMIT_NPROC as usize].cur;
        if nproc_limit != crate::sched::task::RLIM_INFINITY {
            let mut count = 0u64;
            for i in 1..crate::sched::task::MAX_TASKS {
                if sched.tasks[i].active && sched.tasks[i].uid == uid {
                    count += 1;
                }
            }
            if count >= nproc_limit {
                return u64::MAX;
            }
        }
    }

    let pt_root = crate::sched::scheduler::current_page_table_root();
    let len = (name_len as usize).min(64);

    // Copy the filename from user memory.
    let mut buf = [0u8; 64];
    if !copy_from_user(pt_root, name_ptr as usize, &mut buf[..len]) {
        return u64::MAX;
    }

    let name = &buf[..len];
    match crate::sched::scheduler::spawn_user(name, priority as u8, 20, arg0) {
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

fn sys_mmap_anon(va_hint: u64, page_count: u64, prot: u64) -> u64 {
    use crate::mm::page::{PAGE_SIZE, MMUPAGE_SIZE, PAGE_MMUCOUNT};
    use crate::mm::vma::VmaProt;

    let aspace_id = crate::sched::scheduler::current_aspace_id();
    if aspace_id == 0 {
        return u64::MAX; // kernel context
    }

    let pages = page_count as usize;
    if pages == 0 || pages > 256 {
        return u64::MAX;
    }

    // Check page quota and RLIMIT_AS.
    let task_id = crate::sched::current_task_id();
    if task_id != 0 {
        let sched = crate::sched::scheduler::SCHEDULER.lock();
        let task = &sched.tasks[task_id as usize];
        if task.cur_pages + pages as u32 > task.max_pages {
            return u64::MAX;
        }
        // Enforce RLIMIT_AS: total virtual memory in bytes.
        let new_bytes = (task.cur_pages as u64 + pages as u64) * PAGE_SIZE as u64;
        let rlimit_as = task.rlimits[crate::sched::task::RLIMIT_AS as usize].cur;
        if rlimit_as != crate::sched::task::RLIM_INFINITY && new_bytes > rlimit_as {
            return u64::MAX;
        }
        drop(sched);
    }

    let prot = match prot {
        0 => VmaProt::ReadOnly,
        1 => VmaProt::ReadWrite,
        2 => VmaProt::ReadExec,
        3 => VmaProt::ReadWriteExec,
        _ => return u64::MAX,
    };

    // Determine VA: auto-pick if hint is 0, otherwise use hint.
    let va = if va_hint == 0 {
        crate::mm::aspace::with_aspace(aspace_id, |aspace| {
            aspace.alloc_heap_va(pages)
        })
    } else {
        va_hint as usize
    };

    // Create VMA + backing object.
    let obj_id = match crate::mm::aspace::with_aspace(aspace_id, |aspace| {
        aspace.map_anon(va, pages, prot).map(|vma| vma.object_id)
    }) {
        Some(id) => id,
        None => return u64::MAX,
    };

    // Eagerly allocate physical pages and install PTEs.
    let pt_root = crate::sched::scheduler::current_page_table_root();

    #[cfg(target_arch = "aarch64")]
    let pte_flags = match prot {
        VmaProt::ReadOnly => crate::arch::aarch64::mm::USER_RO_FLAGS,
        VmaProt::ReadWrite => crate::arch::aarch64::mm::USER_RW_FLAGS,
        VmaProt::ReadExec => crate::arch::aarch64::mm::USER_RWX_FLAGS,
        VmaProt::ReadWriteExec => crate::arch::aarch64::mm::USER_RWX_FLAGS,
    };
    #[cfg(target_arch = "riscv64")]
    let pte_flags = match prot {
        VmaProt::ReadOnly => crate::arch::riscv64::mm::USER_RO_FLAGS,
        VmaProt::ReadWrite => crate::arch::riscv64::mm::USER_RW_FLAGS,
        VmaProt::ReadExec => crate::arch::riscv64::mm::USER_RWX_FLAGS,
        VmaProt::ReadWriteExec => crate::arch::riscv64::mm::USER_RWX_FLAGS,
    };
    #[cfg(target_arch = "x86_64")]
    let pte_flags = match prot {
        VmaProt::ReadOnly => crate::arch::x86_64::mm::USER_RO_FLAGS,
        VmaProt::ReadWrite => crate::arch::x86_64::mm::USER_RW_FLAGS,
        VmaProt::ReadExec => crate::arch::x86_64::mm::USER_RWX_FLAGS,
        VmaProt::ReadWriteExec => crate::arch::x86_64::mm::USER_RWX_FLAGS,
    };

    for page_idx in 0..pages {
        let page_va = va + page_idx * PAGE_SIZE;

        let pa = match crate::mm::object::with_object(obj_id, |obj| {
            obj.ensure_page(page_idx).map(|(pa, _)| pa)
        }) {
            Some(pa) => pa,
            None => return u64::MAX,
        };
        let pa_usize = pa.as_usize();

        // Zero the page.
        unsafe {
            core::ptr::write_bytes(pa_usize as *mut u8, 0, PAGE_SIZE);
        }

        // Map each MMU page.
        for mmu_idx in 0..PAGE_MMUCOUNT {
            let mmu_va = page_va + mmu_idx * MMUPAGE_SIZE;
            let mmu_pa = pa_usize + mmu_idx * MMUPAGE_SIZE;

            #[cfg(target_arch = "aarch64")]
            crate::arch::aarch64::mm::map_single_mmupage(pt_root, mmu_va, mmu_pa, pte_flags);
            #[cfg(target_arch = "riscv64")]
            crate::arch::riscv64::mm::map_single_mmupage(pt_root, mmu_va, mmu_pa, pte_flags);
            #[cfg(target_arch = "x86_64")]
            crate::arch::x86_64::mm::map_single_mmupage(pt_root, mmu_va, mmu_pa, pte_flags);
        }

        // Mark installed in VMA.
        crate::mm::aspace::with_aspace(aspace_id, |aspace| {
            if let Some(vma) = aspace.find_vma_mut(page_va) {
                for mmu_idx in 0..PAGE_MMUCOUNT {
                    let idx = vma.mmu_index_of(page_va + mmu_idx * MMUPAGE_SIZE);
                    vma.set_installed(idx);
                    vma.set_zeroed(idx);
                }
            }
        });
    }

    // Try superpage promotion for 2 MiB-aligned regions.
    crate::mm::aspace::with_aspace(aspace_id, |aspace| {
        if let Some(vma) = aspace.find_vma_mut(va) {
            crate::mm::fault::try_superpage_promotion_eager(
                pt_root, vma, obj_id,
            );
        }
    });

    // Increment page quota counter.
    if task_id != 0 {
        let mut sched = crate::sched::scheduler::SCHEDULER.lock();
        sched.tasks[task_id as usize].cur_pages += pages as u32;
    }

    va as u64
}

fn sys_munmap(va: u64) -> u64 {
    let aspace_id = crate::sched::scheduler::current_aspace_id();
    if aspace_id == 0 {
        return u64::MAX;
    }
    if crate::mm::aspace::unmap_anon(aspace_id, va as usize) {
        0
    } else {
        u64::MAX
    }
}

fn sys_grant_pages(dst_aspace: u64, src_va: u64, dst_va: u64, page_count: u64, readonly: u64) -> u64 {
    let my_aspace = crate::sched::scheduler::current_aspace_id();
    if my_aspace == 0 {
        return u64::MAX;
    }
    match crate::mm::grant::grant_pages(
        my_aspace,
        src_va as usize,
        dst_aspace as u32,
        dst_va as usize,
        page_count as usize,
        readonly != 0,
    ) {
        Ok(()) => 0,
        Err(_) => u64::MAX,
    }
}

fn sys_revoke(dst_aspace: u64, dst_va: u64) -> u64 {
    crate::mm::grant::revoke_grant(dst_aspace as u32, dst_va as usize);
    0
}

fn sys_aspace_id() -> u64 {
    crate::sched::scheduler::current_aspace_id() as u64
}

fn sys_get_initramfs_port() -> u64 {
    use core::sync::atomic::Ordering;
    let port = crate::io::initramfs::USER_INITRAMFS_PORT.load(Ordering::Acquire);
    port as u64
}

fn sys_port_set_recv(set_id: u64, frame: &mut ExceptionFrame) -> u64 {
    match crate::ipc::port_set::recv_blocking(set_id as u32) {
        Some((port_id, msg)) => {
            let task_id = crate::sched::current_task_id();
            auto_grant_reply_caps(task_id, &msg);
            set_reg(frame, 1, msg.tag);
            set_reg(frame, 2, msg.data[0]);
            set_reg(frame, 3, msg.data[1]);
            set_reg(frame, 4, msg.data[2]);
            set_reg(frame, 5, msg.data[3]);
            set_reg(frame, 6, msg.data[4]);
            set_reg(frame, 7, msg.data[5]);
            (port_id as u64) << 32 // status=0, port_id in high bits
        }
        None => 1,
    }
}

fn sys_nsrv_port() -> u64 {
    use core::sync::atomic::Ordering;
    crate::io::namesrv::NAMESRV_PORT.load(Ordering::Acquire) as u64
}

fn sys_mmap_device(phys_addr: u64, page_count: u64) -> u64 {
    let phys = phys_addr as usize;
    let pages = page_count as usize;
    if pages == 0 || pages > 16 {
        return u64::MAX;
    }

    // Page-align the physical address (PTEs require page-aligned PA).
    let page_offset = phys & 0xFFF;
    let phys_aligned = phys & !0xFFF;
    // If the range spans an extra page due to offset, account for it.
    let total_pages = if page_offset > 0 { pages + 1 } else { pages };

    // Validate phys_addr is within approved device MMIO ranges.
    let end = phys_aligned + total_pages * 4096;
    let valid = {
        #[cfg(target_arch = "aarch64")]
        { phys_aligned >= 0x0a00_0000 && end <= 0x0a00_7000 }
        #[cfg(target_arch = "riscv64")]
        { phys_aligned >= 0x1000_1000 && end <= 0x1000_9000 }
        #[cfg(target_arch = "x86_64")]
        { let _ = end; false } // x86-64: no MMIO device mapping
    };
    if !valid {
        return u64::MAX;
    }

    let aspace_id = crate::sched::scheduler::current_aspace_id();
    if aspace_id == 0 {
        return u64::MAX;
    }

    // Allocate VA in userspace heap.
    let va = crate::mm::aspace::with_aspace(aspace_id, |aspace| {
        aspace.alloc_heap_va(total_pages)
    });

    let pt_root = crate::sched::scheduler::current_page_table_root();

    // Device memory PTE flags (user-accessible).
    #[cfg(target_arch = "aarch64")]
    let pte_flags: u64 = {
        // MAIR Attr1 = device-nGnRnE. User RW, no execute.
        const PT_VALID: u64 = 1 << 0;
        const PT_PAGE: u64 = 1 << 1;
        const PT_AF: u64 = 1 << 10;
        const PT_AP_RW_ALL: u64 = 1 << 6;
        const PT_ATTR_IDX_1: u64 = 1 << 2;
        const PT_UXN: u64 = 1 << 54;
        const PT_PXN: u64 = 1 << 53;
        PT_VALID | PT_PAGE | PT_AF | PT_AP_RW_ALL | PT_ATTR_IDX_1 | PT_UXN | PT_PXN
    };
    #[cfg(target_arch = "riscv64")]
    let pte_flags: u64 = crate::arch::riscv64::mm::USER_RW_FLAGS;
    #[cfg(target_arch = "x86_64")]
    let pte_flags: u64 = 0; // unreachable

    for i in 0..total_pages {
        let page_va = va + i * 4096;
        let page_pa = phys_aligned + i * 4096;

        #[cfg(target_arch = "aarch64")]
        crate::arch::aarch64::mm::map_single_mmupage(pt_root, page_va, page_pa, pte_flags);
        #[cfg(target_arch = "riscv64")]
        crate::arch::riscv64::mm::map_single_mmupage(pt_root, page_va, page_pa, pte_flags);
        #[cfg(target_arch = "x86_64")]
        { let _ = (pt_root, page_va, page_pa, pte_flags); }
    }

    // Return VA + page_offset so caller gets pointer to exact MMIO base.
    (va + page_offset) as u64
}

fn sys_virt_to_phys(va: u64) -> u64 {
    let pt_root = crate::sched::scheduler::current_page_table_root();
    if pt_root == 0 {
        return u64::MAX; // kernel context
    }

    let pa = {
        #[cfg(target_arch = "aarch64")]
        { crate::arch::aarch64::mm::translate_va(pt_root, va as usize) }
        #[cfg(target_arch = "riscv64")]
        { crate::arch::riscv64::mm::translate_va(pt_root, va as usize) }
        #[cfg(target_arch = "x86_64")]
        { crate::arch::x86_64::mm::translate_va(pt_root, va as usize) }
    };

    match pa {
        Some(pa) => pa as u64,
        None => u64::MAX,
    }
}

fn sys_irq_wait(irq_num: u64, mmio_base: u64) -> u64 {
    let irq = irq_num as u32;

    // Validate IRQ is in device range.
    #[cfg(target_arch = "aarch64")]
    let valid = irq >= 48 && irq <= 79;
    #[cfg(target_arch = "riscv64")]
    let valid = irq >= 1 && irq <= 8;
    #[cfg(target_arch = "x86_64")]
    let valid = irq >= 1 && irq <= 15;

    if !valid {
        return u64::MAX;
    }

    // Registration call: register mmio_base, enable IRQ, return immediately.
    if mmio_base != 0 {
        crate::io::irq_dispatch::register(irq, mmio_base as usize);
        return 0;
    }

    // Subsequent calls: block until IRQ fires.
    crate::io::irq_dispatch::wait(irq)
}

fn sys_ioport(op: u64, port: u64, value: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let port = port as u16;
        // Only allow ports >= 0x1000 (avoids system ports like PIC/PIT/COM1).
        if port < 0x1000 {
            return u64::MAX;
        }
        use crate::arch::x86_64::serial;
        unsafe {
            match op {
                0 => serial::inb(port) as u64,
                1 => serial::inw(port) as u64,
                2 => serial::inl(port) as u64,
                3 => { serial::outb(port, value as u8); 0 }
                4 => { serial::outw(port, value as u16); 0 }
                5 => { serial::outl(port, value as u32); 0 }
                _ => u64::MAX,
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (op, port, value);
        u64::MAX
    }
}

fn sys_getchar() -> u64 {
    match crate::arch::platform::serial::getc() {
        Some(ch) => ch as u64,
        None => u64::MAX,
    }
}

/// Maximum ELF size for spawn_elf (256 KiB).
const SPAWN_ELF_MAX: usize = 256 * 1024;

/// Static buffer for ELF data during spawn_elf. Protected by SPAWN_ELF_LOCK.
static SPAWN_ELF_LOCK: crate::sync::SpinLock<()> = crate::sync::SpinLock::new(());
static mut SPAWN_ELF_BUF: [u8; SPAWN_ELF_MAX] = [0u8; SPAWN_ELF_MAX];

fn sys_spawn_elf(elf_ptr: u64, elf_len: u64, priority: u64, arg0: u64) -> u64 {
    let len = elf_len as usize;
    if len == 0 || len > SPAWN_ELF_MAX {
        return u64::MAX;
    }

    let pt_root = crate::sched::scheduler::current_page_table_root();
    let _guard = SPAWN_ELF_LOCK.lock();

    // Copy ELF data from user memory into the static buffer.
    let buf = unsafe { &mut SPAWN_ELF_BUF[..len] };
    if !copy_from_user(pt_root, elf_ptr as usize, buf) {
        return u64::MAX;
    }

    match crate::sched::spawn_user_from_elf(buf, priority as u8, 20, arg0) {
        Some(tid) => tid as u64,
        None => u64::MAX,
    }
}

/// execve: replace current process image with a new ELF from initramfs.
/// a0 = pointer to filename, a1 = filename length.
/// On success, the frame is completely rewritten and we never return to the caller.
/// On failure (before point-of-no-return), sets return value to u64::MAX.
fn sys_execve(name_ptr: u64, name_len: u64, frame: &mut ExceptionFrame) {
    use crate::mm::page::{PAGE_SIZE, MMUPAGE_SIZE};

    let pt_root = crate::sched::scheduler::current_page_table_root();
    let aspace_id = crate::sched::scheduler::current_aspace_id();
    if aspace_id == 0 {
        set_return(frame, u64::MAX);
        return;
    }

    // Copy filename from user memory.
    let len = (name_len as usize).min(64);
    let mut name_buf = [0u8; 64];
    if !copy_from_user(pt_root, name_ptr as usize, &mut name_buf[..len]) {
        set_return(frame, u64::MAX);
        return;
    }
    let name = &name_buf[..len];

    // Look up the ELF in initramfs (before point-of-no-return).
    let elf_data = match crate::io::initramfs::lookup_file(name) {
        Some(d) => d,
        None => {
            set_return(frame, u64::MAX);
            return;
        }
    };

    // Validate ELF header (basic checks before we destroy anything).
    if elf_data.len() < 64 || elf_data[0..4] != [0x7f, b'E', b'L', b'F'] {
        set_return(frame, u64::MAX);
        return;
    }

    // === POINT OF NO RETURN ===

    // Kill sibling threads.
    crate::sched::scheduler::kill_other_threads_in_task();

    // Create a fresh page table for the new image.
    #[cfg(target_arch = "aarch64")]
    let new_pt_root = crate::arch::aarch64::mm::setup_tables().expect("execve: pt alloc");
    #[cfg(target_arch = "riscv64")]
    let new_pt_root = crate::arch::riscv64::mm::setup_tables().expect("execve: pt alloc");
    #[cfg(target_arch = "x86_64")]
    let new_pt_root = crate::arch::x86_64::mm::create_user_page_table().expect("execve: pt alloc");

    // Reset address space: destroy all VMAs/PTEs, free old page table, install new one.
    crate::mm::aspace::reset(aspace_id, new_pt_root);

    // Update task's page table root.
    crate::sched::scheduler::update_task_page_table(new_pt_root);

    // Switch to new page table.
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::mm::switch_page_table(new_pt_root);
    #[cfg(target_arch = "riscv64")]
    crate::arch::riscv64::mm::switch_page_table(new_pt_root);
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::mm::switch_page_table(new_pt_root);

    // Load ELF segments into the fresh address space.
    let entry = match crate::loader::elf::load_elf(elf_data, aspace_id, new_pt_root) {
        Ok(e) => e,
        Err(_) => {
            // Past point-of-no-return, can't recover — exit.
            crate::println!("execve: ELF load failed for {:?}", core::str::from_utf8(name));
            crate::sched::scheduler::exit_current_thread(-1);
        }
    };

    // Flush instruction cache.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb");
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence.i");
    }

    // Map a fresh user stack.
    #[cfg(target_arch = "aarch64")]
    const USER_STACK_TOP: usize = 0x7FFF_F000_0000;
    #[cfg(target_arch = "riscv64")]
    const USER_STACK_TOP: usize = 0x3F_F000_0000;
    #[cfg(target_arch = "x86_64")]
    const USER_STACK_TOP: usize = 0x7FFF_FFFF_0000;

    let stack_pages = 1;
    let stack_va = USER_STACK_TOP - stack_pages * PAGE_SIZE;

    let obj_id = crate::mm::aspace::with_aspace(aspace_id, |aspace| {
        aspace.map_anon(stack_va, stack_pages, crate::mm::vma::VmaProt::ReadWrite)
            .map(|vma| vma.object_id)
    }).expect("execve: stack map");

    // Eagerly allocate and map stack pages.
    let mmu_count = PAGE_SIZE / MMUPAGE_SIZE;
    for page_idx in 0..stack_pages {
        let page_va = stack_va + page_idx * PAGE_SIZE;

        let pa = crate::mm::object::with_object(obj_id, |obj| {
            obj.ensure_page(page_idx).map(|(pa, _)| pa)
        }).expect("execve: stack alloc");
        let pa_usize = pa.as_usize();

        unsafe {
            core::ptr::write_bytes(pa_usize as *mut u8, 0, PAGE_SIZE);
        }

        #[cfg(target_arch = "aarch64")]
        let pte_flags = crate::arch::aarch64::mm::USER_RW_FLAGS;
        #[cfg(target_arch = "riscv64")]
        let pte_flags = crate::arch::riscv64::mm::USER_RW_FLAGS;
        #[cfg(target_arch = "x86_64")]
        let pte_flags = crate::arch::x86_64::mm::USER_RW_FLAGS;

        for mmu_idx in 0..mmu_count {
            let mmu_va = page_va + mmu_idx * MMUPAGE_SIZE;
            let mmu_pa = pa_usize + mmu_idx * MMUPAGE_SIZE;

            #[cfg(target_arch = "aarch64")]
            crate::arch::aarch64::mm::map_single_mmupage(new_pt_root, mmu_va, mmu_pa, pte_flags);
            #[cfg(target_arch = "riscv64")]
            crate::arch::riscv64::mm::map_single_mmupage(new_pt_root, mmu_va, mmu_pa, pte_flags);
            #[cfg(target_arch = "x86_64")]
            crate::arch::x86_64::mm::map_single_mmupage(new_pt_root, mmu_va, mmu_pa, pte_flags);
        }

        crate::mm::aspace::with_aspace(aspace_id, |aspace| {
            if let Some(vma) = aspace.find_vma_mut(page_va) {
                for mmu_idx in 0..mmu_count {
                    let idx = vma.mmu_index_of(page_va + mmu_idx * MMUPAGE_SIZE);
                    vma.set_installed(idx);
                    vma.set_zeroed(idx);
                }
            }
        });
    }

    // Rewrite the exception frame for the new program.
    unsafe {
        let frame_ptr = frame as *mut ExceptionFrame as *mut u64;
        let frame_words = crate::sched::thread::EXCEPTION_FRAME_SIZE / 8;
        for i in 0..frame_words {
            *frame_ptr.add(i) = 0;
        }

        #[cfg(target_arch = "aarch64")]
        {
            *frame_ptr.add(32) = entry as u64;          // ELR_EL1
            *frame_ptr.add(33) = 0x0;                   // SPSR_EL1 = EL0t
            *frame_ptr.add(31) = USER_STACK_TOP as u64; // SP_EL0
        }

        #[cfg(target_arch = "riscv64")]
        {
            *frame_ptr.add(31) = entry as u64;           // sepc
            *frame_ptr.add(32) = 1 << 5;                 // sstatus: SPIE=1, SPP=0
            *frame_ptr.add(1) = USER_STACK_TOP as u64;   // sp (x2)
        }

        #[cfg(target_arch = "x86_64")]
        {
            *frame_ptr.add(17) = entry as u64;                                              // RIP
            *frame_ptr.add(18) = (crate::arch::x86_64::gdt::USER_CS as u64) | 3;           // CS
            *frame_ptr.add(19) = 0x200;                                                      // RFLAGS = IF
            *frame_ptr.add(20) = USER_STACK_TOP as u64;                                      // RSP
            *frame_ptr.add(21) = (crate::arch::x86_64::gdt::USER_DS as u64) | 3;           // SS
        }

        // arg0 = 0 (no argument for execve'd process)
        // (registers were zeroed above, so arg0 is already 0)
    }

    // dispatch() returns after this — the exception return path will
    // restore the rewritten frame and jump to the new program's entry point.
}

fn sys_thread_create(entry: u64, stack_top: u64, arg: u64) -> u64 {
    let task_id = crate::sched::scheduler::current_task_id();
    // Check thread quota.
    if task_id != 0 {
        let sched = crate::sched::scheduler::SCHEDULER.lock();
        let task = &sched.tasks[task_id as usize];
        if task.thread_count >= task.max_threads {
            return u64::MAX;
        }
        drop(sched);
    }
    match crate::sched::thread_create(task_id, entry, stack_top, arg) {
        Some(child_tid) => child_tid as u64,
        None => u64::MAX,
    }
}

/// Block until target thread exits. Returns exit code, or u64::MAX on error.
fn sys_thread_join(tid: u64) -> u64 {
    let caller_task = crate::sched::scheduler::current_task_id();
    crate::sched::thread_join_block(tid as u32, caller_task)
}

fn sys_set_quota(child_tid: u64, resource_type: u64, limit: u64) -> u64 {
    let caller = crate::sched::current_task_id();
    // Resolve thread_id to task_id.
    let child_task = crate::sched::thread_task_id(child_tid as u32);
    if child_task as usize >= crate::sched::task::MAX_TASKS {
        return u64::MAX;
    }
    let mut sched = crate::sched::scheduler::SCHEDULER.lock();
    let task = &sched.tasks[child_task as usize];
    if !task.active || task.parent_task != caller {
        return u64::MAX; // Only parent can set quotas.
    }
    let limit32 = limit as u32;
    match resource_type {
        0 => sched.tasks[child_task as usize].max_ports = limit32,
        1 => sched.tasks[child_task as usize].max_threads = limit32,
        2 => sched.tasks[child_task as usize].max_pages = limit32,
        _ => return u64::MAX,
    }
    0
}

/// Send a message with an attached capability transfer.
///
/// Args: dest_port, tag, data0, data1, grant_port_id, grant_rights
///
/// The kernel grants the specified port capability (with attenuated rights)
/// to the receiver task, then sends the message. The receiver gets:
///   data[0] = sender's data0
///   data[1] = sender's data1
///   data[2] = receiver's new cap slot index
///   data[3] = granted port ID
///   data[4] = granted rights
fn sys_send_cap(dest_port: u64, tag: u64, d0: u64, d1: u64, grant_port: u64, grant_rights: u64) -> u64 {
    // Check sender has SEND on dest_port.
    if !check_port_cap(dest_port as u32, crate::cap::Rights::SEND) {
        return ECAP;
    }

    let sender_task = crate::sched::current_task_id();
    let grant_port_id = grant_port as u32;
    let rights = crate::cap::Rights::from_bits(grant_rights as u32);

    // Check sender has the cap for grant_port with the requested rights.
    if sender_task != 0 && !crate::cap::has_port_cap_fast(sender_task, grant_port_id, rights) {
        return ECAP;
    }

    // Find receiver task: first task (other than sender) with RECV on dest_port.
    let receiver_task = match crate::cap::find_recv_task(dest_port as u32, sender_task) {
        Some(t) => t,
        None => return u64::MAX, // No receiver found.
    };

    // Grant the cap to receiver.
    let receiver_slot = {
        let mut caps = crate::cap::CAP_SYSTEM.lock();
        match caps.grant_port_cap(receiver_task, grant_port_id, rights) {
            Some(slot) => slot as u64,
            None => return u64::MAX, // CSpace full.
        }
    };

    // Build and send the message.
    let mut msg = crate::ipc::Message {
        tag,
        data: [d0, d1, receiver_slot, grant_port_id as u64, rights.bits() as u64, 0],
    };

    match crate::ipc::port::send_direct(dest_port as u32, &mut msg) {
        crate::ipc::port::SendDirectResult::DirectTransfer(receiver_tid) => {
            let recv_task = crate::sched::scheduler::thread_task_id(receiver_tid);
            auto_grant_reply_caps(recv_task, &msg);
            inject_recv_into_frame(receiver_tid, &msg);
            crate::sched::boost_priority(receiver_tid, msg.data[5] as u8);
            crate::sched::scheduler::handoff_to(receiver_tid);
            0
        }
        crate::ipc::port::SendDirectResult::Queued => 0,
        crate::ipc::port::SendDirectResult::Full => {
            match crate::ipc::port::send(dest_port as u32, msg) {
                Ok(()) => 0,
                Err(()) => u64::MAX,
            }
        }
        crate::ipc::port::SendDirectResult::Error => u64::MAX,
    }
}

/// Revoke all derived capabilities from a cap slot.
/// Returns the number of capabilities revoked, or u64::MAX on error.
fn sys_cap_revoke(port_id: u64) -> u64 {
    let task_id = crate::sched::current_task_id();
    if task_id == 0 { return u64::MAX; }

    let mut caps = crate::cap::CAP_SYSTEM.lock();
    // Find the slot containing a cap for this port.
    let slot = match caps.spaces[task_id as usize].find_port_cap(
        port_id as usize,
        crate::cap::Rights::MANAGE,
    ) {
        Some(s) => s,
        None => return u64::MAX,
    };
    // Need to split the borrow: get cdt pointer first.
    let cdt = &mut caps.cdt as *mut crate::cap::Cdt;
    let count = caps.spaces[task_id as usize].revoke(slot, unsafe { &mut *cdt });
    count as u64
}

/// Return VM/scheduler/IPC statistics. `which` selects the stat.
fn sys_vm_stats(which: u64) -> u64 {
    use crate::mm::stats;
    use core::sync::atomic::Ordering;
    match which {
        0 => stats::SUPERPAGE_PROMOTIONS.load(Ordering::Relaxed),
        1 => stats::SUPERPAGE_DEMOTIONS.load(Ordering::Relaxed),
        2 => stats::MAJOR_FAULTS.load(Ordering::Relaxed),
        3 => stats::MINOR_FAULTS.load(Ordering::Relaxed),
        4 => crate::sched::scheduler::COSCHED_HITS.load(Ordering::Relaxed),
        5 => stats::PAGES_ZEROED.load(Ordering::Relaxed),
        6 => stats::PTES_INSTALLED.load(Ordering::Relaxed),
        7 => stats::PTES_REMOVED.load(Ordering::Relaxed),
        8 => stats::PAGES_RECLAIMED.load(Ordering::Relaxed),
        9 => stats::WSCLOCK_SCANS.load(Ordering::Relaxed),
        10 => stats::CONTIGUOUS_PROMOTIONS.load(Ordering::Relaxed),
        11 => stats::COW_FAULTS.load(Ordering::Relaxed),
        12 => stats::COW_PAGES_COPIED.load(Ordering::Relaxed),
        13 => crate::sched::stats::CONTEXT_SWITCHES.load(Ordering::Relaxed),
        14 => crate::sched::stats::SYSCALLS.load(Ordering::Relaxed),
        15 => crate::sched::stats::IPC_SENDS.load(Ordering::Relaxed),
        16 => crate::sched::stats::IPC_RECVS.load(Ordering::Relaxed),
        17 => stats::PAGES_PREZEROED.load(Ordering::Relaxed),
        _ => u64::MAX,
    }
}

/// Copy `dst.len()` bytes from user virtual address `user_va` into `dst`,
/// using the page table at `pt_root` to translate addresses.
pub(crate) fn copy_from_user(pt_root: usize, user_va: usize, dst: &mut [u8]) -> bool {
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

/// Copy `src.len()` bytes to user virtual address `user_va`,
/// using the page table at `pt_root` to translate addresses.
pub(crate) fn copy_to_user(pt_root: usize, user_va: usize, src: &[u8]) -> bool {
    if pt_root == 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), user_va as *mut u8, src.len());
        }
        return true;
    }

    let mut offset = 0;
    while offset < src.len() {
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

        let page_remaining = 4096 - (pa & 0xFFF);
        let to_copy = page_remaining.min(src.len() - offset);
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr().add(offset),
                pa as *mut u8,
                to_copy,
            );
        }
        offset += to_copy;
    }
    true
}

// --- Phase 32: Topology-aware scheduling syscalls ---

/// Set CPU affinity mask for a thread (must be in the same task).
fn sys_set_affinity(tid: u64, mask: u64) -> u64 {
    let caller_task = crate::sched::current_task_id();
    let target_task = crate::sched::thread_task_id(tid as u32);
    if target_task != caller_task {
        return u64::MAX;
    }
    if crate::sched::set_affinity(tid as u32, mask) { 0 } else { u64::MAX }
}

/// Query CPU topology for a given CPU index.
/// Returns packed word: pkg | (core<<8) | (smt<<16) | (online<<24) | (online_cpus<<32)
fn sys_cpu_topology(cpu_id: u64) -> u64 {
    let cpu = cpu_id as usize;
    if cpu >= crate::sched::smp::MAX_CPUS {
        return u64::MAX;
    }
    let entry = crate::sched::topology::get(cpu);
    let online_cpus = crate::sched::smp::online_cpus() as u64;
    (entry.package_id as u64)
        | ((entry.core_id as u64) << 8)
        | ((entry.smt_id as u64) << 16)
        | ((entry.online as u64) << 24)
        | (online_cpus << 32)
}

/// CPU hotplug: offline or online a CPU.
/// action: 0 = offline, 1 = online.
fn sys_cpu_hotplug(cpu_id: u64, action: u64) -> u64 {
    match action {
        0 => crate::sched::hotplug::cpu_offline(cpu_id as u32),
        1 => crate::sched::hotplug::cpu_online(cpu_id as u32),
        _ => 1,
    }
}

/// Query per-CPU load and online state.
/// Returns: load (bits 0-31) | load_window (bits 32-47) | online_mask (bits 48-63 low 16 bits).
fn sys_cpu_load(cpu_id: u64) -> u64 {
    let cpu = cpu_id as u32;
    if (cpu as usize) >= crate::sched::smp::MAX_CPUS {
        return u64::MAX;
    }
    let load = crate::sched::hotplug::cpu_load(cpu) as u64;
    let window = crate::sched::hotplug::load_window() as u64;
    let online = crate::sched::hotplug::online_mask();
    load | (window << 32) | ((online & 0xFFFF) << 48)
}

// --- Phase 42: mprotect + mremap ---

/// mprotect(addr, len, prot) -> 0 on success, u64::MAX on error.
fn sys_mprotect(addr: u64, len: u64, prot: u64) -> u64 {
    let aspace_id = crate::sched::scheduler::current_aspace_id();
    if aspace_id == 0 { return u64::MAX; }

    let new_prot = match prot {
        0 => crate::mm::vma::VmaProt::ReadOnly,
        1 => crate::mm::vma::VmaProt::ReadWrite,
        2 => crate::mm::vma::VmaProt::ReadExec,
        3 => crate::mm::vma::VmaProt::ReadWriteExec,
        _ => return u64::MAX,
    };

    if crate::mm::aspace::mprotect(aspace_id, addr as usize, len as usize, new_prot) {
        0
    } else {
        u64::MAX
    }
}

/// mremap(old_addr, old_len, new_len) -> new_addr on success, u64::MAX on error.
fn sys_mremap(old_addr: u64, old_len: u64, new_len: u64) -> u64 {
    let aspace_id = crate::sched::scheduler::current_aspace_id();
    if aspace_id == 0 { return u64::MAX; }

    let result = crate::mm::aspace::mremap(aspace_id, old_addr as usize, old_len as usize, new_len as usize);
    if result == 0 { u64::MAX } else { result as u64 }
}

// --- Phase 41: Signal delivery framework ---

/// sigaction(sig, handler, sa_mask, flags) -> old_handler or u64::MAX on error.
/// flags: bit 0 = SA_RESTART.
/// handler: 0 = SIG_DFL, 1 = SIG_IGN, else = user function pointer.
fn sys_sigaction(sig: u64, handler: u64, sa_mask: u64, flags: u64) -> u64 {
    use crate::sched::task::{SigHandler, SignalAction};

    let sig = sig as u32;
    let new_handler = match handler {
        0 => SigHandler::Default,
        1 => SigHandler::Ignore,
        addr => SigHandler::User(addr),
    };
    let action = SignalAction {
        handler: new_handler,
        sa_mask,
        restart: flags & 1 != 0,
    };

    match crate::sched::set_signal_action(sig, action) {
        Some(old) => match old.handler {
            SigHandler::Default => 0,
            SigHandler::Ignore => 1,
            SigHandler::User(addr) => addr,
        },
        None => u64::MAX,
    }
}

/// sigprocmask(how, new_mask) -> old_mask.
/// how: 0 = SIG_BLOCK (add to mask), 1 = SIG_UNBLOCK (remove from mask),
///      2 = SIG_SETMASK (replace mask).
fn sys_sigprocmask(how: u64, new_set: u64) -> u64 {
    let current = crate::sched::get_signal_mask();
    let final_mask = match how {
        0 => current | new_set,  // SIG_BLOCK
        1 => current & !new_set, // SIG_UNBLOCK
        2 => new_set,            // SIG_SETMASK
        _ => return current,     // invalid how, return current mask unchanged
    };
    crate::sched::set_signal_mask(final_mask)
}

/// kill_sig(target, sig) -> 0 on success, u64::MAX on error.
/// If target > 0: sends signal to the task containing thread `target`.
fn sys_clock_gettime(clock_id: u64) -> u64 {
    if clock_id != 0 { return u64::MAX; } // CLOCK_MONOTONIC only
    crate::sched::get_monotonic_ns()
}

fn sys_nanosleep(ns: u64) -> u64 {
    if ns == 0 { return 0; }
    let deadline = crate::sched::get_monotonic_ns() + ns;
    crate::sched::park_current_for_sleep(deadline);
    0
}

fn sys_mmap_file(va_hint: u64, page_count: u64, prot: u64, file_handle: u64, file_offset_lo: u64, file_offset_hi: u64) -> u64 {
    use crate::mm::page::PAGE_SIZE;
    use crate::mm::vma::VmaProt;

    let aspace_id = crate::sched::scheduler::current_aspace_id();
    if aspace_id == 0 { return u64::MAX; }

    let pages = page_count as usize;
    if pages == 0 || pages > 256 { return u64::MAX; }

    let prot = match prot {
        0 => VmaProt::ReadOnly,
        1 => VmaProt::ReadWrite,
        2 => VmaProt::ReadExec,
        3 => VmaProt::ReadWriteExec,
        _ => return u64::MAX,
    };

    let file_offset = file_offset_lo | (file_offset_hi << 32);

    // Determine VA.
    let va = if va_hint == 0 {
        crate::mm::aspace::with_aspace(aspace_id, |aspace| aspace.alloc_heap_va(pages))
    } else {
        va_hint as usize
    };

    // Create pager-backed object.
    let obj_id = match crate::mm::object::create_pager(pages as u16, file_handle as u32, file_offset) {
        Some(id) => id,
        None => return u64::MAX,
    };

    // Register mapping and insert VMA.
    let ok = crate::mm::aspace::with_aspace(aspace_id, |aspace| {
        crate::mm::object::with_object(obj_id, |obj| {
            obj.add_mapping(aspace_id, va);
        });
        let va_len = pages * PAGE_SIZE;
        aspace.vmas.insert(va, va_len, prot, obj_id, 0).is_some()
    });

    if !ok {
        crate::mm::object::destroy(obj_id);
        return u64::MAX;
    }

    va as u64
}

fn sys_wait_fault(frame: &mut ExceptionFrame) {
    let aspace_id = crate::sched::scheduler::current_aspace_id();
    if aspace_id == 0 {
        set_return(frame, u64::MAX);
        return;
    }

    match crate::mm::pager::wait_fault(aspace_id) {
        Some((token, fault_va, file_handle, file_offset, len)) => {
            set_return(frame, token as u64);
            set_reg(frame, 1, fault_va as u64);
            set_reg(frame, 2, file_handle as u64);
            set_reg(frame, 3, file_offset);
            set_reg(frame, 4, len as u64);
        }
        None => {
            // Parked — initiate_fault injected data into our saved frame.
            // When woken, frame already has the right values. Nothing to do.
        }
    }

    // Deliver pending signals.
    if crate::sched::scheduler::current_aspace_id() != 0 {
        deliver_pending_signals(frame);
    }
}

fn sys_fault_complete(token: u64, data_va: u64, data_len: u64) -> u64 {
    if crate::mm::pager::complete_fault(token as u32, data_va as usize, data_len as usize) {
        0
    } else {
        u64::MAX
    }
}

/// If target is negative (high bit set): sends signal to process group |target|.
fn sys_kill_sig(target: u64, sig: u64) -> u64 {
    let target_i64 = target as i64;
    if target_i64 < 0 {
        // Send to process group. User passes thread_id; convert to task_id for pgid.
        let raw = (-target_i64) as u32;
        let pgid = if (raw as usize) < crate::sched::thread::MAX_THREADS {
            crate::sched::thread_task_id(raw)
        } else {
            // Not a valid thread_id; treat as raw task_id (pgid).
            raw
        };
        if crate::sched::send_signal_to_pgroup(pgid, sig as u32) { 0 } else { u64::MAX }
    } else {
        let task_id = crate::sched::thread_task_id(target as u32);
        if crate::sched::send_signal_to_task(task_id, sig as u32) { 0 } else { u64::MAX }
    }
}

/// sigreturn(frame_addr): restore the exception frame from the signal frame.
/// frame_addr is the address of the signal frame on the user stack (passed as arg0).
fn sys_sigreturn(frame: &mut ExceptionFrame) {
    let pt_root = crate::sched::scheduler::current_page_table_root();

    // frame_addr is passed as the first syscall argument.
    let frame_addr = syscall_arg(frame, 0) as usize;

    // The signal frame layout (pushed by deliver_pending_signals):
    //   [frame_addr + 0]      = saved_mask (8 bytes)
    //   [frame_addr + 8]      = saved frame data (EXCEPTION_FRAME_SIZE bytes)
    let saved_mask_va = frame_addr;
    let saved_frame_va = frame_addr + 8;

    // Restore signal mask.
    let mut mask_buf = [0u8; 8];
    if copy_from_user(pt_root, saved_mask_va, &mut mask_buf) {
        let mask = u64::from_le_bytes(mask_buf);
        crate::sched::set_signal_mask(mask);
    }

    // Restore exception frame.
    let frame_size = crate::sched::thread::EXCEPTION_FRAME_SIZE;
    let frame_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            frame as *mut ExceptionFrame as *mut u8,
            frame_size,
        )
    };
    copy_from_user(pt_root, saved_frame_va, frame_bytes);
    // frame is now restored — dispatch() returns and exception return
    // will jump back to wherever the program was before the signal.
}

/// Signal frame layout on user stack (grows downward):
///   [SP + 0]   = saved signal mask (u64, 8 bytes)
///   [SP + 8]   = saved exception frame (EXCEPTION_FRAME_SIZE bytes)
///   [SP + 8 + EXCEPTION_FRAME_SIZE] = sigreturn trampoline code (if needed)
/// Total = 8 + EXCEPTION_FRAME_SIZE, aligned to 16 bytes.
const SIGFRAME_OVERHEAD: usize = 8; // saved_mask

/// Deliver pending signals to the current thread by rewriting the exception frame.
/// Called at the end of dispatch() before returning to userspace.
fn deliver_pending_signals(frame: &mut ExceptionFrame) {
    // Dequeue one signal at a time.
    let sig = match crate::sched::dequeue_signal() {
        Some(s) => s,
        None => return,
    };

    let action = match crate::sched::get_signal_action(sig) {
        Some(a) => a,
        None => return,
    };

    use crate::sched::task::SigHandler;

    match action.handler {
        SigHandler::Default => {
            // Default action: terminate for most signals.
            if crate::sched::task::sig_default_is_term(sig) {
                crate::sched::scheduler::exit_current_thread(-(sig as i32));
            }
            // Default ignore: nothing to do.
        }
        SigHandler::Ignore => {
            // Explicitly ignored — do nothing.
        }
        SigHandler::User(handler_addr) => {
            // Push a signal frame and redirect execution to the handler.
            let pt_root = crate::sched::scheduler::current_page_table_root();
            let frame_size = crate::sched::thread::EXCEPTION_FRAME_SIZE;
            let total_frame = SIGFRAME_OVERHEAD + frame_size;
            // Align to 16 bytes.
            let aligned_size = (total_frame + 15) & !15;

            // Get current user SP.
            #[cfg(target_arch = "aarch64")]
            let user_sp = frame.sp as usize;
            #[cfg(target_arch = "riscv64")]
            let user_sp = frame.regs[1] as usize;
            #[cfg(target_arch = "x86_64")]
            let user_sp = frame.rsp() as usize;

            let new_sp = user_sp - aligned_size;

            // Save current signal mask to signal frame.
            let old_mask = crate::sched::get_signal_mask();
            let mask_bytes = old_mask.to_le_bytes();
            if !copy_to_user(pt_root, new_sp, &mask_bytes) {
                // Can't write signal frame — terminate.
                crate::sched::scheduler::exit_current_thread(-(sig as i32));
            }

            // Save current exception frame to signal frame.
            let frame_bytes = unsafe {
                core::slice::from_raw_parts(
                    frame as *const ExceptionFrame as *const u8,
                    frame_size,
                )
            };
            if !copy_to_user(pt_root, new_sp + SIGFRAME_OVERHEAD, frame_bytes) {
                crate::sched::scheduler::exit_current_thread(-(sig as i32));
            }

            // Block signals specified in sa_mask + the delivered signal itself.
            let new_mask = old_mask | action.sa_mask | crate::sched::task::sig_bit(sig);
            crate::sched::set_signal_mask(new_mask);

            // Rewrite frame to jump to the signal handler.
            // Handler signature: fn handler(sig: u64, frame_addr: u64)
            // frame_addr is passed so the handler can call sigreturn(frame_addr).

            #[cfg(target_arch = "aarch64")]
            {
                frame.regs[0] = sig as u64;            // arg0 = signal number
                frame.regs[1] = new_sp as u64;          // arg1 = signal frame address
                frame.sp = new_sp as u64;               // SP_EL0 = new stack
                frame.regs[30] = 0;                     // LR = 0 (handler must sigreturn)
                frame.elr = handler_addr;               // PC = handler entry
            }

            #[cfg(target_arch = "riscv64")]
            {
                frame.regs[9] = sig as u64;             // a0 = signal number
                frame.regs[10] = new_sp as u64;         // a1 = signal frame address
                frame.regs[1] = new_sp as u64;          // sp = new stack
                frame.regs[0] = 0;                      // ra = 0
                let fp = frame as *mut ExceptionFrame as *mut u64;
                unsafe { *fp.add(31) = handler_addr; }
            }

            #[cfg(target_arch = "x86_64")]
            {
                // Push return address (0) on the new stack for x86 calling convention.
                let call_sp = new_sp - 8;
                let zero_bytes = 0u64.to_le_bytes();
                let _ = copy_to_user(pt_root, call_sp, &zero_bytes);

                let fp = frame as *mut ExceptionFrame as *mut u64;
                unsafe {
                    *fp.add(9) = sig as u64;             // rdi = signal number
                    *fp.add(10) = new_sp as u64;          // rsi = signal frame address
                    *fp.add(17) = handler_addr;           // RIP = handler
                    *fp.add(20) = call_sp as u64;         // RSP = adjusted stack
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Credential syscalls (Phase 48)
// ---------------------------------------------------------------------------

fn sys_getuid() -> u64 {
    let sched = crate::sched::scheduler::SCHEDULER.lock();
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let task_id = sched.threads[tid as usize].task_id;
    sched.tasks[task_id as usize].uid as u64
}

fn sys_geteuid() -> u64 {
    let sched = crate::sched::scheduler::SCHEDULER.lock();
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let task_id = sched.threads[tid as usize].task_id;
    sched.tasks[task_id as usize].euid as u64
}

fn sys_getgid() -> u64 {
    let sched = crate::sched::scheduler::SCHEDULER.lock();
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let task_id = sched.threads[tid as usize].task_id;
    sched.tasks[task_id as usize].gid as u64
}

fn sys_getegid() -> u64 {
    let sched = crate::sched::scheduler::SCHEDULER.lock();
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let task_id = sched.threads[tid as usize].task_id;
    sched.tasks[task_id as usize].egid as u64
}

/// setuid: only euid 0 (root) can set arbitrary uid.
/// Non-root can only set uid to their real uid (no-op).
fn sys_setuid(new_uid: u64) -> u64 {
    let mut sched = crate::sched::scheduler::SCHEDULER.lock();
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let task_id = sched.threads[tid as usize].task_id;
    let task = &mut sched.tasks[task_id as usize];
    if task.euid == 0 {
        // Root: set both real and effective.
        task.uid = new_uid as u32;
        task.euid = new_uid as u32;
        0
    } else if new_uid as u32 == task.uid {
        // Non-root: can set euid back to real uid.
        task.euid = task.uid;
        0
    } else {
        u64::MAX // EPERM
    }
}

/// setgid: only euid 0 (root) can set arbitrary gid.
fn sys_setgid(new_gid: u64) -> u64 {
    let mut sched = crate::sched::scheduler::SCHEDULER.lock();
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let task_id = sched.threads[tid as usize].task_id;
    let task = &mut sched.tasks[task_id as usize];
    if task.euid == 0 {
        task.gid = new_gid as u32;
        task.egid = new_gid as u32;
        0
    } else if new_gid as u32 == task.gid {
        task.egid = task.gid;
        0
    } else {
        u64::MAX // EPERM
    }
}

/// setgroups: set supplementary group list. Only euid 0 can call.
/// a0 = count, a1 = pointer to u32 array in user memory.
fn sys_setgroups(count: u64, groups_ptr: u64) -> u64 {
    let mut sched = crate::sched::scheduler::SCHEDULER.lock();
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let task_id = sched.threads[tid as usize].task_id;
    let task = &mut sched.tasks[task_id as usize];
    if task.euid != 0 {
        return u64::MAX; // EPERM
    }
    let n = count as usize;
    if n > crate::sched::task::MAX_GROUPS {
        return u64::MAX; // EINVAL
    }
    if n > 0 && groups_ptr == 0 {
        return u64::MAX;
    }
    // Copy group IDs from user memory.
    let src = groups_ptr as *const u32;
    for i in 0..n {
        task.groups[i] = unsafe { *src.add(i) };
    }
    task.ngroups = n as u32;
    0
}

/// getgroups: get supplementary group list.
/// a0 = max count (0 = just return count), a1 = pointer to u32 array.
fn sys_wait4(pid: u64, flags: u64, frame: &mut ExceptionFrame) -> u64 {
    let (child_id, status) = crate::sched::scheduler::wait4(pid as i64, flags as u32);
    set_reg(frame, 1, status as u64);
    if child_id < 0 {
        u64::MAX // ECHILD
    } else {
        child_id as u64
    }
}

fn sys_getrlimit(resource: u64, frame: &mut ExceptionFrame) -> u64 {
    use crate::sched::task::RLIMIT_COUNT;
    if resource as usize >= RLIMIT_COUNT { return u64::MAX; }
    let sched = crate::sched::scheduler::SCHEDULER.lock();
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let task_id = sched.threads[tid as usize].task_id;
    let rl = &sched.tasks[task_id as usize].rlimits[resource as usize];
    let cur = rl.cur;
    let max = rl.max;
    drop(sched);
    // Return 0 for success, soft in a1, hard in a2.
    set_reg(frame, 1, cur);
    set_reg(frame, 2, max);
    0
}

fn sys_setrlimit(resource: u64, new_cur: u64, new_max: u64) -> u64 {
    use crate::sched::task::{RLIMIT_COUNT, RLIM_INFINITY};
    if resource as usize >= RLIMIT_COUNT { return u64::MAX; }
    let mut sched = crate::sched::scheduler::SCHEDULER.lock();
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let task_id = sched.threads[tid as usize].task_id;
    let euid = sched.tasks[task_id as usize].euid;
    let rl = &sched.tasks[task_id as usize].rlimits[resource as usize];
    let old_max = rl.max;

    // Validate: soft <= hard (unless INFINITY).
    if new_cur != RLIM_INFINITY && new_max != RLIM_INFINITY && new_cur > new_max {
        return u64::MAX;
    }

    // Non-root: cannot raise hard limit.
    if euid != 0 && new_max != RLIM_INFINITY && old_max != RLIM_INFINITY && new_max > old_max {
        return u64::MAX;
    }
    // Non-root: cannot set soft above hard.
    let effective_max = if new_max == RLIM_INFINITY { RLIM_INFINITY } else { new_max };
    if new_cur != RLIM_INFINITY && effective_max != RLIM_INFINITY && new_cur > effective_max {
        return u64::MAX;
    }

    sched.tasks[task_id as usize].rlimits[resource as usize].cur = new_cur;
    sched.tasks[task_id as usize].rlimits[resource as usize].max = new_max;
    0
}

fn sys_prlimit(pid: u64, resource: u64, new_cur: u64, new_max: u64, frame: &mut ExceptionFrame) -> u64 {
    use crate::sched::task::{RLIMIT_COUNT, RLIM_INFINITY};
    if resource as usize >= RLIMIT_COUNT { return u64::MAX; }

    let mut sched = crate::sched::scheduler::SCHEDULER.lock();
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let caller_task_id = sched.threads[tid as usize].task_id;
    let euid = sched.tasks[caller_task_id as usize].euid;

    // Resolve target: pid=0 means self.
    let target_task_id = if pid == 0 {
        caller_task_id
    } else {
        let p = pid as u32;
        if p as usize >= crate::sched::task::MAX_TASKS { return u64::MAX; }
        if !sched.tasks[p as usize].active { return u64::MAX; }
        // Only root or parent can prlimit another process.
        if euid != 0 && sched.tasks[p as usize].parent_task != caller_task_id {
            return u64::MAX;
        }
        p
    };

    // Read old values.
    let rl = &sched.tasks[target_task_id as usize].rlimits[resource as usize];
    let old_cur = rl.cur;
    let old_max = rl.max;

    // Set new values (if new_cur != RLIM_INFINITY-1, treat as "set").
    // Convention: use RLIM_INFINITY-1 as "don't change" sentinel.
    let sentinel = RLIM_INFINITY - 1;
    if new_cur != sentinel || new_max != sentinel {
        let set_cur = if new_cur == sentinel { old_cur } else { new_cur };
        let set_max = if new_max == sentinel { old_max } else { new_max };

        // Validate.
        if set_cur != RLIM_INFINITY && set_max != RLIM_INFINITY && set_cur > set_max {
            return u64::MAX;
        }
        if euid != 0 && set_max != RLIM_INFINITY && old_max != RLIM_INFINITY && set_max > old_max {
            return u64::MAX;
        }

        sched.tasks[target_task_id as usize].rlimits[resource as usize].cur = set_cur;
        sched.tasks[target_task_id as usize].rlimits[resource as usize].max = set_max;
    }

    // Return 0 for success, old soft in a1, old hard in a2.
    set_reg(frame, 1, old_cur);
    set_reg(frame, 2, old_max);
    0
}

fn sys_getgroups(max_count: u64, groups_ptr: u64) -> u64 {
    let sched = crate::sched::scheduler::SCHEDULER.lock();
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let task_id = sched.threads[tid as usize].task_id;
    let task = &sched.tasks[task_id as usize];
    let n = task.ngroups as usize;
    if max_count == 0 {
        return n as u64;
    }
    if (max_count as usize) < n {
        return u64::MAX; // EINVAL — buffer too small
    }
    if groups_ptr != 0 {
        let dst = groups_ptr as *mut u32;
        for i in 0..n {
            unsafe { *dst.add(i) = task.groups[i]; }
        }
    }
    n as u64
}
