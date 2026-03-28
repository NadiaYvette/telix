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
pub const SYS_PROC_LIST: u64 = 88;
pub const SYS_PROC_INFO: u64 = 89;
pub const SYS_MADVISE: u64 = 90;
pub const SYS_TLS_SET: u64 = 91;
pub const SYS_TLS_GET: u64 = 92;
pub const SYS_PORT_SET_RECV_TIMEOUT: u64 = 93;
pub const SYS_TIMER_CREATE: u64 = 94;
pub const SYS_MMAP_GUARD: u64 = 95;
pub const SYS_GETRANDOM: u64 = 96;
pub const SYS_SIGSUSPEND: u64 = 97;
pub const SYS_SIGALTSTACK: u64 = 98;
pub const SYS_PROXY_REGISTER: u64 = 99;
pub const SYS_PORT_RESIZE: u64 = 100;
pub const SYS_FUTEX_WAIT_PI: u64 = 101;
pub const SYS_FUTEX_WAKE_PI: u64 = 102;

/// Error code: capability check failed.
const ECAP: u64 = 2;

/// Resolve a task port_id to the internal task_id.
fn resolve_task_port(port_id: u64) -> Option<u32> {
    if port_id == 0 { return None; }
    crate::sched::task_id_from_port(port_id)
}

/// Resolve a thread port_id to the internal thread_id.
fn resolve_thread_port(port_id: u64) -> Option<u32> {
    if port_id == 0 { return None; }
    crate::sched::thread_id_from_port(port_id)
}

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
        SYS_MMAP_ANON => sys_mmap_anon(a0, a1, a2, a3),
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
        SYS_GET_AFFINITY => {
            match resolve_thread_port(a0) {
                Some(tid) => crate::sched::get_affinity(tid),
                None => u64::MAX,
            }
        },
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
            // User passes task port_id. 0 = self.
            let pid = if a0 != 0 { match resolve_task_port(a0) { Some(t) => t, None => { set_return(frame, u64::MAX); return; } } } else { 0 };
            let pgid = if a1 != 0 { match resolve_task_port(a1) { Some(t) => t, None => { set_return(frame, u64::MAX); return; } } } else { 0 };
            crate::sched::setpgid(pid, pgid)
        },
        SYS_GETPGID => {
            let pid = if a0 != 0 { match resolve_task_port(a0) { Some(t) => t, None => { set_return(frame, u64::MAX); return; } } } else { 0 };
            crate::sched::getpgid(pid)
        },
        SYS_SETSID => crate::sched::setsid(),
        SYS_GETSID => {
            let pid = if a0 != 0 { match resolve_task_port(a0) { Some(t) => t, None => { set_return(frame, u64::MAX); return; } } } else { 0 };
            crate::sched::getsid(pid)
        },
        SYS_TCSETPGRP => {
            let pgid = match resolve_task_port(a0) { Some(t) => t, None => { set_return(frame, u64::MAX); return; } };
            crate::sched::tcsetpgrp(pgid)
        },
        SYS_TCGETPGRP => crate::sched::tcgetpgrp(),
        SYS_SET_CTTY => crate::sched::set_ctty(a0),
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
        SYS_PROC_LIST => sys_proc_list(a0),
        SYS_PROC_INFO => {
            let result = sys_proc_info(a0, frame);
            set_return(frame, result);
            crate::trace::trace_event(crate::trace::EVT_SYSCALL_EXIT, nr as u32, result as u32);
            if crate::sched::scheduler::current_aspace_id() != 0 {
                deliver_pending_signals(frame);
            }
            return;
        }
        SYS_MADVISE => sys_madvise(a0, a1, a2),
        SYS_TLS_SET => sys_tls_set(a0),
        SYS_TLS_GET => sys_tls_get(),
        SYS_PORT_SET_RECV_TIMEOUT => {
            sys_port_set_recv_timeout(a0, a1, frame);
            return;
        }
        SYS_TIMER_CREATE => sys_timer_create(a0, a1),
        SYS_MMAP_GUARD => sys_mmap_guard(a0, a1),
        SYS_GETRANDOM => sys_getrandom(a0, a1, a2),
        SYS_SIGSUSPEND => sys_sigsuspend(a0),
        SYS_SIGALTSTACK => sys_sigaltstack(a0, a1),
        SYS_PROXY_REGISTER => sys_proxy_register(a0),
        SYS_PORT_RESIZE => sys_port_resize(a0, a1),
        SYS_FUTEX_WAIT_PI => crate::sync::turnstile::futex_wait_pi(a0 as usize, a1 as u32),
        SYS_FUTEX_WAKE_PI => crate::sync::turnstile::futex_wake_pi(a0 as usize),
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
    auto_grant_sender_identity(receiver_task, msg.data[4]);
    auto_grant_reply_caps(receiver_task, msg);
    crate::sched::boost_priority(receiver_tid, msg.data[5] as u8);
}

/// Check if the current task has a port capability with the needed rights.
/// Uses lockless bitmap for SEND/RECV checks (fast path).
/// Falls back to per-task cap_lock + CDT_LOCK for MANAGE checks.
/// Task 0 (kernel) bypasses all checks.
#[inline]
fn check_port_cap(port_id: u64, needed: crate::cap::Rights) -> bool {
    let task_id = crate::sched::current_task_id();
    if task_id == 0 { return true; }
    // Fast path: SEND and RECV are tracked in lockless bitmaps.
    if !crate::cap::has_port_cap_fast(task_id, port_id, needed) {
        return false;
    }
    // MANAGE requires the slow path (rare — only port_destroy).
    if needed.contains(crate::cap::Rights::MANAGE) {
        let ptr = crate::sched::scheduler::TASK_TABLE.get(task_id) as *mut crate::sched::task::Task;
        if ptr.is_null() { return false; }
        return unsafe { &*ptr }.capspace.find_port_cap(port_id as usize, needed).is_some();
    }
    true
}

/// Auto-grant SEND caps for active port IDs found in message data words
/// to the receiving task. Only checks high-32 and low-32 of each word,
/// plus bits 16-47 (for protocols that pack port IDs at offset 16).
/// Auto-grant SEND caps for reply ports embedded in a received message.
/// Checks each data word as a full 64-bit port ID. Only grants if the
/// value is a valid active port and the receiver doesn't already hold
/// a SEND cap for it.
fn auto_grant_reply_caps(task_id: u32, msg: &crate::ipc::Message) {
    if task_id == 0 { return; }
    // Scan data words for port IDs. Protocols pack reply ports in various
    // positions; check all 4 user-supplied data words (data[0..3]) plus
    // any sub-word values that look like port IDs (for protocols that pack
    // reply_port << 32 | other_value).
    let mut candidates = [u64::MAX; 12];
    let mut count = 0usize;
    for i in 0..4 {
        let word = msg.data[i];
        // Check full word, high 32 bits, and bits 16+ (for protocols that
        // pack reply_port << 16 | other_value, e.g. net_srv TCP IPC).
        for &val in &[word, word >> 16, word >> 32] {
            if val == 0 || val == u64::MAX { continue; }
            if !crate::ipc::port::port_is_active(val) { continue; }
            if crate::cap::has_port_cap_fast(task_id, val, crate::cap::Rights::SEND) {
                continue;
            }
            let mut dup = false;
            for j in 0..count {
                if candidates[j] == val { dup = true; break; }
            }
            if !dup && count < 8 {
                candidates[count] = val;
                count += 1;
            }
        }
    }
    if count == 0 { return; }
    for i in 0..count {
        crate::cap::grant_send_cap(task_id, candidates[i]);
    }
}

/// Auto-grant SEND on the sender's task port to the receiver.
/// This lets servers identify callers via the port_id in data[4].
#[inline]
fn auto_grant_sender_identity(receiver_task: u32, sender_port: u64) {
    if receiver_task == 0 || sender_port == 0 { return; }
    // Fast-path check: skip if receiver already has SEND on sender's port.
    if crate::cap::has_port_cap_fast(receiver_task, sender_port, crate::cap::Rights::SEND) {
        return;
    }
    crate::cap::grant_send_cap(receiver_task, sender_port);
}

fn sys_debug_putchar(ch: u64) -> u64 {
    let c = ch as u8;
    if c == b'\n' {
        crate::arch::platform::serial::putc(b'\r');
    }
    crate::arch::platform::serial::putc(c);
    0
}

fn sys_port_create() -> u64 {
    let task_id = crate::sched::current_task_id();
    // Check resource quota (lock-free).
    if task_id != 0 {
        let task = crate::sched::scheduler::task_ref(task_id);
        if task.cur_ports >= task.max_ports {
            return u64::MAX;
        }
    }
    match crate::ipc::port::create() {
        Some(id) => {
            // Grant full port cap (SEND|RECV|MANAGE) to creator.
            if task_id != 0 {
                crate::cap::grant_full_port_cap(task_id, id);
            }
            // Increment port quota counter.
            if task_id != 0 {
                unsafe { crate::sched::scheduler::task_mut_from_ref(task_id) }.cur_ports += 1;
            }
            id as u64
        }
        None => u64::MAX,
    }
}

fn sys_port_destroy(port_id: u64) -> u64 {
    if !check_port_cap(port_id, crate::cap::Rights::MANAGE) {
        return ECAP;
    }
    crate::ipc::port::destroy(port_id);
    // Remove port caps from caller's CSpace.
    let task_id = crate::sched::current_task_id();
    if task_id != 0 {
        crate::cap::remove_port_caps(task_id, port_id);
        // Decrement port quota counter.
        let task = unsafe { crate::sched::scheduler::task_mut_from_ref(task_id) };
        if task.cur_ports > 0 {
            task.cur_ports -= 1;
        }
    }
    0
}

fn sys_port_resize(port_id: u64, new_capacity: u64) -> u64 {
    if !check_port_cap(port_id, crate::cap::Rights::MANAGE) {
        return ECAP;
    }
    if crate::ipc::port::resize(port_id, new_capacity as usize) {
        0
    } else {
        u64::MAX
    }
}

fn sys_send(port_id: u64, tag: u64, data: [u64; 6]) -> u64 {
    if crate::ipc::port::port_node(port_id) != 0 {
        return sys_send_to_proxy(port_id, tag, data, true);
    }
    if !check_port_cap(port_id, crate::cap::Rights::SEND) {
        return ECAP;
    }
    let mut msg = crate::ipc::Message::new(tag, data);
    // Stamp sender identity: data[4] = sender's task port_id.
    let sender_task = crate::sched::current_task_id();
    msg.data[4] = crate::sched::task_port_id(sender_task);

    match crate::ipc::port::send_direct(port_id, &mut msg) {
        crate::ipc::port::SendDirectResult::DirectTransfer(receiver_tid) => {
            // L4-style direct handoff: inject message and switch to receiver.
            let receiver_task = crate::sched::scheduler::thread_task_id(receiver_tid);
            auto_grant_sender_identity(receiver_task, msg.data[4]);
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
            match crate::ipc::port::send(port_id, msg) {
                Ok(()) => 0,
                Err(()) => 1,
            }
        }
        crate::ipc::port::SendDirectResult::Error => 1,
    }
}

fn sys_send_nb(port_id: u64, tag: u64, data: [u64; 6]) -> u64 {
    if crate::ipc::port::port_node(port_id) != 0 {
        return sys_send_to_proxy(port_id, tag, data, false);
    }
    if !check_port_cap(port_id, crate::cap::Rights::SEND) {
        return ECAP;
    }
    let mut msg = crate::ipc::Message::new(tag, data);
    // Stamp sender identity: data[4] = sender's task port_id.
    let sender_task = crate::sched::current_task_id();
    msg.data[4] = crate::sched::task_port_id(sender_task);

    match crate::ipc::port::send_direct(port_id, &mut msg) {
        crate::ipc::port::SendDirectResult::DirectTransfer(receiver_tid) => {
            // Direct transfer: inject message into parked receiver's frame and wake.
            let receiver_task = crate::sched::scheduler::thread_task_id(receiver_tid);
            auto_grant_sender_identity(receiver_task, msg.data[4]);
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

/// Proxy marker: low 32 bits of the tag for proxy-redirected messages.
const PROXY_MARKER: u64 = 0xFFFF_0001;

/// Redirect a non-local send to the registered proxy port.
/// `blocking`: true for sys_send (block on full), false for sys_send_nb.
fn sys_send_to_proxy(target_port: u64, tag: u64, data: [u64; 6], blocking: bool) -> u64 {
    let proxy_local = crate::ipc::port::PROXY_PORT.load(core::sync::atomic::Ordering::Acquire);
    if proxy_local == 0 {
        return 1; // No proxy registered.
    }
    // Auto-grant SEND cap on proxy port for transparency.
    let task_id = crate::sched::current_task_id();
    if task_id != 0 && !crate::cap::has_port_cap_fast(task_id, proxy_local, crate::cap::Rights::SEND) {
        crate::cap::grant_send_cap(task_id, proxy_local);
    }
    // Pack: tag = PROXY_MARKER, data[0] = target_port (full 64-bit),
    // data[1] = original_tag, data[2..4] = original_data[0..2].
    let proxy_tag = PROXY_MARKER;
    let mut proxy_msg = crate::ipc::Message::new(proxy_tag, [target_port, tag, data[0], data[1], data[2], 0]);

    match crate::ipc::port::send_direct(proxy_local, &mut proxy_msg) {
        crate::ipc::port::SendDirectResult::DirectTransfer(receiver_tid) => {
            let receiver_task = crate::sched::scheduler::thread_task_id(receiver_tid);
            auto_grant_reply_caps(receiver_task, &proxy_msg);
            inject_recv_into_frame(receiver_tid, &proxy_msg);
            crate::sched::boost_priority(receiver_tid, proxy_msg.data[5] as u8);
            if blocking {
                crate::sched::scheduler::handoff_to(receiver_tid);
            } else {
                crate::sched::scheduler::wake_parked_thread(receiver_tid);
            }
            0
        }
        crate::ipc::port::SendDirectResult::Queued => 0,
        crate::ipc::port::SendDirectResult::Full => {
            if blocking {
                match crate::ipc::port::send(proxy_local, proxy_msg) {
                    Ok(()) => 0,
                    Err(()) => 1,
                }
            } else {
                1
            }
        }
        crate::ipc::port::SendDirectResult::Error => 1,
    }
}

/// Register the calling task's port as the network proxy endpoint.
fn sys_proxy_register(port_id: u64) -> u64 {
    if !check_port_cap(port_id, crate::cap::Rights::RECV) {
        return ECAP;
    }
    crate::ipc::port::PROXY_PORT.store(port_id, core::sync::atomic::Ordering::Release);
    0
}

fn sys_recv(port_id: u64, frame: &mut ExceptionFrame) -> u64 {
    if !check_port_cap(port_id, crate::cap::Rights::RECV) {
        return ECAP;
    }
    match crate::ipc::port::recv_or_park(port_id) {
        Ok(msg) => {
            // Message was immediately available from the queue.
            let task_id = crate::sched::current_task_id();
            auto_grant_sender_identity(task_id, msg.data[4]);
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
    if !check_port_cap(port_id, crate::cap::Rights::RECV) {
        return ECAP;
    }
    match crate::ipc::port::recv_nb(port_id) {
        Ok(msg) => {
            let task_id = crate::sched::current_task_id();
            auto_grant_sender_identity(task_id, msg.data[4]);
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
    if !check_port_cap(port_id, crate::cap::Rights::RECV) {
        return ECAP;
    }
    if crate::ipc::port_set::add_port(set_id as u32, port_id) {
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
    crate::sched::thread_port_id(crate::sched::scheduler::current_thread_id())
}

fn sys_exit(code: u64) -> u64 {
    crate::sched::scheduler::exit_current_thread(code as i32);
    // unreachable
}

fn sys_waitpid(child_port: u64) -> u64 {
    let child_task = match resolve_task_port(child_port) {
        Some(t) => t,
        None => return u64::MAX,
    };
    match crate::sched::scheduler::waitpid(child_task) {
        Some(code) => code as u64,
        None => u64::MAX,
    }
}

fn sys_kill(port_id: u64) -> u64 {
    let task_id = match resolve_task_port(port_id) {
        Some(t) => t,
        None => return u64::MAX,
    };
    if crate::sched::scheduler::kill_task_by_id(task_id) { 0 } else { u64::MAX }
}

fn sys_getpid() -> u64 {
    crate::sched::task_port_id(crate::sched::current_task_id())
}

fn sys_get_cycles() -> u64 {
    crate::arch::timer::read_cycles()
}

fn sys_get_timer_freq() -> u64 {
    crate::arch::timer::timer_freq()
}

fn sys_spawn(name_ptr: u64, name_len: u64, priority: u64, arg0: u64) -> u64 {
    // Enforce RLIMIT_NPROC: count active tasks owned by the same uid (lock-free).
    {
        let task_id = crate::sched::current_task_id();
        let task = crate::sched::scheduler::task_ref(task_id);
        let uid = task.uid;
        let nproc_limit = task.rlimits[crate::sched::task::RLIMIT_NPROC as usize].cur;
        if nproc_limit != crate::sched::task::RLIM_INFINITY {
            let mut count = 0u64;
            crate::sched::scheduler::SCHED_TASK_ART.for_each(|key, val| {
                if key == 0 { return; }
                let t = unsafe { &*(val as *const crate::sched::task::Task) };
                if t.active && t.uid == uid {
                    count += 1;
                }
            });
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
        Some(tid) => {
            let task_id = crate::sched::thread_task_id(tid);
            crate::sched::task_port_id(task_id)
        }
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
        if ch == b'\n' {
            crate::arch::platform::serial::putc(b'\r');
        }
        crate::arch::platform::serial::putc(ch);
    }
    0
}

fn sys_mmap_anon(va_hint: u64, page_count: u64, prot: u64, flags: u64) -> u64 {
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

    let noreplace = flags & crate::mm::aspace::MAP_FIXED_NOREPLACE != 0;

    // Check page quota and RLIMIT_AS (lock-free).
    let task_id = crate::sched::current_task_id();
    if task_id != 0 {
        let task = crate::sched::scheduler::task_ref(task_id);
        if task.cur_pages + pages as u32 > task.max_pages {
            return u64::MAX;
        }
        // Enforce RLIMIT_AS: total virtual memory in bytes.
        let new_bytes = (task.cur_pages as u64 + pages as u64) * PAGE_SIZE as u64;
        let rlimit_as = task.rlimits[crate::sched::task::RLIMIT_AS as usize].cur;
        if rlimit_as != crate::sched::task::RLIM_INFINITY && new_bytes > rlimit_as {
            return u64::MAX;
        }
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

    // MAP_FIXED_NOREPLACE: fail if overlapping existing VMA.
    if noreplace {
        let overlaps = crate::mm::aspace::with_aspace(aspace_id, |aspace| {
            aspace.overlaps_vma(va, pages * PAGE_SIZE)
        });
        if overlaps {
            return u64::MAX;
        }
    }

    // Create VMA + backing object.
    let obj_id = match crate::mm::aspace::with_aspace(aspace_id, |aspace| {
        aspace.map_anon(va, pages, prot).map(|vma| vma.object_id)
    }) {
        Some(id) => id,
        None => return u64::MAX,
    };

    // Eagerly allocate physical pages and install PTEs.
    let pt_root = crate::sched::scheduler::current_page_table_root();

    let sw_z = crate::mm::fault::sw_zeroed_bit();
    let pte_flags = if prot == VmaProt::None {
        0
    } else {
        crate::mm::hat::pte_flags_for_prot(prot) | sw_z
    };

    for page_idx in 0..pages {
        let page_va = va + page_idx * PAGE_SIZE;

        let pa = match crate::mm::object::try_with_object(obj_id, |obj| {
            obj.ensure_page(page_idx).map(|(pa, _)| pa)
        }) {
            Some(Some(pa)) => pa,
            _ => return u64::MAX,
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

            crate::mm::hat::map_single_mmupage(pt_root, mmu_va, mmu_pa, pte_flags);
        }

        // PTE installation with SW_ZEROED is the authority — no bitmap update needed.
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
        unsafe { crate::sched::scheduler::task_mut_from_ref(task_id) }.cur_pages += pages as u32;
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

fn sys_grant_pages(dst_port: u64, src_va: u64, dst_va: u64, page_count: u64, readonly: u64) -> u64 {
    let my_aspace = crate::sched::scheduler::current_aspace_id();
    if my_aspace == 0 {
        return u64::MAX;
    }
    // Resolve destination task port to its aspace_id.
    let dst_task = match resolve_task_port(dst_port) {
        Some(t) => t,
        None => return u64::MAX,
    };
    let dst_aspace = crate::sched::scheduler::task_ref(dst_task).aspace_id;
    match crate::mm::grant::grant_pages(
        my_aspace,
        src_va as usize,
        dst_aspace,
        dst_va as usize,
        page_count as usize,
        readonly != 0,
    ) {
        Ok(()) => 0,
        Err(_) => u64::MAX,
    }
}

fn sys_revoke(dst_port: u64, dst_va: u64) -> u64 {
    let dst_task = match resolve_task_port(dst_port) {
        Some(t) => t,
        None => return u64::MAX,
    };
    let dst_aspace = crate::sched::scheduler::task_ref(dst_task).aspace_id;
    crate::mm::grant::revoke_grant(dst_aspace, dst_va as usize);
    0
}

fn sys_aspace_id() -> u64 {
    crate::sched::task_port_id(crate::sched::current_task_id())
}

fn sys_get_initramfs_port() -> u64 {
    use core::sync::atomic::Ordering;
    let port = crate::io::initramfs::USER_INITRAMFS_PORT.load(Ordering::Acquire);
    port
}

fn sys_port_set_recv(set_id: u64, frame: &mut ExceptionFrame) -> u64 {
    match crate::ipc::port_set::recv_blocking(set_id as u32) {
        Some((port_id, msg)) => {
            let task_id = crate::sched::current_task_id();
            auto_grant_sender_identity(task_id, msg.data[4]);
            auto_grant_reply_caps(task_id, &msg);
            set_reg(frame, 1, msg.tag);
            set_reg(frame, 2, msg.data[0]);
            set_reg(frame, 3, msg.data[1]);
            set_reg(frame, 4, msg.data[2]);
            set_reg(frame, 5, msg.data[3]);
            set_reg(frame, 6, msg.data[4]);
            set_reg(frame, 7, msg.data[5]);
            port_id as u64 // full 64-bit port ID in x0, u64::MAX = error
        }
        None => u64::MAX,
    }
}

fn sys_nsrv_port() -> u64 {
    use core::sync::atomic::Ordering;
    crate::io::namesrv::NAMESRV_PORT.load(Ordering::Acquire)
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
    let pte_flags: u64 = crate::mm::hat::USER_RW_FLAGS;
    #[cfg(target_arch = "x86_64")]
    let pte_flags: u64 = 0; // unreachable

    for i in 0..total_pages {
        let page_va = va + i * 4096;
        let page_pa = phys_aligned + i * 4096;

        #[cfg(not(target_arch = "x86_64"))]
        crate::mm::hat::map_single_mmupage(pt_root, page_va, page_pa, pte_flags);
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

    match crate::mm::hat::translate_va(pt_root, va as usize) {
        Some(pa) => pa as u64,
        None => u64::MAX,
    }
}

fn sys_irq_wait(irq_num: u64, mmio_base: u64) -> u64 {
    let irq = irq_num as u32;

    // Validate IRQ is in device range.
    let (irq_lo, irq_hi) = crate::arch::irq::valid_irq_range();
    let valid = irq >= irq_lo && irq <= irq_hi;

    if !valid {
        return u64::MAX;
    }

    // Registration call: register mmio_base, enable IRQ, return immediately.
    if mmio_base != 0 {
        if !crate::io::irq_dispatch::register(irq, mmio_base as usize) {
            return u64::MAX;
        }
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
fn sys_spawn_elf(elf_ptr: u64, elf_len: u64, priority: u64, arg0: u64) -> u64 {
    use crate::mm::page::PAGE_SIZE;

    let len = elf_len as usize;
    if len < 64 { // Minimum ELF header size
        return u64::MAX;
    }

    let pt_root = crate::sched::scheduler::current_page_table_root();

    // Phase A: Read ELF header + program headers into a scratch page.
    let scratch = match crate::mm::phys::alloc_page() {
        Some(p) => p,
        None => return u64::MAX,
    };
    let header_len = if len < PAGE_SIZE { len } else { PAGE_SIZE };
    let scratch_slice = unsafe {
        core::slice::from_raw_parts_mut(scratch.as_usize() as *mut u8, header_len)
    };
    if !copy_from_user(pt_root, elf_ptr as usize, scratch_slice) {
        crate::mm::phys::free_page(scratch);
        return u64::MAX;
    }

    // Parse ELF header to find maximum file extent needed.
    let ehdr = unsafe { &*(scratch.as_usize() as *const u8 as *const [u8; 64]) };
    if ehdr[0] != 0x7f || ehdr[1] != b'E' || ehdr[2] != b'L' || ehdr[3] != b'F' {
        crate::mm::phys::free_page(scratch);
        return u64::MAX;
    }
    let e_phoff = u64::from_le_bytes([ehdr[32], ehdr[33], ehdr[34], ehdr[35],
                                       ehdr[36], ehdr[37], ehdr[38], ehdr[39]]) as usize;
    let e_phentsize = u16::from_le_bytes([ehdr[54], ehdr[55]]) as usize;
    let e_phnum = u16::from_le_bytes([ehdr[56], ehdr[57]]) as usize;

    if e_phentsize < 56 || e_phnum == 0 {
        crate::mm::phys::free_page(scratch);
        return u64::MAX;
    }

    // Compute maximum file extent from PT_LOAD segments.
    let phdrs_end = e_phoff + e_phnum * e_phentsize;
    if phdrs_end > header_len {
        // Program headers don't fit in the scratch page — need full copy anyway.
        // Fall through to using `len` as the extent.
    }
    let mut max_file_end = 64usize; // at minimum, the ELF header
    if phdrs_end <= header_len {
        for i in 0..e_phnum {
            let ph_base = scratch.as_usize() + e_phoff + i * e_phentsize;
            let ph = unsafe { core::slice::from_raw_parts(ph_base as *const u8, 56) };
            let p_type = u32::from_le_bytes([ph[0], ph[1], ph[2], ph[3]]);
            if p_type == 1 { // PT_LOAD
                let p_offset = u64::from_le_bytes([ph[8], ph[9], ph[10], ph[11],
                                                    ph[12], ph[13], ph[14], ph[15]]) as usize;
                let p_filesz = u64::from_le_bytes([ph[32], ph[33], ph[34], ph[35],
                                                    ph[36], ph[37], ph[38], ph[39]]) as usize;
                let end = p_offset.saturating_add(p_filesz);
                if end > max_file_end {
                    max_file_end = end;
                }
            }
        }
        // Also ensure we include the program headers themselves.
        if phdrs_end > max_file_end {
            max_file_end = phdrs_end;
        }
    } else {
        max_file_end = len;
    }
    // Clamp to user-provided length.
    if max_file_end > len {
        max_file_end = len;
    }

    // Phase B: Allocate contiguous buffer and copy full ELF data.
    let pages_needed = (max_file_end + PAGE_SIZE - 1) / PAGE_SIZE;
    let order = if pages_needed <= 1 { 0 } else { (usize::BITS - (pages_needed - 1).leading_zeros()) as usize };
    let (buf_addr, buf_order) = if order == 0 {
        // Single page — reuse scratch if data already fits.
        if max_file_end <= header_len {
            (scratch, 0usize)
        } else {
            // Need to copy remaining data into scratch page.
            let rest_start = header_len;
            let rest_slice = unsafe {
                core::slice::from_raw_parts_mut(
                    (scratch.as_usize() + rest_start) as *mut u8,
                    max_file_end - rest_start,
                )
            };
            if !copy_from_user(pt_root, elf_ptr as usize + rest_start, rest_slice) {
                crate::mm::phys::free_page(scratch);
                return u64::MAX;
            }
            (scratch, 0usize)
        }
    } else {
        // Multi-page allocation.
        let pages = match crate::mm::phys::alloc_pages(order) {
            Some(p) => p,
            None => {
                crate::mm::phys::free_page(scratch);
                return u64::MAX;
            }
        };
        // Copy full ELF data from userspace.
        let buf_slice = unsafe {
            core::slice::from_raw_parts_mut(pages.as_usize() as *mut u8, max_file_end)
        };
        if !copy_from_user(pt_root, elf_ptr as usize, buf_slice) {
            crate::mm::phys::free_pages(pages, order);
            crate::mm::phys::free_page(scratch);
            return u64::MAX;
        }
        // Free the scratch page (no longer needed).
        crate::mm::phys::free_page(scratch);
        (pages, order)
    };

    // Phase C: Spawn from the buffer, then free it.
    let buf_slice = unsafe {
        core::slice::from_raw_parts(buf_addr.as_usize() as *const u8, max_file_end)
    };
    let result = match crate::sched::spawn_user_from_elf(buf_slice, priority as u8, 20, arg0) {
        Some(tid) => {
            let task_id = crate::sched::thread_task_id(tid);
            crate::sched::task_port_id(task_id)
        }
        None => u64::MAX,
    };
    if buf_order == 0 {
        crate::mm::phys::free_page(buf_addr);
    } else {
        crate::mm::phys::free_pages(buf_addr, buf_order);
    }
    result
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

    // Read argv_ptr and envp_ptr from a2/a3 (may be 0 for backward compat).
    let argv_ptr = syscall_arg(frame, 2) as usize;
    let envp_ptr = syscall_arg(frame, 3) as usize;

    // Copy filename from user memory.
    let len = (name_len as usize).min(64);
    let mut name_buf = [0u8; 64];
    if !copy_from_user(pt_root, name_ptr as usize, &mut name_buf[..len]) {
        set_return(frame, u64::MAX);
        return;
    }
    let name = &name_buf[..len];

    // Copy argv and envp strings from user memory (before point-of-no-return).
    // Page-allocated scratch buffers: metadata page (u16 lengths) + contiguous data pages.
    const ARG_MAX_STRLEN: usize = 4096;
    let arg_max_strings: usize = PAGE_SIZE / 8; // scales with page size
    let arg_max_total: usize = 2 * PAGE_SIZE;   // max total string bytes
    let data_order: usize = 1; // 2 contiguous pages for string data

    // Allocate scratch pages.
    let meta_page = match crate::mm::phys::alloc_page() {
        Some(p) => p,
        None => { set_return(frame, u64::MAX); return; }
    };
    let data_pages = match crate::mm::phys::alloc_pages(data_order) {
        Some(p) => p,
        None => {
            crate::mm::phys::free_page(meta_page);
            set_return(frame, u64::MAX); return;
        }
    };

    // Metadata page: array of u16 string lengths.
    let meta_lens = unsafe {
        core::slice::from_raw_parts_mut(meta_page.as_usize() as *mut u16, PAGE_SIZE / 2)
    };
    let data_buf = unsafe {
        core::slice::from_raw_parts_mut(data_pages.as_usize() as *mut u8, arg_max_total)
    };

    let mut argc: usize = 0;
    let mut envc: usize = 0;
    let mut data_cursor: usize = 0;
    let mut total_strings: usize = 0;

    // Helper closure: copy a null-terminated string from userspace into data_buf.
    // Returns string length (excluding null) or None on error/overflow.
    let copy_str = |pt: usize, str_ptr: usize, buf: &mut [u8], cursor: &mut usize| -> Option<usize> {
        // Copy in chunks, scanning for null terminator.
        let mut total = 0usize;
        let max = ARG_MAX_STRLEN.min(buf.len() - *cursor);
        while total < max {
            let chunk = 256.min(max - total);
            let dst = &mut buf[*cursor + total .. *cursor + total + chunk];
            if !copy_from_user(pt, str_ptr + total, dst) {
                return None;
            }
            if let Some(pos) = dst.iter().position(|&b| b == 0) {
                let slen = total + pos;
                *cursor += slen;
                return Some(slen);
            }
            total += chunk;
        }
        // No null found within limit — truncate.
        *cursor += max;
        Some(max)
    };

    if argv_ptr != 0 {
        loop {
            if total_strings >= arg_max_strings { break; }
            let mut ptr_val = [0u8; 8];
            if !copy_from_user(pt_root, argv_ptr + total_strings * 8, &mut ptr_val) { break; }
            let str_ptr = u64::from_le_bytes(ptr_val) as usize;
            if str_ptr == 0 { break; }
            if data_cursor >= arg_max_total { break; }
            match copy_str(pt_root, str_ptr, data_buf, &mut data_cursor) {
                Some(slen) => {
                    meta_lens[total_strings] = slen as u16;
                    total_strings += 1;
                    argc += 1;
                }
                None => break,
            }
        }
    }

    if envp_ptr != 0 {
        let mut ei = 0usize;
        loop {
            if total_strings >= arg_max_strings { break; }
            let mut ptr_val = [0u8; 8];
            if !copy_from_user(pt_root, envp_ptr + ei * 8, &mut ptr_val) { break; }
            let str_ptr = u64::from_le_bytes(ptr_val) as usize;
            if str_ptr == 0 { break; }
            if data_cursor >= arg_max_total { break; }
            match copy_str(pt_root, str_ptr, data_buf, &mut data_cursor) {
                Some(slen) => {
                    meta_lens[total_strings] = slen as u16;
                    total_strings += 1;
                    envc += 1;
                    ei += 1;
                }
                None => break,
            }
        }
    }

    let string_total = data_cursor; // total bytes of string data (excluding null terminators)

    // Look up the ELF in initramfs (before point-of-no-return).
    let elf_data = match crate::io::initramfs::lookup_file(name) {
        Some(d) => d,
        None => {
            crate::mm::phys::free_page(meta_page);
            crate::mm::phys::free_pages(data_pages, data_order);
            set_return(frame, u64::MAX);
            return;
        }
    };

    // Validate ELF header (basic checks before we destroy anything).
    if elf_data.len() < 64 || elf_data[0..4] != [0x7f, b'E', b'L', b'F'] {
        crate::mm::phys::free_page(meta_page);
        crate::mm::phys::free_pages(data_pages, data_order);
        set_return(frame, u64::MAX);
        return;
    }

    // === POINT OF NO RETURN ===

    // Kill sibling threads.
    crate::sched::scheduler::kill_other_threads_in_task();

    // Create a fresh page table for the new image.
    let new_pt_root = crate::mm::hat::create_user_page_table().expect("execve: pt alloc");

    // Reset address space: destroy all VMAs/PTEs, free old page table, install new one.
    crate::mm::aspace::reset(aspace_id, new_pt_root);

    // Update task's page table root.
    crate::sched::scheduler::update_task_page_table(new_pt_root);

    // Switch to new page table.
    crate::mm::hat::switch_page_table(new_pt_root);

    // Load ELF segments into the fresh address space.
    let elf_info = match crate::loader::elf::load_elf(elf_data, aspace_id, new_pt_root) {
        Ok(e) => e,
        Err(_) => {
            // Past point-of-no-return, can't recover — exit.
            crate::println!("execve: ELF load failed for {:?}", core::str::from_utf8(name));
            crate::sched::scheduler::exit_current_thread(-1);
        }
    };

    // Phase 66: If PT_INTERP is present, load the interpreter ELF and
    // redirect entry to the interpreter. Pass AT_BASE and AT_ENTRY in auxv.
    let (entry, interp_base) = if elf_info.interp_len > 0 {
        // Look up interpreter in initramfs (strip leading "/" if present).
        let iname = &elf_info.interp[..elf_info.interp_len];
        let iname = if iname.first() == Some(&b'/') { &iname[1..] } else { iname };

        match crate::io::initramfs::lookup_file(iname) {
            Some(interp_data) => {
                // Load interpreter at a high base address (0x4_0000_0000).
                // For ET_DYN interpreters, we need to add base offset.
                const INTERP_BASE: usize = 0x4_0000_0000;

                match crate::loader::elf::load_elf_at_base(interp_data, aspace_id, new_pt_root, INTERP_BASE) {
                    Ok(interp_info) => {
                        // Entry goes to interpreter; AT_ENTRY = original program entry.
                        (interp_info.entry, INTERP_BASE)
                    }
                    Err(_) => {
                        crate::println!("execve: interpreter load failed");
                        (elf_info.entry, 0usize)
                    }
                }
            }
            None => {
                crate::println!("execve: interpreter {:?} not found", core::str::from_utf8(iname));
                (elf_info.entry, 0usize)
            }
        }
    } else {
        (elf_info.entry, 0usize)
    };

    // Flush instruction cache.
    crate::arch::cpu::flush_icache();

    // Map a fresh user stack.
    #[cfg(target_arch = "aarch64")]
    const USER_STACK_TOP: usize = 0x7FFF_F000_0000;
    #[cfg(target_arch = "riscv64")]
    const USER_STACK_TOP: usize = 0x3F_F000_0000;
    #[cfg(target_arch = "x86_64")]
    const USER_STACK_TOP: usize = 0x7FFF_FFFF_0000;

    // Compute stack size dynamically: strings + null terminators + pointer table + auxv + margin.
    let strings_with_nulls = string_total + (argc + envc); // each string gets a null terminator
    let ptr_table_size = (1 + argc + 1 + envc + 1 + 14) * 8; // argc + argv[] + NULL + envp[] + NULL + 7 auxv pairs
    let stack_needed = strings_with_nulls + ptr_table_size + 256; // 256 bytes margin
    let stack_pages = ((stack_needed + PAGE_SIZE - 1) / PAGE_SIZE).max(2);
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

        let sw_z = crate::mm::fault::sw_zeroed_bit();
        let pte_flags = crate::mm::hat::USER_RW_FLAGS | sw_z;

        for mmu_idx in 0..mmu_count {
            let mmu_va = page_va + mmu_idx * MMUPAGE_SIZE;
            let mmu_pa = pa_usize + mmu_idx * MMUPAGE_SIZE;

            crate::mm::hat::map_single_mmupage(new_pt_root, mmu_va, mmu_pa, pte_flags);
        }

        // PTE installation with SW_ZEROED is the authority — no bitmap update needed.
    }

    // Build the stack layout with argc/argv/envp/auxv.
    // Layout (growing downward from USER_STACK_TOP):
    //   [strings area] — argv and envp string data (near top)
    //   [padding to 16-byte align]
    //   AT_NULL, 0
    //   auxv pairs...
    //   NULL (end of envp)
    //   envp[envc-1] pointer
    //   ...
    //   envp[0] pointer
    //   NULL (end of argv)
    //   argv[argc-1] pointer
    //   ...
    //   argv[0] pointer
    //   argc            <-- sp points here

    // Write strings from scratch pages to top of stack, building pointer table.
    // Use the metadata page to store user-space addresses (reuse as u64 array).
    let mut str_pos = USER_STACK_TOP; // grows downward
    let mut data_off: usize = 0;
    // We store addresses in a temporary array on the metadata page (reinterpreted as u64).
    // meta_page can hold PAGE_SIZE/8 u64 addresses.
    let addr_buf = unsafe {
        core::slice::from_raw_parts_mut(meta_page.as_usize() as *mut u64, PAGE_SIZE / 8)
    };
    let data_src = unsafe {
        core::slice::from_raw_parts(data_pages.as_usize() as *const u8, arg_max_total)
    };

    // Write argv strings (from top down).
    for i in 0..argc {
        let slen = meta_lens[i] as usize;
        str_pos -= slen + 1; // include null terminator
        addr_buf[i] = str_pos as u64;
        copy_to_user(new_pt_root, str_pos, &data_src[data_off..data_off + slen]);
        // null terminator is already there (stack was zeroed)
        data_off += slen;
    }

    // Write envp strings.
    for i in 0..envc {
        let slen = meta_lens[argc + i] as usize;
        str_pos -= slen + 1;
        addr_buf[argc + i] = str_pos as u64;
        copy_to_user(new_pt_root, str_pos, &data_src[data_off..data_off + slen]);
        data_off += slen;
    }

    // Align str_pos down to 16 bytes.
    str_pos &= !15;

    // Auxv entries (6 pairs + AT_NULL = 7 pairs = 14 u64s).
    const AT_NULL: u64 = 0;
    const AT_PHDR: u64 = 3;
    const AT_PHENT: u64 = 4;
    const AT_PHNUM: u64 = 5;
    const AT_PAGESZ: u64 = 6;
    const AT_BASE: u64 = 7;
    const AT_ENTRY: u64 = 9;

    let auxv: [(u64, u64); 7] = [
        (AT_PHDR, elf_info.phdr_vaddr as u64),
        (AT_PHENT, elf_info.phentsize as u64),
        (AT_PHNUM, elf_info.phnum as u64),
        (AT_PAGESZ, PAGE_SIZE as u64),
        (AT_ENTRY, elf_info.entry as u64),
        (AT_BASE, interp_base as u64),
        (AT_NULL, 0),
    ];

    // Calculate total size of pointer table below strings.
    // Layout: argc(8) + argv ptrs(argc*8) + NULL(8) + envp ptrs(envc*8) + NULL(8) + auxv(14*8)
    let table_words = 1 + argc + 1 + envc + 1 + auxv.len() * 2;
    let table_size = table_words * 8;

    // sp = str_pos - table_size, aligned to 16.
    let sp = (str_pos - table_size) & !15;

    // Write the table via copy_to_user.
    let mut pos = sp;

    // argc
    copy_to_user(new_pt_root, pos, &(argc as u64).to_le_bytes());
    pos += 8;

    // argv pointers
    for i in 0..argc {
        copy_to_user(new_pt_root, pos, &addr_buf[i].to_le_bytes());
        pos += 8;
    }
    // argv NULL terminator
    copy_to_user(new_pt_root, pos, &0u64.to_le_bytes());
    pos += 8;

    // envp pointers
    for i in 0..envc {
        copy_to_user(new_pt_root, pos, &addr_buf[argc + i].to_le_bytes());
        pos += 8;
    }
    // envp NULL terminator
    copy_to_user(new_pt_root, pos, &0u64.to_le_bytes());
    pos += 8;

    // auxv pairs
    for &(key, val) in &auxv {
        copy_to_user(new_pt_root, pos, &key.to_le_bytes());
        pos += 8;
        copy_to_user(new_pt_root, pos, &val.to_le_bytes());
        pos += 8;
    }

    // Free scratch pages (no longer needed).
    crate::mm::phys::free_page(meta_page);
    crate::mm::phys::free_pages(data_pages, data_order);

    // argv pointer (for register passing) = sp + 8
    let argv_base = sp + 8;
    // envp pointer = sp + 8 + (argc + 1) * 8
    let envp_base = sp + 8 + (argc + 1) * 8;

    // Rewrite the exception frame for the new program.
    unsafe {
        let frame_ptr = frame as *mut ExceptionFrame as *mut u64;
        let frame_words = crate::sched::thread::EXCEPTION_FRAME_SIZE / 8;
        for i in 0..frame_words {
            *frame_ptr.add(i) = 0;
        }

        #[cfg(target_arch = "aarch64")]
        {
            *frame_ptr.add(32) = entry as u64;   // ELR_EL1
            *frame_ptr.add(33) = 0x0;            // SPSR_EL1 = EL0t
            *frame_ptr.add(31) = sp as u64;      // SP_EL0
            *frame_ptr.add(0) = argc as u64;     // x0 = argc
            *frame_ptr.add(1) = argv_base as u64; // x1 = argv
            *frame_ptr.add(2) = envp_base as u64; // x2 = envp
        }

        #[cfg(target_arch = "riscv64")]
        {
            *frame_ptr.add(31) = entry as u64;    // sepc
            *frame_ptr.add(32) = 1 << 5;          // sstatus: SPIE=1, SPP=0
            *frame_ptr.add(1) = sp as u64;        // sp (x2)
            *frame_ptr.add(9) = argc as u64;      // a0 = argc
            *frame_ptr.add(10) = argv_base as u64; // a1 = argv
            *frame_ptr.add(11) = envp_base as u64; // a2 = envp
        }

        #[cfg(target_arch = "x86_64")]
        {
            *frame_ptr.add(17) = entry as u64;                                              // RIP
            *frame_ptr.add(18) = (crate::arch::x86_64::gdt::USER_CS as u64) | 3;           // CS
            *frame_ptr.add(19) = 0x200;                                                      // RFLAGS = IF
            *frame_ptr.add(20) = sp as u64;                                                   // RSP
            *frame_ptr.add(21) = (crate::arch::x86_64::gdt::USER_DS as u64) | 3;           // SS
            // x86-64: rdi=argc, rsi=argv, rdx=envp
            frame.set_rdi(argc as u64);
            frame.set_rsi(argv_base as u64);
            frame.set_rdx(envp_base as u64);
        }
    }

    // Flush icache again after frame rewrite, and add DSB to ensure
    // all page table + data writes are complete before we return to userspace.
    crate::arch::cpu::flush_icache();

    // dispatch() returns after this — the exception return path will
    // restore the rewritten frame and jump to the new program's entry point.
}

fn sys_thread_create(entry: u64, stack_top: u64, arg: u64) -> u64 {
    let task_id = crate::sched::scheduler::current_task_id();
    // Check thread quota (lock-free).
    if task_id != 0 {
        let task = crate::sched::scheduler::task_ref(task_id);
        if task.thread_count >= task.max_threads {
            return u64::MAX;
        }
    }
    match crate::sched::thread_create(task_id, entry, stack_top, arg) {
        Some(child_tid) => crate::sched::thread_port_id(child_tid),
        None => u64::MAX,
    }
}

/// Block until target thread exits. Returns exit code, or u64::MAX on error.
fn sys_thread_join(port_id: u64) -> u64 {
    let tid = match resolve_thread_port(port_id) {
        Some(t) => t,
        None => return u64::MAX,
    };
    let caller_task = crate::sched::scheduler::current_task_id();
    crate::sched::thread_join_block(tid, caller_task)
}

fn sys_set_quota(child_port: u64, resource_type: u64, limit: u64) -> u64 {
    let caller = crate::sched::current_task_id();
    let child_task = match resolve_task_port(child_port) {
        Some(t) => t,
        None => return u64::MAX,
    };
    let task = match crate::sched::scheduler::task_ref_opt(child_task) {
        Some(t) => t,
        None => return u64::MAX,
    };
    if !task.active || task.parent_task != caller {
        return u64::MAX; // Only parent can set quotas.
    }
    let limit32 = limit as u32;
    // Safe: only parent sets child's quotas.
    let task = unsafe { crate::sched::scheduler::task_mut_from_ref(child_task) };
    match resource_type {
        0 => task.max_ports = limit32,
        1 => task.max_threads = limit32,
        2 => task.max_pages = limit32,
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
    if !check_port_cap(dest_port, crate::cap::Rights::SEND) {
        return ECAP;
    }

    let sender_task = crate::sched::current_task_id();
    let grant_port_id = grant_port;
    let rights = crate::cap::Rights::from_bits(grant_rights as u32);

    // Check sender has the cap for grant_port with the requested rights.
    if sender_task != 0 && !crate::cap::has_port_cap_fast(sender_task, grant_port_id, rights) {
        return ECAP;
    }

    // Find receiver task: first task (other than sender) with RECV on dest_port.
    let receiver_task = match crate::cap::find_recv_task(dest_port, sender_task) {
        Some(t) => t,
        None => return u64::MAX, // No receiver found.
    };

    // Grant the cap to receiver.
    let receiver_slot = match crate::cap::grant_port_cap(receiver_task, grant_port_id, rights) {
        Some(slot) => slot as u64,
        None => return u64::MAX, // CSpace full.
    };

    // Build and send the message.
    let mut msg = crate::ipc::Message {
        tag,
        data: [d0, d1, receiver_slot, grant_port_id, rights.bits() as u64, 0],
    };

    match crate::ipc::port::send_direct(dest_port, &mut msg) {
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
            match crate::ipc::port::send(dest_port, msg) {
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

    let ptr = crate::sched::scheduler::TASK_TABLE.get(task_id)
        as *mut crate::sched::task::Task;
    if ptr.is_null() { return u64::MAX; }
    let space = unsafe { &(*ptr).capspace };
    // Find the slot containing a cap for this port.
    let slot = match space.find_port_cap(
        port_id as usize,
        crate::cap::Rights::MANAGE,
    ) {
        Some(s) => s,
        None => return u64::MAX,
    };
    let count = crate::cap::revoke_slot(task_id, slot);
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
        18 => { let (total, _) = crate::mm::phys::stats(); total as u64 }
        19 => { let (_, free) = crate::mm::phys::stats(); free as u64 }
        20 => stats::RESERVATION_CONSOLIDATIONS.load(Ordering::Relaxed),
        21 => stats::WSCLOCK_RESERVATION_SKIPS.load(Ordering::Relaxed),
        _ => u64::MAX,
    }
}

/// Enumerate active tasks. Returns task_id of the index-th active task, else 0.
fn sys_proc_list(index: u64) -> u64 {
    let mut i = 0u64;
    let mut result = 0u64;
    crate::sched::scheduler::SCHED_TASK_ART.for_each(|_key, val| {
        let task = unsafe { &*(val as *const crate::sched::task::Task) };
        if task.active {
            if i == index {
                result = task.port_id;
            }
            i += 1;
        }
    });
    result
}

/// Query process metadata. Returns packed info via multi-return registers.
fn sys_proc_info(port_id: u64, frame: &mut ExceptionFrame) -> u64 {
    let task_id = match resolve_task_port(port_id) {
        Some(t) => t,
        None => return u64::MAX,
    };
    let task = match crate::sched::scheduler::task_ref_opt(task_id) {
        Some(t) => t,
        None => return u64::MAX,
    };
    if !task.active && !task.exited { return u64::MAX; }

    let r1 = (task.parent_task as u64) | ((task.thread_count as u64) << 32);
    let r2 = (task.uid as u64) | ((task.gid as u64) << 32);
    let r3 = (task.pgid as u64) | ((task.sid as u64) << 32);
    let mut state: u32 = 0;
    if task.active { state |= 1; }
    if task.exited { state |= 2; }
    let r4 = (task.cur_pages as u64) | ((state as u64) << 32);

    set_reg(frame, 1, r1);
    set_reg(frame, 2, r2);
    set_reg(frame, 3, r3);
    set_reg(frame, 4, r4);
    0
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
        let pa = match crate::mm::hat::translate_va(pt_root, va) {
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
        let pa = match crate::mm::hat::translate_va(pt_root, va) {
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
fn sys_set_affinity(port_id: u64, mask: u64) -> u64 {
    let tid = match resolve_thread_port(port_id) {
        Some(t) => t,
        None => return u64::MAX,
    };
    let caller_task = crate::sched::current_task_id();
    let target_task = crate::sched::thread_task_id(tid);
    if target_task != caller_task {
        return u64::MAX;
    }
    if crate::sched::set_affinity(tid, mask) { 0 } else { u64::MAX }
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
    load | (window << 32) | ((online.as_u64() & 0xFFFF) << 48)
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

fn sys_mmap_file(va_hint: u64, page_count: u64, prot: u64, file_handle: u64, file_offset: u64, pager_task: u64) -> u64 {
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

    // Determine VA.
    let va = if va_hint == 0 {
        crate::mm::aspace::with_aspace(aspace_id, |aspace| aspace.alloc_heap_va(pages))
    } else {
        va_hint as usize
    };

    // Create pager-backed object (gets a normal port for fault IPC).
    let obj_id = match crate::mm::object::create_pager(pages as u16, file_handle as u32, file_offset) {
        Some(id) => id,
        None => return u64::MAX,
    };

    // Grant RECV+SEND on the object port to the pager task.
    let obj_port = crate::mm::object::object_port(obj_id);
    if obj_port != 0 {
        let task_id = crate::sched::current_task_id();
        let rights = crate::cap::Rights::SEND.union(crate::cap::Rights::RECV);
        // Grant to calling task (same-process pagers).
        crate::cap::grant_port_cap(task_id, obj_port, rights);
        // Grant to specified external pager task if different.
        let pager = pager_task as u32;
        if pager != 0 && pager != task_id {
            crate::cap::grant_port_cap(pager, obj_port, rights);
        }
    }

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
        // Negative target: send to process group. Negate to get group leader's task port_id.
        let leader_port = (-target_i64) as u64;
        let leader_task = match resolve_task_port(leader_port) {
            Some(t) => t,
            None => return u64::MAX,
        };
        // The leader's task_id is used as the pgid.
        if crate::sched::send_signal_to_pgroup(leader_task, sig as u32) { 0 } else { u64::MAX }
    } else {
        // Resolve task or thread port to a task_id (validated by port_id match).
        let task_id = match crate::sched::task_id_from_any_port(target) {
            Some(t) => t,
            None => return u64::MAX,
        };
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
    let task_id = crate::sched::current_task_id();
    crate::sched::scheduler::task_ref(task_id).uid as u64
}

fn sys_geteuid() -> u64 {
    let task_id = crate::sched::current_task_id();
    crate::sched::scheduler::task_ref(task_id).euid as u64
}

fn sys_getgid() -> u64 {
    let task_id = crate::sched::current_task_id();
    crate::sched::scheduler::task_ref(task_id).gid as u64
}

fn sys_getegid() -> u64 {
    let task_id = crate::sched::current_task_id();
    crate::sched::scheduler::task_ref(task_id).egid as u64
}

/// setuid: only euid 0 (root) can set arbitrary uid.
/// Non-root can only set uid to their real uid (no-op).
fn sys_setuid(new_uid: u64) -> u64 {
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let task_id = crate::sched::scheduler::thread_ref(tid).task_id;
    // Safe: only the current task modifies its own credentials.
    let task = unsafe { crate::sched::scheduler::task_mut_from_ref(task_id) };
    if task.euid == 0 {
        task.uid = new_uid as u32;
        task.euid = new_uid as u32;
        0
    } else if new_uid as u32 == task.uid {
        task.euid = task.uid;
        0
    } else {
        u64::MAX // EPERM
    }
}

/// setgid: only euid 0 (root) can set arbitrary gid.
fn sys_setgid(new_gid: u64) -> u64 {
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let task_id = crate::sched::scheduler::thread_ref(tid).task_id;
    let task = unsafe { crate::sched::scheduler::task_mut_from_ref(task_id) };
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
    use crate::sched::task::{MAX_GROUPS, GROUPS_INLINE};
    let n = count as usize;
    if n > MAX_GROUPS {
        return u64::MAX; // EINVAL
    }
    if n > 0 && groups_ptr == 0 {
        return u64::MAX;
    }

    // Check permission (lock-free).
    {
        let task_id = crate::sched::current_task_id();
        if crate::sched::scheduler::task_ref(task_id).euid != 0 {
            return u64::MAX; // EPERM
        }
    }

    // Allocate overflow page if needed (outside SCHEDULER lock).
    let overflow_page = if n > GROUPS_INLINE {
        match crate::mm::phys::alloc_page() {
            Some(p) => p.as_usize(),
            None => return u64::MAX, // ENOMEM
        }
    } else {
        0
    };

    // Copy group IDs from user memory.
    let pt_root = crate::sched::scheduler::current_page_table_root();
    let mut inline_buf = [0u32; GROUPS_INLINE];
    if n > 0 {
        if n <= GROUPS_INLINE {
            // Copy into stack buffer, then write to task inline.
            let mut tmp = [0u8; GROUPS_INLINE * 4];
            if !copy_from_user(pt_root, groups_ptr as usize, &mut tmp[..n * 4]) {
                return u64::MAX;
            }
            for i in 0..n {
                let off = i * 4;
                inline_buf[i] = u32::from_le_bytes([tmp[off], tmp[off+1], tmp[off+2], tmp[off+3]]);
            }
        } else {
            // Copy directly into the overflow page.
            let dst = unsafe { core::slice::from_raw_parts_mut(overflow_page as *mut u8, n * 4) };
            if !copy_from_user(pt_root, groups_ptr as usize, dst) {
                crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(overflow_page));
                return u64::MAX;
            }
        }
    }

    // Apply lock-free: only the current task modifies its own groups.
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let task_id = crate::sched::scheduler::thread_ref(tid).task_id;
    let task = unsafe { crate::sched::scheduler::task_mut_from_ref(task_id) };
    // Free old overflow page if present.
    let old_overflow = task.groups_overflow;
    if n <= GROUPS_INLINE {
        task.groups_inline[..n].copy_from_slice(&inline_buf[..n]);
        task.groups_overflow = 0;
    } else {
        task.groups_overflow = overflow_page;
    }
    task.ngroups = n as u32;

    // Free old overflow page outside lock.
    if old_overflow != 0 {
        crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(old_overflow));
    }
    0
}

/// getgroups: get supplementary group list.
/// a0 = max count (0 = just return count), a1 = pointer to u32 array.
fn sys_wait4(pid: u64, flags: u64, frame: &mut ExceptionFrame) -> u64 {
    // Convert port_id-based pid to internal task_id-based pid for wait4.
    let internal_pid = if pid == u64::MAX || pid as i64 == -1 {
        -1i64 // any child
    } else if pid == 0 {
        0i64 // same pgroup
    } else if (pid as i64) < 0 {
        // Negative port_id: specific pgroup leader
        let leader_port = (-(pid as i64)) as u64;
        match resolve_task_port(leader_port) {
            Some(t) => -(t as i64),
            None => { set_return(frame, u64::MAX); return u64::MAX; }
        }
    } else {
        // Positive: specific child task port_id
        match resolve_task_port(pid) {
            Some(t) => t as i64,
            None => { set_return(frame, u64::MAX); return u64::MAX; }
        }
    };
    let (child_port, child_id, status) = crate::sched::scheduler::wait4(internal_pid, flags as u32);
    set_reg(frame, 1, status as u64);
    if child_id < 0 {
        u64::MAX // ECHILD
    } else if child_id == 0 {
        0 // WNOHANG, no child ready
    } else {
        child_port
    }
}

fn sys_getrlimit(resource: u64, frame: &mut ExceptionFrame) -> u64 {
    use crate::sched::task::RLIMIT_COUNT;
    if resource as usize >= RLIMIT_COUNT { return u64::MAX; }
    let task_id = crate::sched::current_task_id();
    let rl = &crate::sched::scheduler::task_ref(task_id).rlimits[resource as usize];
    let cur = rl.cur;
    let max = rl.max;
    // Return 0 for success, soft in a1, hard in a2.
    set_reg(frame, 1, cur);
    set_reg(frame, 2, max);
    0
}

fn sys_setrlimit(resource: u64, new_cur: u64, new_max: u64) -> u64 {
    use crate::sched::task::{RLIMIT_COUNT, RLIM_INFINITY};
    if resource as usize >= RLIMIT_COUNT { return u64::MAX; }
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let task_id = crate::sched::scheduler::thread_ref(tid).task_id;
    let task = crate::sched::scheduler::task_ref(task_id);
    let euid = task.euid;
    let old_max = task.rlimits[resource as usize].max;

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

    // Safe: only the current task modifies its own rlimits.
    let task_mut = unsafe { crate::sched::scheduler::task_mut_from_ref(task_id) };
    task_mut.rlimits[resource as usize].cur = new_cur;
    task_mut.rlimits[resource as usize].max = new_max;
    0
}

fn sys_prlimit(pid: u64, resource: u64, new_cur: u64, new_max: u64, frame: &mut ExceptionFrame) -> u64 {
    use crate::sched::task::{RLIMIT_COUNT, RLIM_INFINITY};
    if resource as usize >= RLIMIT_COUNT { return u64::MAX; }

    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let caller_task_id = crate::sched::scheduler::thread_ref(tid).task_id;
    let euid = crate::sched::scheduler::task_ref(caller_task_id).euid;

    // Resolve target: pid=0 means self, otherwise it's a task port_id.
    let target_task_id = if pid == 0 {
        caller_task_id
    } else {
        let p = match resolve_task_port(pid) {
            Some(t) => t,
            None => return u64::MAX,
        };
        let target = match crate::sched::scheduler::task_ref_opt(p) {
            Some(t) => t,
            None => return u64::MAX,
        };
        if !target.active { return u64::MAX; }
        if euid != 0 && target.parent_task != caller_task_id {
            return u64::MAX;
        }
        p
    };

    // Read old values.
    let target_task = crate::sched::scheduler::task_ref(target_task_id);
    let rl = &target_task.rlimits[resource as usize];
    let old_cur = rl.cur;
    let old_max = rl.max;

    // Set new values (if new_cur != RLIM_INFINITY-1, treat as "set").
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

        // Safe: only root or parent modifies target's rlimits.
        let task_mut = unsafe { crate::sched::scheduler::task_mut_from_ref(target_task_id) };
        task_mut.rlimits[resource as usize].cur = set_cur;
        task_mut.rlimits[resource as usize].max = set_max;
    }

    // Return 0 for success, old soft in a1, old hard in a2.
    set_reg(frame, 1, old_cur);
    set_reg(frame, 2, old_max);
    0
}

fn sys_getgroups(max_count: u64, groups_ptr: u64) -> u64 {
    use crate::sched::task::GROUPS_INLINE;
    let (n, pt_root, inline_copy, overflow_addr) = {
        let task_id = crate::sched::current_task_id();
        let task = crate::sched::scheduler::task_ref(task_id);
        (task.ngroups as usize, task.page_table_root, task.groups_inline, task.groups_overflow)
    };
    if max_count == 0 {
        return n as u64;
    }
    if (max_count as usize) < n {
        return u64::MAX; // EINVAL — buffer too small
    }
    if groups_ptr == 0 || n == 0 {
        return n as u64;
    }
    if n <= GROUPS_INLINE {
        // Serialize inline groups to byte buffer, then copy_to_user.
        let mut tmp = [0u8; GROUPS_INLINE * 4];
        for i in 0..n {
            let bytes = inline_copy[i].to_le_bytes();
            let off = i * 4;
            tmp[off] = bytes[0]; tmp[off+1] = bytes[1];
            tmp[off+2] = bytes[2]; tmp[off+3] = bytes[3];
        }
        if !copy_to_user(pt_root, groups_ptr as usize, &tmp[..n * 4]) {
            return u64::MAX;
        }
    } else {
        // Copy directly from overflow page to userspace.
        let src = unsafe { core::slice::from_raw_parts(overflow_addr as *const u8, n * 4) };
        if !copy_to_user(pt_root, groups_ptr as usize, src) {
            return u64::MAX;
        }
    }
    n as u64
}

// ============================================================
// Phase 77: madvise
// ============================================================

fn sys_madvise(addr: u64, len: u64, advice: u64) -> u64 {
    const MADV_DONTNEED: u64 = 4;

    match advice {
        MADV_DONTNEED => {
            let va_start = addr as usize;
            let va_end = va_start + len as usize;
            let aspace_id = crate::sched::scheduler::current_aspace_id();
            crate::mm::aspace::with_aspace_mut(aspace_id, |aspace| {
                aspace.madvise_dontneed(va_start, va_end);
            });
            0
        }
        _ => 0, // MADV_NORMAL, MADV_WILLNEED: no-op
    }
}

// ============================================================
// Phase 74: TLS set/get
// ============================================================

fn sys_tls_set(base: u64) -> u64 {
    let tid = crate::sched::scheduler::current_thread_id();
    // Safe: only the current thread modifies its own tls_base.
    unsafe { crate::sched::scheduler::thread_mut_from_ref(tid) }.tls_base = base;

    crate::arch::cpu::set_tls(base);
    0
}

fn sys_tls_get() -> u64 {
    let tid = crate::sched::scheduler::current_thread_id();
    match crate::sched::scheduler::thread_ref_opt(tid) {
        Some(t) => t.tls_base,
        None => 0,
    }
}

// ============================================================
// Phase 75: port_set_recv with timeout
// ============================================================

fn sys_port_set_recv_timeout(set_id: u64, timeout_us: u64, frame: &mut ExceptionFrame) {
    // Try non-blocking port_set_recv from the set.
    match crate::ipc::port_set::recv(set_id as u32) {
        Some((port_id, msg)) => {
            let task_id = crate::sched::current_task_id();
            auto_grant_sender_identity(task_id, msg.data[4]);
            auto_grant_reply_caps(task_id, &msg);
            set_reg(frame, 1, msg.tag);
            set_reg(frame, 2, msg.data[0]);
            set_reg(frame, 3, msg.data[1]);
            set_reg(frame, 4, msg.data[2]);
            set_reg(frame, 5, msg.data[3]);
            set_reg(frame, 6, msg.data[4]);
            set_reg(frame, 7, msg.data[5]);
            let result = port_id as u64;
            set_return(frame, result);
            let nr = SYS_PORT_SET_RECV_TIMEOUT;
            crate::trace::trace_event(crate::trace::EVT_SYSCALL_EXIT, nr as u32, result as u32);
            if crate::sched::scheduler::current_aspace_id() != 0 {
                deliver_pending_signals(frame);
            }
        }
        None => {
            if timeout_us == 0xFFFFFFFFFFFFFFFF {
                // Infinite timeout — use blocking recv.
                let result = sys_port_set_recv(set_id, frame);
                set_return(frame, result);
                let nr = SYS_PORT_SET_RECV_TIMEOUT;
                crate::trace::trace_event(crate::trace::EVT_SYSCALL_EXIT, nr as u32, result as u32);
                if crate::sched::scheduler::current_aspace_id() != 0 {
                    deliver_pending_signals(frame);
                }
            } else {
                // Timeout (including 0) — return u64::MAX.
                set_return(frame, u64::MAX);
                let nr = SYS_PORT_SET_RECV_TIMEOUT;
                crate::trace::trace_event(crate::trace::EVT_SYSCALL_EXIT, nr as u32, u64::MAX as u32);
                if crate::sched::scheduler::current_aspace_id() != 0 {
                    deliver_pending_signals(frame);
                }
            }
        }
    }
}

// ============================================================
// Phase 76: timer_create and mmap_guard
// ============================================================

fn sys_timer_create(signal_num: u64, interval_ns: u64) -> u64 {
    let tid = crate::sched::scheduler::current_thread_id();
    // Safe: only the current thread modifies its own timer fields.
    let t = unsafe { crate::sched::scheduler::thread_mut_from_ref(tid) };
    t.timer_signal = signal_num as u32;
    t.timer_interval_ns = interval_ns;
    if interval_ns > 0 {
        t.timer_next_ns = crate::sched::get_monotonic_ns() + interval_ns;
    } else {
        t.timer_next_ns = 0;
    }
    0
}

fn sys_mmap_guard(addr: u64, pages: u64) -> u64 {
    use crate::mm::vma::VmaProt;
    // Map pages with no permissions — access triggers SIGSEGV.
    let aspace_id = crate::sched::scheduler::current_aspace_id();
    let va = addr as usize;
    let count = pages as usize;
    match crate::mm::aspace::with_aspace_mut(aspace_id, |aspace| {
        aspace.map_anon(va, count, VmaProt::None).map(|vma| vma.va_start)
    }) {
        Some(Some(va_start)) => va_start as u64,
        _ => u64::MAX,
    }
}

// ============================================================
// Phase 92: getrandom
// ============================================================

fn sys_getrandom(buf_ptr: u64, buflen: u64, _flags: u64) -> u64 {
    use crate::sync::spinlock::SpinLock;

    static PRNG_STATE: SpinLock<[u64; 4]> = SpinLock::new([0u64; 4]);

    /// Xoshiro256** next — fast, decent quality PRNG.
    fn xoshiro_next(s: &mut [u64; 4]) -> u64 {
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }

    let len = if buflen > 256 { 256 } else { buflen as usize };
    if len == 0 || buf_ptr == 0 {
        return 0;
    }

    // Generate random bytes into a stack buffer.
    let mut tmp = [0u8; 256];
    {
        let mut state = PRNG_STATE.lock();
        // Lazy seed from monotonic clock on first use.
        if state[0] == 0 && state[1] == 0 && state[2] == 0 && state[3] == 0 {
            let seed = crate::sched::get_monotonic_ns();
            // Splitmix64 to expand a single seed into 4 state words.
            let mut z = seed;
            for s in state.iter_mut() {
                z = z.wrapping_add(0x9e3779b97f4a7c15);
                let mut v = z;
                v = (v ^ (v >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                v = (v ^ (v >> 27)).wrapping_mul(0x94d049bb133111eb);
                *s = v ^ (v >> 31);
            }
        }
        let mut offset = 0;
        while offset < len {
            let val = xoshiro_next(&mut state);
            let bytes = val.to_le_bytes();
            let remaining = len - offset;
            let n = if remaining < 8 { remaining } else { 8 };
            tmp[offset..offset + n].copy_from_slice(&bytes[..n]);
            offset += n;
        }
    }

    // Copy to userspace (lock-free).
    let pt_root = crate::sched::scheduler::current_page_table_root();

    if !copy_to_user(pt_root, buf_ptr as usize, &tmp[..len]) {
        return u64::MAX;
    }
    len as u64
}

// ============================================================
// Phase 99: sigsuspend and sigaltstack
// ============================================================

fn sys_sigsuspend(mask: u64) -> u64 {
    // Save old mask, install new one, yield until an unmasked signal is pending.
    let old_mask = crate::sched::get_signal_mask();
    crate::sched::set_signal_mask(mask);

    // Yield in a loop until a signal is pending that is not blocked by the new mask.
    loop {
        let pending = crate::sched::get_signal_pending();
        if pending & !mask != 0 {
            break;
        }
        // Yield to scheduler, waiting for a signal.
        let tid = crate::sched::current_thread_id();
        crate::sched::scheduler::set_yield_asap(tid);
        let saved = crate::sched::scheduler::arch_irq_save_enable();
        crate::sched::scheduler::arch_wait_for_irq();
        crate::sched::scheduler::arch_irq_restore(saved);
    }

    // Restore old mask.
    crate::sched::set_signal_mask(old_mask);
    0
}

fn sys_sigaltstack(ss_ptr: u64, old_ss_ptr: u64) -> u64 {
    let tid = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
    let t = crate::sched::scheduler::thread_ref(tid);
    let task_id = t.task_id;
    let pt_root = crate::sched::scheduler::task_ref(task_id).page_table_root;
    let old_base = t.sig_altstack_base;
    let old_size = t.sig_altstack_size;

    // Write old stack info if requested.
    if old_ss_ptr != 0 {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&old_base.to_le_bytes());
        buf[8..16].copy_from_slice(&old_size.to_le_bytes());
        if !copy_to_user(pt_root, old_ss_ptr as usize, &buf) {
            return u64::MAX;
        }
    }

    // Read new stack info if requested.
    if ss_ptr != 0 {
        let mut buf = [0u8; 16];
        if !copy_from_user(pt_root, ss_ptr as usize, &mut buf) {
            return u64::MAX;
        }
        let new_base = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
        let new_size = u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]);
        let tid2 = crate::sched::smp::current().current_thread.load(core::sync::atomic::Ordering::Relaxed);
        // Safe: only the current thread modifies its own sigaltstack.
        let t = unsafe { crate::sched::scheduler::thread_mut_from_ref(tid2) };
        t.sig_altstack_base = new_base;
        t.sig_altstack_size = new_size;
    }
    0
}
