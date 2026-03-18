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
        _ => {
            crate::println!("Unknown syscall: {}", nr);
            u64::MAX // -1 as error
        }
    };

    set_return(frame, result);

    // Check if this thread was killed — terminate before returning to userspace.
    let tid = crate::sched::scheduler::current_thread_id();
    if crate::sched::scheduler::is_killed(tid) {
        crate::sched::scheduler::exit_current_thread(-9);
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

    // Check page quota.
    let task_id = crate::sched::current_task_id();
    if task_id != 0 {
        let sched = crate::sched::scheduler::SCHEDULER.lock();
        let task = &sched.tasks[task_id as usize];
        if task.cur_pages + pages as u32 > task.max_pages {
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
            obj.ensure_page(page_idx)
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

/// Poll: returns exit code if target thread is dead and in same task, else u64::MAX.
fn sys_thread_join(tid: u64) -> u64 {
    let caller_task = crate::sched::scheduler::current_task_id();
    match crate::sched::thread_join_poll(tid as u32, caller_task) {
        Some(exit_code) => exit_code as u64,
        None => u64::MAX,
    }
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
