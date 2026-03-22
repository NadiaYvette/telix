//! Safe syscall wrappers for Telix userspace.

use crate::arch;

// Syscall numbers (must match kernel/src/syscall/handlers.rs).
const SYS_DEBUG_PUTCHAR: u64 = 0;
const SYS_PORT_CREATE: u64 = 1;
const SYS_PORT_DESTROY: u64 = 2;
const SYS_SEND: u64 = 3;
const SYS_SEND_NB: u64 = 9;
const SYS_RECV_NB: u64 = 10;
const SYS_RECV: u64 = 4;
const SYS_YIELD: u64 = 7;
const SYS_THREAD_ID: u64 = 8;
const SYS_EXIT: u64 = 11;
const SYS_SPAWN: u64 = 12;
const SYS_DEBUG_PUTS: u64 = 14;
const SYS_WAITPID: u64 = 15;
const SYS_MMAP_ANON: u64 = 16;
const SYS_MUNMAP: u64 = 17;
const SYS_GRANT_PAGES: u64 = 18;
const SYS_REVOKE: u64 = 19;
const SYS_ASPACE_ID: u64 = 20;
const SYS_GET_INITRAMFS_PORT: u64 = 21;
const SYS_MMAP_DEVICE: u64 = 24;
const SYS_VIRT_TO_PHYS: u64 = 25;
const SYS_IRQ_WAIT: u64 = 26;
const SYS_GETCHAR: u64 = 27;
const SYS_IOPORT: u64 = 28;
const SYS_SPAWN_ELF: u64 = 29;
const SYS_THREAD_CREATE: u64 = 30;
const SYS_THREAD_JOIN: u64 = 31;
const SYS_FUTEX_WAIT: u64 = 32;
const SYS_FUTEX_WAKE: u64 = 33;
const SYS_KILL: u64 = 34;
const SYS_GETPID: u64 = 35;
const SYS_GET_CYCLES: u64 = 36;
const SYS_GET_TIMER_FREQ: u64 = 37;
const SYS_PORT_SET_CREATE: u64 = 5;
const SYS_PORT_SET_ADD: u64 = 6;
#[allow(dead_code)]
const SYS_PORT_SET_RECV: u64 = 22;
const SYS_NSRV_PORT: u64 = 23;

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

/// Destroy an IPC port, freeing the port ID for reuse.
pub fn port_destroy(port: u32) {
    unsafe { arch::syscall1(SYS_PORT_DESTROY, port as u64); }
}

/// Non-blocking send on a port (2 data words, rest zeroed).
pub fn send_nb(port: u32, tag: u64, d0: u64, d1: u64) -> u64 {
    unsafe { arch::syscall6(SYS_SEND_NB, port as u64, tag, d0, d1, 0, 0) }
}

/// Non-blocking send on a port with all 4 data words.
pub fn send_nb_4(port: u32, tag: u64, d0: u64, d1: u64, d2: u64, d3: u64) -> u64 {
    unsafe { arch::syscall6(SYS_SEND_NB, port as u64, tag, d0, d1, d2, d3) }
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

/// Yield and wait for the next interrupt (WFI/HLT).
/// Use when the caller has no work to do — more efficient than a
/// tight yield_now() loop on QEMU TCG.
pub fn yield_block() {
    unsafe { arch::syscall0(SYS_YIELD_BLOCK); }
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
    unsafe { arch::syscall4(SYS_SPAWN, name.as_ptr() as u64, name.len() as u64, priority as u64, 0) }
}

/// Wait for a child thread to exit. Returns Some(exit_code) or None.
pub fn waitpid(child_tid: u64) -> Option<u64> {
    let r = unsafe { arch::syscall1(SYS_WAITPID, child_tid) };
    if r == u64::MAX { None } else { Some(r) }
}

/// Allocate anonymous pages. va=0 for auto-pick. prot: 0=RO, 1=RW, 2=RX, 3=RWX.
/// Returns mapped VA or None on error.
pub fn mmap_anon(va: usize, page_count: usize, prot: u8) -> Option<usize> {
    let r = unsafe { arch::syscall3(SYS_MMAP_ANON, va as u64, page_count as u64, prot as u64) };
    if r == u64::MAX { None } else { Some(r as usize) }
}

/// Unmap a previously mmap'd region. Returns true on success.
pub fn munmap(va: usize) -> bool {
    let r = unsafe { arch::syscall1(SYS_MUNMAP, va as u64) };
    r == 0
}

/// Grant pages from our address space to another.
pub fn grant_pages(dst_aspace: u32, src_va: usize, dst_va: usize, page_count: usize, readonly: bool) -> bool {
    let r = unsafe { arch::syscall5(SYS_GRANT_PAGES, dst_aspace as u64, src_va as u64, dst_va as u64, page_count as u64, readonly as u64) };
    r == 0
}

/// Revoke a grant.
pub fn revoke(dst_aspace: u32, dst_va: usize) -> bool {
    let r = unsafe { arch::syscall2(SYS_REVOKE, dst_aspace as u64, dst_va as u64) };
    r == 0
}

/// Get our address space ID.
pub fn aspace_id() -> u32 {
    unsafe { arch::syscall0(SYS_ASPACE_ID) as u32 }
}

/// Spawn a new process with an argument passed to main().
pub fn spawn_with_arg(name: &[u8], priority: u8, arg0: u64) -> u64 {
    unsafe { arch::syscall4(SYS_SPAWN, name.as_ptr() as u64, name.len() as u64, priority as u64, arg0) }
}

/// Spawn a new process from ELF data in memory. Returns thread ID or u64::MAX.
pub fn spawn_elf(elf_data: &[u8], priority: u8, arg0: u64) -> u64 {
    unsafe { arch::syscall4(SYS_SPAWN_ELF, elf_data.as_ptr() as u64, elf_data.len() as u64, priority as u64, arg0) }
}

/// Create a new thread in the current process. Returns thread ID or u64::MAX on error.
/// `entry` is the user function address, `stack_top` is the top of the pre-allocated stack,
/// `arg` is passed as the first argument to the entry function.
pub fn thread_create(entry: u64, stack_top: u64, arg: u64) -> u64 {
    unsafe { arch::syscall3(SYS_THREAD_CREATE, entry, stack_top, arg) }
}

/// Poll: check if a thread has exited. Returns Some(exit_code) or None.
pub fn thread_join_poll(tid: u32) -> Option<i64> {
    let r = unsafe { arch::syscall1(SYS_THREAD_JOIN, tid as u64) };
    if r == u64::MAX { None } else { Some(r as i64) }
}

/// Block until a thread exits. Returns its exit code.
/// The kernel blocks the caller until the target thread exits.
pub fn thread_join(tid: u32) -> i64 {
    unsafe { arch::syscall1(SYS_THREAD_JOIN, tid as u64) as i64 }
}

/// Block if the u32 at `addr` equals `expected`. Returns 0 on wake, 1 on value mismatch.
pub fn futex_wait(addr: *const u32, expected: u32) -> u64 {
    unsafe { arch::syscall2(SYS_FUTEX_WAIT, addr as u64, expected as u64) }
}

/// Wake up to `count` threads waiting on the futex at `addr`. Returns number woken.
pub fn futex_wake(addr: *const u32, count: u32) -> u64 {
    unsafe { arch::syscall2(SYS_FUTEX_WAKE, addr as u64, count as u64) }
}

/// Kill all threads in the task that `tid` belongs to. Returns true on success.
pub fn kill(tid: u32) -> bool {
    unsafe { arch::syscall1(SYS_KILL, tid as u64) == 0 }
}

/// Get the current process (task) ID.
pub fn getpid() -> u32 {
    unsafe { arch::syscall0(SYS_GETPID) as u32 }
}

/// Read the hardware cycle/timer counter.
pub fn get_cycles() -> u64 {
    unsafe { arch::syscall0(SYS_GET_CYCLES) }
}

/// Get the timer frequency in Hz.
pub fn get_timer_freq() -> u64 {
    unsafe { arch::syscall0(SYS_GET_TIMER_FREQ) }
}

/// Get the userspace initramfs server's port ID.
pub fn get_initramfs_port() -> u32 {
    unsafe { arch::syscall0(SYS_GET_INITRAMFS_PORT) as u32 }
}

/// IPC message with tag + 6 data words.
pub struct Message {
    pub tag: u64,
    pub data: [u64; 6],
}

/// Blocking receive that returns the full message (tag + data).
pub fn recv_msg(port: u32) -> Option<Message> {
    let status: u64;
    let r1: u64;
    let r2: u64;
    let r3: u64;
    let r4: u64;
    let r5: u64;
    let r6: u64;
    let r7: u64;

    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_RECV,
            inlateout("x0") port as u64 => status,
            lateout("x1") r1,
            lateout("x2") r2,
            lateout("x3") r3,
            lateout("x4") r4,
            lateout("x5") r5,
            lateout("x6") r6,
            lateout("x7") r7,
        );
    }

    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a7") SYS_RECV as u64 => r7,
            inlateout("a0") port as u64 => status,
            lateout("a1") r1,
            lateout("a2") r2,
            lateout("a3") r3,
            lateout("a4") r4,
            lateout("a5") r5,
            lateout("a6") r6,
        );
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "push rbx",
            "int 0x80",
            "mov {r7}, rbx",
            "pop rbx",
            r7 = lateout(reg) r7,
            inlateout("rax") SYS_RECV => status,
            inlateout("rdi") port as u64 => r1,
            lateout("rsi") r2,
            lateout("rdx") r3,
            lateout("r10") r4,
            lateout("r8") r5,
            lateout("r9") r6,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }

    if status != 0 {
        return None;
    }

    Some(Message {
        tag: r1,
        data: [r2, r3, r4, r5, r6, r7],
    })
}

/// Get the name server port.
pub fn nsrv_port() -> u32 {
    unsafe { arch::syscall0(SYS_NSRV_PORT) as u32 }
}

/// Create a port set.
pub fn port_set_create() -> u64 {
    unsafe { arch::syscall0(SYS_PORT_SET_CREATE) }
}

/// Add a port to a port set.
pub fn port_set_add(set_id: u32, port_id: u32) -> bool {
    unsafe { arch::syscall2(SYS_PORT_SET_ADD, set_id as u64, port_id as u64) == 0 }
}

/// Pack a name (up to 24 bytes) into 3 u64 words.
pub fn pack_name(name: &[u8]) -> (u64, u64, u64) {
    let mut words = [0u64; 3];
    for (i, &b) in name.iter().enumerate().take(24) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    (words[0], words[1], words[2])
}

/// Lookup a service by name via the name server. Returns port ID or None.
pub fn ns_lookup(name: &[u8]) -> Option<u32> {
    let nsrv = nsrv_port();
    if nsrv == u32::MAX { return None; }

    let reply_port = port_create() as u32;
    let (n0, n1, n2) = pack_name(name);
    let d3 = (name.len() as u64) | ((reply_port as u64) << 32);

    // NS_LOOKUP = 0x1100
    send(nsrv, 0x1100, n0, n1, n2, d3);

    let result = if let Some(reply) = recv_msg(reply_port) {
        if reply.tag == 0x1101 {
            let port = reply.data[0] as u32;
            if port != u32::MAX { Some(port) } else { None }
        } else {
            None
        }
    } else {
        None
    };
    port_destroy(reply_port);
    result
}

/// Map device MMIO registers into userspace. Returns VA or None.
pub fn mmap_device(phys: usize, page_count: usize) -> Option<usize> {
    let r = unsafe { arch::syscall2(SYS_MMAP_DEVICE, phys as u64, page_count as u64) };
    if r == u64::MAX { None } else { Some(r as usize) }
}

/// Translate a virtual address to physical. Returns PA or None.
pub fn virt_to_phys(va: usize) -> Option<usize> {
    let r = unsafe { arch::syscall1(SYS_VIRT_TO_PHYS, va as u64) };
    if r == u64::MAX { None } else { Some(r as usize) }
}

/// Wait for a device IRQ. On first call, pass mmio_base to register.
/// Subsequent calls: pass mmio_base=0.
pub fn irq_wait(irq: u32, mmio_base: usize) -> u64 {
    unsafe { arch::syscall2(SYS_IRQ_WAIT, irq as u64, mmio_base as u64) }
}

/// Non-blocking read of a single character from the serial console.
pub fn getchar() -> Option<u8> {
    let r = unsafe { arch::syscall0(SYS_GETCHAR) };
    if r == u64::MAX { None } else { Some(r as u8) }
}

/// Non-blocking receive that returns the full message, or None if queue is empty.
pub fn recv_nb_msg(port: u32) -> Option<Message> {
    let status: u64;
    let r1: u64;
    let r2: u64;
    let r3: u64;
    let r4: u64;
    let r5: u64;
    let r6: u64;
    let r7: u64;

    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_RECV_NB,
            inlateout("x0") port as u64 => status,
            lateout("x1") r1,
            lateout("x2") r2,
            lateout("x3") r3,
            lateout("x4") r4,
            lateout("x5") r5,
            lateout("x6") r6,
            lateout("x7") r7,
        );
    }

    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a7") SYS_RECV_NB as u64 => r7,
            inlateout("a0") port as u64 => status,
            lateout("a1") r1,
            lateout("a2") r2,
            lateout("a3") r3,
            lateout("a4") r4,
            lateout("a5") r5,
            lateout("a6") r6,
        );
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "push rbx",
            "int 0x80",
            "mov {r7}, rbx",
            "pop rbx",
            r7 = lateout(reg) r7,
            inlateout("rax") SYS_RECV_NB => status,
            inlateout("rdi") port as u64 => r1,
            lateout("rsi") r2,
            lateout("rdx") r3,
            lateout("r10") r4,
            lateout("r8") r5,
            lateout("r9") r6,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }

    if status != 0 {
        return None;
    }

    Some(Message {
        tag: r1,
        data: [r2, r3, r4, r5, r6, r7],
    })
}

/// Read a byte from an I/O port (x86_64 only).
pub fn ioport_inb(port: u16) -> u8 {
    unsafe { arch::syscall2(SYS_IOPORT, 0, port as u64) as u8 }
}

/// Read a 16-bit word from an I/O port (x86_64 only).
pub fn ioport_inw(port: u16) -> u16 {
    unsafe { arch::syscall2(SYS_IOPORT, 1, port as u64) as u16 }
}

/// Read a 32-bit dword from an I/O port (x86_64 only).
pub fn ioport_inl(port: u16) -> u32 {
    unsafe { arch::syscall2(SYS_IOPORT, 2, port as u64) as u32 }
}

/// Write a byte to an I/O port (x86_64 only).
pub fn ioport_outb(port: u16, val: u8) {
    unsafe { arch::syscall3(SYS_IOPORT, 3, port as u64, val as u64); }
}

/// Write a 16-bit word to an I/O port (x86_64 only).
pub fn ioport_outw(port: u16, val: u16) {
    unsafe { arch::syscall3(SYS_IOPORT, 4, port as u64, val as u64); }
}

/// Write a 32-bit dword to an I/O port (x86_64 only).
pub fn ioport_outl(port: u16, val: u32) {
    unsafe { arch::syscall3(SYS_IOPORT, 5, port as u64, val as u64); }
}

const SYS_SET_QUOTA: u64 = 38;

/// Set a resource quota on a child task.
/// resource_type: 0=ports, 1=threads, 2=pages. Returns true on success.
pub fn set_quota(child_task: u32, resource_type: u32, limit: u32) -> bool {
    unsafe { arch::syscall3(SYS_SET_QUOTA, child_task as u64, resource_type as u64, limit as u64) == 0 }
}

const SYS_EXECVE: u64 = 54;
const SYS_SIGACTION: u64 = 55;
const SYS_SIGPROCMASK: u64 = 56;
const SYS_SIGRETURN: u64 = 57;
const SYS_KILL_SIG: u64 = 58;
const SYS_SIGPENDING: u64 = 59;
const SYS_FORK: u64 = 39;
const SYS_SEND_CAP: u64 = 40;
#[allow(dead_code)]
const SYS_CAP_REVOKE: u64 = 41;

/// Fork the current process. Returns child task ID to parent (>0),
/// 0 to the child, or 0 on failure.
pub fn fork() -> u64 {
    unsafe { arch::syscall0(SYS_FORK) }
}

/// Replace the current process image with a new ELF from initramfs.
/// On success, this function never returns. On failure, returns u64::MAX.
pub fn execve(name: &[u8]) -> u64 {
    unsafe { arch::syscall2(SYS_EXECVE, name.as_ptr() as u64, name.len() as u64) }
}

// Signal constants.
pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;
pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGABRT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGUSR2: u32 = 12;
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
pub const SIGTERM: u32 = 15;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;

/// Bitmask for a signal number (1-based).
pub const fn sig_bit(sig: u32) -> u64 {
    if sig >= 1 && sig <= 32 { 1u64 << (sig - 1) } else { 0 }
}

/// Install a signal handler. handler: 0=SIG_DFL, 1=SIG_IGN, else=function pointer.
/// sa_mask: additional signals to mask during handler execution.
/// flags: bit 0 = SA_RESTART.
/// Returns the previous handler, or u64::MAX on error.
pub fn sigaction(sig: u32, handler: u64, sa_mask: u64, flags: u64) -> u64 {
    unsafe { arch::syscall4(SYS_SIGACTION, sig as u64, handler, sa_mask, flags) }
}

/// Modify the signal mask. how: 0=SIG_BLOCK, 1=SIG_UNBLOCK, 2=SIG_SETMASK.
/// Returns the previous mask.
pub fn sigprocmask(how: u32, set: u64) -> u64 {
    unsafe { arch::syscall2(SYS_SIGPROCMASK, how as u64, set) }
}

/// Restore the pre-signal state after a signal handler completes.
/// `frame_addr` is the signal frame address passed as the second argument to the handler.
pub fn sigreturn(frame_addr: u64) {
    unsafe { arch::syscall1(SYS_SIGRETURN, frame_addr); }
}

/// Get the set of pending signals.
pub fn sigpending() -> u64 {
    unsafe { arch::syscall0(SYS_SIGPENDING) }
}

/// Send a specific signal to a task (identified by any thread ID in it).
pub fn kill_sig(tid: u32, sig: u32) -> bool {
    unsafe { arch::syscall2(SYS_KILL_SIG, tid as u64, sig as u64) == 0 }
}

/// Send a message with an attached capability transfer.
/// Grants the specified port's capability (with given rights) to the
/// receiver on dest_port. The receiver gets:
///   data[0] = d0, data[1] = d1, data[2] = receiver's new cap slot,
///   data[3] = granted port ID, data[4] = granted rights.
pub fn send_cap(dest_port: u32, tag: u64, d0: u64, d1: u64, grant_port: u32, grant_rights: u32) -> bool {
    unsafe {
        arch::syscall6(SYS_SEND_CAP, dest_port as u64, tag, d0, d1,
            grant_port as u64, grant_rights as u64) == 0
    }
}

/// Revoke all derived capabilities for a port.
/// Requires MANAGE right on the port. Returns number of caps revoked.
#[allow(dead_code)]
pub fn cap_revoke(port_id: u32) -> u64 {
    unsafe { arch::syscall1(SYS_CAP_REVOKE, port_id as u64) }
}

const SYS_VM_STATS: u64 = 42;
const SYS_SA_REGISTER: u64 = 43;
const SYS_SA_WAIT: u64 = 44;
const SYS_SA_GETID: u64 = 45;
const SYS_COSCHED_SET: u64 = 46;
const SYS_SET_AFFINITY: u64 = 47;
const SYS_GET_AFFINITY: u64 = 48;
const SYS_CPU_TOPOLOGY: u64 = 49;
const SYS_CPU_HOTPLUG: u64 = 52;
const SYS_CPU_LOAD: u64 = 53;

/// Query VM statistics. which: 0=superpage_promotions, 1=superpage_demotions.
#[allow(dead_code)]
pub fn vm_stats(which: u32) -> u64 {
    unsafe { arch::syscall1(SYS_VM_STATS, which as u64) }
}

/// Register the current task for scheduler activations.
pub fn sa_register() {
    unsafe { arch::syscall0(SYS_SA_REGISTER); }
}

/// Block until a scheduler activation event occurs.
/// Returns the blocked kthread's TID.
pub fn sa_wait() -> u64 {
    unsafe { arch::syscall0(SYS_SA_WAIT) }
}

/// Get the index (0-based) of the current kthread within its task.
pub fn sa_getid() -> u64 {
    unsafe { arch::syscall0(SYS_SA_GETID) }
}

/// Set the coscheduling group for the current thread. group=0 removes from any group.
pub fn cosched_set(group: u32) {
    unsafe { arch::syscall1(SYS_COSCHED_SET, group as u64); }
}

/// Set CPU affinity mask for a thread. Returns true on success.
pub fn set_affinity(tid: u32, mask: u64) -> bool {
    let r = unsafe { arch::syscall2(SYS_SET_AFFINITY, tid as u64, mask) };
    r == 0
}

/// Get CPU affinity mask for a thread.
pub fn get_affinity(tid: u32) -> u64 {
    unsafe { arch::syscall1(SYS_GET_AFFINITY, tid as u64) }
}

/// Query CPU topology for a given CPU index.
/// Returns (package_id, core_id, smt_id, online, online_cpu_count), or None if invalid.
pub fn cpu_topology(cpu_id: u32) -> Option<(u8, u8, u8, bool, u32)> {
    let r = unsafe { arch::syscall1(SYS_CPU_TOPOLOGY, cpu_id as u64) };
    if r == u64::MAX { return None; }
    let pkg = (r & 0xFF) as u8;
    let core = ((r >> 8) & 0xFF) as u8;
    let smt = ((r >> 16) & 0xFF) as u8;
    let online = ((r >> 24) & 0xFF) != 0;
    let count = (r >> 32) as u32;
    Some((pkg, core, smt, online, count))
}

/// Offline or online a CPU. action: 0 = offline, 1 = online.
/// Returns true on success.
#[allow(dead_code)]
pub fn cpu_hotplug(cpu_id: u32, action: u32) -> bool {
    let r = unsafe { arch::syscall2(SYS_CPU_HOTPLUG, cpu_id as u64, action as u64) };
    r == 0
}

/// Query per-CPU load. Returns (load, window, online_mask) or None.
#[allow(dead_code)]
pub fn cpu_load(cpu_id: u32) -> Option<(u32, u32, u16)> {
    let r = unsafe { arch::syscall1(SYS_CPU_LOAD, cpu_id as u64) };
    if r == u64::MAX { return None; }
    let load = (r & 0xFFFF_FFFF) as u32;
    let window = ((r >> 32) & 0xFFFF) as u32;
    let online_mask = ((r >> 48) & 0xFFFF) as u16;
    Some((load, window, online_mask))
}

const SYS_MPROTECT: u64 = 60;
const SYS_MREMAP: u64 = 61;
const SYS_SETPGID: u64 = 62;
const SYS_GETPGID: u64 = 63;
const SYS_SETSID: u64 = 64;
const SYS_GETSID: u64 = 65;
const SYS_TCSETPGRP: u64 = 66;
const SYS_TCGETPGRP: u64 = 67;
const SYS_SET_CTTY: u64 = 68;
const SYS_CLOCK_GETTIME: u64 = 69;
const SYS_NANOSLEEP: u64 = 70;
const SYS_ALARM: u64 = 71;

/// Change the protection of a memory region.
/// addr and len must be MMUPAGE_SIZE (4K) aligned.
/// prot: 0=RO, 1=RW, 2=RX, 3=RWX.
/// Returns true on success.
pub fn mprotect(addr: usize, len: usize, prot: u8) -> bool {
    let r = unsafe { arch::syscall3(SYS_MPROTECT, addr as u64, len as u64, prot as u64) };
    r == 0
}

/// Resize an existing anonymous mapping.
/// old_addr must be the start of a VMA, old_len must match VMA length.
/// new_len is the desired new size (MMUPAGE_SIZE aligned).
/// Returns the new VA (same as old_addr) or None on error.
pub fn mremap(old_addr: usize, old_len: usize, new_len: usize) -> Option<usize> {
    let r = unsafe { arch::syscall3(SYS_MREMAP, old_addr as u64, old_len as u64, new_len as u64) };
    if r == u64::MAX { None } else { Some(r as usize) }
}

/// Set the process group ID. pid=0 means self, pgid=0 means set pgid=pid.
/// Returns true on success.
pub fn setpgid(pid: u32, pgid: u32) -> bool {
    unsafe { arch::syscall2(SYS_SETPGID, pid as u64, pgid as u64) == 0 }
}

/// Get the process group ID. pid=0 means self.
/// Returns the pgid, or u64::MAX on error.
pub fn getpgid(pid: u32) -> u64 {
    unsafe { arch::syscall1(SYS_GETPGID, pid as u64) }
}

/// Create a new session. Returns the new session ID or u64::MAX on error.
pub fn setsid() -> u64 {
    unsafe { arch::syscall0(SYS_SETSID) }
}

/// Get the session ID. pid=0 means self.
pub fn getsid(pid: u32) -> u64 {
    unsafe { arch::syscall1(SYS_GETSID, pid as u64) }
}

/// Set the foreground process group for the controlling terminal.
pub fn tcsetpgrp(pgid: u32) -> bool {
    unsafe { arch::syscall1(SYS_TCSETPGRP, pgid as u64) == 0 }
}

/// Get the foreground process group for the controlling terminal.
pub fn tcgetpgrp() -> u64 {
    unsafe { arch::syscall0(SYS_TCGETPGRP) }
}

/// Set the controlling terminal for the current session.
/// Only the session leader can call this.
pub fn set_ctty(port: u32) -> bool {
    unsafe { arch::syscall1(SYS_SET_CTTY, port as u64) == 0 }
}

/// Send a signal to a process group. Equivalent to kill(-pgid, sig).
pub fn kill_pgroup(pgid: u32, sig: u32) -> bool {
    let neg_pgid = (-(pgid as i64)) as u64;
    unsafe { arch::syscall2(SYS_KILL_SIG, neg_pgid, sig as u64) == 0 }
}

/// Read the monotonic clock (nanoseconds since boot).
/// clock_id 0 = CLOCK_MONOTONIC (only supported clock).
/// Returns nanoseconds, or u64::MAX on invalid clock_id.
pub fn clock_gettime() -> u64 {
    unsafe { arch::syscall1(SYS_CLOCK_GETTIME, 0) }
}

/// Sleep for `ns` nanoseconds. Returns 0.
pub fn nanosleep(ns: u64) -> u64 {
    unsafe { arch::syscall1(SYS_NANOSLEEP, ns) }
}

/// Sleep for `ms` milliseconds.
pub fn sleep_ms(ms: u64) {
    nanosleep(ms * 1_000_000);
}

/// Set or cancel an interval timer.
/// initial_ns: first firing delay (0 = cancel).
/// interval_ns: repeat interval (0 = one-shot).
/// Returns the previous remaining time in nanoseconds.
pub fn alarm(initial_ns: u64, interval_ns: u64) -> u64 {
    unsafe { arch::syscall2(SYS_ALARM, initial_ns, interval_ns) }
}

const SYS_MMAP_FILE: u64 = 72;
const SYS_WAIT_FAULT: u64 = 73;
const SYS_FAULT_COMPLETE: u64 = 74;
const SYS_GETUID: u64 = 75;
const SYS_GETEUID: u64 = 76;
const SYS_GETGID: u64 = 77;
const SYS_GETEGID: u64 = 78;
const SYS_SETUID: u64 = 79;
const SYS_SETGID: u64 = 80;
const SYS_SETGROUPS: u64 = 81;
const SYS_GETGROUPS: u64 = 82;
const SYS_WAIT4: u64 = 83;
const SYS_GETRLIMIT: u64 = 84;
const SYS_SETRLIMIT: u64 = 85;
const SYS_PRLIMIT: u64 = 86;
const SYS_YIELD_BLOCK: u64 = 87;

/// Map a file-backed region via the pager mechanism.
/// Returns the VA on success, or None on failure.
pub fn mmap_file(va: usize, pages: usize, prot: u8, file_handle: u32, file_offset: u64) -> Option<usize> {
    let lo = file_offset & 0xFFFF_FFFF;
    let hi = file_offset >> 32;
    let r = unsafe {
        arch::syscall6(SYS_MMAP_FILE, va as u64, pages as u64, prot as u64,
                       file_handle as u64, lo, hi)
    };
    if r == u64::MAX { None } else { Some(r as usize) }
}

/// Wait for a pager fault in the current address space.
/// Returns (token, fault_va, file_handle, file_offset, page_size).
pub fn wait_fault() -> (u32, usize, u32, u64, usize) {
    let r0: u64;
    let r1: u64;
    let r2: u64;
    let r3: u64;
    let r4: u64;

    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_WAIT_FAULT,
            lateout("x0") r0,
            lateout("x1") r1,
            lateout("x2") r2,
            lateout("x3") r3,
            lateout("x4") r4,
        );
    }

    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SYS_WAIT_FAULT as u64,
            lateout("a0") r0,
            lateout("a1") r1,
            lateout("a2") r2,
            lateout("a3") r3,
            lateout("a4") r4,
        );
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") SYS_WAIT_FAULT => r0,
            lateout("rdi") r1,
            lateout("rsi") r2,
            lateout("rdx") r3,
            lateout("r10") r4,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }

    (r0 as u32, r1 as usize, r2 as u32, r3, r4 as usize)
}

/// Complete a pager fault by providing the page data.
pub fn fault_complete(token: u32, data: &[u8]) -> bool {
    let r = unsafe {
        arch::syscall3(SYS_FAULT_COMPLETE, token as u64, data.as_ptr() as u64, data.len() as u64)
    };
    r == 0
}

// --- Credential syscalls (Phase 48) ---

pub fn getuid() -> u32 {
    unsafe { arch::syscall0(SYS_GETUID) as u32 }
}

pub fn geteuid() -> u32 {
    unsafe { arch::syscall0(SYS_GETEUID) as u32 }
}

pub fn getgid() -> u32 {
    unsafe { arch::syscall0(SYS_GETGID) as u32 }
}

pub fn getegid() -> u32 {
    unsafe { arch::syscall0(SYS_GETEGID) as u32 }
}

/// Set real and effective UID. Only euid 0 can set arbitrary values.
/// Non-root can only set euid back to real uid.
pub fn setuid(uid: u32) -> bool {
    let r = unsafe { arch::syscall1(SYS_SETUID, uid as u64) };
    r == 0
}

/// Set real and effective GID. Only euid 0 can set arbitrary values.
pub fn setgid(gid: u32) -> bool {
    let r = unsafe { arch::syscall1(SYS_SETGID, gid as u64) };
    r == 0
}

/// Set supplementary group list. Only euid 0 can call.
pub fn setgroups(groups: &[u32]) -> bool {
    let r = unsafe {
        arch::syscall2(SYS_SETGROUPS, groups.len() as u64, groups.as_ptr() as u64)
    };
    r == 0
}

/// Get supplementary group list. Returns count, fills `buf` up to its length.
pub fn getgroups(buf: &mut [u32]) -> usize {
    let r = unsafe {
        arch::syscall2(SYS_GETGROUPS, buf.len() as u64, buf.as_mut_ptr() as u64)
    };
    if r == u64::MAX { 0 } else { r as usize }
}

// --- wait4 / waitpid improvements ---

/// WNOHANG: return immediately if no child has exited.
pub const WNOHANG: u32 = 1;
/// WUNTRACED: also report stopped children.
pub const WUNTRACED: u32 = 2;
/// WCONTINUED: also report continued children.
pub const WCONTINUED: u32 = 8;

/// Extract exit status from wait status (valid if WIFEXITED).
pub const fn wexitstatus(status: i32) -> i32 { (status >> 8) & 0xFF }
/// True if child exited normally.
pub const fn wifexited(status: i32) -> bool { (status & 0x7F) == 0 }
/// True if child was killed by a signal.
pub const fn wifsignaled(status: i32) -> bool { (status & 0x7F) != 0 && (status & 0x7F) != 0x7F }
/// Get the signal that killed the child.
pub const fn wtermsig(status: i32) -> i32 { status & 0x7F }

/// Enhanced wait for child process.
///
/// `pid` semantics:
///   -1: wait for any child
///   >0: wait for specific child task_id
///    0: wait for any child in caller's pgroup
///   <-1: wait for child in pgroup |pid|
///
/// Returns (child_task_id, wait_status) or None on ECHILD.
/// With WNOHANG: returns Some((0, 0)) if no child ready.
pub fn wait4(pid: i64, flags: u32) -> Option<(u32, i32)> {
    let r0: u64;
    let r1: u64;

    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_WAIT4,
            inlateout("x0") pid as u64 => r0,
            inlateout("x1") flags as u64 => r1,
        );
    }

    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SYS_WAIT4 as u64,
            inlateout("a0") pid as u64 => r0,
            inlateout("a1") flags as u64 => r1,
        );
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") SYS_WAIT4 => r0,
            inlateout("rdi") pid as u64 => r1,
            in("rsi") flags as u64,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }

    if r0 == u64::MAX {
        None // ECHILD
    } else {
        Some((r0 as u32, r1 as i32))
    }
}

// --- Resource limits (Phase 50) ---

/// Resource limit types (must match kernel).
pub const RLIMIT_STACK: u32 = 0;
pub const RLIMIT_NOFILE: u32 = 1;
pub const RLIMIT_AS: u32 = 2;
pub const RLIMIT_NPROC: u32 = 3;
pub const RLIM_INFINITY: u64 = u64::MAX;

/// Get resource limit. Returns (soft, hard).
pub fn getrlimit(resource: u32) -> Option<(u64, u64)> {
    let r0: u64;
    let r1: u64;
    let r2: u64;

    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_GETRLIMIT,
            inlateout("x0") resource as u64 => r0,
            lateout("x1") r1,
            lateout("x2") r2,
        );
    }

    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SYS_GETRLIMIT as u64,
            inlateout("a0") resource as u64 => r0,
            lateout("a1") r1,
            lateout("a2") r2,
        );
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") SYS_GETRLIMIT => r0,
            inlateout("rdi") resource as u64 => r1,
            lateout("rsi") r2,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }

    if r0 == u64::MAX { None } else { Some((r1, r2)) }
}

/// Set resource limit. Returns true on success.
pub fn setrlimit(resource: u32, soft: u64, hard: u64) -> bool {
    let r = unsafe { arch::syscall3(SYS_SETRLIMIT, resource as u64, soft, hard) };
    r == 0
}

/// Get and optionally set resource limits for a process.
/// pid=0 means self. new_soft/new_hard = RLIM_INFINITY-1 means "don't change".
/// Returns (old_soft, old_hard) or None on error.
pub fn prlimit(pid: u32, resource: u32, new_soft: u64, new_hard: u64) -> Option<(u64, u64)> {
    let r0: u64;
    let r1: u64;
    let r2: u64;

    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_PRLIMIT,
            inlateout("x0") pid as u64 => r0,
            inlateout("x1") resource as u64 => r1,
            inlateout("x2") new_soft => r2,
            in("x3") new_hard,
        );
    }

    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SYS_PRLIMIT as u64,
            inlateout("a0") pid as u64 => r0,
            inlateout("a1") resource as u64 => r1,
            inlateout("a2") new_soft => r2,
            in("a3") new_hard,
        );
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") SYS_PRLIMIT => r0,
            inlateout("rdi") pid as u64 => r1,
            inlateout("rsi") resource as u64 => r2,
            in("rdx") new_soft,
            in("r10") new_hard,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }

    if r0 == u64::MAX { None } else { Some((r1, r2)) }
}

// --- Shared memory (shm_srv) client wrappers ---

// Protocol tags (must match shm_srv.rs).
const SHM_CREATE_TAG: u64 = 0x5000;
const SHM_OPEN_TAG: u64 = 0x5001;
const SHM_MAP_TAG: u64 = 0x5002;
const SHM_UNMAP_TAG: u64 = 0x5003;
const SHM_UNLINK_TAG: u64 = 0x5004;
const SHM_OK_TAG: u64 = 0x5100;
const SHM_MAP_OK_TAG: u64 = 0x5102;

/// Poll for a reply on a temporary port. The send+handoff path causes the
/// server to run immediately (direct transfer), so the reply is usually
/// queued before we even check. Use non-blocking recv to avoid a blocking
/// recv bug where the receiver parks but the queued reply isn't visible.
fn shm_poll_reply(reply_port: u32) -> Option<Message> {
    for _ in 0..50000u32 {
        if let Some(r) = recv_nb_msg(reply_port) {
            return Some(r);
        }
        yield_now();
    }
    None
}

/// Create or open a named shared memory segment.
/// Returns (handle, page_count, srv_aspace) on success.
pub fn shm_create(shm_port: u32, name: &[u8], page_count: usize) -> Option<(u32, usize, u32)> {
    let reply_port = port_create() as u32;
    let (n0, n1, _) = pack_name(name);
    let d2 = (name.len() as u64) | ((reply_port as u64) << 32);
    send(shm_port, SHM_CREATE_TAG, n0, n1, d2, page_count as u64);
    let result = if let Some(reply) = shm_poll_reply(reply_port) {
        if reply.tag == SHM_OK_TAG {
            Some((reply.data[0] as u32, reply.data[1] as usize, reply.data[2] as u32))
        } else {
            None
        }
    } else {
        None
    };
    port_destroy(reply_port);
    result
}

/// Open an existing named shared memory segment.
/// Returns (handle, page_count, srv_aspace) on success.
pub fn shm_open(shm_port: u32, name: &[u8]) -> Option<(u32, usize, u32)> {
    let reply_port = port_create() as u32;
    let (n0, n1, _) = pack_name(name);
    let d2 = (name.len() as u64) | ((reply_port as u64) << 32);
    send(shm_port, SHM_OPEN_TAG, n0, n1, d2, 0);
    let result = if let Some(reply) = shm_poll_reply(reply_port) {
        if reply.tag == SHM_OK_TAG {
            Some((reply.data[0] as u32, reply.data[1] as usize, reply.data[2] as u32))
        } else {
            None
        }
    } else {
        None
    };
    port_destroy(reply_port);
    result
}

/// Map a shared memory segment into the caller's address space.
/// The server grants pages to `client_aspace` at `dst_va`.
/// Returns the number of pages mapped on success.
pub fn shm_map(shm_port: u32, handle: u32, client_aspace: u32, dst_va: usize, readonly: bool) -> Option<usize> {
    let reply_port = port_create() as u32;
    let d2 = ((reply_port as u64) << 32) | (readonly as u64);
    send(shm_port, SHM_MAP_TAG, handle as u64, client_aspace as u64, d2, dst_va as u64);
    let result = if let Some(reply) = shm_poll_reply(reply_port) {
        if reply.tag == SHM_MAP_OK_TAG {
            Some(reply.data[1] as usize)
        } else {
            None
        }
    } else {
        None
    };
    port_destroy(reply_port);
    result
}

/// Unmap a shared memory segment from the caller's address space.
pub fn shm_unmap(shm_port: u32, handle: u32, client_aspace: u32, dst_va: usize) {
    let reply_port = port_create() as u32;
    let d2 = (reply_port as u64) << 32;
    send(shm_port, SHM_UNMAP_TAG, handle as u64, client_aspace as u64, d2, dst_va as u64);
    let _ = shm_poll_reply(reply_port);
    port_destroy(reply_port);
}

/// Unlink (delete) a named shared memory segment.
pub fn shm_unlink(shm_port: u32, name: &[u8]) -> bool {
    let reply_port = port_create() as u32;
    let (n0, n1, _) = pack_name(name);
    let d2 = (name.len() as u64) | ((reply_port as u64) << 32);
    send(shm_port, SHM_UNLINK_TAG, n0, n1, d2, 0);
    let result = if let Some(reply) = shm_poll_reply(reply_port) {
        reply.tag == SHM_OK_TAG
    } else {
        false
    };
    port_destroy(reply_port);
    result
}

/// Register a service with the name server.
pub fn ns_register(name: &[u8], service_port: u32) -> bool {
    let nsrv = nsrv_port();
    if nsrv == u32::MAX { return false; }

    let reply_port = port_create() as u32;
    let (n0, n1, _n2) = pack_name(name);
    let d3 = (name.len() as u64) | ((reply_port as u64) << 32);

    // NS_REGISTER = 0x1000
    // data[0..1] = name, data[2] = service_port, data[3] = name_len | reply_port
    send(nsrv, 0x1000, n0, n1, service_port as u64, d3);

    let result = if let Some(reply) = recv_msg(reply_port) {
        reply.tag == 0x1001
    } else {
        false
    };
    port_destroy(reply_port);
    result
}
