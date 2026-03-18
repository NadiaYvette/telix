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
pub fn thread_join(tid: u32) -> i64 {
    loop {
        if let Some(code) = thread_join_poll(tid) {
            return code;
        }
        yield_now();
    }
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

const SYS_FORK: u64 = 39;
const SYS_SEND_CAP: u64 = 40;
#[allow(dead_code)]
const SYS_CAP_REVOKE: u64 = 41;

/// Fork the current process. Returns child task ID to parent (>0),
/// 0 to the child, or 0 on failure.
pub fn fork() -> u64 {
    unsafe { arch::syscall0(SYS_FORK) }
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
