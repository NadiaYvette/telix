#![no_std]
#![no_main]

//! Linux personality server.
//!
//! Receives forwarded Linux syscalls from the kernel's personality routing
//! layer and translates them into Telix-native operations.
//!
//! Message format (from kernel/src/syscall/personality.rs):
//!   tag     = Linux syscall number (x86_64 numbering)
//!   data[0] = arg0
//!   data[1] = arg1
//!   data[2] = arg2
//!   data[3] = arg3
//!   data[4] = caller's task port_id

extern crate userlib;

use userlib::syscall;

// --- Linux x86_64 syscall numbers ---
const __NR_READ: u64 = 0;
const __NR_WRITE: u64 = 1;
const __NR_CLOSE: u64 = 3;
const __NR_MMAP: u64 = 9;
const __NR_MPROTECT: u64 = 10;
const __NR_MUNMAP: u64 = 11;
const __NR_BRK: u64 = 12;
const __NR_IOCTL: u64 = 16;
const __NR_WRITEV: u64 = 20;
const __NR_GETPID: u64 = 39;
const __NR_EXIT: u64 = 60;
const __NR_UNAME: u64 = 63;
const __NR_GETUID: u64 = 102;
const __NR_GETGID: u64 = 104;
const __NR_GETEUID: u64 = 107;
const __NR_GETEGID: u64 = 108;
const __NR_ARCH_PRCTL: u64 = 158;
const __NR_GETTID: u64 = 186;
const __NR_SET_TID_ADDRESS: u64 = 218;
const __NR_CLOCK_GETTIME: u64 = 228;
const __NR_EXIT_GROUP: u64 = 231;
const __NR_SET_ROBUST_LIST: u64 = 273;
const __NR_PRLIMIT64: u64 = 302;
const __NR_GETRANDOM: u64 = 318;
const __NR_RSEQ: u64 = 334;

// arch_prctl subcodes
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;

// Linux errno values (returned as negative)
const ENOSYS: u64 = 0xFFFF_FFFF_FFFF_FFD8; // -38 as u64

// Per-task state for brk emulation.
// In a full implementation this would be per-task; for now, single-client.
static mut BRK_BASE: usize = 0;
static mut BRK_CURRENT: usize = 0;

fn print_num(n: u64) {
    if n == 0 {
        syscall::debug_puts(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 20;
    let mut val = n;
    while val > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    syscall::debug_puts(&buf[i..20]);
}

/// Handle Linux write(fd, buf, count).
/// For fd 1 (stdout) and fd 2 (stderr), write to debug console.
fn handle_write(caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0];
    let buf_ptr = args[1] as usize;
    let count = args[2] as usize;

    if (fd == 1 || fd == 2) && buf_ptr != 0 && count > 0 {
        // Safety: the caller's address space is active while it's blocked
        // in PersonalityWait (the kernel hasn't switched it out). The buffer
        // pointer is in the caller's user address space, which we share
        // since the personality server runs in a different address space.
        //
        // For now, use a copy-out approach: read from the caller's memory
        // isn't possible directly. Instead, we write to debug console via
        // the kernel, which can access the caller's memory.
        //
        // Simplification: we trust the buffer is valid and copy up to 256
        // bytes at a time. The kernel's debug_puts will use the *current*
        // address space (linux_srv's), not the caller's. So we need to
        // handle this differently.
        //
        // For this initial implementation: the caller's buffer is NOT
        // accessible from our address space. We'll signal success and
        // print a placeholder. A full implementation would use grant pages
        // or a kernel copy-out helper.
        //
        // HACK: return count (pretend we wrote it all). The debug output
        // for the test phase will come from the test itself using native
        // Telix syscalls before switching personality.
        return count as u64;
    }

    // Other FDs: not yet supported.
    ENOSYS
}

/// Handle Linux brk(addr).
fn handle_brk(args: &[u64; 6]) -> u64 {
    let addr = args[0] as usize;

    unsafe {
        if BRK_BASE == 0 {
            // First call: set up brk region at a fixed high address.
            // In a real implementation, this comes from the ELF loader.
            BRK_BASE = 0x4000_0000;
            BRK_CURRENT = BRK_BASE;
        }

        if addr == 0 {
            // Query current brk.
            return BRK_CURRENT as u64;
        }

        if addr >= BRK_BASE && addr <= BRK_BASE + 256 * 1024 * 1024 {
            // Grow or shrink the brk.
            let page_size = syscall::page_size() as usize;
            if addr > BRK_CURRENT {
                // Need to allocate pages.
                let old_pages = (BRK_CURRENT + page_size - 1) / page_size;
                let new_pages = (addr + page_size - 1) / page_size;
                if new_pages > old_pages {
                    let alloc_start = old_pages * page_size;
                    let count = new_pages - old_pages;
                    if syscall::mmap_anon(alloc_start, count, 3).is_none() {
                        return BRK_CURRENT as u64; // Allocation failed
                    }
                }
            }
            BRK_CURRENT = addr;
            return BRK_CURRENT as u64;
        }

        BRK_CURRENT as u64
    }
}

/// Handle Linux arch_prctl(code, addr).
fn handle_arch_prctl(args: &[u64; 6]) -> u64 {
    let code = args[0];
    let addr = args[1];

    match code {
        ARCH_SET_FS => {
            // We can't set TLS for the *caller* from here since tls_set
            // sets it for the current thread. We need a kernel helper.
            // For now, return 0 (success) — the kernel will need a
            // "set TLS for task" variant.
            // TODO: Add SYS_TLS_SET_FOR_TASK or handle in-kernel.
            0
        }
        ARCH_GET_FS => {
            // Similarly can't read the caller's TLS from here.
            0
        }
        _ => ENOSYS,
    }
}

/// Handle Linux set_tid_address(tidptr).
fn handle_set_tid_address(caller_port: u64) -> u64 {
    // Return the caller's thread ID. In Linux this is gettid().
    // Use the task port as a stand-in for now.
    caller_port
}

/// Handle Linux exit(code) or exit_group(code).
fn handle_exit(caller_port: u64, args: &[u64; 6]) -> u64 {
    let _code = args[0];
    // We can't call exit() for the caller from the personality server.
    // The caller is blocked in PersonalityWait — we need to reply and then
    // the caller needs to exit. Since exit doesn't return, we need a
    // different approach: reply with a special value and have the kernel
    // handle exit for personality tasks, OR use a kernel syscall to
    // kill the target task.
    //
    // For now: kill the target task via its port, then don't reply
    // (the task is dead, reply would fail harmlessly).
    syscall::kill(caller_port);
    // Return 0 even though the caller won't see it.
    0
}

/// Handle Linux getpid/gettid/getuid/geteuid/getgid/getegid.
fn handle_getid(nr: u64) -> u64 {
    match nr {
        __NR_GETPID | __NR_GETTID => syscall::getpid(),
        __NR_GETUID => syscall::getuid() as u64,
        __NR_GETEUID => syscall::geteuid() as u64,
        __NR_GETGID => syscall::getgid() as u64,
        __NR_GETEGID => syscall::getegid() as u64,
        _ => 0,
    }
}

/// Handle Linux clock_gettime(clockid, tp).
fn handle_clock_gettime(args: &[u64; 6]) -> u64 {
    let _clockid = args[0];
    // Return nanoseconds since boot. Can't write to caller's tp pointer
    // from here. Return the time value directly — caller won't get the
    // timespec struct filled, but it's a start.
    // TODO: proper implementation with cross-address-space write.
    0
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    let port = syscall::port_create();
    syscall::personality_register(2, port); // 2 = Linux
    syscall::ns_register(b"linux", port);
    syscall::debug_puts(b"[linux_srv] ready on port ");
    print_num(port);
    syscall::debug_puts(b"\n");

    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => continue,
        };

        let linux_nr = msg.tag;
        let caller_port = msg.data[4];

        let result = match linux_nr {
            __NR_WRITE => handle_write(caller_port, &msg.data),
            __NR_BRK => handle_brk(&msg.data),
            __NR_ARCH_PRCTL => handle_arch_prctl(&msg.data),
            __NR_SET_TID_ADDRESS => handle_set_tid_address(caller_port),
            __NR_EXIT | __NR_EXIT_GROUP => {
                handle_exit(caller_port, &msg.data);
                continue; // Don't reply — task is dead.
            }
            __NR_GETPID | __NR_GETTID | __NR_GETUID | __NR_GETEUID
            | __NR_GETGID | __NR_GETEGID => handle_getid(linux_nr),
            __NR_CLOCK_GETTIME => handle_clock_gettime(&msg.data),

            // Stubs that return success (0) to avoid crashing callers.
            __NR_SET_ROBUST_LIST | __NR_RSEQ => 0,
            __NR_PRLIMIT64 => 0,
            __NR_IOCTL => ENOSYS,

            // Anonymous mmap: forward to Telix mmap_anon.
            __NR_MMAP => {
                let addr = msg.data[0] as usize;
                let len = msg.data[1] as usize;
                let prot = msg.data[2] as u8;
                let _flags = msg.data[3];
                // args[4]=fd, args[5]=offset need personality_read_args
                // For anonymous mmap (MAP_ANONYMOUS), fd is ignored.
                let page_size = syscall::page_size() as usize;
                let pages = (len + page_size - 1) / page_size;
                match syscall::mmap_anon(addr, pages, prot) {
                    Some(va) => va as u64,
                    None => u64::MAX, // MAP_FAILED
                }
            }
            __NR_MPROTECT => {
                let addr = msg.data[0] as usize;
                let len = msg.data[1] as usize;
                let prot = msg.data[2] as u8;
                if syscall::mprotect(addr, len, prot) { 0 } else { ENOSYS }
            }
            __NR_MUNMAP => {
                let addr = msg.data[0] as usize;
                if syscall::munmap(addr) { 0 } else { ENOSYS }
            }

            _ => {
                syscall::debug_puts(b"[linux_srv] unhandled nr=");
                print_num(linux_nr);
                syscall::debug_puts(b"\n");
                ENOSYS
            }
        };

        // Reply to the blocked caller.
        syscall::personality_reply(caller_port, result);
    }
}
