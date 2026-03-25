#![no_std]
#![no_main]

//! procfs — process filesystem server.
//!
//! Serves virtual files: meminfo, uptime, N/status (per-process).
//! Implements the standard FS protocol (read-only).

extern crate userlib;

use userlib::syscall;

// FS protocol constants.
const FS_OPEN: u64 = 0x2000;
const FS_OPEN_OK: u64 = 0x2001;
const FS_READ: u64 = 0x2100;
const FS_READ_OK: u64 = 0x2101;
const FS_READDIR: u64 = 0x2200;
const FS_READDIR_OK: u64 = 0x2201;
const FS_READDIR_END: u64 = 0x2202;
const FS_STAT: u64 = 0x2300;
const FS_STAT_OK: u64 = 0x2301;
const FS_CLOSE: u64 = 0x2400;
const FS_ERROR: u64 = 0x2F00;

const ERR_NOT_FOUND: u64 = 1;
const ERR_INVALID: u64 = 3;

const MAX_OPEN: usize = 16;
const MAX_INLINE: usize = 24;
const MAX_BUF: usize = 128;
const MAX_TASKS: usize = 32;
const PAGE_SIZE: usize = 4096;

#[derive(Clone, Copy)]
enum VFile {
    Meminfo,
    Uptime,
    Status(u64),
}

#[derive(Clone, Copy)]
struct OpenHandle {
    active: bool,
    buf: [u8; MAX_BUF],
    buf_len: usize,
}

impl OpenHandle {
    const fn empty() -> Self {
        Self { active: false, buf: [0; MAX_BUF], buf_len: 0 }
    }
}

fn unpack_name(d0: u64, d1: u64, len: usize) -> ([u8; 16], usize) {
    let mut buf = [0u8; 16];
    let actual = len.min(16);
    for i in 0..actual {
        if i < 8 {
            buf[i] = (d0 >> (i * 8)) as u8;
        } else {
            buf[i] = (d1 >> ((i - 8) * 8)) as u8;
        }
    }
    (buf, actual)
}

fn pack_inline_data(data: &[u8]) -> [u64; 3] {
    let mut words = [0u64; 3];
    for (i, &b) in data.iter().enumerate().take(MAX_INLINE) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
}

/// Format a u64 as decimal into buf. Returns number of bytes written.
fn u64_to_dec(mut val: u64, buf: &mut [u8]) -> usize {
    if val == 0 {
        if !buf.is_empty() { buf[0] = b'0'; }
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut pos = 0;
    while val > 0 {
        tmp[pos] = b'0' + (val % 10) as u8;
        val /= 10;
        pos += 1;
    }
    let len = pos.min(buf.len());
    for i in 0..len {
        buf[i] = tmp[pos - 1 - i];
    }
    len
}

/// Append bytes to buffer, return new offset.
fn append(buf: &mut [u8], off: usize, data: &[u8]) -> usize {
    let n = data.len().min(buf.len().saturating_sub(off));
    for i in 0..n {
        buf[off + i] = data[i];
    }
    off + n
}

/// Append a decimal number to buffer, return new offset.
fn append_dec(buf: &mut [u8], off: usize, val: u64) -> usize {
    let mut tmp = [0u8; 20];
    let n = u64_to_dec(val, &mut tmp);
    append(buf, off, &tmp[..n])
}

/// Check if name equals a static string.
fn name_eq(name: &[u8], nlen: usize, s: &[u8]) -> bool {
    if nlen != s.len() { return false; }
    for i in 0..nlen {
        if name[i] != s[i] { return false; }
    }
    true
}

/// Parse "N/status" where N is a decimal task ID. Returns Some(task_id) or None.
fn parse_pid_status(name: &[u8], nlen: usize) -> Option<u64> {
    // Find the '/' separator.
    let mut slash = usize::MAX;
    for i in 0..nlen {
        if name[i] == b'/' { slash = i; break; }
    }
    if slash == usize::MAX || slash == 0 { return None; }
    // Check suffix is "status".
    let suffix_len = nlen - slash - 1;
    if suffix_len != 6 { return None; }
    let status = b"status";
    for i in 0..6 {
        if name[slash + 1 + i] != status[i] { return None; }
    }
    // Parse decimal PID.
    let mut pid: u64 = 0;
    for i in 0..slash {
        let ch = name[i];
        if ch < b'0' || ch > b'9' { return None; }
        pid = pid.wrapping_mul(10).wrapping_add((ch - b'0') as u64);
    }
    Some(pid)
}

/// Generate meminfo content.
fn gen_meminfo(buf: &mut [u8]) -> usize {
    // vm_stats(18) = total_pages, vm_stats(19) = free_pages
    // Pages are 64KiB each in Telix.
    let total_pages = syscall::vm_stats(18);
    let free_pages = syscall::vm_stats(19);
    let total_kb = total_pages * 64; // 64K per page
    let free_kb = free_pages * 64;

    let mut off = 0;
    off = append(buf, off, b"Total: ");
    off = append_dec(buf, off, total_kb);
    off = append(buf, off, b" kB\nFree: ");
    off = append_dec(buf, off, free_kb);
    off = append(buf, off, b" kB\n");
    off
}

/// Generate uptime content.
fn gen_uptime(buf: &mut [u8]) -> usize {
    let ns = syscall::clock_gettime();
    let mut off = 0;
    off = append_dec(buf, off, ns);
    off = append(buf, off, b"\n");
    off
}

/// Generate per-process status content.
fn gen_status(buf: &mut [u8], task_id: u64) -> usize {
    match syscall::proc_info(task_id) {
        Some((ppid_threads, uid_gid, pgid_sid, pages_state)) => {
            let ppid = (ppid_threads & 0xFFFF_FFFF) as u32;
            let threads = (ppid_threads >> 32) as u32;
            let uid = (uid_gid & 0xFFFF_FFFF) as u32;
            let gid = (uid_gid >> 32) as u32;
            let _pgid = (pgid_sid & 0xFFFF_FFFF) as u32;
            let _sid = (pgid_sid >> 32) as u32;
            let pages = (pages_state & 0xFFFF_FFFF) as u32;

            let mut off = 0;
            off = append(buf, off, b"Pid: ");
            off = append_dec(buf, off, task_id as u64);
            off = append(buf, off, b"\nPPid: ");
            off = append_dec(buf, off, ppid as u64);
            off = append(buf, off, b"\nUid: ");
            off = append_dec(buf, off, uid as u64);
            off = append(buf, off, b"\nGid: ");
            off = append_dec(buf, off, gid as u64);
            off = append(buf, off, b"\nThreads: ");
            off = append_dec(buf, off, threads as u64);
            off = append(buf, off, b"\nVmPages: ");
            off = append_dec(buf, off, pages as u64);
            off = append(buf, off, b"\n");
            off
        }
        None => 0,
    }
}

/// Pack a short name (up to 8 bytes) into a u64 for READDIR.
fn pack_name_lo(name: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, &b) in name.iter().enumerate().take(8) {
        v |= (b as u64) << (i * 8);
    }
    v
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [procfs_srv] starting\n");

    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"procfs", port);
    syscall::debug_puts(b"  [procfs_srv] ready\n");

    let mut handles = [OpenHandle::empty(); MAX_OPEN];

    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            FS_OPEN => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let (name, nlen) = unpack_name(msg.data[0], msg.data[1], name_len);

                // Determine virtual file type and generate content.
                let mut buf = [0u8; MAX_BUF];
                let buf_len;

                if name_eq(&name, nlen, b"meminfo") {
                    buf_len = gen_meminfo(&mut buf);
                } else if name_eq(&name, nlen, b"uptime") {
                    buf_len = gen_uptime(&mut buf);
                } else if let Some(pid) = parse_pid_status(&name, nlen) {
                    buf_len = gen_status(&mut buf, pid);
                    if buf_len == 0 {
                        syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                        continue;
                    }
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                    continue;
                }

                // Allocate handle.
                let mut h = u64::MAX;
                for (i, hnd) in handles.iter_mut().enumerate() {
                    if !hnd.active {
                        hnd.active = true;
                        hnd.buf = buf;
                        hnd.buf_len = buf_len;
                        h = i as u64;
                        break;
                    }
                }
                if h == u64::MAX {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                } else {
                    syscall::send(reply_port, FS_OPEN_OK,
                        h, handles[h as usize].buf_len as u64, my_aspace, 0);
                }
            }

            FS_READ => {
                let handle = msg.data[0] as usize;
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let grant_va = msg.data[3] as usize;

                if handle >= MAX_OPEN || !handles[handle].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let hnd = &handles[handle];
                if offset >= hnd.buf_len {
                    syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                    continue;
                }

                let avail = hnd.buf_len - offset;
                let to_read = length.min(avail);

                if grant_va != 0 {
                    let actual = to_read.min(PAGE_SIZE);
                    let dst = grant_va as *mut u8;
                    for i in 0..actual {
                        unsafe { *dst.add(i) = hnd.buf[offset + i]; }
                    }
                    syscall::send_nb(reply_port, FS_READ_OK, actual as u64, 0);
                } else {
                    let inline_len = to_read.min(MAX_INLINE);
                    let packed = pack_inline_data(&hnd.buf[offset..offset + inline_len]);
                    syscall::send(reply_port, FS_READ_OK,
                        inline_len as u64, packed[0], packed[1], packed[2]);
                }
            }

            FS_STAT => {
                let handle = msg.data[0] as usize;
                let reply_port = msg.data[2] & 0xFFFF_FFFF;

                if handle >= MAX_OPEN || !handles[handle].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let size = handles[handle].buf_len;
                // mode = 0o100444 (regular file, read-only)
                syscall::send(reply_port, FS_STAT_OK,
                    size as u64, 0o100444u64, 0, 0);
            }

            FS_READDIR => {
                let start_offset = msg.data[0] as usize;
                let reply_port = msg.data[2] & 0xFFFF_FFFF;

                // Virtual directory layout:
                //   0 = "meminfo"
                //   1 = "uptime"
                //   2..2+MAX_TASKS = PID entries (only active ones)
                //
                // We use a running index to skip inactive slots.
                let mut idx = start_offset;
                let mut sent = false;

                if idx == 0 {
                    let name_lo = pack_name_lo(b"meminfo");
                    syscall::send(reply_port, FS_READDIR_OK,
                        0, name_lo, 0, 1);
                    sent = true;
                } else if idx == 1 {
                    let name_lo = pack_name_lo(b"uptime");
                    syscall::send(reply_port, FS_READDIR_OK,
                        0, name_lo, 0, 2);
                    sent = true;
                } else {
                    // PID entries: idx 2 maps to task slot (idx-2).
                    let mut slot = idx - 2;
                    while slot < MAX_TASKS {
                        let tid = syscall::proc_list(slot as u32);
                        if tid != 0 {
                            // Format PID as name.
                            let mut nbuf = [0u8; 8];
                            let nlen = u64_to_dec(tid, &mut nbuf);
                            let name_lo = pack_name_lo(&nbuf[..nlen]);
                            syscall::send(reply_port, FS_READDIR_OK,
                                0, name_lo, 0, (slot + 3) as u64);
                            sent = true;
                            break;
                        }
                        slot += 1;
                    }
                }

                if !sent {
                    syscall::send(reply_port, FS_READDIR_END, 0, 0, 0, 0);
                }
            }

            FS_CLOSE => {
                let handle = msg.data[0] as usize;
                if handle < MAX_OPEN && handles[handle].active {
                    handles[handle].active = false;
                }
            }

            _ => {}
        }
    }

    loop { core::hint::spin_loop(); }
}
