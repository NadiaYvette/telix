#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

// I/O protocol tags (must match kernel/src/io/protocol.rs).
const IO_CONNECT: u64 = 0x100;
const IO_CONNECT_OK: u64 = 0x101;
const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;
const IO_STAT: u64 = 0x400;
const IO_STAT_OK: u64 = 0x401;
const IO_CLOSE: u64 = 0x500;
const IO_ERROR: u64 = 0xF00;

const ERR_NOT_FOUND: u64 = 1;
const ERR_INVALID: u64 = 3;

const MAX_INLINE_READ: usize = 40;
const MAX_FILES: usize = 512;
const MAX_NAME: usize = 64;

/// Diagnostic flag: log a per-IO_READ summary (handle, offset, len, csum,
/// first 8 bytes) for reads >= 4 KiB.  Pair with the matching log on
/// linux_srv's irfs_read_bulk side; csum mismatch between the two means
/// the grant_pages mapping resolved to different phys pages on the two
/// aspaces — the file-too-short / Verdef-version-0 / cannot-read-file-data
/// flake.  Boot b9mfsq310-r13 ran with this on and confirmed every single
/// observed read matched server↔client; flip back to true if the flake
/// resurfaces and a fresh corruption-check is wanted.
const DEBUG_IO_READ_CSUM: bool = false;

/// Cheap Fletcher-style 32-bit running sum.  Not cryptographic, just
/// enough to detect single-byte changes or wholesale zeroing.
fn csum32(data: &[u8]) -> u32 {
    let mut s1: u32 = 0;
    let mut s2: u32 = 0;
    for &b in data {
        s1 = s1.wrapping_add(b as u32);
        s2 = s2.wrapping_add(s1);
    }
    (s2 << 16) | (s1 & 0xFFFF)
}

fn print_hex32(n: u32) {
    let hex = b"0123456789abcdef";
    let mut buf = [0u8; 8];
    for i in 0..8 {
        buf[7 - i] = hex[((n >> (i * 4)) & 0xF) as usize];
    }
    syscall::debug_puts(&buf);
}

struct FileEntry {
    name: [u8; MAX_NAME],
    name_len: usize,
    data_offset: usize,
    data_len: usize,
    active: bool,
}

impl FileEntry {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_NAME],
            name_len: 0,
            data_offset: 0,
            data_len: 0,
            active: false,
        }
    }

    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

struct Initramfs {
    files: [FileEntry; MAX_FILES],
    count: usize,
}

impl Initramfs {
    const fn new() -> Self {
        Self {
            files: [const { FileEntry::empty() }; MAX_FILES],
            count: 0,
        }
    }

    fn parse(&mut self, data: &[u8]) {
        let mut pos = 0;
        while pos + 110 <= data.len() && self.count < MAX_FILES {
            if &data[pos..pos + 6] != b"070701" {
                break;
            }
            let filesize = parse_hex8(&data[pos + 54..pos + 62]);
            let namesize = parse_hex8(&data[pos + 94..pos + 102]);
            let name_start = pos + 110;
            let name_end = name_start + namesize - 1;
            let data_start = align4(name_start + namesize);
            let data_end = data_start + filesize;
            let next = align4(data_end);
            if name_end > data.len() || data_end > data.len() {
                break;
            }
            let name = &data[name_start..name_end];
            if name == b"TRAILER!!!" {
                break;
            }
            if !(filesize == 0 || name == b".") {
                let entry = &mut self.files[self.count];
                let copy_len = name.len().min(MAX_NAME);
                entry.name[..copy_len].copy_from_slice(&name[..copy_len]);
                entry.name_len = copy_len;
                entry.data_offset = data_start;
                entry.data_len = filesize;
                entry.active = true;
                self.count += 1;
            }
            pos = next;
        }
    }

    fn find(&self, name: &[u8]) -> Option<usize> {
        for i in 0..self.count {
            if self.files[i].active && self.files[i].name_bytes() == name {
                return Some(i);
            }
        }
        None
    }
}

fn parse_hex8(bytes: &[u8]) -> usize {
    let mut val = 0usize;
    for &b in bytes.iter().take(8) {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as usize,
            b'a'..=b'f' => (b - b'a' + 10) as usize,
            b'A'..=b'F' => (b - b'A' + 10) as usize,
            _ => 0,
        };
        val = (val << 4) | digit;
    }
    val
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Unpack a path name from 4 packed u64 words.  d0 / d1 / d3 hold
/// 24 bytes (3 × 8); the upper 32 bits of d2 (whose low 16 bits
/// carry name_len) hold 4 more — total 28 chars.  That fits paths
/// like "lib64/libwayland-client.so.0" (28 chars exactly) without
/// needing a long-path IPC variant.
fn unpack_name(w0: u64, w1: u64, w2_extra: u32, w3: u64, len: usize) -> [u8; 28] {
    let mut buf = [0u8; 28];
    // bytes 0-7 from w0
    for i in 0..len.min(8) {
        buf[i] = (w0 >> (i * 8)) as u8;
    }
    // bytes 8-15 from w1
    for i in 8..len.min(16) {
        buf[i] = (w1 >> ((i - 8) * 8)) as u8;
    }
    // bytes 16-23 from w3
    for i in 16..len.min(24) {
        buf[i] = (w3 >> ((i - 16) * 8)) as u8;
    }
    // bytes 24-27 from upper 32 bits of d2
    for i in 24..len.min(28) {
        buf[i] = (w2_extra >> ((i - 24) * 8)) as u8;
    }
    buf
}

fn pack_inline_data(data: &[u8]) -> [u64; 5] {
    let mut words = [0u64; 5];
    for (i, &b) in data.iter().enumerate().take(MAX_INLINE_READ) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
}

fn print_num(n: u64) {
    if n == 0 {
        syscall::debug_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut val = n;
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        syscall::debug_putchar(buf[i]);
    }
}

/// Entry: arg0 = port ID, arg1 = CPIO data VA, arg2 = CPIO data length.
#[unsafe(no_mangle)]
fn main(port_id: u64, data_va: u64, data_len: u64) {
    let cpio_data = unsafe { core::slice::from_raw_parts(data_va as *const u8, data_len as usize) };

    let mut fs = Initramfs::new();
    fs.parse(cpio_data);

    syscall::debug_puts(b"  [initramfs_srv] parsed ");
    print_num(fs.count as u64);
    syscall::debug_puts(b" files, serving on port ");
    print_num(port_id);
    syscall::debug_puts(b"\n");

    let port = port_id;
    let my_aspace = syscall::aspace_id();

    // Register with name server.
    syscall::ns_register(b"initramfs", port);
    // Also register our aspace under `initramfs_task` so linux_srv (and
    // others) can grant pages to us — same convention as ext_srv /
    // ext2_srv / rootfs_srv.
    syscall::ns_register(b"initramfs_task", my_aspace);

    // Server loop.
    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            IO_CONNECT => {
                // Userspace protocol (4 data words used):
                //   data[0] = name bytes 0-7
                //   data[1] = name bytes 8-15
                //   data[2] = name_len (low 16) | name_bytes_24_27 (upper 32)
                //   data[3] = name bytes 16-23
                // Total 28-char inline name (covers
                // "lib64/libwayland-client.so.0" = 28 exactly).  We pack
                // 4 extra bytes into d2's upper 32 bits because the
                // syscall ABI gives us only 4 data words on the wire.
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let w2_extra = ((msg.data[2] >> 32) & 0xFFFF_FFFF) as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], w2_extra, msg.data[3], name_len);
                let name = &name_buf[..name_len.min(28)];

                match fs.find(name) {
                    Some(idx) => {
                        // d0=handle, d1=size, d2=server_aspace_id
                        let _ = syscall::reply(
                            IO_CONNECT_OK,
                            idx as u64,
                            fs.files[idx].data_len as u64,
                            my_aspace as u64,
                            0,
                            0,
                        );
                    }
                    None => {
                        let _ = syscall::reply(IO_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                    }
                }
            }

            IO_READ => {
                // data[0] = handle, data[1] = offset
                // data[2] = length (low 32)
                // data[3] = grant_dst_va (if grant)
                let file_handle = msg.data[0] as usize;
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let grant_va = msg.data[3] as usize;

                if file_handle >= fs.count || !fs.files[file_handle].active {
                    let _ = syscall::reply(IO_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let f = &fs.files[file_handle];
                let start = f.data_offset + offset.min(f.data_len);
                let end = f.data_offset + (offset + length).min(f.data_len);
                let data = &cpio_data[start..end];

                if grant_va != 0 {
                    if DEBUG_IO_READ_CSUM && data.len() >= 4096 {
                        let cs = csum32(data);
                        syscall::debug_puts(b"[irfs] IO_READ srv h=");
                        print_num(file_handle as u64);
                        syscall::debug_puts(b" off=");
                        print_num(offset as u64);
                        syscall::debug_puts(b" len=");
                        print_num(data.len() as u64);
                        syscall::debug_puts(b" csum=");
                        print_hex32(cs);
                        syscall::debug_puts(b" first8=");
                        for k in 0..8.min(data.len()) {
                            let hex = b"0123456789abcdef";
                            syscall::debug_putchar(hex[(data[k] >> 4) as usize]);
                            syscall::debug_putchar(hex[(data[k] & 0xF) as usize]);
                        }
                        syscall::debug_puts(b"\n");
                    }
                    // Grant-based read with cache_srv-style fence pattern:
                    // volatile u64 stride + Release fence + mfence.  Without
                    // this, ld.so on the receiving CPU sees zero-filled
                    // grant pages under boot concurrency (same shape of bug
                    // cache_srv and ext_srv had — surfaces in Step H as
                    // "Verdef version 0" / "Verneed version 0" on libc).
                    let bytes_read = data.len();
                    unsafe {
                        let src = data.as_ptr();
                        let dst = grant_va as *mut u8;
                        let words = bytes_read / 8;
                        let tail_start = words * 8;
                        let src_u64 = src as *const u64;
                        let dst_u64 = dst as *mut u64;
                        for i in 0..words {
                            let v = core::ptr::read_volatile(src_u64.add(i));
                            core::ptr::write_volatile(dst_u64.add(i), v);
                        }
                        for i in tail_start..bytes_read {
                            let b = core::ptr::read_volatile(src.add(i));
                            core::ptr::write_volatile(dst.add(i), b);
                        }
                    }
                    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                    #[cfg(target_arch = "x86_64")]
                    unsafe { core::arch::asm!("mfence"); }
                    let _ = syscall::reply(IO_READ_OK, bytes_read as u64, 0, 0, 0, 0);
                } else {
                    // Inline read: pack into message words.
                    let bytes_read = data.len().min(MAX_INLINE_READ);
                    let packed = pack_inline_data(&data[..bytes_read]);
                    let _ = syscall::reply(
                        IO_READ_OK,
                        bytes_read as u64,
                        packed[0],
                        packed[1],
                        packed[2],
                        0,
                    );
                }
            }

            IO_STAT => {
                // data[0] = handle (low 32)
                let file_handle = (msg.data[0] & 0xFFFF_FFFF) as usize;

                if file_handle >= fs.count || !fs.files[file_handle].active {
                    let _ = syscall::reply(IO_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let _ = syscall::reply(
                    IO_STAT_OK,
                    fs.files[file_handle].data_len as u64,
                    0,
                    0,
                    0,
                    0,
                );
            }

            IO_CLOSE => {
                let _ = syscall::reply(IO_CONNECT_OK, 0, 0, 0, 0, 0);
            }
            _ => {
                let _ = syscall::reply(IO_ERROR, ERR_INVALID, 0, 0, 0, 0);
            }
        }
    }

    loop {
        core::hint::spin_loop();
    }
}
