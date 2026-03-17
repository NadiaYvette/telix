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
const MAX_FILES: usize = 32;
const MAX_NAME: usize = 64;

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

fn unpack_name(w0: u64, w1: u64, w2: u64, len: usize) -> [u8; 24] {
    let mut buf = [0u8; 24];
    let words = [w0, w1, w2];
    for i in 0..len.min(24) {
        buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
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
    let cpio_data = unsafe {
        core::slice::from_raw_parts(data_va as *const u8, data_len as usize)
    };

    let mut fs = Initramfs::new();
    fs.parse(cpio_data);

    syscall::debug_puts(b"  [initramfs_srv] parsed ");
    print_num(fs.count as u64);
    syscall::debug_puts(b" files, serving on port ");
    print_num(port_id);
    syscall::debug_puts(b"\n");

    let port = port_id as u32;
    let my_aspace = syscall::aspace_id();

    // Register with name server.
    syscall::ns_register(b"initramfs", port);

    // Server loop.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            IO_CONNECT => {
                // Userspace protocol (4 data words max):
                //   data[0] = name bytes 0-7
                //   data[1] = name bytes 8-15
                //   data[2] = name_len (low 32) | reply_port (high 32)
                //   data[3] = unused
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], 0, name_len);
                let name = &name_buf[..name_len.min(16)];

                match fs.find(name) {
                    Some(idx) => {
                        // data[0]=handle, data[1]=size, data[2]=server_aspace_id
                        syscall::send(reply_port, IO_CONNECT_OK,
                            idx as u64, fs.files[idx].data_len as u64,
                            my_aspace as u64, 0);
                    }
                    None => {
                        syscall::send_nb(reply_port, IO_ERROR, ERR_NOT_FOUND, 0);
                    }
                }
            }

            IO_READ => {
                // data[0] = handle, data[1] = offset
                // data[2] = length (low 32) | reply_port (high 32)
                // data[3] = grant_dst_va (if grant), data[4] = flags
                let file_handle = msg.data[0] as usize;
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let grant_va = msg.data[3] as usize;

                if file_handle >= fs.count || !fs.files[file_handle].active {
                    syscall::send_nb(reply_port, IO_ERROR, ERR_INVALID, 0);
                    continue;
                }

                let f = &fs.files[file_handle];
                let start = f.data_offset + offset.min(f.data_len);
                let end = f.data_offset + (offset + length).min(f.data_len);
                let data = &cpio_data[start..end];

                if grant_va != 0 {
                    // Grant-based read: copy file data into granted pages.
                    let bytes_read = data.len();
                    let dst = grant_va as *mut u8;
                    unsafe {
                        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, bytes_read);
                    }
                    syscall::send_nb(reply_port, IO_READ_OK, bytes_read as u64, 0);
                } else {
                    // Inline read: pack into message words.
                    let bytes_read = data.len().min(MAX_INLINE_READ);
                    let packed = pack_inline_data(&data[..bytes_read]);
                    syscall::send(reply_port, IO_READ_OK,
                        bytes_read as u64, packed[0], packed[1], packed[2]);
                }
            }

            IO_STAT => {
                // data[0] = handle | (reply_port << 32)
                let file_handle = (msg.data[0] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[0] >> 32) as u32;

                if file_handle >= fs.count || !fs.files[file_handle].active {
                    syscall::send_nb(reply_port, IO_ERROR, ERR_INVALID, 0);
                    continue;
                }

                syscall::send_nb(reply_port, IO_STAT_OK, fs.files[file_handle].data_len as u64, 0);
            }

            IO_CLOSE => {}
            _ => {}
        }
    }

    loop { core::hint::spin_loop(); }
}
