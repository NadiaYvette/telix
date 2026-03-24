//! Initramfs filesystem server — serves files from an embedded CPIO archive.
//!
//! The CPIO newc-format archive is compiled into the kernel binary via
//! `include_bytes!`. The server parses the archive at startup into a
//! fixed-size file table, then handles I/O protocol messages.

use crate::ipc::port::{self};
use crate::ipc::Message;
use super::protocol::*;
use core::sync::atomic::{AtomicU32, Ordering};

/// Global port ID for the kernel initramfs server (u32::MAX = not yet ready).
pub static INITRAMFS_PORT: AtomicU32 = AtomicU32::new(u32::MAX);

/// Global port ID for the userspace initramfs server (u32::MAX = not yet ready).
pub static USER_INITRAMFS_PORT: AtomicU32 = AtomicU32::new(u32::MAX);

/// Embedded CPIO archive.
static INITRAMFS: &[u8] = include_bytes!("initramfs.cpio");

/// Maximum files in the initramfs.
const MAX_FILES: usize = 64;
/// Maximum filename length.
const MAX_NAME: usize = 64;

/// A parsed file entry from the CPIO archive.
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

/// The initramfs file table.
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

    /// Parse the CPIO newc archive.
    fn parse(&mut self, data: &[u8]) {
        let mut pos = 0;
        while pos + 110 <= data.len() && self.count < MAX_FILES {
            // CPIO newc header: "070701" magic (6 bytes) + 13 × 8-char hex fields.
            if &data[pos..pos + 6] != b"070701" {
                break;
            }

            let filesize = parse_hex8(&data[pos + 54..pos + 62]);
            let namesize = parse_hex8(&data[pos + 94..pos + 102]);

            let name_start = pos + 110;
            let name_end = name_start + namesize - 1; // -1 to strip NUL
            // Header + name is padded to 4-byte boundary.
            let data_start = align4(name_start + namesize);
            let data_end = data_start + filesize;
            // Data is padded to 4-byte boundary.
            let next = align4(data_end);

            if name_end > data.len() || data_end > data.len() {
                break;
            }

            let name = &data[name_start..name_end];

            // Skip the "TRAILER!!!" entry.
            if name == b"TRAILER!!!" {
                break;
            }

            // Skip directories (filesize == 0 and name ends with '/') and "." entry.
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

    /// Find a file by name. Returns index or None.
    fn find(&self, name: &[u8]) -> Option<usize> {
        for i in 0..self.count {
            if self.files[i].active && self.files[i].name_bytes() == name {
                return Some(i);
            }
        }
        None
    }

    /// Read bytes from a file.
    fn read(&self, file_idx: usize, offset: usize, len: usize) -> &[u8] {
        let f = &self.files[file_idx];
        let start = f.data_offset + offset.min(f.data_len);
        let end = f.data_offset + (offset + len).min(f.data_len);
        &INITRAMFS[start..end]
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

/// Lazily-initialized file table for kernel-internal lookups.
/// The server thread has its own local copy; this is for the ELF loader etc.
static PARSED: crate::sync::SpinLock<Option<Initramfs>> = crate::sync::SpinLock::new(None);

/// Look up a file in the initramfs by name.
/// Returns a static slice into the embedded CPIO data, or None if not found.
/// Safe to call from any kernel context (no IPC needed).
pub fn lookup_file(name: &[u8]) -> Option<&'static [u8]> {
    let mut guard = PARSED.lock();
    if guard.is_none() {
        let mut fs = Initramfs::new();
        fs.parse(INITRAMFS);
        *guard = Some(fs);
    }
    let fs = guard.as_ref().unwrap();
    let idx = fs.find(name)?;
    let f = &fs.files[idx];
    Some(&INITRAMFS[f.data_offset..f.data_offset + f.data_len])
}

/// The initramfs server thread entry point.
pub fn initramfs_server() -> ! {
    // Parse the embedded archive.
    let mut fs = Initramfs::new();
    fs.parse(INITRAMFS);
    crate::println!("  [initramfs] parsed {} files from {} byte archive",
        fs.count, INITRAMFS.len());
    for i in 0..fs.count {
        let f = &fs.files[i];
        // Convert name to str for printing.
        let name = core::str::from_utf8(f.name_bytes()).unwrap_or("?");
        crate::println!("  [initramfs]   {} ({} bytes)", name, f.data_len);
    }

    // Create our service port.
    let port = port::create().expect("initramfs port");
    INITRAMFS_PORT.store(port, Ordering::Release);
    crate::println!("  [initramfs] server ready on port {}", port);

    // Server loop.
    loop {
        let msg = match port::recv(port) {
            Ok(m) => m,
            Err(()) => break,
        };

        match msg.tag {
            IO_CONNECT => {
                let name_len = msg.data[3] as usize;
                let name_buf = unpack_name(msg.data[0], msg.data[1], msg.data[2], name_len);
                let name = &name_buf[..name_len.min(24)];
                let reply_port = msg.data[4] as u32;
                match fs.find(name) {
                    Some(idx) => {
                        let reply = Message::new(IO_CONNECT_OK, [
                            idx as u64,
                            fs.files[idx].data_len as u64,
                            0, 0, 0, 0,
                        ]);
                        let _ = port::send_nb(reply_port, reply);
                    }
                    None => {
                        let reply = Message::new(IO_ERROR, [ERR_NOT_FOUND, 0, 0, 0, 0, 0]);
                        let _ = port::send_nb(reply_port, reply);
                    }
                }
            }

            IO_READ => {
                let file_handle = msg.data[0] as usize;
                let offset = msg.data[1] as usize;
                let length = msg.data[2] as usize;
                let reply_port = msg.data[3] as u32;

                if file_handle >= fs.count || !fs.files[file_handle].active {
                    let reply = Message::new(IO_ERROR, [ERR_INVALID, 0, 0, 0, 0, 0]);
                    let _ = port::send_nb(reply_port, reply);
                    continue;
                }

                let data = fs.read(file_handle, offset, length);
                let bytes_read = data.len();

                if bytes_read <= MAX_INLINE_READ {
                    // Inline read — pack data into message words.
                    let packed = pack_inline_data(data);
                    let reply = Message::new(IO_READ_OK, [
                        bytes_read as u64,
                        packed[0], packed[1], packed[2], packed[3], packed[4],
                    ]);
                    let _ = port::send_nb(reply_port, reply);
                } else {
                    // For now, clamp to inline max. Grant-based reads added in M6.
                    let clamped = &data[..MAX_INLINE_READ];
                    let packed = pack_inline_data(clamped);
                    let reply = Message::new(IO_READ_OK, [
                        clamped.len() as u64,
                        packed[0], packed[1], packed[2], packed[3], packed[4],
                    ]);
                    let _ = port::send_nb(reply_port, reply);
                }
            }

            IO_STAT => {
                let file_handle = msg.data[0] as usize;
                let reply_port = msg.data[1] as u32;

                if file_handle >= fs.count || !fs.files[file_handle].active {
                    let reply = Message::new(IO_ERROR, [ERR_INVALID, 0, 0, 0, 0, 0]);
                    let _ = port::send_nb(reply_port, reply);
                    continue;
                }

                let reply = Message::new(IO_STAT_OK, [
                    fs.files[file_handle].data_len as u64,
                    0, // type = regular file
                    0, 0, 0, 0,
                ]);
                let _ = port::send_nb(reply_port, reply);
            }

            IO_CLOSE => {
                // Nothing to clean up for read-only initramfs.
            }

            _ => {
                let reply_port = msg.data[3] as u32;
                if reply_port != 0 {
                    let reply = Message::new(IO_ERROR, [ERR_INVALID, 0, 0, 0, 0, 0]);
                    let _ = port::send_nb(reply_port, reply);
                }
            }
        }
    }

    loop { core::hint::spin_loop(); }
}
