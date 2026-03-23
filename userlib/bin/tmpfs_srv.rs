#![no_std]
#![no_main]

//! tmpfs — in-memory filesystem server.
//!
//! Stores files in dynamically allocated pages. No disk I/O.
//! Serves the standard FS protocol: FS_OPEN, FS_READ, FS_WRITE,
//! FS_CREATE, FS_DELETE, FS_READDIR, FS_STAT, FS_CLOSE.

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
const FS_CREATE: u64 = 0x2500;
const FS_CREATE_OK: u64 = 0x2501;
const FS_WRITE: u64 = 0x2600;
const FS_WRITE_OK: u64 = 0x2601;
const FS_DELETE: u64 = 0x2700;
const FS_DELETE_OK: u64 = 0x2701;
const FS_ERROR: u64 = 0x2F00;

const ERR_NOT_FOUND: u64 = 1;
const ERR_INVALID: u64 = 3;
const ERR_FULL: u64 = 4;

const MAX_FILES: usize = 32;
const MAX_NAME: usize = 16;
const MAX_OPEN: usize = 16;
const MAX_PAGES_PER_FILE: usize = 16; // 16 * 4096 = 64K max per file
const PAGE_SIZE: usize = 4096;
const MAX_INLINE: usize = 24;

#[derive(Clone, Copy)]
struct TmpfsFile {
    name: [u8; MAX_NAME],
    name_len: u8,
    active: bool,
    mode: u16,
    size: u32,
    pages: [usize; MAX_PAGES_PER_FILE], // VA of allocated pages, 0 = unallocated
}

impl TmpfsFile {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_NAME],
            name_len: 0,
            active: false,
            mode: 0,
            size: 0,
            pages: [0; MAX_PAGES_PER_FILE],
        }
    }
}

#[derive(Clone, Copy)]
struct OpenHandle {
    file_idx: usize,
    active: bool,
    writable: bool,
}

impl OpenHandle {
    const fn empty() -> Self {
        Self { file_idx: 0, active: false, writable: false }
    }
}

fn unpack_name(d0: u64, d1: u64, len: usize) -> ([u8; MAX_NAME], usize) {
    let mut buf = [0u8; MAX_NAME];
    let actual = len.min(MAX_NAME);
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

fn find_file(files: &[TmpfsFile; MAX_FILES], name: &[u8], name_len: usize) -> Option<usize> {
    for (i, f) in files.iter().enumerate() {
        if f.active && f.name_len as usize == name_len {
            let mut eq = true;
            for j in 0..name_len {
                if f.name[j] != name[j] { eq = false; break; }
            }
            if eq { return Some(i); }
        }
    }
    None
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [tmpfs_srv] starting\n");

    let port = syscall::port_create() as u32;
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"tmpfs", port);
    syscall::debug_puts(b"  [tmpfs_srv] ready\n");

    let mut files = [TmpfsFile::empty(); MAX_FILES];
    let mut handles = [OpenHandle::empty(); MAX_OPEN];

    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            FS_OPEN => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let (name, nlen) = unpack_name(msg.data[0], msg.data[1], name_len);

                match find_file(&files, &name, nlen) {
                    Some(fi) => {
                        // Allocate handle.
                        let mut h = u64::MAX;
                        for (i, hnd) in handles.iter_mut().enumerate() {
                            if !hnd.active {
                                hnd.active = true;
                                hnd.writable = false;
                                hnd.file_idx = fi;
                                h = i as u64;
                                break;
                            }
                        }
                        if h == u64::MAX {
                            syscall::send(reply_port, FS_ERROR, ERR_FULL, 0, 0, 0);
                        } else {
                            syscall::send(reply_port, FS_OPEN_OK,
                                h, files[fi].size as u64, my_aspace as u64, 0);
                        }
                    }
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                    }
                }
            }

            FS_READ => {
                let handle = msg.data[0] as usize;
                let offset = msg.data[1] as u32;
                let length = (msg.data[2] & 0xFFFF_FFFF) as u32;
                let reply_port = (msg.data[2] >> 32) as u32;
                let grant_va = msg.data[3] as usize;

                if handle >= MAX_OPEN || !handles[handle].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let fi = handles[handle].file_idx;
                let file = &files[fi];
                if offset >= file.size {
                    syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                    continue;
                }

                let avail = file.size - offset;
                let to_read = length.min(avail) as usize;

                let page_idx = offset as usize / PAGE_SIZE;
                let off_in_page = offset as usize % PAGE_SIZE;
                let bytes_in_page = (PAGE_SIZE - off_in_page).min(to_read);

                if page_idx >= MAX_PAGES_PER_FILE || file.pages[page_idx] == 0 {
                    // No data allocated — return zeros.
                    syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                    continue;
                }

                let src = file.pages[page_idx] + off_in_page;

                if grant_va != 0 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            src as *const u8,
                            grant_va as *mut u8,
                            bytes_in_page,
                        );
                    }
                    syscall::send_nb(reply_port, FS_READ_OK, bytes_in_page as u64, 0);
                } else {
                    let inline_len = bytes_in_page.min(MAX_INLINE);
                    let data = unsafe {
                        core::slice::from_raw_parts(src as *const u8, inline_len)
                    };
                    let packed = pack_inline_data(data);
                    syscall::send(reply_port, FS_READ_OK,
                        inline_len as u64, packed[0], packed[1], packed[2]);
                }
            }

            FS_READDIR => {
                let start_offset = msg.data[0] as usize;
                let reply_port = (msg.data[2] & 0xFFFF_FFFF) as u32;

                // start_offset is used as an index into the files array.
                let mut found = false;
                for i in start_offset..MAX_FILES {
                    if files[i].active {
                        let f = &files[i];
                        let mut name_lo = 0u64;
                        let mut name_hi = 0u64;
                        let nlen = f.name_len as usize;
                        for j in 0..nlen.min(8) {
                            name_lo |= (f.name[j] as u64) << (j * 8);
                        }
                        for j in 8..nlen.min(16) {
                            name_hi |= (f.name[j] as u64) << ((j - 8) * 8);
                        }
                        syscall::send(reply_port, FS_READDIR_OK,
                            f.size as u64, name_lo, name_hi, (i + 1) as u64);
                        found = true;
                        break;
                    }
                }
                if !found {
                    syscall::send(reply_port, FS_READDIR_END, 0, 0, 0, 0);
                }
            }

            FS_STAT => {
                let handle = msg.data[0] as usize;
                let reply_port = (msg.data[2] & 0xFFFF_FFFF) as u32;

                if handle >= MAX_OPEN || !handles[handle].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let fi = handles[handle].file_idx;
                let f = &files[fi];
                syscall::send(reply_port, FS_STAT_OK,
                    f.size as u64, f.mode as u64, 0, fi as u64);
            }

            FS_CLOSE => {
                let handle = msg.data[0] as usize;
                if handle < MAX_OPEN && handles[handle].active {
                    handles[handle].active = false;
                }
            }

            FS_CREATE => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let (name, nlen) = unpack_name(msg.data[0], msg.data[1], name_len);

                // Check if file already exists.
                if find_file(&files, &name, nlen).is_some() {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                // Find free file slot.
                let mut fi = usize::MAX;
                for (i, f) in files.iter_mut().enumerate() {
                    if !f.active {
                        f.name = name;
                        f.name_len = nlen as u8;
                        f.active = true;
                        f.mode = 0o100644;
                        f.size = 0;
                        f.pages = [0; MAX_PAGES_PER_FILE];
                        fi = i;
                        break;
                    }
                }
                if fi == usize::MAX {
                    syscall::send(reply_port, FS_ERROR, ERR_FULL, 0, 0, 0);
                    continue;
                }

                // Allocate handle.
                let mut h = u64::MAX;
                for (i, hnd) in handles.iter_mut().enumerate() {
                    if !hnd.active {
                        hnd.active = true;
                        hnd.writable = true;
                        hnd.file_idx = fi;
                        h = i as u64;
                        break;
                    }
                }
                if h == u64::MAX {
                    files[fi].active = false;
                    syscall::send(reply_port, FS_ERROR, ERR_FULL, 0, 0, 0);
                } else {
                    syscall::send(reply_port, FS_CREATE_OK,
                        h, 0, my_aspace as u64, 0);
                }
            }

            FS_WRITE => {
                let handle = msg.data[0] as usize;
                let length = (msg.data[1] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[1] >> 32) as u32;
                let grant_va = msg.data[2] as usize;

                if handle >= MAX_OPEN || !handles[handle].active
                    || !handles[handle].writable
                {
                    if reply_port != 0 {
                        syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    }
                    continue;
                }

                let fi = handles[handle].file_idx;
                let mut written = 0usize;
                let mut offset = files[fi].size as usize;

                while written < length {
                    let page_idx = offset / PAGE_SIZE;
                    let off_in_page = offset % PAGE_SIZE;
                    let space = (PAGE_SIZE - off_in_page).min(length - written);

                    if page_idx >= MAX_PAGES_PER_FILE {
                        break; // File too large.
                    }

                    // Allocate page on demand.
                    if files[fi].pages[page_idx] == 0 {
                        match syscall::mmap_anon(0, 1, 1) {
                            Some(va) => {
                                // Zero the page.
                                unsafe {
                                    core::ptr::write_bytes(va as *mut u8, 0, PAGE_SIZE);
                                }
                                files[fi].pages[page_idx] = va;
                            }
                            None => break,
                        }
                    }

                    let dst = files[fi].pages[page_idx] + off_in_page;
                    if grant_va != 0 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (grant_va + written) as *const u8,
                                dst as *mut u8,
                                space,
                            );
                        }
                    }

                    written += space;
                    offset += space;
                }

                files[fi].size = offset as u32;

                if reply_port != 0 {
                    syscall::send(reply_port, FS_WRITE_OK, written as u64, 0, 0, 0);
                }
            }

            FS_DELETE => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let (name, nlen) = unpack_name(msg.data[0], msg.data[1], name_len);

                match find_file(&files, &name, nlen) {
                    Some(fi) => {
                        // Free pages.
                        for p in 0..MAX_PAGES_PER_FILE {
                            if files[fi].pages[p] != 0 {
                                syscall::munmap(files[fi].pages[p]);
                                files[fi].pages[p] = 0;
                            }
                        }
                        files[fi].active = false;
                        // Close any open handles to this file.
                        for hnd in handles.iter_mut() {
                            if hnd.active && hnd.file_idx == fi {
                                hnd.active = false;
                            }
                        }
                        syscall::send(reply_port, FS_DELETE_OK, 0, 0, 0, 0);
                    }
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                    }
                }
            }

            _ => {}
        }
    }

    loop { core::hint::spin_loop(); }
}
