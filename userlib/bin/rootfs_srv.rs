#![no_std]
#![no_main]

//! rootfs — CPIO-backed writable in-memory filesystem server.
//!
//! Pre-populates from a CPIO archive at startup, then serves the standard
//! FS protocol (0x2000 series). Reads of original files come directly from
//! the CPIO data (zero-copy). Writes and new files use dynamically allocated
//! pages. Designed to be mounted at "/" as a writable root filesystem.

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
const FS_MKDIR: u64 = 0x2A00;
const FS_MKDIR_OK: u64 = 0x2A01;
const FS_UNLINK: u64 = 0x2A20;
const FS_UNLINK_OK: u64 = 0x2A21;
const FS_ERROR: u64 = 0x2F00;

const ERR_NOT_FOUND: u64 = 1;
const ERR_INVALID: u64 = 3;
const ERR_FULL: u64 = 4;

const MAX_FILES: usize = 64;
const MAX_NAME: usize = 16;
const MAX_OPEN: usize = 32;
const PAGE_SIZE: usize = 4096;
const MAX_INLINE: usize = 24;

/// A file in the rootfs. Can be backed by CPIO data, allocated pages, or both.
#[derive(Clone, Copy)]
struct RootfsFile {
    name: [u8; MAX_NAME],
    name_len: u8,
    active: bool,
    is_dir: bool,
    mode: u16,
    size: u32,
    /// Offset into CPIO data for original content (0 = no CPIO backing).
    cpio_offset: u32,
    /// Length of CPIO-backed data. Reads beyond this come from pages[].
    cpio_len: u32,
    /// Dynamically allocated pages for writes. Each entry is a VA or 0.
    /// Covers the file from byte 0; if a page is 0 and within cpio_len,
    /// the read falls through to CPIO data.
    pages: [usize; 64], // 64 pages × 4K = 256K max
}

impl RootfsFile {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_NAME],
            name_len: 0,
            active: false,
            is_dir: false,
            mode: 0,
            size: 0,
            cpio_offset: 0,
            cpio_len: 0,
            pages: [0; 64],
        }
    }
}

#[derive(Clone, Copy)]
struct OpenHandle {
    file_idx: usize,
    active: bool,
    writable: bool,
    pid: u32,
}

impl OpenHandle {
    const fn empty() -> Self {
        Self {
            file_idx: 0,
            active: false,
            writable: false,
            pid: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// CPIO parsing
// ---------------------------------------------------------------------------

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

/// Parse CPIO newc archive into the file table. Returns file count.
fn parse_cpio(cpio: &[u8], files: &mut [RootfsFile; MAX_FILES]) -> usize {
    let mut pos = 0;
    let mut count = 0;
    while pos + 110 <= cpio.len() && count < MAX_FILES {
        if &cpio[pos..pos + 6] != b"070701" {
            break;
        }
        let mode = parse_hex8(&cpio[pos + 14..pos + 22]);
        let filesize = parse_hex8(&cpio[pos + 54..pos + 62]);
        let namesize = parse_hex8(&cpio[pos + 94..pos + 102]);
        let name_start = pos + 110;
        let name_end = name_start + namesize - 1; // strip NUL
        let data_start = align4(name_start + namesize);
        let data_end = data_start + filesize;
        let next = align4(data_end);
        if name_end > cpio.len() || data_end > cpio.len() {
            break;
        }
        let name = &cpio[name_start..name_end];
        if name == b"TRAILER!!!" {
            break;
        }
        // Skip "." entry and empty entries, but keep directories.
        let is_dir = (mode & 0o170000) == 0o040000;
        if name != b"." {
            let f = &mut files[count];
            let copy_len = name.len().min(MAX_NAME);
            f.name[..copy_len].copy_from_slice(&name[..copy_len]);
            f.name_len = copy_len as u8;
            f.active = true;
            f.is_dir = is_dir;
            f.mode = mode as u16;
            f.size = filesize as u32;
            f.cpio_offset = data_start as u32;
            f.cpio_len = filesize as u32;
            f.pages = [0; 64];
            count += 1;
        }
        pos = next;
    }
    count
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unpack_name(w0: u64, w1: u64, max_len: usize) -> ([u8; MAX_NAME], usize) {
    let mut buf = [0u8; MAX_NAME];
    let words = [w0, w1];
    let len = max_len.min(MAX_NAME);
    for i in 0..len {
        buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
    }
    (buf, len)
}

fn find_file(files: &[RootfsFile; MAX_FILES], name: &[u8; MAX_NAME], nlen: usize) -> Option<usize> {
    for (i, f) in files.iter().enumerate() {
        if f.active && f.name_len as usize == nlen && f.name[..nlen] == name[..nlen] {
            return Some(i);
        }
    }
    None
}

fn pack_inline_data(data: &[u8]) -> [u64; 3] {
    let mut words = [0u64; 3];
    for (i, &b) in data.iter().enumerate().take(MAX_INLINE) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
}

/// Read bytes from a file, consulting pages[] first, falling back to CPIO data.
/// Returns bytes actually copied.
fn read_file(
    file: &RootfsFile,
    cpio: &[u8],
    offset: usize,
    dst: &mut [u8],
) -> usize {
    let file_size = file.size as usize;
    if offset >= file_size {
        return 0;
    }
    let avail = file_size - offset;
    let to_read = dst.len().min(avail);
    let mut done = 0;

    while done < to_read {
        let pos = offset + done;
        let page_idx = pos / PAGE_SIZE;
        let off_in_page = pos % PAGE_SIZE;
        let chunk = (PAGE_SIZE - off_in_page).min(to_read - done);

        if page_idx < 64 && file.pages[page_idx] != 0 {
            // Read from allocated page.
            let src = file.pages[page_idx] + off_in_page;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src as *const u8,
                    dst[done..done + chunk].as_mut_ptr(),
                    chunk,
                );
            }
        } else if pos < file.cpio_len as usize {
            // Fall back to CPIO data.
            let cpio_start = file.cpio_offset as usize + pos;
            let cpio_avail = (file.cpio_len as usize).saturating_sub(pos);
            let from_cpio = chunk.min(cpio_avail);
            dst[done..done + from_cpio].copy_from_slice(&cpio[cpio_start..cpio_start + from_cpio]);
            // Zero any remainder in this chunk beyond CPIO data.
            for b in dst[done + from_cpio..done + chunk].iter_mut() {
                *b = 0;
            }
        } else {
            // Beyond CPIO and no page — zeros.
            for b in dst[done..done + chunk].iter_mut() {
                *b = 0;
            }
        }

        done += chunk;
    }
    done
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

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry: arg0 = port ID, arg1 = CPIO data VA, arg2 = CPIO data length.
#[unsafe(no_mangle)]
fn main(port_id: u64, data_va: u64, data_len: u64) {
    let cpio_data = unsafe { core::slice::from_raw_parts(data_va as *const u8, data_len as usize) };

    let mut files = [RootfsFile::empty(); MAX_FILES];
    let file_count = parse_cpio(cpio_data, &mut files);

    syscall::debug_puts(b"  [rootfs_srv] parsed ");
    print_num(file_count as u64);
    syscall::debug_puts(b" files from CPIO, serving on port ");
    print_num(port_id);
    syscall::debug_puts(b"\n");

    let port = port_id;
    let my_aspace = syscall::aspace_id();

    // Register with name server.
    syscall::ns_register(b"rootfs", port);

    let mut handles = [OpenHandle::empty(); MAX_OPEN];

    // Server loop.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            FS_OPEN => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let caller_pid = msg.data[3] as u32;
                let (name, nlen) = unpack_name(msg.data[0], msg.data[1], name_len);

                match find_file(&files, &name, nlen) {
                    Some(fi) => {
                        let mut h = u64::MAX;
                        for (i, hnd) in handles.iter_mut().enumerate() {
                            if !hnd.active {
                                hnd.active = true;
                                hnd.writable = false;
                                hnd.file_idx = fi;
                                hnd.pid = caller_pid;
                                h = i as u64;
                                break;
                            }
                        }
                        if h == u64::MAX {
                            syscall::send(reply_port, FS_ERROR, ERR_FULL, 0, 0, 0);
                        } else {
                            syscall::send(
                                reply_port,
                                FS_OPEN_OK,
                                h,
                                files[fi].size as u64,
                                my_aspace as u64,
                                0,
                            );
                        }
                    }
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                    }
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

                let fi = handles[handle].file_idx;
                let file = &files[fi];
                if offset >= file.size as usize {
                    syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                    continue;
                }

                if grant_va != 0 {
                    // Grant-based read: copy directly into granted pages.
                    let avail = (file.size as usize).saturating_sub(offset);
                    let to_read = length.min(avail);
                    let dst = unsafe { core::slice::from_raw_parts_mut(grant_va as *mut u8, to_read) };
                    let bytes_read = read_file(file, cpio_data, offset, dst);
                    syscall::send_nb(reply_port, FS_READ_OK, bytes_read as u64, 0);
                } else {
                    // Inline read.
                    let mut buf = [0u8; MAX_INLINE];
                    let to_read = length.min(MAX_INLINE);
                    let bytes_read = read_file(file, cpio_data, offset, &mut buf[..to_read]);
                    let packed = pack_inline_data(&buf[..bytes_read]);
                    syscall::send(
                        reply_port,
                        FS_READ_OK,
                        bytes_read as u64,
                        packed[0],
                        packed[1],
                        packed[2],
                    );
                }
            }

            FS_READDIR => {
                let start_offset = msg.data[0] as usize;
                let reply_port = msg.data[2] & 0xFFFF_FFFF;

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
                        syscall::send(
                            reply_port,
                            FS_READDIR_OK,
                            f.size as u64,
                            name_lo,
                            name_hi,
                            (i + 1) as u64,
                        );
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
                let reply_port = msg.data[2] & 0xFFFF_FFFF;

                if handle >= MAX_OPEN || !handles[handle].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let fi = handles[handle].file_idx;
                let f = &files[fi];
                let ftype = if f.is_dir { 1u64 } else { 0u64 };
                syscall::send(
                    reply_port,
                    FS_STAT_OK,
                    f.size as u64,
                    f.mode as u64 | (ftype << 16),
                    0,
                    fi as u64,
                );
            }

            FS_CLOSE => {
                let handle = msg.data[0] as usize;
                if handle < MAX_OPEN && handles[handle].active {
                    handles[handle].active = false;
                }
            }

            FS_CREATE => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let caller_pid = msg.data[3] as u32;
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
                        f.is_dir = false;
                        f.mode = 0o100644;
                        f.size = 0;
                        f.cpio_offset = 0;
                        f.cpio_len = 0;
                        f.pages = [0; 64];
                        fi = i;
                        break;
                    }
                }
                if fi == usize::MAX {
                    syscall::send(reply_port, FS_ERROR, ERR_FULL, 0, 0, 0);
                    continue;
                }

                let mut h = u64::MAX;
                for (i, hnd) in handles.iter_mut().enumerate() {
                    if !hnd.active {
                        hnd.active = true;
                        hnd.writable = true;
                        hnd.file_idx = fi;
                        hnd.pid = caller_pid;
                        h = i as u64;
                        break;
                    }
                }
                if h == u64::MAX {
                    files[fi].active = false;
                    syscall::send(reply_port, FS_ERROR, ERR_FULL, 0, 0, 0);
                } else {
                    syscall::send(reply_port, FS_CREATE_OK, h, 0, my_aspace as u64, 0);
                }
            }

            FS_WRITE => {
                let handle = msg.data[0] as usize;
                let length = (msg.data[1] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[1] >> 32;
                let grant_va = msg.data[2] as usize;

                if handle >= MAX_OPEN || !handles[handle].active || !handles[handle].writable {
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

                    if page_idx >= 64 {
                        break; // File too large.
                    }

                    // Allocate page on demand (copy-on-write from CPIO if needed).
                    if files[fi].pages[page_idx] == 0 {
                        match syscall::mmap_anon(0, 1, 1) {
                            Some(va) => {
                                // Pre-fill from CPIO data if this page has backing.
                                let page_start = page_idx * PAGE_SIZE;
                                let cpio_len = files[fi].cpio_len as usize;
                                if page_start < cpio_len {
                                    let cpio_off = files[fi].cpio_offset as usize + page_start;
                                    let copy_len = PAGE_SIZE.min(cpio_len - page_start);
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            cpio_data[cpio_off..cpio_off + copy_len].as_ptr(),
                                            va as *mut u8,
                                            copy_len,
                                        );
                                        // Zero remainder.
                                        if copy_len < PAGE_SIZE {
                                            core::ptr::write_bytes(
                                                (va + copy_len) as *mut u8,
                                                0,
                                                PAGE_SIZE - copy_len,
                                            );
                                        }
                                    }
                                } else {
                                    unsafe {
                                        core::ptr::write_bytes(va as *mut u8, 0, PAGE_SIZE);
                                    }
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

            FS_DELETE | FS_UNLINK => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let (name, nlen) = unpack_name(msg.data[0], msg.data[1], name_len);

                match find_file(&files, &name, nlen) {
                    Some(fi) => {
                        // Free allocated pages (CPIO data is shared, not freed).
                        for p in 0..64 {
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
                        let ok_tag = if msg.tag == FS_UNLINK { FS_UNLINK_OK } else { FS_DELETE_OK };
                        syscall::send(reply_port, ok_tag, 0, 0, 0, 0);
                    }
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                    }
                }
            }

            FS_MKDIR => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let (name, nlen) = unpack_name(msg.data[0], msg.data[1], name_len);

                // Check if already exists.
                if find_file(&files, &name, nlen).is_some() {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let mut fi = usize::MAX;
                for (i, f) in files.iter_mut().enumerate() {
                    if !f.active {
                        f.name = name;
                        f.name_len = nlen as u8;
                        f.active = true;
                        f.is_dir = true;
                        f.mode = 0o040755;
                        f.size = 0;
                        f.cpio_offset = 0;
                        f.cpio_len = 0;
                        f.pages = [0; 64];
                        fi = i;
                        break;
                    }
                }
                if fi == usize::MAX {
                    syscall::send(reply_port, FS_ERROR, ERR_FULL, 0, 0, 0);
                } else {
                    syscall::send(reply_port, FS_MKDIR_OK, fi as u64, 0, 0, 0);
                }
            }

            _ => {}
        }
    }

    loop {
        core::hint::spin_loop();
    }
}
