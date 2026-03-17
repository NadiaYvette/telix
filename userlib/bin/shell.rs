#![no_std]
#![no_main]

//! Interactive shell for Telix.
//!
//! Connects to console_srv for I/O and fat16_srv for filesystem access.
//! Commands: help, ls, cat, echo, info.

extern crate userlib;

use userlib::syscall;

// Console protocol.
const CON_READ: u64 = 0x3000;
const CON_READ_OK: u64 = 0x3001;
const CON_WRITE: u64 = 0x3100;
#[allow(dead_code)]
const CON_WRITE_OK: u64 = 0x3101;

// FS protocol.
const FS_OPEN: u64 = 0x2000;
const FS_OPEN_OK: u64 = 0x2001;
const FS_READ: u64 = 0x2100;
const FS_READ_OK: u64 = 0x2101;
const FS_READDIR: u64 = 0x2200;
const FS_READDIR_OK: u64 = 0x2201;
#[allow(dead_code)]
const FS_READDIR_END: u64 = 0x2202;
const FS_CLOSE: u64 = 0x2400;

fn pack_name(name: &[u8]) -> (u64, u64, u64) {
    let mut words = [0u64; 3];
    for (i, &b) in name.iter().enumerate().take(24) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    (words[0], words[1], words[2])
}

#[allow(dead_code)]
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

/// Write bytes to console_srv. Chunks into 24-byte messages.
fn con_puts(con_port: u32, reply_port: u32, msg: &[u8]) {
    let mut offset = 0;
    while offset < msg.len() {
        let chunk_len = (msg.len() - offset).min(16); // Use first 2 words (16 bytes) for simplicity
        let mut w0 = 0u64;
        let mut w1 = 0u64;
        for i in 0..chunk_len.min(8) {
            w0 |= (msg[offset + i] as u64) << (i * 8);
        }
        for i in 8..chunk_len.min(16) {
            w1 |= (msg[offset + i] as u64) << ((i - 8) * 8);
        }
        let d2 = (chunk_len as u64) | ((reply_port as u64) << 32);
        syscall::send(con_port, CON_WRITE, w0, w1, d2, 0);
        // Wait for CON_WRITE_OK.
        let _ = syscall::recv_msg(reply_port);
        offset += chunk_len;
    }
}

/// Read a line from console_srv. Returns length.
fn con_readline(con_port: u32, reply_port: u32, buf: &mut [u8; 64]) -> usize {
    let d0 = 64u64 | ((reply_port as u64) << 32);
    syscall::send(con_port, CON_READ, d0, 0, 0, 0);

    if let Some(msg) = syscall::recv_msg(reply_port) {
        if msg.tag == CON_READ_OK {
            let len = (msg.data[0] as usize).min(24).min(64);
            let words = [msg.data[1], msg.data[2], msg.data[3]];
            for i in 0..len {
                buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
            }
            return len;
        }
    }
    0
}

/// Check if `line` starts with `prefix`.
fn starts_with(line: &[u8], prefix: &[u8]) -> bool {
    if line.len() < prefix.len() {
        return false;
    }
    &line[..prefix.len()] == prefix
}

/// Format a decimal number into a buffer. Returns number of bytes written.
fn fmt_num(n: u64, buf: &mut [u8]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut val = n;
    let mut i = 0;
    while val > 0 {
        tmp[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    let len = i;
    for j in 0..len {
        buf[j] = tmp[len - 1 - j];
    }
    len
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    // Wait for console_srv.
    let con_port = loop {
        if let Some(p) = syscall::ns_lookup(b"console") {
            break p;
        }
        for _ in 0..50 { syscall::yield_now(); }
    };

    let reply_port = syscall::port_create() as u32;

    // Try to find fat16_srv (may not exist on x86_64).
    let fat16_port = syscall::ns_lookup(b"fat16");

    // Welcome banner.
    con_puts(con_port, reply_port, b"Telix shell v0.1\r\n");

    // Command loop.
    loop {
        con_puts(con_port, reply_port, b"telix> ");

        let mut line_buf = [0u8; 64];
        let len = con_readline(con_port, reply_port, &mut line_buf);
        let line = &line_buf[..len];

        // Trim trailing whitespace.
        let mut end = len;
        while end > 0 && (line[end - 1] == b' ' || line[end - 1] == b'\n' || line[end - 1] == b'\r') {
            end -= 1;
        }
        let line = &line_buf[..end];

        if end == 0 {
            continue;
        }

        if line == b"help" {
            con_puts(con_port, reply_port, b"Commands:\r\n");
            con_puts(con_port, reply_port, b"  help  - show this\r\n");
            con_puts(con_port, reply_port, b"  ls    - list files\r\n");
            con_puts(con_port, reply_port, b"  cat F - show file\r\n");
            con_puts(con_port, reply_port, b"  echo  - echo text\r\n");
            con_puts(con_port, reply_port, b"  info  - sys info\r\n");
        } else if line == b"ls" {
            cmd_ls(con_port, reply_port, fat16_port);
        } else if starts_with(line, b"cat ") {
            cmd_cat(con_port, reply_port, fat16_port, &line[4..]);
        } else if starts_with(line, b"echo ") {
            con_puts(con_port, reply_port, &line[5..]);
            con_puts(con_port, reply_port, b"\r\n");
        } else if line == b"info" {
            cmd_info(con_port, reply_port);
        } else {
            con_puts(con_port, reply_port, b"unknown: ");
            con_puts(con_port, reply_port, line);
            con_puts(con_port, reply_port, b"\r\n");
        }
    }
}

fn cmd_ls(con_port: u32, reply_port: u32, fat16_port: Option<u32>) {
    let fp = match fat16_port {
        Some(p) => p,
        None => {
            con_puts(con_port, reply_port, b"no filesystem\r\n");
            return;
        }
    };

    let fs_reply = syscall::port_create() as u32;
    let mut idx = 0u64;

    loop {
        // FS_READDIR: data[0]=entry_index, data[2]=reply_port
        syscall::send(fp, FS_READDIR, idx, 0, fs_reply as u64, 0);

        if let Some(msg) = syscall::recv_msg(fs_reply) {
            if msg.tag == FS_READDIR_OK {
                let file_size = msg.data[0] as u32;
                let name_lo = msg.data[1];
                let name_hi = msg.data[2];
                idx = msg.data[3]; // next_index

                // Unpack name.
                let mut name = [0u8; 16];
                let mut name_len = 0;
                for i in 0..8 {
                    let ch = (name_lo >> (i * 8)) as u8;
                    if ch == 0 { break; }
                    name[name_len] = ch;
                    name_len += 1;
                }
                for i in 0..8 {
                    let ch = (name_hi >> (i * 8)) as u8;
                    if ch == 0 { break; }
                    name[name_len] = ch;
                    name_len += 1;
                }

                // Print: "  HELLO.TXT  17\r\n"
                con_puts(con_port, reply_port, b"  ");
                con_puts(con_port, reply_port, &name[..name_len]);

                // Pad to 14 chars.
                let pad = if name_len < 14 { 14 - name_len } else { 1 };
                let spaces = b"              "; // 14 spaces
                con_puts(con_port, reply_port, &spaces[..pad]);

                let mut num_buf = [0u8; 20];
                let num_len = fmt_num(file_size as u64, &mut num_buf);
                con_puts(con_port, reply_port, &num_buf[..num_len]);
                con_puts(con_port, reply_port, b"\r\n");
            } else {
                // FS_READDIR_END or error.
                break;
            }
        } else {
            break;
        }
    }
}

fn cmd_cat(con_port: u32, reply_port: u32, fat16_port: Option<u32>, filename: &[u8]) {
    let fp = match fat16_port {
        Some(p) => p,
        None => {
            con_puts(con_port, reply_port, b"no filesystem\r\n");
            return;
        }
    };

    let fs_reply = syscall::port_create() as u32;

    // FS_OPEN.
    let (n0, n1, _) = pack_name(filename);
    let d2 = (filename.len() as u64) | ((fs_reply as u64) << 32);
    syscall::send(fp, FS_OPEN, n0, n1, d2, 0);

    let (handle, file_size) = if let Some(msg) = syscall::recv_msg(fs_reply) {
        if msg.tag == FS_OPEN_OK {
            (msg.data[0], msg.data[1] as u32)
        } else {
            con_puts(con_port, reply_port, b"file not found\r\n");
            return;
        }
    } else {
        return;
    };

    // Read and print in chunks.
    let mut offset = 0u32;
    while offset < file_size {
        let to_read = (file_size - offset).min(24);
        let rd_d2 = (to_read as u64) | ((fs_reply as u64) << 32);
        syscall::send(fp, FS_READ, handle, offset as u64, rd_d2, 0);

        if let Some(msg) = syscall::recv_msg(fs_reply) {
            if msg.tag == FS_READ_OK {
                let bytes_read = msg.data[0] as usize;
                if bytes_read == 0 { break; }

                // Unpack inline data.
                let words = [msg.data[1], msg.data[2], msg.data[3]];
                let mut buf = [0u8; 24];
                for i in 0..bytes_read.min(24) {
                    buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
                }
                con_puts(con_port, reply_port, &buf[..bytes_read]);
                offset += bytes_read as u32;
            } else {
                con_puts(con_port, reply_port, b"read error\r\n");
                break;
            }
        } else {
            break;
        }
    }
    con_puts(con_port, reply_port, b"\r\n");

    // FS_CLOSE.
    syscall::send_nb(fp, FS_CLOSE, handle, 0);
}

fn cmd_info(con_port: u32, reply_port: u32) {
    let tid = syscall::thread_id();
    let aspace = syscall::aspace_id();

    con_puts(con_port, reply_port, b"Telix microkernel\r\n");
    con_puts(con_port, reply_port, b"  thread: ");
    let mut buf = [0u8; 20];
    let len = fmt_num(tid, &mut buf);
    con_puts(con_port, reply_port, &buf[..len]);
    con_puts(con_port, reply_port, b"\r\n  aspace: ");
    let len = fmt_num(aspace as u64, &mut buf);
    con_puts(con_port, reply_port, &buf[..len]);
    con_puts(con_port, reply_port, b"\r\n");
}
