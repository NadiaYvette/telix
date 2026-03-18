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

// Net protocol.
const NET_STATUS: u64 = 0x4000;
const NET_STATUS_OK: u64 = 0x4001;
const NET_PING: u64 = 0x4100;
const NET_PING_OK: u64 = 0x4101;

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
const FS_CREATE: u64 = 0x2500;
const FS_CREATE_OK: u64 = 0x2501;
const FS_WRITE_FILE: u64 = 0x2600;
const FS_WRITE_OK: u64 = 0x2601;

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
            con_puts(con_port, reply_port, b"  help     - show this\r\n");
            con_puts(con_port, reply_port, b"  ls       - list files\r\n");
            con_puts(con_port, reply_port, b"  cat F    - show file\r\n");
            con_puts(con_port, reply_port, b"  echo     - echo text\r\n");
            con_puts(con_port, reply_port, b"  info     - sys info\r\n");
            con_puts(con_port, reply_port, b"  net      - net status\r\n");
            con_puts(con_port, reply_port, b"  ping IP  - ping host\r\n");
            con_puts(con_port, reply_port, b"  run F    - exec file\r\n");
            con_puts(con_port, reply_port, b"  write F D- write D to F\r\n");
            con_puts(con_port, reply_port, b"  A | B    - pipe A to B\r\n");
        } else if find_byte(line, b'|').is_some() {
            let pos = find_byte(line, b'|').unwrap();
            let left = trim_slice(&line[..pos]);
            let right = trim_slice(&line[pos + 1..]);
            if left.is_empty() || right.is_empty() {
                con_puts(con_port, reply_port, b"usage: CMD | CMD\r\n");
            } else {
                cmd_pipe(con_port, reply_port, fat16_port, left, right);
            }
        } else if line == b"ls" {
            cmd_ls(con_port, reply_port, fat16_port);
        } else if starts_with(line, b"cat ") {
            cmd_cat(con_port, reply_port, fat16_port, &line[4..]);
        } else if starts_with(line, b"echo ") {
            con_puts(con_port, reply_port, &line[5..]);
            con_puts(con_port, reply_port, b"\r\n");
        } else if line == b"info" {
            cmd_info(con_port, reply_port);
        } else if line == b"net" {
            cmd_net(con_port, reply_port);
        } else if starts_with(line, b"ping ") {
            cmd_ping(con_port, reply_port, &line[5..]);
        } else if starts_with(line, b"run ") {
            cmd_run(con_port, reply_port, fat16_port, &line[4..]);
        } else if starts_with(line, b"write ") {
            cmd_write(con_port, reply_port, fat16_port, &line[6..]);
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

fn cmd_net(con_port: u32, reply_port: u32) {
    let np = match syscall::ns_lookup(b"net") {
        Some(p) => p,
        None => {
            con_puts(con_port, reply_port, b"no network\r\n");
            return;
        }
    };
    let net_reply = syscall::port_create() as u32;
    syscall::send(np, NET_STATUS, net_reply as u64, 0, 0, 0);

    if let Some(msg) = syscall::recv_msg(net_reply) {
        if msg.tag == NET_STATUS_OK {
            let mac_val = msg.data[0];
            let ip_val = msg.data[1] as u32;
            let ip = ip_val.to_be_bytes();

            con_puts(con_port, reply_port, b"  MAC: ");
            let mut mac_buf = [0u8; 17]; // xx:xx:xx:xx:xx:xx
            for i in 0..6 {
                let byte = (mac_val >> (i * 8)) as u8;
                let hi = byte >> 4;
                let lo = byte & 0xF;
                mac_buf[i * 3] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                mac_buf[i * 3 + 1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                if i < 5 { mac_buf[i * 3 + 2] = b':'; }
            }
            con_puts(con_port, reply_port, &mac_buf);
            con_puts(con_port, reply_port, b"\r\n  IP:  ");

            let mut ip_buf = [0u8; 20];
            let mut pos = 0;
            for i in 0..4 {
                if i > 0 { ip_buf[pos] = b'.'; pos += 1; }
                let n = fmt_num(ip[i] as u64, &mut ip_buf[pos..]);
                pos += n;
            }
            con_puts(con_port, reply_port, &ip_buf[..pos]);
            con_puts(con_port, reply_port, b"\r\n");
        }
    }
    syscall::port_destroy(net_reply);
}

fn parse_ip(s: &[u8]) -> Option<u32> {
    let mut octets = [0u8; 4];
    let mut octet_idx = 0;
    let mut val: u32 = 0;
    let mut has_digit = false;
    for &ch in s {
        if ch == b'.' {
            if !has_digit || octet_idx >= 3 { return None; }
            if val > 255 { return None; }
            octets[octet_idx] = val as u8;
            octet_idx += 1;
            val = 0;
            has_digit = false;
        } else if ch >= b'0' && ch <= b'9' {
            val = val * 10 + (ch - b'0') as u32;
            has_digit = true;
        } else {
            return None;
        }
    }
    if !has_digit || octet_idx != 3 || val > 255 { return None; }
    octets[3] = val as u8;
    Some(u32::from_be_bytes(octets))
}

fn cmd_ping(con_port: u32, reply_port: u32, target: &[u8]) {
    let np = match syscall::ns_lookup(b"net") {
        Some(p) => p,
        None => {
            con_puts(con_port, reply_port, b"no network\r\n");
            return;
        }
    };

    let ip = match parse_ip(target) {
        Some(v) => v,
        None => {
            con_puts(con_port, reply_port, b"bad IP address\r\n");
            return;
        }
    };

    let net_reply = syscall::port_create() as u32;
    syscall::send(np, NET_PING, ip as u64, net_reply as u64, 0, 0);

    con_puts(con_port, reply_port, b"pinging...\r\n");

    // Wait for reply with timeout (poll-based).
    let mut got_reply = false;
    for _ in 0..20000 {
        if let Some(msg) = syscall::recv_nb_msg(net_reply) {
            if msg.tag == NET_PING_OK {
                con_puts(con_port, reply_port, b"reply received\r\n");
            } else {
                con_puts(con_port, reply_port, b"ping failed\r\n");
            }
            got_reply = true;
            break;
        }
        syscall::yield_now();
    }
    if !got_reply {
        con_puts(con_port, reply_port, b"timeout\r\n");
    }
    syscall::port_destroy(net_reply);
}

fn cmd_run(con_port: u32, reply_port: u32, fat16_port: Option<u32>, filename: &[u8]) {
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

    let (handle, file_size, srv_aspace) = if let Some(msg) = syscall::recv_msg(fs_reply) {
        if msg.tag == FS_OPEN_OK {
            (msg.data[0], msg.data[1] as usize, msg.data[2] as u32)
        } else {
            con_puts(con_port, reply_port, b"file not found\r\n");
            syscall::port_destroy(fs_reply);
            return;
        }
    } else {
        syscall::port_destroy(fs_reply);
        return;
    };

    if file_size == 0 {
        con_puts(con_port, reply_port, b"empty file\r\n");
        syscall::send_nb(fp, FS_CLOSE, handle, 0);
        syscall::port_destroy(fs_reply);
        return;
    }

    // Allocate buffer for ELF data.
    let elf_pages = (file_size + 4095) / 4096;
    let elf_va = match syscall::mmap_anon(0, elf_pages, 1) {
        Some(va) => va,
        None => {
            con_puts(con_port, reply_port, b"alloc failed\r\n");
            syscall::send_nb(fp, FS_CLOSE, handle, 0);
            syscall::port_destroy(fs_reply);
            return;
        }
    };

    // Allocate scratch page for grant-based transfer.
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            con_puts(con_port, reply_port, b"alloc failed\r\n");
            syscall::munmap(elf_va);
            syscall::send_nb(fp, FS_CLOSE, handle, 0);
            syscall::port_destroy(fs_reply);
            return;
        }
    };

    // Grant scratch page to fat16_srv.
    let grant_dst: usize = 0x6_0000_0000;
    if !syscall::grant_pages(srv_aspace, scratch_va, grant_dst, 1, false) {
        con_puts(con_port, reply_port, b"grant failed\r\n");
        syscall::munmap(scratch_va);
        syscall::munmap(elf_va);
        syscall::send_nb(fp, FS_CLOSE, handle, 0);
        syscall::port_destroy(fs_reply);
        return;
    }

    // Read entire file via grant-based FS_READ.
    let mut offset = 0usize;
    let mut read_ok = true;
    while offset < file_size {
        let remaining = file_size - offset;
        let chunk = if remaining > 512 { 512 } else { remaining };
        let rd_d2 = (chunk as u64) | ((fs_reply as u64) << 32);
        syscall::send(fp, FS_READ, handle, offset as u64, rd_d2, grant_dst as u64);

        if let Some(msg) = syscall::recv_msg(fs_reply) {
            if msg.tag == FS_READ_OK {
                let bytes_read = msg.data[0] as usize;
                if bytes_read == 0 { break; }
                // Copy from scratch into elf_buf at correct offset.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        scratch_va as *const u8,
                        (elf_va + offset) as *mut u8,
                        bytes_read,
                    );
                }
                offset += bytes_read;
            } else {
                read_ok = false;
                break;
            }
        } else {
            read_ok = false;
            break;
        }
    }

    // Cleanup grant + file handle.
    syscall::revoke(srv_aspace, grant_dst);
    syscall::send_nb(fp, FS_CLOSE, handle, 0);

    if !read_ok || offset < file_size {
        con_puts(con_port, reply_port, b"read error\r\n");
        syscall::munmap(scratch_va);
        syscall::munmap(elf_va);
        syscall::port_destroy(fs_reply);
        return;
    }

    // Spawn from ELF data.
    let elf_data = unsafe { core::slice::from_raw_parts(elf_va as *const u8, file_size) };
    let tid = syscall::spawn_elf(elf_data, 50, 0);

    // Free buffers (ELF data is copied into kernel during spawn_elf).
    syscall::munmap(scratch_va);
    syscall::munmap(elf_va);

    if tid == u64::MAX {
        con_puts(con_port, reply_port, b"exec failed\r\n");
        syscall::port_destroy(fs_reply);
        return;
    }

    // Wait for child to exit.
    loop {
        if let Some(_code) = syscall::waitpid(tid) {
            break;
        }
        syscall::yield_now();
    }

    syscall::port_destroy(fs_reply);
}

fn cmd_write(con_port: u32, reply_port: u32, fat16_port: Option<u32>, args: &[u8]) {
    let fp = match fat16_port {
        Some(p) => p,
        None => {
            con_puts(con_port, reply_port, b"no filesystem\r\n");
            return;
        }
    };

    // Parse "FILENAME DATA..." — split on first space.
    let mut split = 0;
    while split < args.len() && args[split] != b' ' {
        split += 1;
    }
    if split == 0 || split >= args.len() {
        con_puts(con_port, reply_port, b"usage: write FILE DATA\r\n");
        return;
    }
    let filename = &args[..split];
    let data = &args[split + 1..];
    if data.is_empty() {
        con_puts(con_port, reply_port, b"usage: write FILE DATA\r\n");
        return;
    }

    let fs_reply = syscall::port_create() as u32;

    // FS_CREATE.
    let (n0, n1, _) = pack_name(filename);
    let d2 = (filename.len() as u64) | ((fs_reply as u64) << 32);
    syscall::send(fp, FS_CREATE, n0, n1, d2, 0);

    let (handle, srv_aspace) = if let Some(msg) = syscall::recv_msg(fs_reply) {
        if msg.tag == FS_CREATE_OK {
            (msg.data[0], msg.data[2] as u32)
        } else {
            con_puts(con_port, reply_port, b"create failed\r\n");
            syscall::port_destroy(fs_reply);
            return;
        }
    } else {
        syscall::port_destroy(fs_reply);
        return;
    };

    // Allocate scratch page for grant-based write.
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            con_puts(con_port, reply_port, b"alloc failed\r\n");
            syscall::send_nb(fp, FS_CLOSE, handle, 0);
            syscall::port_destroy(fs_reply);
            return;
        }
    };

    // Copy data into scratch page.
    let write_len = data.len().min(4096);
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            scratch_va as *mut u8,
            write_len,
        );
    }

    // Grant scratch to fat16_srv.
    let grant_dst: usize = 0x6_0000_0000;
    if !syscall::grant_pages(srv_aspace, scratch_va, grant_dst, 1, false) {
        con_puts(con_port, reply_port, b"grant failed\r\n");
        syscall::munmap(scratch_va);
        syscall::send_nb(fp, FS_CLOSE, handle, 0);
        syscall::port_destroy(fs_reply);
        return;
    }

    // FS_WRITE: data[0]=handle, data[1]=length|(reply<<32), data[2]=grant_va
    let wd1 = (write_len as u64) | ((fs_reply as u64) << 32);
    syscall::send(fp, FS_WRITE_FILE, handle, wd1, grant_dst as u64, 0);

    let mut wrote = 0usize;
    if let Some(msg) = syscall::recv_msg(fs_reply) {
        if msg.tag == FS_WRITE_OK {
            wrote = msg.data[0] as usize;
        }
    }

    // Revoke grant, close file.
    syscall::revoke(srv_aspace, grant_dst);
    syscall::munmap(scratch_va);
    syscall::send_nb(fp, FS_CLOSE, handle, 0);
    syscall::port_destroy(fs_reply);

    // Print confirmation.
    con_puts(con_port, reply_port, b"wrote ");
    let mut nbuf = [0u8; 20];
    let nlen = fmt_num(wrote as u64, &mut nbuf);
    con_puts(con_port, reply_port, &nbuf[..nlen]);
    con_puts(con_port, reply_port, b" bytes\r\n");
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

fn find_byte(s: &[u8], b: u8) -> Option<usize> {
    for (i, &ch) in s.iter().enumerate() {
        if ch == b { return Some(i); }
    }
    None
}

fn trim_slice(s: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < s.len() && s[start] == b' ' { start += 1; }
    let mut end = s.len();
    while end > start && s[end - 1] == b' ' { end -= 1; }
    &s[start..end]
}

fn cmd_pipe(con_port: u32, reply_port: u32, fat16_port: Option<u32>, left: &[u8], right: &[u8]) {
    let pipe_port = syscall::port_create() as u32;

    // Extract right-side binary name (first word).
    let right_cmd = first_word(right);

    // Spawn right-side process with pipe_port as arg0. It reads from the pipe.
    let tid = syscall::spawn_with_arg(right_cmd, 50, pipe_port as u64);
    if tid == u64::MAX {
        con_puts(con_port, reply_port, b"spawn failed: ");
        con_puts(con_port, reply_port, right_cmd);
        con_puts(con_port, reply_port, b"\r\n");
        syscall::port_destroy(pipe_port);
        return;
    }

    // Give reader time to start and block on recv.
    for _ in 0..10 { syscall::yield_now(); }

    // Execute left-side inline, writing to pipe instead of console.
    if starts_with(left, b"echo ") {
        userlib::pipe::pipe_write(pipe_port, &left[5..]);
    } else if starts_with(left, b"cat ") {
        pipe_cat(pipe_port, reply_port, fat16_port, &left[4..]);
    } else {
        con_puts(con_port, reply_port, b"pipe: unsupported left cmd\r\n");
    }
    userlib::pipe::pipe_close_writer(pipe_port);

    // Wait for right-side child to exit.
    loop {
        if let Some(_) = syscall::waitpid(tid) { break; }
        syscall::yield_now();
    }

    syscall::port_destroy(pipe_port);
}

/// Read a file and write its contents to a pipe port (instead of console).
fn pipe_cat(pipe_port: u32, reply_port: u32, fat16_port: Option<u32>, filename: &[u8]) {
    let fp = match fat16_port {
        Some(p) => p,
        None => return,
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
            syscall::port_destroy(fs_reply);
            return;
        }
    } else {
        syscall::port_destroy(fs_reply);
        return;
    };

    // Read in chunks and write to pipe.
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
                userlib::pipe::pipe_write(pipe_port, &buf[..bytes_read]);
                offset += bytes_read as u32;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    syscall::send_nb(fp, FS_CLOSE, handle, 0);
    syscall::port_destroy(fs_reply);
}

fn first_word(s: &[u8]) -> &[u8] {
    let mut end = 0;
    while end < s.len() && s[end] != b' ' { end += 1; }
    &s[..end]
}
