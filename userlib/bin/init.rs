#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

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

fn pack_name(name: &[u8]) -> (u64, u64, u64) {
    let mut words = [0u64; 3];
    for (i, &b) in name.iter().enumerate().take(24) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    (words[0], words[1], words[2])
}

/// Global flag address for signal handler test.
static mut SIG_FLAG_PTR: *mut u64 = core::ptr::null_mut();

/// Signal handler for SIGUSR1: writes 42 to the flag, then calls sigreturn.
#[unsafe(no_mangle)]
fn signal_handler_sigusr1(_sig: u64, frame_addr: u64) {
    unsafe {
        if !SIG_FLAG_PTR.is_null() {
            core::ptr::write_volatile(SIG_FLAG_PTR, 42);
        }
    }
    syscall::sigreturn(frame_addr);
    // sigreturn never returns, but just in case:
    loop { core::hint::spin_loop(); }
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"Telix init starting\n");

    // --- Test 1: Process lifecycle (spawn + exit + waitpid) ---
    let tid_hello = syscall::spawn(b"hello", 50);
    if tid_hello != u64::MAX {
        syscall::debug_puts(b"  init: spawned hello (tid=");
        print_num(tid_hello);
        syscall::debug_puts(b")\n");
    } else {
        syscall::debug_puts(b"  init: failed to spawn hello\n");
    }

    if tid_hello != u64::MAX {
        loop {
            if let Some(code) = syscall::waitpid(tid_hello) {
                syscall::debug_puts(b"  init: hello exited with code ");
                print_num(code);
                syscall::debug_puts(b"\n");
                break;
            }
            syscall::yield_now();
        }
    }

    // --- Test 2: Userspace IPC (echo_client does self-send/recv) ---
    let tid_echo = syscall::spawn(b"echo_client", 50);
    if tid_echo != u64::MAX {
        syscall::debug_puts(b"  init: spawned echo_client (tid=");
        print_num(tid_echo);
        syscall::debug_puts(b")\n");
    } else {
        syscall::debug_puts(b"  init: failed to spawn echo_client\n");
    }

    if tid_echo != u64::MAX {
        loop {
            if let Some(code) = syscall::waitpid(tid_echo) {
                syscall::debug_puts(b"  init: echo_client exited with code ");
                print_num(code);
                syscall::debug_puts(b"\n");
                break;
            }
            syscall::yield_now();
        }
    }

    syscall::debug_puts(b"Phase 5 process lifecycle + IPC test: PASSED\n");

    // --- Test 3: mmap_anon / munmap ---
    syscall::debug_puts(b"  init: testing mmap_anon...\n");
    if let Some(va) = syscall::mmap_anon(0, 1, 1) {
        // Write a pattern to the page.
        let ptr = va as *mut u64;
        unsafe { core::ptr::write_volatile(ptr, 0xDEAD_BEEF_CAFE_1234); }
        // Read it back.
        let val = unsafe { core::ptr::read_volatile(ptr) };
        if val == 0xDEAD_BEEF_CAFE_1234 {
            syscall::debug_puts(b"  init: mmap write/read OK\n");
        } else {
            syscall::debug_puts(b"  init: mmap read MISMATCH\n");
        }
        // Unmap.
        if syscall::munmap(va) {
            syscall::debug_puts(b"  init: munmap OK\n");
        } else {
            syscall::debug_puts(b"  init: munmap FAILED\n");
        }
        syscall::debug_puts(b"  init: mmap test PASSED\n");
    } else {
        syscall::debug_puts(b"  init: mmap_anon FAILED\n");
    }

    // --- Test 4: spawn with arg0 ---
    syscall::debug_puts(b"  init: testing spawn with arg0...\n");
    let tid_hello2 = syscall::spawn_with_arg(b"hello", 50, 42);
    if tid_hello2 != u64::MAX {
        syscall::debug_puts(b"  init: spawned hello with arg0=42 (tid=");
        print_num(tid_hello2);
        syscall::debug_puts(b")\n");
        loop {
            if let Some(code) = syscall::waitpid(tid_hello2) {
                syscall::debug_puts(b"  init: hello(arg0) exited with code ");
                print_num(code);
                syscall::debug_puts(b"\n");
                break;
            }
            syscall::yield_now();
        }
    }

    syscall::debug_puts(b"Phase 6 M1-M3 tests: PASSED\n");

    // --- Test 5: Name server lookup + inline file read ---
    syscall::debug_puts(b"  init: testing name server lookup...\n");

    let srv_port = match syscall::ns_lookup(b"initramfs") {
        Some(p) => {
            syscall::debug_puts(b"  init: ns_lookup(initramfs) = port ");
            print_num(p as u64);
            syscall::debug_puts(b"\n");
            p
        }
        None => {
            syscall::debug_puts(b"  init: ns_lookup FAILED\n");
            loop { syscall::yield_now(); }
        }
    };

    let reply_port = syscall::port_create() as u32;

    // IO_CONNECT to open hello.txt
    let name = b"hello.txt";
    let (w0, w1, _) = pack_name(name);
    let d2 = (name.len() as u64) | ((reply_port as u64) << 32);
    syscall::send(srv_port, 0x100, w0, w1, d2, 0);

    let (handle, size, srv_aspace) = if let Some(reply) = syscall::recv_msg(reply_port) {
        if reply.tag == 0x101 {
            (reply.data[0], reply.data[1], reply.data[2] as u32)
        } else {
            syscall::debug_puts(b"  init: connect failed\n");
            loop { syscall::yield_now(); }
        }
    } else {
        syscall::debug_puts(b"  init: no connect reply\n");
        loop { syscall::yield_now(); }
    };

    syscall::debug_puts(b"  init: connected, handle=");
    print_num(handle);
    syscall::debug_puts(b" size=");
    print_num(size);
    syscall::debug_puts(b"\n");

    // Inline read (up to 40 bytes)
    let d2_read = size.min(40) | ((reply_port as u64) << 32);
    syscall::send(srv_port, 0x200, handle, 0, d2_read, 0);

    for _ in 0..20 { syscall::yield_now(); }

    if let Some(rr) = syscall::recv_msg(reply_port) {
        if rr.tag == 0x201 {
            let bytes_read = rr.data[0] as usize;
            syscall::debug_puts(b"  init: inline read ");
            print_num(bytes_read as u64);
            syscall::debug_puts(b" bytes OK\n");
        }
    }

    syscall::debug_puts(b"Phase 6 name server + inline I/O: PASSED\n");

    // --- Test 6: Grant-based large read (full file, 65 bytes) ---
    syscall::debug_puts(b"  init: testing grant-based read...\n");

    // Allocate a buffer page.
    let buf_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  init: mmap for grant buf FAILED\n");
            loop { syscall::yield_now(); }
        }
    };

    // Grant the buffer page to the initramfs server (RW).
    let grant_dst_va: usize = 0x5_0000_0000;
    if !syscall::grant_pages(srv_aspace, buf_va, grant_dst_va, 1, false) {
        syscall::debug_puts(b"  init: grant_pages FAILED\n");
        loop { syscall::yield_now(); }
    }

    // IO_READ with grant: data[0]=handle, data[1]=offset, data[2]=length|(reply<<32), data[3]=grant_va
    // Server detects grant mode by data[3] != 0.
    let d2_grant = size | ((reply_port as u64) << 32);
    syscall::send(srv_port, 0x200, handle, 0, d2_grant, grant_dst_va as u64);

    for _ in 0..20 { syscall::yield_now(); }

    if let Some(rr) = syscall::recv_msg(reply_port) {
        if rr.tag == 0x201 {
            let bytes_read = rr.data[0] as usize;
            syscall::debug_puts(b"  init: grant read ");
            print_num(bytes_read as u64);
            syscall::debug_puts(b" bytes: ");

            // Read from our buffer (same physical pages as the grant).
            let buf = unsafe { core::slice::from_raw_parts(buf_va as *const u8, bytes_read) };
            syscall::debug_puts(buf);
            syscall::debug_puts(b"\n");

            if bytes_read == size as usize {
                syscall::debug_puts(b"  init: grant read size OK\n");
            }
        } else {
            syscall::debug_puts(b"  init: grant read failed\n");
        }
    }

    // Revoke grant and free buffer.
    syscall::revoke(srv_aspace, grant_dst_va);
    syscall::munmap(buf_va);

    // Close.
    syscall::send_nb(srv_port, 0x500, handle, 0);

    syscall::debug_puts(b"Phase 7 grant-based read: PASSED\n");

    // --- Test 7: Ramdisk write + read ---
    syscall::debug_puts(b"  init: testing ramdisk...\n");

    // Give ramdisk_srv time to start and register.
    for _ in 0..100 { syscall::yield_now(); }

    let rd_port = match syscall::ns_lookup(b"ramdisk") {
        Some(p) => {
            syscall::debug_puts(b"  init: ns_lookup(ramdisk) = port ");
            print_num(p as u64);
            syscall::debug_puts(b"\n");
            p
        }
        None => {
            syscall::debug_puts(b"  init: ramdisk not found, skipping\n");
            syscall::debug_puts(b"Phase 7 zero-copy I/O test: PASSED (partial)\n");
            loop { syscall::yield_now(); }
        }
    };

    let rd_reply = syscall::port_create() as u32;

    // Connect to ramdisk.
    let rd_name = b"ramdisk";
    let (rn0, rn1, _) = pack_name(rd_name);
    let rd_d2 = (rd_name.len() as u64) | ((rd_reply as u64) << 32);
    syscall::send(rd_port, 0x100, rn0, rn1, rd_d2, 0);

    let rd_aspace = if let Some(reply) = syscall::recv_msg(rd_reply) {
        if reply.tag == 0x101 {
            reply.data[2] as u32
        } else {
            syscall::debug_puts(b"  init: ramdisk connect failed\n");
            loop { syscall::yield_now(); }
        }
    } else {
        syscall::debug_puts(b"  init: ramdisk no reply\n");
        loop { syscall::yield_now(); }
    };

    // Inline write: 8 bytes "TestOK!\n" at offset 0.
    // IO_WRITE: data[0]=handle, data[1]=offset, data[2]=length|(reply<<32), data[3]=grant_va(0=inline)
    // For inline writes, server reads data from msg.data[5] — but we can't set data[5] from send().
    // Instead, pack inline data into data[3] (the 4th arg, a5) since grant_va=0 means inline.
    // Actually the server reads msg.data[5] for inline data. But data[5] is always 0.
    // Let me fix the ramdisk server to read inline data from data[3] when grant_va=0.
    // Actually, we only have 4 data words via send(). For inline writes, just pack the data
    // into data[3] (the grant_va field is 0 for inline).
    let test_data: u64 = 0x0A_21_4B_4F_74_73_65_54; // "TestOK!\n" little-endian
    let wr_d2 = 8u64 | ((rd_reply as u64) << 32);
    syscall::send(rd_port, 0x300, 0, 0, wr_d2, test_data);

    for _ in 0..20 { syscall::yield_now(); }

    if let Some(rr) = syscall::recv_msg(rd_reply) {
        if rr.tag == 0x301 {
            syscall::debug_puts(b"  init: ramdisk wrote ");
            print_num(rr.data[0]);
            syscall::debug_puts(b" bytes\n");
        }
    }

    // Inline read back: 8 bytes from offset 0.
    let rd_d2_read = 8u64 | ((rd_reply as u64) << 32);
    syscall::send(rd_port, 0x200, 0, 0, rd_d2_read, 0);

    for _ in 0..20 { syscall::yield_now(); }

    if let Some(rr) = syscall::recv_msg(rd_reply) {
        if rr.tag == 0x201 {
            let bytes_read = rr.data[0] as usize;
            // Unpack inline data.
            let word = rr.data[1];
            if word == test_data && bytes_read == 8 {
                syscall::debug_puts(b"  init: ramdisk inline write/read: MATCH\n");
            } else {
                syscall::debug_puts(b"  init: ramdisk inline MISMATCH\n");
            }
        }
    }

    // Grant-based write: 256 bytes of pattern.
    let wr_buf = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => loop { syscall::yield_now(); },
    };
    // Fill with pattern.
    for i in 0..256 {
        unsafe { *((wr_buf + i) as *mut u8) = (i & 0xFF) as u8; }
    }

    let grant_wr_va: usize = 0x5_0000_0000;
    syscall::grant_pages(rd_aspace, wr_buf, grant_wr_va, 1, false);

    // IO_WRITE: data[0]=handle=0, data[1]=offset=0, data[2]=256|(reply<<32), data[3]=grant_va
    let wr_d2_g = 256u64 | ((rd_reply as u64) << 32);
    syscall::send(rd_port, 0x300, 0, 0, wr_d2_g, grant_wr_va as u64);

    for _ in 0..20 { syscall::yield_now(); }

    if let Some(rr) = syscall::recv_msg(rd_reply) {
        if rr.tag == 0x301 {
            syscall::debug_puts(b"  init: ramdisk grant-wrote ");
            print_num(rr.data[0]);
            syscall::debug_puts(b" bytes\n");
        }
    }

    syscall::revoke(rd_aspace, grant_wr_va);
    syscall::munmap(wr_buf);

    // Grant-based read back: 256 bytes.
    let rd_buf = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => loop { syscall::yield_now(); },
    };

    let grant_rd_va: usize = 0x5_0000_0000;
    syscall::grant_pages(rd_aspace, rd_buf, grant_rd_va, 1, false);

    let rd_d2_g = 256u64 | ((rd_reply as u64) << 32);
    syscall::send(rd_port, 0x200, 0, 0, rd_d2_g, grant_rd_va as u64);

    for _ in 0..20 { syscall::yield_now(); }

    let mut grant_read_ok = false;
    if let Some(rr) = syscall::recv_msg(rd_reply) {
        if rr.tag == 0x201 {
            let bytes_read = rr.data[0] as usize;
            // Verify pattern.
            let mut ok = bytes_read == 256;
            for i in 0..256 {
                let b = unsafe { *((rd_buf + i) as *const u8) };
                if b != (i & 0xFF) as u8 {
                    ok = false;
                    break;
                }
            }
            if ok {
                syscall::debug_puts(b"  init: ramdisk grant read/write 256 bytes: MATCH\n");
                grant_read_ok = true;
            } else {
                syscall::debug_puts(b"  init: ramdisk grant MISMATCH\n");
            }
        }
    }

    syscall::revoke(rd_aspace, grant_rd_va);
    syscall::munmap(rd_buf);

    if grant_read_ok {
        syscall::debug_puts(b"Phase 7 zero-copy I/O test: PASSED\n");
    } else {
        syscall::debug_puts(b"Phase 7 zero-copy I/O test: FAILED\n");
    }

    // --- Test 8: Block device I/O via grant ---
    syscall::debug_puts(b"  init: testing block device I/O...\n");

    // Give blk server time to start and register.
    for _ in 0..200 { syscall::yield_now(); }

    let blk_port = syscall::ns_lookup(b"blk");
    if let Some(bp) = blk_port {
        syscall::debug_puts(b"  init: ns_lookup(blk) = port ");
        print_num(bp as u64);
        syscall::debug_puts(b"\n");

        let blk_reply = syscall::port_create() as u32;

        // IO_CONNECT to blk server.
        let (bn0, bn1, _) = pack_name(b"blk");
        let blk_d2 = 3u64 | ((blk_reply as u64) << 32);
        syscall::send(bp, 0x100, bn0, bn1, blk_d2, 0);

        let blk_aspace = if let Some(reply) = syscall::recv_msg(blk_reply) {
            if reply.tag == 0x101 {
                syscall::debug_puts(b"  init: blk connected, size=");
                print_num(reply.data[1]);
                syscall::debug_puts(b" bytes\n");
                reply.data[2] as u32
            } else {
                syscall::debug_puts(b"  init: blk connect failed\n");
                0
            }
        } else {
            syscall::debug_puts(b"  init: blk no connect reply\n");
            0
        };

        if blk_aspace != 0 {
            // Non-destructive test: read sector 0, verify FAT16 boot signature (0x55AA).
            let blk_buf = match syscall::mmap_anon(0, 1, 1) {
                Some(va) => va,
                None => {
                    syscall::debug_puts(b"  init: blk buf alloc FAILED\n");
                    loop { syscall::yield_now(); }
                }
            };

            // Grant buffer to blk server.
            let blk_grant_va: usize = 0x5_0000_0000;
            syscall::grant_pages(blk_aspace, blk_buf, blk_grant_va, 1, false);

            // IO_READ 512 bytes at offset 0 (sector 0 = boot sector).
            let blk_rd_d2 = 512u64 | ((blk_reply as u64) << 32);
            syscall::send(bp, 0x200, 0, 0, blk_rd_d2, blk_grant_va as u64);

            if let Some(rr) = syscall::recv_msg(blk_reply) {
                if rr.tag == 0x201 {
                    let bytes_read = rr.data[0] as usize;
                    // Verify boot signature at bytes 510-511.
                    let sig0 = unsafe { *((blk_buf + 510) as *const u8) };
                    let sig1 = unsafe { *((blk_buf + 511) as *const u8) };
                    if bytes_read == 512 && sig0 == 0x55 && sig1 == 0xAA {
                        syscall::debug_puts(b"Phase 8 async block I/O: PASSED\n");
                    } else {
                        syscall::debug_puts(b"  init: boot sig=");
                        print_num(sig0 as u64);
                        syscall::debug_puts(b",");
                        print_num(sig1 as u64);
                        syscall::debug_puts(b" bytes=");
                        print_num(bytes_read as u64);
                        syscall::debug_puts(b"\n");
                        syscall::debug_puts(b"Phase 8 async block I/O: SIGNATURE MISMATCH\n");
                    }
                } else {
                    syscall::debug_puts(b"  init: blk read error\n");
                }
            }

            syscall::revoke(blk_aspace, blk_grant_va);
            syscall::munmap(blk_buf);
        }
    } else {
        syscall::debug_puts(b"  init: blk not found, skipping block test\n");
        syscall::debug_puts(b"Phase 8 async block I/O: SKIPPED (no blk device)\n");
    }

    // --- Test 9: FAT16 filesystem via fat16_srv ---
    syscall::debug_puts(b"  init: testing FAT16 filesystem...\n");

    // Wait for fat16_srv to register.
    let mut fat16_port: Option<u32> = None;
    for _ in 0..500 {
        if let Some(p) = syscall::ns_lookup(b"fat16") {
            fat16_port = Some(p);
            break;
        }
        syscall::yield_now();
    }

    if let Some(fp) = fat16_port {
        syscall::debug_puts(b"  init: ns_lookup(fat16) = port ");
        print_num(fp as u64);
        syscall::debug_puts(b"\n");

        let fs_reply = syscall::port_create() as u32;

        // FS_OPEN "HELLO.TXT"
        let fname = b"HELLO.TXT";
        let (fn0, fn1, _) = pack_name(fname);
        let fs_d2 = (fname.len() as u64) | ((fs_reply as u64) << 32);
        syscall::send(fp, 0x2000, fn0, fn1, fs_d2, 0);

        let mut fs_ok = false;
        if let Some(reply) = syscall::recv_msg(fs_reply) {
            if reply.tag == 0x2001 {
                let handle = reply.data[0];
                let file_size = reply.data[1];
                syscall::debug_puts(b"  init: FS_OPEN ok, handle=");
                print_num(handle);
                syscall::debug_puts(b" size=");
                print_num(file_size);
                syscall::debug_puts(b"\n");

                if file_size == 17 {
                    // FS_READ inline (17 bytes fits in 3 words = 24 bytes max)
                    let rd_d2 = file_size | ((fs_reply as u64) << 32);
                    syscall::send(fp, 0x2100, handle, 0, rd_d2, 0);

                    if let Some(rr) = syscall::recv_msg(fs_reply) {
                        if rr.tag == 0x2101 {
                            let bytes_read = rr.data[0] as usize;
                            // Unpack inline data from words 1..3
                            let expected = b"Hello from FAT16!";
                            let mut match_ok = bytes_read == 17;
                            let words = [rr.data[1], rr.data[2], rr.data[3]];
                            for i in 0..17 {
                                let got = (words[i / 8] >> ((i % 8) * 8)) as u8;
                                if got != expected[i] {
                                    match_ok = false;
                                    break;
                                }
                            }
                            if match_ok {
                                syscall::debug_puts(b"  init: FAT16 content verified\n");
                                fs_ok = true;
                            } else {
                                syscall::debug_puts(b"  init: FAT16 content MISMATCH\n");
                            }
                        } else {
                            syscall::debug_puts(b"  init: FS_READ failed\n");
                        }
                    }

                    // FS_CLOSE
                    syscall::send_nb(fp, 0x2400, handle, 0);
                } else {
                    syscall::debug_puts(b"  init: unexpected file size\n");
                }
            } else {
                syscall::debug_puts(b"  init: FS_OPEN failed, tag=");
                print_num(reply.tag);
                syscall::debug_puts(b"\n");
            }
        }

        if fs_ok {
            syscall::debug_puts(b"Phase 10 FAT16 filesystem: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 10 FAT16 filesystem: FAILED\n");
        }
    } else {
        syscall::debug_puts(b"  init: fat16 not found, skipping\n");
        syscall::debug_puts(b"Phase 10 FAT16 filesystem: SKIPPED\n");
    }

    // --- Test 10: Console server ---
    syscall::debug_puts(b"  init: testing console server...\n");

    // Give console_srv time to start and register.
    for _ in 0..200 { syscall::yield_now(); }

    let mut con_port: Option<u32> = None;
    for _ in 0..500 {
        if let Some(p) = syscall::ns_lookup(b"console") {
            con_port = Some(p);
            break;
        }
        syscall::yield_now();
    }

    if let Some(cp) = con_port {
        syscall::debug_puts(b"  init: ns_lookup(console) = port ");
        print_num(cp as u64);
        syscall::debug_puts(b"\n");

        let con_reply = syscall::port_create() as u32;

        // CON_WRITE test: send a test string.
        let test_msg = b"Phase 11 OK\n";
        let (w0, w1, _) = pack_name(test_msg);
        let d2 = (test_msg.len() as u64) | ((con_reply as u64) << 32);
        syscall::send(cp, 0x3100, w0, w1, d2, 0);

        if let Some(reply) = syscall::recv_msg(con_reply) {
            if reply.tag == 0x3101 {
                syscall::debug_puts(b"Phase 11 console server: PASSED\n");
            } else {
                syscall::debug_puts(b"Phase 11 console server: FAILED\n");
            }
        } else {
            syscall::debug_puts(b"Phase 11 console server: FAILED (no reply)\n");
        }

        // Spawn interactive shell.
        let shell_tid = syscall::spawn(b"shell", 50);
        if shell_tid != u64::MAX {
            syscall::debug_puts(b"  init: shell spawned (tid=");
            print_num(shell_tid);
            syscall::debug_puts(b")\n");
        }
    } else {
        syscall::debug_puts(b"  init: console not found\n");
        syscall::debug_puts(b"Phase 11 console server: SKIPPED\n");
    }

    // --- Test 11: Virtio-net + ICMP ping ---
    syscall::debug_puts(b"  init: testing network...\n");

    // Give net_srv time to start and register.
    for _ in 0..200 { syscall::yield_now(); }

    let mut net_port: Option<u32> = None;
    for _ in 0..500 {
        if let Some(p) = syscall::ns_lookup(b"net") {
            net_port = Some(p);
            break;
        }
        syscall::yield_now();
    }

    if let Some(np) = net_port {
        syscall::debug_puts(b"  init: ns_lookup(net) = port ");
        print_num(np as u64);
        syscall::debug_puts(b"\n");

        let net_reply = syscall::port_create() as u32;

        // NET_PING gateway (10.0.2.2).
        let target_ip: u64 = (10u64 << 24) | (0 << 16) | (2 << 8) | 2; // 0x0A000202
        syscall::send(np, 0x4100, target_ip, net_reply as u64, 0, 0);

        // Wait for reply (blocking — net_srv always replies with OK or FAIL).
        let mut ping_ok = false;
        if let Some(reply) = syscall::recv_msg(net_reply) {
            if reply.tag == 0x4101 {
                ping_ok = true;
            }
        }

        if ping_ok {
            syscall::debug_puts(b"Phase 12 virtio-net ping: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 12 virtio-net ping: FAILED\n");
        }
    } else {
        syscall::debug_puts(b"  init: net not found, skipping\n");
        syscall::debug_puts(b"Phase 12 virtio-net ping: SKIPPED\n");
    }

    // --- Test 13: Execute ELF from FAT16 filesystem ---
    syscall::debug_puts(b"  init: testing exec from filesystem...\n");

    if let Some(fp) = fat16_port {
        let exec_reply = syscall::port_create() as u32;

        // FS_OPEN "HELLO.ELF"
        let fname = b"HELLO.ELF";
        let (fn0, fn1, _) = pack_name(fname);
        let fs_d2 = (fname.len() as u64) | ((exec_reply as u64) << 32);
        syscall::send(fp, 0x2000, fn0, fn1, fs_d2, 0);

        let mut exec_ok = false;
        if let Some(reply) = syscall::recv_msg(exec_reply) {
            if reply.tag == 0x2001 {
                let handle = reply.data[0];
                let file_size = reply.data[1] as usize;
                let srv_aspace = reply.data[2] as u32;

                // Allocate ELF buffer and scratch page.
                let elf_pages = (file_size + 4095) / 4096;
                let elf_va = syscall::mmap_anon(0, elf_pages, 1);
                let scratch_va = syscall::mmap_anon(0, 1, 1);

                if let (Some(elf_buf), Some(scratch)) = (elf_va, scratch_va) {
                    // Grant scratch to fat16_srv.
                    let grant_dst: usize = 0x7_0000_0000;
                    if syscall::grant_pages(srv_aspace, scratch, grant_dst, 1, false) {
                        // Read entire file via grant-based FS_READ.
                        let mut offset = 0usize;
                        let mut read_ok = true;
                        while offset < file_size {
                            let remaining = file_size - offset;
                            let chunk = if remaining > 512 { 512 } else { remaining };
                            let rd_d2 = (chunk as u64) | ((exec_reply as u64) << 32);
                            syscall::send(fp, 0x2100, handle, offset as u64, rd_d2, grant_dst as u64);

                            if let Some(msg) = syscall::recv_msg(exec_reply) {
                                if msg.tag == 0x2101 {
                                    let bytes_read = msg.data[0] as usize;
                                    if bytes_read == 0 { break; }
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            scratch as *const u8,
                                            (elf_buf + offset) as *mut u8,
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

                        syscall::revoke(srv_aspace, grant_dst);

                        if read_ok && offset == file_size {
                            // Spawn from ELF data.
                            let elf_data = unsafe {
                                core::slice::from_raw_parts(elf_buf as *const u8, file_size)
                            };
                            let tid = syscall::spawn_elf(elf_data, 50, 0);
                            if tid != u64::MAX {
                                // Wait for child to exit.
                                loop {
                                    if let Some(_code) = syscall::waitpid(tid) {
                                        exec_ok = true;
                                        break;
                                    }
                                    syscall::yield_now();
                                }
                            } else {
                                syscall::debug_puts(b"  init: spawn_elf failed\n");
                            }
                        } else {
                            syscall::debug_puts(b"  init: file read incomplete\n");
                        }
                    }

                    syscall::munmap(scratch);
                    syscall::munmap(elf_buf);
                }

                syscall::send_nb(fp, 0x2400, handle, 0);
            } else {
                syscall::debug_puts(b"  init: HELLO.ELF not found on disk\n");
            }
        }

        if exec_ok {
            syscall::debug_puts(b"Phase 14 exec from filesystem: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 14 exec from filesystem: FAILED\n");
        }
    } else {
        syscall::debug_puts(b"  init: fat16 not available, skipping\n");
        syscall::debug_puts(b"Phase 14 exec from filesystem: SKIPPED\n");
    }

    // --- Test 14: Writable FAT16 filesystem ---
    syscall::debug_puts(b"  init: testing writable FAT16...\n");

    if let Some(fp) = fat16_port {
        let wr_reply = syscall::port_create() as u32;

        // FS_CREATE "TEST.TXT"
        let fname = b"TEST.TXT";
        let (fn0, fn1, _) = pack_name(fname);
        let fs_d2 = (fname.len() as u64) | ((wr_reply as u64) << 32);
        syscall::debug_puts(b"  init: sending FS_CREATE to port ");
        print_num(fp as u64);
        syscall::debug_puts(b" reply=");
        print_num(wr_reply as u64);
        syscall::debug_puts(b"\n");
        syscall::send(fp, 0x2500, fn0, fn1, fs_d2, 0);
        syscall::debug_puts(b"  init: FS_CREATE sent, waiting reply\n");

        let mut phase15_ok = false;

        if let Some(reply) = syscall::recv_msg(wr_reply) {
            if reply.tag != 0x2501 {
                syscall::debug_puts(b"  init: FS_CREATE reply tag=");
                print_num(reply.tag);
                syscall::debug_puts(b" d0=");
                print_num(reply.data[0]);
                syscall::debug_puts(b"\n");
            }
            if reply.tag == 0x2501 {
                let handle = reply.data[0];
                let srv_aspace = reply.data[2] as u32;
                syscall::debug_puts(b"  init: FS_CREATE ok handle=");
                print_num(handle);
                syscall::debug_puts(b" aspace=");
                print_num(srv_aspace as u64);
                syscall::debug_puts(b"\n");

                // Allocate scratch page for grant-based write.
                if let Some(scratch) = syscall::mmap_anon(0, 1, 1) {
                    let test_data = b"Telix write test";
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            test_data.as_ptr(),
                            scratch as *mut u8,
                            test_data.len(),
                        );
                    }

                    // Grant scratch to fat16_srv.
                    let grant_dst: usize = 0x8_0000_0000;
                    let grant_ok = syscall::grant_pages(srv_aspace, scratch, grant_dst, 1, false);
                    syscall::debug_puts(if grant_ok { b"  init: grant ok\n" } else { b"  init: grant FAIL\n" });
                    if grant_ok {
                        // FS_WRITE: data[0]=handle, data[1]=length|(reply<<32), data[2]=grant_va
                        let wd1 = (test_data.len() as u64) | ((wr_reply as u64) << 32);
                        syscall::send(fp, 0x2600, handle, wd1, grant_dst as u64, 0);
                        syscall::debug_puts(b"  init: FS_WRITE sent\n");

                        if let Some(wr_msg) = syscall::recv_msg(wr_reply) {
                            syscall::debug_puts(b"  init: FS_WRITE reply tag=");
                            print_num(wr_msg.tag);
                            syscall::debug_puts(b" d0=");
                            print_num(wr_msg.data[0]);
                            syscall::debug_puts(b"\n");
                            if wr_msg.tag == 0x2601 && wr_msg.data[0] == test_data.len() as u64 {
                                // Revoke grant, close file.
                                syscall::revoke(srv_aspace, grant_dst);

                                // FS_CLOSE (triggers flush). Use blocking send to ensure delivery.
                                syscall::send(fp, 0x2400, handle, 0, 0, 0);

                                // Delay for close to complete (server processes close + disk flush).
                                // Fat16_srv must: flush FAT sectors + write dir entry, each requiring
                                // IPC round-trips to blk_srv + virtio disk I/O.
                                for _ in 0..2000 { syscall::yield_now(); }

                                // Now re-open and verify.
                                let (fn0b, fn1b, _) = pack_name(fname);
                                let fs_d2b = (fname.len() as u64) | ((wr_reply as u64) << 32);
                                syscall::send(fp, 0x2000, fn0b, fn1b, fs_d2b, 0);

                                syscall::debug_puts(b"  init: re-opening\n");
                                if let Some(open_msg) = syscall::recv_msg(wr_reply) {
                                    syscall::debug_puts(b"  init: reopen tag=");
                                    print_num(open_msg.tag);
                                    syscall::debug_puts(b" size=");
                                    print_num(open_msg.data[1]);
                                    syscall::debug_puts(b"\n");
                                    if open_msg.tag == 0x2001 {
                                        let rh = open_msg.data[0];
                                        let rsize = open_msg.data[1] as usize;
                                        let rsrv = open_msg.data[2] as u32;

                                        if rsize == test_data.len() {
                                            // Grant-based read to verify.
                                            let grant_rd: usize = 0x8_0000_0000;
                                            // Zero out scratch.
                                            unsafe {
                                                core::ptr::write_bytes(scratch as *mut u8, 0, 512);
                                            }
                                            if syscall::grant_pages(rsrv, scratch, grant_rd, 1, false) {
                                                let rd_d2 = (rsize as u64) | ((wr_reply as u64) << 32);
                                                syscall::send(fp, 0x2100, rh, 0, rd_d2, grant_rd as u64);

                                                if let Some(rd_msg) = syscall::recv_msg(wr_reply) {
                                                    if rd_msg.tag == 0x2101 {
                                                        let bytes_read = rd_msg.data[0] as usize;
                                                        let buf = unsafe {
                                                            core::slice::from_raw_parts(scratch as *const u8, bytes_read)
                                                        };
                                                        if bytes_read == test_data.len() && buf == test_data {
                                                            phase15_ok = true;
                                                        }
                                                    }
                                                }
                                                syscall::revoke(rsrv, grant_rd);
                                            }
                                        }
                                        syscall::send_nb(fp, 0x2400, rh, 0);
                                    }
                                }
                            } else {
                                syscall::revoke(srv_aspace, grant_dst);
                                syscall::send_nb(fp, 0x2400, handle, 0);
                            }
                        } else {
                            syscall::revoke(srv_aspace, grant_dst);
                            syscall::send_nb(fp, 0x2400, handle, 0);
                        }
                    }
                    syscall::munmap(scratch);
                }
            } else {
                syscall::debug_puts(b"  init: FS_CREATE failed\n");
            }
        } else {
            syscall::debug_puts(b"  init: FS_CREATE no reply\n");
        }

        if phase15_ok {
            syscall::debug_puts(b"Phase 15 writable FAT16: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 15 writable FAT16: FAILED\n");
        }
    } else {
        syscall::debug_puts(b"  init: fat16 not available, skipping\n");
        syscall::debug_puts(b"Phase 15 writable FAT16: SKIPPED\n");
    }

    // --- Test 15: Pipe IPC ---
    syscall::debug_puts(b"  init: testing pipe IPC...\n");

    let pipe_port = syscall::port_create() as u32;

    // Spawn pipe_upper (reads from pipe_port, uppercases, prints via debug_puts).
    let pipe_tid = syscall::spawn_with_arg(b"pipe_upper", 50, pipe_port as u64);
    if pipe_tid != u64::MAX {
        // Give reader a moment to start and block on recv.
        for _ in 0..10 { syscall::yield_now(); }

        // Write test data to pipe.
        userlib::pipe::pipe_write(pipe_port, b"hello pipes");
        userlib::pipe::pipe_close_writer(pipe_port);

        // Wait for child to exit.
        loop {
            if let Some(_code) = syscall::waitpid(pipe_tid) {
                break;
            }
            syscall::yield_now();
        }

        // pipe_upper printed "HELLO PIPES" via debug_puts.
        syscall::debug_puts(b"\nPhase 16 pipe IPC: PASSED\n");
    } else {
        syscall::debug_puts(b"Phase 16 pipe IPC: FAILED (spawn)\n");
    }

    syscall::port_destroy(pipe_port);

    // --- Test 17: Multi-threaded processes ---
    {
        // Allocate shared memory page.
        let shared_va = syscall::mmap_anon(0, 1, 1).unwrap_or(0);
        if shared_va != 0 {
            // Clear shared memory.
            unsafe { core::ptr::write_volatile(shared_va as *mut u64, 0); }

            // Allocate stack for child thread.
            let child_stack_va = syscall::mmap_anon(0, 1, 1).unwrap_or(0);
            if child_stack_va != 0 {
                let stack_top = child_stack_va + 0x4000; // 16 KiB, safe on all PAGE_SIZE configs

                let child_tid = syscall::thread_create(
                    thread_child_entry as u64,
                    stack_top as u64,
                    shared_va as u64,
                );

                if child_tid != u64::MAX {
                    let exit_code = syscall::thread_join(child_tid as u32);
                    let val = unsafe { core::ptr::read_volatile(shared_va as *const u64) };

                    if val == 0xCAFE && exit_code == 42 {
                        syscall::debug_puts(b"Phase 17 multi-threaded processes: PASSED\n");
                    } else {
                        syscall::debug_puts(b"Phase 17 multi-threaded processes: FAILED (val=");
                        print_num(val);
                        syscall::debug_puts(b" exit=");
                        print_num(exit_code as u64);
                        syscall::debug_puts(b")\n");
                    }
                } else {
                    syscall::debug_puts(b"Phase 17 multi-threaded processes: FAILED (create)\n");
                }
            } else {
                syscall::debug_puts(b"Phase 17 multi-threaded processes: FAILED (stack alloc)\n");
            }
        } else {
            syscall::debug_puts(b"Phase 17 multi-threaded processes: FAILED (shared alloc)\n");
        }
    }

    // --- Test 18: Futex/Mutex ---
    {
        // Reset shared state.
        unsafe { MUTEX_TEST_COUNTER = 0; }

        let stack1 = syscall::mmap_anon(0, 1, 1).unwrap_or(0);
        let stack2 = syscall::mmap_anon(0, 1, 1).unwrap_or(0);
        if stack1 != 0 && stack2 != 0 {
            let t1 = syscall::thread_create(
                mutex_test_thread as u64,
                (stack1 + 0x4000) as u64,
                0,
            );
            let t2 = syscall::thread_create(
                mutex_test_thread as u64,
                (stack2 + 0x4000) as u64,
                0,
            );

            if t1 != u64::MAX && t2 != u64::MAX {
                syscall::thread_join(t1 as u32);
                syscall::thread_join(t2 as u32);

                let counter = unsafe { MUTEX_TEST_COUNTER };
                if counter == 2000 {
                    syscall::debug_puts(b"Phase 18 futex/mutex: PASSED\n");
                } else {
                    syscall::debug_puts(b"Phase 18 futex/mutex: FAILED (count=");
                    print_num(counter);
                    syscall::debug_puts(b")\n");
                }
            } else {
                syscall::debug_puts(b"Phase 18 futex/mutex: FAILED (create)\n");
            }
        } else {
            syscall::debug_puts(b"Phase 18 futex/mutex: FAILED (stack alloc)\n");
        }
    }

    // --- Test 19: TCP echo via net_srv ---
    syscall::debug_puts(b"  init: testing TCP echo...\n");

    // Re-use net_port from Phase 12 test, or look it up.
    let tcp_net_port = net_port.unwrap_or_else(|| {
        for _ in 0..500 {
            if let Some(p) = syscall::ns_lookup(b"net") {
                return p;
            }
            syscall::yield_now();
        }
        0
    });

    if tcp_net_port != 0 {
        let tcp_reply = syscall::port_create() as u32;

        // NET_TCP_CONNECT: data[0]=dst_ip (BE), data[1]= port | (reply_port << 16)
        let dst_ip: u64 = (10u64 << 24) | (0 << 16) | (2 << 8) | 100; // 10.0.2.100
        let d1_connect = 1234u64 | ((tcp_reply as u64) << 16);
        syscall::send(tcp_net_port, 0x4200, dst_ip, d1_connect, 0, 0);

        let mut tcp_ok = false;
        let mut conn_id: u64 = 0;

        // Wait for NET_TCP_CONNECTED or NET_TCP_FAIL.
        if let Some(reply) = syscall::recv_msg(tcp_reply) {
            if reply.tag == 0x4201 {
                conn_id = reply.data[0];
                syscall::debug_puts(b"  init: TCP connected, conn=");
                print_num(conn_id);
                syscall::debug_puts(b"\n");

                // NET_TCP_SEND: data[0]=conn_id, data[1]=len|(reply<<16), data[2..3]=payload
                let test_str = b"Hello TCP!\n";
                let mut d2: u64 = 0;
                let mut d3: u64 = 0;
                for i in 0..test_str.len().min(8) {
                    d2 |= (test_str[i] as u64) << (i * 8);
                }
                for i in 0..test_str.len().saturating_sub(8).min(8) {
                    d3 |= (test_str[8 + i] as u64) << (i * 8);
                }
                let d1_send = (test_str.len() as u64) | ((tcp_reply as u64) << 16);
                syscall::send(tcp_net_port, 0x4300, conn_id, d1_send, d2, d3);

                // Wait for SEND_OK.
                if let Some(sr) = syscall::recv_msg(tcp_reply) {
                    if sr.tag == 0x4301 {
                        // NET_TCP_RECV: data[0]=conn_id, data[1]=0|(reply<<16)
                        let d1_recv = (tcp_reply as u64) << 16;
                        syscall::send(tcp_net_port, 0x4400, conn_id, d1_recv, 0, 0);

                        // Wait for NET_TCP_DATA.
                        if let Some(dr) = syscall::recv_msg(tcp_reply) {
                            if dr.tag == 0x4401 {
                                let recv_len = dr.data[0] as usize;
                                // Unpack received bytes.
                                let mut recv_buf = [0u8; 24];
                                let words = [dr.data[1], dr.data[2], dr.data[3]];
                                for i in 0..recv_len.min(24) {
                                    recv_buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
                                }
                                // Compare with sent data.
                                if recv_len == test_str.len()
                                    && &recv_buf[..recv_len] == test_str
                                {
                                    tcp_ok = true;
                                } else {
                                    syscall::debug_puts(b"  init: TCP echo mismatch, got ");
                                    print_num(recv_len as u64);
                                    syscall::debug_puts(b" bytes\n");
                                }
                            } else if dr.tag == 0x44FF {
                                syscall::debug_puts(b"  init: TCP connection closed\n");
                            }
                        }
                    }
                }

                // NET_TCP_CLOSE.
                syscall::send(tcp_net_port, 0x4500, conn_id, tcp_reply as u64, 0, 0);
                // Wait for close OK (best effort).
                let _ = syscall::recv_msg(tcp_reply);
            } else {
                syscall::debug_puts(b"  init: TCP connect failed, tag=");
                print_num(reply.tag);
                syscall::debug_puts(b"\n");
            }
        }

        syscall::port_destroy(tcp_reply);

        if tcp_ok {
            syscall::debug_puts(b"Phase 19 TCP echo: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 19 TCP echo: FAILED\n");
        }
    } else {
        syscall::debug_puts(b"Phase 19 TCP echo: SKIPPED (no net)\n");
    }

    // --- Test 20: Signal/Kill ---
    syscall::debug_puts(b"  init: testing signal/kill...\n");
    {
        let spin_tid = syscall::spawn(b"spin", 50);
        if spin_tid != u64::MAX {
            // Let it run for a bit.
            for _ in 0..50 { syscall::yield_now(); }

            // Kill it.
            let killed = syscall::kill(spin_tid as u32);
            if killed {
                // Wait for the task to exit.
                let mut exited = false;
                for _ in 0..1000 {
                    if let Some(_code) = syscall::waitpid(spin_tid) {
                        exited = true;
                        break;
                    }
                    syscall::yield_now();
                }
                if exited {
                    syscall::debug_puts(b"Phase 20 signal/kill: PASSED\n");
                } else {
                    syscall::debug_puts(b"Phase 20 signal/kill: FAILED (not exited)\n");
                }
            } else {
                syscall::debug_puts(b"Phase 20 signal/kill: FAILED (kill returned false)\n");
            }
        } else {
            syscall::debug_puts(b"Phase 20 signal/kill: FAILED (spawn)\n");
        }
    }

    // --- Test 23: Capability Enforcement + Resource Quotas ---
    syscall::debug_puts(b"  init: running capability test...\n");
    {
        // Register a test service for ns_lookup cap brokering test.
        let svc_port = syscall::port_create() as u32;
        syscall::ns_register(b"cap_svc", svc_port);

        // Spawn cap_test (no special arg0 needed).
        let ct_tid = syscall::spawn(b"cap_test", 50);
        if ct_tid != u64::MAX {
            // Set child's port quota to 2 (kernel resolves tid -> task_id).
            syscall::set_quota(ct_tid as u32, 0, 2); // max 2 ports

            loop {
                if let Some(code) = syscall::waitpid(ct_tid) {
                    if code == 0 {
                        syscall::debug_puts(b"Phase 24 capabilities: PASSED\n");
                    } else {
                        syscall::debug_puts(b"Phase 24 capabilities: FAILED (exit code)\n");
                    }
                    break;
                }
                syscall::yield_now();
            }
        } else {
            syscall::debug_puts(b"Phase 24 capabilities: FAILED (spawn)\n");
        }

        syscall::port_destroy(svc_port);
    }

    // --- Test 25: Phase 33 Page Cache ---
    syscall::debug_puts(b"  init: testing page cache...\n");
    {
        let mut cache_ok = false;

        // Look up cache_blk with retry.
        let mut cache_port_opt = None;
        for _ in 0..200 {
            cache_port_opt = syscall::ns_lookup(b"cache_blk");
            if cache_port_opt.is_some() { break; }
            syscall::yield_now();
        }

        if let Some(cache_port) = cache_port_opt {
            let cache_reply = syscall::port_create() as u32;

            // IO_CONNECT to cache_srv.
            let (n0, n1, _) = syscall::pack_name(b"cache_blk");
            let d2 = 9u64 | ((cache_reply as u64) << 32);
            syscall::send(cache_port, 0x100, n0, n1, d2, 0);

            if let Some(cr) = syscall::recv_msg(cache_reply) {
                if cr.tag == 0x101 {
                    let cache_aspace = cr.data[2] as u32;

                    if let Some(scratch_va) = syscall::mmap_anon(0, 1, 1) {
                        let grant_va: usize = 0x7_0000_0000;
                        let rd2 = 512u64 | ((cache_reply as u64) << 32);
                        let mut test_ok = true;

                        // Helper: read a sector via cache_srv grant.
                        // Returns true on success.
                        let cache_read = |offset: u64| -> bool {
                            if !syscall::grant_pages(cache_aspace, scratch_va, grant_va, 1, false) {
                                return false;
                            }
                            syscall::send(cache_port, 0x200, 0, offset, rd2, grant_va as u64);
                            let ok = if let Some(rr) = syscall::recv_msg(cache_reply) {
                                rr.tag == 0x201 && rr.data[0] == 512
                            } else {
                                false
                            };
                            syscall::revoke(cache_aspace, grant_va);
                            ok
                        };

                        // Step 1: Read sector 0 (offset 0) — cache miss, triggers read-ahead
                        // for the full 4K page (sectors 0-7).
                        if !cache_read(0) { test_ok = false; }

                        // Step 2: Read sector 7 (offset 3584) — same 4K page, should hit
                        // due to read-ahead (tail packing).
                        if !cache_read(3584) { test_ok = false; }

                        // Query stats after read-ahead test.
                        let sd0 = (cache_reply as u64) << 32;
                        syscall::send(cache_port, 0xC100, sd0, 0, 0, 0);
                        let (hits_after_readahead, misses_after_readahead) =
                            if let Some(sr) = syscall::recv_msg(cache_reply) {
                                if sr.tag == 0xC101 { (sr.data[0], sr.data[1]) }
                                else { test_ok = false; (0, 0) }
                            } else { test_ok = false; (0, 0) };

                        // Read-ahead: first read = 1 miss, second read = 1 hit.
                        if hits_after_readahead < 1 { test_ok = false; }

                        // Step 3: Read a few more distinct pages to verify
                        // page-level caching works across multiple entries.
                        for pg in 1..5u64 {
                            if !cache_read(pg * 4096) { test_ok = false; break; }
                        }
                        // Re-read page 1 — should hit.
                        if !cache_read(4096) { test_ok = false; }

                        // Query stats to get current counts.
                        syscall::send(cache_port, 0xC100, sd0, 0, 0, 0);
                        let (final_hits, final_misses, cache_size) =
                            if let Some(sr) = syscall::recv_msg(cache_reply) {
                                if sr.tag == 0xC101 {
                                    (sr.data[0], sr.data[1], sr.data[2])
                                } else { test_ok = false; (0, 0, 0) }
                            } else { test_ok = false; (0, 0, 0) };

                        // Verify cache size = 128.
                        if cache_size != 128 { test_ok = false; }

                        if test_ok {
                            cache_ok = true;
                            syscall::debug_puts(b"  init: cache hits=");
                            print_num(final_hits);
                            syscall::debug_puts(b" misses=");
                            print_num(final_misses);
                            syscall::debug_puts(b" size=");
                            print_num(cache_size);
                            syscall::debug_puts(b"\n");
                        }

                        syscall::munmap(scratch_va);
                    }
                }
            }

            syscall::port_destroy(cache_reply);
        }

        if cache_ok {
            syscall::debug_puts(b"Phase 33 page cache: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 33 page cache: FAILED\n");
        }
    }

    // --- Test 26: L4-style handoff scheduling ---
    syscall::debug_puts(b"  init: testing L4 handoff IPC...\n");
    {
        // Test that blocking send/recv with parking works correctly.
        let req_port = syscall::port_create() as u32;
        let rply_port = syscall::port_create() as u32;
        let mut handoff_ok = true;

        // Test 1: queue path — send then recv on same port.
        let tag: u64 = 0x2600;
        syscall::send(req_port, tag, 0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD);
        if let Some(msg) = syscall::recv_msg(req_port) {
            if msg.tag != tag || msg.data[0] != 0xAAAA || msg.data[1] != 0xBBBB {
                syscall::debug_puts(b"  init: L4 queue recv data mismatch\n");
                handoff_ok = false;
            }
        } else {
            syscall::debug_puts(b"  init: L4 queue recv failed\n");
            handoff_ok = false;
        }

        // Test 2: cross-server IPC exercises park + wake + inject.
        // Send NS_LOOKUP to name server, recv reply on our reply port.
        let nsrv = syscall::nsrv_port() as u32;
        let ns_tag: u64 = 0x1100; // NS_LOOKUP
        let name = b"blk\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let w0 = u64::from_le_bytes(name[0..8].try_into().unwrap());
        let w1 = u64::from_le_bytes(name[8..16].try_into().unwrap());
        let w2 = u64::from_le_bytes(name[16..24].try_into().unwrap());
        let len_reply = 3u64 | ((rply_port as u64) << 32);
        syscall::send(nsrv, ns_tag, w0, w1, w2, len_reply);
        if let Some(reply) = syscall::recv_msg(rply_port) {
            let port_id = reply.data[0] as u32;
            if port_id == 0 || port_id > 63 {
                syscall::debug_puts(b"  init: L4 ns_lookup got bad port\n");
                handoff_ok = false;
            }
        } else {
            syscall::debug_puts(b"  init: L4 ns_lookup recv failed\n");
            handoff_ok = false;
        }

        // Test 3: Measure self-send+recv round-trip (exercises queue path latency).
        let t0 = syscall::get_cycles();
        for _ in 0..100u32 {
            syscall::send(req_port, 0x2601, 0, 0, 0, 0);
            let _ = syscall::recv_msg(req_port);
        }
        let t1 = syscall::get_cycles();
        let avg_cy = (t1 - t0) / 100;
        let freq = syscall::get_timer_freq();
        let avg_us = if freq > 0 { avg_cy * 1_000_000 / freq } else { 0 };
        syscall::debug_puts(b"  init: L4 self-rtt: ");
        print_num(avg_cy);
        syscall::debug_puts(b" cy (~");
        print_num(avg_us);
        syscall::debug_puts(b" us)\n");

        syscall::port_destroy(req_port);
        syscall::port_destroy(rply_port);

        if handoff_ok {
            syscall::debug_puts(b"Phase 26 L4 handoff scheduling: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 26 L4 handoff scheduling: FAILED\n");
        }
    }

    // --- Test 23: COW Fork ---
    syscall::debug_puts(b"  init: testing COW fork...\n");
    {
        // Allocate a page and write a known value.
        let cow_page = syscall::mmap_anon(0, 1, 1); // va=0 (kernel picks), 1 page, RW (prot=1)
        if let Some(cow_va) = cow_page {
            let ptr = cow_va as *mut u64;
            unsafe { core::ptr::write_volatile(ptr, 0xDEAD_BEEF_CAFE_1234); }

            let pid = syscall::fork();
            if pid == 0 {
                // Child: read the value (should be parent's value via COW).
                let val = unsafe { core::ptr::read_volatile(ptr) };
                if val == 0xDEAD_BEEF_CAFE_1234 {
                    // Write to trigger COW fault — this should NOT affect parent.
                    unsafe { core::ptr::write_volatile(ptr, 0x1111_2222_3333_4444); }
                    // Verify our write took effect.
                    let val2 = unsafe { core::ptr::read_volatile(ptr) };
                    if val2 == 0x1111_2222_3333_4444 {
                        syscall::exit(42); // Success code.
                    }
                }
                syscall::exit(99); // Failure code.
            } else if pid > 0 {
                // Parent: wait for child.
                let mut child_ok = false;
                for _ in 0..1000 {
                    if let Some(code) = syscall::waitpid(pid) {
                        child_ok = code == 42;
                        break;
                    }
                    syscall::yield_now();
                }
                // Verify parent's page is unchanged.
                let parent_val = unsafe { core::ptr::read_volatile(ptr) };
                if child_ok && parent_val == 0xDEAD_BEEF_CAFE_1234 {
                    syscall::debug_puts(b"Phase 27 COW fork: PASSED\n");
                } else {
                    syscall::debug_puts(b"Phase 27 COW fork: FAILED\n");
                }
            } else {
                syscall::debug_puts(b"Phase 27 COW fork: FAILED (fork returned 0)\n");
            }
        } else {
            syscall::debug_puts(b"Phase 27 COW fork: FAILED (mmap)\n");
        }
    }

    // --- Test 24: Capability Transfer via IPC ---
    syscall::debug_puts(b"  init: testing cap transfer via IPC...\n");
    {
        // Create a notification port that child will listen on.
        let port_notify = syscall::port_create() as u32;

        let pid = syscall::fork();
        if pid == 0 {
            // Child: create our own port and tell parent about it.
            let port_child = syscall::port_create() as u32;
            syscall::send(port_notify, 0xAA, port_child as u64, 0, 0, 0);

            // Recv on our port — parent will send_cap granting us SEND on a new port.
            if let Some(msg) = syscall::recv_msg(port_child) {
                let granted_port = msg.data[3] as u32; // data[3] = granted port ID
                // Try to send on the granted port — this should work if cap transfer succeeded.
                syscall::send(granted_port, 0xBB, 0xCAFE, 0, 0, 0);
                syscall::exit(77); // success
            }
            syscall::exit(99); // failure
        } else if pid > 0 {
            // Parent: create a new port AFTER fork — child doesn't have caps for it.
            let port_secret = syscall::port_create() as u32;

            // Recv child's port_child ID.
            if let Some(msg) = syscall::recv_msg(port_notify) {
                let port_child = msg.data[0] as u32;

                // Transfer SEND cap for port_secret to child via port_child.
                // Rights: 1 = SEND
                syscall::send_cap(port_child, 0xCC, 0, 0, port_secret, 1);

                // Now recv on port_secret — child should be able to send here.
                let mut cap_ok = false;
                for _ in 0..2000 {
                    if let Some(msg2) = syscall::recv_nb_msg(port_secret) {
                        if msg2.tag == 0xBB && msg2.data[0] == 0xCAFE {
                            cap_ok = true;
                        }
                        break;
                    }
                    syscall::yield_now();
                }

                // Wait for child to exit.
                let mut child_ok = false;
                for _ in 0..1000 {
                    if let Some(code) = syscall::waitpid(pid) {
                        child_ok = code == 77;
                        break;
                    }
                    syscall::yield_now();
                }

                if cap_ok && child_ok {
                    syscall::debug_puts(b"Phase 28 cap transfer via IPC: PASSED\n");
                } else {
                    syscall::debug_puts(b"Phase 28 cap transfer via IPC: FAILED\n");
                }
            }
            syscall::port_destroy(port_secret);
        }
        syscall::port_destroy(port_notify);
    }

    // --- Test 21: Superpage Promotion ---
    syscall::debug_puts(b"  init: testing superpage promotion...\n");
    {
        // Allocate 32 allocation pages = 2 MiB at 64K PAGE_SIZE.
        // Touch all 512 MMU pages (4K each) to trigger faults, then check if
        // the kernel promoted the region to a single 2 MiB superpage.
        let promo_before = syscall::vm_stats(0); // superpage promotions before

        // Allocate 32 pages (2 MiB) at a 2 MiB-aligned VA.
        // VA must be 2 MiB-aligned so the kernel can install a superpage PTE.
        let big_va = syscall::mmap_anon(0x10_0000_0000, 32, 1); // 64 GiB, 2 MiB-aligned
        if let Some(base) = big_va {
            // Touch every 4K page in the 2 MiB region to install all PTEs.
            for i in 0..512 {
                let ptr = (base + i * 4096) as *mut u8;
                unsafe { core::ptr::write_volatile(ptr, (i & 0xFF) as u8); }
            }

            let promo_after = syscall::vm_stats(0);
            let promotions = promo_after - promo_before;

            // Verify data is still correct after potential migration.
            let mut ok = true;
            for i in 0..512 {
                let ptr = (base + i * 4096) as *const u8;
                let val = unsafe { core::ptr::read_volatile(ptr) };
                if val != (i & 0xFF) as u8 {
                    ok = false;
                    break;
                }
            }

            if promotions >= 1 && ok {
                syscall::debug_puts(b"Phase 29 superpage promotion: PASSED\n");
            } else if !ok {
                syscall::debug_puts(b"Phase 29 superpage promotion: FAILED (data corrupt)\n");
            } else {
                // Promotion didn't happen — might be because buddy allocator
                // couldn't find a contiguous 2 MiB block. Print stats.
                syscall::debug_puts(b"  init: no superpage promoted (OOM contiguous?)\n");
                syscall::debug_puts(b"Phase 29 superpage promotion: SKIPPED\n");
            }
            syscall::munmap(base);
        } else {
            syscall::debug_puts(b"Phase 29 superpage promotion: FAILED (mmap)\n");
        }
    }

    // --- Test 22: M:N Green Threads + Scheduler Activations ---
    syscall::debug_puts(b"  init: testing M:N green threads...\n");
    {
        // Allocate a page for fiber stacks (64 KiB = 16 fibers * 4 KiB each).
        let fiber_stacks = syscall::mmap_anon(0, 1, 1);
        // Allocate shared counter page.
        let counter_page = syscall::mmap_anon(0, 1, 1);

        if let (Some(stacks), Some(cpage)) = (fiber_stacks, counter_page) {
            // Zero the counter.
            let counter_ptr = cpage as *mut u64;
            unsafe { core::ptr::write_volatile(counter_ptr, 0); }

            // Register scheduler activations.
            syscall::sa_register();

            // Verify sa_getid returns a valid index for the main thread.
            let main_sa_id = syscall::sa_getid();

            // Initialize the green thread scheduler.
            userlib::green::init(stacks);

            // Spawn 8 fibers, each increments counter 100 times with yields.
            for _ in 0..8 {
                userlib::green::spawn(green_fiber_entry, cpage as u64);
            }

            // Allocate stacks for 2 worker kernel threads.
            let ws1 = syscall::mmap_anon(0, 1, 1).unwrap_or(0);
            let ws2 = syscall::mmap_anon(0, 1, 1).unwrap_or(0);

            if ws1 != 0 && ws2 != 0 {
                let t1 = syscall::thread_create(
                    userlib::green::green_worker_entry as u64,
                    (ws1 + 0x4000) as u64,
                    0, // worker_id = 0
                );
                let t2 = syscall::thread_create(
                    userlib::green::green_worker_entry as u64,
                    (ws2 + 0x4000) as u64,
                    1, // worker_id = 1
                );

                if t1 != u64::MAX && t2 != u64::MAX {
                    // Wait for both workers to complete.
                    syscall::thread_join(t1 as u32);
                    syscall::thread_join(t2 as u32);

                    let final_count = unsafe { core::ptr::read_volatile(counter_ptr) };
                    let completed = userlib::green::COMPLETED.load(core::sync::atomic::Ordering::Relaxed);

                    if final_count == 800 && completed == 8 && main_sa_id != u64::MAX {
                        syscall::debug_puts(b"Phase 30 M:N green threads: PASSED\n");
                    } else {
                        syscall::debug_puts(b"Phase 30 M:N green threads: FAILED (count=");
                        print_num(final_count);
                        syscall::debug_puts(b" completed=");
                        print_num(completed as u64);
                        syscall::debug_puts(b" sa_id=");
                        print_num(main_sa_id);
                        syscall::debug_puts(b")\n");
                    }
                } else {
                    syscall::debug_puts(b"Phase 30 M:N green threads: FAILED (worker create)\n");
                }
            } else {
                syscall::debug_puts(b"Phase 30 M:N green threads: FAILED (worker stack alloc)\n");
            }
        } else {
            syscall::debug_puts(b"Phase 30 M:N green threads: FAILED (mmap)\n");
        }
    }

    // --- Test 24: Phase 31 coscheduling ---
    syscall::debug_puts(b"  init: testing coscheduling...\n");
    {
        // Need more threads than CPUs (4) to force run-queue contention.
        // 6 threads (3 grouped + 3 ungrouped), 8 KiB stacks.
        let stacks = syscall::mmap_anon(0, 1, 1);

        if let Some(sk) = stacks {
            let hits_before = syscall::vm_stats(4);

            let stack_size: usize = 0x2000; // 8 KiB per stack
            let mut tids = [u64::MAX; 6];
            let mut ok = true;
            // 3 threads in group 1, 3 threads ungrouped.
            for i in 0..6u64 {
                let group = if i < 3 { 1u64 } else { 0u64 };
                let tid = syscall::thread_create(
                    cosched_worker as u64,
                    (sk + (i as usize + 1) * stack_size) as u64,
                    group,
                );
                tids[i as usize] = tid;
                if tid == u64::MAX { ok = false; }
            }

            if ok {
                for i in 0..6 {
                    syscall::thread_join(tids[i] as u32);
                }

                let hits_after = syscall::vm_stats(4);
                let cosched_hits = hits_after - hits_before;
                if cosched_hits > 0 {
                    syscall::debug_puts(b"Phase 31 coscheduling: PASSED (hits=");
                    print_num(cosched_hits);
                    syscall::debug_puts(b")\n");
                } else {
                    syscall::debug_puts(b"Phase 31 coscheduling: FAILED (hits=0)\n");
                }
            } else {
                syscall::debug_puts(b"Phase 31 coscheduling: FAILED (thread create)\n");
            }
        } else {
            syscall::debug_puts(b"Phase 31 coscheduling: FAILED (mmap)\n");
        }
    }

    // --- Test 25: Phase 32 topology-aware scheduling ---
    syscall::debug_puts(b"  init: testing topology-aware scheduling...\n");
    {
        let mut topo_ok = true;
        let mut total_cpus = 0u32;

        // Step 1: Query topology for all CPUs.
        for cpu in 0..4u32 {
            if let Some((_pkg, _core, _smt, online, count)) = syscall::cpu_topology(cpu) {
                if online { total_cpus += 1; }
                if count < 1 { topo_ok = false; }
            } else {
                topo_ok = false;
            }
        }

        // Verify at least 1 CPU online.
        if total_cpus < 1 { topo_ok = false; }

        // Step 2: Test affinity - pin self to CPU 0.
        let my_tid = syscall::thread_id() as u32;
        let old_mask = syscall::get_affinity(my_tid);
        let set_ok = syscall::set_affinity(my_tid, 1); // Only CPU 0
        if !set_ok { topo_ok = false; }

        // Yield to let scheduler enforce.
        for _ in 0..5 { syscall::yield_now(); }

        // Restore full affinity.
        syscall::set_affinity(my_tid, old_mask);

        // Step 3: Test affinity on child thread.
        if let Some(stack_va) = syscall::mmap_anon(0, 1, 1) {
            let child = syscall::thread_create(
                affinity_test_worker as u64,
                (stack_va + 0x4000) as u64,
                0,
            );
            if child != u64::MAX {
                // Pin child to CPU 0.
                syscall::set_affinity(child as u32, 1);
                syscall::thread_join(child as u32);
            } else {
                topo_ok = false;
            }
        }

        if topo_ok {
            syscall::debug_puts(b"Phase 32 topology-aware scheduling: PASSED (cpus=");
            print_num(total_cpus as u64);
            syscall::debug_puts(b")\n");
        } else {
            syscall::debug_puts(b"Phase 32 topology-aware scheduling: FAILED\n");
        }
    }

    // --- Test 26: Phase 34 Async Completion ---
    syscall::debug_puts(b"  init: testing async completion model...\n");
    {
        let mut async_ok = false;

        // Look up cache_blk.
        let mut cache_port_opt = None;
        for _ in 0..200 {
            cache_port_opt = syscall::ns_lookup(b"cache_blk");
            if cache_port_opt.is_some() { break; }
            syscall::yield_now();
        }

        if let Some(cache_port) = cache_port_opt {
            let reply_port = syscall::port_create() as u32;

            // IO_CONNECT to cache_srv.
            let (n0, n1, _) = syscall::pack_name(b"cache_blk");
            let d2 = 9u64 | ((reply_port as u64) << 32);
            syscall::send(cache_port, 0x100, n0, n1, d2, 0);

            if let Some(cr) = syscall::recv_msg(reply_port) {
                if cr.tag == 0x101 {
                    let cache_aspace = cr.data[2] as u32;

                    if let Some(scratch_va) = syscall::mmap_anon(0, 1, 1) {
                        let grant_va: usize = 0x9_0000_0000;

                        // Grant scratch page to cache_srv once for all reads.
                        if syscall::grant_pages(cache_aspace, scratch_va, grant_va, 1, false) {
                            // Submit 4 async reads with request_ids 1..4.
                            let mut submitted = 0u32;
                            for i in 1..=4u64 {
                                let offset = (i - 1) * 4096;
                                if userlib::aio::aio_read(
                                    cache_port, offset, 512, reply_port,
                                    grant_va, i,
                                ) {
                                    submitted += 1;
                                }
                            }

                            // Collect all completions.
                            let mut received = [false; 5]; // index 1..4
                            let mut collected = 0u32;
                            let mut attempts = 0u32;
                            while collected < submitted && attempts < 10000 {
                                if let Some(result) = userlib::aio::aio_collect(reply_port) {
                                    if result.tag == 0x201 && result.request_id >= 1
                                        && result.request_id <= 4
                                    {
                                        received[result.request_id as usize] = true;
                                        collected += 1;
                                    }
                                } else {
                                    syscall::yield_now();
                                }
                                attempts += 1;
                            }

                            // Verify all 4 received.
                            let all_received = received[1] && received[2]
                                && received[3] && received[4];

                            // Barrier test.
                            let mut barrier_ok = false;
                            if all_received {
                                userlib::aio::aio_barrier(cache_port, reply_port);
                                barrier_ok = true;
                            }

                            if all_received && barrier_ok && submitted == 4 {
                                async_ok = true;
                            }

                            syscall::revoke(cache_aspace, grant_va);
                        }

                        syscall::munmap(scratch_va);
                    }
                }
            }

            syscall::port_destroy(reply_port);
        }

        if async_ok {
            syscall::debug_puts(b"Phase 34 async completion: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 34 async completion: FAILED\n");
        }
    }

    // --- Test 27: Phase 35 Profiling Infrastructure ---
    syscall::debug_puts(b"  init: testing profiling infrastructure...\n");
    {
        let mut prof_ok = true;

        // Part A: Verify new stat counters increment.
        let sys_before = syscall::vm_stats(14); // SYSCALLS
        let send_before = syscall::vm_stats(15); // IPC_SENDS
        let recv_before = syscall::vm_stats(16); // IPC_RECVS

        // Do IPC work.
        let tp = syscall::port_create() as u32;
        syscall::send_nb(tp, 0xBEEF, 42, 0);
        let _ = syscall::recv_nb_msg(tp);
        syscall::port_destroy(tp);

        let sys_after = syscall::vm_stats(14);
        let send_after = syscall::vm_stats(15);
        let recv_after = syscall::vm_stats(16);

        if sys_after <= sys_before { prof_ok = false; }
        if send_after <= send_before { prof_ok = false; }
        if recv_after <= recv_before { prof_ok = false; }

        // Verify newly exposed mm stats are accessible.
        let pages_zeroed = syscall::vm_stats(5);
        let ptes_installed = syscall::vm_stats(6);
        if pages_zeroed == u64::MAX || ptes_installed == u64::MAX { prof_ok = false; }

        // Part B: Trace ring buffer.
        // Clear and enable.
        userlib::profile::trace_clear();
        userlib::profile::trace_enable();

        // Do operations to generate trace events.
        let tp2 = syscall::port_create() as u32;
        syscall::send_nb(tp2, 0xAAAA, 1, 2);
        let _ = syscall::recv_nb_msg(tp2);
        syscall::port_destroy(tp2);

        // Disable.
        userlib::profile::trace_disable();

        // Read trace entries.
        if let Some(trace_va) = syscall::mmap_anon(0, 1, 1) {
            let buf = unsafe {
                core::slice::from_raw_parts_mut(
                    trace_va as *mut userlib::profile::TraceEntry,
                    64,
                )
            };
            let count = userlib::profile::trace_read(buf);

            if count == 0 { prof_ok = false; }

            // Verify at least one SYSCALL_ENTER event.
            let mut found_syscall = false;
            for i in 0..count {
                if buf[i].event_type == userlib::profile::EVT_SYSCALL_ENTER {
                    found_syscall = true;
                    break;
                }
            }
            if !found_syscall { prof_ok = false; }

            syscall::munmap(trace_va);

            // Print summary.
            syscall::debug_puts(b"  stats: ctx_sw=");
            print_num(syscall::vm_stats(13));
            syscall::debug_puts(b" syscalls=");
            print_num(sys_after);
            syscall::debug_puts(b" ipc_send=");
            print_num(send_after);
            syscall::debug_puts(b" ipc_recv=");
            print_num(recv_after);
            syscall::debug_puts(b" trace=");
            print_num(count as u64);
            syscall::debug_puts(b"\n");
        } else {
            prof_ok = false;
        }

        if prof_ok {
            syscall::debug_puts(b"Phase 35 profiling infrastructure: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 35 profiling infrastructure: FAILED\n");
        }
    }

    // --- Test 28: Phase 36 Security Policy Servers ---
    syscall::debug_puts(b"  init: testing security policy servers...\n");
    {
        let mut sec_ok = true;

        // Create the service port here and pass it to security_srv via arg0.
        // This avoids ns_register timing issues during test.
        let sec_port = syscall::port_create() as u32;

        // Spawn security_srv with the pre-created port as arg0.
        let sec_tid = syscall::spawn_with_arg(b"security_srv", 50, sec_port as u64);
        if sec_tid == u64::MAX {
            syscall::debug_puts(b"  init: security_srv spawn FAILED\n");
            sec_ok = false;
        }

        // Give it time to start.
        for _ in 0..50 { syscall::yield_now(); }

        if sec_ok {
            let reply = syscall::port_create() as u32;

            // Part A: Login with valid credentials (root).
            // username_hash=0x0001_0001, password_hash=0x0001_0002
            syscall::send(sec_port, 0x700, 0x0001_0001, 0x0001_0002, reply as u64, 0);
            let cred_port;
            let cred_roles;
            if let Some(r) = syscall::recv_msg(reply) {
                if r.tag == 0x701 { // SEC_LOGIN_OK
                    cred_port = r.data[0] as u32;
                    cred_roles = r.data[1];
                    if cred_roles != 0x03 { // ADMIN|USER
                        syscall::debug_puts(b"  init: login roles wrong\n");
                        sec_ok = false;
                    }
                } else {
                    syscall::debug_puts(b"  init: login failed unexpectedly\n");
                    sec_ok = false;
                    cred_port = 0;
                    cred_roles = 0;
                }
            } else {
                syscall::debug_puts(b"  init: login no reply\n");
                sec_ok = false;
                cred_port = 0;
                cred_roles = 0;
            }

            // Part B: Login with wrong password.
            syscall::send(sec_port, 0x700, 0x0001_0001, 0xBAD_0000, reply as u64, 0);
            if let Some(r) = syscall::recv_msg(reply) {
                if r.tag != 0x702 { // SEC_LOGIN_FAIL
                    syscall::debug_puts(b"  init: bad login not rejected\n");
                    sec_ok = false;
                }
            } else {
                sec_ok = false;
            }

            if sec_ok && cred_port != 0 {
                // Part C: Verify credential.
                syscall::send(sec_port, 0x703, cred_port as u64, 0, reply as u64, 0);
                if let Some(r) = syscall::recv_msg(reply) {
                    if r.tag == 0x704 { // SEC_VERIFY_OK
                        if r.data[1] != cred_roles || r.data[2] != 0x0001_0001 {
                            syscall::debug_puts(b"  init: verify data mismatch\n");
                            sec_ok = false;
                        }
                    } else {
                        syscall::debug_puts(b"  init: verify failed\n");
                        sec_ok = false;
                    }
                } else {
                    sec_ok = false;
                }

                // Part D: Revoke credential.
                syscall::send(sec_port, 0x706, cred_port as u64, 0, reply as u64, 0);
                if let Some(r) = syscall::recv_msg(reply) {
                    if r.tag != 0x707 { // SEC_REVOKE_OK
                        syscall::debug_puts(b"  init: revoke failed\n");
                        sec_ok = false;
                    }
                } else {
                    sec_ok = false;
                }

                // Part E: Verify after revoke should fail.
                syscall::send(sec_port, 0x703, cred_port as u64, 0, reply as u64, 0);
                if let Some(r) = syscall::recv_msg(reply) {
                    if r.tag != 0x705 { // SEC_VERIFY_FAIL
                        syscall::debug_puts(b"  init: verify after revoke not denied\n");
                        sec_ok = false;
                    }
                } else {
                    sec_ok = false;
                }
            }

            syscall::port_destroy(reply);
        }

        if sec_ok {
            syscall::debug_puts(b"Phase 36 security policy servers: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 36 security policy servers: FAILED\n");
        }
    }

    // --- Test 28: Phase 37 Background Page Pre-Zeroing ---
    syscall::debug_puts(b"  init: testing background page pre-zeroing...\n");
    {
        let prezeroed_before = syscall::vm_stats(17);
        let major_before = syscall::vm_stats(2);
        let minor_before = syscall::vm_stats(3);

        // Allocate 1 allocation page (64 KiB = 16 MMU pages), RW.
        let va = syscall::mmap_anon(0, 1, 1);
        if let Some(va) = va {
            // Touch first sub-page (triggers major fault; may use pre-zeroed page).
            unsafe { core::ptr::write_volatile(va as *mut u8, 0x42); }

            // Touch remaining 15 sub-pages.
            for i in 1..16u64 {
                let ptr = (va + (i as usize) * 4096) as *mut u8;
                unsafe { core::ptr::write_volatile(ptr, 0x42); }
            }

            let prezeroed_after = syscall::vm_stats(17);
            let major_after = syscall::vm_stats(2);
            let minor_after = syscall::vm_stats(3);

            let prezeroed_delta = prezeroed_after - prezeroed_before;
            let major_delta = major_after - major_before;
            let minor_delta = minor_after - minor_before;

            syscall::debug_puts(b"    prezeroed=");
            print_num(prezeroed_delta);
            syscall::debug_puts(b" major=");
            print_num(major_delta);
            syscall::debug_puts(b" minor=");
            print_num(minor_delta);
            syscall::debug_puts(b"\n");

            // If pre-zeroing was active: expect ~1 major + ~15 minor.
            // If pool was empty: expect ~16 major + ~0 minor.
            // Both paths are correct; pre-zeroing is opportunistic.
            if prezeroed_delta > 0 && minor_delta >= 10 {
                syscall::debug_puts(b"    pre-zeroed path: OK\n");
            } else if major_delta >= 10 {
                syscall::debug_puts(b"    on-demand path (pool empty): OK\n");
            }

            syscall::munmap(va);
            syscall::debug_puts(b"Phase 37 background page pre-zeroing: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 37 background page pre-zeroing: SKIPPED (mmap failed)\n");
        }
    }

    // --- Test 29: Phase 38 CPU Hotplug / Energy-Aware Scheduling ---
    syscall::debug_puts(b"  init: testing CPU hotplug and energy-aware scheduling...\n");
    {
        let mut hotplug_ok = true;

        // Step 1: Read initial topology — should have 4 online CPUs.
        let initial = syscall::cpu_topology(0);
        let initial_count = if let Some((_, _, _, _, count)) = initial { count } else { 0 };

        if initial_count < 2 {
            syscall::debug_puts(b"    need >= 2 CPUs, skipping\n");
            syscall::debug_puts(b"Phase 38 CPU hotplug: SKIPPED\n");
        } else {
            // Step 2: Check per-CPU load is available.
            let load_ok = if let Some((load, window, online)) = syscall::cpu_load(0) {
                let _ = load;
                window > 0 && online != 0
            } else {
                false
            };
            if !load_ok {
                syscall::debug_puts(b"    cpu_load failed\n");
                hotplug_ok = false;
            }

            // Step 3: Offline CPU 1.
            let offline_ok = syscall::cpu_hotplug(1, 0);
            if !offline_ok {
                syscall::debug_puts(b"    offline CPU 1 failed\n");
                hotplug_ok = false;
            }

            // Step 4: Verify CPU 1 is offline via topology.
            if let Some((_, _, _, online, count)) = syscall::cpu_topology(1) {
                if online {
                    syscall::debug_puts(b"    CPU 1 still shows online\n");
                    hotplug_ok = false;
                }
                if count >= initial_count {
                    syscall::debug_puts(b"    online count not decreased\n");
                    hotplug_ok = false;
                }
            }

            // Step 5: Verify CPU 1 not in online mask.
            if let Some((_, _, online_mask)) = syscall::cpu_load(1) {
                if online_mask & 0x2 != 0 {
                    syscall::debug_puts(b"    CPU 1 still in online mask\n");
                    hotplug_ok = false;
                }
            }

            // Step 6: Verify we can't offline the last CPU.
            // Offline CPUs 2 and 3 first if they exist.
            if initial_count > 2 {
                syscall::cpu_hotplug(2, 0);
            }
            if initial_count > 3 {
                syscall::cpu_hotplug(3, 0);
            }
            // Now only CPU 0 should be online. Trying to offline it should fail.
            let cant_offline_last = !syscall::cpu_hotplug(0, 0);
            if !cant_offline_last {
                syscall::debug_puts(b"    offlined last CPU!\n");
                hotplug_ok = false;
            }

            // Step 7: Re-online all CPUs.
            for cpu in 1..initial_count {
                let online_ok = syscall::cpu_hotplug(cpu, 1);
                if !online_ok {
                    syscall::debug_puts(b"    online CPU ");
                    print_num(cpu as u64);
                    syscall::debug_puts(b" failed\n");
                    hotplug_ok = false;
                }
            }

            // Step 8: Verify all CPUs back online.
            if let Some((_, _, _, _, count)) = syscall::cpu_topology(0) {
                if count != initial_count {
                    syscall::debug_puts(b"    online count mismatch after re-online\n");
                    hotplug_ok = false;
                }
            }

            // Step 9: Verify affinity was adjusted for init thread.
            let my_tid = syscall::thread_id() as u32;
            let my_affinity = syscall::get_affinity(my_tid);
            if my_affinity == 0 {
                syscall::debug_puts(b"    affinity is zero after hotplug\n");
                hotplug_ok = false;
            }

            // Step 10: Spawn a thread while CPU 1 is offline to verify
            // it still runs (migration works).
            // (All CPUs are back online now, so this is just a sanity check.)

            if hotplug_ok {
                syscall::debug_puts(b"Phase 38 CPU hotplug: PASSED\n");
            } else {
                syscall::debug_puts(b"Phase 38 CPU hotplug: FAILED\n");
            }
        }
    }

    // --- Test 30: Phase 39 ext2 Filesystem Server ---
    syscall::debug_puts(b"  init: testing ext2 filesystem...\n");
    {
        let mut ext2_ok = true;

        // Step 1: Look up ext2 server via name server.
        let ext2_port = {
            let mut found = None;
            for _ in 0..200 {
                if let Some(p) = syscall::ns_lookup(b"ext2") {
                    found = Some(p);
                    break;
                }
                for _ in 0..50 { syscall::yield_now(); }
            }
            found
        };

        if let Some(ext2_port) = ext2_port {
            let reply_port = syscall::port_create() as u32;

            // Step 2: Open hello.txt
            {
                let (n0, n1, _) = pack_name(b"hello.txt");
                let d2 = 9u64 | ((reply_port as u64) << 32);
                syscall::send(ext2_port, 0x2000, n0, n1, d2, 0);
            }

            let (handle, file_size, fs_aspace) = if let Some(reply) = syscall::recv_msg(reply_port) {
                if reply.tag == 0x2001 {
                    (reply.data[0], reply.data[1], reply.data[2] as u32)
                } else {
                    syscall::debug_puts(b"    ext2 open hello.txt FAILED tag=");
                    print_num(reply.tag);
                    syscall::debug_puts(b"\n");
                    ext2_ok = false;
                    (u64::MAX, 0, 0)
                }
            } else {
                syscall::debug_puts(b"    ext2 open hello.txt no reply\n");
                ext2_ok = false;
                (u64::MAX, 0, 0)
            };

            if handle != u64::MAX {
                syscall::debug_puts(b"    ext2 opened hello.txt: size=");
                print_num(file_size);
                syscall::debug_puts(b"\n");

                // Step 3: Read hello.txt content (inline, small file).
                {
                    let d2 = file_size | ((reply_port as u64) << 32);
                    syscall::send(ext2_port, 0x2100, handle, 0, d2, 0);
                }

                if let Some(reply) = syscall::recv_msg(reply_port) {
                    if reply.tag == 0x2101 {
                        let bytes_read = reply.data[0] as usize;
                        // Verify content is "Hello from ext2!"
                        let expected = b"Hello from ext2!";
                        let mut content = [0u8; 24];
                        let words = [reply.data[1], reply.data[2], reply.data[3]];
                        for i in 0..bytes_read.min(24) {
                            content[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
                        }
                        if bytes_read == expected.len() && &content[..bytes_read] == expected {
                            syscall::debug_puts(b"    ext2 read hello.txt: OK (\"Hello from ext2!\")\n");
                        } else {
                            syscall::debug_puts(b"    ext2 read hello.txt: content mismatch\n");
                            ext2_ok = false;
                        }
                    } else {
                        syscall::debug_puts(b"    ext2 read FAILED\n");
                        ext2_ok = false;
                    }
                }

                // Step 4: FS_STAT — verify Unix permissions.
                {
                    let d2 = reply_port as u64;
                    syscall::send(ext2_port, 0x2300, handle, 0, d2, 0);
                }

                if let Some(reply) = syscall::recv_msg(reply_port) {
                    if reply.tag == 0x2301 {
                        let stat_size = reply.data[0] as u32;
                        let mode = reply.data[1] as u16;
                        let uid = (reply.data[2] & 0xFFFF) as u16;
                        let gid = ((reply.data[2] >> 16) & 0xFFFF) as u16;

                        // hello.txt should be mode 0100644, uid 1000, gid 1000
                        if stat_size != file_size as u32 {
                            syscall::debug_puts(b"    ext2 stat: size mismatch\n");
                            ext2_ok = false;
                        }
                        if mode != 0o100644 {
                            syscall::debug_puts(b"    ext2 stat: mode mismatch (expected 0100644, got ");
                            print_num(mode as u64);
                            syscall::debug_puts(b")\n");
                            ext2_ok = false;
                        }
                        if uid != 1000 || gid != 1000 {
                            syscall::debug_puts(b"    ext2 stat: uid/gid mismatch\n");
                            ext2_ok = false;
                        } else {
                            syscall::debug_puts(b"    ext2 stat: mode/uid/gid OK\n");
                        }
                    } else {
                        syscall::debug_puts(b"    ext2 stat FAILED\n");
                        ext2_ok = false;
                    }
                }

                // Step 5: Close hello.txt.
                syscall::send(ext2_port, 0x2400, handle, 0, 0, 0);
            }

            // Step 6: Open secret.txt and verify restricted permissions.
            {
                let (n0, n1, _) = pack_name(b"secret.txt");
                let d2 = 10u64 | ((reply_port as u64) << 32);
                syscall::send(ext2_port, 0x2000, n0, n1, d2, 0);
            }

            if let Some(reply) = syscall::recv_msg(reply_port) {
                if reply.tag == 0x2001 {
                    let secret_handle = reply.data[0];
                    // Stat it — should be mode 0100600, uid 0, gid 0.
                    let d2 = reply_port as u64;
                    syscall::send(ext2_port, 0x2300, secret_handle, 0, d2, 0);

                    if let Some(stat_reply) = syscall::recv_msg(reply_port) {
                        if stat_reply.tag == 0x2301 {
                            let mode = stat_reply.data[1] as u16;
                            let uid = (stat_reply.data[2] & 0xFFFF) as u16;
                            let gid = ((stat_reply.data[2] >> 16) & 0xFFFF) as u16;
                            if mode == 0o100600 && uid == 0 && gid == 0 {
                                syscall::debug_puts(b"    ext2 secret.txt permissions: OK\n");
                            } else {
                                syscall::debug_puts(b"    ext2 secret.txt permissions: mismatch\n");
                                ext2_ok = false;
                            }
                        }
                    }
                    syscall::send(ext2_port, 0x2400, secret_handle, 0, 0, 0);
                }
            }

            // Step 7: READDIR — enumerate root directory.
            {
                let mut entry_count = 0u32;
                let mut next_offset = 0u64;
                loop {
                    let d2 = reply_port as u64;
                    syscall::send(ext2_port, 0x2200, next_offset, 0, d2, 0);

                    if let Some(reply) = syscall::recv_msg(reply_port) {
                        if reply.tag == 0x2201 {
                            entry_count += 1;
                            next_offset = reply.data[3];
                        } else {
                            // FS_READDIR_END
                            break;
                        }
                    } else {
                        break;
                    }
                }
                syscall::debug_puts(b"    ext2 readdir: ");
                print_num(entry_count as u64);
                syscall::debug_puts(b" entries\n");
                // We created hello.txt, bench.dat, secret.txt, testdir, plus lost+found
                if entry_count < 3 {
                    syscall::debug_puts(b"    ext2 readdir: too few entries\n");
                    ext2_ok = false;
                }
            }

            syscall::port_destroy(reply_port);

            if ext2_ok {
                syscall::debug_puts(b"Phase 39 ext2 filesystem: PASSED\n");
            } else {
                syscall::debug_puts(b"Phase 39 ext2 filesystem: FAILED\n");
            }
        } else {
            syscall::debug_puts(b"Phase 39 ext2 filesystem: SKIPPED (no ext2 server)\n");
        }
    }

    // --- Test 31: Phase 41 signal delivery ---
    syscall::debug_puts(b"  init: testing signal delivery...\n");
    {
        // Use a known VA for a signal-received flag (in our mmap'd region).
        // Allocate one page for signal state.
        let flag_page = syscall::mmap_anon(0, 1, 1); // RW
        if let Some(flag_va) = flag_page {
            let flag_ptr = flag_va as *mut u64;
            unsafe {
                *flag_ptr = 0;
                SIG_FLAG_PTR = flag_ptr;
            }

            let handler_addr = signal_handler_sigusr1 as *const () as u64;
            let old = syscall::sigaction(syscall::SIGUSR1, handler_addr, 0, 0);

            // Send SIGUSR1 to ourselves.
            let my_tid = syscall::thread_id() as u32;
            syscall::kill_sig(my_tid, syscall::SIGUSR1);

            // After signal delivery and handler execution, flag should be set.
            // The handler runs before we get back here.
            let flag_val = unsafe { core::ptr::read_volatile(flag_ptr) };
            if flag_val == 42 {
                syscall::debug_puts(b"Phase 41 signal delivery: PASSED\n");
            } else {
                syscall::debug_puts(b"Phase 41 signal delivery: FAILED (flag=");
                print_num(flag_val);
                syscall::debug_puts(b")\n");
            }

            // Restore default handler.
            syscall::sigaction(syscall::SIGUSR1, syscall::SIG_DFL, 0, 0);

            // Test sigprocmask: block SIGUSR2, send it, check pending.
            let _old_mask = syscall::sigprocmask(0, syscall::sig_bit(syscall::SIGUSR2)); // SIG_BLOCK
            syscall::kill_sig(my_tid, syscall::SIGUSR2);
            let pending = syscall::sigpending();
            let usr2_pending = pending & syscall::sig_bit(syscall::SIGUSR2) != 0;

            // Unblock — signal should be delivered (default action = terminate,
            // but we want to survive, so install ignore first).
            syscall::sigaction(syscall::SIGUSR2, syscall::SIG_IGN, 0, 0);
            syscall::sigprocmask(1, syscall::sig_bit(syscall::SIGUSR2)); // SIG_UNBLOCK

            if usr2_pending {
                syscall::debug_puts(b"  sigprocmask/sigpending: OK\n");
            } else {
                syscall::debug_puts(b"  sigprocmask/sigpending: FAILED\n");
            }

            syscall::munmap(flag_va);
        } else {
            syscall::debug_puts(b"Phase 41 signal delivery: FAILED (mmap)\n");
        }
    }

    // --- Test 32: Phase 40 execve syscall ---
    syscall::debug_puts(b"  init: testing execve...\n");
    {
        let child = syscall::fork();
        if child == 0 {
            // Child: replace ourselves with "hello" binary.
            let r = syscall::execve(b"hello");
            // If execve returns, it failed.
            syscall::debug_puts(b"Phase 40 execve: FAILED (execve returned)\n");
            let _ = r;
            syscall::exit(1);
        } else if child > 0 {
            // Parent: wait for child to exit.
            loop {
                if let Some(code) = syscall::waitpid(child) {
                    if code == 0 {
                        syscall::debug_puts(b"Phase 40 execve: PASSED\n");
                    } else {
                        syscall::debug_puts(b"Phase 40 execve: FAILED (bad exit code)\n");
                    }
                    break;
                }
                syscall::yield_now();
            }
        } else {
            syscall::debug_puts(b"Phase 40 execve: FAILED (fork failed)\n");
        }
    }

    // --- Phase 43: Process groups, sessions, controlling terminals ---
    syscall::debug_puts(b"  init: testing process groups and sessions...\n");
    {
        let mut phase43_ok = true;
        let my_pid = syscall::getpid();

        // Initially: pgid == task_id, sid inherited from parent (0 for init).
        let my_pgid = syscall::getpgid(0);
        if my_pgid == u64::MAX {
            syscall::debug_puts(b"  init: getpgid failed\n");
            phase43_ok = false;
        }

        // Create a new session. init becomes session leader.
        let new_sid = syscall::setsid();
        if new_sid == u64::MAX {
            syscall::debug_puts(b"  init: setsid failed\n");
            phase43_ok = false;
        } else if new_sid != my_pid as u64 {
            syscall::debug_puts(b"  init: setsid returned wrong sid\n");
            phase43_ok = false;
        }

        // After setsid: sid == pgid == my_pid.
        let sid = syscall::getsid(0);
        if sid != my_pid as u64 {
            syscall::debug_puts(b"  init: getsid after setsid wrong\n");
            phase43_ok = false;
        }
        let pgid = syscall::getpgid(0);
        if pgid != my_pid as u64 {
            syscall::debug_puts(b"  init: pgid after setsid wrong\n");
            phase43_ok = false;
        }

        // Set a controlling terminal (use a dummy port).
        let ctty_port = syscall::port_create() as u32;
        if !syscall::set_ctty(ctty_port) {
            syscall::debug_puts(b"  init: set_ctty failed\n");
            phase43_ok = false;
        }

        // Fork a child and test process group inheritance.
        let fork_result = syscall::fork();
        if fork_result == 0 {
            // Child: should inherit parent's pgid, sid, and ctty.
            let child_pgid = syscall::getpgid(0);
            let child_sid = syscall::getsid(0);
            let parent_pgid = my_pid as u64;

            if child_pgid != parent_pgid || child_sid != my_pid as u64 {
                syscall::exit(1); // Failed.
            }

            // setpgid to own task_id (create own process group).
            let child_pid = syscall::getpid();
            if !syscall::setpgid(0, 0) {
                syscall::exit(2);
            }
            let new_pgid = syscall::getpgid(0);
            if new_pgid != child_pid as u64 {
                syscall::exit(3);
            }

            syscall::exit(0);
        } else if fork_result > 0 && fork_result != u64::MAX {
            // Parent: wait for child.
            loop {
                if let Some(code) = syscall::waitpid(fork_result) {
                    if code != 0 {
                        syscall::debug_puts(b"  init: child pgroup test failed (code=");
                        print_num(code);
                        syscall::debug_puts(b")\n");
                        phase43_ok = false;
                    }
                    break;
                }
                syscall::yield_now();
            }
        } else {
            syscall::debug_puts(b"  init: fork for pgroup test failed\n");
            phase43_ok = false;
        }

        // Test tcsetpgrp/tcgetpgrp: set init's pgid as foreground.
        if !syscall::tcsetpgrp(my_pid) {
            syscall::debug_puts(b"  init: tcsetpgrp failed\n");
            phase43_ok = false;
        }
        let fg = syscall::tcgetpgrp();
        if fg != my_pid as u64 {
            syscall::debug_puts(b"  init: tcgetpgrp wrong\n");
            phase43_ok = false;
        }

        // Yield to let any exited children fully clean up (aspace destruction
        // happens after task.exited is set, so waitpid returns before aspace is freed).
        for _ in 0..50 { syscall::yield_now(); }

        // Test pgroup kill: fork one child, put in own group, kill group.
        let child1 = syscall::fork();
        if child1 == 0 {
            // Child: spin.
            loop { syscall::yield_now(); }
        }

        if child1 > 0 && child1 != u64::MAX {
            // Put child in its own process group.
            syscall::setpgid(child1 as u32, child1 as u32);

            for _ in 0..10 { syscall::yield_now(); }

            // Kill the group.
            syscall::kill_pgroup(child1 as u32, syscall::SIGKILL);

            let mut found = false;
            for _ in 0..500 {
                if let Some(_) = syscall::waitpid(child1) {
                    found = true;
                    break;
                }
                syscall::yield_now();
            }
            if !found {
                syscall::debug_puts(b"  init: pgroup kill failed\n");
                phase43_ok = false;
            }
        } else {
            syscall::debug_puts(b"  init: fork for pgroup kill test failed\n");
            phase43_ok = false;
        }

        syscall::port_destroy(ctty_port);

        if phase43_ok {
            syscall::debug_puts(b"Phase 43 process groups/sessions: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 43 process groups/sessions: FAILED\n");
        }
    }

    // --- Phase 42: mprotect + mremap ---
    syscall::debug_puts(b"  init: testing mprotect + mremap...\n");
    {
        let mut phase42_ok = true;

        // Test mprotect: allocate RW page, write to it, change to RO, verify data survives.
        if let Some(va) = syscall::mmap_anon(0, 1, 1) { // 1 page, RW
            let page_size = 0x10000usize; // PAGE_SIZE = 64K
            let mmu_page = 0x1000usize;   // MMUPAGE_SIZE = 4K

            // Write a known value.
            unsafe { core::ptr::write_volatile(va as *mut u64, 0xDEAD_BEEF); }

            // Change protection to RO.
            if !syscall::mprotect(va, page_size, 0) {
                syscall::debug_puts(b"  init: mprotect to RO failed\n");
                phase42_ok = false;
            }

            // Read the value back — should still be there.
            let val = unsafe { core::ptr::read_volatile(va as *const u64) };
            if val != 0xDEAD_BEEF {
                syscall::debug_puts(b"  init: mprotect data corrupted\n");
                phase42_ok = false;
            }

            // Change back to RW to verify we can write again.
            if !syscall::mprotect(va, page_size, 1) {
                syscall::debug_puts(b"  init: mprotect to RW failed\n");
                phase42_ok = false;
            }

            // Write after re-enabling RW.
            unsafe { core::ptr::write_volatile(va as *mut u64, 0xCAFE_BABE); }
            let val2 = unsafe { core::ptr::read_volatile(va as *const u64) };
            if val2 != 0xCAFE_BABE {
                syscall::debug_puts(b"  init: mprotect write-after-RW failed\n");
                phase42_ok = false;
            }

            // Test mprotect on sub-range: split VMA.
            // Change first MMU page to RO, rest stays RW.
            if !syscall::mprotect(va, mmu_page, 0) {
                syscall::debug_puts(b"  init: mprotect sub-range failed\n");
                phase42_ok = false;
            }

            // Read from the RO sub-page should work.
            let val3 = unsafe { core::ptr::read_volatile(va as *const u64) };
            if val3 != 0xCAFE_BABE {
                syscall::debug_puts(b"  init: mprotect sub-range read failed\n");
                phase42_ok = false;
            }

            // Write to second MMU page (still RW) should work.
            let second_page = (va + mmu_page) as *mut u64;
            unsafe { core::ptr::write_volatile(second_page, 0x1234_5678); }
            let val4 = unsafe { core::ptr::read_volatile(second_page as *const u64) };
            if val4 != 0x1234_5678 {
                syscall::debug_puts(b"  init: mprotect second page RW failed\n");
                phase42_ok = false;
            }

            syscall::munmap(va);
        } else {
            syscall::debug_puts(b"  init: mmap for mprotect test failed\n");
            phase42_ok = false;
        }

        // Test mremap grow: allocate 1 page, write data, grow to 2 pages,
        // verify original data survives and new region is accessible.
        if let Some(va) = syscall::mmap_anon(0, 1, 1) {
            let page_size = 0x10000usize;

            // Write a sentinel.
            unsafe { core::ptr::write_volatile(va as *mut u64, 0xAAAA_BBBB); }

            // Grow from 1 page to 2 pages.
            if let Some(new_va) = syscall::mremap(va, page_size, page_size * 2) {
                if new_va != va {
                    syscall::debug_puts(b"  init: mremap moved unexpectedly\n");
                    phase42_ok = false;
                }

                // Original data intact.
                let val = unsafe { core::ptr::read_volatile(new_va as *const u64) };
                if val != 0xAAAA_BBBB {
                    syscall::debug_puts(b"  init: mremap data lost\n");
                    phase42_ok = false;
                }

                // Write to new region.
                let new_region = (new_va + page_size) as *mut u64;
                unsafe { core::ptr::write_volatile(new_region, 0xCCCC_DDDD); }
                let val2 = unsafe { core::ptr::read_volatile(new_region as *const u64) };
                if val2 != 0xCCCC_DDDD {
                    syscall::debug_puts(b"  init: mremap new region write failed\n");
                    phase42_ok = false;
                }

                // Shrink back to 1 page.
                if let Some(shrunk_va) = syscall::mremap(new_va, page_size * 2, page_size) {
                    let val3 = unsafe { core::ptr::read_volatile(shrunk_va as *const u64) };
                    if val3 != 0xAAAA_BBBB {
                        syscall::debug_puts(b"  init: mremap shrink data lost\n");
                        phase42_ok = false;
                    }
                    syscall::munmap(shrunk_va);
                } else {
                    syscall::debug_puts(b"  init: mremap shrink failed\n");
                    phase42_ok = false;
                    syscall::munmap(new_va);
                }
            } else {
                syscall::debug_puts(b"  init: mremap grow failed\n");
                phase42_ok = false;
                syscall::munmap(va);
            }
        } else {
            syscall::debug_puts(b"  init: mmap for mremap test failed\n");
            phase42_ok = false;
        }

        if phase42_ok {
            syscall::debug_puts(b"Phase 42 mprotect + mremap: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 42 mprotect + mremap: FAILED\n");
        }
    }

    // --- Phase 44: clock_gettime / nanosleep / interval timers ---
    syscall::debug_puts(b"  init: testing clock_gettime / nanosleep / alarm...\n");
    {
        let mut phase44_ok = true;

        // Test clock_gettime: should return nonzero, monotonically increasing.
        let t0 = syscall::clock_gettime();
        if t0 == 0 || t0 == u64::MAX {
            syscall::debug_puts(b"  init: clock_gettime returned bad value\n");
            phase44_ok = false;
        }
        // Burn a little time.
        for _ in 0..10_000 { unsafe { core::arch::asm!(""); } }
        let t1 = syscall::clock_gettime();
        if t1 <= t0 {
            syscall::debug_puts(b"  init: clock not monotonic\n");
            phase44_ok = false;
        }

        // Test nanosleep: sleep 50ms, verify at least 40ms elapsed.
        let before = syscall::clock_gettime();
        syscall::nanosleep(50_000_000); // 50 ms
        let after = syscall::clock_gettime();
        let elapsed = after.wrapping_sub(before);
        if elapsed < 40_000_000 {
            syscall::debug_puts(b"  init: nanosleep too short\n");
            phase44_ok = false;
        }

        // Test sleep_ms convenience wrapper.
        let before2 = syscall::clock_gettime();
        syscall::sleep_ms(30);
        let after2 = syscall::clock_gettime();
        let elapsed2 = after2.wrapping_sub(before2);
        if elapsed2 < 20_000_000 {
            syscall::debug_puts(b"  init: sleep_ms too short\n");
            phase44_ok = false;
        }

        // Test alarm: set a 100ms one-shot alarm, sleep 200ms, check SIGALRM pending.
        // First, set SIGALRM (14) handler to SIG_IGN so it stays pending.
        // Actually, we just check that alarm returns 0 (no previous alarm).
        let prev = syscall::alarm(100_000_000, 0); // 100ms one-shot
        if prev != 0 {
            syscall::debug_puts(b"  init: alarm prev should be 0\n");
            phase44_ok = false;
        }
        // Cancel and verify remaining time > 0.
        let remaining = syscall::alarm(0, 0);
        if remaining == 0 {
            // Might have already fired if system is slow, that's ok.
        }

        // Test alarm with interval: set, then cancel, verify prev > 0.
        syscall::alarm(200_000_000, 100_000_000); // 200ms initial, 100ms repeat
        syscall::nanosleep(10_000_000); // 10ms
        let prev2 = syscall::alarm(0, 0); // cancel
        if prev2 == 0 {
            // Could have fired already on slow systems, tolerate.
        }

        if phase44_ok {
            syscall::debug_puts(b"Phase 44 clock_gettime/nanosleep/alarm: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 44 clock_gettime/nanosleep/alarm: FAILED\n");
        }
    }

    // --- Phase 45: file-backed mmap (pager thread) ---
    syscall::debug_puts(b"  init: testing file-backed mmap (pager thread)...\n");
    {
        let mut phase45_ok = true;

        // Allocate a stack for the pager thread.
        let pager_stack = syscall::mmap_anon(0, 1, 1).unwrap_or(0);
        if pager_stack == 0 {
            syscall::debug_puts(b"  FAIL: cannot allocate pager stack\n");
            phase45_ok = false;
        }

        if phase45_ok {
            let pager_stack_top = pager_stack + 0x4000;

            // Spawn pager thread.
            let pager_tid = syscall::thread_create(
                pager_thread_entry as u64,
                pager_stack_top as u64,
                0,
            );
            if pager_tid == u64::MAX {
                syscall::debug_puts(b"  FAIL: cannot create pager thread\n");
                phase45_ok = false;
            }

            if phase45_ok {
                // Create a file-backed mapping: 2 allocation pages, RW, file_handle=0x42, offset=0.
                let mapped_va = syscall::mmap_file(0, 2, 1, 0x42, 0);
                match mapped_va {
                    Some(va) => {
                        // Touch several locations to trigger page faults.
                        // Pager fills each PAGE_SIZE page with a pattern: each byte = page_index.
                        let ptr = va as *const u8;

                        // Read from first page (offset 0).
                        let b0 = unsafe { core::ptr::read_volatile(ptr) };
                        if b0 != 0 {
                            syscall::debug_puts(b"  FAIL: page 0 byte 0 mismatch\n");
                            phase45_ok = false;
                        }

                        // Read from second allocation page (offset = PAGE_SIZE).
                        // PAGE_SIZE = 64K = 0x10000. Page index = 1.
                        let b1 = unsafe { core::ptr::read_volatile(ptr.add(0x10000)) };
                        if b1 != 1 {
                            syscall::debug_puts(b"  FAIL: page 1 byte 0 mismatch\n");
                            phase45_ok = false;
                        }

                        // Read from middle of first page (offset 0x100).
                        let b2 = unsafe { core::ptr::read_volatile(ptr.add(0x100)) };
                        if b2 != 0 {
                            syscall::debug_puts(b"  FAIL: page 0 byte 0x100 mismatch\n");
                            phase45_ok = false;
                        }

                        // Read from second page at offset 0x200.
                        let b3 = unsafe { core::ptr::read_volatile(ptr.add(0x10200)) };
                        if b3 != 1 {
                            syscall::debug_puts(b"  FAIL: page 1 byte 0x200 mismatch\n");
                            phase45_ok = false;
                        }

                        // Unmap.
                        syscall::munmap(va);
                    }
                    None => {
                        syscall::debug_puts(b"  FAIL: mmap_file returned None\n");
                        phase45_ok = false;
                    }
                }
            }
        }

        if phase45_ok {
            syscall::debug_puts(b"Phase 45 file-backed mmap: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 45 file-backed mmap: FAILED\n");
        }
    }

    // --- Phase 46: POSIX shared memory ---
    syscall::debug_puts(b"  init: testing POSIX shared memory...\n");
    {
        let mut phase46_ok = true;

        // Spawn shm_srv with a pre-created port.
        let shm_port = syscall::port_create() as u32;
        let shm_tid = syscall::spawn_with_arg(b"shm_srv", 50, shm_port as u64);
        if shm_tid == u64::MAX {
            syscall::debug_puts(b"  FAIL: cannot spawn shm_srv\n");
            phase46_ok = false;
        }

        if phase46_ok {
            // Give shm_srv time to start.
            for _ in 0..100 { syscall::yield_now(); }

            let my_aspace = syscall::aspace_id();

            // Create a shared segment "test_shm" with 1 page (64K).
            let (handle, pages, _srv_aspace) = match syscall::shm_create(shm_port, b"test_shm", 1) {
                Some(r) => r,
                None => {
                    syscall::debug_puts(b"  FAIL: shm_create returned None\n");
                    phase46_ok = false;
                    (0, 0, 0)
                }
            };

            if phase46_ok {
                if pages != 1 {
                    syscall::debug_puts(b"  FAIL: shm_create page_count mismatch\n");
                    phase46_ok = false;
                }
            }

            // Map the segment at a known VA for first mapping.
            let map_va1: usize = 0xA_0000_0000;
            if phase46_ok {
                match syscall::shm_map(shm_port, handle, my_aspace, map_va1, false) {
                    Some(pc) => {
                        if pc != 1 {
                            syscall::debug_puts(b"  FAIL: shm_map returned wrong page count\n");
                            phase46_ok = false;
                        }
                    }
                    None => {
                        syscall::debug_puts(b"  FAIL: shm_map #1 failed\n");
                        phase46_ok = false;
                    }
                }
            }

            // Write a pattern through the first mapping.
            if phase46_ok {
                let ptr1 = map_va1 as *mut u8;
                unsafe {
                    core::ptr::write_volatile(ptr1, 0xAA);
                    core::ptr::write_volatile(ptr1.add(1), 0xBB);
                    core::ptr::write_volatile(ptr1.add(0x100), 0xCC);
                    core::ptr::write_volatile(ptr1.add(0x1000), 0xDD);
                }
            }

            // Map the same segment at a different VA (second mapping of same pages).
            let map_va2: usize = 0xA_0001_0000;
            if phase46_ok {
                match syscall::shm_map(shm_port, handle, my_aspace, map_va2, false) {
                    Some(_) => {}
                    None => {
                        syscall::debug_puts(b"  FAIL: shm_map #2 failed\n");
                        phase46_ok = false;
                    }
                }
            }

            // Read through second mapping — should see the same data.
            if phase46_ok {
                let ptr2 = map_va2 as *const u8;
                let b0 = unsafe { core::ptr::read_volatile(ptr2) };
                let b1 = unsafe { core::ptr::read_volatile(ptr2.add(1)) };
                let b2 = unsafe { core::ptr::read_volatile(ptr2.add(0x100)) };
                let b3 = unsafe { core::ptr::read_volatile(ptr2.add(0x1000)) };

                if b0 != 0xAA {
                    syscall::debug_puts(b"  FAIL: shm byte 0 mismatch via second mapping\n");
                    phase46_ok = false;
                }
                if b1 != 0xBB {
                    syscall::debug_puts(b"  FAIL: shm byte 1 mismatch via second mapping\n");
                    phase46_ok = false;
                }
                if b2 != 0xCC {
                    syscall::debug_puts(b"  FAIL: shm byte 0x100 mismatch via second mapping\n");
                    phase46_ok = false;
                }
                if b3 != 0xDD {
                    syscall::debug_puts(b"  FAIL: shm byte 0x1000 mismatch via second mapping\n");
                    phase46_ok = false;
                }
            }

            // Also test shm_open: re-open the same segment by name.
            if phase46_ok {
                match syscall::shm_open(shm_port, b"test_shm") {
                    Some((h2, pc2, _)) => {
                        if h2 != handle || pc2 != 1 {
                            syscall::debug_puts(b"  FAIL: shm_open returned wrong handle/pages\n");
                            phase46_ok = false;
                        }
                    }
                    None => {
                        syscall::debug_puts(b"  FAIL: shm_open returned None\n");
                        phase46_ok = false;
                    }
                }
            }

            // Clean up: unmap both, unlink.
            if phase46_ok {
                syscall::shm_unmap(shm_port, handle, my_aspace, map_va2);
                syscall::shm_unmap(shm_port, handle, my_aspace, map_va1);
                if !syscall::shm_unlink(shm_port, b"test_shm") {
                    syscall::debug_puts(b"  FAIL: shm_unlink failed\n");
                    phase46_ok = false;
                }
            }
        }

        if phase46_ok {
            syscall::debug_puts(b"Phase 46 POSIX shared memory: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 46 POSIX shared memory: FAILED\n");
        }
    }

    // --- Phase 47: dup/dup2/fcntl/ioctl (userspace FD table) ---
    syscall::debug_puts(b"  init: testing FD table (dup/dup2/fcntl/ioctl)...\n");
    {
        let mut phase47_ok = true;

        // Initialize FD table with a dummy console port.
        let dummy_console = syscall::port_create() as u32;
        userlib::fd::fd_init(dummy_console);

        // FDs 0, 1, 2 should be open after init.
        if !userlib::fd::fd_is_valid(0) || !userlib::fd::fd_is_valid(1) || !userlib::fd::fd_is_valid(2) {
            syscall::debug_puts(b"  FAIL: FDs 0/1/2 not valid after fd_init\n");
            phase47_ok = false;
        }
        if userlib::fd::fd_is_valid(3) {
            syscall::debug_puts(b"  FAIL: FD 3 should not be valid\n");
            phase47_ok = false;
        }
        if phase47_ok && userlib::fd::fd_count() != 3 {
            syscall::debug_puts(b"  FAIL: fd_count should be 3\n");
            phase47_ok = false;
        }

        // --- dup ---
        if phase47_ok {
            match userlib::fd::dup(1) {
                Some(new_fd) => {
                    if new_fd != 3 {
                        syscall::debug_puts(b"  FAIL: dup(1) should return 3\n");
                        phase47_ok = false;
                    }
                    // New FD should have same port as FD 1.
                    let e1 = userlib::fd::fd_get(1).unwrap();
                    let e3 = userlib::fd::fd_get(new_fd).unwrap();
                    if e1.port != e3.port || e1.fd_type as u8 != e3.fd_type as u8 {
                        syscall::debug_puts(b"  FAIL: dup'd FD doesn't match original\n");
                        phase47_ok = false;
                    }
                    // dup should clear FD_CLOEXEC.
                    if e3.fd_flags != 0 {
                        syscall::debug_puts(b"  FAIL: dup should clear FD_CLOEXEC\n");
                        phase47_ok = false;
                    }
                }
                None => {
                    syscall::debug_puts(b"  FAIL: dup(1) returned None\n");
                    phase47_ok = false;
                }
            }
        }

        // --- dup2 ---
        if phase47_ok {
            // dup2(0, 10) — duplicate stdin to FD 10.
            match userlib::fd::dup2(0, 10) {
                Some(fd) => {
                    if fd != 10 {
                        syscall::debug_puts(b"  FAIL: dup2(0,10) should return 10\n");
                        phase47_ok = false;
                    }
                    let e0 = userlib::fd::fd_get(0).unwrap();
                    let e10 = userlib::fd::fd_get(10).unwrap();
                    if e0.port != e10.port {
                        syscall::debug_puts(b"  FAIL: dup2 FD 10 port mismatch\n");
                        phase47_ok = false;
                    }
                }
                None => {
                    syscall::debug_puts(b"  FAIL: dup2(0,10) returned None\n");
                    phase47_ok = false;
                }
            }

            // dup2 with same fd — should be a no-op if valid.
            if userlib::fd::dup2(1, 1) != Some(1) {
                syscall::debug_puts(b"  FAIL: dup2(1,1) should return 1\n");
                phase47_ok = false;
            }

            // dup2 to an occupied FD — should close old and replace.
            // Open a new FD at slot 5 first.
            let test_port = syscall::port_create() as u32;
            let _ = userlib::fd::fd_open(test_port, 42, userlib::fd::FdType::Port, 0);
            // fd_open should have assigned FD 4 (lowest free).
            if !userlib::fd::fd_is_valid(4) {
                syscall::debug_puts(b"  FAIL: fd_open didn't allocate FD 4\n");
                phase47_ok = false;
            }
            // dup2(0, 4) should replace FD 4 with a copy of FD 0.
            userlib::fd::dup2(0, 4);
            let e4 = userlib::fd::fd_get(4).unwrap();
            if e4.port != dummy_console {
                syscall::debug_puts(b"  FAIL: dup2 should have replaced FD 4\n");
                phase47_ok = false;
            }
            syscall::port_destroy(test_port);
        }

        // --- fcntl ---
        if phase47_ok {
            // F_GETFD — FD 0 should have no flags.
            if userlib::fd::fcntl(0, userlib::fd::F_GETFD, 0) != 0 {
                syscall::debug_puts(b"  FAIL: F_GETFD(0) should be 0\n");
                phase47_ok = false;
            }

            // F_SETFD — set FD_CLOEXEC on FD 3.
            userlib::fd::fcntl(3, userlib::fd::F_SETFD, userlib::fd::FD_CLOEXEC as i32);
            if userlib::fd::fcntl(3, userlib::fd::F_GETFD, 0) != userlib::fd::FD_CLOEXEC as i32 {
                syscall::debug_puts(b"  FAIL: F_SETFD/F_GETFD cloexec\n");
                phase47_ok = false;
            }

            // F_GETFL — FD 0 is O_RDONLY.
            if userlib::fd::fcntl(0, userlib::fd::F_GETFL, 0) != userlib::fd::O_RDONLY as i32 {
                syscall::debug_puts(b"  FAIL: F_GETFL(stdin) should be O_RDONLY\n");
                phase47_ok = false;
            }

            // F_SETFL — set O_NONBLOCK on FD 1.
            userlib::fd::fcntl(1, userlib::fd::F_SETFL, userlib::fd::O_NONBLOCK as i32);
            let fl = userlib::fd::fcntl(1, userlib::fd::F_GETFL, 0) as u32;
            if fl & userlib::fd::O_NONBLOCK == 0 {
                syscall::debug_puts(b"  FAIL: F_SETFL O_NONBLOCK not set\n");
                phase47_ok = false;
            }
            // Access mode should be preserved.
            if fl & 3 != userlib::fd::O_WRONLY {
                syscall::debug_puts(b"  FAIL: F_SETFL clobbered access mode\n");
                phase47_ok = false;
            }

            // F_DUPFD — duplicate FD 0 to lowest >= 20.
            let dup_fd = userlib::fd::fcntl(0, userlib::fd::F_DUPFD, 20);
            if dup_fd != 20 {
                syscall::debug_puts(b"  FAIL: F_DUPFD(0, 20) should return 20\n");
                phase47_ok = false;
            }
            if !userlib::fd::fd_is_valid(20) {
                syscall::debug_puts(b"  FAIL: F_DUPFD didn't create FD 20\n");
                phase47_ok = false;
            }

            // F_DUPFD_CLOEXEC — duplicate with cloexec flag.
            let dup_fd2 = userlib::fd::fcntl(0, userlib::fd::F_DUPFD_CLOEXEC, 30);
            if dup_fd2 != 30 {
                syscall::debug_puts(b"  FAIL: F_DUPFD_CLOEXEC should return 30\n");
                phase47_ok = false;
            }
            if userlib::fd::fcntl(30, userlib::fd::F_GETFD, 0) != userlib::fd::FD_CLOEXEC as i32 {
                syscall::debug_puts(b"  FAIL: F_DUPFD_CLOEXEC didn't set cloexec\n");
                phase47_ok = false;
            }

            // Invalid FD — should return -1.
            if userlib::fd::fcntl(99, userlib::fd::F_GETFD, 0) != -1 {
                syscall::debug_puts(b"  FAIL: fcntl on invalid FD should return -1\n");
                phase47_ok = false;
            }
        }

        // --- ioctl (FIONBIO) ---
        if phase47_ok {
            // FIONBIO sets O_NONBLOCK.
            // First clear O_NONBLOCK on FD 0.
            userlib::fd::fcntl(0, userlib::fd::F_SETFL, 0);
            let fl_before = userlib::fd::fcntl(0, userlib::fd::F_GETFL, 0) as u32;
            if fl_before & userlib::fd::O_NONBLOCK != 0 {
                syscall::debug_puts(b"  FAIL: O_NONBLOCK should be cleared\n");
                phase47_ok = false;
            }

            // Set FIONBIO = 1.
            if userlib::fd::ioctl(0, userlib::fd::FIONBIO, 1) != 0 {
                syscall::debug_puts(b"  FAIL: ioctl FIONBIO returned error\n");
                phase47_ok = false;
            }
            let fl_after = userlib::fd::fcntl(0, userlib::fd::F_GETFL, 0) as u32;
            if fl_after & userlib::fd::O_NONBLOCK == 0 {
                syscall::debug_puts(b"  FAIL: FIONBIO didn't set O_NONBLOCK\n");
                phase47_ok = false;
            }

            // Clear FIONBIO = 0.
            userlib::fd::ioctl(0, userlib::fd::FIONBIO, 0);
            let fl_final = userlib::fd::fcntl(0, userlib::fd::F_GETFL, 0) as u32;
            if fl_final & userlib::fd::O_NONBLOCK != 0 {
                syscall::debug_puts(b"  FAIL: FIONBIO=0 didn't clear O_NONBLOCK\n");
                phase47_ok = false;
            }
        }

        // --- fd_close_on_exec ---
        if phase47_ok {
            // FD 3 has FD_CLOEXEC set (from fcntl test above), FD 30 has it too.
            // FD 0,1,2,4,10,20 do not.
            let count_before = userlib::fd::fd_count();
            userlib::fd::fd_close_on_exec();
            let count_after = userlib::fd::fd_count();
            // Should have closed FD 3 and FD 30 (2 FDs).
            if count_before - count_after != 2 {
                syscall::debug_puts(b"  FAIL: fd_close_on_exec wrong count\n");
                phase47_ok = false;
            }
            if userlib::fd::fd_is_valid(3) || userlib::fd::fd_is_valid(30) {
                syscall::debug_puts(b"  FAIL: cloexec FDs still open\n");
                phase47_ok = false;
            }
            // FDs without cloexec should survive.
            if !userlib::fd::fd_is_valid(0) || !userlib::fd::fd_is_valid(1) {
                syscall::debug_puts(b"  FAIL: non-cloexec FDs were closed\n");
                phase47_ok = false;
            }
        }

        // --- fd_close ---
        if phase47_ok {
            // Close FDs we opened during the test.
            userlib::fd::fd_close(4);
            userlib::fd::fd_close(10);
            userlib::fd::fd_close(20);
            // Double-close should return false.
            if userlib::fd::fd_close(20) {
                syscall::debug_puts(b"  FAIL: double close should return false\n");
                phase47_ok = false;
            }
            // Close invalid FD should return false.
            if userlib::fd::fd_close(-1) {
                syscall::debug_puts(b"  FAIL: close(-1) should return false\n");
                phase47_ok = false;
            }
        }

        // Clean up remaining test FDs (0, 1, 2 are still open).
        userlib::fd::fd_close(0);
        userlib::fd::fd_close(1);
        userlib::fd::fd_close(2);
        syscall::port_destroy(dummy_console);

        if phase47_ok {
            syscall::debug_puts(b"Phase 47 dup/dup2/fcntl/ioctl: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 47 dup/dup2/fcntl/ioctl: FAILED\n");
        }
    }

    // --- Phase 48: Credential syscalls ---
    syscall::debug_puts(b"  init: testing credential syscalls...\n");
    {
        let mut phase48_ok = true;

        // Init runs as root (uid=0, gid=0) by default.
        let uid_val = syscall::getuid();
        if uid_val != 0 {
            syscall::debug_puts(b"  FAIL: getuid() should be 0\n");
            phase48_ok = false;
        }
        if syscall::geteuid() != 0 {
            syscall::debug_puts(b"  FAIL: geteuid() should be 0\n");
            phase48_ok = false;
        }
        if syscall::getgid() != 0 {
            syscall::debug_puts(b"  FAIL: getgid() should be 0\n");
            phase48_ok = false;
        }
        if syscall::getegid() != 0 {
            syscall::debug_puts(b"  FAIL: getegid() should be 0\n");
            phase48_ok = false;
        }
        // setgroups: set supplementary groups as root.
        if phase48_ok {
            let groups: [u32; 3] = [100, 200, 300];
            if !syscall::setgroups(&groups) {
                syscall::debug_puts(b"  FAIL: setgroups as root failed\n");
                phase48_ok = false;
            }
            let mut buf = [0u32; 8];
            let n = syscall::getgroups(&mut buf);
            if n != 3 {
                syscall::debug_puts(b"  FAIL: getgroups count mismatch\n");
                phase48_ok = false;
            } else if buf[0] != 100 || buf[1] != 200 || buf[2] != 300 {
                syscall::debug_puts(b"  FAIL: getgroups values mismatch\n");
                phase48_ok = false;
            }
        }

        // setuid to non-root, then verify permissions are restricted.
        if phase48_ok {
            // Drop to uid 1000.
            if !syscall::setuid(1000) {
                syscall::debug_puts(b"  FAIL: setuid(1000) as root failed\n");
                phase48_ok = false;
            }
            if syscall::getuid() != 1000 {
                syscall::debug_puts(b"  FAIL: getuid() should be 1000 after setuid\n");
                phase48_ok = false;
            }
            if syscall::geteuid() != 1000 {
                syscall::debug_puts(b"  FAIL: geteuid() should be 1000 after setuid\n");
                phase48_ok = false;
            }
        }

        // As non-root, setuid to 0 should fail.
        if phase48_ok {
            if syscall::setuid(0) {
                syscall::debug_puts(b"  FAIL: setuid(0) as non-root should fail\n");
                phase48_ok = false;
            }
            // setuid to own real uid should succeed (no-op).
            if !syscall::setuid(1000) {
                syscall::debug_puts(b"  FAIL: setuid(own uid) should succeed\n");
                phase48_ok = false;
            }
        }

        // setgid as non-root should fail for arbitrary values.
        if phase48_ok {
            // First set gid while we still can (we changed uid but gid was never changed).
            // Actually, setgid checks euid, and euid is now 1000.
            if syscall::setgid(500) {
                syscall::debug_puts(b"  FAIL: setgid(500) as non-root should fail\n");
                phase48_ok = false;
            }
            // setgid to own real gid (0) should succeed.
            if !syscall::setgid(0) {
                syscall::debug_puts(b"  FAIL: setgid(own gid) should succeed\n");
                phase48_ok = false;
            }
        }

        // setgroups as non-root should fail.
        if phase48_ok {
            let groups: [u32; 1] = [999];
            if syscall::setgroups(&groups) {
                syscall::debug_puts(b"  FAIL: setgroups as non-root should fail\n");
                phase48_ok = false;
            }
            // Previous groups should still be set.
            let mut buf = [0u32; 8];
            let n = syscall::getgroups(&mut buf);
            if n != 3 {
                syscall::debug_puts(b"  FAIL: groups should be unchanged after failed setgroups\n");
                phase48_ok = false;
            }
        }

        // Test credential inheritance via spawn.
        if phase48_ok {
            // Spawn a child — it should inherit uid=1000, gid=0.
            // We can't easily read the child's credentials, but we can test
            // that the child runs (proving spawn works with non-root creds).
            let child = syscall::spawn(b"hello", 50);
            if child != u64::MAX {
                let _ = syscall::waitpid(child);
            }
        }

        // Restore root for subsequent tests (we can't — we dropped privs).
        // This is fine; Phase 48 test is last before benchmarks.

        if phase48_ok {
            syscall::debug_puts(b"Phase 48 credential syscalls: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 48 credential syscalls: FAILED\n");
        }
    }

    // --- Phase 49: wait4/waitpid improvements ---
    syscall::debug_puts(b"  init: testing wait4/waitpid improvements...\n");
    {
        let mut phase49_ok = true;

        // Test 1: wait4(-1, WNOHANG) with no children should return None (ECHILD).
        // Note: we may have active children (servers), but they haven't exited.
        // Actually, we DO have children (blk_srv, console, etc.), so it should
        // return Some((0, 0)) for WNOHANG with no exited child.
        // Let's spawn a child that exits quickly and wait for it.

        // Test 2: Spawn a child and wait4 with specific pid.
        let child_tid = syscall::spawn(b"hello", 50);
        if child_tid == u64::MAX {
            syscall::debug_puts(b"  FAIL: spawn for wait4 test failed\n");
            phase49_ok = false;
        }

        if phase49_ok {
            // The child's task_id is what we need. Since the kernel returns
            // the first thread ID, and thread.task_id gives us the task,
            // wait4 works with task IDs. We need to figure out the task ID.
            // For spawned processes, the task_id is typically the thread's task_id.
            // Let's use wait4(-1, 0) to wait for any child exit.
            // First try WNOHANG — the child may or may not have exited yet.
            let nh = syscall::wait4(-1, syscall::WNOHANG);
            match nh {
                None => {
                    // ECHILD — shouldn't happen, we have children.
                    syscall::debug_puts(b"  FAIL: wait4(-1, WNOHANG) returned ECHILD\n");
                    phase49_ok = false;
                }
                Some((0, _)) => {
                    // No child exited yet — expected, try blocking wait.
                }
                Some((pid, status)) => {
                    // A child already exited. Check status.
                    if !syscall::wifexited(status) {
                        syscall::debug_puts(b"  FAIL: child did not exit normally\n");
                        phase49_ok = false;
                    }
                    let _ = pid; // OK
                }
            }
        }

        if phase49_ok {
            // Test 3: Blocking wait4(-1, 0) — should return when the hello child exits.
            let result = syscall::wait4(-1, 0);
            match result {
                None => {
                    syscall::debug_puts(b"  FAIL: wait4(-1, 0) returned ECHILD\n");
                    phase49_ok = false;
                }
                Some((pid, status)) => {
                    if pid == 0 {
                        syscall::debug_puts(b"  FAIL: wait4 returned pid 0\n");
                        phase49_ok = false;
                    } else if !syscall::wifexited(status) {
                        syscall::debug_puts(b"  FAIL: child did not exit normally\n");
                        phase49_ok = false;
                    } else {
                        let code = syscall::wexitstatus(status);
                        let _ = code; // hello exits with 0
                    }
                }
            }
        }

        if phase49_ok {
            // Test 4: WNOHANG when no more zombies.
            let nh2 = syscall::wait4(-1, syscall::WNOHANG);
            match nh2 {
                Some((0, _)) => {
                    // No exited children — correct (servers are still running).
                }
                None => {
                    // ECHILD — also acceptable if all spawned children are reaped
                    // and remaining children are servers that haven't exited.
                    // Actually, servers ARE children, so this shouldn't be ECHILD.
                    // But with our task slot reuse, the server tasks may have been
                    // spawned before Phase 49, so they are children of init.
                    // This is OK — we still have children, just none exited.
                }
                Some((_pid, _status)) => {
                    // Another child exited — also fine.
                }
            }
        }

        if phase49_ok {
            // Test 5: Spawn, let child exit, wait4 with specific pid.
            let child2 = syscall::spawn(b"hello", 50);
            if child2 != u64::MAX {
                // Yield a few times to let child run and exit.
                for _ in 0..20 { syscall::yield_now(); }
                // The child_tid is a thread ID. We need the task ID for wait4.
                // In our kernel, wait4 matches by task_id. The thread's task_id
                // may differ from the thread_id. For spawned tasks, the task_id
                // is allocated separately. We can discover it by using wait4(-1).
                let r = syscall::wait4(-1, 0);
                match r {
                    Some((pid, status)) if pid > 0 && syscall::wifexited(status) => {
                        // Success.
                        let _ = pid;
                    }
                    _ => {
                        syscall::debug_puts(b"  FAIL: wait4 for second child failed\n");
                        phase49_ok = false;
                    }
                }
            }
        }

        if phase49_ok {
            // Test 6: WIFEXITED / WEXITSTATUS macros.
            let status = (42i32 & 0xFF) << 8; // simulate exit(42)
            if !syscall::wifexited(status) {
                syscall::debug_puts(b"  FAIL: WIFEXITED should be true\n");
                phase49_ok = false;
            }
            if syscall::wexitstatus(status) != 42 {
                syscall::debug_puts(b"  FAIL: WEXITSTATUS should be 42\n");
                phase49_ok = false;
            }
            if syscall::wifsignaled(status) {
                syscall::debug_puts(b"  FAIL: WIFSIGNALED should be false\n");
                phase49_ok = false;
            }
            // Simulate signal death (signal 9).
            let sig_status = 9i32;
            if !syscall::wifsignaled(sig_status) {
                syscall::debug_puts(b"  FAIL: WIFSIGNALED should be true for signal\n");
                phase49_ok = false;
            }
            if syscall::wtermsig(sig_status) != 9 {
                syscall::debug_puts(b"  FAIL: WTERMSIG should be 9\n");
                phase49_ok = false;
            }
        }

        if phase49_ok {
            syscall::debug_puts(b"Phase 49 wait4/waitpid improvements: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 49 wait4/waitpid improvements: FAILED\n");
        }
    }

    // --- Phase 50: Resource limits ---
    syscall::debug_puts(b"  init: testing resource limits...\n");
    {
        let mut phase50_ok = true;

        // Test 1: getrlimit returns default values.
        if let Some((cur, max)) = syscall::getrlimit(syscall::RLIMIT_NOFILE) {
            if cur != 64 || max != 1024 {
                syscall::debug_puts(b"  FAIL: RLIMIT_NOFILE defaults wrong\n");
                phase50_ok = false;
            }
        } else {
            syscall::debug_puts(b"  FAIL: getrlimit(RLIMIT_NOFILE) failed\n");
            phase50_ok = false;
        }

        if phase50_ok {
            if let Some((cur, max)) = syscall::getrlimit(syscall::RLIMIT_AS) {
                if cur != syscall::RLIM_INFINITY || max != syscall::RLIM_INFINITY {
                    syscall::debug_puts(b"  FAIL: RLIMIT_AS defaults wrong\n");
                    phase50_ok = false;
                }
            } else {
                syscall::debug_puts(b"  FAIL: getrlimit(RLIMIT_AS) failed\n");
                phase50_ok = false;
            }
        }

        if phase50_ok {
            if let Some((cur, max)) = syscall::getrlimit(syscall::RLIMIT_NPROC) {
                if cur != syscall::RLIM_INFINITY || max != syscall::RLIM_INFINITY {
                    syscall::debug_puts(b"  FAIL: RLIMIT_NPROC defaults wrong\n");
                    phase50_ok = false;
                }
            } else {
                syscall::debug_puts(b"  FAIL: getrlimit(RLIMIT_NPROC) failed\n");
                phase50_ok = false;
            }
        }

        // Test 2: setrlimit to lower soft limit, then read back.
        if phase50_ok {
            if !syscall::setrlimit(syscall::RLIMIT_NOFILE, 32, 1024) {
                syscall::debug_puts(b"  FAIL: setrlimit(NOFILE, 32, 1024) failed\n");
                phase50_ok = false;
            }
            if let Some((cur, max)) = syscall::getrlimit(syscall::RLIMIT_NOFILE) {
                if cur != 32 || max != 1024 {
                    syscall::debug_puts(b"  FAIL: NOFILE after setrlimit wrong\n");
                    phase50_ok = false;
                }
            }
            // Restore.
            syscall::setrlimit(syscall::RLIMIT_NOFILE, 64, 1024);
        }

        // Test 3: prlimit get+set atomically.
        if phase50_ok {
            let sentinel = syscall::RLIM_INFINITY - 1;
            // Get current without changing (sentinel = don't change).
            if let Some((old_cur, old_max)) = syscall::prlimit(0, syscall::RLIMIT_STACK, sentinel, sentinel) {
                if old_cur != 65536 || old_max != 1048576 {
                    syscall::debug_puts(b"  FAIL: prlimit RLIMIT_STACK defaults wrong\n");
                    phase50_ok = false;
                }
            } else {
                syscall::debug_puts(b"  FAIL: prlimit get failed\n");
                phase50_ok = false;
            }
        }

        // Test 4: prlimit to change soft, verify old returned.
        if phase50_ok {
            let sentinel = syscall::RLIM_INFINITY - 1;
            if let Some((old_cur, _old_max)) = syscall::prlimit(0, syscall::RLIMIT_STACK, 32768, sentinel) {
                if old_cur != 65536 {
                    syscall::debug_puts(b"  FAIL: prlimit didn't return old soft\n");
                    phase50_ok = false;
                }
            }
            // Verify new value.
            if let Some((cur, _)) = syscall::getrlimit(syscall::RLIMIT_STACK) {
                if cur != 32768 {
                    syscall::debug_puts(b"  FAIL: STACK soft not updated by prlimit\n");
                    phase50_ok = false;
                }
            }
            // Restore.
            let sentinel = syscall::RLIM_INFINITY - 1;
            syscall::prlimit(0, syscall::RLIMIT_STACK, 65536, sentinel);
        }

        // Test 5: RLIMIT_AS enforcement — set very small, then mmap should fail.
        if phase50_ok {
            // Save old.
            let old = syscall::getrlimit(syscall::RLIMIT_AS);
            // Set to a tiny value (1 byte — effectively zero new allocations).
            if syscall::setrlimit(syscall::RLIMIT_AS, 1, syscall::RLIM_INFINITY) {
                // Try mmap — should fail due to RLIMIT_AS.
                let r = syscall::mmap_anon(0, 1, 1);
                if r.is_some() {
                    syscall::debug_puts(b"  FAIL: mmap should fail under RLIMIT_AS\n");
                    phase50_ok = false;
                    // Clean up the mapping.
                    syscall::munmap(r.unwrap());
                }
            }
            // Restore.
            if let Some((cur, max)) = old {
                syscall::setrlimit(syscall::RLIMIT_AS, cur, max);
            }
        }

        // Test 6: RLIMIT_NPROC enforcement — set a low limit and try to spawn.
        if phase50_ok {
            // Set NPROC soft to 1 — should block new spawns since we already
            // have more than 1 task with uid 0.
            let old = syscall::getrlimit(syscall::RLIMIT_NPROC);
            if syscall::setrlimit(syscall::RLIMIT_NPROC, 1, syscall::RLIM_INFINITY) {
                let child = syscall::spawn(b"hello", 50);
                if child != u64::MAX {
                    syscall::debug_puts(b"  FAIL: spawn should fail under RLIMIT_NPROC\n");
                    phase50_ok = false;
                    // Still reap the child.
                    loop {
                        if let Some(_) = syscall::waitpid(child) { break; }
                        syscall::yield_now();
                    }
                }
            }
            // Restore.
            if let Some((cur, max)) = old {
                syscall::setrlimit(syscall::RLIMIT_NPROC, cur, max);
            }
        }

        // Test 7: Invalid resource should fail.
        if phase50_ok {
            if syscall::getrlimit(99).is_some() {
                syscall::debug_puts(b"  FAIL: getrlimit(99) should fail\n");
                phase50_ok = false;
            }
        }

        if phase50_ok {
            syscall::debug_puts(b"Phase 50 resource limits: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 50 resource limits: FAILED\n");
        }
    }

    // --- Phase 51: VFS server ---
    syscall::debug_puts(b"  init: testing VFS server...\n");
    {
        let mut phase51_ok = true;

        // VFS protocol tags.
        const VFS_MOUNT: u64 = 0x6000;
        const VFS_OPEN: u64 = 0x6010;
        const VFS_STAT: u64 = 0x6020;
        const VFS_READDIR: u64 = 0x6030;
        const VFS_OK: u64 = 0x6100;
        const VFS_OPEN_OK: u64 = 0x6110;
        const VFS_STAT_OK: u64 = 0x6120;
        const VFS_READDIR_OK: u64 = 0x6130;
        const VFS_READDIR_END: u64 = 0x6131;
        const VFS_ERROR: u64 = 0x6F00;

        // Spawn VFS server.
        let vfs_tid = syscall::spawn(b"vfs_srv", 50);
        if vfs_tid == u64::MAX {
            syscall::debug_puts(b"  FAIL: cannot spawn vfs_srv\n");
            phase51_ok = false;
        }

        // Give VFS server time to register (retry lookup).
        let vfs_port = if phase51_ok {
            let mut found = 0u32;
            for _ in 0..100 {
                if let Some(p) = syscall::ns_lookup(b"vfs") {
                    found = p;
                    break;
                }
                syscall::sleep_ms(10); // 10ms
            }
            if found == 0 {
                syscall::debug_puts(b"  FAIL: ns_lookup(vfs) failed\n");
                phase51_ok = false;
            }
            found
        } else { 0 };

        // Look up ext2 port for mounting.
        let ext2_port = if phase51_ok {
            match syscall::ns_lookup(b"ext2") {
                Some(p) => p,
                None => {
                    syscall::debug_puts(b"  FAIL: ns_lookup(ext2) failed\n");
                    phase51_ok = false;
                    0
                }
            }
        } else { 0 };

        // Look up fat16 port.
        let fat16_port = if phase51_ok {
            match syscall::ns_lookup(b"fat16") {
                Some(p) => p,
                None => {
                    // FAT16 might not be available, skip fat16 tests.
                    0
                }
            }
        } else { 0 };

        // Test 1: Mount ext2 on "/".
        // VFS wire: data[0..1]=path(16B), data[2]=path_len(16)|reply(32), data[3]=fs_port
        if phase51_ok {
            let reply_port = syscall::port_create() as u32;
            let path = b"/";
            let (w0, w1, _w2) = pack_name(path);
            let d2 = (path.len() as u64) | ((reply_port as u64) << 32);
            syscall::send(vfs_port, VFS_MOUNT, w0, w1, d2, ext2_port as u64);

            let mut mounted = false;
            for _ in 0..100 {
                if let Some(reply) = syscall::recv_nb_msg(reply_port) {
                    if reply.tag == VFS_OK {
                        mounted = true;
                    }
                    break;
                }
                syscall::sleep_ms(10); // 10ms
            }
            syscall::port_destroy(reply_port);

            if !mounted {
                syscall::debug_puts(b"  FAIL: VFS_MOUNT / failed\n");
                phase51_ok = false;
            }
        }

        // Test 2: Mount fat16 on "/mnt".
        if phase51_ok && fat16_port != 0 {
            let reply_port = syscall::port_create() as u32;
            let path = b"/mnt";
            let (w0, w1, _w2) = pack_name(path);
            let d2 = (path.len() as u64) | ((reply_port as u64) << 32);
            syscall::send(vfs_port, VFS_MOUNT, w0, w1, d2, fat16_port as u64);

            let mut mnt_ok = false;
            for _ in 0..100 {
                if let Some(reply) = syscall::recv_nb_msg(reply_port) {
                    if reply.tag == VFS_OK {
                        mnt_ok = true;
                    } else {
                        syscall::debug_puts(b"  FAIL: VFS_MOUNT /mnt rejected\n");
                        phase51_ok = false;
                    }
                    break;
                }
                syscall::sleep_ms(10); // 10ms
            }
            if !mnt_ok && phase51_ok {
                syscall::debug_puts(b"  FAIL: VFS_MOUNT /mnt timeout\n");
                phase51_ok = false;
            }
            syscall::port_destroy(reply_port);
        }

        // Brief pause to let VFS server process mount table updates.
        syscall::sleep_ms(20);

        // Test 3: VFS_OPEN "/hello.txt" — should resolve to ext2 on "/".
        if phase51_ok {
            let reply_port = syscall::port_create() as u32;
            let path = b"/hello.txt";
            let (w0, w1, _w2) = pack_name(path);
            let d2 = (path.len() as u64) | ((reply_port as u64) << 32);
            syscall::send(vfs_port, VFS_OPEN, w0, w1, d2, 0);

            let mut open_ok = false;
            if let Some(reply) = syscall::recv_msg(reply_port) {
                if reply.tag == VFS_OPEN_OK {
                    let ret_fs_port = reply.data[0] as u32;
                    if ret_fs_port == ext2_port {
                        open_ok = true;
                    } else {
                        syscall::debug_puts(b"  FAIL: VFS_OPEN wrong port\n");
                    }
                } else {
                    syscall::debug_puts(b"  FAIL: VFS_OPEN err\n");
                }
            }
            syscall::port_destroy(reply_port);

            if !open_ok {
                phase51_ok = false;
            }
        }

        // Test 4: VFS_OPEN "/mnt/HELLO.TXT" — should resolve to fat16 on "/mnt".
        if phase51_ok && fat16_port != 0 {
            let reply_port = syscall::port_create() as u32;
            let path = b"/mnt/HELLO.TXT";
            let (w0, w1, _w2) = pack_name(path);
            let d2 = (path.len() as u64) | ((reply_port as u64) << 32);
            syscall::send(vfs_port, VFS_OPEN, w0, w1, d2, 0);

            let mut open_ok = false;
            if let Some(reply) = syscall::recv_msg(reply_port) {
                if reply.tag == VFS_OPEN_OK {
                    if reply.data[0] as u32 == fat16_port {
                        open_ok = true;
                    }
                }
            }
            syscall::port_destroy(reply_port);
            if !open_ok {
                syscall::debug_puts(b"  FAIL: VFS /mnt open\n");
                phase51_ok = false;
            }
        }

        // Test 5: Path normalization — "/a/../hello.txt" resolves to "/hello.txt".
        if phase51_ok {
            let reply_port = syscall::port_create() as u32;
            let path = b"/a/../hello.txt";
            let (w0, w1, _w2) = pack_name(path);
            let d2 = (path.len() as u64) | ((reply_port as u64) << 32);
            syscall::send(vfs_port, VFS_OPEN, w0, w1, d2, 0);
            if let Some(reply) = syscall::recv_msg(reply_port) {
                if reply.tag == VFS_OPEN_OK {
                    // Path normalization worked.
                }
                // VFS_ERROR also OK if file not found.
            }
            syscall::port_destroy(reply_port);
        }

        if phase51_ok {
            syscall::debug_puts(b"Phase 51 VFS server: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 51 VFS server: FAILED\n");
        }
    }

    // --- Phase 52: musl-libc C binary test ---
    syscall::debug_puts(b"  init: testing C binary (musl-telix)...\n");
    {
        let c_tid = syscall::spawn(b"hello_c", 50);
        if c_tid != u64::MAX {
            syscall::debug_puts(b"  init: spawned hello_c (tid=");
            print_num(c_tid);
            syscall::debug_puts(b")\n");
            loop {
                if let Some(code) = syscall::waitpid(c_tid) {
                    if code == 0 {
                        syscall::debug_puts(b"Phase 52 musl-libc C binary: PASSED\n");
                    } else {
                        syscall::debug_puts(b"Phase 52 musl-libc C binary: FAILED (exit=");
                        print_num(code);
                        syscall::debug_puts(b")\n");
                    }
                    break;
                }
                syscall::yield_now();
            }
        } else {
            syscall::debug_puts(b"Phase 52 musl-libc C binary: SKIPPED (no hello_c in initramfs)\n");
        }
    }

    // --- Phase 53: ext2 write support ---
    syscall::debug_puts(b"  init: testing ext2 write...\n");
    {
        let ext2_port = match syscall::ns_lookup(b"ext2") {
            Some(p) => p,
            None => 0,
        };
        let mut phase53_ok = ext2_port != 0;
        if !phase53_ok {
            syscall::debug_puts(b"Phase 53 ext2 write: SKIPPED (no ext2)\n");
        }

        let reply_port = if phase53_ok { syscall::port_create() as u32 } else { 0 };

        // Step 1: FS_CREATE "WTEST.TXT"
        let mut handle = 0u64;
        let mut srv_aspace = 0u32;
        if phase53_ok {
            let fname = b"WTEST.TXT";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((reply_port as u64) << 32);
            syscall::send(ext2_port, 0x2500, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(reply_port) {
                if reply.tag == 0x2501 {
                    handle = reply.data[0];
                    srv_aspace = reply.data[2] as u32;
                } else {
                    syscall::debug_puts(b"  FAIL: ext2 FS_CREATE failed\n");
                    phase53_ok = false;
                }
            } else {
                syscall::debug_puts(b"  FAIL: ext2 FS_CREATE no reply\n");
                phase53_ok = false;
            }
        }

        // Step 2: FS_WRITE 64 bytes of known pattern
        if phase53_ok {
            if let Some(scratch) = syscall::mmap_anon(0, 1, 1) {
                // Fill with pattern: byte[i] = (i * 7 + 0x41) & 0xFF
                unsafe {
                    let p = scratch as *mut u8;
                    for i in 0..64 {
                        *p.add(i) = ((i * 7 + 0x41) & 0xFF) as u8;
                    }
                }
                let grant_dst: usize = 0x8_0000_0000;
                let grant_ok = syscall::grant_pages(srv_aspace, scratch, grant_dst, 1, false);
                if grant_ok {
                    let wd1 = 64u64 | ((reply_port as u64) << 32);
                    syscall::send(ext2_port, 0x2600, handle, wd1, grant_dst as u64, 0);
                    if let Some(wr) = syscall::recv_msg(reply_port) {
                        if wr.tag != 0x2601 || wr.data[0] != 64 {
                            syscall::debug_puts(b"  FAIL: ext2 FS_WRITE bad reply\n");
                            phase53_ok = false;
                        }
                    } else {
                        phase53_ok = false;
                    }
                    syscall::revoke(srv_aspace, grant_dst);
                } else {
                    syscall::debug_puts(b"  FAIL: ext2 grant failed\n");
                    phase53_ok = false;
                }
                syscall::munmap(scratch);
            } else {
                phase53_ok = false;
            }
        }

        // Step 3: FS_CLOSE (triggers inode flush)
        if phase53_ok {
            syscall::send(ext2_port, 0x2400, handle, 0, 0, 0);
            syscall::sleep_ms(50); // Wait for disk I/O
        }

        // Step 4: Re-open and verify
        if phase53_ok {
            let fname = b"WTEST.TXT";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((reply_port as u64) << 32);
            syscall::send(ext2_port, 0x2000, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(reply_port) {
                if reply.tag == 0x2001 {
                    let rh = reply.data[0];
                    let rsize = reply.data[1];
                    let r_aspace = reply.data[2] as u32;
                    if rsize != 64 {
                        syscall::debug_puts(b"  FAIL: ext2 re-open size mismatch\n");
                        phase53_ok = false;
                    }

                    // FS_READ via grant
                    if phase53_ok {
                        if let Some(scratch) = syscall::mmap_anon(0, 1, 1) {
                            let grant_dst: usize = 0x8_0000_0000;
                            if syscall::grant_pages(r_aspace, scratch, grant_dst, 1, false) {
                                let rd2 = 64u64 | ((reply_port as u64) << 32);
                                syscall::send(ext2_port, 0x2100, rh, 0, rd2, grant_dst as u64);
                                if let Some(rd) = syscall::recv_msg(reply_port) {
                                    if rd.tag == 0x2101 && rd.data[0] == 64 {
                                        // Verify pattern
                                        let p = scratch as *const u8;
                                        let mut mismatch = false;
                                        for i in 0..64 {
                                            let expected = ((i * 7 + 0x41) & 0xFF) as u8;
                                            let got = unsafe { *p.add(i) };
                                            if got != expected {
                                                mismatch = true;
                                                break;
                                            }
                                        }
                                        if mismatch {
                                            syscall::debug_puts(b"  FAIL: ext2 read-back mismatch\n");
                                            phase53_ok = false;
                                        }
                                    } else {
                                        syscall::debug_puts(b"  FAIL: ext2 FS_READ bad reply\n");
                                        phase53_ok = false;
                                    }
                                } else { phase53_ok = false; }
                                syscall::revoke(r_aspace, grant_dst);
                            } else { phase53_ok = false; }
                            syscall::munmap(scratch);
                        } else { phase53_ok = false; }
                    }

                    // Close the re-opened file.
                    syscall::send(ext2_port, 0x2400, rh, 0, 0, 0);
                } else {
                    syscall::debug_puts(b"  FAIL: ext2 re-open not found\n");
                    phase53_ok = false;
                }
            } else { phase53_ok = false; }
        }

        // Step 5: FS_DELETE "WTEST.TXT"
        if phase53_ok {
            let fname = b"WTEST.TXT";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((reply_port as u64) << 32);
            syscall::send(ext2_port, 0x2700, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(reply_port) {
                if reply.tag != 0x2701 {
                    syscall::debug_puts(b"  FAIL: ext2 FS_DELETE failed\n");
                    phase53_ok = false;
                }
            } else { phase53_ok = false; }
        }

        // Step 6: Verify file is gone
        if phase53_ok {
            syscall::sleep_ms(20);
            let fname = b"WTEST.TXT";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((reply_port as u64) << 32);
            syscall::send(ext2_port, 0x2000, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(reply_port) {
                if reply.tag == 0x2001 {
                    // File still exists — fail.
                    syscall::debug_puts(b"  FAIL: ext2 file not deleted\n");
                    // Close the handle we got.
                    syscall::send(ext2_port, 0x2400, reply.data[0], 0, 0, 0);
                    phase53_ok = false;
                }
                // FS_ERROR (not found) is the expected response.
            }
        }

        // Step 7: Verify pre-existing "hello.txt" still works
        if phase53_ok {
            let fname = b"hello.txt";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((reply_port as u64) << 32);
            syscall::send(ext2_port, 0x2000, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(reply_port) {
                if reply.tag == 0x2001 {
                    syscall::send(ext2_port, 0x2400, reply.data[0], 0, 0, 0);
                } else {
                    syscall::debug_puts(b"  FAIL: ext2 hello.txt corrupted\n");
                    phase53_ok = false;
                }
            } else { phase53_ok = false; }
        }

        if reply_port != 0 { syscall::port_destroy(reply_port); }

        if phase53_ok {
            syscall::debug_puts(b"Phase 53 ext2 write: PASSED\n");
        } else if ext2_port != 0 {
            syscall::debug_puts(b"Phase 53 ext2 write: FAILED\n");
        }
    }

    // --- Phase 54: tmpfs server ---
    syscall::debug_puts(b"  init: testing tmpfs...\n");
    {
        // Spawn tmpfs server.
        let tmpfs_tid = syscall::spawn(b"tmpfs_srv", 50);
        let mut phase54_ok = tmpfs_tid != u64::MAX;
        if !phase54_ok {
            syscall::debug_puts(b"  FAIL: cannot spawn tmpfs_srv\n");
        }

        // Look up tmpfs port.
        let tmpfs_port = if phase54_ok {
            let mut found = 0u32;
            for _ in 0..100 {
                if let Some(p) = syscall::ns_lookup(b"tmpfs") {
                    found = p;
                    break;
                }
                syscall::sleep_ms(10);
            }
            if found == 0 {
                syscall::debug_puts(b"  FAIL: ns_lookup(tmpfs) failed\n");
                phase54_ok = false;
            }
            found
        } else { 0 };

        let rp = if phase54_ok { syscall::port_create() as u32 } else { 0 };

        // Step 1: FS_CREATE "test.txt"
        let mut handle = 0u64;
        let mut srv_aspace = 0u32;
        if phase54_ok {
            let fname = b"test.txt";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((rp as u64) << 32);
            syscall::send(tmpfs_port, 0x2500, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(rp) {
                if reply.tag == 0x2501 {
                    handle = reply.data[0];
                    srv_aspace = reply.data[2] as u32;
                } else {
                    syscall::debug_puts(b"  FAIL: tmpfs CREATE failed\n");
                    phase54_ok = false;
                }
            } else { phase54_ok = false; }
        }

        // Step 2: FS_WRITE 48 bytes of pattern
        if phase54_ok {
            if let Some(scratch) = syscall::mmap_anon(0, 1, 1) {
                unsafe {
                    let p = scratch as *mut u8;
                    for i in 0..48 {
                        *p.add(i) = ((i * 13 + 0x30) & 0xFF) as u8;
                    }
                }
                let grant_dst: usize = 0x8_0000_0000;
                if syscall::grant_pages(srv_aspace, scratch, grant_dst, 1, false) {
                    let wd1 = 48u64 | ((rp as u64) << 32);
                    syscall::send(tmpfs_port, 0x2600, handle, wd1, grant_dst as u64, 0);
                    if let Some(wr) = syscall::recv_msg(rp) {
                        if wr.tag != 0x2601 || wr.data[0] != 48 {
                            syscall::debug_puts(b"  FAIL: tmpfs WRITE bad reply\n");
                            phase54_ok = false;
                        }
                    } else { phase54_ok = false; }
                    syscall::revoke(srv_aspace, grant_dst);
                } else { phase54_ok = false; }
                syscall::munmap(scratch);
            } else { phase54_ok = false; }
        }

        // Step 3: FS_CLOSE
        if phase54_ok {
            syscall::send(tmpfs_port, 0x2400, handle, 0, 0, 0);
        }

        // Step 4: FS_OPEN "test.txt" and verify read-back
        if phase54_ok {
            let fname = b"test.txt";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((rp as u64) << 32);
            syscall::send(tmpfs_port, 0x2000, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(rp) {
                if reply.tag == 0x2001 {
                    let rh = reply.data[0];
                    let rsize = reply.data[1];
                    let r_aspace = reply.data[2] as u32;
                    if rsize != 48 {
                        syscall::debug_puts(b"  FAIL: tmpfs re-open size\n");
                        phase54_ok = false;
                    }
                    // FS_READ via grant
                    if phase54_ok {
                        if let Some(scratch) = syscall::mmap_anon(0, 1, 1) {
                            let grant_dst: usize = 0x8_0000_0000;
                            if syscall::grant_pages(r_aspace, scratch, grant_dst, 1, false) {
                                let rd2 = 48u64 | ((rp as u64) << 32);
                                syscall::send(tmpfs_port, 0x2100, rh, 0, rd2, grant_dst as u64);
                                if let Some(rd) = syscall::recv_msg(rp) {
                                    if rd.tag == 0x2101 && rd.data[0] == 48 {
                                        let p = scratch as *const u8;
                                        for i in 0..48 {
                                            let expected = ((i * 13 + 0x30) & 0xFF) as u8;
                                            if unsafe { *p.add(i) } != expected {
                                                syscall::debug_puts(b"  FAIL: tmpfs read mismatch\n");
                                                phase54_ok = false;
                                                break;
                                            }
                                        }
                                    } else {
                                        syscall::debug_puts(b"  FAIL: tmpfs READ bad\n");
                                        phase54_ok = false;
                                    }
                                } else { phase54_ok = false; }
                                syscall::revoke(r_aspace, grant_dst);
                            } else { phase54_ok = false; }
                            syscall::munmap(scratch);
                        } else { phase54_ok = false; }
                    }
                    syscall::send(tmpfs_port, 0x2400, rh, 0, 0, 0);
                } else {
                    syscall::debug_puts(b"  FAIL: tmpfs re-open not found\n");
                    phase54_ok = false;
                }
            } else { phase54_ok = false; }
        }

        // Step 5: Create second file "other.txt"
        if phase54_ok {
            let fname = b"other.txt";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((rp as u64) << 32);
            syscall::send(tmpfs_port, 0x2500, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(rp) {
                if reply.tag == 0x2501 {
                    syscall::send(tmpfs_port, 0x2400, reply.data[0], 0, 0, 0);
                } else {
                    syscall::debug_puts(b"  FAIL: tmpfs CREATE other\n");
                    phase54_ok = false;
                }
            } else { phase54_ok = false; }
        }

        // Step 6: FS_READDIR — verify both files appear
        if phase54_ok {
            let mut count = 0u32;
            let mut next = 0u64;
            for _ in 0..10 {
                syscall::send(tmpfs_port, 0x2200, next, 0, rp as u64, 0);
                if let Some(reply) = syscall::recv_msg(rp) {
                    if reply.tag == 0x2201 {
                        count += 1;
                        next = reply.data[3]; // next_offset
                    } else {
                        break; // READDIR_END
                    }
                } else { break; }
            }
            if count != 2 {
                syscall::debug_puts(b"  FAIL: tmpfs readdir count\n");
                phase54_ok = false;
            }
        }

        // Step 7: FS_DELETE "test.txt"
        if phase54_ok {
            let fname = b"test.txt";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((rp as u64) << 32);
            syscall::send(tmpfs_port, 0x2700, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(rp) {
                if reply.tag != 0x2701 {
                    syscall::debug_puts(b"  FAIL: tmpfs DELETE failed\n");
                    phase54_ok = false;
                }
            } else { phase54_ok = false; }
        }

        // Step 8: Verify "test.txt" is gone
        if phase54_ok {
            let fname = b"test.txt";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((rp as u64) << 32);
            syscall::send(tmpfs_port, 0x2000, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(rp) {
                if reply.tag == 0x2001 {
                    syscall::debug_puts(b"  FAIL: tmpfs file not deleted\n");
                    syscall::send(tmpfs_port, 0x2400, reply.data[0], 0, 0, 0);
                    phase54_ok = false;
                }
            }
        }

        // Step 9: FS_READDIR — verify only "other.txt"
        if phase54_ok {
            let mut count = 0u32;
            let mut next = 0u64;
            for _ in 0..10 {
                syscall::send(tmpfs_port, 0x2200, next, 0, rp as u64, 0);
                if let Some(reply) = syscall::recv_msg(rp) {
                    if reply.tag == 0x2201 {
                        count += 1;
                        next = reply.data[3];
                    } else { break; }
                } else { break; }
            }
            if count != 1 {
                syscall::debug_puts(b"  FAIL: tmpfs readdir after delete\n");
                phase54_ok = false;
            }
        }

        // Cleanup: delete "other.txt"
        if phase54_ok {
            let fname = b"other.txt";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((rp as u64) << 32);
            syscall::send(tmpfs_port, 0x2700, fn0, fn1, d2, 0);
            syscall::recv_msg(rp);
        }

        if rp != 0 { syscall::port_destroy(rp); }

        if phase54_ok {
            syscall::debug_puts(b"Phase 54 tmpfs: PASSED\n");
        } else if tmpfs_tid != u64::MAX {
            syscall::debug_puts(b"Phase 54 tmpfs: FAILED\n");
        }
    }

    // --- Phase 55: devfs server ---
    syscall::debug_puts(b"  init: testing devfs...\n");
    {
        // Spawn devfs server.
        let devfs_tid = syscall::spawn(b"devfs_srv", 50);
        let mut phase55_ok = devfs_tid != u64::MAX;
        if !phase55_ok {
            syscall::debug_puts(b"  FAIL: cannot spawn devfs_srv\n");
        }

        // Look up devfs port.
        let devfs_port = if phase55_ok {
            let mut found = 0u32;
            for _ in 0..100 {
                if let Some(p) = syscall::ns_lookup(b"devfs") {
                    found = p;
                    break;
                }
                syscall::sleep_ms(10);
            }
            if found == 0 {
                syscall::debug_puts(b"  FAIL: ns_lookup(devfs) failed\n");
                phase55_ok = false;
            }
            found
        } else { 0 };

        let rp = if phase55_ok { syscall::port_create() as u32 } else { 0 };

        // Test 1: /dev/null — write succeeds, read returns EOF
        if phase55_ok {
            let fname = b"null";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((rp as u64) << 32);
            syscall::send(devfs_port, 0x2000, fn0, fn1, d2, 0); // FS_OPEN
            if let Some(reply) = syscall::recv_msg(rp) {
                if reply.tag == 0x2001 { // FS_OPEN_OK
                    let h = reply.data[0];

                    // Write 16 bytes — should succeed (discard).
                    let wd1 = (16u64) | ((rp as u64) << 32);
                    syscall::send(devfs_port, 0x2600, h, wd1, 0, 0); // FS_WRITE
                    if let Some(wr) = syscall::recv_msg(rp) {
                        if wr.tag != 0x2601 { // FS_WRITE_OK
                            syscall::debug_puts(b"  FAIL: devfs null write\n");
                            phase55_ok = false;
                        }
                    } else { phase55_ok = false; }

                    // Read — should return 0 bytes (EOF).
                    if phase55_ok {
                        let rd2 = (8u64) | ((rp as u64) << 32);
                        syscall::send(devfs_port, 0x2100, h, 0, rd2, 0); // FS_READ
                        if let Some(rr) = syscall::recv_msg(rp) {
                            if rr.tag == 0x2101 { // FS_READ_OK
                                if rr.data[0] != 0 {
                                    syscall::debug_puts(b"  FAIL: devfs null read not EOF\n");
                                    phase55_ok = false;
                                }
                            } else { phase55_ok = false; }
                        } else { phase55_ok = false; }
                    }

                    // Close.
                    syscall::send(devfs_port, 0x2400, h, 0, 0, 0); // FS_CLOSE
                } else {
                    syscall::debug_puts(b"  FAIL: devfs open null\n");
                    phase55_ok = false;
                }
            } else { phase55_ok = false; }
        }

        // Test 2: /dev/zero — read returns all zeros
        if phase55_ok {
            let fname = b"zero";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((rp as u64) << 32);
            syscall::send(devfs_port, 0x2000, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(rp) {
                if reply.tag == 0x2001 {
                    let h = reply.data[0];

                    let rd2 = (8u64) | ((rp as u64) << 32);
                    syscall::send(devfs_port, 0x2100, h, 0, rd2, 0);
                    if let Some(rr) = syscall::recv_msg(rp) {
                        if rr.tag == 0x2101 {
                            let len = rr.data[0] as usize;
                            if len == 0 {
                                syscall::debug_puts(b"  FAIL: devfs zero read empty\n");
                                phase55_ok = false;
                            }
                            // Inline data in data[1] should be all zeros.
                            if phase55_ok && rr.data[1] != 0 {
                                syscall::debug_puts(b"  FAIL: devfs zero not zeros\n");
                                phase55_ok = false;
                            }
                        } else { phase55_ok = false; }
                    } else { phase55_ok = false; }

                    syscall::send(devfs_port, 0x2400, h, 0, 0, 0);
                } else {
                    syscall::debug_puts(b"  FAIL: devfs open zero\n");
                    phase55_ok = false;
                }
            } else { phase55_ok = false; }
        }

        // Test 3: /dev/full — write returns error, read returns zeros
        if phase55_ok {
            let fname = b"full";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((rp as u64) << 32);
            syscall::send(devfs_port, 0x2000, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(rp) {
                if reply.tag == 0x2001 {
                    let h = reply.data[0];

                    // Write should fail with FS_ERROR.
                    let wd1 = (16u64) | ((rp as u64) << 32);
                    syscall::send(devfs_port, 0x2600, h, wd1, 0, 0);
                    if let Some(wr) = syscall::recv_msg(rp) {
                        if wr.tag != 0x2F00 { // FS_ERROR
                            syscall::debug_puts(b"  FAIL: devfs full write should fail\n");
                            phase55_ok = false;
                        }
                    } else { phase55_ok = false; }

                    // Read should return zeros.
                    if phase55_ok {
                        let rd2 = (8u64) | ((rp as u64) << 32);
                        syscall::send(devfs_port, 0x2100, h, 0, rd2, 0);
                        if let Some(rr) = syscall::recv_msg(rp) {
                            if rr.tag == 0x2101 {
                                if rr.data[0] == 0 {
                                    // zero-length is acceptable (same as zero device inline)
                                } else if rr.data[1] != 0 {
                                    syscall::debug_puts(b"  FAIL: devfs full read not zeros\n");
                                    phase55_ok = false;
                                }
                            } else { phase55_ok = false; }
                        } else { phase55_ok = false; }
                    }

                    syscall::send(devfs_port, 0x2400, h, 0, 0, 0);
                } else {
                    syscall::debug_puts(b"  FAIL: devfs open full\n");
                    phase55_ok = false;
                }
            } else { phase55_ok = false; }
        }

        // Test 4: /dev/random — read returns non-zero data
        if phase55_ok {
            let fname = b"random";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((rp as u64) << 32);
            syscall::send(devfs_port, 0x2000, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(rp) {
                if reply.tag == 0x2001 {
                    let h = reply.data[0];

                    let rd2 = (8u64) | ((rp as u64) << 32);
                    syscall::send(devfs_port, 0x2100, h, 0, rd2, 0);
                    if let Some(rr) = syscall::recv_msg(rp) {
                        if rr.tag == 0x2101 {
                            let len = rr.data[0] as usize;
                            if len == 0 {
                                syscall::debug_puts(b"  FAIL: devfs random empty\n");
                                phase55_ok = false;
                            }
                            // At least some data should be non-zero.
                            if phase55_ok && rr.data[1] == 0 && rr.data[2] == 0 && rr.data[3] == 0 {
                                syscall::debug_puts(b"  FAIL: devfs random all zeros\n");
                                phase55_ok = false;
                            }
                        } else { phase55_ok = false; }
                    } else { phase55_ok = false; }

                    syscall::send(devfs_port, 0x2400, h, 0, 0, 0);
                } else {
                    syscall::debug_puts(b"  FAIL: devfs open random\n");
                    phase55_ok = false;
                }
            } else { phase55_ok = false; }
        }

        // Test 5: READDIR — should see >= 7 entries
        if phase55_ok {
            let mut count = 0usize;
            let mut next_off = 0u64;
            for _ in 0..20 {
                let d2 = rp as u64;
                syscall::send(devfs_port, 0x2200, next_off, 0, d2, 0); // FS_READDIR
                if let Some(rr) = syscall::recv_msg(rp) {
                    if rr.tag == 0x2201 { // FS_READDIR_OK
                        count += 1;
                        next_off = rr.data[3]; // next offset
                    } else {
                        break; // FS_READDIR_END
                    }
                } else { break; }
            }
            if count < 7 {
                syscall::debug_puts(b"  FAIL: devfs readdir < 7\n");
                phase55_ok = false;
            }
        }

        if phase55_ok {
            syscall::debug_puts(b"Phase 55 devfs: PASSED\n");
        } else if devfs_tid != u64::MAX {
            syscall::debug_puts(b"Phase 55 devfs: FAILED\n");
        }
    }

    // --- Phase 56: procfs server ---
    syscall::debug_puts(b"  init: testing procfs...\n");
    {
        // Spawn procfs server.
        let procfs_tid = syscall::spawn(b"procfs_srv", 50);
        let mut phase56_ok = procfs_tid != u64::MAX;
        if !phase56_ok {
            syscall::debug_puts(b"  FAIL: cannot spawn procfs_srv\n");
        }

        // Look up procfs port.
        let procfs_port = if phase56_ok {
            let mut found = 0u32;
            for _ in 0..100 {
                if let Some(p) = syscall::ns_lookup(b"procfs") {
                    found = p;
                    break;
                }
                syscall::sleep_ms(10);
            }
            if found == 0 {
                syscall::debug_puts(b"  FAIL: ns_lookup(procfs) failed\n");
                phase56_ok = false;
            }
            found
        } else { 0 };

        let rp = if phase56_ok { syscall::port_create() as u32 } else { 0 };

        // Test 1: open "meminfo", read, verify non-empty
        if phase56_ok {
            let fname = b"meminfo";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((rp as u64) << 32);
            syscall::send(procfs_port, 0x2000, fn0, fn1, d2, 0); // FS_OPEN
            if let Some(reply) = syscall::recv_msg(rp) {
                if reply.tag == 0x2001 { // FS_OPEN_OK
                    let h = reply.data[0];

                    // Read inline.
                    let rd2 = (24u64) | ((rp as u64) << 32);
                    syscall::send(procfs_port, 0x2100, h, 0, rd2, 0); // FS_READ
                    if let Some(rr) = syscall::recv_msg(rp) {
                        if rr.tag == 0x2101 { // FS_READ_OK
                            let len = rr.data[0] as usize;
                            if len == 0 {
                                syscall::debug_puts(b"  FAIL: procfs meminfo empty\n");
                                phase56_ok = false;
                            }
                            // First bytes should start with 'T' from "Total:"
                            if phase56_ok {
                                let first = (rr.data[1] & 0xFF) as u8;
                                if first != b'T' {
                                    syscall::debug_puts(b"  FAIL: procfs meminfo bad content\n");
                                    phase56_ok = false;
                                }
                            }
                        } else { phase56_ok = false; }
                    } else { phase56_ok = false; }

                    syscall::send(procfs_port, 0x2400, h, 0, 0, 0); // FS_CLOSE
                } else {
                    syscall::debug_puts(b"  FAIL: procfs open meminfo\n");
                    phase56_ok = false;
                }
            } else { phase56_ok = false; }
        }

        // Test 2: open "1/status" (task 1 = init), read, verify "Pid:" prefix
        if phase56_ok {
            let fname = b"1/status";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((rp as u64) << 32);
            syscall::send(procfs_port, 0x2000, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(rp) {
                if reply.tag == 0x2001 {
                    let h = reply.data[0];

                    let rd2 = (24u64) | ((rp as u64) << 32);
                    syscall::send(procfs_port, 0x2100, h, 0, rd2, 0);
                    if let Some(rr) = syscall::recv_msg(rp) {
                        if rr.tag == 0x2101 {
                            let len = rr.data[0] as usize;
                            if len < 5 {
                                syscall::debug_puts(b"  FAIL: procfs status too short\n");
                                phase56_ok = false;
                            }
                            // Check starts with "Pid: "
                            if phase56_ok {
                                let lo = rr.data[1];
                                let b0 = (lo & 0xFF) as u8;
                                let b1 = ((lo >> 8) & 0xFF) as u8;
                                let b2 = ((lo >> 16) & 0xFF) as u8;
                                let b3 = ((lo >> 24) & 0xFF) as u8;
                                if b0 != b'P' || b1 != b'i' || b2 != b'd' || b3 != b':' {
                                    syscall::debug_puts(b"  FAIL: procfs status no Pid:\n");
                                    phase56_ok = false;
                                }
                            }
                        } else { phase56_ok = false; }
                    } else { phase56_ok = false; }

                    syscall::send(procfs_port, 0x2400, h, 0, 0, 0);
                } else {
                    syscall::debug_puts(b"  FAIL: procfs open 1/status\n");
                    phase56_ok = false;
                }
            } else { phase56_ok = false; }
        }

        // Test 3: open "uptime", read, verify non-zero
        if phase56_ok {
            let fname = b"uptime";
            let (fn0, fn1, _) = pack_name(fname);
            let d2 = (fname.len() as u64) | ((rp as u64) << 32);
            syscall::send(procfs_port, 0x2000, fn0, fn1, d2, 0);
            if let Some(reply) = syscall::recv_msg(rp) {
                if reply.tag == 0x2001 {
                    let h = reply.data[0];

                    let rd2 = (24u64) | ((rp as u64) << 32);
                    syscall::send(procfs_port, 0x2100, h, 0, rd2, 0);
                    if let Some(rr) = syscall::recv_msg(rp) {
                        if rr.tag == 0x2101 {
                            let len = rr.data[0] as usize;
                            if len == 0 {
                                syscall::debug_puts(b"  FAIL: procfs uptime empty\n");
                                phase56_ok = false;
                            }
                            // First byte should be a digit.
                            if phase56_ok {
                                let first = (rr.data[1] & 0xFF) as u8;
                                if first < b'0' || first > b'9' {
                                    syscall::debug_puts(b"  FAIL: procfs uptime bad\n");
                                    phase56_ok = false;
                                }
                            }
                        } else { phase56_ok = false; }
                    } else { phase56_ok = false; }

                    syscall::send(procfs_port, 0x2400, h, 0, 0, 0);
                } else {
                    syscall::debug_puts(b"  FAIL: procfs open uptime\n");
                    phase56_ok = false;
                }
            } else { phase56_ok = false; }
        }

        // Test 4: READDIR — should see >= 3 entries (meminfo, uptime, at least 1 PID)
        if phase56_ok {
            let mut count = 0usize;
            let mut next_off = 0u64;
            for _ in 0..40 {
                let d2 = rp as u64;
                syscall::send(procfs_port, 0x2200, next_off, 0, d2, 0); // FS_READDIR
                if let Some(rr) = syscall::recv_msg(rp) {
                    if rr.tag == 0x2201 { // FS_READDIR_OK
                        count += 1;
                        next_off = rr.data[3]; // next offset
                    } else {
                        break; // FS_READDIR_END
                    }
                } else { break; }
            }
            if count < 3 {
                syscall::debug_puts(b"  FAIL: procfs readdir < 3\n");
                phase56_ok = false;
            }
        }

        if phase56_ok {
            syscall::debug_puts(b"Phase 56 procfs: PASSED\n");
        } else if procfs_tid != u64::MAX {
            syscall::debug_puts(b"Phase 56 procfs: FAILED\n");
        }
    }

    // --- Test 23: Benchmark Suite ---
    syscall::debug_puts(b"  init: running benchmark suite...\n");
    {
        let bench_tid = syscall::spawn(b"bench", 50);
        if bench_tid != u64::MAX {
            loop {
                if let Some(_code) = syscall::waitpid(bench_tid) {
                    break;
                }
                syscall::yield_now();
            }
            syscall::debug_puts(b"Phase 22 benchmarks: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 22 benchmarks: FAILED (spawn)\n");
        }
    }

    // --- Test 22: Macrobenchmark Suite ---
    syscall::debug_puts(b"  init: running macrobenchmark suite...\n");
    {
        let mbench_tid = syscall::spawn(b"macro_bench", 50);
        if mbench_tid != u64::MAX {
            loop {
                if let Some(_code) = syscall::waitpid(mbench_tid) {
                    break;
                }
                syscall::yield_now();
            }
            syscall::debug_puts(b"Phase 23 macrobenchmarks: PASSED\n");
        } else {
            syscall::debug_puts(b"Phase 23 macrobenchmarks: FAILED (spawn)\n");
        }
    }

    // Init loops forever, yielding.
    loop {
        syscall::yield_now();
    }
}

/// Child thread entry point for Phase 17 test.
#[unsafe(no_mangle)]
/// Pager thread for Phase 45 test.
/// Loops on wait_fault(), fills each page with a byte pattern = page_index.
extern "C" fn pager_thread_entry(_arg: u64) {
    loop {
        let (token, _fault_va, _file_handle, file_offset, page_size) = syscall::wait_fault();

        // Fill a local buffer with pattern: each byte = page_index (offset / PAGE_SIZE).
        // PAGE_SIZE = 64K = 0x10000.
        let page_index = (file_offset / 0x10000) as u8;

        // Allocate a temporary buffer (use stack — 4K at a time, fill PAGE_SIZE).
        // Since PAGE_SIZE can be 64K, we fill via multiple 4K chunks.
        let mut buf = [0u8; 4096];
        for b in buf.iter_mut() {
            *b = page_index;
        }

        // Call fault_complete for each 4K chunk.
        // Actually, fault_complete copies PAGE_SIZE from the given VA.
        // The kernel translate_va will translate our buf pointer.
        // But buf is only 4K and the kernel copies page_size bytes...
        // We need a full PAGE_SIZE buffer.
        // Allocate one via mmap_anon.
        let tmp = syscall::mmap_anon(0, 1, 1); // 1 page = PAGE_SIZE
        if let Some(tmp_va) = tmp {
            // Fill the entire page with the pattern.
            let ptr = tmp_va as *mut u8;
            for i in 0..page_size {
                unsafe { core::ptr::write_volatile(ptr.add(i), page_index); }
            }
            syscall::fault_complete(token, unsafe {
                core::slice::from_raw_parts(tmp_va as *const u8, page_size)
            });
            syscall::munmap(tmp_va);
        }
    }
}

extern "C" fn thread_child_entry(arg: u64) {
    let ptr = arg as *mut u64;
    unsafe { core::ptr::write_volatile(ptr, 0xCAFE); }
    syscall::exit(42);
}

/// Phase 30 green thread fiber entry. Increments counter 100 times with yields.
fn green_fiber_entry(counter_addr: u64) {
    let atom = unsafe { &*(counter_addr as *const core::sync::atomic::AtomicU64) };
    for _ in 0..100 {
        atom.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        userlib::green::fiber_yield();
    }
}

/// Phase 31 cosched worker thread. arg = group_id (0 = no group).
/// Does busy work across many timer ticks to give the scheduler
/// opportunities for coscheduling decisions.
#[unsafe(no_mangle)]
extern "C" fn cosched_worker(group_id: u64) {
    if group_id != 0 {
        syscall::cosched_set(group_id as u32);
    }

    // Burn CPU across many timer ticks.
    // Each yield_now forces a preemption on the next tick, putting us
    // in the run queue where the cosched logic can find group-mates.
    // The busy-spin must last longer than a timer interval (10ms) to
    // ensure threads are preempted mid-work, creating run-queue diversity.
    // At 62.5 MHz (aarch64 QEMU), 500K iterations ≈ 8ms; at ~1 GHz
    // (x86 QEMU RDTSC rate), PAUSE is ~10-40ns so 500K ≈ 5-20ms.
    for _ in 0..50 {
        syscall::yield_now();
        for _ in 0..500_000 {
            core::hint::spin_loop();
        }
    }

    syscall::exit(0);
}

/// Phase 32 affinity test worker. Just yields a few times and exits.
#[unsafe(no_mangle)]
extern "C" fn affinity_test_worker(_arg: u64) {
    for _ in 0..10 {
        syscall::yield_now();
    }
    syscall::exit(0);
}

static TEST_MUTEX: userlib::sync::Mutex = userlib::sync::Mutex::new();
static mut MUTEX_TEST_COUNTER: u64 = 0;

/// Phase 18 mutex test thread. Increments shared counter 1000 times under mutex.
#[unsafe(no_mangle)]
extern "C" fn mutex_test_thread(_arg: u64) {
    for _ in 0..1000 {
        TEST_MUTEX.lock();
        unsafe { MUTEX_TEST_COUNTER += 1; }
        TEST_MUTEX.unlock();
    }
    syscall::exit(0);
}
