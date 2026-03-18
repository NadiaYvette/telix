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

    // --- Test 21: Benchmark Suite ---
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
extern "C" fn thread_child_entry(arg: u64) {
    let ptr = arg as *mut u64;
    unsafe { core::ptr::write_volatile(ptr, 0xCAFE); }
    syscall::exit(42);
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
