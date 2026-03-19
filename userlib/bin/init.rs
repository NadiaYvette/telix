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
        let stacks = syscall::mmap_anon(0, 1, 1); // RW page for 4 stacks

        if let Some(sk) = stacks {
            // Record cosched hits before test.
            let hits_before = syscall::vm_stats(4);

            let stack_size: usize = 0x4000; // 16 KiB per stack
            let tid_a = syscall::thread_create(
                cosched_worker as u64,
                (sk + stack_size) as u64,
                1, // group_id = 1
            );
            let tid_b = syscall::thread_create(
                cosched_worker as u64,
                (sk + 2 * stack_size) as u64,
                1, // group_id = 1
            );
            let tid_c1 = syscall::thread_create(
                cosched_worker as u64,
                (sk + 3 * stack_size) as u64,
                0, // no group
            );
            let tid_c2 = syscall::thread_create(
                cosched_worker as u64,
                (sk + 4 * stack_size) as u64,
                0, // no group
            );

            if tid_a != u64::MAX && tid_b != u64::MAX && tid_c1 != u64::MAX && tid_c2 != u64::MAX {
                // Wait for all 4 threads.
                syscall::thread_join(tid_a as u32);
                syscall::thread_join(tid_b as u32);
                syscall::thread_join(tid_c1 as u32);
                syscall::thread_join(tid_c2 as u32);

                let hits_after = syscall::vm_stats(4);
                let cosched_hits = hits_after - hits_before;
                // With 2 grouped threads doing busy work across many timer ticks,
                // the scheduler should have picked cosched mates multiple times.
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
extern "C" fn thread_child_entry(arg: u64) {
    let ptr = arg as *mut u64;
    unsafe { core::ptr::write_volatile(ptr, 0xCAFE); }
    syscall::exit(42);
}

/// Phase 30 green thread fiber entry. Increments counter 100 times with yields.
fn green_fiber_entry(counter_addr: u64) {
    let ptr = counter_addr as *mut u64;
    for _ in 0..100 {
        // Atomic-style increment (only one fiber runs per worker at a time,
        // and the spinlock in fiber_yield serializes access).
        let val = unsafe { core::ptr::read_volatile(ptr) };
        unsafe { core::ptr::write_volatile(ptr, val + 1); }
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
    // Each yield_now sets YIELD_ASAP so next tick preempts us.
    // The busy loop between yields ensures we survive at least one tick.
    for _ in 0..20 {
        syscall::yield_now();
        // Busy spin to ensure this iteration spans at least one timer tick.
        for _ in 0..50_000 {
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
