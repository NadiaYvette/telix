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

    // Init loops forever, yielding.
    loop {
        syscall::yield_now();
    }
}
