#![no_std]
#![no_main]

//! Telix macrobenchmark suite. Exercises the full multi-server I/O pipeline:
//! app → fat16_srv (IPC + FAT chain walk) → blk_srv (IPC + grant) → virtio DMA.

extern crate userlib;

use userlib::syscall;

// FS protocol constants.
const FS_OPEN: u64 = 0x2000;
const FS_OPEN_OK: u64 = 0x2001;
const FS_READ: u64 = 0x2100;
const FS_READ_OK: u64 = 0x2101;
const FS_CLOSE: u64 = 0x2400;
const FS_CREATE: u64 = 0x2500;
const FS_CREATE_OK: u64 = 0x2501;
const FS_WRITE: u64 = 0x2600;
const FS_WRITE_OK: u64 = 0x2601;
const FS_DELETE: u64 = 0x2700;
const FS_DELETE_OK: u64 = 0x2701;
const FS_ERROR: u64 = 0x2F00;

const GRANT_DST: usize = 0xB_0000_0000;

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

fn print_throughput(name: &[u8], total_bytes: u64, total_cycles: u64, freq: u64, iters: u64) {
    // KB/s = total_bytes * freq / total_cycles / 1024
    let kbs = if total_cycles > 0 {
        total_bytes * (freq / 1024) / total_cycles
    } else {
        0
    };
    syscall::debug_puts(b"  macro: ");
    syscall::debug_puts(name);
    syscall::debug_puts(b": ");
    print_num(total_bytes);
    syscall::debug_puts(b" B in ");
    print_num(total_cycles);
    syscall::debug_puts(b" cy (");
    print_num(kbs);
    syscall::debug_puts(b" KB/s, ");
    print_num(iters);
    syscall::debug_puts(b" iters)\n");
}

fn print_opsec(name: &[u8], total_cycles: u64, freq: u64, iters: u64) {
    let per_iter = if iters > 0 { total_cycles / iters } else { 0 };
    let ops = if total_cycles > 0 { iters * freq / total_cycles } else { 0 };
    syscall::debug_puts(b"  macro: ");
    syscall::debug_puts(name);
    syscall::debug_puts(b": ");
    print_num(total_cycles);
    syscall::debug_puts(b" cy / ");
    print_num(iters);
    syscall::debug_puts(b" = ");
    print_num(per_iter);
    syscall::debug_puts(b" cy/op (");
    print_num(ops);
    syscall::debug_puts(b" ops/s)\n");
}

/// Open a file on the given fat16 port. Returns (handle, file_size, srv_aspace) or None.
fn fs_open(fat_port: u64, name: &[u8]) -> Option<(u64, u32, u32)> {
    let reply_port = syscall::port_create();
    let (n0, n1, _) = syscall::pack_name(name);
    let d2 = (name.len() as u64) | ((reply_port) << 32);
    syscall::send(fat_port, FS_OPEN, n0, n1, d2, 0);
    let result = if let Some(msg) = syscall::recv_msg(reply_port) {
        if msg.tag == FS_OPEN_OK {
            Some((msg.data[0], msg.data[1] as u32, msg.data[2] as u32))
        } else {
            None
        }
    } else {
        None
    };
    syscall::port_destroy(reply_port);
    result
}

/// Grant-based read: reads `length` bytes at `offset` from handle into scratch_va.
/// Returns bytes read, or 0 on error.
fn fs_read_grant(fat_port: u64, handle: u64, offset: u32, length: u32,
                 srv_aspace: u32, scratch_va: usize) -> u32 {
    let reply_port = syscall::port_create();
    // Grant our scratch page to fat16_srv.
    if !syscall::grant_pages(srv_aspace, scratch_va, GRANT_DST, 1, false) {
        syscall::port_destroy(reply_port);
        return 0;
    }
    let d2 = (length as u64) | ((reply_port) << 32);
    syscall::send(fat_port, FS_READ, handle, offset as u64, d2, GRANT_DST as u64);
    let bytes = if let Some(msg) = syscall::recv_msg(reply_port) {
        if msg.tag == FS_READ_OK { msg.data[0] as u32 } else { 0 }
    } else {
        0
    };
    syscall::revoke(srv_aspace, GRANT_DST);
    syscall::port_destroy(reply_port);
    bytes
}

/// Create a file. Returns (handle, srv_aspace) or None.
fn fs_create(fat_port: u64, name: &[u8]) -> Option<(u64, u32)> {
    let reply_port = syscall::port_create();
    let (n0, n1, _) = syscall::pack_name(name);
    let d2 = (name.len() as u64) | ((reply_port) << 32);
    syscall::send(fat_port, FS_CREATE, n0, n1, d2, 0);
    let result = if let Some(msg) = syscall::recv_msg(reply_port) {
        if msg.tag == FS_CREATE_OK {
            Some((msg.data[0], msg.data[2] as u32))
        } else {
            None
        }
    } else {
        None
    };
    syscall::port_destroy(reply_port);
    result
}

/// Grant-based write: writes `length` bytes from scratch_va to handle.
/// Returns bytes written.
fn fs_write_grant(fat_port: u64, handle: u64, length: u32,
                  srv_aspace: u32, scratch_va: usize) -> u32 {
    let reply_port = syscall::port_create();
    if !syscall::grant_pages(srv_aspace, scratch_va, GRANT_DST, 1, false) {
        syscall::port_destroy(reply_port);
        return 0;
    }
    let d1 = (length as u64) | ((reply_port) << 32);
    syscall::send(fat_port, FS_WRITE, handle, d1, GRANT_DST as u64, 0);
    let written = if let Some(msg) = syscall::recv_msg(reply_port) {
        if msg.tag == FS_WRITE_OK { msg.data[0] as u32 } else { 0 }
    } else {
        0
    };
    syscall::revoke(srv_aspace, GRANT_DST);
    syscall::port_destroy(reply_port);
    written
}

/// Close a file handle.
fn fs_close(fat_port: u64, handle: u64) {
    syscall::send_nb(fat_port, FS_CLOSE, handle, 0);
    // Give time for close + flush.
    for _ in 0..500 { syscall::yield_now(); }
}

/// Delete a file by name.
fn fs_delete(fat_port: u64, name: &[u8]) -> bool {
    let reply_port = syscall::port_create();
    let (n0, n1, _) = syscall::pack_name(name);
    let d2 = (name.len() as u64) | ((reply_port) << 32);
    syscall::send(fat_port, FS_DELETE, n0, n1, d2, 0);
    let ok = if let Some(msg) = syscall::recv_msg(reply_port) {
        msg.tag == FS_DELETE_OK
    } else {
        false
    };
    syscall::port_destroy(reply_port);
    ok
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"=== Telix Macrobenchmark Suite ===\n");

    let freq = syscall::get_timer_freq();
    syscall::debug_puts(b"  macro: timer freq = ");
    print_num(freq);
    syscall::debug_puts(b" Hz\n");

    // Look up fat16 server.
    let fat_port = loop {
        if let Some(p) = syscall::ns_lookup(b"fat16") {
            break p;
        }
        for _ in 0..100 { syscall::yield_now(); }
    };

    // Allocate scratch page for grant-based I/O.
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  macro: scratch alloc FAILED\n");
            syscall::exit(1);
        }
    };

    // --- Macro 1: Sequential File Read Throughput (seq_read_32k) ---
    {
        const ITERS: u64 = 10;
        const FILE_SIZE: u32 = 32768;

        if let Some((handle, fsize, srv_aspace)) = fs_open(fat_port, b"BENCH.DAT") {
            if fsize != FILE_SIZE {
                syscall::debug_puts(b"  macro: seq_read_32k: BENCH.DAT size mismatch (");
                print_num(fsize as u64);
                syscall::debug_puts(b" != 32768)\n");
            } else {
                let t0 = syscall::get_cycles();
                let mut total_bytes: u64 = 0;
                for _ in 0..ITERS {
                    let mut offset: u32 = 0;
                    while offset < FILE_SIZE {
                        let to_read = 512u32.min(FILE_SIZE - offset);
                        let got = fs_read_grant(fat_port, handle, offset, to_read, srv_aspace, scratch_va);
                        if got == 0 { break; }
                        total_bytes += got as u64;
                        offset += got;
                    }
                }
                let t1 = syscall::get_cycles();
                print_throughput(b"seq_read_32k", total_bytes, t1 - t0, freq, ITERS);
            }
            fs_close(fat_port, handle);
        } else {
            syscall::debug_puts(b"  macro: seq_read_32k: SKIP (BENCH.DAT not found)\n");
        }
    }

    // --- Macro 2: File Create-Write-Delete Cycle (create_write_del) ---
    {
        const ITERS: u64 = 10;
        const WRITE_SIZE: u32 = 4096;

        // Fill scratch with pattern.
        for i in 0..WRITE_SIZE as usize {
            unsafe { *((scratch_va + i) as *mut u8) = (i & 0xFF) as u8; }
        }

        // Use numbered filenames: BNCH00.DAT through BNCH09.DAT
        let t0 = syscall::get_cycles();
        let mut ok_count: u64 = 0;
        for iter in 0..ITERS {
            let mut fname = *b"BNCHnn.DAT";
            fname[4] = b'0' + (iter / 10) as u8;
            fname[5] = b'0' + (iter % 10) as u8;

            if let Some((handle, srv_aspace)) = fs_create(fat_port, &fname) {
                let written = fs_write_grant(fat_port, handle, WRITE_SIZE, srv_aspace, scratch_va);
                fs_close(fat_port, handle);
                if written == WRITE_SIZE {
                    if fs_delete(fat_port, &fname) {
                        ok_count += 1;
                    }
                }
            }
        }
        let t1 = syscall::get_cycles();

        if ok_count == ITERS {
            print_opsec(b"create_write_del", t1 - t0, freq, ITERS);
        } else {
            syscall::debug_puts(b"  macro: create_write_del: ");
            print_num(ok_count);
            syscall::debug_puts(b"/");
            print_num(ITERS);
            syscall::debug_puts(b" succeeded\n");
        }
    }

    // --- Macro 3: Data Integrity Check (file_checksum) ---
    {
        const FILE_SIZE: u32 = 32768;

        if let Some((handle, fsize, srv_aspace)) = fs_open(fat_port, b"BENCH.DAT") {
            if fsize == FILE_SIZE {
                let t0 = syscall::get_cycles();
                let mut xor: u8 = 0;
                let mut offset: u32 = 0;
                let mut total_read: u64 = 0;
                while offset < FILE_SIZE {
                    let to_read = 512u32.min(FILE_SIZE - offset);
                    let got = fs_read_grant(fat_port, handle, offset, to_read, srv_aspace, scratch_va);
                    if got == 0 { break; }
                    // XOR all bytes.
                    for i in 0..got as usize {
                        xor ^= unsafe { *((scratch_va + i) as *const u8) };
                    }
                    total_read += got as u64;
                    offset += got;
                }
                let t1 = syscall::get_cycles();

                // The pattern is 0x00..0xFF repeated 128 times.
                // XOR of 0x00..0xFF = 0x00 (even number of each bit).
                // So expected XOR = 0x00.
                let expected_xor: u8 = 0;
                let checksum_ok = xor == expected_xor && total_read == FILE_SIZE as u64;

                syscall::debug_puts(b"  macro: file_checksum: ");
                print_num(total_read);
                syscall::debug_puts(b" B, XOR=0x");
                let hi = xor >> 4;
                let lo = xor & 0xF;
                syscall::debug_putchar(if hi < 10 { b'0' + hi } else { b'A' + hi - 10 });
                syscall::debug_putchar(if lo < 10 { b'0' + lo } else { b'A' + lo - 10 });
                if checksum_ok {
                    syscall::debug_puts(b" OK, ");
                } else {
                    syscall::debug_puts(b" MISMATCH, ");
                }
                let kbs = if (t1 - t0) > 0 {
                    total_read * (freq / 1024) / (t1 - t0)
                } else { 0 };
                print_num(t1 - t0);
                syscall::debug_puts(b" cy (");
                print_num(kbs);
                syscall::debug_puts(b" KB/s)\n");
            } else {
                syscall::debug_puts(b"  macro: file_checksum: SKIP (size mismatch)\n");
            }
            fs_close(fat_port, handle);
        } else {
            syscall::debug_puts(b"  macro: file_checksum: SKIP (BENCH.DAT not found)\n");
        }
    }

    // --- Macro 4: Server Crash Recovery (srv_recovery) ---
    {
        // Spawn our own fat16_srv instance.
        let mut fat16_tid = syscall::spawn(b"fat16_srv", 50);
        if fat16_tid != u64::MAX {
            // Wait for it to register and become operational.
            let mut my_fat_port: Option<u64> = None;
            for _ in 0..10_000 {
                syscall::yield_now();
                if let Some(p) = syscall::ns_lookup(b"fat16") {
                    // Try opening BENCH.DAT to confirm it's operational.
                    if let Some((h, _sz, _asp)) = fs_open(p, b"BENCH.DAT") {
                        fs_close(p, h);
                        my_fat_port = Some(p);
                        break;
                    }
                }
            }

            if let Some(fp) = my_fat_port {
                // Baseline: read first sector.
                let mut baseline = [0u8; 512];
                let baseline_ok = if let Some((h, _sz, asp)) = fs_open(fp, b"BENCH.DAT") {
                    let got = fs_read_grant(fp, h, 0, 512, asp, scratch_va);
                    if got == 512 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                scratch_va as *const u8,
                                baseline.as_mut_ptr(),
                                512,
                            );
                        }
                    }
                    fs_close(fp, h);
                    got == 512
                } else {
                    false
                };

                if baseline_ok {
                    // Timed: kill, respawn, verify.
                    let t0 = syscall::get_cycles();

                    syscall::kill(fat16_tid as u32);
                    loop {
                        if syscall::waitpid(fat16_tid).is_some() { break; }
                        syscall::yield_now();
                    }

                    // Respawn.
                    fat16_tid = syscall::spawn(b"fat16_srv", 50);
                    if fat16_tid != u64::MAX {
                        // Poll until the new instance is operational.
                        let mut recovery_ok = false;
                        for _ in 0..10_000 {
                            syscall::yield_now();
                            if let Some(new_port) = syscall::ns_lookup(b"fat16") {
                                if let Some((h, _sz, asp)) = fs_open(new_port, b"BENCH.DAT") {
                                    let got = fs_read_grant(new_port, h, 0, 512, asp, scratch_va);
                                    if got == 512 {
                                        // Verify data matches baseline.
                                        let mut match_ok = true;
                                        for i in 0..512 {
                                            let b = unsafe { *((scratch_va + i) as *const u8) };
                                            if b != baseline[i] { match_ok = false; break; }
                                        }
                                        if match_ok { recovery_ok = true; }
                                    }
                                    fs_close(new_port, h);
                                    if recovery_ok { break; }
                                }
                            }
                        }

                        let t1 = syscall::get_cycles();

                        if recovery_ok {
                            let us = if freq > 0 {
                                (t1 - t0) / (freq / 1_000_000)
                            } else { 0 };
                            syscall::debug_puts(b"  macro: srv_recovery: ");
                            print_num(t1 - t0);
                            syscall::debug_puts(b" cy (~");
                            print_num(us);
                            syscall::debug_puts(b" us recovery window)\n");
                        } else {
                            syscall::debug_puts(b"  macro: srv_recovery: FAILED (could not verify)\n");
                        }

                        // Cleanup: kill our fat16_srv.
                        syscall::kill(fat16_tid as u32);
                        loop {
                            if syscall::waitpid(fat16_tid).is_some() { break; }
                            syscall::yield_now();
                        }
                    } else {
                        syscall::debug_puts(b"  macro: srv_recovery: FAILED (respawn failed)\n");
                    }
                } else {
                    syscall::debug_puts(b"  macro: srv_recovery: SKIP (baseline read failed)\n");
                    syscall::kill(fat16_tid as u32);
                    loop {
                        if syscall::waitpid(fat16_tid).is_some() { break; }
                        syscall::yield_now();
                    }
                }
            } else {
                syscall::debug_puts(b"  macro: srv_recovery: SKIP (fat16_srv not ready)\n");
                syscall::kill(fat16_tid as u32);
                loop {
                    if syscall::waitpid(fat16_tid).is_some() { break; }
                    syscall::yield_now();
                }
            }
        } else {
            syscall::debug_puts(b"  macro: srv_recovery: SKIP (spawn failed)\n");
        }
    }

    syscall::munmap(scratch_va);
    syscall::debug_puts(b"=== Macrobenchmarks complete ===\n");
    syscall::exit(0);
}
