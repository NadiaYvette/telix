#![no_std]
#![no_main]

//! Telix benchmark suite. Measures IPC latency, syscall overhead,
//! context switch cost, pipe throughput, and memory allocation speed.

extern crate userlib;

use userlib::syscall;

const BENCH_PING: u64 = 0x6000;
const BENCH_PONG: u64 = 0x6001;
const BENCH_QUIT: u64 = 0x60FF;

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

fn print_result(name: &[u8], total_cycles: u64, iters: u64, freq: u64) {
    let per_iter = if iters > 0 { total_cycles / iters } else { 0 };
    // Compute microseconds: (total_cycles * 1_000_000) / freq / iters
    let us = if freq > 0 && iters > 0 {
        total_cycles / (freq / 1_000_000) / iters
    } else {
        0
    };

    syscall::debug_puts(b"  bench: ");
    syscall::debug_puts(name);
    syscall::debug_puts(b": ");
    print_num(total_cycles);
    syscall::debug_puts(b" cy / ");
    print_num(iters);
    syscall::debug_puts(b" = ");
    print_num(per_iter);
    syscall::debug_puts(b" cy/iter (~");
    print_num(us);
    syscall::debug_puts(b" us)\n");
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"=== Telix Benchmark Suite ===\n");

    let freq = syscall::get_timer_freq();
    syscall::debug_puts(b"  bench: timer freq = ");
    print_num(freq);
    syscall::debug_puts(b" Hz\n");

    // --- Benchmark 1: Null syscall overhead ---
    {
        const N: u64 = 10_000;
        // Warmup.
        for _ in 0..100 {
            let _ = syscall::thread_id();
        }

        let t0 = syscall::get_cycles();
        for _ in 0..N {
            let _ = syscall::thread_id();
        }
        let t1 = syscall::get_cycles();
        print_result(b"null_syscall", t1 - t0, N, freq);
    }

    // --- Benchmark 2: IPC self round-trip (send_nb + recv_msg, same port) ---
    {
        const N: u64 = 10_000;
        let port = syscall::port_create();

        // Warmup.
        for _ in 0..100 {
            syscall::send_nb(port, 0x01, 0, 0);
            let _ = syscall::recv_msg(port);
        }

        let t0 = syscall::get_cycles();
        for _ in 0..N {
            syscall::send_nb(port, 0x01, 0, 0);
            let _ = syscall::recv_msg(port);
        }
        let t1 = syscall::get_cycles();
        syscall::port_destroy(port);
        print_result(b"ipc_self_rtt", t1 - t0, N, freq);
    }

    // --- Benchmark 3: IPC cross-process ping-pong ---
    {
        const N: u64 = 1_000;
        let pong_port = syscall::port_create();
        let reply_port = syscall::port_create();

        let pong_tid = syscall::spawn_with_arg(b"pong", 50, pong_port as u64);
        if pong_tid != u64::MAX {
            // Give pong time to start and block on recv.
            for _ in 0..20 {
                syscall::yield_now();
            }

            // Warmup.
            for _ in 0..10 {
                syscall::send(pong_port, BENCH_PING, reply_port as u64, 0, 0, 0);
                let _ = syscall::recv_msg(reply_port);
            }

            let t0 = syscall::get_cycles();
            for _ in 0..N {
                syscall::send(pong_port, BENCH_PING, reply_port as u64, 0, 0, 0);
                let _ = syscall::recv_msg(reply_port);
            }
            let t1 = syscall::get_cycles();

            // Tell pong to quit.
            syscall::send_nb(pong_port, BENCH_QUIT, 0, 0);
            loop {
                if syscall::waitpid(pong_tid).is_some() {
                    break;
                }
                syscall::yield_now();
            }

            print_result(b"ipc_pingpong", t1 - t0, N, freq);
        } else {
            syscall::debug_puts(b"  bench: ipc_pingpong: SKIP (spawn failed)\n");
        }
        syscall::port_destroy(reply_port);
        syscall::port_destroy(pong_port);
    }

    // --- Benchmark 4: Yield (context switch overhead) ---
    {
        const N: u64 = 10_000;
        // Warmup.
        for _ in 0..100 {
            syscall::yield_now();
        }

        let t0 = syscall::get_cycles();
        for _ in 0..N {
            syscall::yield_now();
        }
        let t1 = syscall::get_cycles();
        print_result(b"yield", t1 - t0, N, freq);
    }

    // --- Benchmark 5: Pipe throughput (64 KB) ---
    {
        let pipe_port = syscall::port_create();

        // Spawn a silent reader that drains the pipe.
        let reader_tid = syscall::spawn_with_arg(b"pipe_drain", 50, pipe_port as u64);
        if reader_tid != u64::MAX {
            for _ in 0..10 {
                syscall::yield_now();
            }

            // Write 64 KB of data.
            const DATA_SIZE: usize = 65536;
            let mut buf = [0x41u8; 16]; // 'A' repeated
            let chunks = DATA_SIZE / 16;

            let t0 = syscall::get_cycles();
            for _ in 0..chunks {
                userlib::pipe::pipe_write(pipe_port, &buf);
            }
            userlib::pipe::pipe_close_writer(pipe_port);
            let t1 = syscall::get_cycles();

            // Wait for reader to exit.
            loop {
                if syscall::waitpid(reader_tid).is_some() {
                    break;
                }
                syscall::yield_now();
            }

            let total = t1 - t0;
            let bytes_per_cycle = if total > 0 {
                (DATA_SIZE as u64 * 1000) / total
            } else {
                0
            };
            syscall::debug_puts(b"  bench: pipe_64k: ");
            print_num(total);
            syscall::debug_puts(b" cy for ");
            print_num(DATA_SIZE as u64);
            syscall::debug_puts(b" B (");
            print_num(bytes_per_cycle);
            syscall::debug_puts(b" B*1000/cy)\n");
        } else {
            syscall::debug_puts(b"  bench: pipe_64k: SKIP (spawn failed)\n");
        }
        syscall::port_destroy(pipe_port);
    }

    // --- Benchmark 6: mmap/munmap ---
    {
        const N: u64 = 1_000;
        // Warmup.
        for _ in 0..10 {
            if let Some(va) = syscall::mmap_anon(0, 1, 1) {
                syscall::munmap(va);
            }
        }

        let t0 = syscall::get_cycles();
        for _ in 0..N {
            if let Some(va) = syscall::mmap_anon(0, 1, 1) {
                syscall::munmap(va);
            }
        }
        let t1 = syscall::get_cycles();
        print_result(b"mmap_munmap", t1 - t0, N, freq);
    }

    // --- Benchmark 7: Fault recovery (kill + respawn) ---
    {
        const N: u64 = 100;
        // Warmup.
        let warmup_tid = syscall::spawn(b"spin", 50);
        if warmup_tid != u64::MAX {
            for _ in 0..10 {
                syscall::yield_now();
            }
            syscall::kill(warmup_tid);
            loop {
                if syscall::waitpid(warmup_tid).is_some() {
                    break;
                }
                syscall::yield_now();
            }
        }

        let t0 = syscall::get_cycles();
        for _ in 0..N {
            let tid = syscall::spawn(b"spin", 50);
            if tid == u64::MAX {
                break;
            }
            for _ in 0..5 {
                syscall::yield_now();
            }
            syscall::kill(tid);
            loop {
                if syscall::waitpid(tid).is_some() {
                    break;
                }
                syscall::yield_now();
            }
        }
        let t1 = syscall::get_cycles();
        print_result(b"kill_respawn", t1 - t0, N, freq);
    }

    // --- Benchmark 8: Grant/revoke overhead ---
    {
        const GRANT_BENCH_ASPACE: u64 = 0x7000;
        const GRANT_BENCH_QUIT: u64 = 0x70FF;
        const DST_VA: usize = 0xA_0000_0000;
        const N: u64 = 1_000;

        // Allocate 1 page and touch it to ensure physical backing.
        if let Some(src_va) = syscall::mmap_anon(0, 1, 1) {
            unsafe {
                core::ptr::write_volatile(src_va as *mut u8, 0xAA);
            }

            let coord_port = syscall::port_create();
            let child_tid = syscall::spawn_with_arg(b"grant_echo", 50, coord_port as u64);
            if child_tid != u64::MAX {
                // Receive child's aspace_id.
                let child_aspace = if let Some(msg) = syscall::recv_msg(coord_port) {
                    if msg.tag == GRANT_BENCH_ASPACE {
                        msg.data[0]
                    } else {
                        0
                    }
                } else {
                    0
                };

                if child_aspace != 0 {
                    // Warmup.
                    for _ in 0..10 {
                        syscall::grant_pages(child_aspace, src_va, DST_VA, 1, true);
                        syscall::revoke(child_aspace, DST_VA);
                    }

                    let t0 = syscall::get_cycles();
                    for _ in 0..N {
                        syscall::grant_pages(child_aspace, src_va, DST_VA, 1, true);
                        syscall::revoke(child_aspace, DST_VA);
                    }
                    let t1 = syscall::get_cycles();
                    print_result(b"grant_revoke", t1 - t0, N, freq);
                } else {
                    syscall::debug_puts(b"  bench: grant_revoke: SKIP (no aspace)\n");
                }

                syscall::send_nb(coord_port, GRANT_BENCH_QUIT, 0, 0);
                loop {
                    if syscall::waitpid(child_tid).is_some() {
                        break;
                    }
                    syscall::yield_now();
                }
            } else {
                syscall::debug_puts(b"  bench: grant_revoke: SKIP (spawn failed)\n");
            }
            syscall::port_destroy(coord_port);
            syscall::munmap(src_va);
        }
    }

    // --- Benchmark 9: Grant 64 KB (compare with pipe_64k) ---
    {
        const GRANT_BENCH_ASPACE: u64 = 0x7000;
        const GRANT_BENCH_QUIT: u64 = 0x70FF;
        const DST_VA: usize = 0xA_0000_0000;

        // Allocate 16 pages (64 KB at 4 KB MMU page size).
        if let Some(src_va) = syscall::mmap_anon(0, 16, 1) {
            // Touch all pages to ensure backing.
            for i in 0..16 {
                unsafe {
                    core::ptr::write_volatile((src_va + i * 4096) as *mut u8, 0xBB);
                }
            }

            let coord_port = syscall::port_create();
            let child_tid = syscall::spawn_with_arg(b"grant_echo", 50, coord_port as u64);
            if child_tid != u64::MAX {
                let child_aspace = if let Some(msg) = syscall::recv_msg(coord_port) {
                    if msg.tag == GRANT_BENCH_ASPACE {
                        msg.data[0]
                    } else {
                        0
                    }
                } else {
                    0
                };

                if child_aspace != 0 {
                    // Warmup.
                    syscall::grant_pages(child_aspace, src_va, DST_VA, 16, true);
                    syscall::revoke(child_aspace, DST_VA);

                    let t0 = syscall::get_cycles();
                    syscall::grant_pages(child_aspace, src_va, DST_VA, 16, true);
                    syscall::revoke(child_aspace, DST_VA);
                    let t1 = syscall::get_cycles();

                    let total = t1 - t0;
                    syscall::debug_puts(b"  bench: grant_64k: ");
                    print_num(total);
                    syscall::debug_puts(b" cy for 65536 B (grant+revoke)\n");
                } else {
                    syscall::debug_puts(b"  bench: grant_64k: SKIP (no aspace)\n");
                }

                syscall::send_nb(coord_port, GRANT_BENCH_QUIT, 0, 0);
                loop {
                    if syscall::waitpid(child_tid).is_some() {
                        break;
                    }
                    syscall::yield_now();
                }
            } else {
                syscall::debug_puts(b"  bench: grant_64k: SKIP (spawn failed)\n");
            }
            syscall::port_destroy(coord_port);
            syscall::munmap(src_va);
        }
    }

    // --- Benchmark 10: Priority scheduling under load ---
    {
        const N: u64 = 500;
        let pong_port = syscall::port_create();
        let reply_port = syscall::port_create();

        // Spawn pong at high priority (10).
        let pong_tid = syscall::spawn_with_arg(b"pong", 10, pong_port as u64);
        if pong_tid != u64::MAX {
            for _ in 0..20 {
                syscall::yield_now();
            }

            // Warmup.
            for _ in 0..10 {
                syscall::send(pong_port, BENCH_PING, reply_port as u64, 0, 0, 0);
                let _ = syscall::recv_msg(reply_port);
            }

            // Measure without load.
            let t0 = syscall::get_cycles();
            for _ in 0..N {
                syscall::send(pong_port, BENCH_PING, reply_port as u64, 0, 0, 0);
                let _ = syscall::recv_msg(reply_port);
            }
            let t1 = syscall::get_cycles();
            print_result(b"prio_ipc_noload", t1 - t0, N, freq);

            // Spawn 2 low-priority CPU-bound tasks.
            let spin1 = syscall::spawn(b"spin", 200);
            let spin2 = syscall::spawn(b"spin", 200);
            for _ in 0..10 {
                syscall::yield_now();
            }

            // Measure with load.
            let t0 = syscall::get_cycles();
            for _ in 0..N {
                syscall::send(pong_port, BENCH_PING, reply_port as u64, 0, 0, 0);
                let _ = syscall::recv_msg(reply_port);
            }
            let t1 = syscall::get_cycles();
            print_result(b"prio_ipc_loaded", t1 - t0, N, freq);

            // Cleanup (use sleep_ms retries — yield_now alone can't preempt
            // to let the killed process run its exit path on another CPU).
            if spin1 != u64::MAX {
                syscall::kill(spin1);
                for _ in 0..100 {
                    if syscall::waitpid(spin1).is_some() {
                        break;
                    }
                    syscall::sleep_ms(10);
                }
            }
            if spin2 != u64::MAX {
                syscall::kill(spin2);
                for _ in 0..100 {
                    if syscall::waitpid(spin2).is_some() {
                        break;
                    }
                    syscall::sleep_ms(10);
                }
            }
            syscall::send_nb(pong_port, BENCH_QUIT, 0, 0);
            for _ in 0..100 {
                if syscall::waitpid(pong_tid).is_some() {
                    break;
                }
                syscall::sleep_ms(10);
            }
        } else {
            syscall::debug_puts(b"  bench: prio_ipc: SKIP (spawn failed)\n");
        }
        syscall::port_destroy(reply_port);
        syscall::port_destroy(pong_port);
    }

    // --- Benchmark 11: Server fault isolation + recovery ---
    // DISABLED: kill-while-blocked-on-recv leaves stale turnstile entry,
    // causing the replacement pong to never receive BENCH_PING.
    // TODO: fix turnstile cleanup on thread kill, then re-enable.
    syscall::debug_puts(b"  bench: srv_restart: SKIP (disabled, turnstile bug)\n");

    syscall::debug_puts(b"=== Benchmarks complete ===\n");
    syscall::exit(0);
}
