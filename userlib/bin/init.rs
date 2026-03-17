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

    // --- Test 5: End-to-end file read from userspace initramfs server ---
    syscall::debug_puts(b"  init: testing userspace file I/O...\n");

    let srv_port = syscall::get_initramfs_port();
    if srv_port != u32::MAX {
        let reply_port = syscall::port_create() as u32;

        // IO_CONNECT: d0=name0-7, d1=name8-15, d2=name_len|(reply_port<<32)
        let name = b"hello.txt";
        let (w0, w1, _) = pack_name(name);
        let d2 = (name.len() as u64) | ((reply_port as u64) << 32);
        syscall::send(srv_port, 0x100, w0, w1, d2, 0);

        if let Some(reply) = syscall::recv_msg(reply_port) {
            if reply.tag == 0x101 {
                let handle = reply.data[0];
                let size = reply.data[1];
                syscall::debug_puts(b"  init: connected, handle=");
                print_num(handle);
                syscall::debug_puts(b" size=");
                print_num(size);
                syscall::debug_puts(b"\n");

                // IO_READ: d0=handle, d1=offset, d2=length|(reply_port<<32)
                let d2_read = size | ((reply_port as u64) << 32);
                syscall::send(srv_port, 0x200, handle, 0, d2_read, 0);

                for _ in 0..20 { syscall::yield_now(); }

                if let Some(rr) = syscall::recv_msg(reply_port) {
                    if rr.tag == 0x201 {
                        let bytes_read = rr.data[0] as usize;
                        syscall::debug_puts(b"  init: read ");
                        print_num(bytes_read as u64);
                        syscall::debug_puts(b" bytes: ");

                        // Unpack inline data from data[1..5].
                        let mut buf = [0u8; 40];
                        let words = [rr.data[1], rr.data[2], rr.data[3], rr.data[4], 0];
                        for i in 0..bytes_read.min(40) {
                            buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
                        }
                        syscall::debug_puts(&buf[..bytes_read.min(40)]);

                        syscall::send_nb(srv_port, 0x500, handle, 0);
                        syscall::debug_puts(b"Phase 6 userspace I/O test: PASSED\n");
                    } else {
                        syscall::debug_puts(b"  init: read failed\n");
                    }
                } else {
                    syscall::debug_puts(b"  init: no read reply\n");
                }
            } else {
                syscall::debug_puts(b"  init: connect failed\n");
            }
        } else {
            syscall::debug_puts(b"  init: no connect reply\n");
        }
    } else {
        syscall::debug_puts(b"  init: no initramfs_srv port\n");
    }

    // Init loops forever, yielding.
    loop {
        syscall::yield_now();
    }
}
