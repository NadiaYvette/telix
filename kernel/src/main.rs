#![no_std]
#![no_main]

mod arch;
mod cap;
mod ipc;
mod mm;
mod sched;
mod sync;
mod syscall;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("KERNEL PANIC: {}", info);
    loop {
        core::hint::spin_loop();
    }
}

pub fn kmain() -> ! {
    println!("Telix kernel initializing...");

    // M2: Exception handling, interrupt controller, timer.
    arch::aarch64::exception::init();
    arch::aarch64::irq::init();
    arch::aarch64::timer::init();

    // M3: Physical memory allocator.
    // QEMU virt: RAM at 0x4000_0000, size = 256 MiB (from -m 256M).
    let ram_start = arch::aarch64::boot::QEMU_VIRT_RAM_BASE;
    let ram_end = ram_start + 256 * 1024 * 1024;
    let kernel_end = arch::aarch64::boot::kernel_end_addr();
    // Reserve from RAM start through kernel end (includes kernel image + BSS).
    mm::phys::init(ram_start, ram_end, ram_start, kernel_end);

    // Quick phys allocator test.
    if let Some(page) = mm::phys::alloc_page() {
        println!("  Phys alloc test: page at {:?}", page);
        mm::phys::free_page(page);
        println!("  Phys alloc test: freed");
    }

    // M4: Slab allocator test.
    mm::slab::print_stats();
    if let Some(obj) = mm::slab::alloc(64) {
        println!("  Slab alloc test: 64-byte object at {:?}", obj);
        mm::slab::free(obj, 64);
        println!("  Slab alloc test: freed");
    }
    if let Some(obj) = mm::slab::alloc(256) {
        println!("  Slab alloc test: 256-byte object at {:?}", obj);
        mm::slab::free(obj, 256);
        println!("  Slab alloc test: freed");
    }

    // M6: Capability system test.
    test_capabilities();

    // M7/M8: Scheduler + thread management.
    sched::init();

    // M9: IPC test — create a port, spawn sender/receiver threads.
    let port = ipc::port::create().expect("create IPC port");
    IPC_TEST_PORT.store(port, core::sync::atomic::Ordering::Relaxed);
    println!("  IPC test port {} created", port);

    sched::spawn(ipc_sender, 100, 10).expect("spawn sender");
    sched::spawn(ipc_receiver, 100, 10).expect("spawn receiver");

    // M10: Syscall test from EL1 (using SVC).
    test_syscalls();

    println!("Enabling interrupts");
    arch::aarch64::timer::enable_interrupts();

    println!("Telix kernel initialized — entering idle loop");
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

use core::sync::atomic::{AtomicU32, Ordering};
static IPC_TEST_PORT: AtomicU32 = AtomicU32::new(0);

fn ipc_sender() -> ! {
    let port_id = IPC_TEST_PORT.load(Ordering::Relaxed);
    let mut seq = 0u64;
    loop {
        let msg = ipc::Message::new(1, [seq, 0, 0, 0, 0, 0]);
        match ipc::port::send(port_id, msg) {
            Ok(()) => {
                if seq % 10 == 0 {
                    println!("[sender] sent seq={}", seq);
                }
                seq += 1;
            }
            Err(_) => {
                // Queue full — spin and retry.
                for _ in 0..1_000 {
                    core::hint::spin_loop();
                }
            }
        }
    }
}

fn ipc_receiver() -> ! {
    let port_id = IPC_TEST_PORT.load(Ordering::Relaxed);
    let mut received = 0u64;
    loop {
        match ipc::port::recv(port_id) {
            Ok(msg) => {
                if received % 10 == 0 {
                    println!("[receiver] got tag={} seq={}", msg.tag, msg.data[0]);
                }
                received += 1;
            }
            Err(()) => {
                // Queue empty — spin and retry.
                for _ in 0..1_000 {
                    core::hint::spin_loop();
                }
            }
        }
    }
}

fn test_capabilities() {
    use cap::{Capability, CapType, Rights, CapSpace, Cdt};
    use sync::SpinLock;

    // CDT is ~128 KB — too large for the stack. Use a static.
    static CDT_STORAGE: SpinLock<Cdt> = SpinLock::new(Cdt::new());
    {
        let mut cdt = CDT_STORAGE.lock();
        cdt.init();

        // Task 0: server with full port capability.
        let mut server_space = CapSpace::new(0);
        let port_cap = Capability::new(
            CapType::Port,
            Rights::SEND.union(Rights::RECV).union(Rights::GRANT),
            0xDEAD_0001,
        );
        let server_slot = server_space.insert(port_cap, &mut cdt).unwrap();
        println!("  Cap test: server has {:?} at slot {}", server_space.lookup(server_slot).unwrap(), server_slot);

        // Task 1: client gets a derived send-only capability.
        let mut client_space = CapSpace::new(1);
        let client_slot = server_space.derive_to(
            server_slot,
            Rights::SEND,
            &mut client_space,
            &mut cdt,
        ).unwrap();
        println!("  Cap test: client has {:?} at slot {}", client_space.lookup(client_slot).unwrap(), client_slot);

        // Task 2: another client gets send+grant derived from server.
        let mut client2_space = CapSpace::new(2);
        let client2_slot = server_space.derive_to(
            server_slot,
            Rights::SEND.union(Rights::GRANT),
            &mut client2_space,
            &mut cdt,
        ).unwrap();
        println!("  Cap test: client2 has {:?} at slot {}", client2_space.lookup(client2_slot).unwrap(), client2_slot);

        // Revoke all derived capabilities.
        let revoked = server_space.revoke(server_slot, &mut cdt);
        println!("  Cap test: revoked {} derived capabilities", revoked);
        println!("  Cap test: server still has {:?}", server_space.lookup(server_slot).unwrap());
    }
    println!("  Cap test: PASSED");
}

fn test_syscalls() {
    // Test SVC from EL1 (kernel mode).
    // SYS_DEBUG_PUTCHAR = 0, write 'S' to serial.
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "mov x8, #0",     // SYS_DEBUG_PUTCHAR
            "mov x0, #0x53",  // 'S'
            "svc #0",
            out("x0") ret,
            out("x8") _,
            out("x1") _, out("x2") _, out("x3") _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
        );
    }
    // Should have printed 'S' to serial.
    println!(""); // Newline after the 'S'.
    println!("  Syscall test: debug_putchar returned {}", ret);

    // Test SYS_THREAD_ID = 8.
    let tid: u64;
    unsafe {
        core::arch::asm!(
            "mov x8, #8",     // SYS_THREAD_ID
            "svc #0",
            out("x0") tid,
            out("x8") _,
            out("x1") _, out("x2") _, out("x3") _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
        );
    }
    println!("  Syscall test: thread_id={}", tid);
    println!("  Syscall test: PASSED");
}
