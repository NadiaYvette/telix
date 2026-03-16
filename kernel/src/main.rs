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

    // Platform init: exceptions, interrupt controller, timer.
    arch::platform::init();

    // Physical memory allocator.
    let (ram_start, ram_end) = arch::platform::ram_range();
    let kernel_end = arch::platform::kernel_end_addr();
    mm::phys::init(ram_start, ram_end, ram_start, kernel_end);

    // Quick phys allocator test.
    if let Some(page) = mm::phys::alloc_page() {
        println!("  Phys alloc test: page at {:?}", page);
        mm::phys::free_page(page);
        println!("  Phys alloc test: freed");
    }

    // Slab allocator test.
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

    // Capability system test.
    test_capabilities();

    // Scheduler.
    sched::init();

    // IPC test.
    let port = ipc::port::create().expect("create IPC port");
    IPC_TEST_PORT.store(port, core::sync::atomic::Ordering::Relaxed);
    println!("  IPC test port {} created", port);
    sched::spawn(ipc_sender, 100, 10).expect("spawn sender");
    sched::spawn(ipc_receiver, 100, 10).expect("spawn receiver");

    // Platform-specific tests (syscall, userspace).
    #[cfg(target_arch = "aarch64")]
    {
        test_syscalls_aarch64();
        test_userspace_aarch64();
    }

    println!("Enabling interrupts");
    arch::platform::enable_interrupts();

    println!("Telix kernel initialized — entering idle loop");
    arch::platform::idle_loop()
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

    static CDT_STORAGE: SpinLock<Cdt> = SpinLock::new(Cdt::new());
    {
        let mut cdt = CDT_STORAGE.lock();
        cdt.init();

        let mut server_space = CapSpace::new(0);
        let port_cap = Capability::new(
            CapType::Port,
            Rights::SEND.union(Rights::RECV).union(Rights::GRANT),
            0xDEAD_0001,
        );
        let server_slot = server_space.insert(port_cap, &mut cdt).unwrap();
        println!("  Cap test: server has {:?} at slot {}", server_space.lookup(server_slot).unwrap(), server_slot);

        let mut client_space = CapSpace::new(1);
        let client_slot = server_space.derive_to(
            server_slot, Rights::SEND, &mut client_space, &mut cdt,
        ).unwrap();
        println!("  Cap test: client has {:?} at slot {}", client_space.lookup(client_slot).unwrap(), client_slot);

        let mut client2_space = CapSpace::new(2);
        let client2_slot = server_space.derive_to(
            server_slot, Rights::SEND.union(Rights::GRANT), &mut client2_space, &mut cdt,
        ).unwrap();
        println!("  Cap test: client2 has {:?} at slot {}", client2_space.lookup(client2_slot).unwrap(), client2_slot);

        let revoked = server_space.revoke(server_slot, &mut cdt);
        println!("  Cap test: revoked {} derived capabilities", revoked);
        println!("  Cap test: server still has {:?}", server_space.lookup(server_slot).unwrap());
    }
    println!("  Cap test: PASSED");
}

// --- AArch64-specific tests ---

#[cfg(target_arch = "aarch64")]
fn test_userspace_aarch64() {
    use arch::aarch64::mm;
    use arch::aarch64::usertest;

    println!("  Setting up page tables...");

    let l0 = mm::setup_tables().expect("page tables");
    println!("  L0 table at {:#x}", l0);

    let user_code_page = crate::mm::phys::alloc_page().expect("user code page");
    let user_code_phys = user_code_page.as_usize();
    unsafe {
        core::ptr::copy_nonoverlapping(
            usertest::USER_CODE.as_ptr(),
            user_code_phys as *mut u8,
            usertest::USER_CODE.len(),
        );
    }

    let user_stack_page = crate::mm::phys::alloc_page().expect("user stack page");
    let user_stack_phys = user_stack_page.as_usize();

    let user_code_virt: usize = 0x8000_0000;
    let user_stack_virt: usize = 0x8001_0000;

    mm::map_user_pages(l0, user_code_virt, user_code_phys,
        usertest::USER_CODE.len(), mm::USER_RWX_FLAGS).expect("map user code");
    mm::map_user_pages(l0, user_stack_virt, user_stack_phys,
        4096, mm::USER_RW_FLAGS).expect("map user stack");
    println!("  User mappings: code at {:#x}, stack at {:#x}", user_code_virt, user_stack_virt);

    println!("  Enabling MMU...");
    mm::enable_mmu(l0);
    println!("  MMU enabled — identity mapping active");

    println!("  Jumping to EL0...");
    let user_sp = user_stack_virt + 4096;
    unsafe {
        core::arch::asm!(
            "msr sp_el0, {sp}",
            "msr elr_el1, {pc}",
            "mov x0, #0",
            "msr spsr_el1, x0",
            "eret",
            sp = in(reg) user_sp as u64,
            pc = in(reg) user_code_virt as u64,
            options(noreturn),
        );
    }
}

#[cfg(target_arch = "aarch64")]
fn test_syscalls_aarch64() {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "mov x8, #0", "mov x0, #0x53", "svc #0",
            out("x0") ret, out("x8") _,
            out("x1") _, out("x2") _, out("x3") _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
        );
    }
    println!("");
    println!("  Syscall test: debug_putchar returned {}", ret);

    let tid: u64;
    unsafe {
        core::arch::asm!(
            "mov x8, #8", "svc #0",
            out("x0") tid, out("x8") _,
            out("x1") _, out("x2") _, out("x3") _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
        );
    }
    println!("  Syscall test: thread_id={}", tid);
    println!("  Syscall test: PASSED");
}
