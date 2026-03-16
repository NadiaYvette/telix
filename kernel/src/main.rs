#![no_std]
#![no_main]

mod arch;
mod cap;
mod mm;
mod sync;

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

    println!("Enabling interrupts");
    arch::aarch64::timer::enable_interrupts();

    println!("Telix kernel initialized — entering idle loop");
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

fn test_capabilities() {
    use cap::{Capability, CapType, Rights, CapSpace, Cdt};

    let mut cdt = Cdt::new();
    cdt.init();

    // Task 0: server with full port capability.
    let mut server_space = CapSpace::new(0);
    let port_cap = Capability::new(
        CapType::Port,
        Rights::SEND.union(Rights::RECV).union(Rights::GRANT),
        0xDEAD_0001, // Fake port object ID.
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

    // Revoke: server revokes all derived capabilities.
    let revoked = server_space.revoke(server_slot, &mut cdt);
    println!("  Cap test: revoked {} derived capabilities", revoked);

    // Server's own capability is still valid.
    println!("  Cap test: server still has {:?}", server_space.lookup(server_slot).unwrap());
    println!("  Cap test: PASSED");
}
