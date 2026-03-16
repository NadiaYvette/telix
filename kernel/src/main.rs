#![no_std]
#![no_main]

mod arch;
mod mm;

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

    // Quick allocator test.
    if let Some(page) = mm::phys::alloc_page() {
        println!("  Alloc test: page at {:?}", page);
        mm::phys::free_page(page);
        println!("  Alloc test: freed");
    }

    println!("Enabling interrupts");
    arch::aarch64::timer::enable_interrupts();

    println!("Telix kernel initialized — entering idle loop");
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}
