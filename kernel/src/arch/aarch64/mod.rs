pub mod boot;
pub mod exception;
pub mod irq;
pub mod mm;
pub mod serial;
pub mod smp;
pub mod timer;
pub mod usertest;

use core::arch::global_asm;

global_asm!(include_str!("boot.S"));
global_asm!(include_str!("vectors.S"));

/// Platform init: exceptions, interrupt controller, timer.
pub fn init() {
    exception::init();
    irq::init();
    timer::init();
}

/// Parse firmware tables (DTB).
/// Must be called before phys::init().
pub fn parse_firmware() {
    boot::parse_firmware();
}

/// RAM range for the physical allocator.
pub fn ram_range() -> (usize, usize) {
    let regions = crate::firmware::mem_regions();
    if let Some(r) = regions.first() {
        return (r.base as usize, (r.base + r.size) as usize);
    }
    // Fallback: hardcoded QEMU virt values.
    let start = boot::QEMU_VIRT_RAM_BASE;
    let end = start + 256 * 1024 * 1024;
    (start, end)
}

/// Physical address past the kernel image.
pub fn kernel_end_addr() -> usize {
    boot::kernel_end_addr()
}

/// Set up page tables and enable the MMU.
/// Must be called after phys allocator init, before secondary CPUs.
pub fn enable_mmu() {
    let l0 = mm::setup_tables().expect("page tables");
    mm::enable_mmu(l0);
    crate::println!("  MMU enabled (L0 at {:#x})", l0);
}

/// Enable interrupts (unmask IRQ).
pub fn enable_interrupts() {
    timer::enable_interrupts();
}

/// Start secondary CPUs.
pub fn start_secondary_cpus() {
    smp::start_secondary_cpus();
}

/// Idle loop — WFI until interrupted.
pub fn idle_loop() -> ! {
    loop {
        unsafe { core::arch::asm!("wfi"); }
    }
}
