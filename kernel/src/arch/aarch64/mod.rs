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

/// RAM range for the physical allocator.
pub fn ram_range() -> (usize, usize) {
    let start = boot::QEMU_VIRT_RAM_BASE;
    let end = start + 256 * 1024 * 1024; // 256 MiB
    (start, end)
}

/// Physical address past the kernel image.
pub fn kernel_end_addr() -> usize {
    boot::kernel_end_addr()
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
