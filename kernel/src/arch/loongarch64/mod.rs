pub mod boot;
pub mod mm;
pub mod serial;
pub mod trap;

use core::arch::global_asm;

global_asm!(include_str!("boot.S"));
global_asm!(include_str!("vectors.S"));

/// Platform init: trap vector, timer.
pub fn init() {
    trap::init();
}

/// Parse firmware tables (scan for DTB bootargs).
pub fn parse_firmware() {
    boot::parse_firmware();
}

/// RAM range for the physical allocator.
pub fn ram_range() -> (usize, usize) {
    // QEMU virt: 256 MiB starting at 0x0
    let start = 0x0;
    let end = start + 256 * 1024 * 1024;
    (start, end)
}

/// Physical address past the kernel image.
pub fn kernel_end_addr() -> usize {
    boot::kernel_end_addr()
}

/// Set up page tables and enable the MMU.
pub fn enable_mmu() {
    let root = mm::setup_tables().expect("page tables");
    mm::enable_mmu(root);
    crate::println!("  MMU enabled (root at {:#x})", root);
}

/// Enable interrupts.
pub fn enable_interrupts() {
    trap::enable_interrupts();
}

/// Start secondary CPUs.
pub fn start_secondary_cpus() {
    // TODO: SMP bring-up
}

/// Idle loop.
pub fn idle_loop() -> ! {
    loop {
        unsafe {
            core::arch::asm!("idle 0");
        }
    }
}
