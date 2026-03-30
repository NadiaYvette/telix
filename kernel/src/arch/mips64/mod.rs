pub mod boot;
pub mod mm;
pub mod pci;
pub mod serial;
pub mod trap;

use core::arch::global_asm;

global_asm!(include_str!("boot.S"));
global_asm!(include_str!("vectors.S"));

/// Platform init: trap vector, timer.
pub fn init() {
    trap::init();
}

/// Parse firmware tables (YAMON argv).
pub fn parse_firmware() {
    boot::parse_firmware();
}

/// RAM range for the physical allocator.
/// Returns KSEG0 virtual addresses so PA == VA throughout the kernel.
pub fn ram_range() -> (usize, usize) {
    // QEMU Malta: 256 MiB starting at PA 0x0.
    // Map through KSEG0: VA = PA | 0xFFFF_FFFF_8000_0000.
    let start: usize = 0xFFFF_FFFF_8000_0000;
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
            core::arch::asm!("wait");
        }
    }
}
