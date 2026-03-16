pub mod boot;
pub mod serial;
pub mod trap;

use core::arch::global_asm;

global_asm!(include_str!("boot.S"));
global_asm!(include_str!("vectors.S"));

/// Platform init: trap vector, timer.
pub fn init() {
    trap::init();
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

/// Enable interrupts (set sstatus.SIE).
pub fn enable_interrupts() {
    trap::enable_interrupts();
}

/// Idle loop — WFI until interrupted.
pub fn idle_loop() -> ! {
    loop {
        unsafe { core::arch::asm!("wfi"); }
    }
}
