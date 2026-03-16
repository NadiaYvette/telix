pub mod boot;
pub mod exception;
pub mod gdt;
pub mod idt;
pub mod lapic;
pub mod mm;
pub mod pic;
pub mod serial;
pub mod smp;
pub mod timer;
pub mod usertest;

use core::arch::global_asm;

global_asm!(include_str!("boot.S"));
global_asm!(include_str!("vectors.S"));
global_asm!(include_str!("ap_trampoline.S"));
global_asm!(include_str!("usertest.S"));

/// Platform init: GDT, IDT, PIC, PIT timer, LAPIC.
pub fn init() {
    gdt::init();
    idt::init();
    pic::init();
    timer::init();
    lapic::init_bsp();
}

/// RAM range for the physical allocator.
/// x86 QEMU: RAM starts at 1 MiB, we use 256 MiB total.
pub fn ram_range() -> (usize, usize) {
    let start = boot::RAM_BASE;
    let end = start + 256 * 1024 * 1024;
    (start, end)
}

/// Physical address past the kernel image.
pub fn kernel_end_addr() -> usize {
    boot::kernel_end_addr()
}

/// Enable interrupts (STI).
pub fn enable_interrupts() {
    timer::enable_interrupts();
}

/// Start secondary CPUs.
pub fn start_secondary_cpus() {
    smp::start_secondary_cpus();
}

/// Idle loop — HLT until interrupted.
pub fn idle_loop() -> ! {
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
