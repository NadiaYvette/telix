pub mod boot;
pub mod hypervisor;
pub mod mm;
pub mod pci;
pub mod serial;
pub mod smp;
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
///
/// QEMU loongarch64 virt splits RAM into a low 256-MiB window at PA 0
/// and a high window starting at PA 0x8000_0000 sized to fill `-m`.
/// `phys::init` only manages a single contiguous range, so we pick the
/// LARGEST region.  When `-m 2G` is set, the high region is ~1.75 GiB
/// — much larger than the 256-MiB low region — and `main.rs` is
/// responsible for not trying to reserve the kernel image inside the
/// high region (the kernel sits in the low region).
pub fn ram_range() -> (usize, usize) {
    let regions = crate::firmware::mem_regions();
    if !regions.is_empty() {
        let mut best = &regions[0];
        for r in &regions[1..] {
            if r.size > best.size {
                best = r;
            }
        }
        return (best.base as usize, (best.base + best.size) as usize);
    }
    // Fallback: QEMU virt default 256 MiB at PA 0.
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
    smp::start_secondary_cpus();
}

/// Idle loop.
pub fn idle_loop() -> ! {
    loop {
        unsafe {
            core::arch::asm!("idle 0");
        }
    }
}
