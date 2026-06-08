pub mod boot;
pub mod coredump;
pub mod exception;
pub mod gdt;
pub mod hypervisor;
pub mod idt;
pub mod lapic;
pub mod mm;
pub mod pci;
pub mod ioapic;
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

/// Platform init: GDT, IDT, PIC, PIT (for calibration), LAPIC one-shot timer.
pub fn init() {
    gdt::init();
    idt::init();
    pic::init();
    timer::init();        // PIT fires for LAPIC calibration reference
    timer::init_tsc_freq(); // Calibrate TSC freq via CPUID before LAPIC calibration
    lapic::init_bsp();
    lapic::calibrate_timer();
    lapic::setup_timer(); // LAPIC one-shot mode, vector 32
    pic::mask(0);         // Mask PIT IRQ 0 — LAPIC timer takes over
}

/// Parse firmware tables (Multiboot memory map + ACPI MADT),
/// then initialize the I/O APIC (after LAPIC init + MADT ISO entries).
pub fn parse_firmware() {
    boot::parse_firmware();
    ioapic::init();
}

/// RAM range for the physical allocator.
/// Uses Multiboot memory map when available, falls back to hardcoded 256 MiB.
pub fn ram_range() -> (usize, usize) {
    let regions = crate::firmware::mem_regions();
    let kernel_end = boot::kernel_end_addr();

    // Find the region containing kernel_end (the main usable RAM).
    for r in regions {
        let base = r.base as usize;
        let end = (r.base + r.size) as usize;
        if base <= kernel_end && kernel_end < end {
            return (base, end);
        }
    }

    // Fallback: largest region at or above 1 MiB.
    let mut best_start = 0usize;
    let mut best_end = 0usize;
    for r in regions {
        if r.base >= 0x10_0000 {
            let end = (r.base + r.size) as usize;
            if end - r.base as usize > best_end - best_start {
                best_start = r.base as usize;
                best_end = end;
            }
        }
    }
    if best_end > best_start {
        return (best_start, best_end);
    }

    // Hardcoded fallback.
    let start = boot::RAM_BASE;
    let end = start + 256 * 1024 * 1024;
    (start, end)
}

/// Physical address past the kernel image.
pub fn kernel_end_addr() -> usize {
    boot::kernel_end_addr()
}

/// #229: log the VA layout of kernel static buffers (IST stacks, per-CPU
/// print buffers) alongside the kstack VA region and assert no overlap.
///
/// The #229 corruption hypothesis was that IST stacks or print buffers
/// could end up VA-aliasing fresh kstacks, scrambling iretq frames as a
/// side effect of an unrelated print or IST entry.  After #217 (VA
/// isolation Phase 5b) kstacks live in PML4[508] (`KSTACK_REGION`) while
/// IST stacks and print buffers are statics in `.bss` (PML4[511] kernel
/// image).  These slots can't overlap by construction.
///
/// We log the actual VA ranges once at boot — future investigators see
/// the geometry in the boot log, and the panic-on-overlap guards against
/// a refactor that moves one of these regions into a colliding slot.
pub fn log_static_buffer_layout() {
    let (ist_lo, ist_hi) = gdt::ist_stack_va_range();
    let (pb_lo, pb_hi) = serial::print_buf_va_range();
    let kstack_lo = mm::KSTACK_REGION_BASE;
    let kstack_hi = mm::KSTACK_REGION_BASE + mm::PML4_SLOT_SIZE;
    crate::println!(
        "VM-LAYOUT: IST [{:#x}..{:#x}) PRINT [{:#x}..{:#x}) KSTACK [{:#x}..{:#x})",
        ist_lo, ist_hi, pb_lo, pb_hi, kstack_lo, kstack_hi,
    );
    let overlap = |a_lo: u64, a_hi: u64| {
        a_lo < kstack_hi && a_hi > kstack_lo
    };
    if overlap(ist_lo, ist_hi) {
        panic!(
            "VM-LAYOUT-BAD: IST stacks [{:#x}..{:#x}) overlap KSTACK_REGION [{:#x}..{:#x})",
            ist_lo, ist_hi, kstack_lo, kstack_hi,
        );
    }
    if overlap(pb_lo, pb_hi) {
        panic!(
            "VM-LAYOUT-BAD: print bufs [{:#x}..{:#x}) overlap KSTACK_REGION [{:#x}..{:#x})",
            pb_lo, pb_hi, kstack_lo, kstack_hi,
        );
    }
}

/// Set up page tables and enable the MMU.
pub fn enable_mmu() {
    let pml4 = mm::setup_tables().expect("page tables");
    mm::enable_mmu(pml4);
    crate::println!("  MMU enabled (PML4 at {:#x})", pml4);
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
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
