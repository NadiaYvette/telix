//! x86-64 SMP: LAPIC-based AP startup via INIT-SIPI-SIPI sequence.
//!
//! The BSP copies an AP trampoline to low memory (0x8000), fills in
//! startup parameters, and sends INIT + SIPI to each AP.

use crate::sched::smp::MAX_CPUS;
use core::sync::atomic::{AtomicU32, Ordering};

/// Physical address where the AP trampoline is copied.
const TRAMPOLINE_PHYS: usize = 0x8000;
/// SIPI vector = trampoline physical page number.
const SIPI_VECTOR: u8 = (TRAMPOLINE_PHYS >> 12) as u8; // 0x08

/// Offset of the data block within the trampoline page.
const DATA_OFFSET: usize = 0xF00;

/// Number of APs that have completed init.
static AP_READY_COUNT: AtomicU32 = AtomicU32::new(0);

/// Per-AP boot stacks.
const AP_STACK_SIZE: usize = 16384;
#[repr(C, align(16))]
struct ApStacks([[u8; AP_STACK_SIZE]; MAX_CPUS]);
static mut AP_STACKS: ApStacks = ApStacks([[0u8; AP_STACK_SIZE]; MAX_CPUS]);

/// Start secondary CPUs via INIT-SIPI-SIPI.
pub fn start_secondary_cpus() {
    // Get trampoline blob boundaries.
    unsafe extern "C" {
        static _ap_trampoline_start: u8;
        static _ap_trampoline_end: u8;
    }
    let trampoline_src = unsafe { &_ap_trampoline_start as *const u8 };
    let trampoline_end = unsafe { &_ap_trampoline_end as *const u8 };
    let trampoline_size = trampoline_end as usize - trampoline_src as usize;

    // Copy trampoline to low memory.
    unsafe {
        core::ptr::copy_nonoverlapping(
            trampoline_src,
            TRAMPOLINE_PHYS as *mut u8,
            trampoline_size,
        );
    }

    let bsp_id = super::lapic::id();

    // Get PML4 from CR3 (BSP's page tables — identity mapped, shared with APs).
    let cr3: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3); }
    let pml4 = cr3 as u32; // PML4 physical address fits in 32 bits.

    // Get the GDT pointer that the APs should use (same as BSP).
    // We read it from the current GDTR.
    let mut gdt_ptr_bytes = [0u8; 10];
    unsafe {
        core::arch::asm!(
            "sgdt [{}]",
            in(reg) gdt_ptr_bytes.as_mut_ptr(),
            options(nostack),
        );
    }

    // Start each AP one at a time.
    let mut expected_aps = 0u32;
    for cpu in 0..(MAX_CPUS as u32) {
        if cpu == bsp_id {
            continue;
        }

        let stack_top = unsafe {
            AP_STACKS.0[cpu as usize].as_ptr().add(AP_STACK_SIZE) as u64
        };

        // Write the data block at TRAMPOLINE_PHYS + DATA_OFFSET.
        let data_base = (TRAMPOLINE_PHYS + DATA_OFFSET) as *mut u8;
        unsafe {
            // +0x00: PML4 (u32)
            core::ptr::write_unaligned(data_base.add(0x00) as *mut u32, pml4);
            // +0x08: stack (u64)
            core::ptr::write_unaligned(data_base.add(0x08) as *mut u64, stack_top);
            // +0x10: cpu_id (u32)
            core::ptr::write_unaligned(data_base.add(0x10) as *mut u32, cpu);
            // +0x18: entry point (u64)
            core::ptr::write_unaligned(
                data_base.add(0x18) as *mut u64,
                ap_rust_entry as *const () as u64,
            );
            // +0x20: 64-bit GDT pointer (10 bytes: 2-byte limit + 8-byte base).
            // Copy the BSP's GDTR.
            core::ptr::copy_nonoverlapping(
                gdt_ptr_bytes.as_ptr(),
                data_base.add(0x20),
                10,
            );
            // +0x30: 32-bit GDT (3 descriptors x 8 bytes = 24 bytes).
            let gdt32_base = data_base.add(0x30) as *mut u64;
            core::ptr::write_unaligned(gdt32_base.add(0), 0x0000_0000_0000_0000); // null
            core::ptr::write_unaligned(gdt32_base.add(1), 0x00CF_9A00_0000_FFFF); // 32-bit code
            core::ptr::write_unaligned(gdt32_base.add(2), 0x00CF_9200_0000_FFFF); // 32-bit data
            // +0x48: 32-bit GDT pointer (2-byte limit + 4-byte base).
            let gdt32_ptr = data_base.add(0x48);
            core::ptr::write_unaligned(gdt32_ptr as *mut u16, 23); // 3*8 - 1
            core::ptr::write_unaligned(gdt32_ptr.add(2) as *mut u32,
                (TRAMPOLINE_PHYS + DATA_OFFSET + 0x30) as u32); // base
        }

        // INIT-SIPI-SIPI sequence.
        // Delays are minimal — QEMU processes IPIs immediately.
        super::lapic::send_init(cpu);
        super::lapic::delay_us(200);

        super::lapic::send_sipi(cpu, SIPI_VECTOR);
        super::lapic::delay_us(20);

        super::lapic::send_sipi(cpu, SIPI_VECTOR); // Second SIPI.
        super::lapic::delay_us(20);

        // Wait for this AP to signal ready (with timeout).
        expected_aps += 1;
        let target_count = expected_aps;
        let mut timeout = 100_000_000u64;
        while AP_READY_COUNT.load(Ordering::Acquire) < target_count {
            core::hint::spin_loop();
            timeout -= 1;
            if timeout == 0 {
                crate::println!("  CPU {} startup timeout", cpu);
                break;
            }
        }
    }

    crate::println!("  {} CPUs online", crate::sched::smp::online_cpus());
}

/// Rust entry point for APs. Called from the trampoline in 64-bit mode.
#[unsafe(no_mangle)]
extern "C" fn ap_rust_entry(cpu_id: u32) {
    // Initialize this CPU's LAPIC.
    super::lapic::init_ap();

    // Load the IDT (shared with BSP — it's at a fixed address).
    super::idt::load();

    // Set up LAPIC timer for this CPU.
    super::lapic::setup_timer();

    // Register with the scheduler.
    crate::sched::scheduler::init_ap(cpu_id);

    // Signal ready.
    AP_READY_COUNT.fetch_add(1, Ordering::Release);

    crate::println!("  CPU {} online (LAPIC ID {})", cpu_id, super::lapic::id());

    // Enable interrupts and idle.
    unsafe { core::arch::asm!("sti"); }
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
