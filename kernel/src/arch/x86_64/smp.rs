//! x86-64 SMP: LAPIC-based AP startup via INIT-SIPI-SIPI sequence.
//!
//! The BSP copies an AP trampoline to low memory (0x8000), fills in
//! startup parameters, and sends INIT + SIPI to each AP.

use crate::sched::smp::{self, MAX_CPUS};
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

/// Physical address where the AP trampoline is copied.
const TRAMPOLINE_PHYS: usize = 0x8000;
/// SIPI vector = trampoline physical page number.
const SIPI_VECTOR: u8 = (TRAMPOLINE_PHYS >> 12) as u8; // 0x08

/// Offset of the data block within the trampoline page.
const DATA_OFFSET: usize = 0xF00;

/// Number of APs that have completed init.
static AP_READY_COUNT: AtomicU32 = AtomicU32::new(0);

/// Per-AP boot stack size (4 pages).
const AP_STACK_SIZE: usize = 16384;

/// Per-AP boot stacks. Stored as a dynamic flat byte slice of length
/// `num_cpus() * AP_STACK_SIZE`, allocated by `init_dynamic_percpu` from
/// phys after `phys::init`. Indexed by kernel CPU id (== LAPIC ID on x86_64
/// for the dense QEMU/most-real-hardware layout). The trampoline is only
/// invoked for APs with id < num_cpus(), so an out-of-range LAPIC ID (in
/// theory possible on sparse-APIC-ID hardware) is filtered out before we
/// dereference the slice.
static AP_STACKS_PTR: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn ap_stack_top(cpu: usize) -> u64 {
    let base = AP_STACKS_PTR.load(Ordering::Relaxed);
    debug_assert!(!base.is_null(), "AP_STACKS not init");
    debug_assert!(cpu < smp::num_cpus());
    unsafe { base.add((cpu + 1) * AP_STACK_SIZE) as u64 }
}

/// Allocate the dynamic AP boot-stack region. Called from
/// `smp::init_dynamic_percpu` after `phys::init`.
pub(crate) fn init_dynamic_percpu() {
    let n = smp::num_cpus();
    let total = n.checked_mul(AP_STACK_SIZE).expect("AP stack overflow");
    unsafe {
        let s = crate::mm::phys::alloc_static_slice::<u8>(total);
        AP_STACKS_PTR.store(s.as_mut_ptr(), Ordering::Release);
    }
    // Per-AP GDT/TSS slices.
    super::gdt::init_dynamic_percpu();
}

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
        core::ptr::copy_nonoverlapping(trampoline_src, TRAMPOLINE_PHYS as *mut u8, trampoline_size);
    }

    let bsp_id = super::lapic::id();

    // Get PML4 from CR3 (BSP's page tables — identity mapped, shared with APs).
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3);
    }
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

    // Build list of APIC IDs to start. Use ACPI MADT if available,
    // otherwise probe sequentially 0..num_cpus().
    //
    // Cap at num_cpus()-1 entries (the BSP doesn't need an AP slot). The
    // resulting list is sized by the runtime CPU count, not MAX_CPUS, so
    // the bitmap-width compile-time ceiling can be raised aggressively
    // without enlarging this stack-resident scratch buffer.
    let fw_cpus = crate::firmware::cpus();
    let n = smp::num_cpus();
    let mut ap_ids = [0u32; MAX_CPUS];
    let mut ap_count = 0usize;
    let cap = n.saturating_sub(1);

    if !fw_cpus.is_empty() {
        for desc in fw_cpus {
            if desc.id == bsp_id || desc.flags & 1 == 0 {
                continue;
            }
            // Skip APIC IDs that exceed our runtime CPU count: they have
            // no AP stack slot allocated and can't participate in
            // scheduling without growing every per-CPU slice.
            if (desc.id as usize) >= n {
                continue;
            }
            if ap_count < cap {
                ap_ids[ap_count] = desc.id;
                ap_count += 1;
            }
        }
    } else {
        // Fallback: probe sequential IDs.
        for id in 0..(n as u32) {
            if id == bsp_id {
                continue;
            }
            if ap_count >= cap {
                break;
            }
            ap_ids[ap_count] = id;
            ap_count += 1;
        }
    }

    // Start each AP one at a time.
    let mut expected_aps = 0u32;
    let mut consecutive_timeouts = 0u32;
    for i in 0..ap_count {
        let cpu = ap_ids[i];

        let stack_top = ap_stack_top(cpu as usize);

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
            core::ptr::copy_nonoverlapping(gdt_ptr_bytes.as_ptr(), data_base.add(0x20), 10);
            // +0x30: 32-bit GDT (3 descriptors x 8 bytes = 24 bytes).
            let gdt32_base = data_base.add(0x30) as *mut u64;
            core::ptr::write_unaligned(gdt32_base.add(0), 0x0000_0000_0000_0000); // null
            core::ptr::write_unaligned(gdt32_base.add(1), 0x00CF_9A00_0000_FFFF); // 32-bit code
            core::ptr::write_unaligned(gdt32_base.add(2), 0x00CF_9200_0000_FFFF); // 32-bit data
            // +0x48: 32-bit GDT pointer (2-byte limit + 4-byte base).
            let gdt32_ptr = data_base.add(0x48);
            core::ptr::write_unaligned(gdt32_ptr as *mut u16, 23); // 3*8 - 1
            core::ptr::write_unaligned(
                gdt32_ptr.add(2) as *mut u32,
                (TRAMPOLINE_PHYS + DATA_OFFSET + 0x30) as u32,
            ); // base
        }

        // INIT-SIPI-SIPI sequence.
        super::lapic::send_init(cpu);
        super::lapic::delay_us(200);

        super::lapic::send_sipi(cpu, SIPI_VECTOR);
        super::lapic::delay_us(20);

        super::lapic::send_sipi(cpu, SIPI_VECTOR); // Second SIPI.
        super::lapic::delay_us(20);

        // Wait for this AP to signal ready (with timeout).
        expected_aps += 1;
        let target_count = expected_aps;
        let mut timeout = 5_000_000u64;
        while AP_READY_COUNT.load(Ordering::Acquire) < target_count {
            core::hint::spin_loop();
            timeout -= 1;
            if timeout == 0 {
                crate::println!("  CPU {} (APIC {}) startup timeout", i + 1, cpu);
                expected_aps -= 1;
                consecutive_timeouts += 1;
                break;
            }
        }
        if timeout > 0 {
            consecutive_timeouts = 0;
        }
        // With MADT data, all CPUs should be present — but still stop
        // after 2 consecutive timeouts as a safety net.
        if consecutive_timeouts >= 2 && fw_cpus.is_empty() {
            break;
        }
    }

    crate::println!("  {} CPUs online", crate::sched::smp::online_cpus());
}

/// Rust entry point for APs. Called from the trampoline in 64-bit mode.
#[unsafe(no_mangle)]
extern "C" fn ap_rust_entry(cpu_id: u32) {
    // Initialize this CPU's LAPIC.
    super::lapic::init_ap();

    // Load per-CPU GDT with TSS (needed for ring 3→0 transitions).
    super::gdt::init_ap(cpu_id);

    // Load the IDT (shared with BSP — it's at a fixed address).
    super::idt::load();

    // Set up LAPIC timer for this CPU.
    super::lapic::setup_timer();

    // Register with the scheduler.
    crate::sched::scheduler::init_ap(cpu_id);
    crate::sched::topology::init_ap(cpu_id);

    // Signal ready.
    AP_READY_COUNT.fetch_add(1, Ordering::Release);

    crate::println!("  CPU {} online (LAPIC ID {})", cpu_id, super::lapic::id());

    // Enable interrupts and idle.
    unsafe {
        core::arch::asm!("sti");
    }
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
