//! AArch64 SMP: secondary core bring-up via PSCI CPU_ON.
//!
//! QEMU virt provides PSCI via HVC (when running with EL2 firmware).
//! The PSCI CPU_ON function starts a secondary core at a given entry point.

use crate::sched::smp::MAX_CPUS;
use core::sync::atomic::{AtomicU32, Ordering};

/// PSCI function IDs (SMCCC convention, 64-bit).
const PSCI_CPU_ON_64: u64 = 0xC400_0003;

/// Number of secondary CPUs that have completed init.
static AP_READY_COUNT: AtomicU32 = AtomicU32::new(0);

/// Invoke PSCI CPU_ON via HVC.
/// target_cpu: MPIDR value of the target CPU.
/// entry_point: physical address of the entry function.
/// context_id: passed in x0 to the entry function.
fn psci_cpu_on(target_cpu: u64, entry_point: u64, context_id: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") PSCI_CPU_ON_64 => ret,
            in("x1") target_cpu,
            in("x2") entry_point,
            in("x3") context_id,
        );
    }
    ret
}

/// Per-CPU boot stacks for secondary cores (allocated statically).
/// Each secondary gets a 16 KiB stack.
const AP_STACK_SIZE: usize = 16384;
#[repr(C, align(16))]
struct ApStacks([[u8; AP_STACK_SIZE]; MAX_CPUS]);
static mut AP_STACKS: ApStacks = ApStacks([[0u8; AP_STACK_SIZE]; MAX_CPUS]);

/// Start secondary CPUs. Called by BSP after scheduler init.
pub fn start_secondary_cpus() {
    // Get the entry point symbol from boot.S.
    unsafe extern "C" {
        fn _secondary_entry();
    }
    let entry = _secondary_entry as *const () as u64;

    for cpu in 1..MAX_CPUS {
        let target_mpidr = cpu as u64; // QEMU virt: MPIDR Aff0 = cpu index
        let stack_top = unsafe {
            AP_STACKS.0[cpu].as_ptr().add(AP_STACK_SIZE) as u64
        };

        // Pass stack_top as context_id (arrives in x0 on secondary).
        // The secondary reads its CPU ID from MPIDR_EL1.
        let ret = psci_cpu_on(target_mpidr, entry, stack_top);
        if ret != 0 {
            crate::println!("  PSCI CPU_ON for CPU {} failed: {}", cpu, ret);
            continue;
        }
    }

    // Wait for all secondaries to report ready.
    let expected = (MAX_CPUS - 1) as u32;
    while AP_READY_COUNT.load(Ordering::Acquire) < expected {
        core::hint::spin_loop();
    }
    crate::println!("  All {} CPUs online", MAX_CPUS);
}

/// Secondary CPU Rust entry point. Called from _secondary_entry in boot.S.
/// cpu_id already set via MPIDR, stack already set.
#[unsafe(no_mangle)]
extern "C" fn secondary_rust_entry(cpu_id: u64) {
    let cpu = cpu_id as u32;

    // Set TPIDR_EL1 = cpu_id for smp::cpu_id().
    unsafe {
        core::arch::asm!("msr tpidr_el1, {}", in(reg) cpu_id);
    }

    // Enable MMU with the BSP's kernel page table.
    super::mm::enable_mmu_secondary();

    // Install exception vectors.
    unsafe {
        core::arch::asm!(
            "adr x0, __exception_vectors",
            "msr vbar_el1, x0",
            "isb",
            out("x0") _,
        );
    }

    // Init GICv3 redistributor for this CPU.
    super::irq::init_cpu(cpu);

    // Init and enable timer for this CPU.
    super::timer::init_ap();

    // Register with the scheduler (creates idle thread for this CPU).
    crate::sched::scheduler::init_ap(cpu);

    // Signal that we're ready.
    AP_READY_COUNT.fetch_add(1, Ordering::Release);

    // Enable interrupts and enter idle loop.
    super::timer::enable_interrupts();
    crate::println!("  CPU {} online", cpu);
    loop {
        unsafe { core::arch::asm!("wfi"); }
    }
}
