//! AArch64 SMP: secondary core bring-up via PSCI CPU_ON.
//!
//! QEMU virt provides PSCI via HVC (when running with EL2 firmware).
//! The PSCI CPU_ON function starts a secondary core at a given entry point.

use crate::sched::smp;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

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

/// Each secondary gets a 16 KiB boot stack.
const AP_STACK_SIZE: usize = 16384;

/// Per-CPU boot stacks for secondary cores. Stored as a dynamic flat byte
/// slice of length `num_cpus() * AP_STACK_SIZE`, allocated by
/// `init_dynamic_percpu` from phys after `phys::init`. Indexed by linear
/// CPU id (0 = BSP, 1.. = secondaries).
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
}

/// Start secondary CPUs. Called by BSP after scheduler init.
pub fn start_secondary_cpus() {
    // Get the entry point symbol from boot.S.
    unsafe extern "C" {
        fn _secondary_entry();
    }
    let entry = _secondary_entry as *const () as u64;

    let fw_cpus = crate::firmware::cpus();
    let mut started = 0u32;

    let n = smp::num_cpus();
    if fw_cpus.len() > 1 {
        // Use firmware-discovered CPU list (skip first = BSP).
        for (i, desc) in fw_cpus.iter().enumerate() {
            if i == 0 {
                continue;
            } // BSP
            if i >= n {
                break;
            }
            let target_mpidr = desc.id as u64;
            let stack_top = ap_stack_top(i);
            let ret = psci_cpu_on(target_mpidr, entry, stack_top);
            if ret != 0 {
                crate::println!(
                    "  PSCI CPU_ON for MPIDR {:#x} failed: {}",
                    target_mpidr,
                    ret
                );
                continue;
            }
            started += 1;
        }
    } else {
        // Fallback: probe sequentially (original behavior).
        for cpu in 1..n {
            let target_mpidr = cpu as u64;
            let stack_top = ap_stack_top(cpu);
            let ret = psci_cpu_on(target_mpidr, entry, stack_top);
            if ret != 0 {
                break;
            }
            started += 1;
        }
    }

    if started == 0 {
        crate::println!("  Single-CPU mode (no secondaries started)");
        // Clamp NR_CPUS to 1 so the scheduler only uses CPU 0's run queue.
        smp::NR_CPUS.store(1, Ordering::Release);
        return;
    }

    // Wait for all successfully started secondaries, with timeout.
    let mut timeout = 100_000_000u64;
    while AP_READY_COUNT.load(Ordering::Acquire) < started {
        core::hint::spin_loop();
        timeout -= 1;
        if timeout == 0 {
            crate::println!(
                "  SMP startup timeout ({}/{} CPUs ready)",
                AP_READY_COUNT.load(Ordering::Relaxed) + 1,
                started + 1
            );
            break;
        }
    }
    let online = AP_READY_COUNT.load(Ordering::Relaxed) + 1;
    crate::println!("  All {} CPUs online", online);
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
    crate::sched::topology::init_ap(cpu);

    // Signal that we're ready.
    AP_READY_COUNT.fetch_add(1, Ordering::Release);

    // Enable interrupts and enter idle loop.
    super::timer::enable_interrupts();
    crate::println!("  CPU {} online", cpu);
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}
