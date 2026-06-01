//! LoongArch64 SMP: secondary core bring-up via memory-rendezvous + IPI.
//!
//! Unlike PSCI (aarch64) or SBI HSM (riscv64), there is no firmware hook
//! that takes a (target_core, entry, stack) tuple.  QEMU's `virt` machine
//! launches every core directly at `_start`; the atomic increment of
//! `_boot_lock` in boot.S elects core 0 as the BSP and the others fall
//! through to `.secondary_spin`, which polls a per-core slot in
//! `_ap_entry_slot` for an (entry, stack_top) pair.
//!
//! Once the BSP has finished its own MMU/scheduler init it allocates the
//! AP stacks and fills the slot for each secondary core in turn.  We
//! also `send_ipi` to that core so a future implementation can have the
//! APs use `idle 0` instead of busy-polling; the current spin path doesn't
//! require it but keeping IPIs in the start path is the symmetry the
//! other arches enforce.

use crate::sched::smp::{self, MAX_CPUS};
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

/// Per-AP boot stack size (matches aarch64/riscv64).
const AP_STACK_SIZE: usize = 16384;

/// Number of secondary cores that have completed init.
static AP_READY_COUNT: AtomicU32 = AtomicU32::new(0);

/// Per-core boot stacks for secondaries.  Allocated by
/// `init_dynamic_percpu` from phys after `phys::init`.  Indexed by
/// linear CPU id (0 = BSP, 1.. = secondaries).
static AP_STACKS_PTR: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

/// Per-core (entry, stack_top) slots that boot.S's `.ap_poll` reads.
/// 16 B per slot — see `boot.S`.  Defined as `extern "C"` because the
/// asm needs the symbol.
unsafe extern "C" {
    /// `[(entry: u64, stack_top: u64); MAX_CPUS]` — written from
    /// `start_secondary_cpus` below; polled by secondaries in boot.S.
    static _ap_entry_slot: [u64; MAX_CPUS * 2];
}

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

/// Start secondary CPUs.  Writes (secondary_rust_entry, stack_top) into
/// each AP's `_ap_entry_slot` entry, sends an IPI as a wake nudge, then
/// waits for `AP_READY_COUNT` to match the number started.
pub fn start_secondary_cpus() {
    let entry = secondary_rust_entry as *const () as u64;
    let n = smp::num_cpus();
    let mut started = 0u32;

    let slot_ptr = (&raw const _ap_entry_slot) as *mut u64;

    for cpu in 1..n {
        let stack_top = ap_stack_top(cpu);
        unsafe {
            // Stack first so the secondary observes it once entry != 0.
            core::ptr::write_volatile(slot_ptr.add(cpu * 2 + 1), stack_top);
            core::sync::atomic::fence(Ordering::Release);
            core::ptr::write_volatile(slot_ptr.add(cpu * 2), entry);
        }
        // Nudge: if the secondary ever uses `idle 0` in its spin we want
        // the IPI to wake it.  Today's busy-poll path doesn't need it.
        super::trap::send_ipi(cpu as u32);
        started += 1;
    }

    if started == 0 {
        crate::println!("  Single-CPU mode (no secondaries to start)");
        smp::NR_CPUS.store(1, Ordering::Release);
        return;
    }

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

/// AP entry point — jumped to by boot.S `.ap_poll` once the BSP fills
/// this core's slot.  `a0` is the core id (CSR.CPUID) and the stack has
/// already been switched to the per-AP region.  Identity to the BSP
/// from here on: MMU, trap vectors, then register with the scheduler
/// and drop into the idle loop.
#[unsafe(no_mangle)]
extern "C" fn secondary_rust_entry(cpu_id: u64) -> ! {
    let cpu = cpu_id as u32;

    super::mm::enable_mmu_secondary();
    super::trap::init();

    crate::sched::scheduler::init_ap(cpu);
    crate::sched::topology::init_ap(cpu);

    AP_READY_COUNT.fetch_add(1, Ordering::Release);

    super::trap::enable_interrupts();
    crate::println!("  CPU {} online", cpu);

    loop {
        unsafe {
            core::arch::asm!("idle 0");
        }
    }
}
