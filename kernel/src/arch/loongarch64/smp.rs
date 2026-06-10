//! LoongArch64 SMP: secondary core bring-up via IOCSR MailBox + IPI.
//!
//! Unlike PSCI (aarch64) or SBI HSM (riscv64), the LoongArch wake
//! protocol uses the per-core IPI/MailBox unit (3A5000 manual chapter
//! 10).  APs sit halted at hardware reset waiting for any IPI bit; the
//! BSP wakes each one by stamping its entry_pc into MailBox0 (via the
//! local `Mail_Send` register) and then sending an `ACTION_BOOT_CPU`
//! IPI.  Firmware (QEMU virt's emulated stub, or hardware UEFI on real
//! 3A5000) reads MailBox0 and jumps there — matching the convention
//! Linux's `arch/loongarch/kernel/smp.c` uses.
//!
//! The AP entry point (`ap_wake_entry` in boot.S) reads its own
//! `CSR.CPUID`, looks up its stack from `_ap_entry_slot` (which the
//! BSP filled before sending the wake IPI), sets `$sp`, and calls
//! `secondary_rust_entry`.  Identity with x86_64/aarch64/riscv64 from
//! there on.

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

/// Per-core (entry, stack_top) slots that the AP entry stub
/// (`ap_wake_entry` in boot.S) consults to find its stack.  16 B per
/// slot.  The `entry` field is no longer required for control flow
/// (the wake IPI delivers the entry via MailBox0) but we still write
/// it for diagnostic clarity and to leave room for hot-plug or future
/// non-MBUF wake paths.  Defined as `extern "C"` because boot.S needs
/// the symbol.
unsafe extern "C" {
    /// `[(entry: u64, stack_top: u64); MAX_CPUS]` — written from
    /// `start_secondary_cpus` below; the `stack_top` half is what
    /// `ap_wake_entry` actually reads.
    static _ap_entry_slot: [u64; MAX_CPUS * 2];
    /// AP wake entry point — destination of the MailBox-delivered
    /// entry_pc.  Defined as a global label in boot.S.
    fn ap_wake_entry();
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

/// Start secondary CPUs via the LoongArch IOCSR wake protocol (#257).
///
/// For each AP we:
///   1. Fill `_ap_entry_slot[cpu]` with `(ap_wake_entry, stack_top)`
///      so the AP's entry stub can find its stack via `CSR.CPUID`
///      lookup after the firmware hands off control.
///   2. Stamp `ap_wake_entry`'s VA into the AP's MailBox0 via the
///      `Mail_Send` register.  Two 32-bit BLOCKING writes; the
///      BLOCKING flag self-fences each one.
///   3. Send `ACTION_BOOT_CPU` IPI; the AP wakes from halt, firmware
///      reads MailBox0 and jumps to `ap_wake_entry`.
///
/// Then waits for `AP_READY_COUNT` to match.  Matches the convention
/// Linux `arch/loongarch/kernel/smp.c` `loongson_boot_secondary` uses.
pub fn start_secondary_cpus() {
    let entry = ap_wake_entry as *const () as u64;
    let n = smp::num_cpus();
    let mut started = 0u32;

    let slot_ptr = (&raw const _ap_entry_slot) as *mut u64;

    for cpu in 1..n {
        let stack_top = ap_stack_top(cpu);
        unsafe {
            // Stack first so the AP's CSR.CPUID lookup finds it before
            // we hand off via MailBox.  Both writes precede mail_send_to,
            // which is BLOCKING and acts as a release boundary.
            core::ptr::write_volatile(slot_ptr.add(cpu * 2 + 1), stack_top);
            core::ptr::write_volatile(slot_ptr.add(cpu * 2), entry);
        }
        // Stamp entry_pc into the AP's MailBox0 and send the wake IPI.
        // mail_send_to is BLOCKING; send_ipi_action is BLOCKING too.
        super::trap::mail_send_to(cpu as u32, 0, entry);
        super::trap::send_ipi_action(
            cpu as u32,
            super::trap::ACTION_BOOT_CPU,
        );
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
