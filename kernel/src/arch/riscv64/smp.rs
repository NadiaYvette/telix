//! RISC-V SMP: secondary hart bring-up via SBI HSM extension.
//!
//! The SBI HSM (Hart State Management) extension starts secondary harts
//! at a specified entry point with an opaque value in a1.

use crate::sched::smp::MAX_CPUS;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// SBI HSM extension ID and function IDs.
const SBI_EXT_HSM: u64 = 0x48534D;
const SBI_HSM_HART_START: u64 = 0;

/// Number of secondary harts that have completed init.
static AP_READY_COUNT: AtomicU32 = AtomicU32::new(0);

/// Stack tops for secondary harts, indexed by CPU index (not hart ID).
/// Accessed from boot.S, hence no_mangle.
#[unsafe(no_mangle)]
static AP_STACK_TOPS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// CPU index for each hart (written by BSP, read by secondary).
/// Maps hart_id → cpu_index.
#[allow(dead_code)]
static HART_TO_CPU: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

/// SBI ecall: hart_start(hartid, start_addr, opaque).
/// opaque is passed in a1 to the started hart.
fn sbi_hart_start(hartid: u64, start_addr: u64, opaque: u64) -> i64 {
    let error: i64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a0") hartid,
            in("a1") start_addr,
            in("a2") opaque,
            in("a6") SBI_HSM_HART_START,
            in("a7") SBI_EXT_HSM,
            lateout("a0") error,
            lateout("a1") _,
        );
    }
    error
}

/// Per-CPU boot stacks for secondary harts.
const AP_STACK_SIZE: usize = 16384;
#[repr(C, align(16))]
struct ApStacks([[u8; AP_STACK_SIZE]; MAX_CPUS]);
static mut AP_STACKS: ApStacks = ApStacks([[0u8; AP_STACK_SIZE]; MAX_CPUS]);

/// Start secondary harts. Called by BSP after scheduler init.
pub fn start_secondary_cpus() {
    unsafe extern "C" {
        fn _secondary_hart_entry();
    }
    let entry = _secondary_hart_entry as *const () as u64;
    let boot_hart = super::boot::BOOT_HART_ID.load(Ordering::Relaxed) as u64;

    let fw_cpus = crate::firmware::cpus();
    let mut cpu_index: usize = 1;
    let mut started = 0u32;

    if fw_cpus.len() > 1 {
        // Use firmware-discovered hart list.
        for desc in fw_cpus.iter() {
            let hartid = desc.id as u64;
            if hartid == boot_hart {
                continue; // Skip the boot hart.
            }
            if cpu_index >= MAX_CPUS { break; }

            let stack_top = unsafe {
                AP_STACKS.0[cpu_index].as_ptr().add(AP_STACK_SIZE) as u64
            };
            AP_STACK_TOPS[cpu_index].store(stack_top, Ordering::Release);

            let ret = sbi_hart_start(hartid, entry, cpu_index as u64);
            if ret != 0 {
                crate::println!("  SBI hart_start for hart {} failed: {}", hartid, ret);
            } else {
                started += 1;
            }
            cpu_index += 1;
        }
    } else {
        // Fallback: probe sequentially (original behavior).
        for hartid in 0..(MAX_CPUS as u64) {
            if hartid == boot_hart {
                continue;
            }

            let stack_top = unsafe {
                AP_STACKS.0[cpu_index].as_ptr().add(AP_STACK_SIZE) as u64
            };
            AP_STACK_TOPS[cpu_index].store(stack_top, Ordering::Release);

            let ret = sbi_hart_start(hartid, entry, cpu_index as u64);
            if ret != 0 {
                crate::println!("  SBI hart_start for hart {} failed: {}", hartid, ret);
            } else {
                started += 1;
            }
            cpu_index += 1;
        }
    }

    if started == 0 {
        crate::println!("  Single-CPU mode (no secondaries started)");
        return;
    }

    // Wait for all successfully started secondaries, with timeout.
    let mut timeout = 100_000_000u64;
    while AP_READY_COUNT.load(Ordering::Acquire) < started {
        core::hint::spin_loop();
        timeout -= 1;
        if timeout == 0 {
            crate::println!("  SMP startup timeout ({}/{} harts ready)",
                AP_READY_COUNT.load(Ordering::Relaxed) + 1, started + 1);
            break;
        }
    }
    let online = AP_READY_COUNT.load(Ordering::Relaxed) + 1;
    crate::println!("  All {} CPUs online", online);
}

/// Secondary hart Rust entry point.
/// cpu_id is set from the opaque parameter passed via SBI.
#[unsafe(no_mangle)]
extern "C" fn secondary_hart_rust_entry(cpu_id: u64) {
    let cpu = cpu_id as u32;

    // Enable MMU using BSP's kernel page table (must happen before user VA handling).
    super::mm::enable_mmu_secondary();

    // Set tp = cpu_id for smp::cpu_id().
    unsafe {
        core::arch::asm!("mv tp, {}", in(reg) cpu_id);
    }

    // Install trap vector and ensure sscratch = 0 (S-mode convention).
    unsafe {
        core::arch::asm!(
            "csrw sscratch, zero",
            "la {tmp}, _trap_entry",
            "csrw stvec, {tmp}",
            tmp = out(reg) _,
        );
    }

    // Configure timer for this hart.
    super::trap::init_ap();

    // Register with the scheduler.
    crate::sched::scheduler::init_ap(cpu);
    crate::sched::topology::init_ap(cpu);

    // Signal ready.
    AP_READY_COUNT.fetch_add(1, Ordering::Release);

    // Enable interrupts and enter idle loop.
    super::trap::enable_interrupts();
    crate::println!("  CPU {} (hart) online", cpu);
    loop {
        unsafe { core::arch::asm!("wfi"); }
    }
}
