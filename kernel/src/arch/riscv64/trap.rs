//! RISC-V trap handling.
//!
//! RISC-V uses a single trap vector for all exceptions and interrupts.
//! The trap entry/exit assembly is in vectors.S.
//! This file contains the Rust handler functions called from those stubs.

use core::sync::atomic::{AtomicU64, Ordering};

static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Timer interval in time-base ticks (set during init).
static TIMER_INTERVAL: AtomicU64 = AtomicU64::new(0);

/// Exception/trap context saved on the stack by the vector entry stub.
/// Layout must match vectors.S exactly.
#[repr(C)]
pub struct TrapFrame {
    pub regs: [u64; 31], // x1-x31 (indices 0..31, where index i = register x(i+1))
    pub sepc: u64,       // saved exception PC
    pub sstatus: u64,    // saved status register
    pub scause: u64,     // trap cause (saved for convenience)
}

// scause values
const SCAUSE_INTERRUPT_BIT: u64 = 1 << 63;
const SCAUSE_S_SOFTWARE_IRQ: u64 = SCAUSE_INTERRUPT_BIT | 1;
const SCAUSE_S_TIMER_IRQ: u64 = SCAUSE_INTERRUPT_BIT | 5;
const SCAUSE_S_EXTERNAL_IRQ: u64 = SCAUSE_INTERRUPT_BIT | 9;
const SCAUSE_ECALL_FROM_UMODE: u64 = 8;
const SCAUSE_ECALL_FROM_SMODE: u64 = 9;
const SCAUSE_INST_PAGE_FAULT: u64 = 12;
const SCAUSE_LOAD_PAGE_FAULT: u64 = 13;
const SCAUSE_STORE_PAGE_FAULT: u64 = 15;

/// SBI TIME extension ID and function.
const SBI_EXT_TIME: u64 = 0x54494D45;
const SBI_FUN_SET_TIMER: u64 = 0;
/// SBI IPI extension ('sPI' = 0x735049) with function 0 = send_ipi
/// (hart_mask, hart_mask_base).  Used by send_reschedule_ipi to wake
/// another hart out of WFI when the scheduler decides it has work for it.
const SBI_EXT_IPI: u64 = 0x735049;
const SBI_FUN_SEND_IPI: u64 = 0;

/// Read the `time` CSR (or rdtime pseudo-instruction).
pub fn read_time() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("rdtime {}", out(reg) val) };
    val
}

/// Set the next timer deadline via SBI ecall.
fn sbi_set_timer(stime_value: u64) {
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a0") stime_value,
            in("a6") SBI_FUN_SET_TIMER,
            in("a7") SBI_EXT_TIME,
            lateout("a0") _,
            lateout("a1") _,
        );
    }
}

/// Send a reschedule IPI to `target_hart` via SBI.  Sets the target hart's
/// `msip` bit; the hart takes a supervisor software interrupt on its next
/// interruptible point (which includes waking from WFI), so a runnable
/// thread enqueued on its runqueue is seen by the next sched::tick.
pub fn sbi_send_ipi(target_hart: u32) {
    // SBI v0.2+ IPI extension (ID "sPI" = 0x735049): a0 is the hart
    // mask VALUE (not a pointer — that was the legacy v0.1 convention
    // and silently sent IPIs to garbage hart ids).  a1 is the base
    // hart id; bit n of the mask targets hart (base + n).
    let mask: u64 = 1u64 << (target_hart & 63);
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a0") mask,
            in("a1") 0u64,       /* hart_mask_base */
            in("a6") SBI_FUN_SEND_IPI,
            in("a7") SBI_EXT_IPI,
            lateout("a0") _,
            lateout("a1") _,
        );
    }
    SGI_SEND_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

pub static SGI_SEND_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static SGI_RECV_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Initialize trap handling: set stvec, configure timer.
pub fn init() {
    // Set stvec to our trap vector (direct mode) and ensure sscratch = 0 (S-mode).
    unsafe {
        core::arch::asm!(
            "csrw sscratch, zero",
            "la {tmp}, _trap_entry",
            "csrw stvec, {tmp}",
            tmp = out(reg) _,
        );
    }
    crate::println!("  Trap vector installed");

    // Configure the timer.
    // Use DTB-discovered timebase frequency, fall back to 10 MHz (QEMU default).
    let fw_freq = crate::firmware::timebase_freq();
    let freq: u64 = if fw_freq != 0 { fw_freq } else { 10_000_000 };
    let interval = freq / 100; // 100 Hz
    TIMER_INTERVAL.store(interval, Ordering::Relaxed);

    // Set first timer deadline.
    let now = read_time();
    sbi_set_timer(now + interval);

    // Enable S-mode timer interrupt and external interrupt in sie.
    unsafe {
        // sie.STIE = bit 5, sie.SEIE = bit 9
        // sie.STIE = bit 5, sie.SSIE = bit 1, sie.SEIE = bit 9.  SSIE
        // lets SBI-delivered software IPIs wake this hart.
        core::arch::asm!("csrs sie, {}", in(reg) (1u64 << 1) | (1u64 << 5) | (1u64 << 9));
    }

    // Initialize PLIC for hart 0.
    super::plic::init(0);

    crate::println!(
        "  Timer initialized: timebase={}Hz, interval={} ticks ({}ms)",
        freq,
        interval,
        1000 * interval / freq
    );
}

/// Initialize trap/timer on a secondary hart.
pub fn init_ap() {
    // Set stvec (already done in assembly, but be safe).
    unsafe {
        core::arch::asm!(
            "la {tmp}, _trap_entry",
            "csrw stvec, {tmp}",
            tmp = out(reg) _,
        );
    }

    // Set first timer deadline for this hart.
    let interval = TIMER_INTERVAL.load(Ordering::Relaxed);
    let now = read_time();
    sbi_set_timer(now + interval);

    // Enable S-mode timer and external interrupts in sie.
    unsafe {
        // sie.STIE = bit 5, sie.SSIE = bit 1, sie.SEIE = bit 9.  SSIE
        // lets SBI-delivered software IPIs wake this hart.
        core::arch::asm!("csrs sie, {}", in(reg) (1u64 << 1) | (1u64 << 5) | (1u64 << 9));
    }

    // Initialize PLIC for this hart.
    let hart: u32;
    unsafe {
        core::arch::asm!("mv {0}, tp", out(reg) hart);
    }
    super::plic::init(hart);
}

/// Enable S-mode interrupts (set sstatus.SIE).
pub fn enable_interrupts() {
    unsafe {
        core::arch::asm!("csrs sstatus, {}", in(reg) 1u64 << 1);
    }
}

/// Handle S-mode external interrupt via PLIC.
fn handle_external_irq() {
    // Determine hart ID from tp register.
    let hart: u32;
    unsafe {
        core::arch::asm!("mv {0}, tp", out(reg) hart);
    }

    let irq = super::plic::claim(hart);
    if irq == 0 {
        return; // Spurious
    }

    // Virtio-blk on QEMU virt is PLIC IRQ 1-8 (first virtio device = highest address = IRQ 8,
    // but QEMU virt maps them in reverse: device at 0x10008000 = IRQ 8, 0x10007000 = IRQ 7, etc.)
    // The virtio-blk device gets the first available IRQ. With a single virtio device added
    // via -device, it typically gets IRQ 1. We match any IRQ in 1..=8 to the virtio-blk handler.
    match irq {
        1..=8 => {
            // Try userspace dispatch first; fall back to kernel driver.
            if !crate::io::irq_dispatch::handle_irq(irq) {
                crate::drivers::virtio_blk::irq_handler();
            }
        }
        _ => {
            crate::println!("PLIC: unhandled IRQ {}", irq);
        }
    }

    super::plic::complete(hart, irq);
}

/// Handle timer interrupt: increment tick count. Timer is NOT rearmed here;
/// the scheduler calls `program_oneshot()` after processing the tick.
fn handle_timer_irq() {
    let _ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
}

/// Program the timer to fire at `deadline_ns` nanoseconds since boot.
pub fn program_oneshot(deadline_ns: u64) {
    let fw_freq = crate::firmware::timebase_freq();
    let freq = if fw_freq != 0 { fw_freq } else { 10_000_000 } as u128;
    let ticks = ((deadline_ns as u128 * freq) / 1_000_000_000u128) as u64;
    let now = read_time();
    let deadline = if ticks > now { ticks } else { now + 1 };
    sbi_set_timer(deadline);
}

/// Main Rust trap handler. Called from vectors.S with current SP as argument.
/// For timer interrupts, calls scheduler tick and returns (potentially new) SP.
/// For other traps, handles and returns same SP.
#[unsafe(no_mangle)]
extern "C" fn trap_handler(frame_sp: u64) -> u64 {
    // #246 Fix D drain — every trap entry must drain the per-CPU release
    // slot so threads transitioned to ON_CPU_RELEASING by try_switch are
    // CAS'd to ON_CPU_PENDING and become dispatchable on peer CPUs.
    // Without this, blocked threads stay stuck at on_cpu=RELEASING forever
    // and the SMP scheduler wedges (matches the aarch64 #246 surface).
    // Mirror of x86_64/exception.rs:1438.
    crate::sched::scheduler::finalize_release_after_stack_switch();
    // Mirror the aarch64 PARK_WOKEN arbitration drain so wake_parked_thread
    // deferred-local paths can complete on the parking hart.
    crate::sched::scheduler::clear_pending_switch(crate::sched::smp::cpu_id() as usize);
    let frame = unsafe { &mut *(frame_sp as *mut TrapFrame) };
    let scause = frame.scause;

    match scause {
        SCAUSE_S_TIMER_IRQ => {
            handle_timer_irq();
            // Let the scheduler decide if we should switch threads.
            crate::sched::tick(frame_sp)
        }

        SCAUSE_S_SOFTWARE_IRQ => {
            // SBI-delivered reschedule IPI.  Clear sip.SSIP and let the
            // scheduler run — sched::tick picks up any freshly-enqueued
            // work on this hart's runqueue.
            unsafe {
                core::arch::asm!("csrc sip, {}", in(reg) 1u64 << 1);
            }
            SGI_RECV_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            crate::sched::tick(frame_sp)
        }

        SCAUSE_S_EXTERNAL_IRQ => {
            handle_external_irq();
            frame_sp
        }

        SCAUSE_ECALL_FROM_SMODE | SCAUSE_ECALL_FROM_UMODE => {
            // Advance sepc past the ecall instruction (4 bytes).
            frame.sepc += 4;
            crate::sched::scheduler::store_frame_sp(frame_sp);
            crate::arch::irq::enable();
            crate::syscall::dispatch(frame);
            let _ = crate::arch::irq::disable();
            crate::sched::scheduler::check_preempt_on_return();
            let pending = crate::sched::scheduler::take_pending_switch();
            if pending != 0 {
                return pending;
            }
            frame_sp
        }

        SCAUSE_INST_PAGE_FAULT | SCAUSE_LOAD_PAGE_FAULT | SCAUSE_STORE_PAGE_FAULT => {
            let stval = read_stval();
            let fault_type = match scause {
                SCAUSE_INST_PAGE_FAULT => crate::mm::fault::FaultType::Exec,
                SCAUSE_STORE_PAGE_FAULT => crate::mm::fault::FaultType::Write,
                _ => crate::mm::fault::FaultType::Read,
            };
            let aspace_id = crate::sched::current_aspace_id();
            if aspace_id == 0 {
                let cpu = crate::sched::smp::cpu_id();
                let tid = crate::sched::current_thread_id();
                let spp = (frame.sstatus >> 8) & 1;
                crate::println!(
                    "Kernel page fault: cause={:#x} sepc={:#x} stval={:#x} cpu={} tid={} spp={} sstatus={:#x} sp(frame)={:#x}",
                    scause,
                    frame.sepc,
                    stval,
                    cpu,
                    tid,
                    spp,
                    frame.sstatus,
                    frame.regs[1]
                );
                loop {
                    core::hint::spin_loop();
                }
            }
            let result = crate::mm::fault::handle_page_fault(aspace_id, stval as usize, fault_type);
            match result {
                crate::mm::fault::FaultResult::NeedPager { token } => {
                    crate::sched::scheduler::store_frame_sp(frame_sp);
                    crate::mm::pager::initiate_fault(token);
                    let pending = crate::sched::scheduler::take_pending_switch();
                    if pending != 0 {
                        return pending;
                    }
                    frame_sp
                }
                crate::mm::fault::FaultResult::Failed => {
                    // Re-read the live CSRs at failure time so we can tell:
                    //   * frame.sepc == live sepc → straight user-mode fault
                    //   * frame.sepc != live sepc → kernel-side syscall fault
                    //     (nested trap; frame.sepc preserved from user entry,
                    //     live sepc is the kernel handler's RIP at fault).
                    // SPP bit (sstatus[8]): 0=fault came from U-mode, 1=S-mode.
                    // See memory/project_riscv64_init_pf_residual.md for the
                    // anomaly this probes.
                    let live_sepc = read_sepc();
                    let live_sstatus = read_sstatus();
                    let frame_spp = (frame.sstatus >> 8) & 1;
                    let live_spp = (live_sstatus >> 8) & 1;
                    crate::println!(
                        "Unhandled page fault: cause={:#x} sepc={:#x} stval={:#x} \
                         frame_spp={} live_sepc={:#x} live_spp={} \
                         — killing thread",
                        scause,
                        frame.sepc,
                        stval,
                        frame_spp,
                        live_sepc,
                        live_spp,
                    );
                    crate::sched::scheduler::exit_current_thread(-11); // SIGSEGV
                }
                _ => frame_sp,
            }
        }

        _ => {
            if scause & SCAUSE_INTERRUPT_BIT != 0 {
                crate::println!(
                    "Unhandled S-mode interrupt: cause={:#x} sepc={:#x}",
                    scause & !SCAUSE_INTERRUPT_BIT,
                    frame.sepc
                );
            } else {
                crate::println!(
                    "Unhandled S-mode exception: cause={:#x} sepc={:#x} stval={:#x}",
                    scause,
                    frame.sepc,
                    read_stval()
                );
                loop {
                    core::hint::spin_loop();
                }
            }
            frame_sp
        }
    }
}

/// Read the stval CSR.
fn read_stval() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("csrr {}, stval", out(reg) val) };
    val
}

/// Read the sepc CSR.  Used by failure-path probes to detect a
/// mismatch between `frame.sepc` (saved at trap entry) and the
/// live CSR value at the time the failure logs — distinguishes
/// nested-trap state from a corrupted/stale frame.
fn read_sepc() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("csrr {}, sepc", out(reg) val) };
    val
}

/// Read the sstatus CSR (for live SPP at fault-handler entry).
fn read_sstatus() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("csrr {}, sstatus", out(reg) val) };
    val
}
