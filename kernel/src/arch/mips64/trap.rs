//! MIPS64 trap/exception handling.
//!
//! MIPS64 uses a single general exception vector (EBase + 0x180).
//! The trap entry/exit assembly is in vectors.S.

use core::sync::atomic::{AtomicU64, Ordering};

static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Timer interval in CP0 Count ticks (set during init).
static TIMER_INTERVAL: AtomicU64 = AtomicU64::new(0);

/// Trap frame saved/restored by vectors.S.
#[repr(C)]
pub struct TrapFrame {
    /// General-purpose registers $0-$31 (k0/k1 slots zeroed).
    pub regs: [u64; 32],
    /// Exception return address (CP0 EPC).
    pub epc: u64,
    /// CP0 Status saved at entry.
    pub status: u64,
    /// CP0 Cause.
    pub cause: u64,
    /// CP0 BadVAddr.
    pub badvaddr: u64,
}

// ExcCode values (Cause bits 6:2)
const EXC_INT: u64 = 0;   // Interrupt
const EXC_MOD: u64 = 1;   // TLB Modified (store to V=1, D=0 entry)
const EXC_TLBL: u64 = 2;  // TLB miss (load/fetch)
const EXC_TLBS: u64 = 3;  // TLB miss (store)
const EXC_ADEL: u64 = 4;  // Address error (load/fetch)
const EXC_ADES: u64 = 5;  // Address error (store)
const EXC_SYS: u64 = 8;   // Syscall

/// Read CP0 Count register.
pub fn read_count() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("mfc0 {}, $9", out(reg) val) };
    val
}

/// Write CP0 Compare register (clears timer interrupt).
fn write_compare(val: u64) {
    unsafe { core::arch::asm!("mtc0 {}, $11", in(reg) val) };
}

/// Read CP0 Compare register.
fn read_compare() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("mfc0 {}, $11", out(reg) val) };
    val
}

/// Initialize trap handling: set EBase, configure Status, install timer.
pub fn init() {
    let ebase_val: u64;
    unsafe {
        // Set EBase to our exception vector page.
        // _exception_vectors is 4K-aligned. TLB refill is at offset 0x000,
        // general exception handler at offset 0x180.
        core::arch::asm!(
            ".set push",
            ".set mips64r2",
            "dla {tmp}, _exception_vectors",
            "dmtc0 {tmp}, $15, 1",   // CP0 EBase
            "ehb",
            ".set pop",
            tmp = out(reg) ebase_val,
        );

        // Configure Status: clear BEV (use RAM vectors), set IM bits for
        // timer (IP7 = bit 15) and HW interrupts, keep IE=0 (enable later),
        // clear EXL/ERL. KX=SX=UX=1 for 64-bit addressing.
        let status: u64 = (1 << 15)  // IM7 (timer)
                        | 0xe0;      // KX=SX=UX
        core::arch::asm!(
            "mtc0 {val}, $12",
            "ehb",
            val = in(reg) status,
        );
    }
    // Read back EBase to verify.
    let ebase_readback: u64;
    unsafe {
        core::arch::asm!(
            ".set push",
            ".set mips64r2",
            "dmfc0 {val}, $15, 1",
            ".set pop",
            val = out(reg) ebase_readback,
        );
    }
    crate::println!("  Trap vector installed (set={:#x} readback={:#x})", ebase_val, ebase_readback);

    // Configure the timer.
    // MIPS CP0 Count increments at half the pipeline clock.
    // QEMU Malta: ~100 MHz pipeline → Count at ~50 MHz. Use 100 MHz estimate.
    let freq: u64 = 100_000_000;
    let interval = freq / 100; // 100 Hz
    TIMER_INTERVAL.store(interval, Ordering::Relaxed);

    // Set first timer deadline.
    let now = read_count();
    write_compare(now + interval);

    crate::println!(
        "  Timer initialized: freq={}Hz, interval={} ticks ({}ms)",
        freq,
        interval,
        1000 * interval / freq
    );
}

/// Enable interrupts (set Status.IE = bit 0).
pub fn enable_interrupts() {
    unsafe {
        core::arch::asm!(
            ".set push",
            ".set mips64r2",
            "mfc0 {tmp}, $12",
            "ori  {tmp}, {tmp}, 1",
            "mtc0 {tmp}, $12",
            "ehb",
            ".set pop",
            tmp = out(reg) _,
        );
    }
}

/// Handle timer interrupt: reset the timer and increment tick count.
///
/// If Count has advanced past Compare by multiple intervals (common after
/// boot when interrupts were disabled), skip ahead to avoid a storm of
/// rapid back-to-back timer interrupts that burn through thread quantum
/// without giving threads time to execute.
fn handle_timer_irq() {
    let _ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;

    let interval = TIMER_INTERVAL.load(Ordering::Relaxed);
    let now = read_count();
    let mut next = read_compare() + interval;
    // Skip ahead if Compare is still in the past.
    while next <= now {
        next += interval;
    }
    write_compare(next);
}

/// Main Rust trap handler. Called from vectors.S with current SP as argument.
/// Returns (potentially new) SP for context switch.
///
/// Note: MIPS64 calling convention returns in $v0 ($2), so we return u64.
#[unsafe(no_mangle)]
extern "C" fn trap_handler(frame_sp: u64) -> u64 {
    let frame = unsafe { &mut *(frame_sp as *mut TrapFrame) };
    let cause = frame.cause;
    let exccode = (cause >> 2) & 0x1F;

    match exccode {
        EXC_INT => {
            // Interrupt — check which one via Cause.IP & Status.IM.
            let pending = (cause >> 8) & 0xFF; // IP bits
            let enabled = (frame.status >> 8) & 0xFF; // IM bits
            let active = pending & enabled;

            if active & (1 << 7) != 0 {
                // CP0 Timer interrupt (IP7).
                handle_timer_irq();
                crate::sched::tick(frame_sp)
            } else if active & (1 << 2) != 0 {
                // HW IRQ 0 (IP2).
                // TODO: proper interrupt controller dispatch.
                crate::println!("MIPS64: HW IRQ 0");
                frame_sp
            } else {
                crate::println!("MIPS64: unhandled interrupt IP={:#x}", active);
                frame_sp
            }
        }

        EXC_SYS => {
            // Syscall — advance EPC past the syscall instruction (4 bytes).
            frame.epc += 4;
            crate::sched::scheduler::store_frame_sp(frame_sp);
            crate::syscall::dispatch(frame);
            let pending = crate::sched::scheduler::take_pending_switch();
            if pending != 0 {
                return pending;
            }
            frame_sp
        }

        EXC_MOD | EXC_TLBL | EXC_TLBS | EXC_ADEL | EXC_ADES => {
            let badvaddr = frame.badvaddr;
            let fault_type = match exccode {
                EXC_MOD | EXC_TLBS | EXC_ADES => crate::mm::fault::FaultType::Write,
                _ => crate::mm::fault::FaultType::Read,
            };

            let aspace_id = crate::sched::current_aspace_id();
            if aspace_id == 0 {
                let cpu = crate::sched::smp::cpu_id();
                let tid = crate::sched::current_thread_id();
                let ksu = (frame.status >> 3) & 0x3;
                crate::println!(
                    "Kernel page fault: exccode={:#x} epc={:#x} badvaddr={:#x} cpu={} tid={} ksu={}",
                    exccode,
                    frame.epc,
                    badvaddr,
                    cpu,
                    tid,
                    ksu,
                );
                loop {
                    core::hint::spin_loop();
                }
            }
            let result =
                crate::mm::fault::handle_page_fault(aspace_id, badvaddr as usize, fault_type);
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
                    let tid = crate::sched::current_thread_id();
                    let ksu = (frame.status >> 3) & 0x3;
                    crate::println!(
                        "Unhandled page fault: exccode={:#x} epc={:#x} badvaddr={:#x} tid={} ksu={} — killing thread",
                        exccode,
                        frame.epc,
                        badvaddr,
                        tid,
                        ksu,
                    );
                    crate::sched::scheduler::exit_current_thread(-11) // SIGSEGV
                }
                _ => frame_sp,
            }
        }

        _ => {
            crate::println!(
                "Unhandled exception: exccode={:#x} cause={:#x} epc={:#x} badvaddr={:#x}",
                exccode,
                cause,
                frame.epc,
                frame.badvaddr
            );
            loop {
                core::hint::spin_loop();
            }
        }
    }
}
