//! LoongArch64 trap/exception handling.
//!
//! LoongArch64 uses CSR.EENTRY as the single exception entry point.
//! The trap entry/exit assembly is in vectors.S.

use core::sync::atomic::{AtomicU64, Ordering};

static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Timer interval in stable counter ticks (set during init).
static TIMER_INTERVAL: AtomicU64 = AtomicU64::new(0);

/// Trap frame saved/restored by vectors.S.
#[repr(C)]
pub struct TrapFrame {
    /// General-purpose registers r0-r31.
    pub regs: [u64; 32],
    /// Exception return address (CSR.ERA).
    pub era: u64,
    /// Pre-exception mode (CSR.PRMD).
    pub prmd: u64,
    /// Exception status (CSR.ESTAT).
    pub estat: u64,
}

// ESTAT.Ecode (bits 21:16)
const ECODE_INT: u64 = 0x0;  // Interrupt
const ECODE_PIL: u64 = 0x1;  // Page invalid (load)
const ECODE_PIS: u64 = 0x2;  // Page invalid (store)
const ECODE_PIF: u64 = 0x3;  // Page invalid (fetch)
const ECODE_PME: u64 = 0x4;  // Page modification exception
const ECODE_PNR: u64 = 0x5;  // Page not readable
const ECODE_PNX: u64 = 0x6;  // Page not executable
const ECODE_PPI: u64 = 0x7;  // Page privilege illegal
#[allow(dead_code)]
const ECODE_ADE: u64 = 0x8;  // Address error (ADEF/ADEM)
#[allow(dead_code)]
const ECODE_ALE: u64 = 0x9;  // Alignment error
const ECODE_SYS: u64 = 0xB;  // Syscall
#[allow(dead_code)]
const ECODE_BRK: u64 = 0xC;  // Breakpoint
#[allow(dead_code)]
const ECODE_INE: u64 = 0xD;  // Instruction not exist

// CSR numbers
const CSR_CRMD: u32 = 0x0;
const CSR_EENTRY: u32 = 0xC;
const CSR_ECFG: u32 = 0x4;
const CSR_SAVE0: u32 = 0x30;
const CSR_TCFG: u32 = 0x41;
const CSR_TICLR: u32 = 0x44;
const CSR_BADV: u32 = 0x7;

/// Read the stable counter (RDTIME instruction).
pub fn read_time() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("rdtime.d {}, $zero", out(reg) val) };
    val
}

/// Initialize trap handling: set CSR.EENTRY, configure timer.
pub fn init() {
    // Set EENTRY to our trap vector and ensure SAVE0 = 0 (kernel mode).
    unsafe {
        core::arch::asm!(
            "csrwr {zero}, {save0}",
            "la.pcrel {tmp}, _trap_entry",
            "csrwr {tmp}, {eentry}",
            zero = in(reg) 0u64,
            tmp = out(reg) _,
            save0 = const CSR_SAVE0,
            eentry = const CSR_EENTRY,
        );
    }
    crate::println!("  Trap vector installed");

    // Configure the timer.
    // LoongArch64 stable counter frequency: QEMU uses 100 MHz.
    let freq: u64 = 100_000_000;
    let interval = freq / 100; // 100 Hz
    TIMER_INTERVAL.store(interval, Ordering::Relaxed);

    // Set timer: TCFG.En=1, TCFG.Periodic=1, TCFG.InitVal=interval.
    // TCFG format: bits 31:2 = InitVal, bit 1 = Periodic, bit 0 = En.
    let tcfg = (interval << 2) | 0x3; // periodic + enable
    unsafe {
        core::arch::asm!(
            "csrwr {val}, {tcfg}",
            val = in(reg) tcfg,
            tcfg = const CSR_TCFG,
        );
    }

    // Enable timer interrupt (bit 11) and HWI0 (bit 2) in ECFG.LIE.
    // Bits 12:0 of ECFG are the Local Interrupt Enable mask.
    // bit 11 = TI (timer interrupt)
    // bit 2  = HWI0
    let ecfg_lie: u64 = (1 << 11) | (1 << 2);
    unsafe {
        core::arch::asm!(
            "csrwr {val}, {ecfg}",
            val = in(reg) ecfg_lie,
            ecfg = const CSR_ECFG,
        );
    }

    crate::println!(
        "  Timer initialized: freq={}Hz, interval={} ticks ({}ms)",
        freq,
        interval,
        1000 * interval / freq
    );
}

/// Enable interrupts (set CRMD.IE = bit 2).
pub fn enable_interrupts() {
    unsafe {
        core::arch::asm!(
            "li.w {tmp}, 0x4",
            "csrxchg {tmp}, {tmp}, {crmd}",
            tmp = out(reg) _,
            crmd = const CSR_CRMD,
        );
    }
}

/// Handle timer interrupt: clear TI, rearm, and increment tick count.
fn handle_timer_irq() {
    let _ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;

    // Clear timer interrupt by writing 1 to TICLR.CLR (bit 0).
    unsafe {
        core::arch::asm!(
            "li.w {tmp}, 1",
            "csrwr {tmp}, {ticlr}",
            tmp = out(reg) _,
            ticlr = const CSR_TICLR,
        );
    }

    // Timer is periodic (auto-reload), no need to manually rearm.
}

/// Read CSR.BADV.
fn read_badv() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!(
            "csrrd {out}, {badv}",
            out = out(reg) val,
            badv = const CSR_BADV,
        );
    }
    val
}

/// Main Rust trap handler. Called from vectors.S with current SP as argument.
/// Returns (potentially new) SP for context switch.
#[unsafe(no_mangle)]
extern "C" fn trap_handler(frame_sp: u64) -> u64 {
    let frame = unsafe { &mut *(frame_sp as *mut TrapFrame) };
    let estat = frame.estat;
    let ecode = (estat >> 16) & 0x3F;

    match ecode {
        ECODE_INT => {
            // Interrupt — check which one.
            let is = estat & 0x1FFF; // IS bits 12:0
            if is & (1 << 11) != 0 {
                // Timer interrupt (TI).
                handle_timer_irq();
                crate::sched::tick(frame_sp)
            } else if is & (1 << 2) != 0 {
                // HWI0 — external device interrupt.
                // TODO: proper interrupt controller dispatch.
                crate::println!("LoongArch64: HWI0 interrupt");
                frame_sp
            } else {
                crate::println!("LoongArch64: unhandled interrupt IS={:#x}", is);
                frame_sp
            }
        }

        ECODE_SYS => {
            // Syscall — advance ERA past the syscall instruction (4 bytes).
            frame.era += 4;
            crate::sched::scheduler::store_frame_sp(frame_sp);
            crate::syscall::dispatch(frame);
            let pending = crate::sched::scheduler::take_pending_switch();
            if pending != 0 {
                return pending;
            }
            frame_sp
        }

        ECODE_PIL | ECODE_PIS | ECODE_PIF | ECODE_PME | ECODE_PNR | ECODE_PNX | ECODE_PPI => {
            let badv = read_badv();
            let fault_type = match ecode {
                ECODE_PIF | ECODE_PNX => crate::mm::fault::FaultType::Exec,
                ECODE_PIS | ECODE_PME => crate::mm::fault::FaultType::Write,
                _ => crate::mm::fault::FaultType::Read,
            };
            let aspace_id = crate::sched::current_aspace_id();
            if aspace_id == 0 {
                let cpu = crate::sched::smp::cpu_id();
                let tid = crate::sched::current_thread_id();
                let pplv = frame.prmd & 0x3;
                crate::println!(
                    "Kernel page fault: ecode={:#x} era={:#x} badv={:#x} cpu={} tid={} pplv={}",
                    ecode,
                    frame.era,
                    badv,
                    cpu,
                    tid,
                    pplv,
                );
                loop {
                    core::hint::spin_loop();
                }
            }
            let result = crate::mm::fault::handle_page_fault(aspace_id, badv as usize, fault_type);
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
                    crate::println!(
                        "Unhandled page fault: ecode={:#x} era={:#x} badv={:#x} — killing thread",
                        ecode,
                        frame.era,
                        badv
                    );
                    crate::sched::scheduler::exit_current_thread(-11) // SIGSEGV
                }
                _ => frame_sp,
            }
        }

        ECODE_INE => {
            crate::println!(
                "INE: era={:#x} badv={:#x} prmd={:#x} tid={}",
                frame.era, read_badv(), frame.prmd,
                crate::sched::current_thread_id()
            );
            crate::sched::scheduler::exit_current_thread(-4) // SIGILL
        }
        _ => {
            crate::println!(
                "Unhandled exception: ecode={:#x} estat={:#x} era={:#x} badv={:#x}",
                ecode,
                estat,
                frame.era,
                read_badv()
            );
            loop {
                core::hint::spin_loop();
            }
        }
    }
}
