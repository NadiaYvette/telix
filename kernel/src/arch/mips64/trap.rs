//! MIPS64 trap/exception handling.
//!
//! MIPS64 uses a single general exception vector (EBase + 0x180).
//! The trap entry/exit assembly is in vectors.S.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Timer interval in CP0 Count ticks (32-bit, set during init).
static TIMER_INTERVAL: AtomicU32 = AtomicU32::new(0);

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

/// Read CP0 Count register (32-bit counter, masked to avoid sign-extension).
pub fn read_count() -> u32 {
    let val: u64;
    unsafe { core::arch::asm!("mfc0 {}, $9", out(reg) val) };
    val as u32
}

/// Write CP0 Compare register (clears timer interrupt).
fn write_compare(val: u32) {
    unsafe { core::arch::asm!("mtc0 {}, $11", in(reg) val as u64) };
}

/// Read CP0 Compare register (32-bit, masked to avoid sign-extension).
fn read_compare() -> u32 {
    let val: u64;
    unsafe { core::arch::asm!("mfc0 {}, $11", out(reg) val) };
    val as u32
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
    let freq: u32 = 100_000_000;
    let interval = freq / 100; // 100 Hz
    TIMER_INTERVAL.store(interval, Ordering::Relaxed);

    // Set first timer deadline.
    let now = read_count();
    write_compare(now.wrapping_add(interval));

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

/// Handle timer interrupt: increment tick count. Timer is NOT rearmed here;
/// the scheduler calls `program_oneshot()` after processing the tick.
fn handle_timer_irq() {
    let _ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    // Clear the timer interrupt by writing a far-future Compare value.
    // This prevents immediate re-fire before the scheduler reprograms.
    let now = read_count();
    write_compare(now.wrapping_add(0x7FFF_FFFF));
}

/// Program the timer to fire at `deadline_ns` nanoseconds since boot.
/// CP0.Compare is 32-bit; cap at ~30 seconds to avoid wrap issues.
pub fn program_oneshot(deadline_ns: u64) {
    let now_ns = crate::arch::timer::monotonic_ns();
    let delta_ns = deadline_ns.saturating_sub(now_ns);
    // Cap at 30 seconds (3 billion ticks at 100 MHz wraps 32-bit counter).
    let delta_ns = delta_ns.min(30_000_000_000);
    let freq: u128 = 100_000_000;
    let ticks = ((delta_ns as u128 * freq) / 1_000_000_000u128) as u32;
    let ticks = ticks.max(1);
    let now = read_count();
    write_compare(now.wrapping_add(ticks));
}

/// Main Rust trap handler. Called from vectors.S with current SP as argument.
/// Returns (potentially new) SP for context switch.
///
/// Note: MIPS64 calling convention returns in $v0 ($2), so we return u64.
#[unsafe(no_mangle)]
extern "C" fn trap_handler(frame_sp: u64) -> u64 {
    // #246 Fix D drain + #267 real-park wiring — mirror riscv64/trap.rs and
    // loongarch64/trap.rs (themselves mirroring x86_64/exception.rs:1438).
    // Every trap entry drains the per-CPU release slot so threads moved to
    // ON_CPU_RELEASING by try_switch are CAS'd to ON_CPU_PENDING and become
    // dispatchable on peer CPUs, and completes the real-park PARK_WOKEN
    // arbitration on the parking CPU.  These are no-ops while BLOCK_REAL_PARK
    // is off for mips64; wiring them here is the prerequisite for enabling
    // real-park on mips64 once it can be boot-validated.
    crate::sched::scheduler::finalize_release_after_stack_switch();
    crate::sched::scheduler::clear_pending_switch(crate::sched::smp::cpu_id() as usize);
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

            // Clear EXL and KSU to leave exception context (stay in kernel
            // mode with IRQs masked). EXL must be cleared before enabling
            // interrupts so nested exceptions use the correct handler path.
            unsafe {
                core::arch::asm!(
                    "di",                            // clear IE first
                    "ehb",
                    "mfc0 {tmp}, $12",
                    "ins  {tmp}, $zero, 0, 5",       // clear bits 4:0 (KSU+EXL+IE)
                    "mtc0 {tmp}, $12",
                    "ehb",
                    tmp = out(reg) _,
                );
            }

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

        EXC_MOD | EXC_TLBL | EXC_TLBS | EXC_ADEL | EXC_ADES => {
            let badvaddr = frame.badvaddr;
            let fault_type = match exccode {
                EXC_MOD | EXC_TLBS | EXC_ADES => crate::mm::fault::FaultType::Write,
                _ => crate::mm::fault::FaultType::Read,
            };

            let aspace_id = crate::sched::current_aspace_id();
            // Detect kernel-mode faults: either no aspace (idle/kernel thread)
            // or EPC is in kernel address space (syscall handler crashed).
            let is_kernel_fault = aspace_id == 0
                || (frame.epc & 0xFFFF_FFFF_8000_0000) == 0xFFFF_FFFF_8000_0000;
            if is_kernel_fault {
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
                crate::println!(
                    "  ra={:#x} sp={:#x} v0={:#x} a0={:#x} a1={:#x}",
                    frame.regs[31], frame.regs[29], frame.regs[2],
                    frame.regs[4], frame.regs[5]
                );
                panic!(
                    "kernel null pointer dereference at epc={:#x} badvaddr={:#x}",
                    frame.epc, badvaddr
                );
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
                        exccode, frame.epc, badvaddr, tid, ksu,
                    );
                    crate::println!(
                        "  ra={:#x} sp={:#x} v0={:#x} a0={:#x} a1={:#x}",
                        frame.regs[31], frame.regs[29], frame.regs[2],
                        frame.regs[4], frame.regs[5]
                    );
                    crate::println!(
                        "  at={:#x} t0={:#x} t1={:#x} t2={:#x} t3={:#x}",
                        frame.regs[1], frame.regs[8], frame.regs[9],
                        frame.regs[10], frame.regs[11]
                    );
                    crate::println!(
                        "  s0={:#x} s1={:#x} s2={:#x} s3={:#x} gp={:#x}",
                        frame.regs[16], frame.regs[17], frame.regs[18],
                        frame.regs[19], frame.regs[28]
                    );
                    crate::sched::scheduler::exit_current_thread(-11) // SIGSEGV
                }
                _ => frame_sp,
            }
        }

        _ => {
            let ksu = (frame.status >> 3) & 0x3;
            crate::println!(
                "Unhandled exception: exccode={:#x} cause={:#x} epc={:#x} badvaddr={:#x} ksu={}",
                exccode,
                cause,
                frame.epc,
                frame.badvaddr,
                ksu
            );
            // User-mode (ksu==2) unhandled exception → SIGSEGV the faulting
            // thread instead of wedging this CPU forever.  Mirrors the page-
            // fault Failed arm (-11) above; kernel-mode is a genuine kernel bug
            // → spin to preserve state.  (Same class as the loongarch64 ADE fix.)
            if ksu == 2 {
                return crate::sched::scheduler::exit_current_thread(-11); // SIGSEGV
            }
            loop {
                core::hint::spin_loop();
            }
        }
    }
}
