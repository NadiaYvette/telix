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

// IOCSR addresses for the IPI unit (per-core).  LoongArch IPIs are
// delivered as bit 12 of ESTAT.IS and dispatched through the per-core
// IPI mailbox CSRs.  `_SEND` lets a core raise an IPI on *another* core
// — bits[25:16] hold the target CPU id and bits[4:0] select the IPI
// vector (a single bit in the target's IPI_STATUS).
const LOONGARCH_IOCSR_IPI_STATUS: u32 = 0x1000;
const LOONGARCH_IOCSR_IPI_EN:     u32 = 0x1004;
#[allow(dead_code)]
const LOONGARCH_IOCSR_IPI_SET:    u32 = 0x1008;
const LOONGARCH_IOCSR_IPI_CLEAR:  u32 = 0x100c;
const LOONGARCH_IOCSR_IPI_SEND:   u32 = 0x1040;
/// 64-bit MailBox transfer register; #257 wake protocol uses this to
/// stamp a remote AP's MailBox0 with the entry_pc before sending the
/// BOOT_CPU IPI.  See 3A5000 manual §10.2 Table 63.
const LOONGARCH_IOCSR_MAIL_SEND:  u32 = 0x1048;

/// IPI action / vector numbers (3A5000 §10.1 IPI_Status format).  Each
/// is a bit position in the per-core IPI_Status register.  Matches the
/// Linux `arch/loongarch/kernel/smp.c` convention so QEMU virt's
/// firmware stub (which dispatches the AP wake on ACTION_BOOT_CPU=0)
/// works without further glue.
pub(super) const ACTION_BOOT_CPU:      u32 = 0;
pub(super) const ACTION_RESCHEDULE:    u32 = 1;
#[allow(dead_code)]
pub(super) const ACTION_CALL_FUNCTION: u32 = 2;

/// Vector used for reschedule IPIs.  Kept for back-compat with existing
/// callers; new code should pass `ACTION_RESCHEDULE` directly to
/// `send_ipi_action`.
const IPI_VECTOR_RESCHEDULE: u32 = ACTION_RESCHEDULE;

// Mail_Send payload field positions (3A5000 manual §10.2 Table 63).
const IOCSR_MBUF_BLOCKING:  u64 = 1 << 31;
const IOCSR_MBUF_CPU_SHIFT: u32 = 16;
const IOCSR_MBUF_BOX_SHIFT: u32 = 2;
const IOCSR_MBUF_H32_MASK:  u64 = 0xFFFF_FFFF_0000_0000;

/// Mail_Send subindex: low half of MailBox `b` (0..3).
#[inline(always)]
const fn mbox_lo(b: u32) -> u32 { b * 2 }
/// Mail_Send subindex: high half of MailBox `b` (0..3).
#[inline(always)]
const fn mbox_hi(b: u32) -> u32 { b * 2 + 1 }

/// Write a 32-bit value to an IOCSR register (iocsrwr.w).
#[inline]
fn iocsr_write32(addr: u32, val: u32) {
    unsafe {
        core::arch::asm!(
            "iocsrwr.w {val}, {addr}",
            val = in(reg) val,
            addr = in(reg) addr,
        );
    }
}

/// Read a 32-bit value from an IOCSR register (iocsrrd.w).
#[inline]
fn iocsr_read32(addr: u32) -> u32 {
    let val: u32;
    unsafe {
        core::arch::asm!(
            "iocsrrd.w {val}, {addr}",
            val = out(reg) val,
            addr = in(reg) addr,
        );
    }
    val
}

/// Write a 64-bit value to an IOCSR register (iocsrwr.d).  Used by
/// `mail_send_to` to stamp a remote core's MailBox via the per-core
/// `Mail_Send` register.
#[inline]
fn iocsr_write64(addr: u32, val: u64) {
    unsafe {
        core::arch::asm!(
            "iocsrwr.d {val}, {addr}",
            val = in(reg) val,
            addr = in(reg) addr,
        );
    }
}

/// Stamp `data` (64 bits) into remote core `cpu`'s MailBox `box_idx`
/// (0..3).  Mail_Send only transports 32 data bits per write, so this
/// issues two iocsrwr.d ops — high half first, then low half — matching
/// Linux's `csr_mail_send` ordering convention.  Both writes use the
/// BLOCKING flag so each completes before the next instruction issues.
///
/// Used by the #257 wake protocol: BSP writes `entry_pc` to AP's
/// MailBox0, then sends an `ACTION_BOOT_CPU` IPI; the AP's firmware
/// stub reads MailBox0 and jumps there.
pub(super) fn mail_send_to(cpu: u32, box_idx: u32, data: u64) {
    debug_assert!(box_idx < 4);
    let cpu_field = (cpu as u64) << IOCSR_MBUF_CPU_SHIFT;
    // High 32 bits first.
    let hi = (data & IOCSR_MBUF_H32_MASK)
        | IOCSR_MBUF_BLOCKING
        | ((mbox_hi(box_idx) as u64) << IOCSR_MBUF_BOX_SHIFT)
        | cpu_field;
    iocsr_write64(LOONGARCH_IOCSR_MAIL_SEND, hi);
    // Low 32 bits.
    let lo = ((data << 32) & IOCSR_MBUF_H32_MASK)
        | IOCSR_MBUF_BLOCKING
        | ((mbox_lo(box_idx) as u64) << IOCSR_MBUF_BOX_SHIFT)
        | cpu_field;
    iocsr_write64(LOONGARCH_IOCSR_MAIL_SEND, lo);
}

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

    // Set timer: TCFG.En=1, TCFG.Periodic=0 (one-shot), TCFG.InitVal=interval.
    // TCFG format: bits 31:2 = InitVal, bit 1 = Periodic, bit 0 = En.
    let tcfg = (interval << 2) | 0x1; // one-shot + enable
    unsafe {
        core::arch::asm!(
            "csrwr {val}, {tcfg}",
            val = in(reg) tcfg,
            tcfg = const CSR_TCFG,
        );
    }

    // Enable timer (TI = bit 11), HWI0 (bit 2), and IPI (bit 12) in
    // ECFG.LIE.  IPI is how send_reschedule_ipi wakes another core out
    // of `idle`; per-core IPI_EN below gates which vectors actually
    // raise the interrupt.
    let ecfg_lie: u64 = (1 << 11) | (1 << 2) | (1 << 12);
    unsafe {
        core::arch::asm!(
            "csrwr {val}, {ecfg}",
            val = in(reg) ecfg_lie,
            ecfg = const CSR_ECFG,
        );
    }

    // Unmask all IPI vectors on this core so iocsr-delivered IPIs set
    // bits in IPI_STATUS and raise ESTAT.IS[12].
    iocsr_write32(LOONGARCH_IOCSR_IPI_EN, 0xFFFF_FFFF);

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

/// Send INTID-equivalent reschedule IPI to `target_cpu` (LoongArch IPI).
/// Writes `(target << 16) | vector` to the IOCSR IPI_SEND mailbox; the
/// target core sees bit `vector` set in its IPI_STATUS, and if that
/// vector is unmasked in IPI_EN it raises ESTAT.IS[12].  Our
/// dispatcher then calls sched::tick which picks up newly-enqueued
/// work on the target's runqueue — same pattern as x86 LAPIC /
/// aarch64 SGI / riscv64 SSIP.
///
/// Currently a latent mechanism: start_secondary_cpus is still a TODO
/// on LoongArch64, so the only CPU online is CPU 0 and nothing calls
/// this with a non-self target.  Wiring it now keeps things consistent
/// and avoids a sharp edge the moment SMP lands.
pub fn send_ipi(target_cpu: u32) {
    send_ipi_action(target_cpu, IPI_VECTOR_RESCHEDULE);
}

/// Raw IPI send with explicit action vector.  Used by the #257 wake
/// path with `ACTION_BOOT_CPU` to lift APs out of their reset halt;
/// also the underlying primitive for `send_ipi` (reschedule).
///
/// Payload format (3A5000 §10.2 Table 63 IPI_Send): `[31]` = BLOCKING,
/// `[25:16]` = destination cpu, `[4:0]` = action / vector.  BLOCKING
/// makes the iocsrwr complete before the next instruction so callers
/// don't need an explicit `dbar` between mail_send_to + send_ipi_action.
pub(super) fn send_ipi_action(target_cpu: u32, action: u32) {
    let payload = (1u32 << 31)
        | ((target_cpu & 0x3FF) << 16)
        | (action & 0x1F);
    iocsr_write32(LOONGARCH_IOCSR_IPI_SEND, payload);
    SGI_SEND_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

pub static SGI_SEND_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static SGI_RECV_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Ack the pending IPI vectors on this core.  Called from the IS[12]
/// branch of the trap handler before sched::tick runs.
fn handle_ipi_irq() {
    let pending = iocsr_read32(LOONGARCH_IOCSR_IPI_STATUS);
    if pending != 0 {
        iocsr_write32(LOONGARCH_IOCSR_IPI_CLEAR, pending);
    }
    SGI_RECV_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// Handle timer interrupt: clear TI and increment tick count.
/// Timer is NOT rearmed here; the scheduler calls `program_oneshot()`.
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
}

/// Program the timer to fire at `deadline_ns` nanoseconds since boot.
pub fn program_oneshot(deadline_ns: u64) {
    let now_ns = crate::arch::timer::monotonic_ns();
    let delta_ns = deadline_ns.saturating_sub(now_ns);
    let freq: u128 = 100_000_000; // QEMU virt Stable Counter = 100 MHz
    let ticks = ((delta_ns as u128 * freq) / 1_000_000_000u128) as u64;
    let ticks = ticks.max(1);

    // Clear any pending timer interrupt.
    unsafe {
        core::arch::asm!(
            "li.w {tmp}, 1",
            "csrwr {tmp}, {ticlr}",
            tmp = out(reg) _,
            ticlr = const CSR_TICLR,
        );
    }
    // Program TCFG: one-shot + enable.
    let tcfg = (ticks << 2) | 0x1;
    unsafe {
        core::arch::asm!(
            "csrwr {val}, {tcfg}",
            val = in(reg) tcfg,
            tcfg = const CSR_TCFG,
        );
    }
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
    // #246 Fix D drain — see riscv64/trap.rs and aarch64/exception.rs.
    // Mirrors x86_64/exception.rs:1438 so ON_CPU_RELEASING → ON_CPU_PENDING
    // transitions complete on every trap entry.
    crate::sched::scheduler::finalize_release_after_stack_switch();
    crate::sched::scheduler::clear_pending_switch(crate::sched::smp::cpu_id() as usize);
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
            } else if is & (1 << 12) != 0 {
                // IPI — reschedule wake-up from another core.
                handle_ipi_irq();
                crate::sched::tick(frame_sp)
            } else if is & (1 << 2) != 0 {
                // HWI0 — external device interrupt.  EXTIOI routes PCI IRQs to
                // CPU HWI0; drain this core's EXTIOI pending bits, dispatch each
                // to its registered IRQ port (W1C-acked in claim_and_dispatch),
                // then run the scheduler so a woken server thread can preempt.
                crate::arch::loongarch64::eiointc::claim_and_dispatch(|irq| {
                    crate::io::irq_dispatch::handle_irq(irq);
                });
                crate::sched::tick(frame_sp)
            } else {
                crate::println!("LoongArch64: unhandled interrupt IS={:#x}", is);
                frame_sp
            }
        }

        ECODE_SYS => {
            // Syscall — advance ERA past the syscall instruction (4 bytes).
            frame.era += 4;
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
                // #254 anti-interleave: stack-buffer + handler_write_bytes.
                {
                    use crate::arch::loongarch64::serial::{
                        handler_write_bytes, put_byte, put_bytes, put_dec_u64, put_hex_u64,
                    };
                    let mut buf = [0u8; 256];
                    let mut k = 0;
                    put_bytes(&mut buf, &mut k, b"Kernel page fault: ecode=");
                    put_hex_u64(&mut buf, &mut k, ecode);
                    put_bytes(&mut buf, &mut k, b" era=");
                    put_hex_u64(&mut buf, &mut k, frame.era);
                    put_bytes(&mut buf, &mut k, b" badv=");
                    put_hex_u64(&mut buf, &mut k, badv as u64);
                    put_bytes(&mut buf, &mut k, b" cpu=");
                    put_dec_u64(&mut buf, &mut k, cpu as u64);
                    put_bytes(&mut buf, &mut k, b" tid=");
                    put_dec_u64(&mut buf, &mut k, tid as u64);
                    put_bytes(&mut buf, &mut k, b" pplv=");
                    put_dec_u64(&mut buf, &mut k, pplv);
                    put_byte(&mut buf, &mut k, b'\n');
                    handler_write_bytes(&buf[..k.min(buf.len())]);
                }
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
                    // #254 anti-interleave.
                    {
                        use crate::arch::loongarch64::serial::{
                            handler_write_bytes, put_bytes, put_hex_u64,
                        };
                        let mut buf = [0u8; 192];
                        let mut k = 0;
                        put_bytes(&mut buf, &mut k, b"Unhandled page fault: ecode=");
                        put_hex_u64(&mut buf, &mut k, ecode);
                        put_bytes(&mut buf, &mut k, b" era=");
                        put_hex_u64(&mut buf, &mut k, frame.era);
                        put_bytes(&mut buf, &mut k, b" badv=");
                        put_hex_u64(&mut buf, &mut k, badv as u64);
                        put_bytes(&mut buf, &mut k, b" \xe2\x80\x94 killing thread\n");
                        handler_write_bytes(&buf[..k.min(buf.len())]);
                    }
                    crate::sched::scheduler::exit_current_thread(-11) // SIGSEGV
                }
                _ => frame_sp,
            }
        }

        ECODE_INE => {
            // #254 anti-interleave.
            {
                use crate::arch::loongarch64::serial::{
                    handler_write_bytes, put_bytes, put_dec_u64, put_hex_u64,
                };
                let mut buf = [0u8; 192];
                let mut k = 0;
                put_bytes(&mut buf, &mut k, b"INE: era=");
                put_hex_u64(&mut buf, &mut k, frame.era);
                put_bytes(&mut buf, &mut k, b" badv=");
                put_hex_u64(&mut buf, &mut k, read_badv());
                put_bytes(&mut buf, &mut k, b" prmd=");
                put_hex_u64(&mut buf, &mut k, frame.prmd);
                put_bytes(&mut buf, &mut k, b" tid=");
                put_dec_u64(&mut buf, &mut k, crate::sched::current_thread_id() as u64);
                put_bytes(&mut buf, &mut k, b"\n");
                handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            crate::sched::scheduler::exit_current_thread(-4) // SIGILL
        }
        _ => {
            // #254 anti-interleave.
            {
                use crate::arch::loongarch64::serial::{
                    handler_write_bytes, put_bytes, put_hex_u64,
                };
                let mut buf = [0u8; 192];
                let mut k = 0;
                put_bytes(&mut buf, &mut k, b"Unhandled exception: ecode=");
                put_hex_u64(&mut buf, &mut k, ecode);
                put_bytes(&mut buf, &mut k, b" estat=");
                put_hex_u64(&mut buf, &mut k, estat);
                put_bytes(&mut buf, &mut k, b" era=");
                put_hex_u64(&mut buf, &mut k, frame.era);
                put_bytes(&mut buf, &mut k, b" badv=");
                put_hex_u64(&mut buf, &mut k, read_badv());
                put_bytes(&mut buf, &mut k, b"\n");
                handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            // User-mode unhandled exceptions (ADE/ALE/...) must TERMINATE the
            // faulting thread with a signal — NOT spin-loop this CPU forever
            // (which wedges the core and hangs every client of a faulting
            // server).  Mirrors the PIL-Failed (-11) and INE (-4) arms above.
            // A kernel-mode unhandled exception is a genuine kernel bug → keep
            // the spin so the state is preserved for inspection.
            if (frame.prmd & 0x3) == 3 {
                let sig = match ecode {
                    ECODE_ALE => -7,  // SIGBUS (alignment error)
                    _ => -11,         // SIGSEGV (address error / other)
                };
                crate::sched::scheduler::exit_current_thread(sig)
            } else {
                loop {
                    core::hint::spin_loop();
                }
            }
        }
    }
}
