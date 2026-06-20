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
const SCAUSE_BREAKPOINT: u64 = 3;
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
    // #251 scause-spill probe: capture scause once at entry; we re-read
    // it at the "Kernel page fault" print site and compare the three
    // values (entry-local, frame.scause, live sscause CSR).  If any of
    // them disagree we've localised which storage got clobbered.
    // `black_box` discourages the optimiser from spilling+reloading the
    // local around inner calls, so the entry value sticks.
    let scause = core::hint::black_box(frame.scause);

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

        SCAUSE_BREAKPOINT => {
            // #228 hardware watchpoint hit.  tselect/tdata2 was armed
            // via watchpoint::arm() on a specific Thread.saved_sp slot;
            // this fires whenever S-mode (or M-mode) writes there.
            //
            // Policy (legit-PC re-arm):
            //   1. Decode the trapped store and emulate it so legit
            //      writes (write_saved_sp's inline `thread.saved_sp =
            //      new_value`) keep their semantics — otherwise we
            //      lose every kstack save and kernel wedges.
            //   2. The first 8 distinct sepcs that fire are "learned"
            //      as legit (they're the inlined call sites of
            //      write_saved_sp).  Log a LEARN line per new PC.
            //   3. Subsequent hits at known-legit PCs are silent +
            //      re-armed.
            //   4. A 9th distinct PC = the corrupting writer.  Log
            //      a loud BAD-WRITER line and disarm so we don't
            //      keep storming the trace ring.
            //   5. Emulation skips on unknown insn formats — we log
            //      INSN-SKIP and re-arm without touching memory.
            super::watchpoint::HIT_COUNT
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let stval = read_stval();
            let live_scause = read_scause();
            let cpu = crate::sched::smp::cpu_id();
            let tid = crate::sched::current_thread_id();
            let ra = frame.regs[0];
            let sp = frame.regs[1];

            // Two triggers may be armed: primary on tid=4 saved_sp,
            // aux on the local PerCpuData.current_thread slot.  stval
            // gives the offending access address, so we route by
            // matching it against each WATCHED_ADDR.
            let watched_pri = super::watchpoint::watched_addr();
            let watched_aux = super::watchpoint::watched_addr_aux();
            let is_aux_hit = watched_aux != 0 && stval as u64 == watched_aux;
            let _ = watched_pri; // suppress unused if logging changes

            // Peek insn at sepc.  Lower 2 bits decide 16- vs 32-bit
            // form per RISC-V spec; we read enough bytes for either.
            let insn_first = unsafe { (frame.sepc as *const u16).read_volatile() };
            let is_compressed = (insn_first & 0x3) != 0x3;
            let insn_len: u64 = if is_compressed { 2 } else { 4 };
            let insn32: u32 = if is_compressed {
                insn_first as u32
            } else {
                unsafe { (frame.sepc as *const u32).read_volatile() }
            };

            let known = super::watchpoint::is_legit_pc(frame.sepc);
            let learned_slot = if known {
                None
            } else {
                super::watchpoint::learn_legit_pc(frame.sepc)
            };
            let is_bad = !known && learned_slot.is_none();

            // We DON'T emulate the legit store — repeated tests on
            // patched QEMU showed the trap re-enters during the
            // emulator's write_volatile (only 21 of 8403 writes
            // completed in a 10s run, vs the trap firing 8403x).
            // Suspected QEMU TCG behavior is that the trigger
            // remains "armed" within the trap re-entry window so the
            // emulator's own store re-fires, recursing.  Skipping
            // the store is lossy (the legit value never reaches
            // memory for that particular call) but kernel observed
            // to survive — saved_sp values cycle, so a few missed
            // updates don't break dispatch in practice.  Treat the
            // mode flag as: 1 = catch first hit only, 3 = catch
            // every hit (legit PCs re-armed silently, others loudly).
            let mode_pre = crate::boot::cmdline::BOOT_CONFIG
                .wp_savedsp
                .load(core::sync::atomic::Ordering::Relaxed);
            let emulated = false;
            let _ = emulate_store; // keep referenced for future use

            // Log policy: always log new learns and bad-writer hits;
            // log first N (=64) other hits so a smoke run can confirm
            // the path; suppress thereafter to avoid serial flood.
            let n = super::watchpoint::HIT_COUNT
                .load(core::sync::atomic::Ordering::Relaxed);
            let want_log = is_bad || learned_slot.is_some() || n <= 64;
            if want_log {
                use crate::arch::riscv64::serial::{
                    handler_write_bytes, put_byte, put_bytes, put_dec_u64, put_hex_u64,
                };
                let mut buf = [0u8; 512];
                let mut k = 0;
                let tag: &[u8] = match (is_bad, learned_slot.is_some(), is_aux_hit) {
                    (true,  _,    true)  => b"WP-AUX-BAD-WRITER: cpu=",
                    (true,  _,    false) => b"WP-BAD-WRITER: cpu=",
                    (false, true, true)  => b"WP-AUX-LEARN: cpu=",
                    (false, true, false) => b"WP-LEARN: cpu=",
                    (false, false, true) => b"WP-AUX-INSN-SKIP: cpu=",
                    (false, false, false) => b"WP-INSN-SKIP: cpu=",
                };
                put_bytes(&mut buf, &mut k, tag);
                put_dec_u64(&mut buf, &mut k, cpu as u64);
                put_bytes(&mut buf, &mut k, b" tid=");
                put_dec_u64(&mut buf, &mut k, tid as u64);
                put_bytes(&mut buf, &mut k, b" sepc=");
                put_hex_u64(&mut buf, &mut k, frame.sepc);
                put_bytes(&mut buf, &mut k, b" stval=");
                put_hex_u64(&mut buf, &mut k, stval as u64);
                put_bytes(&mut buf, &mut k, b" scause=");
                put_hex_u64(&mut buf, &mut k, live_scause);
                put_bytes(&mut buf, &mut k, b" insn=");
                put_hex_u64(&mut buf, &mut k, insn32 as u64);
                put_bytes(&mut buf, &mut k, b" ra=");
                put_hex_u64(&mut buf, &mut k, ra);
                put_bytes(&mut buf, &mut k, b" sp=");
                put_hex_u64(&mut buf, &mut k, sp);
                if let Some(slot) = learned_slot {
                    put_bytes(&mut buf, &mut k, b" slot=");
                    put_dec_u64(&mut buf, &mut k, slot as u64);
                }
                put_byte(&mut buf, &mut k, b'\n');
                handler_write_bytes(&buf[..k.min(buf.len())]);
            }

            // Disarm + advance sepc.  Legit path re-arms; bad path
            // leaves it disarmed so the loud log isn't drowned by
            // subsequent stores from the same caller.
            // Modes:
            //   1 = disarm permanently after first hit (baseline
            //       sanity check; loses only one saved_sp write)
            //   3 = re-arm on every legit-PC hit (catches a future
            //       corrupting writer; loses one saved_sp write per
            //       hit, but kernel observed to survive)
            //
            // With two triggers armed we route disarm/re-arm to
            // the one that fired (selected by stval match above).
            if is_aux_hit {
                super::watchpoint::disarm_aux();
            } else {
                super::watchpoint::disarm();
            }
            frame.sepc = frame.sepc.wrapping_add(insn_len);
            if !is_bad && mode_pre >= 3 {
                if is_aux_hit {
                    super::watchpoint::re_arm_aux();
                } else {
                    super::watchpoint::re_arm();
                }
            }
            frame_sp
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
                // #251 scause-spill probe: log the entry-captured `scause`
                // alongside `frame.scause` (re-read from kstack) and live
                // sscause CSR.  In the bug we're chasing, the path that
                // reaches this log requires scause ∈ {12,13,15}, but the
                // printed value has been observed as 0 — implying either
                // the spilled local, the frame slot, or the CSR was
                // clobbered between the match arm and this print.
                let live_scause = read_scause();
                let frame_scause_reread = frame.scause;
                // #251 ra+fp probe: log saved registers so we can tell
                // ret-with-ra=0 (corrupted return address) vs jalr-to-NULL
                // (indirect call through a clobbered function pointer):
                //   * sepc=0 + ra=0  → returned via `ret` after stack
                //                       corruption zeroed the saved ra.
                //   * sepc=0 + ra!=0 → indirect call to a NULL pointer;
                //                       ra holds the next PC after the
                //                       calling site, useful for addr2line.
                // Also log s0/fp (frame.regs[7] = x8) and a2..a5 to seed
                // backtrace work without a full unwinder.
                let ra = frame.regs[0]; // x1
                let sp = frame.regs[1]; // x2
                let fp = frame.regs[7]; // x8 / s0
                // #253 anti-interleave: format the whole record into a
                // stack buffer and emit atomically.  Multiple harts
                // hitting the corruption family (#251 ⊂ #228) at the
                // same instant would otherwise mash bytes through the
                // shared 16550 + run core::fmt over a corrupted kstack
                // (Surface B second-fault inside pad_integral).  See
                // memory/project_riscv64_251_is_228_family.md.
                {
                    use crate::arch::riscv64::serial::{
                        handler_write_bytes, put_byte, put_bytes, put_dec_u64, put_hex_u64,
                    };
                    let mut buf = [0u8; 384];
                    let mut k = 0;
                    put_bytes(&mut buf, &mut k, b"Kernel page fault: cause=");
                    put_hex_u64(&mut buf, &mut k, scause);
                    put_bytes(&mut buf, &mut k, b" sepc=");
                    put_hex_u64(&mut buf, &mut k, frame.sepc);
                    put_bytes(&mut buf, &mut k, b" stval=");
                    put_hex_u64(&mut buf, &mut k, stval as u64);
                    put_bytes(&mut buf, &mut k, b" cpu=");
                    put_dec_u64(&mut buf, &mut k, cpu as u64);
                    put_bytes(&mut buf, &mut k, b" tid=");
                    put_dec_u64(&mut buf, &mut k, tid as u64);
                    put_bytes(&mut buf, &mut k, b" spp=");
                    put_dec_u64(&mut buf, &mut k, spp);
                    put_bytes(&mut buf, &mut k, b" sstatus=");
                    put_hex_u64(&mut buf, &mut k, frame.sstatus);
                    put_bytes(&mut buf, &mut k, b" sp(frame)=");
                    put_hex_u64(&mut buf, &mut k, frame.regs[1]);
                    put_bytes(&mut buf, &mut k, b" [#251 probe: entry_scause=");
                    put_hex_u64(&mut buf, &mut k, scause);
                    put_bytes(&mut buf, &mut k, b" frame.scause=");
                    put_hex_u64(&mut buf, &mut k, frame_scause_reread);
                    put_bytes(&mut buf, &mut k, b" live_scause=");
                    put_hex_u64(&mut buf, &mut k, live_scause);
                    put_bytes(&mut buf, &mut k, b" ra=");
                    put_hex_u64(&mut buf, &mut k, ra);
                    put_bytes(&mut buf, &mut k, b" sp=");
                    put_hex_u64(&mut buf, &mut k, sp);
                    put_bytes(&mut buf, &mut k, b" fp=");
                    put_hex_u64(&mut buf, &mut k, fp);
                    put_byte(&mut buf, &mut k, b']');
                    put_byte(&mut buf, &mut k, b'\n');
                    handler_write_bytes(&buf[..k.min(buf.len())]);
                }
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
                    // #253 anti-interleave.
                    {
                        use crate::arch::riscv64::serial::{
                            handler_write_bytes, put_bytes, put_dec_u64, put_hex_u64,
                        };
                        let mut buf = [0u8; 256];
                        let mut k = 0;
                        put_bytes(&mut buf, &mut k, b"Unhandled page fault: cause=");
                        put_hex_u64(&mut buf, &mut k, scause);
                        put_bytes(&mut buf, &mut k, b" sepc=");
                        put_hex_u64(&mut buf, &mut k, frame.sepc);
                        put_bytes(&mut buf, &mut k, b" stval=");
                        put_hex_u64(&mut buf, &mut k, stval as u64);
                        put_bytes(&mut buf, &mut k, b" frame_spp=");
                        put_dec_u64(&mut buf, &mut k, frame_spp);
                        put_bytes(&mut buf, &mut k, b" live_sepc=");
                        put_hex_u64(&mut buf, &mut k, live_sepc);
                        put_bytes(&mut buf, &mut k, b" live_spp=");
                        put_dec_u64(&mut buf, &mut k, live_spp);
                        put_bytes(&mut buf, &mut k, b" \xe2\x80\x94 killing thread\n");
                        handler_write_bytes(&buf[..k.min(buf.len())]);
                    }
                    crate::sched::scheduler::exit_current_thread(-11); // SIGSEGV
                }
                _ => frame_sp,
            }
        }

        _ => {
            // #253 anti-interleave: stack-buffer + handler_write_bytes.
            use crate::arch::riscv64::serial::{
                handler_write_bytes, put_bytes, put_hex_u64,
            };
            let mut buf = [0u8; 192];
            let mut k = 0;
            if scause & SCAUSE_INTERRUPT_BIT != 0 {
                put_bytes(&mut buf, &mut k, b"Unhandled S-mode interrupt: cause=");
                put_hex_u64(&mut buf, &mut k, scause & !SCAUSE_INTERRUPT_BIT);
                put_bytes(&mut buf, &mut k, b" sepc=");
                put_hex_u64(&mut buf, &mut k, frame.sepc);
                put_bytes(&mut buf, &mut k, b"\n");
                handler_write_bytes(&buf[..k.min(buf.len())]);
            } else {
                put_bytes(&mut buf, &mut k, b"Unhandled S-mode exception: cause=");
                put_hex_u64(&mut buf, &mut k, scause);
                put_bytes(&mut buf, &mut k, b" sepc=");
                put_hex_u64(&mut buf, &mut k, frame.sepc);
                put_bytes(&mut buf, &mut k, b" stval=");
                put_hex_u64(&mut buf, &mut k, read_stval() as u64);
                put_bytes(&mut buf, &mut k, b"\n");
                handler_write_bytes(&buf[..k.min(buf.len())]);
                // User-mode unhandled exception (illegal instr / misaligned /
                // etc.) → SIGSEGV the faulting thread instead of wedging this
                // CPU forever (which also hangs every client of a faulting
                // server).  sstatus.SPP (bit 8) == 0 means the trap came from
                // U-mode.  Mirrors the page-fault Failed arm (-11) above;
                // kernel-mode (SPP=1) is a genuine kernel bug → spin to preserve
                // state for inspection.  (Same class as the loongarch64 ADE fix.)
                if (frame.sstatus >> 8) & 1 == 0 {
                    crate::sched::scheduler::exit_current_thread(-11); // SIGSEGV
                }
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

/// Read the scause CSR — used by #251 to compare against frame.scause +
/// the locally captured `scause` variable at the println site.
fn read_scause() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("csrr {}, scause", out(reg) val) };
    val
}

/// Read register `idx` from the trap frame.  RISC-V `x0` always reads
/// as 0; `x1..x31` are stored at `frame.regs[0..31]`.
#[inline]
fn frame_x(frame: &TrapFrame, idx: u32) -> u64 {
    if idx == 0 { 0 } else { frame.regs[(idx - 1) as usize] }
}

/// Decode the store at `frame.sepc` and perform the write to memory
/// so legit `write_saved_sp` traffic preserves its semantics across
/// the trapped instruction.  Returns true on successful emulation,
/// false if the insn isn't a recognized store form (caller then
/// skips it with sepc advance only).
///
/// Disarms + re-arms the watchpoint around the emulated write so we
/// don't recursively trap on ourselves.
fn emulate_store(frame: &TrapFrame, insn32: u32, is_compressed: bool) -> bool {
    if !is_compressed {
        // 32-bit Store-type (S-type): opcode = 0b0100011, funct3
        // distinguishes sb/sh/sw/sd.
        if (insn32 & 0x7f) != 0x23 {
            return false;
        }
        let funct3 = (insn32 >> 12) & 0x7;
        let rs1 = (insn32 >> 15) & 0x1f;
        let rs2 = (insn32 >> 20) & 0x1f;
        let imm_11_5 = ((insn32 >> 25) & 0x7f) as i32;
        let imm_4_0 = ((insn32 >> 7) & 0x1f) as i32;
        let mut imm = (imm_11_5 << 5) | imm_4_0;
        if (imm & 0x800) != 0 { imm |= !0xfff_i32; }
        let imm = imm as i64;

        let base = frame_x(frame, rs1) as i64;
        let addr = base.wrapping_add(imm) as u64;
        let val = frame_x(frame, rs2);

        super::watchpoint::disarm();
        unsafe {
            match funct3 {
                0b000 => (addr as *mut u8).write_volatile(val as u8),         // sb
                0b001 => (addr as *mut u16).write_volatile(val as u16),       // sh
                0b010 => (addr as *mut u32).write_volatile(val as u32),       // sw
                0b011 => (addr as *mut u64).write_volatile(val),              // sd
                _ => return false,
            }
        }
        true
    } else {
        // Compressed stores.  RVC quadrant 0 covers c.sw / c.sd.
        // c.sd encoding (RV64): funct3 = 0b111, op = 0b00.
        // c.sw encoding:        funct3 = 0b110, op = 0b00.
        let op = insn32 & 0x3;
        let funct3 = (insn32 >> 13) & 0x7;
        if op != 0b00 {
            return false;
        }
        // rs1' = bits[9:7] + 8; rs2' = bits[4:2] + 8.
        let rs1p = ((insn32 >> 7) & 0x7) + 8;
        let rs2p = ((insn32 >> 2) & 0x7) + 8;
        let base = frame_x(frame, rs1p) as u64;
        let val = frame_x(frame, rs2p);
        match funct3 {
            0b111 => {
                // c.sd uimm = {bits[6:5], bits[12:10], 000}  (8-byte offset)
                let uimm_7_6 = ((insn32 >> 5) & 0x3) as u64;
                let uimm_5_3 = ((insn32 >> 10) & 0x7) as u64;
                let off = (uimm_5_3 << 3) | (uimm_7_6 << 6);
                let addr = base.wrapping_add(off);
                super::watchpoint::disarm();
                unsafe { (addr as *mut u64).write_volatile(val) };
                true
            }
            0b110 => {
                // c.sw uimm = {bits[5], bits[12:10], bits[6], 00}  (4-byte offset)
                let uimm_2 = ((insn32 >> 6) & 0x1) as u64;
                let uimm_6 = ((insn32 >> 5) & 0x1) as u64;
                let uimm_5_3 = ((insn32 >> 10) & 0x7) as u64;
                let off = (uimm_2 << 2) | (uimm_5_3 << 3) | (uimm_6 << 6);
                let addr = base.wrapping_add(off);
                super::watchpoint::disarm();
                unsafe { (addr as *mut u32).write_volatile(val as u32) };
                true
            }
            _ => false,
        }
    }
}
