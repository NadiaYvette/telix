//! x86-64 exception handlers.
//!
//! The vector stubs and IDT loading are in vectors.S and idt.rs.
//! This file contains the ExceptionFrame definition and Rust handlers.

/// Per-tid IRETQ probe counter.  Module-scope (not function-local) so
/// scheduler::exit_current_thread can reset it when a tid is freed —
/// otherwise tid reuse leaves the new thread with a quenched counter
/// and we get zero syscall trace.  See Stage 6 cage debug.
static IRETQ_LOG_COUNT: [core::sync::atomic::AtomicU32; 256] = {
    const Z: core::sync::atomic::AtomicU32 =
        core::sync::atomic::AtomicU32::new(0);
    [Z; 256]
};

/// Called from `scheduler::exit_current_thread` when a thread dies, so
/// the next thread to reuse the tid slot starts with a fresh quota.
pub fn reset_iretq_log_count(tid: u32) {
    if (tid as usize) < IRETQ_LOG_COUNT.len() {
        IRETQ_LOG_COUNT[tid as usize]
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Exception context saved on the stack by the vector entry stubs.
///
/// Layout (matching vectors.S push order):
///   regs[0]  = r15
///   regs[1]  = r14
///   regs[2]  = r13
///   regs[3]  = r12
///   regs[4]  = r11
///   regs[5]  = r10
///   regs[6]  = r9
///   regs[7]  = r8
///   regs[8]  = rbp
///   regs[9]  = rdi
///   regs[10] = rsi
///   regs[11] = rdx
///   regs[12] = rcx
///   regs[13] = rbx
///   regs[14] = rax
///   regs[15] = vector_number
///   regs[16] = error_code (real or dummy)
///   regs[17] = rip        (pushed by CPU)
///   regs[18] = cs         (pushed by CPU)
///   regs[19] = rflags     (pushed by CPU)
///   regs[20] = rsp        (pushed by CPU)
///   regs[21] = ss         (pushed by CPU)
#[repr(C)]
pub struct ExceptionFrame {
    pub regs: [u64; 22],
}

// Named indices into ExceptionFrame.regs for convenience.
#[allow(dead_code)]
impl ExceptionFrame {
    pub fn rax(&self) -> u64 {
        self.regs[14]
    }
    pub fn rbx(&self) -> u64 {
        self.regs[13]
    }
    pub fn rcx(&self) -> u64 {
        self.regs[12]
    }
    pub fn rdx(&self) -> u64 {
        self.regs[11]
    }
    pub fn rsi(&self) -> u64 {
        self.regs[10]
    }
    pub fn rdi(&self) -> u64 {
        self.regs[9]
    }
    pub fn rbp(&self) -> u64 {
        self.regs[8]
    }
    pub fn r8(&self) -> u64 {
        self.regs[7]
    }
    pub fn r9(&self) -> u64 {
        self.regs[6]
    }
    pub fn r10(&self) -> u64 {
        self.regs[5]
    }
    pub fn r11(&self) -> u64 {
        self.regs[4]
    }
    pub fn r12(&self) -> u64 {
        self.regs[3]
    }
    pub fn r13(&self) -> u64 {
        self.regs[2]
    }
    pub fn r14(&self) -> u64 {
        self.regs[1]
    }
    pub fn r15(&self) -> u64 {
        self.regs[0]
    }
    pub fn vector(&self) -> u64 {
        self.regs[15]
    }
    pub fn error_code(&self) -> u64 {
        self.regs[16]
    }
    pub fn rip(&self) -> u64 {
        self.regs[17]
    }
    pub fn cs(&self) -> u64 {
        self.regs[18]
    }
    pub fn rflags(&self) -> u64 {
        self.regs[19]
    }
    pub fn rsp(&self) -> u64 {
        self.regs[20]
    }
    pub fn ss(&self) -> u64 {
        self.regs[21]
    }

    pub fn set_rax(&mut self, v: u64) {
        self.regs[14] = v;
    }
    pub fn set_rbx(&mut self, v: u64) {
        self.regs[13] = v;
    }
    pub fn set_rcx(&mut self, v: u64) {
        self.regs[12] = v;
    }
    pub fn set_rdx(&mut self, v: u64) {
        self.regs[11] = v;
    }
    pub fn set_rsi(&mut self, v: u64) {
        self.regs[10] = v;
    }
    pub fn set_rdi(&mut self, v: u64) {
        self.regs[9] = v;
    }
    pub fn set_r8(&mut self, v: u64) {
        self.regs[7] = v;
    }
    pub fn set_r9(&mut self, v: u64) {
        self.regs[6] = v;
    }
    pub fn set_r10(&mut self, v: u64) {
        self.regs[5] = v;
    }
    pub fn set_rsp(&mut self, v: u64) {
        self.regs[20] = v;
    }
    pub fn set_rip(&mut self, v: u64) {
        self.regs[17] = v;
    }
}

/// Number of u64 values in the exception frame.
#[allow(dead_code)]
pub const FRAME_SIZE_U64: usize = 22;

/// Size of the exception frame in bytes.
#[allow(dead_code)]
pub const EXCEPTION_FRAME_SIZE: usize = FRAME_SIZE_U64 * 8; // 176 bytes

/// Validate the iretq frame at `sp` before returning to assembly.
/// If the frame is bad but `sp == fallback_sp` (no context switch happened),
/// we have no safe recovery — halt. If a switch did happen, mark the target
/// killed and return fallback_sp.
#[inline]
fn validate_iretq_frame(sp: u64, fallback_sp: u64, vector: u64) -> u64 {
    // Re-apply the current thread's TLS base before any exception-return
    // path (syscall, IRQ, fault retry).  Empirically FSBASE drifts to 0 on
    // x86 KVM when a personality_set_tls runs while the target is parked
    // and the wake-up race-loses the set_tls call (project_step_g_flakes.md
    // CR2=0x28 mode).  A single wrmsr here is cheap and makes the bug
    // disappear.
    {
        let tid = crate::sched::scheduler::current_thread_id();
        let tls = crate::sched::scheduler::thread_ref(tid).tls_base;
        crate::arch::cpu::set_tls(tls);
    }
    // #208 self-scribble probe: snapshot the 5 hardware-pushed iretq fields
    // (rip/cs/rflags/rsp/ss at u64 slots [17..21]) AT ENTRY to this function
    // AND after each subsequent step (FIRST-IRETQ-USER println, below-64K
    // check, check_iretq_shadow).  Logging which transition introduces the
    // first diff pinpoints the culprit.  Also snapshot 4 u64s ABOVE and 4
    // u64s BELOW the iretq frame so we can see scribble extent — buffer
    // overlap from an inline-call's stack frame would smear past the iretq
    // boundaries.  Boot 1021 caught a BAD frame whose bytes spelled the
    // FIRST-IRETQ-USER println format literally — strong hint the validator
    // scribbles its own input.
    //
    // Layout of pre_snap_all / mid_*_snap / post_snap (each [u64; 13]):
    //   slot[0..4]   = u64s at sp+8*13..sp+8*16  (4 slots BELOW iretq region)
    //   slot[4]      = errcode/dummy at sp+8*16
    //   slot[5..10]  = iretq fields: rip, cs, rflags, rsp, ss  (slot[17..21])
    //   slot[10..13] = u64s at sp+8*22..sp+8*25  (3 slots ABOVE iretq region)
    #[inline(always)]
    fn snap_iretq_region(sp: u64) -> [u64; 13] {
        use crate::arch::x86_64::mm::{KSTACK_REGION_BASE, KSTACK_WINDOW_SIZE, PML4_SLOT_SIZE};
        let max_safe: u64 = if sp >= KSTACK_REGION_BASE
            && sp < KSTACK_REGION_BASE.wrapping_add(PML4_SLOT_SIZE)
        {
            (sp & !(KSTACK_WINDOW_SIZE - 1)).wrapping_add(KSTACK_WINDOW_SIZE)
        } else {
            u64::MAX
        };
        let mut out = [0u64; 13];
        for (i, slot) in out.iter_mut().enumerate() {
            let addr = sp + (13 + i as u64) * 8;
            if addr.wrapping_add(8) <= max_safe {
                *slot = unsafe { core::ptr::read_volatile(addr as *const u64) };
            }
        }
        out
    }
    // Take an RSP snapshot alongside each iretq snap so we know if the
    // validator's own stack pushed past the iretq region (geometric overlap
    // check).
    #[inline(always)]
    fn cur_rsp() -> u64 {
        let r: u64;
        unsafe {
            core::arch::asm!("mov {0}, rsp", out(reg) r, options(nomem, nostack, preserves_flags));
        }
        r
    }
    let pre_snap_all: [u64; 13] = if sp >= 0x10000 {
        snap_iretq_region(sp)
    } else {
        [0; 13]
    };
    let pre_rsp: u64 = cur_rsp();
    // #208 pre-bad probe: if the iretq frame is ALREADY corrupt at entry
    // (cs neither 0x08 kernel nor 0x23 user, or otherwise out of selector
    // range), log the pre_snap immediately.  That tells us the corruption
    // happened BEFORE validate_iretq_frame was called — the validator is
    // innocent for these cases.  Captures the BAD-frame data path before
    // any of our own work could possibly perturb the bytes.
    //
    // ALSO dump the iretq SHADOW (taken at park-time) and saved_sp last-
    // writer log.  Three discriminations now possible:
    //   1. Shadow inside kstack, shadow.cs valid, pre snap garbage
    //      → saved_sp itself was OK; the memory at sp got mutated after
    //        save (use-after-recycle of stack page).
    //   2. Shadow not taken (sp outside kstack at save time)
    //      → saved_sp was bogus from the start; check writer log for who
    //        set it and to what.
    //   3. Shadow garbage too
    //      → the save itself observed garbage (snapshot at wrong sp).
    if sp >= 0x10000 {
        let pre_cs = pre_snap_all[5];
        if pre_cs > 0xffff || (pre_cs != 0x08 && pre_cs != 0x23) {
            let tid = crate::sched::scheduler::current_thread_id();
            let tref = crate::sched::scheduler::thread_ref(tid);
            crate::println!(
                "VALIDATOR-PRE-BAD: tid={} cpu={} sp={:#x} vec={} pre_rsp={:#x} \
                 stack_base={:#x} saved_sp_now={:#x} saved_sp_source={} \
                 pre.rip={:#x} pre.cs={:#x} pre.rflags={:#x} pre.rsp={:#x} pre.ss={:#x} \
                 pre_below=[{:#x} {:#x} {:#x} {:#x}] pre_above=[{:#x} {:#x} {:#x} {:#x}] \
                 shadow.sp={:#x} shadow.rip={:#x} shadow.cs={:#x} shadow.rflags={:#x} shadow.rsp={:#x} shadow.ss={:#x}",
                tid,
                crate::sched::smp::cpu_id(),
                sp, vector, pre_rsp,
                tref.stack_base, tref.saved_sp, tref.saved_sp_source,
                pre_snap_all[4], pre_snap_all[5], pre_snap_all[6], pre_snap_all[7], pre_snap_all[8],
                pre_snap_all[0], pre_snap_all[1], pre_snap_all[2], pre_snap_all[3],
                pre_snap_all[9], pre_snap_all[10], pre_snap_all[11], pre_snap_all[12],
                tref.iretq_shadow_sp, tref.iretq_shadow_rip, tref.iretq_shadow_cs,
                tref.iretq_shadow_rflags, tref.iretq_shadow_rsp, tref.iretq_shadow_ss,
            );
            // Last-writer log: who SET saved_sp last, with what value + tag.
            crate::sched::scheduler::dump_saved_sp_log(tid);
        }
    }
    // #135 first-iretq-to-user probe: log the FIRST time we return-to-user
    // for each tid.  Tells us whether iretq is delivering correct (RIP, CS,
    // SS) to userspace.  If a freshly-spawned thread shows FIRST-IRETQ with
    // a garbage RIP or non-23 CS, the spawn_user fake-frame setup is broken.
    // One-shot per tid via 256-slot bitmap.
    {
        static FIRST_IRETQ_USER_LOGGED: [core::sync::atomic::AtomicBool; 256] = {
            const Z: core::sync::atomic::AtomicBool =
                core::sync::atomic::AtomicBool::new(false);
            [Z; 256]
        };
        let frame_peek = unsafe { &*(sp as *const ExceptionFrame) };
        let cs_peek = frame_peek.cs();
        if (cs_peek & 3) == 3 {
            // Going to userspace (CS RPL=3).
            let tid = crate::sched::scheduler::current_thread_id();
            if (tid as usize) < FIRST_IRETQ_USER_LOGGED.len() {
                if !FIRST_IRETQ_USER_LOGGED[tid as usize]
                    .swap(true, core::sync::atomic::Ordering::Relaxed)
                {
                    // #155 anon-zero-page family probe: peek at the
                    // first 16 bytes the user is about to execute.  If
                    // they're zero or otherwise corrupt at this moment,
                    // the corruption happened BEFORE iretq (i.e. in
                    // finalize_spawn / percpu_enqueue / context-switch).
                    // If they look like valid x86 code here, the
                    // corruption is in iretq itself or the very-first
                    // instruction fetch.  copy_from_user walks the
                    // user's PT so we see exactly what the user CPU
                    // will see.
                    let rip = frame_peek.rip();
                    let mut bytes = [0u8; 16];
                    let pt_root = crate::sched::scheduler::current_page_table_root();
                    let ok = crate::syscall::handlers::copy_from_user(
                        pt_root, rip as usize, &mut bytes,
                    );
                    let all_zero = bytes.iter().all(|&b| b == 0);
                    crate::println!(
                        "FIRST-IRETQ-USER: tid={} cpu={} vec={} sp={:#x} \
                         rip={:#x} cs={:#x} ss={:#x} rax={:#x} rsp={:#x} \
                         rip_bytes_ok={} rip_bytes_zero={} rip_bytes=[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}]",
                        tid,
                        crate::sched::smp::cpu_id(),
                        vector, sp,
                        rip,
                        cs_peek,
                        frame_peek.ss(),
                        frame_peek.rax(),
                        frame_peek.rsp(),
                        ok, all_zero,
                        bytes[0], bytes[1], bytes[2], bytes[3],
                        bytes[4], bytes[5], bytes[6], bytes[7],
                    );
                }
            }
        }
    }
    // Absolute minimum: no valid kstack frame can be below 64K — catch
    // saved_sp=0 or any pointer into the real-mode IVT / BIOS data area.
    if sp < 0x10000 {
        let tid = crate::sched::scheduler::current_thread_id();
        crate::println!(
            "BAD frame: sp={:#x} (below 64K) vec={} tid={}",
            sp, vector, tid
        );
        crate::sched::scheduler::thread_ref(tid)
            .killed.store(true, core::sync::atomic::Ordering::Release);
        crate::arch::irq::enable();
        loop { core::hint::spin_loop(); }
    }
    // #208 mid-validator snapshot: BEFORE check_iretq_shadow, so a diff at
    // this point vs pre_snap_all isolates corruption to the
    // FIRST-IRETQ-USER block + below-64K check (the two steps run above).
    let mid1_snap_all: [u64; 13] = if sp >= 0x10000 {
        snap_iretq_region(sp)
    } else {
        [0; 13]
    };
    let mid1_rsp: u64 = cur_rsp();
    // #208 Probe A: compare live iretq fields against the shadow recorded
    // at park time.  Fires FRAME-DELTA whenever fields changed in between.
    {
        let tid = crate::sched::scheduler::current_thread_id();
        crate::sched::scheduler::check_iretq_shadow(tid, sp);
    }
    // #208 self-scribble check: re-read the iretq region and compare to
    // pre_snap_all and mid1_snap_all.  A diff between pre→mid1 isolates
    // FIRST-IRETQ-USER or below-64K as the corrupter; a diff between
    // mid1→post implicates check_iretq_shadow.  Surrounding bytes show
    // scribble extent (geometric overlap with a stack buffer).
    if sp >= 0x10000 {
        let post_snap_all: [u64; 13] = snap_iretq_region(sp);
        let post_rsp: u64 = cur_rsp();
        if pre_snap_all != post_snap_all {
            let tid = crate::sched::scheduler::current_thread_id();
            // Find first slot that differs at each transition.
            let mut pre_mid_first = -1i32;
            let mut mid_post_first = -1i32;
            for i in 0..13 {
                if pre_mid_first < 0 && pre_snap_all[i] != mid1_snap_all[i] {
                    pre_mid_first = i as i32;
                }
                if mid_post_first < 0 && mid1_snap_all[i] != post_snap_all[i] {
                    mid_post_first = i as i32;
                }
            }
            crate::println!(
                "VALIDATOR-SELF-SCRIBBLE: tid={} cpu={} sp={:#x} vec={} \
                 pre_rsp={:#x} mid1_rsp={:#x} post_rsp={:#x} \
                 pre_mid_first_diff={} mid_post_first_diff={} \
                 pre.rip={:#x} pre.cs={:#x} pre.rflags={:#x} pre.rsp={:#x} pre.ss={:#x} \
                 mid1.rip={:#x} mid1.cs={:#x} mid1.rflags={:#x} mid1.rsp={:#x} mid1.ss={:#x} \
                 post.rip={:#x} post.cs={:#x} post.rflags={:#x} post.rsp={:#x} post.ss={:#x} \
                 pre_below=[{:#x} {:#x} {:#x} {:#x}] pre_above=[{:#x} {:#x} {:#x} {:#x}] \
                 post_below=[{:#x} {:#x} {:#x} {:#x}] post_above=[{:#x} {:#x} {:#x} {:#x}]",
                tid,
                crate::sched::smp::cpu_id(),
                sp, vector,
                pre_rsp, mid1_rsp, post_rsp,
                pre_mid_first, mid_post_first,
                pre_snap_all[4], pre_snap_all[5], pre_snap_all[6], pre_snap_all[7], pre_snap_all[8],
                mid1_snap_all[4], mid1_snap_all[5], mid1_snap_all[6], mid1_snap_all[7], mid1_snap_all[8],
                post_snap_all[4], post_snap_all[5], post_snap_all[6], post_snap_all[7], post_snap_all[8],
                pre_snap_all[0], pre_snap_all[1], pre_snap_all[2], pre_snap_all[3],
                pre_snap_all[9], pre_snap_all[10], pre_snap_all[11], pre_snap_all[12],
                post_snap_all[0], post_snap_all[1], post_snap_all[2], post_snap_all[3],
                post_snap_all[9], post_snap_all[10], post_snap_all[11], post_snap_all[12],
            );
        }
    }
    let f = unsafe { &*(sp as *const ExceptionFrame) };
    // Use volatile reads so the compiler can't fuse the first read with the
    // re-read below.  Without volatile, LLVM would CSE the second `f.cs()`
    // back to the first, and the flicker probe would always show "no change."
    let cs;
    let ss;
    let rip;
    unsafe {
        cs = core::ptr::read_volatile(&f.regs[18] as *const u64);
        ss = core::ptr::read_volatile(&f.regs[21] as *const u64);
        rip = core::ptr::read_volatile(&f.regs[17] as *const u64);
    }
    // Probe #208: latching frame snapshot.  Immediately re-read CS/SS/RIP
    // and log if any of them changed.  Boot 584 caught the SS field
    // flickering between validate's first read (0x109431, BAD) and the
    // subsequent dump loop's read (0x0, valid) ~50 println-lines later —
    // strong evidence a different CPU is writing to this kstack page
    // concurrently with the validation.  This probe puts the second read
    // in the same hot path, ~ns apart from the first, so any flicker
    // attributable to a concurrent writer surfaces with a tight time
    // bound.
    let cs2: u64;
    let ss2: u64;
    let rip2: u64;
    unsafe {
        cs2 = core::ptr::read_volatile(&f.regs[18] as *const u64);
        ss2 = core::ptr::read_volatile(&f.regs[21] as *const u64);
        rip2 = core::ptr::read_volatile(&f.regs[17] as *const u64);
    }
    if cs != cs2 || ss != ss2 || rip != rip2 {
        let tid_local = crate::sched::scheduler::current_thread_id();
        let cur_cpu = crate::sched::smp::cpu_id();
        crate::println!(
            "FRAME-FLICKER: vec={} tid={} cpu={} sp={:#x} CS={:#x}->{:#x} SS={:#x}->{:#x} RIP={:#x}->{:#x}",
            vector, tid_local, cur_cpu, sp,
            cs, cs2, ss, ss2, rip, rip2
        );
    }
    let bad_cs = cs != 0x08 && cs != 0x23;
    let bad_ss = ss != 0x00 && ss != 0x10 && ss != 0x1B;
    // Tightened RIP check (chasing #UD corruption family, task #208):
    // for kernel-mode iretq (CS=0x08), RIP must be in kernel
    // .text range (0x101000–0x1ac1be) because there's no other place kernel
    // execution belongs.  For user iretq (CS=0x23), RIP must be in the
    // user-binary range (top 32 bits in {0x1, 0x2, 0x4}) because all
    // userspace binaries load at 0x100000000+ and Linux personality stacks
    // map at 0x200000000+ / 0x400000000+.  Boots 575/576/578 slipped past
    // the old check by having CS=0x08 with a userspace-ish RIP like 0x9fc42
    // (truncated from 0x10009fc42) — they iretq'd to a non-kernel-text RIP
    // in kernel mode and #UD'd on instruction fetch.
    // Use linker-provided __text_end (set in linker.ld at end of .text)
    // so the bound tracks kernel size across builds.  Earlier hardcoded
    // 0x1ac1be was too tight: boot 586 caught RIP=0x1ac1d9 in compiler
    // memset (rep stos) past the nominal section end — false positive.
    unsafe extern "C" {
        static __text_end: u8;
    }
    let text_end = unsafe { &__text_end as *const _ as u64 };
    let bad_kernel_rip = cs == 0x08 && !(rip >= 0x101000 && rip < text_end);
    let bad_user_rip = cs == 0x23 && {
        let hi = rip >> 32;
        !(hi == 0x1 || hi == 0x2 || hi == 0x4)
    };
    if bad_cs || bad_ss || bad_kernel_rip || bad_user_rip {
        let tid = crate::sched::scheduler::current_thread_id();
        let tref = crate::sched::scheduler::thread_ref(tid);
        let cur_cpu = crate::sched::smp::cpu_id();
        crate::println!(
            "BAD frame: CS={:#x} SS={:#x} RIP={:#x} vec={} tid={} sp={:#x} src={} last_cpu={} cur_cpu={}",
            cs, ss, f.rip(), vector, tid, sp,
            tref.saved_sp_source,
            tref.last_cpu.load(core::sync::atomic::Ordering::Relaxed),
            cur_cpu
        );
        // Dump full frame to diagnose corruption pattern. If GPRs (offsets
        // 0-112) are valid but CPU-pushed (136-168) are garbage: partial
        // overwrite from frame top. If everything is garbage: full page alias.
        crate::println!(
            "  saved_sp={:#x} kstack={:#x} task={}",
            tref.saved_sp, tref.stack_base, tref.task_id
        );
        // Raw dump: 22 u64 values at [sp..sp+176).  Annotate any value
        // that falls in a live thread's kstack range (#208 ladder
        // step 1: visually distinguish kstack pointers from garbage).
        for i in 0..22u64 {
            let val = unsafe { *((sp + i * 8) as *const u64) };
            if let Some((annot_tid, off)) =
                crate::sched::scheduler::classify_kstack_value(val)
            {
                crate::println!(
                    "  frame[{}]={:#018x} [kstack tid={} +{:#x}]",
                    i, val, annot_tid, off,
                );
            } else {
                crate::println!("  frame[{}]={:#018x}", i, val);
            }
        }
        // #208 H-A vs H-B probe: also dump the frame at tref.saved_sp.
        // If validate's sp ≠ saved_sp, we're checking the wrong frame.
        // If BOTH frames are corrupt → page-reuse / aliasing bug (H-A).
        // If saved_sp frame is clean → validate's sp path is wrong (H-B).
        let saved_sp = tref.saved_sp;
        if saved_sp != 0 && saved_sp != sp {
            crate::println!(
                "  [also dumping at saved_sp={:#x} (Δ={:#x})]",
                saved_sp,
                saved_sp.wrapping_sub(sp) as i64,
            );
            for i in 17..22u64 {
                let val = unsafe { *((saved_sp + i * 8) as *const u64) };
                let label = match i {
                    17 => "RIP",
                    18 => "CS ",
                    19 => "FLG",
                    20 => "RSP",
                    21 => "SS ",
                    _ => "   ",
                };
                crate::println!(
                    "  ssp[{}={}]={:#018x}", i, label, val,
                );
            }
        }
        // #208 shadow + saved_sp last-writer dump: tell whether the
        // SHADOW (taken at park-time by snapshot_iretq_shadow) was
        // already corrupt (in which case the save itself was wrong)
        // or is valid (in which case the memory at sp got mutated
        // between save and validate).  The dump_saved_sp_log call
        // emits SAVED-SP-LAST with the tag (1=try_switch, 2=voluntary,
        // 3=pre_save_frame/park_ipc, 5=park_for_sleep, 6=resync_clone)
        // identifying who set saved_sp last.
        crate::println!(
            "  shadow.sp={:#x} shadow.rip={:#x} shadow.cs={:#x} shadow.rflags={:#x} shadow.rsp={:#x} shadow.ss={:#x}",
            tref.iretq_shadow_sp,
            tref.iretq_shadow_rip,
            tref.iretq_shadow_cs,
            tref.iretq_shadow_rflags,
            tref.iretq_shadow_rsp,
            tref.iretq_shadow_ss,
        );
        crate::sched::scheduler::dump_saved_sp_log(tid);
        // #208 saved_sp watchpoint: arm GLOBAL DR0 to catch the next
        // write to tref.saved_sp.  All CPUs will arm DR0 on this
        // address at their next x86_exception_handler entry.  Any
        // writer outside the stub-region (which is filtered in the
        // #DB handler) logs as DR0-HIT-OFF-PATH with the writer's RIP.
        // Boot 1798 #PF root cause: tref pointer was 0xfffffe00031fff50
        // (a kstack VA, not a SLAB_THREAD_REGION VA — Thread structs live
        // at 0xfffffe80_..., PML4[509]).  Writing `killed=true` at offset
        // 0x2f0 hit unmapped memory and PF'd here.  Guard the write by
        // verifying tref points into SLAB_REGION before touching it.
        let tref_addr = tref as *const _ as u64;
        let tref_ok = tref_addr >= crate::arch::x86_64::mm::SLAB_REGION_BASE
            && tref_addr < crate::arch::x86_64::mm::SLAB_REGION_BASE
                .wrapping_add(crate::arch::x86_64::mm::PML4_SLOT_SIZE);
        if !tref_ok {
            crate::dump_atomic!(
                "VALIDATOR-BAD-TREF: tid={} tref={:#x} (NOT in SLAB_REGION \
                 {:#x}..{:#x}) — THREAD_TABLE[{}] corrupted; skipping \
                 killed.store and DR0-arm",
                tid, tref_addr,
                crate::arch::x86_64::mm::SLAB_REGION_BASE,
                crate::arch::x86_64::mm::SLAB_REGION_BASE
                    .wrapping_add(crate::arch::x86_64::mm::PML4_SLOT_SIZE),
                tid,
            );
            // Dump the SET-LOG trajectory for this tid to discriminate
            // set-side bug (prev_val already wrong) vs post-set scribble
            // (prev_val was SLAB_REGION on the last set).
            crate::sched::radix::dump_set_log_for_tid(tid);
        } else {
            let saved_sp_addr = &tref.saved_sp as *const u64 as u64;
            crate::arch::x86_64::gdt::GLOBAL_SAVED_SP_WATCH_ADDR
                .store(saved_sp_addr, core::sync::atomic::Ordering::Relaxed);
            crate::println!(
                "DR0-WATCH-ARMED: addr={:#x} (= &tref({}).saved_sp)",
                saved_sp_addr, tid,
            );
            // Mark the current thread (the one with corrupt state) as
            // killed so the scheduler won't re-enqueue it on the next
            // tick.
            tref.killed.store(true, core::sync::atomic::Ordering::Release);
        }
        // Enable interrupts so timer can switch us off this thread.
        crate::arch::irq::enable();
        loop { core::hint::spin_loop(); }
    }
    sp
}

/// Common interrupt/exception handler called from assembly.
/// For timer IRQ (vector 32), returns potentially new SP for context switch.
#[unsafe(no_mangle)]
extern "C" fn x86_exception_handler(frame_sp: u64) -> u64 {
    // Clear any stale pending_switch_sp left by the previous exception's
    // return path.  The previous cycle's take_pending_switch() loaded the
    // SP without clearing it (so wake_parked_thread's spin-wait could see
    // the non-zero value until the assembly `mov rsp, rax` completed).
    // By this point the stack switch is done — safe to signal completion.
    let cpu = crate::sched::smp::cpu_id() as usize;
    crate::sched::scheduler::clear_pending_switch(cpu);

    // #208 saved_sp watchpoint — one-shot arm on tid=4's saved_sp
    // field as soon as the Thread is allocated.  Pre-fix, BIOS-IVT
    // corruption clusters on tid=4 (init).  Proactive arming catches
    // writes BEFORE BAD frame fires (post-fire arming was useless
    // because killed thread is never written again).
    {
        let target = crate::arch::x86_64::gdt::GLOBAL_SAVED_SP_WATCH_ADDR
            .load(core::sync::atomic::Ordering::Relaxed);
        if target == 0 {
            // First exception_handler call where tid=4 exists: arm it.
            let t4 =
                crate::sched::scheduler::thread_ref_opt(4);
            if let Some(t) = t4 {
                let addr = &t.saved_sp as *const u64 as u64;
                crate::arch::x86_64::gdt::GLOBAL_SAVED_SP_WATCH_ADDR
                    .store(addr, core::sync::atomic::Ordering::Relaxed);
                crate::println!(
                    "DR0-WATCH-PROACTIVE: addr={:#x} cpu={}",
                    addr, cpu,
                );
            }
        } else {
            crate::arch::x86_64::gdt::dr0_ensure_watching(target);
        }
    }

    let frame = unsafe { &mut *(frame_sp as *mut ExceptionFrame) };
    let vector = frame.vector();

    // #208 early-stage CS sanity check.  Runs IMMEDIATELY at handler
    // entry, before any other Rust code that could write to the
    // iretq slots.  If CS is bad here, the corruption is in the
    // assembly stub or earlier (extremely unlikely — CPU push and
    // __isr_common pushes don't touch +144).  If CS is OK here but
    // bad at validate (end of handler), the corruption happened
    // during the Rust handler — narrows the writer hunt to the
    // dispatch/tick/syscall code paths.  Rate-limited to 50.
    {
        let cs_early = unsafe {
            core::ptr::read_volatile(&frame.regs[18] as *const u64)
        };
        if cs_early != 0x08 && cs_early != 0x23 {
            static EARLY_BAD_CS: core::sync::atomic::AtomicU32 =
                core::sync::atomic::AtomicU32::new(0);
            let n = EARLY_BAD_CS.fetch_add(
                1, core::sync::atomic::Ordering::Relaxed,
            );
            if n < 50 {
                crate::println!(
                    "EARLY-BAD-CS: vec={} cs={:#x} rip={:#x} frame_sp={:#x} cpu={} n={}",
                    vector,
                    cs_early,
                    unsafe {
                        core::ptr::read_volatile(
                            &frame.regs[17] as *const u64,
                        )
                    },
                    frame_sp,
                    cpu,
                    n,
                );
            }
        }
    }

    // #135 last_irq_ns: stamp every exception/IRQ entry so the rescue
    // can distinguish "CPU is alive but try_switch not reached" from
    // "CPU is truly halted (no IRQs arriving)".
    if vector >= 32 {
        crate::sched::smp::get(cpu as u32)
            .last_irq_ns
            .store(crate::arch::timer::monotonic_ns(), core::sync::atomic::Ordering::Relaxed);
    }

    // #208 RSP0-MISMATCH probe.  When entering from user mode (CPL=3),
    // the CPU loaded the new RSP from TSS RSP0.  If RSP0 was stale
    // relative to `current_thread` (e.g., not updated between
    // dispatch and the next user-mode trap), `frame_sp` now points
    // into the wrong thread's kstack — exactly the symptom of the
    // kernel #UD family.  Boot 600 tid=13 had frame_sp=0x835fda0
    // while its real kstack was [0x7f70000..0x7f90000).  One log
    // line per fire, rate-limited to 100/boot.
    {
        let from_user = (frame.cs() & 3) == 3;
        if from_user {
            let tid = crate::sched::smp::current()
                .current_thread
                .load(core::sync::atomic::Ordering::Relaxed);
            let idle_id = crate::sched::smp::current()
                .idle_thread_id
                .load(core::sync::atomic::Ordering::Relaxed);
            if tid != idle_id {
                let t = crate::sched::scheduler::thread_ref(tid);
                let sb = t.stack_base as u64;
                let sz = crate::sched::scheduler::kstack_size() as u64;
                if sb != 0 && !(frame_sp >= sb && frame_sp <= sb + sz) {
                    static RSP0_MISMATCH_LOG: core::sync::atomic::AtomicU32 =
                        core::sync::atomic::AtomicU32::new(0);
                    let n = RSP0_MISMATCH_LOG.fetch_add(
                        1, core::sync::atomic::Ordering::Relaxed,
                    );
                    if n < 100 {
                        let tss_rsp0 = crate::arch::x86_64::gdt::get_rsp0();
                        let expected_rsp0 = sb + sz;
                        crate::println!(
                            "RSP0-MISMATCH: tid={} cpu={} vec={} frame_sp={:#x} expected_kstack=[{:#x}..{:#x}) tss_rsp0={:#x} expected_rsp0={:#x} cs={:#x} n={}",
                            tid, cpu, vector, frame_sp, sb, sb + sz,
                            tss_rsp0, expected_rsp0,
                            frame.cs(), n,
                        );
                        crate::sched::scheduler::dump_rsp0_ring(cpu as u32);
                        crate::sched::scheduler::dump_ct_ring(cpu as u32);
                    }
                    // #208 Path C extension: fix TSS.RSP0 now so the NEXT
                    // user→kernel transition pushes onto the correct
                    // kstack.  The CURRENT iret frame is already pushed
                    // wrong (we can't fix that retroactively), but
                    // subsequent transitions will be safe until
                    // current_thread changes again.
                    let expected_rsp0 = sb + sz;
                    crate::arch::x86_64::gdt::set_rsp0(tid, expected_rsp0);
                }
            }
        }
    }

    match vector {
        // CPU exceptions 0-31.
        0 => exception_fault("Divide Error (#DE)", frame),
        1 => {
            // #208 DR0 hit handler.  Two cases:
            //   1. RIP is inside the __isr_stub_* region: that's the
            //      CPU's automatic CS push at exception entry on a
            //      thread sharing the watched address.  Expected
            //      noise — re-arm DR0 silently and continue.
            //   2. RIP is OUTSIDE the stub region: a kernel function
            //      wrote to the watched CS slot.  Log it (this is
            //      the corruption writer we're hunting) and disable
            //      DR0 to prevent further fires.
            let dr6 = crate::arch::x86_64::gdt::dr6_read_clear();
            if dr6 & 0xF != 0 {
                let rip = frame.rip();
                unsafe extern "C" {
                    static __isr_stub_0: u8;
                }
                let stub_lo = unsafe { &__isr_stub_0 as *const _ as u64 };
                // Each stub is 16-byte aligned; 256 stubs = 0x1000 span.
                let stub_hi = stub_lo + 0x1000;
                let in_stub_region = rip >= stub_lo && rip < stub_hi;
                if in_stub_region {
                    // Expected CPU push at exception entry.  Re-arm DR0
                    // with the same address so we keep watching for the
                    // off-path writer.
                    let watched =
                        crate::arch::x86_64::gdt::dr0_get_watched();
                    if watched != 0 {
                        crate::arch::x86_64::gdt::dr0_set_watch_write_qword(
                            watched,
                        );
                    }
                } else {
                    let tid = crate::sched::scheduler::current_thread_id();
                    let tref = crate::sched::scheduler::thread_ref(tid);
                    let kbase = tref.stack_base as u64;
                    let ksize = crate::sched::scheduler::kstack_size() as u64;
                    let watched =
                        crate::arch::x86_64::gdt::dr0_get_watched();
                    // Read actual DR0 register to verify it matches.
                    let dr0_reg: u64;
                    unsafe {
                        core::arch::asm!("mov {0}, dr0", out(reg) dr0_reg);
                    }
                    let in_kstack =
                        watched >= kbase && watched < kbase + ksize;
                    // frame_sp is rsp at handler entry; compute rsp at
                    // exception entry (before CPU/stub pushes). Same-CPL:
                    // CPU pushes 3 quads + stub pushes 2 (vec, err) + 15
                    // GPRs = 20 * 8 = 160 bytes.
                    let rsp_entry = frame_sp + 22 * 8;
                    let rdi = frame.regs[12]; // GPR push order check
                    let rax = frame.regs[14];
                    crate::println!(
                        "DR0-HIT-OFF-PATH-OVERLAP: watched={:#x} dr0_reg={:#x} kbase={:#x}..{:#x} in_kstack={} rsp_entry={:#x} rdi={:#x} rax={:#x}",
                        watched, dr0_reg, kbase, kbase + ksize, in_kstack, rsp_entry, rdi, rax,
                    );
                    // #208 ts probe: timestamp DR0 hits so a post-mortem can
                    // sort by time and look for overlapping write windows
                    // from different CPUs on the same tid — signature of
                    // concurrent dispatch of the same thread.
                    let ts_ns = crate::arch::timer::monotonic_ns();
                    crate::println!(
                        "DR0-HIT-OFF-PATH: dr6={:#x} rip={:#x} tid={} cpu={} cs={:#x} ts_ns={}",
                        dr6, rip, tid, cpu, frame.cs(), ts_ns,
                    );
                    crate::arch::x86_64::gdt::dr0_clear();
                }
                return validate_iretq_frame(frame_sp, frame_sp, 1);
            }
            exception_fault("Debug (#DB)", frame)
        }
        2 => exception_fault("NMI", frame),
        3 => {
            // #BP (vector 3) from user mode is the Linux SIGTRAP path:
            // glibc abort/assertion sequences emit INT 3 (0xCC) after
            // writing the diagnostic message via sys_write.  Linux
            // contract: deliver SIGTRAP to the user task.  Telix's
            // minimum viable handling is to terminate with the
            // SIGTRAP exit code, mirroring the user's clear intent
            // to abort.  Future work: full signal-delivery so the
            // task's installed SIGTRAP handler can run.
            //
            // From kernel mode, #BP is unexpected (debug placement,
            // corrupted control flow) — fall through to the generic
            // fault dump + panic.
            //
            // Pattern C (boots 547/550/556 deterministic) — see
            // [[project-overnight-boot-patterns]] memory note.
            let from_user = (frame.cs() & 3) == 3;
            if from_user {
                // Advance past the INT 3 (1 byte) so a hypothetical
                // future signal handler would resume after the trap.
                // Currently we exit the thread, so this is for
                // diagnostic consistency only.
                frame.set_rip(frame.rip() + 1);
                crate::println!(
                    "USER #BP (INT 3) at RIP={:#x} tid={} → exit SIGTRAP(5)",
                    frame.rip() - 1,
                    crate::sched::scheduler::current_thread_id(),
                );
                crate::sched::scheduler::exit_current_thread(-5);
                // exit_current_thread is divergent; unreachable below.
            }
            exception_fault("Breakpoint (#BP)", frame)
        }
        4 => exception_fault("Overflow (#OF)", frame),
        5 => exception_fault("Bound Range (#BR)", frame),
        6 => {
            // #UD handling: if the faulting instruction in userspace is
            // `syscall` (0x0f 0x05) — used by glibc and other Linux binaries —
            // emulate it by dispatching through the normal int 0x80 path.
            // The x86_64 syscall ABI (rax=nr, rdi/rsi/rdx/r10/r8/r9=args)
            // already matches the Telix trapframe accessors.
            let cs = frame.cs();
            let from_user = (cs & 3) == 3;
            if from_user {
                let rip = frame.rip() as *const u8;
                let (b0, b1) = unsafe { (*rip, *rip.add(1)) };
                if b0 == 0x0f && b1 == 0x05 {
                    // Advance past `syscall` (2 bytes) so iretq returns to
                    // the instruction after it.
                    frame.set_rip(frame.rip() + 2);
                    crate::sched::scheduler::store_frame_sp(frame_sp);
                    crate::arch::irq::enable();
                    crate::syscall::dispatch(frame);
                    let _ = crate::arch::irq::disable();
                    crate::sched::scheduler::check_preempt_on_return();
                    let pending = crate::sched::scheduler::take_pending_switch();
                    // #136 IRETQ-RIP probe: for Linux-personality threads,
                    // dump the frame's RIP just before iretq.  Boots 654-658
                    // show the child reaches its first syscall and returns
                    // (write prints [clone_child_w]) but never reaches the
                    // immediately-next instruction (int3 placed there never
                    // traps).  If the RIP printed here is 0x1c64 (the int3
                    // address), the iretq is correct and the bug is on the
                    // userspace side or in the int3 trap path.  If RIP is
                    // SOMETHING ELSE, the kernel iretq is misdirecting and
                    // we've localized the bug to here.  Rate-limit to the
                    // first ~6 fires per Linux thread to avoid log spam.
                    {
                        let tid = crate::sched::scheduler::current_thread_id();
                        let task_id =
                            crate::sched::scheduler::thread_ref(tid).task_id;
                        let task = crate::sched::scheduler::task_ref(task_id);
                        if task.personality as u8 != 0 {
                            if (tid as usize) < IRETQ_LOG_COUNT.len() {
                                let n = IRETQ_LOG_COUNT[tid as usize]
                                    .fetch_add(
                                        1,
                                        core::sync::atomic::Ordering::Relaxed,
                                    );
                                if n < 100 {
                                    let final_sp = if pending != 0 {
                                        pending
                                    } else {
                                        frame_sp
                                    };
                                    let final_frame = unsafe {
                                        &*(final_sp as *const ExceptionFrame)
                                    };
                                    crate::println!(
                                        "IRETQ: tid={} task={} sp={:#x} \
                                         rip={:#x} cs={:#x} rax={:#x} \
                                         pending={}",
                                        tid, task_id, final_sp,
                                        final_frame.rip(),
                                        final_frame.cs(),
                                        final_frame.rax(),
                                        if pending != 0 { "yes" } else { "no" }
                                    );
                                }
                            }
                        }
                    }
                    if pending != 0 {
                        return validate_iretq_frame(pending, frame_sp, 6);
                    }
                    return frame_sp;
                }
                // Diagnostic: dump 16 bytes at the faulting RIP so we can
                // decode the instruction post-mortem.  Boot 421 caught an
                // unexplained #UD inside a userspace dynamic-library
                // region (RIP=0x200bf52d5) — without the bytes it's
                // impossible to tell whether it's an unsupported
                // CPU-feature instruction (AVX-512, CET ENDBR64, etc),
                // memcpy corruption from the IO_READ path, or something
                // else.  Read can fault again if the RIP page is
                // unmapped, but at this point we're about to kill the
                // thread anyway, so a triple-fault here is no worse than
                // the current behavior.
                let mut bytes = [0u8; 16];
                for i in 0..16 {
                    bytes[i] = unsafe { *rip.add(i) };
                }
                crate::println!(
                    "  #UD bytes at RIP: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} \
                     {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                    bytes[8], bytes[9], bytes[10], bytes[11],
                    bytes[12], bytes[13], bytes[14], bytes[15]
                );
            }
            exception_fault("Invalid Opcode (#UD)", frame)
        }
        7 => exception_fault("Device Not Available (#NM)", frame),
        8 => {
            // #DF runs on IST stack — safe to print diagnostics.  Use
            // DirectUart (#208) instead of println! because if the kernel
            // got into #DF via the corruption family, StackBuf's `len`
            // field is likely also corrupted and println! would re-panic
            // → silent triple-fault.  DirectUart writes one byte at a
            // time directly to COM1 with no kstack temporaries.
            use core::fmt::Write;
            let cr2: u64;
            unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2); }
            let tid = crate::sched::scheduler::current_thread_id();
            let mut d = crate::arch::x86_64::serial::DirectUart;
            let _ = writeln!(
                d,
                "DOUBLE FAULT (#DF): RIP={:#x} RSP={:#x} CR2={:#x} tid={} error={:#x}",
                frame.rip(), frame.rsp(), cr2, tid, frame.error_code()
            );
            let _ = writeln!(
                d,
                "  RAX={:#x} RBX={:#x} RCX={:#x} RDX={:#x}",
                frame.rax(), frame.rbx(), frame.rcx(), frame.rdx()
            );
            let _ = writeln!(
                d,
                "  RSI={:#x} RDI={:#x} RBP={:#x} CS={:#x} SS={:#x}",
                frame.rsi(), frame.rdi(), frame.rbp(), frame.cs(), frame.ss()
            );
            let tref = crate::sched::scheduler::thread_ref(tid);
            let _ = writeln!(
                d,
                "  task={} saved_sp={:#x} kstack={:#x} personality_frame_sp={:#x}",
                tref.task_id, tref.saved_sp, tref.stack_base,
                tref.personality_frame_sp
            );
            tref.killed.store(true, core::sync::atomic::Ordering::Release);
            crate::arch::irq::enable();
            loop { core::hint::spin_loop(); }
        }
        10 => exception_fault("Invalid TSS (#TS)", frame),
        11 => exception_fault("Segment Not Present (#NP)", frame),
        12 => exception_fault("Stack Segment (#SS)", frame),
        13 => exception_fault("General Protection (#GP)", frame),
        14 => {
            return handle_page_fault_x86(frame, frame_sp);
        }
        16 => exception_fault("x87 FP Exception (#MF)", frame),
        17 => exception_fault("Alignment Check (#AC)", frame),
        18 => exception_fault("Machine Check (#MC)", frame),
        19 => exception_fault("SIMD FP Exception (#XM)", frame),

        // Timer (PIT IRQ 0 -> vector 32, or LAPIC timer -> vector 32).
        32 => {
            super::timer::handle_timer_irq();
            super::lapic::eoi();
            super::pic::send_eoi(0);
            // #135 LAPIC probe: snapshot AFTER EOI so vector 32's own
            // ISR bit (priority class 2 ⇒ PPR=0x20) doesn't pollute
            // readings.  Post-EOI, the snapshot reveals any OTHER stuck
            // ISR / pending IRR that would block vector 0xFD.
            super::lapic::snapshot_state_to_pcpu();
            return validate_iretq_frame(crate::sched::tick(frame_sp), frame_sp, 32);
        }

        // Syscall via int 0x80.
        0x80 => {
            crate::sched::scheduler::store_frame_sp(frame_sp);
            crate::arch::irq::enable();
            crate::syscall::dispatch(frame);
            let _ = crate::arch::irq::disable();
            crate::sched::scheduler::check_preempt_on_return();
            let pending = crate::sched::scheduler::take_pending_switch();
            if pending != 0 {
                return validate_iretq_frame(pending, frame_sp, 0x80);
            }
            return validate_iretq_frame(frame_sp, frame_sp, 0x80);
        }

        // Reschedule IPI (vector 0xFD). Sent by a remote CPU when it
        // enqueues a thread on our run queue while we are idle.  Only
        // runs try_switch() — no tick accounting, no timer reprogramming.
        0xFD => {
            super::lapic::IPI_RECV_COUNT
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            // #135 per-CPU IPI recv counter — combined with per-CPU
            // dispatch_count, exposes "IPI arrives but try_switch
            // doesn't dispatch" — the suspected on_cpu / pick-side
            // failure mode for the boot variability.
            {
                let cpu = crate::sched::smp::cpu_id();
                let pcpu = crate::sched::smp::get(cpu);
                pcpu.ipi_recv_count
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                // Layer 4 paravirt: stamp recv timestamp + Stage-1
                // adaptive EWMA of inter-arrival mean and MAD for the
                // per-CPU IPI-staleness threshold in
                // choose_wake_target_steal_aware.
                let now_ns = crate::sched::scheduler::get_monotonic_ns();
                let last = pcpu
                    .last_ipi_recv_ns
                    .load(core::sync::atomic::Ordering::Relaxed);
                pcpu.last_ipi_recv_ns
                    .store(now_ns, core::sync::atomic::Ordering::Relaxed);
                if last != 0 && now_ns > last {
                    let dt = now_ns - last;
                    let mean = pcpu
                        .ipi_interarrival_mean_ns
                        .load(core::sync::atomic::Ordering::Relaxed);
                    let mad = pcpu
                        .ipi_interarrival_mad_ns
                        .load(core::sync::atomic::Ordering::Relaxed);
                    // Outlier clamp: if a host pause produced a huge dt,
                    // don't let it poison the baseline.  Cap dt at
                    // mean + 16·MAD before incorporating into the EWMA.
                    // Use a small floor for the first ~16 samples when
                    // mean+MAD is still close to zero.
                    let clamp_ceiling = mean
                        .saturating_add(mad.saturating_mul(16))
                        .max(1_000_000);
                    let dt_clipped = dt.min(clamp_ceiling);
                    // EWMA: mean += (dt_clipped - mean) / 16
                    // Signed subtraction handled by branching.
                    let new_mean = if dt_clipped >= mean {
                        mean + (dt_clipped - mean) / 16
                    } else {
                        mean - (mean - dt_clipped) / 16
                    };
                    // MAD: mad += (|dt_clipped - new_mean| - mad) / 16
                    let abs_dev = if dt_clipped >= new_mean {
                        dt_clipped - new_mean
                    } else {
                        new_mean - dt_clipped
                    };
                    let new_mad = if abs_dev >= mad {
                        mad + (abs_dev - mad) / 16
                    } else {
                        mad - (mad - abs_dev) / 16
                    };
                    pcpu.ipi_interarrival_mean_ns
                        .store(new_mean, core::sync::atomic::Ordering::Relaxed);
                    pcpu.ipi_interarrival_mad_ns
                        .store(new_mad, core::sync::atomic::Ordering::Relaxed);
                }
            }
            super::lapic::eoi();
            return validate_iretq_frame(crate::sched::scheduler::reschedule_ipi(frame_sp), frame_sp, 0xFD);
        }

        // Other IRQs (33-47).
        33..=47 => {
            let irq = (vector - 32) as u8;
            if !crate::io::irq_dispatch::handle_irq(irq as u32) {
                crate::println!("Unhandled IRQ {}", irq);
            }
            if super::ioapic::available() {
                super::lapic::eoi();
            } else {
                super::pic::send_eoi(irq);
            }
        }

        _ => {
            crate::println!("Unhandled interrupt vector {}", vector);
        }
    }

    validate_iretq_frame(frame_sp, frame_sp, vector)
}

// ---------------------------------------------------------------------------
// Async-PF (Layer 3 paravirt)
// ---------------------------------------------------------------------------

/// Counts async-PF events received from the host (sum of NOT_PRESENT
/// + PAGE_READY).  Non-zero indicates the host is actually using
/// async-PF — i.e. memory is being swapped out and the host wants
/// the guest to dispatch around the faulting thread instead of
/// blocking the vCPU.  In CPU-pressure-only scenarios this stays 0.
static ASYNC_PF_EVENTS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Fixed-size map from async-PF token → parked tid.  Tokens are
/// 32-bit host-assigned identifiers; we never look at more than ~16
/// at once in practice (one per outstanding swap-in).  Linear scan
/// is fine for that scale.  Slot value: low 32 = tid, high 32 = token.
/// A slot with token == 0 is empty (host never uses token 0).
const APF_MAP_SLOTS: usize = 64;
static APF_MAP: [core::sync::atomic::AtomicU64; APF_MAP_SLOTS] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; APF_MAP_SLOTS]
};

fn async_pf_insert(token: u32, tid: u32) -> bool {
    use core::sync::atomic::Ordering;
    let want_empty: u64 = 0;
    let new_entry: u64 = (tid as u64) | ((token as u64) << 32);
    for slot in APF_MAP.iter() {
        if slot.compare_exchange(
            want_empty, new_entry,
            Ordering::AcqRel, Ordering::Relaxed,
        ).is_ok() {
            return true;
        }
    }
    false
}

fn async_pf_remove(token: u32) -> Option<u32> {
    use core::sync::atomic::Ordering;
    for slot in APF_MAP.iter() {
        let v = slot.load(Ordering::Acquire);
        let entry_tok = (v >> 32) as u32;
        if entry_tok == token && v != 0 {
            // Try to claim by CASing to 0.
            if slot.compare_exchange(
                v, 0,
                Ordering::AcqRel, Ordering::Relaxed,
            ).is_ok() {
                return Some(v as u32);
            }
            // Lost the race — another waker took it.
        }
    }
    None
}

/// Park the current thread on `token`.  Called from the #PF handler
/// when the host posted KVM_PV_REASON_PAGE_NOT_PRESENT.  Falls back
/// to immediately retrying the fault if the map is full (rare).
fn async_pf_park(token: u32) {
    let tid = crate::sched::current_thread_id();
    if !async_pf_insert(token, tid) {
        // Map full — fall back to no-op.  The thread will refault
        // and either the host's normal sync-PF path eventually
        // delivers, or the next async-PF event reuses the map.
        return;
    }
    // Block on a generic pager-wait.  When PAGE_READY arrives,
    // async_pf_wake removes the entry and wake_thread runs.
    crate::sched::block_current(crate::sched::thread::BlockReason::PagerWait);
}

/// Wake the thread parked on `token`, if any.
fn async_pf_wake(token: u32) {
    if let Some(tid) = async_pf_remove(token) {
        crate::sched::scheduler::wake_thread(tid);
    }
}

/// Diagnostic export.
pub fn async_pf_event_count() -> u64 {
    ASYNC_PF_EVENTS.load(core::sync::atomic::Ordering::Relaxed)
}

fn handle_page_fault_x86(frame: &ExceptionFrame, frame_sp: u64) -> u64 {
    // Layer 3 paravirt: KVM async-PF dispatch.  Before normal fault
    // handling, check whether the host posted an async-PF event for
    // this CPU.  If reason == NOT_PRESENT the host has started a swap-in
    // (or similar) for the faulting page; park the thread on its token
    // so the vCPU can run other work.  If reason == PAGE_READY the
    // swap-in completed; wake the thread that was parked on that token.
    if let Some((reason, token)) = crate::arch::x86_64::hypervisor::take_async_pf_event() {
        ASYNC_PF_EVENTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        match reason {
            crate::arch::x86_64::hypervisor::ASYNC_PF_REASON_NOT_PRESENT => {
                // Park the current thread on this token.  Will be woken
                // when the matching PAGE_READY arrives.  block_current
                // performs the dispatch internally.
                async_pf_park(token);
                // We return — block_current rescheduled.  frame_sp is
                // updated via the existing pending-switch mechanism.
                let pending = crate::sched::scheduler::take_pending_switch();
                return if pending != 0 { pending } else { frame_sp };
            }
            crate::arch::x86_64::hypervisor::ASYNC_PF_REASON_PAGE_READY => {
                async_pf_wake(token);
                // Falls through to retry the faulting instruction —
                // the page may already be present from the perspective
                // of the next CPU access, but we still need to return
                // from the trap.  CR2 holds either the original faulting
                // VA or a synthetic value; either way the IRETQ returns
                // to the same RIP which will re-fault if needed.
                return frame_sp;
            }
            _ => {
                // Unknown reason — ack via take_async_pf_event already,
                // fall through to normal PF handling.
            }
        }
    }

    let cr2: u64;
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) cr2);
    }
    let error = frame.error_code();
    // Error code bits: bit 0 = P (present), bit 1 = W/R, bit 2 = U/S, bit 4 = I/D.
    let fault_type = if error & (1 << 4) != 0 {
        crate::mm::fault::FaultType::Exec
    } else if error & (1 << 1) != 0 {
        crate::mm::fault::FaultType::Write
    } else {
        crate::mm::fault::FaultType::Read
    };
    let is_user = (error & (1 << 2)) != 0;
    if !is_user {
        let cr3: u64;
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)); }
        let cpu = crate::sched::smp::cpu_id();
        // Walk the PT chain for CR2 to identify which level is missing.
        // Bit-level breakdown of the 4 levels of pointers.
        let cr3_pa = (cr3 & !0xFFF) as usize;
        let pml4_e = unsafe { *((cr3_pa + ((cr2 >> 39) & 0x1FF) as usize * 8) as *const u64) };
        let pdpt_e = if pml4_e & 1 != 0 {
            let pdpt_pa = (pml4_e & 0x000F_FFFF_FFFF_F000) as usize;
            unsafe { *((pdpt_pa + ((cr2 >> 30) & 0x1FF) as usize * 8) as *const u64) }
        } else { 0 };
        let pd_e = if pdpt_e & 1 != 0 {
            let pd_pa = (pdpt_e & 0x000F_FFFF_FFFF_F000) as usize;
            unsafe { *((pd_pa + ((cr2 >> 21) & 0x1FF) as usize * 8) as *const u64) }
        } else { 0 };
        let pt_e = if pd_e & 1 != 0 {
            let pt_pa = (pd_e & 0x000F_FFFF_FFFF_F000) as usize;
            unsafe { *((pt_pa + ((cr2 >> 12) & 0x1FF) as usize * 8) as *const u64) }
        } else { 0 };
        // Stack-content snapshot: read 16 quads at and below rsp.  For
        // the wild-RIP-in-kstack pattern (boots 1690/1691), the saved
        // return address that was popped lives at `*(rsp - 8)` from the
        // perspective of the ret that jumped wild.  Walk *up* from the
        // current rsp to find it.  Stops on first non-kstack quad
        // (heuristic: address with high bits not 0xfffffe...) to avoid
        // dereferencing wild pointers.
        let rsp = frame.rsp();
        let mut stack_words: [u64; 16] = [0; 16];
        for i in 0..16 {
            let addr = rsp.wrapping_add((i as u64) * 8);
            // Only read if addr is in a plausible kstack range
            // (PML4[508] = 0xfffffe0000000000..0xfffffe7fffffffff).
            if (addr & 0xffffff8000000000) == 0xfffffe0000000000 {
                stack_words[i] = unsafe { *(addr as *const u64) };
            } else {
                stack_words[i] = 0xdeadbeefcafef00d;
                break;
            }
        }
        // Also read 8 quads BELOW rsp (recently-popped slots).  After a
        // `ret`, the popped RIP value lives at `*(rsp - 8)` until the
        // next push overwrites it.  Wild-RIP-via-ret crashes leave that
        // signature here.
        let mut stack_words_below: [u64; 8] = [0; 8];
        for i in 0..8 {
            let addr = rsp.wrapping_sub(((i + 1) as u64) * 8);
            if (addr & 0xffffff8000000000) == 0xfffffe0000000000 {
                stack_words_below[i] = unsafe { *(addr as *const u64) };
            } else {
                stack_words_below[i] = 0xdeadbeefcafef00d;
            }
        }
        // Walk the RBP chain up to 6 frames.  Each frame's saved RIP is
        // at `*(rbp + 8)`, the previous RBP is at `*rbp`.  Stops on
        // non-kstack or null RBP.
        let mut backtrace: [u64; 6] = [0; 6];
        let mut bp = frame.rbp();
        for slot in backtrace.iter_mut() {
            if (bp & 0xffffff8000000000) != 0xfffffe0000000000 || bp == 0 {
                *slot = 0;
                break;
            }
            let saved_rip_addr = bp + 8;
            *slot = unsafe { *(saved_rip_addr as *const u64) };
            // Next RBP
            bp = unsafe { *(bp as *const u64) };
        }

        // Use dump_atomic! — holds PRINT_LOCK across the whole emit so
        // other CPUs' prints cannot interleave (regular println! showed
        // mid-dump truncation in boot 1786 even with a coalesced single
        // call; bytes from peer CPUs appeared after ~250 bytes of cpu=1's
        // dump despite the lock).
        crate::dump_atomic!(
"Kernel #PF at RIP={:#x} CR2={:#x} error={:#x} cpu={} cr3={:#x} pml4_e={:#x} pdpt_e={:#x} pd_e={:#x} pt_e={:#x}
  rsp={:#x} rbp={:#x} cs={:#x} ss={:#x} rflags={:#x}
  rax={:#x} rbx={:#x} rcx={:#x} rdx={:#x}
  rsi={:#x} rdi={:#x} r8={:#x} r9={:#x}
  r10={:#x} r11={:#x} r12={:#x} r13={:#x}
  r14={:#x} r15={:#x}
  stk[0..4]={:#x} {:#x} {:#x} {:#x}
  stk[4..8]={:#x} {:#x} {:#x} {:#x}
  stk[8..12]={:#x} {:#x} {:#x} {:#x}
  stk[12..16]={:#x} {:#x} {:#x} {:#x}
  below[1..4]={:#x} {:#x} {:#x} {:#x}
  below[5..8]={:#x} {:#x} {:#x} {:#x}
  backtrace={:#x} {:#x} {:#x} {:#x} {:#x} {:#x}",
            frame.rip(), cr2, error, cpu, cr3, pml4_e, pdpt_e, pd_e, pt_e,
            frame.rsp(), frame.rbp(), frame.cs(), frame.ss(), frame.rflags(),
            frame.rax(), frame.rbx(), frame.rcx(), frame.rdx(),
            frame.rsi(), frame.rdi(), frame.r8(), frame.r9(),
            frame.r10(), frame.r11(), frame.r12(), frame.r13(),
            frame.r14(), frame.r15(),
            stack_words[0], stack_words[1], stack_words[2], stack_words[3],
            stack_words[4], stack_words[5], stack_words[6], stack_words[7],
            stack_words[8], stack_words[9], stack_words[10], stack_words[11],
            stack_words[12], stack_words[13], stack_words[14], stack_words[15],
            stack_words_below[0], stack_words_below[1], stack_words_below[2], stack_words_below[3],
            stack_words_below[4], stack_words_below[5], stack_words_below[6], stack_words_below[7],
            backtrace[0], backtrace[1], backtrace[2], backtrace[3], backtrace[4], backtrace[5],
        );
        loop {
            core::hint::spin_loop();
        }
    }
    let aspace_id = crate::sched::current_aspace_id();
    if aspace_id == 0 {
        crate::println!(
            "User #PF with no address space: CR2={:#x} RIP={:#x}",
            cr2,
            frame.rip()
        );
        loop {
            core::hint::spin_loop();
        }
    }
    let result = crate::mm::fault::handle_page_fault(aspace_id, cr2 as usize, fault_type);
    match result {
        crate::mm::fault::FaultResult::NeedPager { token } => {
            crate::sched::scheduler::store_frame_sp(frame_sp);
            crate::mm::pager::initiate_fault(token);
            let pending = crate::sched::scheduler::take_pending_switch();
            return if pending != 0 { pending } else { frame_sp };
        }
        crate::mm::fault::FaultResult::Failed => {
            crate::println!(
                "Unhandled #PF: CR2={:#x} RIP={:#x} RSP={:#x} error={:#x} tid={} task={}",
                cr2,
                frame.rip(),
                frame.rsp(),
                error,
                crate::sched::scheduler::current_thread_id(),
                crate::sched::scheduler::thread_ref(crate::sched::scheduler::current_thread_id()).task_id,
            );
            // Tier-3 core dump for unhandled user-space page faults.
            // Vector 14 = #PF.
            crate::arch::x86_64::coredump::dump_user_fault(frame, 14);
            // Stack snapshot + RBP chain walk — same shape as
            // exception_fault's enhanced dump.  Pair RIPs with
            // [lib-load] entries to resolve via addr2line.
            let rsp = frame.rsp();
            let mut sw = [0u64; 8];
            for i in 0..8 {
                sw[i] = crate::arch::x86_64::coredump::safe_read_user_u64(
                    rsp.wrapping_add((i * 8) as u64),
                ).unwrap_or(0);
            }
            crate::println!(
                "  STACK[0..8]@RSP: {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}",
                sw[0], sw[1], sw[2], sw[3], sw[4], sw[5], sw[6], sw[7]
            );
            let mut rbp = frame.rbp();
            for f in 0..6 {
                if rbp < 0x1000 { break; }
                let saved_rbp = match crate::arch::x86_64::coredump::safe_read_user_u64(rbp) {
                    Some(v) => v, None => break,
                };
                let saved_rip = match crate::arch::x86_64::coredump::safe_read_user_u64(rbp.wrapping_add(8)) {
                    Some(v) => v, None => break,
                };
                crate::println!(
                    "  FRAME[{}]: rbp={:#x} caller_rip={:#x}",
                    f, saved_rbp, saved_rip
                );
                if saved_rbp == 0 || saved_rbp <= rbp { break; }
                rbp = saved_rbp;
            }
            crate::sched::scheduler::exit_current_thread(-11); // SIGSEGV
        }
        _ => {}
    }
    frame_sp
}

/// Handle a CPU exception. For userspace faults, kill the thread so the CPU
/// can continue running other threads. For kernel faults, halt (fatal).
fn exception_fault(name: &str, frame: &ExceptionFrame) -> ! {
    let is_user = (frame.cs() & 3) == 3;
    // Coalesced atomic dump — peer CPUs cannot interleave this block.
    crate::dump_atomic!(
        "EXCEPTION: {} at RIP={:#x} error_code={:#x} tid={} {}\n\
         \x20 RAX={:#x} RBX={:#x} RCX={:#x} RDX={:#x}\n\
         \x20 RSP={:#x} RBP={:#x} RSI={:#x} RDI={:#x}\n\
         \x20 CS={:#x} RFLAGS={:#x} SS={:#x}",
        name,
        frame.rip(), frame.error_code(),
        crate::sched::scheduler::current_thread_id(),
        if is_user { "(user)" } else { "(KERNEL)" },
        frame.rax(), frame.rbx(), frame.rcx(), frame.rdx(),
        frame.rsp(), frame.rbp(), frame.rsi(), frame.rdi(),
        frame.cs(), frame.rflags(), frame.ss(),
    );
    // Kernel-fault stack dump: 16 quads from RSP.  At #UD time, an indirect
    // call through a corrupted function pointer has just pushed its return
    // address (the instruction after the bad `call *reg`) to [RSP], then
    // jumped to the bad target — which faults here.  So [RSP] reveals the
    // call site that dispatched to RIP={0,3,7,…}.  Bounds-check RSP first
    // because reads through a bogus pointer would triple-fault.
    if !is_user {
        let rsp = frame.rsp();
        if rsp != 0 && (rsp & 7) == 0 && rsp < 0x8000_0000 {
            let mut sw = [0u64; 16];
            unsafe {
                for i in 0..16 {
                    let p = rsp.wrapping_add((i * 8) as u64) as *const u64;
                    sw[i] = core::ptr::read_volatile(p);
                }
            }
            for row in 0..2 {
                let b = row * 8;
                crate::println!(
                    "  KSTACK[{}..{}]@RSP+{:#x}: {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}",
                    b, b + 8, (b * 8) as u64,
                    sw[b], sw[b+1], sw[b+2], sw[b+3],
                    sw[b+4], sw[b+5], sw[b+6], sw[b+7]
                );
            }
            // Also walk the RBP chain if RBP is sane.  Each frame layout
            // (SysV AMD64): [RBP] = caller RBP, [RBP+8] = caller RIP.
            let mut rbp = frame.rbp();
            for f in 0..6 {
                if rbp < 0x1000 || (rbp & 7) != 0 || rbp >= 0x8000_0000 {
                    break;
                }
                let saved_rbp = unsafe { core::ptr::read_volatile(rbp as *const u64) };
                let saved_rip = unsafe {
                    core::ptr::read_volatile(rbp.wrapping_add(8) as *const u64)
                };
                crate::println!(
                    "  KFRAME[{}]: rbp={:#x} caller_rip={:#x}",
                    f, saved_rbp, saved_rip
                );
                if saved_rbp == 0 || saved_rbp <= rbp {
                    break;
                }
                rbp = saved_rbp;
            }
        } else {
            crate::println!(
                "  KSTACK skipped: RSP={:#x} out of kernel range / misaligned",
                rsp
            );
        }
    }
    if is_user {
        // Tier-3 core dump: emit machine-readable register +
        // stack-page block to the debug log.  Host script
        // tools/extract-core.py reconstructs an ELF64 core file
        // from these markers + the [lib-load] log lines.
        crate::arch::x86_64::coredump::dump_user_fault(frame, frame.vector());
        // Stack snapshot: 256 bytes (32 u64s) at RSP.  Wide enough to
        // cover the saved return address that pushed the faulting RIP
        // (typically at RBP+8, often well above RSP for ret-faults) plus
        // surrounding spill slots.  Faults here would re-fault the
        // thread (which we're killing anyway), so reads are best-effort.
        let rsp = frame.rsp();
        let mut sw = [0u64; 32];
        for i in 0..32 {
            sw[i] = crate::arch::x86_64::coredump::safe_read_user_u64(
                rsp.wrapping_add((i * 8) as u64),
            ).unwrap_or(0);
        }
        for row in 0..4 {
            let b = row * 8;
            crate::println!(
                "  STACK[{}..{}]@RSP+{:#x}: {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}",
                b, b + 8, (b * 8) as u64,
                sw[b], sw[b+1], sw[b+2], sw[b+3],
                sw[b+4], sw[b+5], sw[b+6], sw[b+7]
            );
        }
        // Code-pointer scan: walk one 4 KiB page above RSP and print every
        // qword that falls into a plausible user-text range.  The pre-fault
        // call chain emerges as a sparse list of code pointers; noise
        // (heap data, FP bit-patterns, etc.) drops out.  The 0x4xxx_xxxxx
        // range matches Telix's standard libc / Xwayland load addresses.
        // Output format: `CODE@<offset_above_rsp>: <pointer>` so the host
        // can resolve via addr2line / objdump.
        let mut printed = 0u32;
        for i in 32..512 { // already printed 0..32 above
            let v = match crate::arch::x86_64::coredump::safe_read_user_u64(
                rsp.wrapping_add((i * 8) as u64),
            ) { Some(v) => v, None => break };
            // Plausible user code: top 32 bits == 0x4 OR == 0x2 (Telix
            // userspace text typically lives in 0x100000000..0x500000000).
            let hi = v >> 32;
            if hi == 0x4 || hi == 0x2 || hi == 0x1 {
                crate::println!("  CODE@RSP+{:#x}: {:#x}", (i * 8) as u64, v);
                printed += 1;
                if printed >= 16 { break; } // cap to avoid log flood
            }
        }
        // RBP chain walk: print the saved-RIP at each frame for up
        // to 6 frames.  Each frame's layout (per System V AMD64):
        //   [RBP]      = caller's RBP
        //   [RBP + 8]  = caller's saved RIP (return address)
        // Pair these RIPs with the [lib-load] log lines emitted by
        // linux_srv to map them to function names via addr2line.
        let mut rbp = frame.rbp();
        for f in 0..6 {
            if rbp < 0x1000 {
                break;
            }
            let saved_rbp = match crate::arch::x86_64::coredump::safe_read_user_u64(rbp) {
                Some(v) => v, None => break,
            };
            let saved_rip = match crate::arch::x86_64::coredump::safe_read_user_u64(rbp.wrapping_add(8)) {
                Some(v) => v, None => break,
            };
            crate::println!(
                "  FRAME[{}]: rbp={:#x} caller_rip={:#x}",
                f, saved_rbp, saved_rip
            );
            // Stop if RBP didn't decrease (corrupted chain or top of stack).
            if saved_rbp == 0 || saved_rbp <= rbp {
                break;
            }
            rbp = saved_rbp;
        }
        // Kill the faulting thread so the CPU can continue running others.
        // Signal number: SIGILL(4) for #UD, SIGSEGV(11) for #GP/#SS, etc.
        crate::sched::scheduler::exit_current_thread(-11);
    }
    // Mark the current thread as killed so the scheduler won't re-run it,
    // then spin with interrupts enabled so the timer can switch us off.
    let tid = crate::sched::scheduler::current_thread_id();
    if tid != 0 {
        crate::sched::scheduler::thread_ref(tid)
            .killed
            .store(true, core::sync::atomic::Ordering::Release);
    }
    crate::arch::irq::enable();
    loop {
        core::hint::spin_loop();
    }
}
