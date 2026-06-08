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
// #208 Pattern A sweep: module-level put_* helpers used by atomic-emit
// dump paths that must avoid `format_args!()` — the macro's temporary
// Argument array gets placed by the optimizer at slots that overlap
// the caller's locals, surfacing as the recurring print-then-deref
// kernel-text #PF family.  These helpers take a stack-local buffer +
// index by mut ref, write ASCII, and the caller emits via
// `serial::handler_write_bytes` (atomic per-call, no format_args).

#[inline]
fn put_byte(buf: &mut [u8], n: &mut usize, b: u8) {
    if *n < buf.len() { buf[*n] = b; *n += 1; }
}
#[inline]
fn put_bytes(buf: &mut [u8], n: &mut usize, s: &[u8]) {
    for &b in s { put_byte(buf, n, b); }
}
#[inline]
fn put_hex_u64(buf: &mut [u8], n: &mut usize, mut v: u64) {
    put_bytes(buf, n, b"0x");
    if v == 0 { put_byte(buf, n, b'0'); return; }
    let mut digits = [0u8; 16];
    let mut k = 0;
    while v > 0 {
        let d = (v & 0xf) as u8;
        digits[k] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
        v >>= 4;
        k += 1;
    }
    for i in (0..k).rev() { put_byte(buf, n, digits[i]); }
}
#[inline]
fn put_dec_u64(buf: &mut [u8], n: &mut usize, mut v: u64) {
    if v == 0 { put_byte(buf, n, b'0'); return; }
    let mut digits = [0u8; 20];
    let mut k = 0;
    while v > 0 {
        digits[k] = b'0' + (v % 10) as u8;
        v /= 10;
        k += 1;
    }
    for i in (0..k).rev() { put_byte(buf, n, digits[i]); }
}
#[inline]
fn put_hex_018(buf: &mut [u8], n: &mut usize, v: u64) {
    // 0x + 16-nibble zero-padded — matches `{:#018x}`.
    put_bytes(buf, n, b"0x");
    for shift in (0..16).rev() {
        let d = ((v >> (shift * 4)) & 0xf) as u8;
        let c = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
        put_byte(buf, n, c);
    }
}

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
            // #208 Pattern A sweep: atomic put_* emit (no format_args)
            // — the prior println! had 27 args and was a prime
            // collision candidate.  Split into three handler_write_bytes
            // calls to keep each stack buffer small.
            let cpu = crate::sched::smp::cpu_id();
            {
                let mut buf = [0u8; 256];
                let mut n = 0;
                put_bytes(&mut buf, &mut n, b"VALIDATOR-PRE-BAD: tid=");
                put_dec_u64(&mut buf, &mut n, tid as u64);
                put_bytes(&mut buf, &mut n, b" cpu=");
                put_dec_u64(&mut buf, &mut n, cpu as u64);
                put_bytes(&mut buf, &mut n, b" sp=");
                put_hex_u64(&mut buf, &mut n, sp);
                put_bytes(&mut buf, &mut n, b" vec=");
                put_dec_u64(&mut buf, &mut n, vector);
                put_bytes(&mut buf, &mut n, b" pre_rsp=");
                put_hex_u64(&mut buf, &mut n, pre_rsp);
                put_bytes(&mut buf, &mut n, b" stack_base=");
                put_hex_u64(&mut buf, &mut n, tref.stack_base as u64);
                put_bytes(&mut buf, &mut n, b" saved_sp_now=");
                put_hex_u64(&mut buf, &mut n, tref.saved_sp);
                put_bytes(&mut buf, &mut n, b" saved_sp_source=");
                put_dec_u64(&mut buf, &mut n, tref.saved_sp_source as u64);
                put_byte(&mut buf, &mut n, b'\n');
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
            }
            {
                let mut buf = [0u8; 256];
                let mut n = 0;
                put_bytes(&mut buf, &mut n, b"  pre.rip=");
                put_hex_u64(&mut buf, &mut n, pre_snap_all[5]);
                put_bytes(&mut buf, &mut n, b" pre.cs=");
                put_hex_u64(&mut buf, &mut n, pre_snap_all[6]);
                put_bytes(&mut buf, &mut n, b" pre.rflags=");
                put_hex_u64(&mut buf, &mut n, pre_snap_all[7]);
                put_bytes(&mut buf, &mut n, b" pre.rsp=");
                put_hex_u64(&mut buf, &mut n, pre_snap_all[8]);
                put_bytes(&mut buf, &mut n, b" pre.ss=");
                put_hex_u64(&mut buf, &mut n, pre_snap_all[4]);
                put_bytes(&mut buf, &mut n, b" pre_below=[");
                put_hex_u64(&mut buf, &mut n, pre_snap_all[0]); put_byte(&mut buf, &mut n, b' ');
                put_hex_u64(&mut buf, &mut n, pre_snap_all[1]); put_byte(&mut buf, &mut n, b' ');
                put_hex_u64(&mut buf, &mut n, pre_snap_all[2]); put_byte(&mut buf, &mut n, b' ');
                put_hex_u64(&mut buf, &mut n, pre_snap_all[3]);
                put_bytes(&mut buf, &mut n, b"] pre_above=[");
                put_hex_u64(&mut buf, &mut n, pre_snap_all[9]); put_byte(&mut buf, &mut n, b' ');
                put_hex_u64(&mut buf, &mut n, pre_snap_all[10]); put_byte(&mut buf, &mut n, b' ');
                put_hex_u64(&mut buf, &mut n, pre_snap_all[11]); put_byte(&mut buf, &mut n, b' ');
                put_hex_u64(&mut buf, &mut n, pre_snap_all[12]);
                put_bytes(&mut buf, &mut n, b"]\n");
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
            }
            {
                let mut buf = [0u8; 256];
                let mut n = 0;
                put_bytes(&mut buf, &mut n, b"  shadow.sp=");
                put_hex_u64(&mut buf, &mut n, tref.iretq_shadow_sp);
                put_bytes(&mut buf, &mut n, b" shadow.rip=");
                put_hex_u64(&mut buf, &mut n, tref.iretq_shadow_rip);
                put_bytes(&mut buf, &mut n, b" shadow.cs=");
                put_hex_u64(&mut buf, &mut n, tref.iretq_shadow_cs);
                put_bytes(&mut buf, &mut n, b" shadow.rflags=");
                put_hex_u64(&mut buf, &mut n, tref.iretq_shadow_rflags);
                put_bytes(&mut buf, &mut n, b" shadow.rsp=");
                put_hex_u64(&mut buf, &mut n, tref.iretq_shadow_rsp);
                put_bytes(&mut buf, &mut n, b" shadow.ss=");
                put_hex_u64(&mut buf, &mut n, tref.iretq_shadow_ss);
                put_byte(&mut buf, &mut n, b'\n');
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
            }
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
                    // #208 family: a corrupted iretq frame can carry user CS
                    // even on a kernel task whose pt_root is 0.  Skipping the
                    // peek there avoids falling into copy_from_user's
                    // "kernel thread, direct deref" path, which would
                    // re-fault on the user RIP and add noise to the PF
                    // record we're already trying to diagnose.
                    let ok = if pt_root == 0 {
                        false
                    } else {
                        crate::syscall::handlers::copy_from_user(
                            pt_root, rip as usize, &mut bytes,
                        )
                    };
                    let all_zero = bytes.iter().all(|&b| b == 0);
                    // #208 Pattern A sweep: 19-arg println! → atomic put_*.
                    let cpu = crate::sched::smp::cpu_id();
                    let ss = frame_peek.ss();
                    let rax_v = frame_peek.rax();
                    let rsp_v = frame_peek.rsp();
                    let mut buf = [0u8; 256];
                    let mut n = 0;
                    put_bytes(&mut buf, &mut n, b"FIRST-IRETQ-USER: tid=");
                    put_dec_u64(&mut buf, &mut n, tid as u64);
                    put_bytes(&mut buf, &mut n, b" cpu=");
                    put_dec_u64(&mut buf, &mut n, cpu as u64);
                    put_bytes(&mut buf, &mut n, b" vec=");
                    put_dec_u64(&mut buf, &mut n, vector);
                    put_bytes(&mut buf, &mut n, b" sp=");
                    put_hex_u64(&mut buf, &mut n, sp);
                    put_bytes(&mut buf, &mut n, b" rip=");
                    put_hex_u64(&mut buf, &mut n, rip);
                    put_bytes(&mut buf, &mut n, b" cs=");
                    put_hex_u64(&mut buf, &mut n, cs_peek);
                    put_bytes(&mut buf, &mut n, b" ss=");
                    put_hex_u64(&mut buf, &mut n, ss);
                    put_bytes(&mut buf, &mut n, b" rax=");
                    put_hex_u64(&mut buf, &mut n, rax_v);
                    put_bytes(&mut buf, &mut n, b" rsp=");
                    put_hex_u64(&mut buf, &mut n, rsp_v);
                    put_bytes(&mut buf, &mut n, b" rip_bytes_ok=");
                    put_bytes(&mut buf, &mut n, if ok { b"1" } else { b"0" });
                    put_bytes(&mut buf, &mut n, b" rip_bytes_zero=");
                    put_bytes(&mut buf, &mut n, if all_zero { b"1" } else { b"0" });
                    put_bytes(&mut buf, &mut n, b" rip_bytes=[");
                    for i in 0..8 {
                        if i > 0 { put_byte(&mut buf, &mut n, b' '); }
                        let b = bytes[i];
                        // 2-digit hex (no 0x).
                        let hi = (b >> 4) & 0xF;
                        let lo = b & 0xF;
                        put_byte(&mut buf, &mut n,
                            if hi < 10 { b'0' + hi } else { b'a' + (hi - 10) });
                        put_byte(&mut buf, &mut n,
                            if lo < 10 { b'0' + lo } else { b'a' + (lo - 10) });
                    }
                    put_bytes(&mut buf, &mut n, b"]\n");
                    crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
                }
            }
        }
    }
    // Absolute minimum: no valid kstack frame can be below 64K — catch
    // saved_sp=0 or any pointer into the real-mode IVT / BIOS data area.
    if sp < 0x10000 {
        let tid = crate::sched::scheduler::current_thread_id();
        // #208 Pattern A sweep: atomic put_*.
        let mut buf = [0u8; 96];
        let mut n = 0;
        put_bytes(&mut buf, &mut n, b"BAD frame: sp=");
        put_hex_u64(&mut buf, &mut n, sp);
        put_bytes(&mut buf, &mut n, b" (below 64K) vec=");
        put_dec_u64(&mut buf, &mut n, vector);
        put_bytes(&mut buf, &mut n, b" tid=");
        put_dec_u64(&mut buf, &mut n, tid as u64);
        put_byte(&mut buf, &mut n, b'\n');
        crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
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
            // #208 Pattern A sweep: 33-arg println! → atomic put_*
            // emit, chunked into 4 lines (header, pre, mid1, post).
            let cpu = crate::sched::smp::cpu_id();
            {
                let mut buf = [0u8; 256];
                let mut n = 0;
                put_bytes(&mut buf, &mut n, b"VALIDATOR-SELF-SCRIBBLE: tid=");
                put_dec_u64(&mut buf, &mut n, tid as u64);
                put_bytes(&mut buf, &mut n, b" cpu=");
                put_dec_u64(&mut buf, &mut n, cpu as u64);
                put_bytes(&mut buf, &mut n, b" sp=");
                put_hex_u64(&mut buf, &mut n, sp);
                put_bytes(&mut buf, &mut n, b" vec=");
                put_dec_u64(&mut buf, &mut n, vector);
                put_bytes(&mut buf, &mut n, b" pre_rsp=");
                put_hex_u64(&mut buf, &mut n, pre_rsp);
                put_bytes(&mut buf, &mut n, b" mid1_rsp=");
                put_hex_u64(&mut buf, &mut n, mid1_rsp);
                put_bytes(&mut buf, &mut n, b" post_rsp=");
                put_hex_u64(&mut buf, &mut n, post_rsp);
                put_bytes(&mut buf, &mut n, b" pre_mid_first=");
                if pre_mid_first < 0 {
                    put_byte(&mut buf, &mut n, b'-');
                    put_dec_u64(&mut buf, &mut n, (-(pre_mid_first as i64)) as u64);
                } else {
                    put_dec_u64(&mut buf, &mut n, pre_mid_first as u64);
                }
                put_bytes(&mut buf, &mut n, b" mid_post_first=");
                if mid_post_first < 0 {
                    put_byte(&mut buf, &mut n, b'-');
                    put_dec_u64(&mut buf, &mut n, (-(mid_post_first as i64)) as u64);
                } else {
                    put_dec_u64(&mut buf, &mut n, mid_post_first as u64);
                }
                put_byte(&mut buf, &mut n, b'\n');
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
            }
            // Emit pre/mid1/post snap rows.
            fn snap_row(
                label: &[u8], snap: &[u64; 13],
            ) {
                let mut buf = [0u8; 256];
                let mut n = 0;
                put_bytes(&mut buf, &mut n, b"  ");
                put_bytes(&mut buf, &mut n, label);
                put_bytes(&mut buf, &mut n, b".rip=");
                put_hex_u64(&mut buf, &mut n, snap[5]);
                put_bytes(&mut buf, &mut n, b" ");
                put_bytes(&mut buf, &mut n, label);
                put_bytes(&mut buf, &mut n, b".cs=");
                put_hex_u64(&mut buf, &mut n, snap[6]);
                put_bytes(&mut buf, &mut n, b" ");
                put_bytes(&mut buf, &mut n, label);
                put_bytes(&mut buf, &mut n, b".rflags=");
                put_hex_u64(&mut buf, &mut n, snap[7]);
                put_bytes(&mut buf, &mut n, b" ");
                put_bytes(&mut buf, &mut n, label);
                put_bytes(&mut buf, &mut n, b".rsp=");
                put_hex_u64(&mut buf, &mut n, snap[8]);
                put_bytes(&mut buf, &mut n, b" ");
                put_bytes(&mut buf, &mut n, label);
                put_bytes(&mut buf, &mut n, b".ss=");
                put_hex_u64(&mut buf, &mut n, snap[4]);
                put_bytes(&mut buf, &mut n, b" below=[");
                put_hex_u64(&mut buf, &mut n, snap[0]); put_byte(&mut buf, &mut n, b' ');
                put_hex_u64(&mut buf, &mut n, snap[1]); put_byte(&mut buf, &mut n, b' ');
                put_hex_u64(&mut buf, &mut n, snap[2]); put_byte(&mut buf, &mut n, b' ');
                put_hex_u64(&mut buf, &mut n, snap[3]);
                put_bytes(&mut buf, &mut n, b"] above=[");
                put_hex_u64(&mut buf, &mut n, snap[9]); put_byte(&mut buf, &mut n, b' ');
                put_hex_u64(&mut buf, &mut n, snap[10]); put_byte(&mut buf, &mut n, b' ');
                put_hex_u64(&mut buf, &mut n, snap[11]); put_byte(&mut buf, &mut n, b' ');
                put_hex_u64(&mut buf, &mut n, snap[12]);
                put_bytes(&mut buf, &mut n, b"]\n");
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
            }
            snap_row(b"pre", &pre_snap_all);
            snap_row(b"mid1", &mid1_snap_all);
            snap_row(b"post", &post_snap_all);
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
        // #208 Pattern A sweep: atomic put_* emit.
        let mut buf = [0u8; 256];
        let mut n = 0;
        put_bytes(&mut buf, &mut n, b"FRAME-FLICKER: vec=");
        put_dec_u64(&mut buf, &mut n, vector);
        put_bytes(&mut buf, &mut n, b" tid=");
        put_dec_u64(&mut buf, &mut n, tid_local as u64);
        put_bytes(&mut buf, &mut n, b" cpu=");
        put_dec_u64(&mut buf, &mut n, cur_cpu as u64);
        put_bytes(&mut buf, &mut n, b" sp=");
        put_hex_u64(&mut buf, &mut n, sp);
        put_bytes(&mut buf, &mut n, b" CS=");
        put_hex_u64(&mut buf, &mut n, cs);
        put_bytes(&mut buf, &mut n, b"->");
        put_hex_u64(&mut buf, &mut n, cs2);
        put_bytes(&mut buf, &mut n, b" SS=");
        put_hex_u64(&mut buf, &mut n, ss);
        put_bytes(&mut buf, &mut n, b"->");
        put_hex_u64(&mut buf, &mut n, ss2);
        put_bytes(&mut buf, &mut n, b" RIP=");
        put_hex_u64(&mut buf, &mut n, rip);
        put_bytes(&mut buf, &mut n, b"->");
        put_hex_u64(&mut buf, &mut n, rip2);
        put_byte(&mut buf, &mut n, b'\n');
        crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
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
        // #208 Pattern A sweep: atomic emit via handler_write_bytes —
        // each chunk is a stack-local buf + manual put_*, no
        // format_args!() temporaries that the optimizer could place
        // at slots overlapping the caller's locals.
        {
            let mut buf = [0u8; 256];
            let mut n = 0;
            put_bytes(&mut buf, &mut n, b"BAD frame: CS=");
            put_hex_u64(&mut buf, &mut n, cs);
            put_bytes(&mut buf, &mut n, b" SS=");
            put_hex_u64(&mut buf, &mut n, ss);
            put_bytes(&mut buf, &mut n, b" RIP=");
            put_hex_u64(&mut buf, &mut n, f.rip());
            put_bytes(&mut buf, &mut n, b" vec=");
            put_dec_u64(&mut buf, &mut n, vector);
            put_bytes(&mut buf, &mut n, b" tid=");
            put_dec_u64(&mut buf, &mut n, tid as u64);
            put_bytes(&mut buf, &mut n, b" sp=");
            put_hex_u64(&mut buf, &mut n, sp);
            put_bytes(&mut buf, &mut n, b" src=");
            put_dec_u64(&mut buf, &mut n, tref.saved_sp_source as u64);
            put_bytes(&mut buf, &mut n, b" last_cpu=");
            put_dec_u64(
                &mut buf, &mut n,
                tref.last_cpu.load(core::sync::atomic::Ordering::Relaxed) as u64,
            );
            put_bytes(&mut buf, &mut n, b" cur_cpu=");
            put_dec_u64(&mut buf, &mut n, cur_cpu as u64);
            put_byte(&mut buf, &mut n, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
        }
        {
            let mut buf = [0u8; 128];
            let mut n = 0;
            put_bytes(&mut buf, &mut n, b"  saved_sp=");
            put_hex_u64(&mut buf, &mut n, tref.saved_sp);
            put_bytes(&mut buf, &mut n, b" kstack=");
            put_hex_u64(&mut buf, &mut n, tref.stack_base as u64);
            put_bytes(&mut buf, &mut n, b" task=");
            put_dec_u64(&mut buf, &mut n, tref.task_id as u64);
            put_byte(&mut buf, &mut n, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
        }
        // Raw dump: 22 u64 values at [sp..sp+176).  Annotate any value
        // that falls in a live thread's kstack range (#208 ladder
        // step 1: visually distinguish kstack pointers from garbage).
        for i in 0..22u64 {
            let val = unsafe { *((sp + i * 8) as *const u64) };
            let mut buf = [0u8; 128];
            let mut n = 0;
            put_bytes(&mut buf, &mut n, b"  frame[");
            put_dec_u64(&mut buf, &mut n, i);
            put_bytes(&mut buf, &mut n, b"]=");
            put_hex_018(&mut buf, &mut n, val);
            if let Some((annot_tid, off)) =
                crate::sched::scheduler::classify_kstack_value(val)
            {
                put_bytes(&mut buf, &mut n, b" [kstack tid=");
                put_dec_u64(&mut buf, &mut n, annot_tid as u64);
                put_bytes(&mut buf, &mut n, b" +");
                put_hex_u64(&mut buf, &mut n, off as u64);
                put_byte(&mut buf, &mut n, b']');
            }
            put_byte(&mut buf, &mut n, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
        }
        // #208 H-A vs H-B probe: also dump the frame at tref.saved_sp.
        // If validate's sp ≠ saved_sp, we're checking the wrong frame.
        // If BOTH frames are corrupt → page-reuse / aliasing bug (H-A).
        // If saved_sp frame is clean → validate's sp path is wrong (H-B).
        let saved_sp = tref.saved_sp;
        if saved_sp != 0 && saved_sp != sp {
            let mut buf = [0u8; 96];
            let mut n = 0;
            put_bytes(&mut buf, &mut n, b"  [also dumping at saved_sp=");
            put_hex_u64(&mut buf, &mut n, saved_sp);
            put_bytes(&mut buf, &mut n, b" delta=");
            // Print as signed: if delta < 0 prefix with '-' and negate.
            let d = saved_sp.wrapping_sub(sp) as i64;
            if d < 0 {
                put_byte(&mut buf, &mut n, b'-');
                put_hex_u64(&mut buf, &mut n, (-d) as u64);
            } else {
                put_hex_u64(&mut buf, &mut n, d as u64);
            }
            put_bytes(&mut buf, &mut n, b"]\n");
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
            for i in 17..22u64 {
                let val = unsafe { *((saved_sp + i * 8) as *const u64) };
                let label: &[u8] = match i {
                    17 => b"RIP",
                    18 => b"CS ",
                    19 => b"FLG",
                    20 => b"RSP",
                    21 => b"SS ",
                    _ => b"   ",
                };
                let mut buf = [0u8; 64];
                let mut n = 0;
                put_bytes(&mut buf, &mut n, b"  ssp[");
                put_dec_u64(&mut buf, &mut n, i);
                put_byte(&mut buf, &mut n, b'=');
                put_bytes(&mut buf, &mut n, label);
                put_bytes(&mut buf, &mut n, b"]=");
                put_hex_018(&mut buf, &mut n, val);
                put_byte(&mut buf, &mut n, b'\n');
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
            }
        }
        // #208 shadow + saved_sp last-writer dump.
        {
            let mut buf = [0u8; 256];
            let mut n = 0;
            put_bytes(&mut buf, &mut n, b"  shadow.sp=");
            put_hex_u64(&mut buf, &mut n, tref.iretq_shadow_sp);
            put_bytes(&mut buf, &mut n, b" shadow.rip=");
            put_hex_u64(&mut buf, &mut n, tref.iretq_shadow_rip);
            put_bytes(&mut buf, &mut n, b" shadow.cs=");
            put_hex_u64(&mut buf, &mut n, tref.iretq_shadow_cs);
            put_bytes(&mut buf, &mut n, b" shadow.rflags=");
            put_hex_u64(&mut buf, &mut n, tref.iretq_shadow_rflags);
            put_bytes(&mut buf, &mut n, b" shadow.rsp=");
            put_hex_u64(&mut buf, &mut n, tref.iretq_shadow_rsp);
            put_bytes(&mut buf, &mut n, b" shadow.ss=");
            put_hex_u64(&mut buf, &mut n, tref.iretq_shadow_ss);
            put_byte(&mut buf, &mut n, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
        }
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
            let mut buf = [0u8; 256];
            let mut k = 0;
            put_bytes(&mut buf, &mut k, b"VALIDATOR-BAD-TREF: tid=");
            put_dec_u64(&mut buf, &mut k, tid as u64);
            put_bytes(&mut buf, &mut k, b" tref=");
            put_hex_u64(&mut buf, &mut k, tref_addr);
            put_bytes(&mut buf, &mut k, b" (NOT in SLAB_REGION ");
            put_hex_u64(&mut buf, &mut k, crate::arch::x86_64::mm::SLAB_REGION_BASE);
            put_bytes(&mut buf, &mut k, b"..");
            put_hex_u64(&mut buf, &mut k,
                crate::arch::x86_64::mm::SLAB_REGION_BASE
                    .wrapping_add(crate::arch::x86_64::mm::PML4_SLOT_SIZE));
            put_bytes(&mut buf, &mut k, b") -- THREAD_TABLE[");
            put_dec_u64(&mut buf, &mut k, tid as u64);
            put_bytes(&mut buf, &mut k, b"] corrupted; skipping killed.store and DR0-arm\n");
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
            // Dump the SET-LOG trajectory for this tid to discriminate
            // set-side bug (prev_val already wrong) vs post-set scribble
            // (prev_val was SLAB_REGION on the last set).
            crate::sched::radix::dump_set_log_for_tid(tid);
            // Also dump L0[0] + L1[4] separately to test the L0 corruption
            // hypothesis: if L0[0] is bogus, get(4) chases a wild L1 page
            // and reads tref from a kstack address — which explains why
            // a DR0 watch on the OLD L1[4] slot doesn't fire.
            let (l0_addr, l0_entry_0, l1_4_val) =
                crate::sched::scheduler::THREAD_TABLE.raw_l0_slots();
            let mut buf = [0u8; 128];
            let mut k = 0;
            put_bytes(&mut buf, &mut k, b"VALIDATOR-RAW-RADIX: l0=");
            put_hex_u64(&mut buf, &mut k, l0_addr as u64);
            put_bytes(&mut buf, &mut k, b" l0[0]=");
            put_hex_u64(&mut buf, &mut k, l0_entry_0 as u64);
            put_bytes(&mut buf, &mut k, b" *(l0[0]+0x20)=");
            put_hex_u64(&mut buf, &mut k, l1_4_val as u64);
            put_byte(&mut buf, &mut k, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
        } else {
            // (Old saved_sp DR0-arm removed: it overrode the TT4 L1-slot
            // watch in radix.rs, redirecting DR0 to legitimate try_switch
            // saved_sp writes instead of the actual L1-slot corruption.
            // The TT4 L1-slot watch armed at THREAD_TABLE.set time is the
            // current source of truth.)
            //
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

/// Thin hex writer used by handler probes to avoid invoking core::fmt
/// (which adds 400-600 B of stack per call via Display::fmt/Debug::fmt
/// nesting).  Writes a fixed-format ASCII line directly to the serial
/// port via the existing direct-uart path.
fn handler_log_iretq(tag: &str, cpu: u32, tid: u32, slots: &[u64; 5], frame_va: u64) {
    let mut buf = [0u8; 256];
    let mut n = 0;
    fn put(buf: &mut [u8; 256], n: &mut usize, b: u8) {
        if *n < buf.len() { buf[*n] = b; *n += 1; }
    }
    fn put_str(buf: &mut [u8; 256], n: &mut usize, s: &str) {
        for &b in s.as_bytes() { put(buf, n, b); }
    }
    fn put_hex(buf: &mut [u8; 256], n: &mut usize, mut v: u64) {
        put_str(buf, n, "0x");
        if v == 0 { put(buf, n, b'0'); return; }
        let mut digits = [0u8; 16];
        let mut k = 0;
        while v > 0 {
            let d = (v & 0xf) as u8;
            digits[k] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
            v >>= 4;
            k += 1;
        }
        for i in (0..k).rev() { put(buf, n, digits[i]); }
    }
    fn put_dec(buf: &mut [u8; 256], n: &mut usize, mut v: u32) {
        if v == 0 { put(buf, n, b'0'); return; }
        let mut digits = [0u8; 10];
        let mut k = 0;
        while v > 0 {
            digits[k] = b'0' + (v % 10) as u8;
            v /= 10;
            k += 1;
        }
        for i in (0..k).rev() { put(buf, n, digits[i]); }
    }
    put_str(&mut buf, &mut n, tag);
    put_str(&mut buf, &mut n, ": cpu="); put_dec(&mut buf, &mut n, cpu);
    put_str(&mut buf, &mut n, " tid="); put_dec(&mut buf, &mut n, tid);
    put_str(&mut buf, &mut n, " RIP="); put_hex(&mut buf, &mut n, slots[0]);
    put_str(&mut buf, &mut n, " CS=");  put_hex(&mut buf, &mut n, slots[1]);
    put_str(&mut buf, &mut n, " RFLAGS="); put_hex(&mut buf, &mut n, slots[2]);
    put_str(&mut buf, &mut n, " RSP="); put_hex(&mut buf, &mut n, slots[3]);
    put_str(&mut buf, &mut n, " SS=");  put_hex(&mut buf, &mut n, slots[4]);
    put_str(&mut buf, &mut n, " frame_va="); put_hex(&mut buf, &mut n, frame_va);
    put(&mut buf, &mut n, b'\n');
    crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
}

/// Thin hex writer for ret-scribble with frame.rip + shadow_rip correlation.
fn handler_log_ret_scribble_ctx2(
    cpu: u32, tid: u32, slot: u64, was: u64, now: u64,
    handler_tsc: u64, print_holder: i32,
    entry_frame_rip: u64, shadow_rip: u64, match_src: u32,
) {
    let mut buf = [0u8; 320];
    let mut n = 0;
    fn put(buf: &mut [u8; 320], n: &mut usize, b: u8) {
        if *n < buf.len() { buf[*n] = b; *n += 1; }
    }
    fn put_str(buf: &mut [u8; 320], n: &mut usize, s: &str) {
        for &b in s.as_bytes() { put(buf, n, b); }
    }
    fn put_hex(buf: &mut [u8; 320], n: &mut usize, mut v: u64) {
        put_str(buf, n, "0x");
        if v == 0 { put(buf, n, b'0'); return; }
        let mut digits = [0u8; 16];
        let mut k = 0;
        while v > 0 {
            let d = (v & 0xf) as u8;
            digits[k] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
            v >>= 4;
            k += 1;
        }
        for i in (0..k).rev() { put(buf, n, digits[i]); }
    }
    fn put_dec_u32(buf: &mut [u8; 320], n: &mut usize, mut v: u32) {
        if v == 0 { put(buf, n, b'0'); return; }
        let mut digits = [0u8; 10];
        let mut k = 0;
        while v > 0 {
            digits[k] = b'0' + (v % 10) as u8;
            v /= 10;
            k += 1;
        }
        for i in (0..k).rev() { put(buf, n, digits[i]); }
    }
    fn put_dec_i32(buf: &mut [u8; 320], n: &mut usize, v: i32) {
        if v < 0 { put(buf, n, b'-'); put_dec_u32(buf, n, v.unsigned_abs()); }
        else { put_dec_u32(buf, n, v as u32); }
    }
    put_str(&mut buf, &mut n, "RET-SCRIBBLE: cpu=");
    put_dec_u32(&mut buf, &mut n, cpu);
    put_str(&mut buf, &mut n, " tid=");
    put_dec_u32(&mut buf, &mut n, tid);
    put_str(&mut buf, &mut n, " slot=");
    put_hex(&mut buf, &mut n, slot);
    put_str(&mut buf, &mut n, " was=");
    put_hex(&mut buf, &mut n, was);
    put_str(&mut buf, &mut n, " now=");
    put_hex(&mut buf, &mut n, now);
    put_str(&mut buf, &mut n, " handler_tsc=");
    put_hex(&mut buf, &mut n, handler_tsc);
    put_str(&mut buf, &mut n, " print_holder=");
    put_dec_i32(&mut buf, &mut n, print_holder);
    put_str(&mut buf, &mut n, " entry_frame_rip=");
    put_hex(&mut buf, &mut n, entry_frame_rip);
    put_str(&mut buf, &mut n, " shadow_rip=");
    put_hex(&mut buf, &mut n, shadow_rip);
    put_str(&mut buf, &mut n, " match=");
    put_dec_u32(&mut buf, &mut n, match_src);
    put(&mut buf, &mut n, b'\n');
    crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
}

/// Thin hex writer for ret-scribble events with correlation context.
#[allow(dead_code)]
fn handler_log_ret_scribble_ctx(
    cpu: u32, tid: u32, slot: u64, was: u64, now: u64,
    handler_tsc: u64, print_holder: i32,
) {
    let mut buf = [0u8; 256];
    let mut n = 0;
    fn put(buf: &mut [u8; 256], n: &mut usize, b: u8) {
        if *n < buf.len() { buf[*n] = b; *n += 1; }
    }
    fn put_str(buf: &mut [u8; 256], n: &mut usize, s: &str) {
        for &b in s.as_bytes() { put(buf, n, b); }
    }
    fn put_hex(buf: &mut [u8; 256], n: &mut usize, mut v: u64) {
        put_str(buf, n, "0x");
        if v == 0 { put(buf, n, b'0'); return; }
        let mut digits = [0u8; 16];
        let mut k = 0;
        while v > 0 {
            let d = (v & 0xf) as u8;
            digits[k] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
            v >>= 4;
            k += 1;
        }
        for i in (0..k).rev() { put(buf, n, digits[i]); }
    }
    fn put_dec_u32(buf: &mut [u8; 256], n: &mut usize, mut v: u32) {
        if v == 0 { put(buf, n, b'0'); return; }
        let mut digits = [0u8; 10];
        let mut k = 0;
        while v > 0 {
            digits[k] = b'0' + (v % 10) as u8;
            v /= 10;
            k += 1;
        }
        for i in (0..k).rev() { put(buf, n, digits[i]); }
    }
    fn put_dec_i32(buf: &mut [u8; 256], n: &mut usize, v: i32) {
        if v < 0 { put(buf, n, b'-'); put_dec_u32(buf, n, v.unsigned_abs()); }
        else { put_dec_u32(buf, n, v as u32); }
    }
    put_str(&mut buf, &mut n, "RET-SCRIBBLE: cpu=");
    put_dec_u32(&mut buf, &mut n, cpu);
    put_str(&mut buf, &mut n, " tid=");
    put_dec_u32(&mut buf, &mut n, tid);
    put_str(&mut buf, &mut n, " slot=");
    put_hex(&mut buf, &mut n, slot);
    put_str(&mut buf, &mut n, " was=");
    put_hex(&mut buf, &mut n, was);
    put_str(&mut buf, &mut n, " now=");
    put_hex(&mut buf, &mut n, now);
    put_str(&mut buf, &mut n, " handler_tsc=");
    put_hex(&mut buf, &mut n, handler_tsc);
    put_str(&mut buf, &mut n, " print_holder=");
    put_dec_i32(&mut buf, &mut n, print_holder);
    put(&mut buf, &mut n, b'\n');
    crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
}

/// Thin hex writer for ret-scribble events (legacy, no context).
#[allow(dead_code)]
fn handler_log_ret_scribble(cpu: u32, tid: u32, slot: u64, was: u64, now: u64) {
    let mut buf = [0u8; 192];
    let mut n = 0;
    fn put(buf: &mut [u8; 192], n: &mut usize, b: u8) {
        if *n < buf.len() { buf[*n] = b; *n += 1; }
    }
    fn put_str(buf: &mut [u8; 192], n: &mut usize, s: &str) {
        for &b in s.as_bytes() { put(buf, n, b); }
    }
    fn put_hex(buf: &mut [u8; 192], n: &mut usize, mut v: u64) {
        put_str(buf, n, "0x");
        if v == 0 { put(buf, n, b'0'); return; }
        let mut digits = [0u8; 16];
        let mut k = 0;
        while v > 0 {
            let d = (v & 0xf) as u8;
            digits[k] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
            v >>= 4;
            k += 1;
        }
        for i in (0..k).rev() { put(buf, n, digits[i]); }
    }
    fn put_dec(buf: &mut [u8; 192], n: &mut usize, mut v: u32) {
        if v == 0 { put(buf, n, b'0'); return; }
        let mut digits = [0u8; 10];
        let mut k = 0;
        while v > 0 {
            digits[k] = b'0' + (v % 10) as u8;
            v /= 10;
            k += 1;
        }
        for i in (0..k).rev() { put(buf, n, digits[i]); }
    }
    put_str(&mut buf, &mut n, "RET-SCRIBBLE: cpu=");
    put_dec(&mut buf, &mut n, cpu);
    put_str(&mut buf, &mut n, " tid=");
    put_dec(&mut buf, &mut n, tid);
    put_str(&mut buf, &mut n, " slot=");
    put_hex(&mut buf, &mut n, slot);
    put_str(&mut buf, &mut n, " was=");
    put_hex(&mut buf, &mut n, was);
    put_str(&mut buf, &mut n, " now=");
    put_hex(&mut buf, &mut n, now);
    put(&mut buf, &mut n, b'\n');
    crate::arch::x86_64::serial::handler_write_bytes(&buf[..n.min(buf.len())]);
}

/// #233 PRE-IRETQ probe: called from __isr_common JUST BEFORE iretq when
/// the iretq frame's CS slot doesn't match {kernel 0x08, user 0x23}.
/// `frame` points at the 5-quad iretq frame (RIP, CS, RFLAGS, RSP, SS).
/// Captures and prints the corrupted frame so we can identify the writer
/// signature (instruction-byte shape, kernel-VA shape, ASCII text, etc.).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pre_iretq_dump(frame: *const u64) {
    let slots: [u64; 5] = [
        unsafe { core::ptr::read_volatile(frame) },
        unsafe { core::ptr::read_volatile(frame.add(1)) },
        unsafe { core::ptr::read_volatile(frame.add(2)) },
        unsafe { core::ptr::read_volatile(frame.add(3)) },
        unsafe { core::ptr::read_volatile(frame.add(4)) },
    ];
    let cpu = crate::sched::smp::cpu_id();
    let tid = crate::sched::scheduler::current_thread_id();
    handler_log_iretq("PRE-IRETQ-SUSPECT", cpu, tid, &slots, frame as u64);
}

/// #233 (1) Dr1Guard: clears DR1 at handler exit so the watchpoint
/// only fires DURING the handler.  Without this, the watchpoint would
/// continue firing on legitimate iretq frame writes after the handler.
struct Dr1Guard;
impl Drop for Dr1Guard {
    fn drop(&mut self) {
        unsafe {
            // Clear DR1 by setting it to 0 + clearing its DR7 bits.
            let zero: u64 = 0;
            core::arch::asm!("mov dr1, {0}", in(reg) zero, options(nostack));
            let mut cur_dr7: u64;
            core::arch::asm!("mov {0}, dr7", out(reg) cur_dr7, options(nomem, nostack));
            // Clear L1 + RW1 + LEN1.
            let mask: u64 = (1u64 << 2) | (0b11u64 << 20) | (0b11u64 << 22);
            cur_dr7 &= !mask;
            core::arch::asm!("mov dr7, {0}", in(reg) cur_dr7, options(nostack));
        }
    }
}

/// #233 (4) NMI-in-handler probe state.  Each CPU sets IN_HANDLER[cpu]
/// at x86_exception_handler entry and clears at exit.  The NMI vector
/// checks this flag and bumps NMI_IN_HANDLER_COUNT[cpu] (+ logs first
/// few events) when it fires while a handler is in progress — which
/// could explain how the second-call ret-target keeps landing in the
/// outer ret-slot despite the no-stack-switch mitigation.
///
/// #241 NMI re-entrancy state.  NMI_NEST_DEPTH[cpu] counts the number
/// of NMI vector dispatches currently in-flight on this CPU.  Outer NMI
/// (depth was 0 → 1) takes the normal processing path; nested NMI
/// (depth was ≥ 1 → ≥ 2) takes the safe-abort path that skips
/// exception_fault and returns to the iretq stub immediately, avoiding
/// (a) deadlock on locks the interrupted handler may hold (PRINT_LOCK,
/// scheduler locks, …) and (b) infinite recursion through panic.
///
/// NMI_OUTERMOST_IRETQ_FRAME[cpu] is forward-looking storage for the
/// `paranoid_entry`-style asm trampoline that #216 Phase 2 will add
/// when NMI moves to IST 3.  The single-shot rsp store on IST entry
/// means a nested NMI overwrites the outer NMI's iretq frame at
/// IST3_TOP; the trampoline copies that frame into this per-CPU slot
/// on outer entry, then restores it on outer exit.  We populate the
/// field today from Rust so existing diagnostics can see what the
/// outermost iretq frame looked like, and so the asm trampoline can
/// drop in later without changing this file.
const MAX_NMI_CPUS: usize = 8;
pub static NMI_NEST_DEPTH: [core::sync::atomic::AtomicU32; MAX_NMI_CPUS] = [const {
    core::sync::atomic::AtomicU32::new(0)
}; MAX_NMI_CPUS];
pub static NMI_NESTED_TOTAL: [core::sync::atomic::AtomicU32; MAX_NMI_CPUS] = [const {
    core::sync::atomic::AtomicU32::new(0)
}; MAX_NMI_CPUS];

/// Outermost iretq frame (rip, cs, rflags, rsp, ss) populated by the
/// outer NMI handler at entry.  See #241 design note above.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NmiIretqFrame {
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}
pub static mut NMI_OUTERMOST_IRETQ_FRAME: [NmiIretqFrame; MAX_NMI_CPUS] =
    [NmiIretqFrame { rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0 }; MAX_NMI_CPUS];


static IN_HANDLER: [core::sync::atomic::AtomicBool; MAX_NMI_CPUS] = [const {
    core::sync::atomic::AtomicBool::new(false)
}; MAX_NMI_CPUS];
pub static NMI_IN_HANDLER_COUNT: [core::sync::atomic::AtomicU32; MAX_NMI_CPUS] = [const {
    core::sync::atomic::AtomicU32::new(0)
}; MAX_NMI_CPUS];
pub fn set_in_handler(cpu: usize, v: bool) {
    if cpu < MAX_NMI_CPUS {
        IN_HANDLER[cpu].store(v, core::sync::atomic::Ordering::Release);
    }
}
pub fn get_in_handler(cpu: usize) -> bool {
    if cpu < MAX_NMI_CPUS {
        IN_HANDLER[cpu].load(core::sync::atomic::Ordering::Acquire)
    } else {
        false
    }
}
struct InHandlerGuard { cpu: usize }
impl Drop for InHandlerGuard {
    fn drop(&mut self) { set_in_handler(self.cpu, false); }
}

/// #233 RET-SCRIBBLE guard: snapshots the return-address slot of the
/// `call x86_exception_handler` instruction in `__isr_common` at handler
/// entry; checks on Drop (i.e., every normal return path).  If a peer
/// CPU or local code scribbled the slot during handler execution, the
/// `ret` would have jumped to a wild RIP — Drop catches it first.
struct RetScribbleCheck {
    slot: *const u64,
    saved: u64,
    entry_tsc: u64,
    /// User RIP from the iretq frame at handler entry (frame_sp + 0x88).
    /// Used in Drop to test if scribbled `now` value equals this user
    /// RIP — if so, the writer is something that copies the frame's
    /// RIP to the slot.
    entry_frame_rip: u64,
}
impl Drop for RetScribbleCheck {
    fn drop(&mut self) {
        let now = unsafe { core::ptr::read_volatile(self.slot) };
        if now != self.saved {
            let cpu = crate::sched::smp::cpu_id();
            let tid = crate::sched::scheduler::current_thread_id();
            let exit_tsc = crate::arch::x86_64::timer::rdtsc();
            let handler_tsc = exit_tsc.wrapping_sub(self.entry_tsc);
            let print_holder = crate::arch::x86_64::serial::PRINT_HOLDER_CPU
                .load(core::sync::atomic::Ordering::Acquire);
            // Read this thread's iretq_shadow_rip for correlation.
            let shadow_rip = if tid != 0 {
                crate::sched::scheduler::thread_ref(tid).iretq_shadow_rip
            } else {
                0
            };
            // Encode source match in a single byte:
            //   1 = matches entry_frame_rip
            //   2 = matches shadow_rip
            //   3 = matches both
            //   0 = neither
            let mut match_src: u32 = 0;
            if now == self.entry_frame_rip { match_src |= 1; }
            if now == shadow_rip { match_src |= 2; }
            handler_log_ret_scribble_ctx2(
                cpu, tid, self.slot as u64, self.saved, now,
                handler_tsc, print_holder,
                self.entry_frame_rip, shadow_rip, match_src,
            );
        }
    }
}

/// Common interrupt/exception handler called from assembly.
/// For timer IRQ (vector 32), returns potentially new SP for context switch.
#[unsafe(no_mangle)]
extern "C" fn x86_exception_handler(frame_sp: u64) -> u64 {
    // #244 ARGS-PROBE: rate-limited scan of the interrupted thread's
    // kstack starting at frame_sp.  Exceptions fire millions of times
    // per boot, so sample every 65536th entry — heavy enough rates
    // (e.g. 1024) kept the kernel from reaching Phase 5 under 4-multi
    // stress.  Skip when we're on an IST stack — the partial-write
    // pattern only applies to alloc_kstack_zeroed kstacks, not IST
    // stacks (which have their own initialization).
    {
        use core::sync::atomic::{AtomicU32, Ordering};
        static EXC_PROBE_TICK: AtomicU32 = AtomicU32::new(0);
        let n = EXC_PROBE_TICK.fetch_add(1, Ordering::Relaxed);
        if n & 0xFFFF == 0 {
            if crate::arch::x86_64::gdt::is_on_ist(frame_sp).is_none() {
                crate::arch::x86_64::serial::args_probe_scan(frame_sp);
            }
        }
    }
    // #237 IST detection: at handler entry, check whether we're running
    // on a per-CPU IST stack instead of the interrupted thread's kstack.
    // Probes that compare frame_sp against current_thread.stack_base
    // would mis-classify on an IST entry; this flag lets them branch.
    // Log the first 8 IST entries for visibility.  Once Phase 2/3 of
    // #216 land more vectors on IST, this will fire on every kstack
    // overflow caught by #SS/#PF on IST — exactly the signal we want.
    let ist_slot = crate::arch::x86_64::gdt::is_on_ist(frame_sp);
    if let Some((slot, cpu)) = ist_slot {
        static IST_ENTRY_LOG: core::sync::atomic::AtomicU32 =
            core::sync::atomic::AtomicU32::new(0);
        let n = IST_ENTRY_LOG
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if n < 8 {
            let mut buf = [0u8; 128];
            let mut k = 0;
            put_bytes(&mut buf, &mut k, b"IST-ENTRY: slot=");
            put_dec_u64(&mut buf, &mut k, slot as u64);
            put_bytes(&mut buf, &mut k, b" cpu_idx=");
            put_dec_u64(&mut buf, &mut k, cpu as u64);
            put_bytes(&mut buf, &mut k, b" rsp=");
            put_hex_u64(&mut buf, &mut k, frame_sp);
            put_bytes(&mut buf, &mut k, b" n=");
            put_dec_u64(&mut buf, &mut k, n as u64);
            put_byte(&mut buf, &mut k, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(
                &buf[..k.min(buf.len())]);
        }
    }
    // #208 STACK-NEAR-GUARD probe: at handler entry, frame_sp is the lowest
    // address of the current kstack usage (just-pushed GPRs).  If
    // frame_sp - stack_base is small, the next CALL/PUSH could touch the
    // guard page.  Boot 11amfsq3243 caught a real overflow on tid=4
    // zero_daemon (kstack window 0xfffffe0000b00000..0xfffffe0000c00000,
    // guard hit at 0xfffffe0000c00000 — *upward* off the top, suggesting
    // an asm-stub frame-pushed-past-allocation pattern).  This probe fires
    // BEFORE that page-fault state: catches "stack distance to base/top
    // boundary smaller than safety margin" so we see a warning ahead of
    // the cascade.  One-shot per tid to avoid storms.
    //
    // #237: skip when on IST — frame_sp is an IST stack address, not the
    // thread's kstack, so the kbase/ksize comparison is meaningless.
    if ist_slot.is_none() {
        let tid = crate::sched::scheduler::current_thread_id();
        if tid != 0 && (tid as usize) < 256 {
            let tref = crate::sched::scheduler::thread_ref(tid);
            let kbase = tref.stack_base as u64;
            let ksize = crate::sched::scheduler::kstack_size() as u64;
            let ktop = kbase.wrapping_add(ksize);
            // Skip per-CPU idle threads — they run on the boot/AP stacks
            // in PHYS_DIRECT_MAP, legitimately outside their allocated
            // kstack window.  Same filter as the SAVED-SP-WRITE-OUT-OF-
            // RANGE probe (commit b766f91).
            let mut is_idle = false;
            let ncpus = crate::sched::smp::num_cpus() as u32;
            for cpu in 0..ncpus {
                let pcpu = crate::sched::smp::get(cpu);
                if pcpu.idle_thread_id
                    .load(core::sync::atomic::Ordering::Relaxed) == tid
                {
                    is_idle = true;
                    break;
                }
            }
            // Stack grows DOWN from top toward base.  Near the top is
            // healthy (just-started frame); near the base is dangerous
            // (deep recursion approaching guard).  Warn only when RSP
            // is within 16 KiB of the base — that's the real
            // overflow-imminent signal.
            const MARGIN: u64 = 16 * 1024;
            let near_base = frame_sp > kbase
                && frame_sp.wrapping_sub(kbase) < MARGIN;
            // Explicit out-of-range (already overflow / wild sp).
            let out_of_range = frame_sp < kbase || frame_sp > ktop;
            let near_top = false; // legacy field, kept for the log path
            if (near_base || out_of_range) && kbase != 0 && !is_idle {
                static STACK_NEAR_LOG: core::sync::atomic::AtomicU32 =
                    core::sync::atomic::AtomicU32::new(0);
                let n = STACK_NEAR_LOG
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                if n < 16 {
                    let mut buf = [0u8; 192];
                    let mut k = 0;
                    put_bytes(&mut buf, &mut k, b"STACK-NEAR-GUARD: tid=");
                    put_dec_u64(&mut buf, &mut k, tid as u64);
                    put_bytes(&mut buf, &mut k, b" rsp=");
                    put_hex_u64(&mut buf, &mut k, frame_sp);
                    put_bytes(&mut buf, &mut k, b" kstack=[");
                    put_hex_u64(&mut buf, &mut k, kbase);
                    put_bytes(&mut buf, &mut k, b"..");
                    put_hex_u64(&mut buf, &mut k, ktop);
                    put_bytes(&mut buf, &mut k, b") edge=");
                    put_bytes(&mut buf, &mut k,
                        if out_of_range { b"OOR" }
                        else if near_base { b"base" }
                        else { b"top" });
                    put_bytes(&mut buf, &mut k, b" margin_left=");
                    let dist = if frame_sp > kbase {
                        frame_sp.wrapping_sub(kbase)
                    } else { 0 };
                    put_dec_u64(&mut buf, &mut k, dist);
                    put_bytes(&mut buf, &mut k, b" n=");
                    put_dec_u64(&mut buf, &mut k, n as u64);
                    put_byte(&mut buf, &mut k, b'\n');
                    crate::arch::x86_64::serial::handler_write_bytes(
                        &buf[..k.min(buf.len())]);
                }
            }
        }
    } // end if ist_slot.is_none()
    // #233 ret-addr scribble check: __isr_common does `call x86_exception_handler`,
    // which pushes its return address onto frame_sp.  So [frame_sp - 8] is the
    // return-address slot; expected value is RIP-after-call in __isr_common.
    let ret_slot = (frame_sp - 8) as *const u64;
    // ExceptionFrame layout: regs[17] = user RIP at frame_sp + 17*8 = +0x88.
    let entry_frame_rip = unsafe {
        core::ptr::read_volatile((frame_sp + 0x88) as *const u64)
    };
    let _ret_check = RetScribbleCheck {
        slot: ret_slot,
        saved: unsafe { core::ptr::read_volatile(ret_slot) },
        entry_tsc: crate::arch::x86_64::timer::rdtsc(),
        entry_frame_rip,
    };
    // #233 (5) Move finalize_release_after_stack_switch from the second
    // call in __isr_common to here.  The original call pushed a ret-addr
    // at our outer slot when rsp didn't change (and even under
    // mitigation the captures kept showing this pattern).  Running the
    // drain on the SAME CPU at the next handler entry is safe — by then
    // the previous handler's `mov rsp,rax` has already moved us off
    // prev's kstack.
    crate::sched::scheduler::finalize_release_after_stack_switch();
    // #233 (1) Dynamic DR1: arm the watchpoint to THIS handler's outer
    // ret-addr slot.  Catches any local-CPU writer that scribbles the
    // slot during this handler's execution.  Disarmed at handler exit
    // via the Drop guard `_dr1_guard` below so we don't trigger on
    // legitimate iretq frame writes from later code.
    crate::arch::x86_64::gdt::dr1_set_watch_write_qword(frame_sp - 8);
    let _dr1_guard = Dr1Guard;
    // #233 (4) NMI-in-handler probe: mark this CPU as "in handler".
    // NMI vector checks this and logs if it fires while we're here.
    let cpu_for_in_handler = crate::sched::smp::cpu_id() as usize;
    set_in_handler(cpu_for_in_handler, true);
    let _in_handler_guard = InHandlerGuard { cpu: cpu_for_in_handler };

    // Clear any stale pending_switch_sp left by the previous exception's
    // return path.  The previous cycle's take_pending_switch() loaded the
    // SP without clearing it (so wake_parked_thread's spin-wait could see
    // the non-zero value until the assembly `mov rsp, rax` completed).
    // By this point the stack switch is done — safe to signal completion.
    let cpu = crate::sched::smp::cpu_id() as usize;
    crate::sched::scheduler::clear_pending_switch(cpu);

    // #208 L1-slot watchpoint — every CPU re-arms its DR0 on the
    // global watch address (set by sched::radix's TT4-WATCH-ARM probe
    // when THREAD_TABLE[4] is first written with a SLAB VA).  Always
    // calls dr0_ensure_watching unconditionally so each CPU's HW DR0
    // converges on the current global target — the old "if target==0
    // then set saved_sp" branch was a stale saved_sp-era arm that
    // overrode the L1-slot watch and caused DR0 hits to fire on
    // legitimate saved_sp writes instead of the L1-slot corruption.
    {
        let target = crate::arch::x86_64::gdt::GLOBAL_SAVED_SP_WATCH_ADDR
            .load(core::sync::atomic::Ordering::Relaxed);
        if target != 0 {
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
                let rip_early = unsafe {
                    core::ptr::read_volatile(&frame.regs[17] as *const u64)
                };
                // #208 Pattern A sweep: atomic put_*.
                let mut buf = [0u8; 192];
                let mut k = 0;
                put_bytes(&mut buf, &mut k, b"EARLY-BAD-CS: vec=");
                put_dec_u64(&mut buf, &mut k, vector);
                put_bytes(&mut buf, &mut k, b" cs=");
                put_hex_u64(&mut buf, &mut k, cs_early);
                put_bytes(&mut buf, &mut k, b" rip=");
                put_hex_u64(&mut buf, &mut k, rip_early);
                put_bytes(&mut buf, &mut k, b" frame_sp=");
                put_hex_u64(&mut buf, &mut k, frame_sp);
                put_bytes(&mut buf, &mut k, b" cpu=");
                put_dec_u64(&mut buf, &mut k, cpu as u64);
                put_bytes(&mut buf, &mut k, b" n=");
                put_dec_u64(&mut buf, &mut k, n as u64);
                put_byte(&mut buf, &mut k, b'\n');
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
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
    //
    // #238: skip when on IST.  An IST-routed entry from user has
    // `frame_sp` on the IST stack, not the thread's kstack — the
    // "outside kstack range" comparison would always false-positive.
    // For Phase 1 (#DF, #SS on IST) this path isn't reached anyway
    // because those vectors dispatch into exception_fault directly,
    // but future-proofs for Phase 2/3.
    {
        let from_user = (frame.cs() & 3) == 3;
        let on_ist = crate::arch::x86_64::gdt::is_on_ist(frame_sp).is_some();
        if from_user && !on_ist {
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
                        let cs_val = frame.cs();
                        // #208 Pattern A sweep: atomic put_*.
                        let mut buf = [0u8; 256];
                        let mut k = 0;
                        put_bytes(&mut buf, &mut k, b"RSP0-MISMATCH: tid=");
                        put_dec_u64(&mut buf, &mut k, tid as u64);
                        put_bytes(&mut buf, &mut k, b" cpu=");
                        put_dec_u64(&mut buf, &mut k, cpu as u64);
                        put_bytes(&mut buf, &mut k, b" vec=");
                        put_dec_u64(&mut buf, &mut k, vector);
                        put_bytes(&mut buf, &mut k, b" frame_sp=");
                        put_hex_u64(&mut buf, &mut k, frame_sp);
                        put_bytes(&mut buf, &mut k, b" expected_kstack=[");
                        put_hex_u64(&mut buf, &mut k, sb);
                        put_bytes(&mut buf, &mut k, b"..");
                        put_hex_u64(&mut buf, &mut k, sb + sz);
                        put_bytes(&mut buf, &mut k, b") tss_rsp0=");
                        put_hex_u64(&mut buf, &mut k, tss_rsp0);
                        put_bytes(&mut buf, &mut k, b" expected_rsp0=");
                        put_hex_u64(&mut buf, &mut k, expected_rsp0);
                        put_bytes(&mut buf, &mut k, b" cs=");
                        put_hex_u64(&mut buf, &mut k, cs_val);
                        put_bytes(&mut buf, &mut k, b" n=");
                        put_dec_u64(&mut buf, &mut k, n as u64);
                        put_byte(&mut buf, &mut k, b'\n');
                        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
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
            // #233 (1) DR1/DR2/DR3 hits — log writer RIP for any of the
            // three recurring scribble slots.  Re-arm to keep watching.
            let b1 = (dr6 >> 1) & 1 != 0;
            let b2 = (dr6 >> 2) & 1 != 0;
            let b3 = (dr6 >> 3) & 1 != 0;
            if b1 | b2 | b3 {
                let rip = frame.rip();
                let cpu_id = crate::sched::smp::cpu_id();
                let tid = crate::sched::scheduler::current_thread_id();
                let (which, va) = if b1 {
                    (1u32, crate::arch::x86_64::gdt::SLOT_WATCH_VA)
                } else if b2 {
                    (2u32, crate::arch::x86_64::gdt::SLOT_WATCH_VA_2)
                } else {
                    (3u32, crate::arch::x86_64::gdt::SLOT_WATCH_VA_3)
                };
                {
                    let mut buf = [0u8; 192];
                    let mut k = 0;
                    put_bytes(&mut buf, &mut k, b"DR-HIT-SLOT: dr=");
                    put_dec_u64(&mut buf, &mut k, which as u64);
                    put_bytes(&mut buf, &mut k, b" va=");
                    put_hex_u64(&mut buf, &mut k, va);
                    put_bytes(&mut buf, &mut k, b" rip=");
                    put_hex_u64(&mut buf, &mut k, rip);
                    put_bytes(&mut buf, &mut k, b" cpu=");
                    put_dec_u64(&mut buf, &mut k, cpu_id as u64);
                    put_bytes(&mut buf, &mut k, b" tid=");
                    put_dec_u64(&mut buf, &mut k, tid as u64);
                    put_bytes(&mut buf, &mut k, b" cs=");
                    put_hex_u64(&mut buf, &mut k, frame.cs());
                    put_bytes(&mut buf, &mut k, b" ts_ns=");
                    put_dec_u64(&mut buf, &mut k, crate::arch::timer::monotonic_ns());
                    put_byte(&mut buf, &mut k, b'\n');
                    crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                }
                if b1 {
                    crate::arch::x86_64::gdt::dr1_set_watch_write_qword(
                        crate::arch::x86_64::gdt::SLOT_WATCH_VA);
                }
                if b2 {
                    crate::arch::x86_64::gdt::dr2_set_watch_write_qword(
                        crate::arch::x86_64::gdt::SLOT_WATCH_VA_2);
                }
                if b3 {
                    crate::arch::x86_64::gdt::dr3_set_watch_write_qword(
                        crate::arch::x86_64::gdt::SLOT_WATCH_VA_3);
                }
                return validate_iretq_frame(frame_sp, frame_sp, 1);
            }
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
                    {
                        let mut buf = [0u8; 256];
                        let mut k = 0;
                        put_bytes(&mut buf, &mut k, b"DR0-HIT-OFF-PATH-OVERLAP: watched=");
                        put_hex_u64(&mut buf, &mut k, watched);
                        put_bytes(&mut buf, &mut k, b" dr0_reg=");
                        put_hex_u64(&mut buf, &mut k, dr0_reg);
                        put_bytes(&mut buf, &mut k, b" kbase=");
                        put_hex_u64(&mut buf, &mut k, kbase);
                        put_bytes(&mut buf, &mut k, b"..");
                        put_hex_u64(&mut buf, &mut k, kbase + ksize);
                        put_bytes(&mut buf, &mut k, b" in_kstack=");
                        put_bytes(&mut buf, &mut k, if in_kstack { b"true" } else { b"false" });
                        put_bytes(&mut buf, &mut k, b" rsp_entry=");
                        put_hex_u64(&mut buf, &mut k, rsp_entry);
                        put_bytes(&mut buf, &mut k, b" rdi=");
                        put_hex_u64(&mut buf, &mut k, rdi);
                        put_bytes(&mut buf, &mut k, b" rax=");
                        put_hex_u64(&mut buf, &mut k, rax);
                        put_byte(&mut buf, &mut k, b'\n');
                        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                    }
                    // #208 ts probe: timestamp DR0 hits so a post-mortem can
                    // sort by time and look for overlapping write windows
                    // from different CPUs on the same tid — signature of
                    // concurrent dispatch of the same thread.
                    let ts_ns = crate::arch::timer::monotonic_ns();
                    {
                        let mut buf = [0u8; 192];
                        let mut k = 0;
                        put_bytes(&mut buf, &mut k, b"DR0-HIT-OFF-PATH: dr6=");
                        put_hex_u64(&mut buf, &mut k, dr6);
                        put_bytes(&mut buf, &mut k, b" rip=");
                        put_hex_u64(&mut buf, &mut k, rip);
                        put_bytes(&mut buf, &mut k, b" tid=");
                        put_dec_u64(&mut buf, &mut k, tid as u64);
                        put_bytes(&mut buf, &mut k, b" cpu=");
                        put_dec_u64(&mut buf, &mut k, cpu as u64);
                        put_bytes(&mut buf, &mut k, b" cs=");
                        put_hex_u64(&mut buf, &mut k, frame.cs());
                        put_bytes(&mut buf, &mut k, b" ts_ns=");
                        put_dec_u64(&mut buf, &mut k, ts_ns);
                        put_byte(&mut buf, &mut k, b'\n');
                        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                    }
                    crate::arch::x86_64::gdt::dr0_clear();
                }
                return validate_iretq_frame(frame_sp, frame_sp, 1);
            }
            exception_fault("Debug (#DB)", frame)
        }
        2 => {
            // #241 NMI re-entrancy.  Atomically bump the per-CPU nest
            // counter; outer NMI takes the depth 0 → 1 transition and
            // the normal exception_fault path, nested NMI takes ≥ 1 → ≥ 2
            // and returns early without calling exception_fault.
            //
            // Why skip exception_fault on nested:
            //   - exception_fault prints (handler_write_bytes is itself
            //     re-entrant after #243, but the deeper dump path may
            //     touch scheduler/format/etc. locks that the interrupted
            //     handler holds).
            //   - exception_fault calls exit_current_thread which takes
            //     scheduler locks; running it twice on this CPU at once
            //     would deadlock.
            //   - Panic + halt are also non-re-entrant in practice.
            //
            // The depth-counter is the kstack analogue of Linux's
            // `paranoid_entry` sentinel.  When NMI moves to IST 3
            // (#216 Phase 2), the same depth counter combined with the
            // NMI_OUTERMOST_IRETQ_FRAME storage will form the basis of
            // the asm trampoline that protects the outer iretq frame
            // from being overwritten by an inner NMI's single-shot rsp
            // store at IST3_TOP.  Until then, NMI stays on the kstack
            // (no IST), so the frame-overwrite case can't trigger; only
            // the lock-recursion case can, and the depth counter blocks
            // it.
            let cpu_for_nmi = crate::sched::smp::cpu_id() as usize;
            if cpu_for_nmi < MAX_NMI_CPUS {
                let prev_depth = NMI_NEST_DEPTH[cpu_for_nmi]
                    .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
                if prev_depth == 0 {
                    // Outer NMI: snapshot the iretq frame into the
                    // per-CPU outermost-frame slot.  This populates the
                    // forward-looking #216 Phase 2 hook in code today;
                    // when the asm trampoline lands, the snapshot will
                    // move into asm and the Rust path will only read.
                    let snap = NmiIretqFrame {
                        rip: frame.rip(),
                        cs: frame.cs(),
                        rflags: frame.rflags(),
                        rsp: frame.rsp(),
                        ss: frame.ss(),
                    };
                    // SAFETY: per-CPU slot, only touched by this CPU's
                    // outer NMI handler (depth was 0 → 1, so no other
                    // writer is running on this CPU).
                    unsafe { NMI_OUTERMOST_IRETQ_FRAME[cpu_for_nmi] = snap; }
                } else {
                    // Nested NMI: log + safe-abort.
                    let n = NMI_NESTED_TOTAL[cpu_for_nmi]
                        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    if n < 16 {
                        use crate::arch::x86_64::serial::{
                            put_byte, put_bytes, put_dec_u64, put_hex_u64,
                        };
                        let mut buf = [0u8; 128];
                        let mut k = 0;
                        put_bytes(&mut buf, &mut k, b"NMI-NESTED: cpu=");
                        put_dec_u64(&mut buf, &mut k, cpu_for_nmi as u64);
                        put_bytes(&mut buf, &mut k, b" depth=");
                        put_dec_u64(&mut buf, &mut k, (prev_depth + 1) as u64);
                        put_bytes(&mut buf, &mut k, b" n=");
                        put_dec_u64(&mut buf, &mut k, n as u64);
                        put_bytes(&mut buf, &mut k, b" inner_rip=");
                        put_hex_u64(&mut buf, &mut k, frame.rip());
                        put_byte(&mut buf, &mut k, b'\n');
                        crate::arch::x86_64::serial::handler_write_bytes(
                            &buf[..k.min(buf.len())]
                        );
                    }
                    // Drop nest depth and return — outer keeps running.
                    NMI_NEST_DEPTH[cpu_for_nmi]
                        .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
                    return validate_iretq_frame(frame_sp, frame_sp, 2);
                }
                // #233 (4): keep the historical NMI-IN-HANDLER probe for
                // the case where an unrelated exception was already in
                // flight on this CPU (NMI fired during e.g. a #PF).
                if get_in_handler(cpu_for_nmi) {
                    let n = NMI_IN_HANDLER_COUNT[cpu_for_nmi]
                        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    if n < 16 {
                        use crate::arch::x86_64::serial::{
                            put_byte, put_bytes, put_dec_u64, put_hex_u64,
                        };
                        let mut buf = [0u8; 96];
                        let mut k = 0;
                        put_bytes(&mut buf, &mut k, b"NMI-IN-HANDLER: cpu=");
                        put_dec_u64(&mut buf, &mut k, cpu_for_nmi as u64);
                        put_bytes(&mut buf, &mut k, b" n=");
                        put_dec_u64(&mut buf, &mut k, n as u64);
                        put_bytes(&mut buf, &mut k, b" rip=");
                        put_hex_u64(&mut buf, &mut k, frame.rip());
                        put_byte(&mut buf, &mut k, b'\n');
                        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k]);
                    }
                }
            }
            exception_fault("NMI", frame)
        }
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
                {
                    let mut buf = [0u8; 96];
                    let mut k = 0;
                    put_bytes(&mut buf, &mut k, b"USER #BP (INT 3) at RIP=");
                    put_hex_u64(&mut buf, &mut k, frame.rip() - 1);
                    put_bytes(&mut buf, &mut k, b" tid=");
                    put_dec_u64(&mut buf, &mut k, crate::sched::scheduler::current_thread_id() as u64);
                    put_bytes(&mut buf, &mut k, b" -> exit SIGTRAP(5)\n");
                    crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                }
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
                                    let mut buf = [0u8; 192];
                                    let mut k = 0;
                                    put_bytes(&mut buf, &mut k, b"IRETQ: tid=");
                                    put_dec_u64(&mut buf, &mut k, tid as u64);
                                    put_bytes(&mut buf, &mut k, b" task=");
                                    put_dec_u64(&mut buf, &mut k, task_id as u64);
                                    put_bytes(&mut buf, &mut k, b" sp=");
                                    put_hex_u64(&mut buf, &mut k, final_sp);
                                    put_bytes(&mut buf, &mut k, b" rip=");
                                    put_hex_u64(&mut buf, &mut k, final_frame.rip());
                                    put_bytes(&mut buf, &mut k, b" cs=");
                                    put_hex_u64(&mut buf, &mut k, final_frame.cs());
                                    put_bytes(&mut buf, &mut k, b" rax=");
                                    put_hex_u64(&mut buf, &mut k, final_frame.rax());
                                    put_bytes(&mut buf, &mut k, b" pending=");
                                    put_bytes(&mut buf, &mut k, if pending != 0 { b"yes" } else { b"no" });
                                    put_byte(&mut buf, &mut k, b'\n');
                                    crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
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
                {
                    let mut buf = [0u8; 96];
                    let mut k = 0;
                    put_bytes(&mut buf, &mut k, b"  #UD bytes at RIP:");
                    for &b in bytes.iter() {
                        put_byte(&mut buf, &mut k, b' ');
                        let hi = b >> 4;
                        let lo = b & 0xf;
                        put_byte(&mut buf, &mut k, if hi < 10 { b'0' + hi } else { b'a' + (hi - 10) });
                        put_byte(&mut buf, &mut k, if lo < 10 { b'0' + lo } else { b'a' + (lo - 10) });
                    }
                    put_byte(&mut buf, &mut k, b'\n');
                    crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                }
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
            // #233 (2) PF-WPROT probe: if CR2 lies on our write-protected
            // slot page AND the fault was caused by a write, log the
            // writer's RIP+CR2 (cross-CPU writers are caught here too,
            // unlike DR1 which is per-CPU).  Then re-enable write on the
            // page (one-shot per boot) and let the writer proceed.
            #[cfg(target_arch = "x86_64")]
            {
                let cr2: u64;
                unsafe {
                    core::arch::asm!("mov {0}, cr2", out(reg) cr2, options(nomem, nostack));
                }
                let ec = frame.error_code();
                // Error code bit 1 = write fault.
                let was_write = (ec & 2) != 0;
                let watched_page_base =
                    crate::sched::scheduler::PF_WPROT_VA & !0xFFF;
                let dm_page_base = crate::sched::scheduler::PF_WPROT_DM_VA
                    .load(core::sync::atomic::Ordering::Acquire);
                let cr2_page = cr2 & !0xFFF;
                let hit_kstack = cr2_page == watched_page_base;
                let hit_dm = dm_page_base != 0 && cr2_page == dm_page_base;
                if was_write && (hit_kstack || hit_dm) {
                    let already_disarmed = if hit_kstack {
                        crate::sched::scheduler::PF_WPROT_DISARMED
                            .swap(true, core::sync::atomic::Ordering::AcqRel)
                    } else {
                        crate::sched::scheduler::PF_WPROT_DM_DISARMED
                            .swap(true, core::sync::atomic::Ordering::AcqRel)
                    };
                    if !already_disarmed {
                        let rip = frame.rip();
                        let cpu_id = crate::sched::smp::cpu_id();
                        let tid = crate::sched::scheduler::current_thread_id();
                        let alias: &[u8] = if hit_dm { b"DM" } else { b"KSTACK" };
                        {
                            let mut buf = [0u8; 192];
                            let mut k = 0;
                            put_bytes(&mut buf, &mut k, b"PF-WPROT-HIT: alias=");
                            put_bytes(&mut buf, &mut k, alias);
                            put_bytes(&mut buf, &mut k, b" cr2=");
                            put_hex_u64(&mut buf, &mut k, cr2);
                            put_bytes(&mut buf, &mut k, b" rip=");
                            put_hex_u64(&mut buf, &mut k, rip);
                            put_bytes(&mut buf, &mut k, b" cpu=");
                            put_dec_u64(&mut buf, &mut k, cpu_id as u64);
                            put_bytes(&mut buf, &mut k, b" tid=");
                            put_dec_u64(&mut buf, &mut k, tid as u64);
                            put_bytes(&mut buf, &mut k, b" cs=");
                            put_hex_u64(&mut buf, &mut k, frame.cs());
                            put_bytes(&mut buf, &mut k, b" ec=");
                            put_hex_u64(&mut buf, &mut k, ec);
                            put_byte(&mut buf, &mut k, b'\n');
                            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                        }
                        let boot_pml4 = {
                            let cr3: u64;
                            unsafe { core::arch::asm!("mov {0}, cr3", out(reg) cr3, options(nomem, nostack)); }
                            (cr3 & !0xFFF) as usize
                        };
                        crate::arch::x86_64::mm::set_pte_writable(
                            boot_pml4, cr2_page as usize, true,
                        );
                        return validate_iretq_frame(frame_sp, frame_sp, 14);
                    }
                }
            }
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

        // TLB shootdown IPI (vector 0xFC).  Sent by `broadcast_tlb_flush`
        // after demoting shared page tables (PHYS_DIRECT_MAP gigapages).
        // Reload CR3 to drop all non-global TLB entries so the receiving
        // CPU walks the new PT and observes any leaf wprot.
        0xFC => {
            super::lapic::TLB_FLUSH_RECV_COUNT
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            unsafe {
                core::arch::asm!(
                    "mov {tmp}, cr3",
                    "mov cr3, {tmp}",
                    tmp = out(reg) _,
                    options(nostack, preserves_flags),
                );
            }
            super::lapic::eoi();
            return validate_iretq_frame(frame_sp, frame_sp, 0xFC);
        }

        // Other IRQs (33-47).
        33..=47 => {
            let irq = (vector - 32) as u8;
            if !crate::io::irq_dispatch::handle_irq(irq as u32) {
                let mut buf = [0u8; 48];
                let mut k = 0;
                put_bytes(&mut buf, &mut k, b"Unhandled IRQ ");
                put_dec_u64(&mut buf, &mut k, irq as u64);
                put_byte(&mut buf, &mut k, b'\n');
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            if super::ioapic::available() {
                super::lapic::eoi();
            } else {
                super::pic::send_eoi(irq);
            }
        }

        _ => {
            let mut buf = [0u8; 64];
            let mut k = 0;
            put_bytes(&mut buf, &mut k, b"Unhandled interrupt vector ");
            put_dec_u64(&mut buf, &mut k, vector as u64);
            put_byte(&mut buf, &mut k, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
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
        // #235: route the diagnostic PT walk through PHYS_DIRECT_MAP so
        // the handler doesn't re-fault when the kernel #PFs at a low VA
        // after the PML4[0] identity unmap.
        let cr3_pa = (cr3 & !0xFFF) as usize;
        let pml4_kva = crate::mm::page::phys_to_kva(cr3_pa);
        let pml4_e = unsafe { *((pml4_kva + ((cr2 >> 39) & 0x1FF) as usize * 8) as *const u64) };
        let pdpt_e = if pml4_e & 1 != 0 {
            let pdpt_pa = (pml4_e & 0x000F_FFFF_FFFF_F000) as usize;
            let pdpt_kva = crate::mm::page::phys_to_kva(pdpt_pa);
            unsafe { *((pdpt_kva + ((cr2 >> 30) & 0x1FF) as usize * 8) as *const u64) }
        } else { 0 };
        let pd_e = if pdpt_e & 1 != 0 {
            let pd_pa = (pdpt_e & 0x000F_FFFF_FFFF_F000) as usize;
            let pd_kva = crate::mm::page::phys_to_kva(pd_pa);
            unsafe { *((pd_kva + ((cr2 >> 21) & 0x1FF) as usize * 8) as *const u64) }
        } else { 0 };
        let pt_e = if pd_e & 1 != 0 {
            let pt_pa = (pd_e & 0x000F_FFFF_FFFF_F000) as usize;
            let pt_kva = crate::mm::page::phys_to_kva(pt_pa);
            unsafe { *((pt_kva + ((cr2 >> 12) & 0x1FF) as usize * 8) as *const u64) }
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

        // Replaced dump_atomic! (which uses format_args!() internally and
        // had ~58 args) with atomic put_* into a stack buffer.  Boot
        // 11amfsq3243 captured the Pattern A cascade: original PF →
        // x86_exception_handler → dump_atomic → wild RIP=0x4 fetch.
        // The format_args Argument array (~58 × 16 B = ~928 B of stack
        // temporaries) overlapped caller frame slots, corrupting the
        // print-path dispatch.  Atomic put_* avoids the temporaries.
        {
            let mut buf = [0u8; 2048];
            let mut k = 0;
            put_bytes(&mut buf, &mut k, b"Kernel #PF at RIP=");
            put_hex_u64(&mut buf, &mut k, frame.rip());
            put_bytes(&mut buf, &mut k, b" CR2=");
            put_hex_u64(&mut buf, &mut k, cr2);
            put_bytes(&mut buf, &mut k, b" error=");
            put_hex_u64(&mut buf, &mut k, error);
            put_bytes(&mut buf, &mut k, b" cpu=");
            put_dec_u64(&mut buf, &mut k, cpu as u64);
            put_bytes(&mut buf, &mut k, b" cr3=");
            put_hex_u64(&mut buf, &mut k, cr3);
            put_bytes(&mut buf, &mut k, b" pml4_e=");
            put_hex_u64(&mut buf, &mut k, pml4_e);
            put_bytes(&mut buf, &mut k, b" pdpt_e=");
            put_hex_u64(&mut buf, &mut k, pdpt_e);
            put_bytes(&mut buf, &mut k, b" pd_e=");
            put_hex_u64(&mut buf, &mut k, pd_e);
            put_bytes(&mut buf, &mut k, b" pt_e=");
            put_hex_u64(&mut buf, &mut k, pt_e);
            put_bytes(&mut buf, &mut k, b"\n  rsp=");
            put_hex_u64(&mut buf, &mut k, frame.rsp());
            put_bytes(&mut buf, &mut k, b" rbp=");
            put_hex_u64(&mut buf, &mut k, frame.rbp());
            put_bytes(&mut buf, &mut k, b" cs=");
            put_hex_u64(&mut buf, &mut k, frame.cs());
            put_bytes(&mut buf, &mut k, b" ss=");
            put_hex_u64(&mut buf, &mut k, frame.ss());
            put_bytes(&mut buf, &mut k, b" rflags=");
            put_hex_u64(&mut buf, &mut k, frame.rflags());
            // GPR block (4 per line).
            let gprs: [(&[u8], u64); 14] = [
                (b"\n  rax=", frame.rax()), (b" rbx=", frame.rbx()),
                (b" rcx=", frame.rcx()), (b" rdx=", frame.rdx()),
                (b"\n  rsi=", frame.rsi()), (b" rdi=", frame.rdi()),
                (b" r8=",  frame.r8()),  (b" r9=",  frame.r9()),
                (b"\n  r10=", frame.r10()), (b" r11=", frame.r11()),
                (b" r12=", frame.r12()), (b" r13=", frame.r13()),
                (b"\n  r14=", frame.r14()), (b" r15=", frame.r15()),
            ];
            for (label, val) in gprs {
                put_bytes(&mut buf, &mut k, label);
                put_hex_u64(&mut buf, &mut k, val);
            }
            // stk[0..16] in 4-quad rows.
            for row in 0..4 {
                let b = row * 4;
                put_bytes(&mut buf, &mut k, b"\n  stk[");
                put_dec_u64(&mut buf, &mut k, b as u64);
                put_bytes(&mut buf, &mut k, b"..");
                put_dec_u64(&mut buf, &mut k, (b + 4) as u64);
                put_bytes(&mut buf, &mut k, b"]=");
                for j in 0..4 {
                    if j > 0 { put_byte(&mut buf, &mut k, b' '); }
                    put_hex_u64(&mut buf, &mut k, stack_words[b + j]);
                }
            }
            // below[1..4] and below[5..8].
            put_bytes(&mut buf, &mut k, b"\n  below[1..4]=");
            for j in 0..4 {
                if j > 0 { put_byte(&mut buf, &mut k, b' '); }
                put_hex_u64(&mut buf, &mut k, stack_words_below[j]);
            }
            put_bytes(&mut buf, &mut k, b"\n  below[5..8]=");
            for j in 4..8 {
                if j > 4 { put_byte(&mut buf, &mut k, b' '); }
                put_hex_u64(&mut buf, &mut k, stack_words_below[j]);
            }
            put_bytes(&mut buf, &mut k, b"\n  backtrace=");
            for j in 0..6 {
                if j > 0 { put_byte(&mut buf, &mut k, b' '); }
                put_hex_u64(&mut buf, &mut k, backtrace[j]);
            }
            put_byte(&mut buf, &mut k, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
        }
        // #216 Phase 3 follow-up: wild-RIP byte-decomposition probe.
        // When the kernel-mode #PF was caused by an instr-fetch on a
        // bogus RIP (error bit 4 = I/D set), the popped-from slot at
        // `frame.rsp() - 8` held the wild value.  Today's 4-multi
        // survey (boots 3406/3407) showed RIPs with structure: lower
        // 32 bits = a real kernel-text offset, upper 32 bits = 0.
        // Log the slot's byte breakdown so the next investigation can
        // confirm the upper4-zero hypothesis (a partial 32-bit write
        // into a zero-initialized kstack slot) across more samples.
        if (error & (1 << 4)) != 0 {
            let mut buf2 = [0u8; 192];
            let mut k = 0;
            let popped_slot_addr = frame.rsp().wrapping_sub(8);
            let popped: u64 = if (popped_slot_addr & 0xffffff8000000000) == 0xfffffe0000000000 {
                unsafe { *(popped_slot_addr as *const u64) }
            } else {
                0xdeadbeefcafef00d
            };
            let upper4 = (popped >> 32) as u32;
            let lower4 = popped as u32;
            put_bytes(&mut buf2, &mut k, b"  PF-INSTRFETCH-RET-SLOT: addr=");
            put_hex_u64(&mut buf2, &mut k, popped_slot_addr);
            put_bytes(&mut buf2, &mut k, b" val=");
            put_hex_u64(&mut buf2, &mut k, popped);
            put_bytes(&mut buf2, &mut k, b" upper4=");
            put_hex_u64(&mut buf2, &mut k, upper4 as u64);
            put_bytes(&mut buf2, &mut k, b" lower4=");
            put_hex_u64(&mut buf2, &mut k, lower4 as u64);
            put_bytes(&mut buf2, &mut k, b" upper4_zero=");
            put_bytes(&mut buf2, &mut k, if upper4 == 0 { b"YES" } else { b"NO" });
            // If the lower-4 + kernel base looks like a plausible kernel
            // text VA, hint at it for the post-mortem grep.
            let kernel_base: u64 = 0xffffffff80000000;
            let candidate = kernel_base | (lower4 as u64);
            put_bytes(&mut buf2, &mut k, b" lower4_as_kvma=");
            put_hex_u64(&mut buf2, &mut k, candidate);
            put_byte(&mut buf2, &mut k, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(&buf2[..k.min(buf2.len())]);
        }
        loop {
            core::hint::spin_loop();
        }
    }
    let aspace_id = crate::sched::current_aspace_id();
    if aspace_id == 0 {
        let mut buf = [0u8; 128];
        let mut k = 0;
        put_bytes(&mut buf, &mut k, b"User #PF with no address space: CR2=");
        put_hex_u64(&mut buf, &mut k, cr2);
        put_bytes(&mut buf, &mut k, b" RIP=");
        put_hex_u64(&mut buf, &mut k, frame.rip());
        put_byte(&mut buf, &mut k, b'\n');
        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
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
            let tid_u = crate::sched::scheduler::current_thread_id();
            let task_u = crate::sched::scheduler::thread_ref(tid_u).task_id;
            let rip_u = frame.rip();
            let rsp_u = frame.rsp();
            let mut buf = [0u8; 192];
            let mut k = 0;
            put_bytes(&mut buf, &mut k, b"Unhandled #PF: CR2=");
            put_hex_u64(&mut buf, &mut k, cr2);
            put_bytes(&mut buf, &mut k, b" RIP=");
            put_hex_u64(&mut buf, &mut k, rip_u);
            put_bytes(&mut buf, &mut k, b" RSP=");
            put_hex_u64(&mut buf, &mut k, rsp_u);
            put_bytes(&mut buf, &mut k, b" error=");
            put_hex_u64(&mut buf, &mut k, error);
            put_bytes(&mut buf, &mut k, b" tid=");
            put_dec_u64(&mut buf, &mut k, tid_u as u64);
            put_bytes(&mut buf, &mut k, b" task=");
            put_dec_u64(&mut buf, &mut k, task_u as u64);
            put_byte(&mut buf, &mut k, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
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
            {
                let mut buf = [0u8; 192];
                let mut k = 0;
                put_bytes(&mut buf, &mut k, b"  STACK[0..8]@RSP:");
                for w in &sw {
                    put_byte(&mut buf, &mut k, b' ');
                    put_hex_u64(&mut buf, &mut k, *w);
                }
                put_byte(&mut buf, &mut k, b'\n');
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            let mut rbp = frame.rbp();
            for f in 0..6 {
                if rbp < 0x1000 { break; }
                let saved_rbp = match crate::arch::x86_64::coredump::safe_read_user_u64(rbp) {
                    Some(v) => v, None => break,
                };
                let saved_rip = match crate::arch::x86_64::coredump::safe_read_user_u64(rbp.wrapping_add(8)) {
                    Some(v) => v, None => break,
                };
                {
                    let mut buf = [0u8; 96];
                    let mut k = 0;
                    put_bytes(&mut buf, &mut k, b"  FRAME[");
                    put_dec_u64(&mut buf, &mut k, f as u64);
                    put_bytes(&mut buf, &mut k, b"]: rbp=");
                    put_hex_u64(&mut buf, &mut k, saved_rbp);
                    put_bytes(&mut buf, &mut k, b" caller_rip=");
                    put_hex_u64(&mut buf, &mut k, saved_rip);
                    put_byte(&mut buf, &mut k, b'\n');
                    crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                }
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
    // #229 CORRUPTED-FRAME early signal: if CS or SS look bogus (high bits
    // set, or sentinel "not a legal selector" values), log a compact
    // signature BEFORE the full dump_atomic! — that text can get
    // scribbled by interleaving prints or by the wild-RIP IST stack
    // overlap, but this one short line through dump_atomic! lands first.
    // Valid x86_64 selectors fit in 16 bits and use known GDT indices
    // (0x08, 0x10, 0x1b, 0x23, 0x33, 0x2b).  Anything with high bits set
    // or > 0xffff is a smoking gun for iretq-frame corruption.
    let cs_v = frame.cs();
    let ss_v = frame.ss();
    let cs_bogus = cs_v > 0xffff || (cs_v != 0 && cs_v != 0x08 && cs_v != 0x10
        && cs_v != 0x1b && cs_v != 0x23 && cs_v != 0x33);
    let ss_bogus = ss_v > 0xffff || (ss_v != 0 && ss_v != 0x10 && ss_v != 0x18
        && ss_v != 0x1b && ss_v != 0x23 && ss_v != 0x2b && ss_v != 0x33);
    if cs_bogus || ss_bogus {
        let mut buf = [0u8; 192];
        let mut k = 0;
        put_bytes(&mut buf, &mut k, b"CORRUPTED-FRAME: vec=");
        put_bytes(&mut buf, &mut k, name.as_bytes());
        put_bytes(&mut buf, &mut k, b" cs=");
        put_hex_u64(&mut buf, &mut k, cs_v);
        put_bytes(&mut buf, &mut k, b" ss=");
        put_hex_u64(&mut buf, &mut k, ss_v);
        put_bytes(&mut buf, &mut k, b" rip=");
        put_hex_u64(&mut buf, &mut k, frame.rip());
        put_bytes(&mut buf, &mut k, b" rsp=");
        put_hex_u64(&mut buf, &mut k, frame.rsp());
        put_bytes(&mut buf, &mut k, b" tid=");
        put_dec_u64(&mut buf, &mut k, crate::sched::scheduler::current_thread_id() as u64);
        put_byte(&mut buf, &mut k, b'\n');
        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
    }
    // Coalesced atomic dump — peer CPUs cannot interleave this block.
    // Converted from dump_atomic! to atomic put_* (Pattern A fix, same
    // family as commit 0d50618 kernel-#PF-dump conversion).
    {
        let mut buf = [0u8; 512];
        let mut k = 0;
        put_bytes(&mut buf, &mut k, b"EXCEPTION: ");
        put_bytes(&mut buf, &mut k, name.as_bytes());
        put_bytes(&mut buf, &mut k, b" at RIP=");
        put_hex_u64(&mut buf, &mut k, frame.rip());
        put_bytes(&mut buf, &mut k, b" error_code=");
        put_hex_u64(&mut buf, &mut k, frame.error_code());
        put_bytes(&mut buf, &mut k, b" tid=");
        put_dec_u64(&mut buf, &mut k, crate::sched::scheduler::current_thread_id() as u64);
        put_byte(&mut buf, &mut k, b' ');
        put_bytes(&mut buf, &mut k, if is_user { b"(user)" } else { b"(KERNEL)" });
        let row1: [(&[u8], u64); 4] = [
            (b"\n  RAX=", frame.rax()), (b" RBX=", frame.rbx()),
            (b" RCX=", frame.rcx()), (b" RDX=", frame.rdx()),
        ];
        for (label, val) in row1 {
            put_bytes(&mut buf, &mut k, label);
            put_hex_u64(&mut buf, &mut k, val);
        }
        let row2: [(&[u8], u64); 4] = [
            (b"\n  RSP=", frame.rsp()), (b" RBP=", frame.rbp()),
            (b" RSI=", frame.rsi()), (b" RDI=", frame.rdi()),
        ];
        for (label, val) in row2 {
            put_bytes(&mut buf, &mut k, label);
            put_hex_u64(&mut buf, &mut k, val);
        }
        let row3: [(&[u8], u64); 3] = [
            (b"\n  CS=", frame.cs()), (b" RFLAGS=", frame.rflags()),
            (b" SS=", frame.ss()),
        ];
        for (label, val) in row3 {
            put_bytes(&mut buf, &mut k, label);
            put_hex_u64(&mut buf, &mut k, val);
        }
        put_byte(&mut buf, &mut k, b'\n');
        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
    }
    // Kernel-fault stack dump: 16 quads from RSP.  At #UD time, an indirect
    // call through a corrupted function pointer has just pushed its return
    // address (the instruction after the bad `call *reg`) to [RSP], then
    // jumped to the bad target — which faults here.  So [RSP] reveals the
    // call site that dispatched to RIP={0,3,7,…}.  Bounds-check RSP first
    // because reads through a bogus pointer would triple-fault.
    if !is_user {
        let rsp = frame.rsp();
        // #230: accept kstack region (0xfffffe___) too — was rejecting all
        // dumps because exception RSP is in kstack VA range, not low PA.
        let rsp_in_kstack = rsp >= 0xfffffe0000000000 && rsp < 0xffffffff80000000;
        if rsp != 0 && (rsp & 7) == 0 && (rsp < 0x8000_0000 || rsp_in_kstack) {
            let mut sw = [0u64; 16];
            unsafe {
                for i in 0..16 {
                    let p = rsp.wrapping_add((i * 8) as u64) as *const u64;
                    sw[i] = core::ptr::read_volatile(p);
                }
            }
            for row in 0..2 {
                let b = row * 8;
                let mut buf = [0u8; 192];
                let mut k = 0;
                put_bytes(&mut buf, &mut k, b"  KSTACK[");
                put_dec_u64(&mut buf, &mut k, b as u64);
                put_bytes(&mut buf, &mut k, b"..");
                put_dec_u64(&mut buf, &mut k, (b + 8) as u64);
                put_bytes(&mut buf, &mut k, b"]@RSP+");
                put_hex_u64(&mut buf, &mut k, (b * 8) as u64);
                put_byte(&mut buf, &mut k, b':');
                for off in 0..8 {
                    put_byte(&mut buf, &mut k, b' ');
                    put_hex_u64(&mut buf, &mut k, sw[b + off]);
                }
                put_byte(&mut buf, &mut k, b'\n');
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            // #233 RBP backtrace extended to ~10 frames + accept kstack VAs.
            // Each frame: [RBP] = caller RBP, [RBP+8] = caller RIP.
            // Bounds: accept low identity OR kstack region (0xfffffe___).
            let mut rbp = frame.rbp();
            for f in 0..10 {
                let rbp_ok_low = rbp >= 0x1000 && rbp < 0x8000_0000;
                let rbp_ok_kstack = rbp >= 0xfffffe0000000000
                    && rbp < 0xffffffff80000000;
                if !(rbp_ok_low || rbp_ok_kstack) || (rbp & 7) != 0 {
                    break;
                }
                let saved_rbp = unsafe { core::ptr::read_volatile(rbp as *const u64) };
                let saved_rip = unsafe {
                    core::ptr::read_volatile(rbp.wrapping_add(8) as *const u64)
                };
                {
                    let mut buf = [0u8; 96];
                    let mut k = 0;
                    put_bytes(&mut buf, &mut k, b"  KFRAME[");
                    put_dec_u64(&mut buf, &mut k, f as u64);
                    put_bytes(&mut buf, &mut k, b"]: rbp=");
                    put_hex_u64(&mut buf, &mut k, saved_rbp);
                    put_bytes(&mut buf, &mut k, b" caller_rip=");
                    put_hex_u64(&mut buf, &mut k, saved_rip);
                    put_byte(&mut buf, &mut k, b'\n');
                    crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                }
                if saved_rbp == 0 || saved_rbp <= rbp {
                    break;
                }
                rbp = saved_rbp;
            }
            // #233 RAX→Thread lookup: scan tids 1..100 for any matching
            // pointer in RAX/RBX/RDI/RSI/RBP/R12-R15.  Widened to ALL
            // canonical kernel-VA candidates (the slab-range pre-gate
            // missed the recurring linux_srv crash because the
            // CORRUPTED value isn't in slab range — but we still want
            // to know whether the CLEAN value should have been there).
            {
                let regs: [(u64, &str); 8] = [
                    (frame.rax(), "rax"),
                    (frame.rbx(), "rbx"),
                    (frame.rdi(), "rdi"),
                    (frame.rsi(), "rsi"),
                    (frame.rbp(), "rbp"),
                    (frame.r12(), "r12"),
                    (frame.r13(), "r13"),
                    (frame.r14(), "r14"),
                ];
                for (val, name) in regs {
                    if val < 0xffff800000000000 {
                        continue; // not canonical kernel addr
                    }
                    for tid in 1u32..100u32 {
                        let tp = crate::sched::scheduler::THREAD_TABLE.get(tid);
                        if !tp.is_null() && (tp as u64) == val {
                            let mut buf = [0u8; 96];
                            let mut k = 0;
                            put_bytes(&mut buf, &mut k, b"  REG-IS-THREAD: ");
                            put_bytes(&mut buf, &mut k, name.as_bytes());
                            put_byte(&mut buf, &mut k, b'=');
                            put_hex_u64(&mut buf, &mut k, val);
                            put_bytes(&mut buf, &mut k, b" = THREAD_TABLE[");
                            put_dec_u64(&mut buf, &mut k, tid as u64);
                            put_bytes(&mut buf, &mut k, b"]\n");
                            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                            break;
                        }
                    }
                }
            }
            // #233 iretq-frame slot probe.  x86_64 in 64-bit mode ALWAYS
            // pushes 5 quads (RIP/CS/RFLAGS/RSP/SS) regardless of CPL
            // change — so frame.rsp() points at the LATEST iretq frame,
            // whether this is the outermost (ring-3→0) frame or a
            // nested ring-0→0 fault during handler execution.
            //
            // For outermost user→kernel: CS should be user 0x1b/0x23.
            // For nested kernel→kernel: CS should be kernel 0x08.
            // Anything else in slot[1] is corruption — possibly visible
            // only for nested frames (variable VA), which is why the
            // tid-34 DR0 watchpoint (fixed-VA outermost frame) didn't
            // fire while these probes did.
            //
            // Also flag whether this is outermost vs nested by checking
            // whether RSP is near kstack_top (outermost) or lower (nested).
            {
                let rsp = frame.rsp();
                let rsp_in_kstack = rsp >= 0xfffffe0000000000 && rsp < 0xffffffff80000000;
                if rsp_in_kstack && (rsp & 7) == 0 {
                    unsafe {
                        let p = rsp as *const u64;
                        let s0 = core::ptr::read_volatile(p);
                        let s1 = core::ptr::read_volatile(p.add(1));
                        let s2 = core::ptr::read_volatile(p.add(2));
                        let s3 = core::ptr::read_volatile(p.add(3));
                        let s4 = core::ptr::read_volatile(p.add(4));
                        let cs_legit = s1 == 0x08 || s1 == 0x10 || s1 == 0x1b
                            || s1 == 0x23 || s1 == 0x2b || s1 == 0x33;
                        // Outermost if RSP within 256 B of nearest 16 KiB
                        // boundary above (kstack_top is at 16 KiB-aligned VAs).
                        let kstack_top_approx = (rsp + 0x4000) & !0x3FFF;
                        let outermost = (kstack_top_approx - rsp) <= 256;
                        // What the CALLING ring should be for this iretq.
                        // frame.cs() gives the CPU's current CS at handler
                        // entry (= kernel 0x08 for kernel-mode faults).
                        // The iretq frame's CS slot[1] should match the
                        // PREVIOUS CS (whatever was running when fault fired).
                        let cur_cs = frame.cs();
                        let cur_ring = (cur_cs & 3) as u32;
                        let mut buf = [0u8; 256];
                        let mut k = 0;
                        put_bytes(&mut buf, &mut k, b"  IRETQ-FRAME @RSP: RIP=");
                        put_hex_u64(&mut buf, &mut k, s0);
                        put_bytes(&mut buf, &mut k, b" CS=");
                        put_hex_u64(&mut buf, &mut k, s1);
                        if !cs_legit { put_bytes(&mut buf, &mut k, b" GARBAGE"); }
                        put_bytes(&mut buf, &mut k, b" RFLAGS=");
                        put_hex_u64(&mut buf, &mut k, s2);
                        put_bytes(&mut buf, &mut k, b" RSP=");
                        put_hex_u64(&mut buf, &mut k, s3);
                        put_bytes(&mut buf, &mut k, b" SS=");
                        put_hex_u64(&mut buf, &mut k, s4);
                        put_bytes(&mut buf, &mut k, b" (cur_cs=");
                        put_hex_u64(&mut buf, &mut k, cur_cs);
                        put_bytes(&mut buf, &mut k, b" ring=");
                        put_dec_u64(&mut buf, &mut k, cur_ring as u64);
                        put_byte(&mut buf, &mut k, b' ');
                        put_bytes(&mut buf, &mut k, if outermost { b"outermost" } else { b"nested" });
                        put_bytes(&mut buf, &mut k, b")\n");
                        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                    }
                }
            }
        } else {
            let mut buf = [0u8; 96];
            let mut k = 0;
            put_bytes(&mut buf, &mut k, b"  KSTACK skipped: RSP=");
            put_hex_u64(&mut buf, &mut k, rsp);
            put_bytes(&mut buf, &mut k, b" out of kernel range / misaligned\n");
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
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
            let mut buf = [0u8; 256];
            let mut k = 0;
            put_bytes(&mut buf, &mut k, b"  STACK[");
            put_dec_u64(&mut buf, &mut k, b as u64);
            put_bytes(&mut buf, &mut k, b"..");
            put_dec_u64(&mut buf, &mut k, (b + 8) as u64);
            put_bytes(&mut buf, &mut k, b"]@RSP+");
            put_hex_u64(&mut buf, &mut k, (b * 8) as u64);
            put_bytes(&mut buf, &mut k, b": ");
            for j in 0..8 {
                if j > 0 { put_byte(&mut buf, &mut k, b' '); }
                put_hex_u64(&mut buf, &mut k, sw[b + j]);
            }
            put_byte(&mut buf, &mut k, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
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
                let mut buf = [0u8; 64];
                let mut k = 0;
                put_bytes(&mut buf, &mut k, b"  CODE@RSP+");
                put_hex_u64(&mut buf, &mut k, (i * 8) as u64);
                put_bytes(&mut buf, &mut k, b": ");
                put_hex_u64(&mut buf, &mut k, v);
                put_byte(&mut buf, &mut k, b'\n');
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                printed += 1;
                if printed >= 16 { break; }
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
            let mut buf = [0u8; 96];
            let mut k = 0;
            put_bytes(&mut buf, &mut k, b"  FRAME[");
            put_dec_u64(&mut buf, &mut k, f as u64);
            put_bytes(&mut buf, &mut k, b"]: rbp=");
            put_hex_u64(&mut buf, &mut k, saved_rbp);
            put_bytes(&mut buf, &mut k, b" caller_rip=");
            put_hex_u64(&mut buf, &mut k, saved_rip);
            put_byte(&mut buf, &mut k, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
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
