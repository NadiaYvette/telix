//! Scheduler — priority-based round-robin with timer-driven preemption.
//!
//! Context switching works by swapping kernel stack pointers. When a timer
//! IRQ fires, the exception vector saves all registers onto the current
//! thread's kernel stack. If preemption is needed, we save the current SP
//! in the thread's TCB, load the new thread's SP, and the exception return
//! path restores the new thread's registers and `eret`s to it.
//!
//! SMP: Run queues are shared across all CPUs, protected by the scheduler
//! spinlock. Each CPU tracks its own current/idle thread via smp::PerCpuData.
//!
//! Thread and Task data is stored in ART (Adaptive Radix Tree) keyed by ID,
//! with Thread entries slab-allocated (256 bytes) and Task entries page-
//! allocated (~1400 bytes). Per-thread/task atomics are embedded in the
//! Thread/Task structs and accessed via TASK_TABLE/THREAD_TABLE radix
//! page tables for lock-free lookup.

use super::cpumask;
use super::radix::RadixTable;
use super::smp;
use super::task::{GROUPS_INLINE, RLIMIT_COUNT, Rlimit, Task, TaskId};
use super::thread::{BlockReason, Thread, ThreadId, ThreadState};
use crate::arch::trapframe::EXCEPTION_FRAME_SIZE;
use crate::ipc::art::Art;
use crate::mm::page::{self, MMUPAGE_SIZE, PhysAddr};
use crate::mm::{phys, slab};
use crate::sync::SpinLock;
use super::thread::SCHED_NORMAL;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// EEVDF virtual-time constants
// ---------------------------------------------------------------------------

/// Fixed-point scaling factor for virtual time. ~1M gives microsecond-ish
/// granularity in virtual time space with pure integer arithmetic.
const VTIME_UNIT: u64 = 1 << 20;

/// Kernel stack allocation order (0 = 1 page, 1 = 2 pages).
/// 2 pages provides headroom for deep syscall call chains.
// Bumped 1→2 for #208 residual probe (boots 1765/1766/1767).  Doubles
// the per-thread kstack from 128 KiB to 256 KiB.  If the residual wild-
// RIP/wild-INDEX PFs disappear, the corruption depends on tight overlap
// between deep println!/format frames and outer-caller local-variable
// slots — bigger stack creates headroom that masks it.  If they
// persist, the corruption is from a fixed-offset slot reuse pattern
// independent of stack depth.
const KSTACK_ORDER: usize = 4;

/// Kernel stack size in bytes (2^KSTACK_ORDER pages).
/// 2^4 = 16 pages × 4 KiB = 64 KiB, raised from 16 KiB after boot 2511
/// captured an iretq-frame scribble coincident with a serial.rs:445
/// fmt_len-OOB panic — strong evidence of in-handler println pushing
/// the kstack past the 16 KiB envelope.  The VA window is 2 MiB so
/// the larger phys-backed region fits without infra changes.
#[inline]
pub fn kstack_size() -> usize {
    page::page_size() << KSTACK_ORDER
}

/// #208 fix attempt: phys::alloc_pages does NOT zero pages on return.
/// Kstacks were inheriting stale page contents — observed pattern was
/// BIOS-region data (`0xf000ff53...`) at high kstack offsets where the
/// running thread's call stack never reached.  When validate_iretq_frame
/// read parked/transient frame slots above the live stack pointer, it
/// saw that stale data and flagged it as BAD frame corruption.
///
/// Eight kstack alloc sites now call this helper; behavior identical to
/// `alloc_pages(KSTACK_ORDER)` except the page is zeroed before return.
///
/// Phase 5b: result wraps VA base (in KSTACK_REGION) + PA base.
pub struct KStackHandle {
    /// Virtual base address of the kstack (in KSTACK_REGION).
    /// Stored in Thread.stack_base for range checks and TSS RSP0.
    pub va_base: u64,
    /// Physical base address — stored in Thread.stack_phys_base for
    /// phys::free_pages on the deferred-kill path.
    pub pa_base: PhysAddr,
}

impl KStackHandle {
    /// Convenience: returns the VA base as usize (the value to store in
    /// Thread.stack_base).  Callers that need the PA access pa_base
    /// directly.
    #[inline]
    pub fn as_usize(&self) -> usize {
        self.va_base as usize
    }
}

/// Phys-allocator audit: track which 64-KiB phys pages are currently
/// in use as kstacks.  If phys::alloc_pages returns a PA that's still
/// marked live, we have a double-allocation — the bug hypothesis behind
/// the wild-RIP-in-kstack family.  Indexed by `pa >> 16` (page index
/// for a 64 KiB-granularity tracker), sized for 2 GiB of phys.
///
/// Also reused (via `record_pa_alias_check`) to detect alias between
/// kstack PAs and other allocations (e.g. RadixTable L1 pages).  An
/// L1 page at PA P falls into the 64 KiB tracker slot `P >> 16` — if
/// any kstack is currently using that slot, writes through the kstack
/// VA scribble the L1 page contents (which is exactly the
/// THREAD_TABLE[4] corruption signature: DR0 on the identity VA can't
/// see the write because the writer goes through the kstack VA).
// 4 GiB / 64 KiB. Must cover rv64 RAM base 0x80000000..0x100000000
// (slot index = pa>>16 ranges 0x8000..0x10000) — earlier cap of 32768
// silently no-op'd the audit on rv64 because every kstack's slot index
// was exactly at cap.  See #228.
const KSTACK_PA_OWNER_CAP: usize = 65536;
static KSTACK_PA_OWNER: [core::sync::atomic::AtomicU32; KSTACK_PA_OWNER_CAP] = {
    const Z: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    [Z; KSTACK_PA_OWNER_CAP]
};

/// #230: canonical stack_phys_base per tid (for early tids only).
/// Set at create_thread / create_thread_in_task; checked at every read
/// site (kill defer, exit defer, drain).  Divergence proves Thread
/// struct corruption between creation and read.
const SPB_CANONICAL_MAX: usize = 100;
static SPB_CANONICAL: [core::sync::atomic::AtomicU64; SPB_CANONICAL_MAX] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; SPB_CANONICAL_MAX]
};

pub fn spb_set_canonical(tid: u32, pa: u64) {
    if (tid as usize) < SPB_CANONICAL_MAX {
        SPB_CANONICAL[tid as usize].store(pa, core::sync::atomic::Ordering::Release);
    }
}

pub fn spb_check(tid: u32, observed: u64, site: &str) {
    if (tid as usize) >= SPB_CANONICAL_MAX {
        return;
    }
    let canon = SPB_CANONICAL[tid as usize].load(core::sync::atomic::Ordering::Acquire);
    if canon == 0 || canon == observed {
        return;
    }
    static DIVERG_LOG: core::sync::atomic::AtomicU32 =
        core::sync::atomic::AtomicU32::new(0);
    let n = DIVERG_LOG.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if n < 32 {
        crate::println!(
            "SPB-DIVERGED: tid={} site={} canon={:#x} observed={:#x} n={}",
            tid, site, canon, observed, n,
        );
    }
}

/// Query whether `pa`'s 64 KiB slot is currently owned by a kstack.
/// Used by zero_daemon to skip writing to PAs that are in use as
/// kstack pages (the #208 BAD-frame root cause).
pub fn pa_in_kstack_slot(pa: usize) -> bool {
    let slot = pa >> 16;
    if slot >= KSTACK_PA_OWNER_CAP {
        return false;
    }
    KSTACK_PA_OWNER[slot].load(core::sync::atomic::Ordering::Relaxed) != 0
}

/// Check whether `pa` (4 KiB-granularity) falls into a 64 KiB slot
/// currently owned by a kstack, and stamp the slot so a later kstack
/// alloc on the same PA detects the alias via `KSTACK-PA-DOUBLE-ALLOC`.
/// Bidirectional detection: this catches the "radix-first then
/// kstack-on-same-PA" case (via the existing kstack audit) AND the
/// "kstack-first then radix-on-same-PA" case (via PA-ALIAS here).
pub fn record_pa_alias_check(pa: usize, tag: &str) {
    let slot = pa >> 16;
    if slot >= KSTACK_PA_OWNER_CAP {
        return;
    }
    // Read-modify-write: detect prior kstack ownership AND stamp so we
    // catch any later kstack alloc on the same slot.
    let prev = KSTACK_PA_OWNER[slot]
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if prev != 0 {
        static ALIAS_LOG: core::sync::atomic::AtomicU32 =
            core::sync::atomic::AtomicU32::new(0);
        let n = ALIAS_LOG.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if n < 32 {
            crate::println!(
                "PA-ALIAS: tag={} pa={:#x} slot={} prev_count={} n={}",
                tag, pa, slot, prev, n,
            );
        }
    }
    // Note: never decrement — radix L0/L1 pages live forever, so the
    // stamp is permanent.  This means a kstack free + re-alloc on the
    // same slot won't underflow because the radix stamp keeps it >0.
    // The existing KSTACK-PA-FREE-UNDERFLOW check will see this and
    // log; tag it as a known-benign side effect of this probe.
}

/// Audit hook called on every kstack PA alloc/free.  `delta` is +1
/// (alloc) or -1 (free); we track an integer count rather than a boolean
/// so we can detect ANY repeat-alloc, not just double — and so concurrent
/// alloc/free order doesn't matter to the detection.
#[inline]
fn kstack_pa_audit(pa: usize, ksize: usize, delta: i32, tag: &str) {
    // 64 KiB granularity — every page in the kstack gets stamped.
    let base = pa >> 16;
    let pages = (ksize + 0xffff) >> 16;
    for i in 0..pages {
        let slot = base + i;
        if slot >= KSTACK_PA_OWNER_CAP {
            continue;
        }
        if delta > 0 {
            let prev = KSTACK_PA_OWNER[slot]
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if prev != 0 {
                static DUP_LOG: core::sync::atomic::AtomicU32 =
                    core::sync::atomic::AtomicU32::new(0);
                let n = DUP_LOG.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                if n < 32 {
                    crate::println!(
                        "KSTACK-PA-DOUBLE-ALLOC: tag={} pa={:#x} page_idx={} prev_count={} n={}",
                        tag, pa + (i << 16), slot, prev, n,
                    );
                }
            }
        } else {
            let prev = KSTACK_PA_OWNER[slot]
                .fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
            if prev == 0 {
                static UNDER_LOG: core::sync::atomic::AtomicU32 =
                    core::sync::atomic::AtomicU32::new(0);
                let n = UNDER_LOG.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                if n < 16 {
                    // Underflow: freed a PA that wasn't tracked as live.
                    // Either we missed an alloc (instrumentation gap) or
                    // someone freed twice.
                    let bad_pa = pa + (i << 16);
                    crate::println!(
                        "KSTACK-PA-FREE-UNDERFLOW: tag={} pa={:#x} page_idx={} n={}",
                        tag, bad_pa, slot, n,
                    );
                    // #230: chunk 163 (0xA3) is the recurring UNDERFLOW
                    // target across boots 2312/2317/2320.  Dump phys event
                    // ring filtered to this chunk so we can replay the
                    // alloc+free sequence that left the slot count at 0
                    // with stack_phys_base still pointing here.  Once per
                    // underflow site.
                    if n < 4 {
                        let chunk_size = 64 * crate::mm::page::page_size();
                        let chunk_idx = bad_pa / chunk_size;
                        crate::mm::phys::dump_evt_ring_for_chunk(chunk_idx);
                    }
                }
            }
        }
    }
}

/// #233 (2) PF-write-protection probe state.  We pick a deterministic
/// kstack slot VA, write-protect its page at alloc time, and log the
/// first writer (any CPU) via the #PF handler.  After one hit the
/// page is re-enabled so the writer can complete; ARMED stays true so
/// later kstack allocs don't re-protect the page.
pub const PF_WPROT_VA: u64 = 0xfffffe00049ff608;
pub static PF_WPROT_ARMED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
pub static PF_WPROT_DISARMED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// #233 (3) DM-alias of the watched page.  Stored on arm so the PF
/// handler can recognize a write that arrived via the PHYS_DIRECT_MAP
/// (or the legacy PML4[0] identity, since DM and identity overlap RAM).
/// 0 = not armed; non-zero = page-base VA in PHYS_DIRECT_MAP.
pub static PF_WPROT_DM_VA: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static PF_WPROT_DM_DISARMED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// #233 THREAD-VA-ALIAS detector: registry of (PA, slot_idx) of currently
/// alive kstacks.  On every new alloc, scan to see if the PA we just got
/// matches an already-registered live PA — that would mean phys::alloc
/// double-issued and two threads now share a kstack PA via their VAs.
/// Bounded array — covers up to 256 simultaneous kstacks.
const KSTACK_PA_REG_CAP: usize = 256;
static KSTACK_PA_REG: [core::sync::atomic::AtomicU64; KSTACK_PA_REG_CAP] =
    [const { core::sync::atomic::AtomicU64::new(0) }; KSTACK_PA_REG_CAP];

fn kstack_pa_register(pa: u64) {
    use core::sync::atomic::Ordering;
    // Check for alias before claiming a slot.
    for slot in KSTACK_PA_REG.iter() {
        let v = slot.load(Ordering::Acquire);
        if v == pa {
            // Alias detected — PA already registered to a live kstack.
            let mut buf = [0u8; 96];
            let mut n = 0;
            for &b in b"THREAD-VA-ALIAS: pa=0x".iter() {
                if n < buf.len() { buf[n] = b; n += 1; }
            }
            let mut v = pa;
            let mut digits = [0u8; 16];
            let mut k = 0;
            if v == 0 { digits[0] = b'0'; k = 1; }
            else {
                while v > 0 {
                    let d = (v & 0xf) as u8;
                    digits[k] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
                    v >>= 4;
                    k += 1;
                }
            }
            for i in (0..k).rev() {
                if n < buf.len() { buf[n] = digits[i]; n += 1; }
            }
            if n < buf.len() { buf[n] = b'\n'; n += 1; }
            #[cfg(target_arch = "x86_64")]
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..n]);
            #[cfg(target_arch = "aarch64")]
            {
                use crate::arch::aarch64::serial::{
                    fault_buf_for_current_cpu, handler_write_bytes,
                };
                let fbuf = fault_buf_for_current_cpu();
                let nn = n.min(fbuf.len());
                fbuf[..nn].copy_from_slice(&buf[..nn]);
                handler_write_bytes(&fbuf[..nn]);
            }
            #[cfg(target_arch = "riscv64")]
            {
                crate::arch::riscv64::serial::handler_write_bytes(&buf[..n]);
            }
            break;
        }
    }
    // Claim a free slot.
    for slot in KSTACK_PA_REG.iter() {
        if slot
            .compare_exchange(0, pa, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
}

#[allow(dead_code)]
fn kstack_pa_unregister(pa: u64) {
    use core::sync::atomic::Ordering;
    for slot in KSTACK_PA_REG.iter() {
        if slot
            .compare_exchange(pa, 0, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
}

fn alloc_kstack_zeroed() -> Option<KStackHandle> {
    let pa = crate::mm::phys::alloc_pages(KSTACK_ORDER)?;
    let ksize = kstack_size();
    kstack_pa_audit(pa.as_usize(), ksize, 1, "alloc");
    kstack_pa_register(pa.as_usize() as u64);
    // #208 KSTACK_LIVENESS_GUARD: the realloc side of the premature-free
    // race.  The allocator just handed us this phys; no thread has claimed
    // it as a kstack yet (the caller wires stack_phys_base AFTER this
    // returns).  So if ANY live thread already reports stack_phys_base ==
    // new_pa, the page was freed out from under it and re-issued here —
    // the two will alias the same kstack phys.  Detection-only: we still
    // return the page so boot behavior is unchanged.
    #[cfg(target_arch = "x86_64")]
    if KSTACK_LIVENESS_GUARD {
        if let Some((tid, state)) = live_thread_owning_kstack_phys(pa.as_usize(), u32::MAX) {
            report_kstack_phys_realias(pa.as_usize(), tid, state);
        }
    }
    // #208 KSTACK_WRITE_RING tag: action=1, alloc_kstack_zeroed
    // write_bytes(0) of the entire kstack via identity-map PA.  If the
    // phys allocator double-issued this PA (use-after-free), the zero
    // hits the other VA that's still mapped to it — a SCRIBBLE.
    record_kstack_write(pa.as_usize() as u64, ksize as u32, 1);
    // Phase 5b: zero via the existing identity map (still active in
    // PML4[507] direct map) so the zero survives PML4[0] unmap (#235);
    // the subsequent VA window mapping below points to the same RAM.
    //
    // #244 wild-RIP probe (KSTACK_FILL_SENTINEL): when enabled, fill
    // the kstack with a recognizable u64 sentinel pattern instead of
    // zero.  Today's IST 4 captures showed wild RIPs with the pattern
    // upper32=0, lower32=<small structured value>.  The hypothesis is
    // that a Rust function's 32-bit write to a stack-local slot leaves
    // the upper 4 bytes at their zero-fill value; when that slot is
    // later RET'd, the popped pseudo-RIP has structure in the low 32
    // bits and zero in the high 32.  With the sentinel fill, wild RIPs
    // would instead show upper32=0xCAFEBABE which (a) confirms the
    // zero-fill is the upper-byte source, and (b) lets the byte-decomp
    // probe (PF-INSTRFETCH-RET-SLOT) attribute lower32 to a specific
    // 32-bit-write site.
    const KSTACK_FILL_SENTINEL: u64 = 0xCAFEBABE_00000000;
    unsafe {
        let dst = crate::mm::page::phys_to_kva(pa.as_usize()) as *mut u64;
        let n = ksize / 8;
        for i in 0..n {
            dst.add(i).write(KSTACK_FILL_SENTINEL);
        }
    }
    // Phase 5b: reserve a 2 MiB VA window and map the phys pages into
    // its TOP `ksize` bytes.  The remaining VA below the kstack is
    // unmapped — guard zone catches stack underflow.
    #[cfg(target_arch = "x86_64")]
    {
        let va_window = crate::arch::x86_64::mm::alloc_kstack_va_window();
        // map_kstack_window operates at MMU 4 KiB page granularity (the
        // primitive map_single_mmupage handles).  Telix's page_size is
        // 64 KiB, so we need ksize/4096 calls to cover the whole kstack.
        let num_mmu_pages = ksize / 4096;
        let boot_pml4 = {
            let cr3: u64;
            unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)); }
            (cr3 & !0xFFF) as usize
        };
        let va_top = crate::arch::x86_64::mm::map_kstack_window(
            boot_pml4, va_window, pa.as_usize(), num_mmu_pages,
        )?;
        let va_base = va_top - ksize as u64;
        // #233 (2) PF-WPROT arm: when we allocate the SPECIFIC kstack VA
        // window containing our chosen recurring slot, write-protect
        // the 4 KiB page containing the slot.  Any subsequent write
        // (from any CPU) hits #PF and we log the writer.  Only set
        // ARMED when we actually arm (slot_va within this window).
        #[cfg(target_arch = "x86_64")]
        {
            let slot_va = PF_WPROT_VA;
            if slot_va >= va_base
                && slot_va < va_top
                && !PF_WPROT_ARMED.swap(true, core::sync::atomic::Ordering::AcqRel)
            {
                let boot_pml4 = {
                    let cr3: u64;
                    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)); }
                    (cr3 & !0xFFF) as usize
                };
                let ok = crate::arch::x86_64::mm::set_pte_writable(
                    boot_pml4, (slot_va as usize) & !0xFFF, false,
                );
                if ok {
                    // Cross-CPU shootdown: peers may have walked +
                    // cached this VA from a prior visit on the same
                    // kstack window (recycled PA).  Force them to drop
                    // stale RW entries.
                    crate::arch::x86_64::lapic::broadcast_tlb_flush();
                }
                crate::println!(
                    "PF-WPROT-ARMED: slot_va={:#x} page_base={:#x} ok={}",
                    slot_va, slot_va & !0xFFF, ok,
                );
                // #233 (3) PHYS_DIRECT_MAP alias: same RAM is also reachable
                // via PML4[507] (and PML4[0] identity, overlapping RAM).
                // Compute PA of the slot's 4 KiB page and write-protect it
                // through DM as well — catches writers that bypass the
                // KSTACK_REGION VA.
                let pa_of_slot =
                    pa.as_usize() + (slot_va as usize - va_base as usize);
                let pa_page_base = pa_of_slot & !0xFFF;
                let dm_va_base = crate::arch::x86_64::mm::phys_to_kva(pa_page_base);
                let dm_ok = crate::arch::x86_64::mm::wprot_4k_via_direct_map(
                    boot_pml4, pa_page_base,
                );
                PF_WPROT_DM_VA.store(
                    dm_va_base as u64,
                    core::sync::atomic::Ordering::Release,
                );
                crate::println!(
                    "PF-WPROT-DM-ARMED: pa_page={:#x} dm_va={:#x} ok={}",
                    pa_page_base, dm_va_base, dm_ok,
                );
            }
        }
        // #233 (2): log every kstack VA at alloc time with a sequence
        // counter so we can correlate scribble slots with the (n-th
        // kstack ever allocated) of the matching VA.
        {
            static SEQ: core::sync::atomic::AtomicU32 =
                core::sync::atomic::AtomicU32::new(0);
            let n = SEQ.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if n < 256 {
                use crate::arch::x86_64::serial::{put_byte, put_bytes, put_hex_u64, put_dec_u64};
                let mut buf = [0u8; 128];
                let mut k = 0;
                put_bytes(&mut buf, &mut k, b"KSTACK-ALLOC: seq=");
                put_dec_u64(&mut buf, &mut k, n as u64);
                put_bytes(&mut buf, &mut k, b" va_base=");
                put_hex_u64(&mut buf, &mut k, va_base as u64);
                put_bytes(&mut buf, &mut k, b" va_top=");
                put_hex_u64(&mut buf, &mut k, va_top as u64);
                put_bytes(&mut buf, &mut k, b" pa=");
                put_hex_u64(&mut buf, &mut k, pa.as_usize() as u64);
                put_byte(&mut buf, &mut k, b'\n');
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
            }
        }
        Some(KStackHandle { va_base, pa_base: pa })
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Non-x86: use identity-mapped PA as both va and pa.  Phase 5b
        // x86-only for now.
        Some(KStackHandle { va_base: pa.as_usize() as u64, pa_base: pa })
    }
}

/// Two-level radix table for lockless task pointer lookup.
/// Used by has_port_cap_fast() and SA atomics on the hot path.
pub static TASK_TABLE: RadixTable = RadixTable::new();

/// Two-level radix table for lockless thread pointer lookup.
/// Used by wake_thread(), is_killed(), current_task_id(), etc.
pub static THREAD_TABLE: RadixTable = RadixTable::new();

/// Wrapper for a global ART with interior mutability.
/// Lock-free reads (RCU-safe); writes require holding the corresponding write lock.
pub struct GlobalArt {
    inner: core::cell::UnsafeCell<Art>,
}
unsafe impl Sync for GlobalArt {}
impl GlobalArt {
    const fn new() -> Self {
        Self {
            inner: core::cell::UnsafeCell::new(Art::new()),
        }
    }
    /// Lock-free lookup. Safe without any lock (RCU read-side).
    #[inline]
    pub fn lookup(&self, key: u64) -> Option<usize> {
        unsafe { &*self.inner.get() }.lookup(key)
    }
    /// Lock-free iteration. Safe without any lock (RCU read-side).
    pub fn for_each<F: FnMut(u64, usize)>(&self, f: F) {
        unsafe { &*self.inner.get() }.for_each(f)
    }
    /// Insert. Must hold the corresponding write lock.
    pub fn insert(&self, key: u64, val: usize) -> bool {
        unsafe { &mut *self.inner.get() }.insert(key, val)
    }
    /// Remove. Must hold the corresponding write lock.
    #[allow(dead_code)]
    pub fn remove(&self, key: u64) -> Option<usize> {
        unsafe { &mut *self.inner.get() }.remove(key)
    }
}

/// Global thread ART — lock-free reads (RCU); writes serialized by `SPAWN_LOCK`.
pub static SCHED_THREAD_ART: GlobalArt = GlobalArt::new();
/// Global task ART — lock-free reads (RCU); writes serialized by `SPAWN_LOCK`.
pub static SCHED_TASK_ART: GlobalArt = GlobalArt::new();

// ---------------------------------------------------------------------------
// Sleep queue — sorted singly-linked list of sleeping threads by deadline.
// Replaces O(N) full-ART scan with O(1) tick-check + O(K) wake for K expired.
// Protected by SLEEP_QUEUE_LOCK. Head has the earliest deadline.
// ---------------------------------------------------------------------------

/// Head of the sleep queue (thread ID, u32::MAX = empty).
static SLEEP_QUEUE_HEAD: AtomicU32 = AtomicU32::new(u32::MAX);
/// Lock protecting sleep queue mutations (insert / drain).
static SLEEP_QUEUE_LOCK: SpinLock<()> = SpinLock::new(());

/// Cached earliest alarm deadline (0 = none). Updated by alarm() and check_alarm_timers().
static EARLIEST_ALARM_NS: AtomicU64 = AtomicU64::new(0);
/// Cached earliest interval timer deadline (0 = none). Updated by timer_create and check_interval_timers().
static EARLIEST_INTERVAL_NS: AtomicU64 = AtomicU64::new(0);

/// Maximum idle duration (1 second). Prevents unbounded sleep in case of stale caches.
const MAX_IDLE_NS: u64 = 10_000_000; // 10ms — one tick interval, matches TICK_INTERVAL_NS

/// Sentinel value for on_cpu: thread has been dequeued by percpu_pick_next
/// but the CAS in try_switch hasn't promoted it to a real CPU id yet.
/// Prevents rescue_orphaned_threads from re-enqueuing threads in this
/// transient window (which could cause DOUBLE-SCHED if a third CPU steals
/// the re-enqueued thread before the original CAS completes).
const ON_CPU_PENDING: u32 = u32::MAX - 1;
/// #208 Fix D: intermediate state between Running and PENDING.  Set by the
/// park-side of try_switch (scheduler.rs:4276/4303) when prev is about to be
/// re-enqueued or marked Blocked.  Indicates "this thread is being released
/// but cpu_old is still using its kstack."  Peer CPUs' dispatch CAS
/// only accepts PENDING, so they cannot dispatch a RELEASING thread —
/// closes the migration-handoff race where cpu_old and cpu_new would both
/// hold prev's kstack pages and produce iretq-frame scribbles.  Transitioned
/// to PENDING by `transition_release_to_pending` just before try_switch
/// returns to its asm caller (which then `mov rsp, rax`s off prev's kstack).
const ON_CPU_RELEASING: u32 = u32::MAX - 2;

/// #135 transition-ring action IDs.
pub const TRANS_SET_PENDING: u8 = 1;
pub const TRANS_CAS_OK: u8 = 2;
pub const TRANS_CAS_FAIL: u8 = 3;
#[allow(dead_code)]
pub const TRANS_DESCHED: u8 = 4;
#[allow(dead_code)]
pub const TRANS_WAKE_SET_READY: u8 = 5;

/// #135 set on_cpu=ON_CPU_PENDING with action-tagged transition record.
/// Use this instead of `t.on_cpu.store(ON_CPU_PENDING, Release)` at any
/// site where the thread is transitioning Ready/Blocked → about-to-be-picked.
/// `action_tag`: 5 = WAKE_SET_READY (wake/enqueue path),
///               6 = PARK_SET_PENDING (park_current_for_* deferred store).
#[inline]
pub fn set_on_cpu_pending(tid: ThreadId, action_tag: u8, state: ThreadState) {
    thread_ref(tid).on_cpu.store(ON_CPU_PENDING, Ordering::Release);
    record_trans(tid as u32, action_tag, state, ON_CPU_PENDING);
}

/// #208 Fix D — per-CPU release slot.  Populated by try_switch (via
/// `transition_release_to_pending`) just before returning to its asm
/// caller; drained by `finalize_release_after_stack_switch` invoked from
/// vectors.S AFTER `mov rsp, rax`.  Holds the tid that needs its on_cpu
/// transitioned RELEASING→PENDING once cpu_old has actually left prev's
/// kstack.  0 = no pending release on this CPU.
static RELEASE_SLOT_TID: [core::sync::atomic::AtomicU32; smp::MAX_CPUS] = {
    const Z: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    [Z; smp::MAX_CPUS]
};

/// #208 Fix D Stage 2 — publish prev's tid to the per-CPU release slot.
///
/// Called just before each post-park-side return in try_switch.  Does
/// NOT itself transition on_cpu RELEASING→PENDING; that transition is
/// done by `finalize_release_after_stack_switch` after vectors.S's
/// `mov rsp, rax` has actually moved cpu_old off prev's kstack.
///
/// Until finalize runs, peer CPUs that observe RELEASING fail the
/// dispatch CAS (which expects PENDING) and yield to idle — naturally
/// retrying on the next tick when finalize has completed.
#[inline]
pub fn transition_release_to_pending(prev_id: ThreadId) {
    let cpu = smp::cpu_id() as usize;
    if cpu < smp::MAX_CPUS {
        RELEASE_SLOT_TID[cpu].store(
            prev_id as u32,
            core::sync::atomic::Ordering::Release,
        );
    }
}

/// #208 Fix D Stage 2 — drain the per-CPU release slot and transition
/// the stashed tid's on_cpu RELEASING→PENDING.
///
/// Called from vectors.S asm postlude immediately after `mov rsp, rax`.
/// By this point, cpu_old's RSP has moved off prev's kstack onto next's
/// kstack — it is safe for peer CPUs to dispatch prev.  Publishing
/// PENDING here is the precise "kstack released" handoff.
///
/// CAS protects against races with paths that also transition the slot
/// (e.g., a backstop drain at exception-handler entry).
#[unsafe(no_mangle)]
pub extern "C" fn finalize_release_after_stack_switch() {
    let cpu = smp::cpu_id() as usize;
    if cpu >= smp::MAX_CPUS {
        return;
    }
    let tid = RELEASE_SLOT_TID[cpu].swap(0, core::sync::atomic::Ordering::Acquire);
    if tid != 0 {
        let _ = thread_ref(tid).on_cpu.compare_exchange(
            ON_CPU_RELEASING,
            ON_CPU_PENDING,
            core::sync::atomic::Ordering::Release,
            core::sync::atomic::Ordering::Relaxed,
        );
    }
    // #208 defensive TSS.RSP0 sync (Path C).  We just landed on next's
    // kstack.  If any earlier code path changed current_thread without
    // pairing it with update_kernel_stack, this CPU's TSS.RSP0 still
    // points at the previous thread's kstack — the exact bug captured
    // by RSP0-MISMATCH in boot 1706.  Re-set TSS.RSP0 unconditionally
    // here so a subsequent user→kernel transition pushes onto the
    // correct kstack.  Logged as DEFENSIVE-RSP0-FIX when the value
    // would have been stale; bounded to avoid log flood.
    //
    // This is a stopgap until every current_thread.store callsite is
    // audited (option A) or the pair is centralized in a helper
    // (option B).
    #[cfg(target_arch = "x86_64")]
    {
        let pcpu = smp::current();
        let current_tid = pcpu.current_thread.load(Ordering::Relaxed) as u32;
        let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed) as u32;
        if current_tid != idle_id {
            let t = thread_ref(current_tid);
            let sb = t.stack_base as u64;
            if sb != 0 {
                let expected = sb + kstack_size() as u64;
                let actual = crate::arch::x86_64::gdt::get_rsp0();
                if actual != expected {
                    static FIX_LOG: core::sync::atomic::AtomicU32 =
                        core::sync::atomic::AtomicU32::new(0);
                    let n = FIX_LOG.fetch_add(1, Ordering::Relaxed);
                    if n < 64 {
                        // #233 thin-hex writer: avoid crate::println! here.
                        // The fmt machinery adds 400-600 B of stack per call
                        // and runs on the same kstack as the outer handler —
                        // a contributor to the RET-SCRIBBLE family.  Build
                        // the line manually into a small fixed buffer.
                        let mut buf = [0u8; 160];
                        let mut k = 0usize;
                        fn put(buf: &mut [u8; 160], k: &mut usize, b: u8) {
                            if *k < buf.len() { buf[*k] = b; *k += 1; }
                        }
                        fn put_str(buf: &mut [u8; 160], k: &mut usize, s: &str) {
                            for &b in s.as_bytes() { put(buf, k, b); }
                        }
                        fn put_hex(buf: &mut [u8; 160], k: &mut usize, mut v: u64) {
                            put_str(buf, k, "0x");
                            if v == 0 { put(buf, k, b'0'); return; }
                            let mut digits = [0u8; 16];
                            let mut j = 0;
                            while v > 0 {
                                let d = (v & 0xf) as u8;
                                digits[j] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
                                v >>= 4;
                                j += 1;
                            }
                            for i in (0..j).rev() { put(buf, k, digits[i]); }
                        }
                        fn put_dec_u32(buf: &mut [u8; 160], k: &mut usize, mut v: u32) {
                            if v == 0 { put(buf, k, b'0'); return; }
                            let mut digits = [0u8; 10];
                            let mut j = 0;
                            while v > 0 {
                                digits[j] = b'0' + (v % 10) as u8;
                                v /= 10;
                                j += 1;
                            }
                            for i in (0..j).rev() { put(buf, k, digits[i]); }
                        }
                        put_str(&mut buf, &mut k, "DEFENSIVE-RSP0-FIX: cpu=");
                        put_dec_u32(&mut buf, &mut k, cpu as u32);
                        put_str(&mut buf, &mut k, " tid=");
                        put_dec_u32(&mut buf, &mut k, current_tid);
                        put_str(&mut buf, &mut k, " actual=");
                        put_hex(&mut buf, &mut k, actual);
                        put_str(&mut buf, &mut k, " expected=");
                        put_hex(&mut buf, &mut k, expected);
                        put_str(&mut buf, &mut k, " n=");
                        put_dec_u32(&mut buf, &mut k, n);
                        put(&mut buf, &mut k, b'\n');
                        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k]);
                    }
                    crate::arch::x86_64::gdt::set_rsp0(current_tid, expected);
                }
            }
        }
    }
}

/// #208 root-cause prevention (option B): the only way to set
/// pcpu.current_thread.  Pairs the store with update_kernel_stack
/// so TSS.RSP0 can never drift relative to the running thread.
///
/// Before this helper existed, sites like handoff_to's CAS-fail bail
/// stored current_thread without updating TSS.RSP0, leaving a window
/// where the CPU would push iret frames onto the WRONG thread's
/// kstack on the next user→kernel transition.  See commit f250848.
#[inline]
pub fn set_current_thread(pcpu: &smp::PerCpuData, tid: ThreadId) {
    // #232 self-pcpu guard: update_kernel_stack uses smp::cpu_id() to
    // determine WHICH TSS to write.  If a caller mistakenly passes a
    // peer's pcpu, current_thread on the peer gets updated but its
    // TSS does not.  Verify pcpu corresponds to the current CPU; if
    // not, log + skip the TSS update so we don't corrupt this CPU's
    // TSS with a peer's stack.
    let cpu = smp::cpu_id();
    let expected_pcpu = smp::get(cpu) as *const smp::PerCpuData;
    let actual_pcpu = pcpu as *const smp::PerCpuData;
    if expected_pcpu != actual_pcpu {
        static MISUSE_LOG: core::sync::atomic::AtomicU32 =
            core::sync::atomic::AtomicU32::new(0);
        let n = MISUSE_LOG.fetch_add(1, Ordering::Relaxed);
        if n < 8 {
            crate::println!(
                "SCT-PEER-PCPU: cur_cpu={} pcpu_addr={:p} expected={:p} tid={} n={}",
                cpu, actual_pcpu, expected_pcpu, tid, n,
            );
        }
    }
    // #232 ordering fix: update TSS.RSP0 BEFORE the current_thread.store.
    // Hardware reads TSS.RSP0 on every ring 3→0 transition.  If
    // current_thread is visible to peers but TSS.RSP0 is still the
    // OLD thread's kstack top, a syscall on this CPU lands on the
    // OLD thread's kstack and scribbles its iretq frame.  Reversing
    // the order means: after current_thread is visible, TSS.RSP0 is
    // already correct, so peer-observed (current_thread, TSS) is
    // always consistent.  Periodic TSS-RSP0-AUDIT false positives
    // from the old order disappear with this fix.
    let t = thread_ref(tid);
    let kbase = t.stack_base;
    if kbase != 0 {
        crate::arch::trapframe::update_kernel_stack(
            tid as u32,
            kbase + kstack_size(),
        );
    }
    pcpu.current_thread.store(tid, Ordering::Release);
    record_current_thread_change(cpu, tid as u32);
}

/// #135 record one transition into the per-thread `trans_ring`.  Each
/// entry packs (action, cpu, state, on_cpu_enc, ts_low32) into a u64.
/// `on_cpu_enc`: 0..0xFD = real CPU id, 0xFE = PENDING, 0xFF = MAX.
#[inline]
pub fn record_trans(tid: u32, action: u8, state: ThreadState, on_cpu: u32) {
    let t = thread_ref(tid);
    let cpu = smp::cpu_id() as u8;
    let on_cpu_enc: u8 = if on_cpu == u32::MAX {
        0xFF
    } else if on_cpu == ON_CPU_PENDING {
        0xFE
    } else if on_cpu < 0xFD {
        on_cpu as u8
    } else {
        0xFD
    };
    let ts = (crate::arch::timer::monotonic_ns() & 0xFFFF_FFFF) as u64;
    let entry: u64 = (action as u64)
        | ((cpu as u64) << 8)
        | ((state as u8 as u64) << 16)
        | ((on_cpu_enc as u64) << 24)
        | (ts << 32);
    let pos = (t.trans_pos.fetch_add(1, Ordering::Relaxed) as usize) & 3;
    t.trans_ring[pos].store(entry, Ordering::Relaxed);
}

/// #203 (Thread struct corruption probe — 2026-05-20).
///
/// Validate that a Thread struct's stable fields hold sane values.
/// Catches the corruption family that boot 563 captured: saved_sp set
/// to BIOS-region 32-bit-repeating garbage (`0xf000ff53f000ff53`),
/// saved_sp_source=255 (out of valid 0-5 range).
///
/// Called at key entry points (park_current_for_ipc, try_switch,
/// wake_parked_thread) — fires CLOSER to the time of corruption than
/// the existing BUG: park_ipc check, which only fires when the
/// outgoing thread switches IN to a corrupted thread state.
///
/// Logs to serial only (non-fatal) — boot continues so we can correlate
/// with downstream symptoms (TS-INVARIANT-FAIL, kernel #GP/#UD, etc.).
/// Rate-limited to first 8 fires across all callers (atomic counter).
///
/// Returns true if any anomaly was detected.
#[inline]
pub fn validate_thread_canary(tid: ThreadId, callsite: &str) -> bool {
    use core::sync::atomic::{AtomicU32, Ordering};
    static FAIL_COUNT: AtomicU32 = AtomicU32::new(0);

    if tid == 0 {
        return false; // idle thread — skip
    }
    let t = thread_ref(tid);

    let id_ok = t.id == tid;
    let src = t.saved_sp_source;
    let src_ok = src <= 5;
    let state_byte = t.state as u8;
    let state_ok = state_byte <= 7;
    let on = t.on_cpu.load(Ordering::Relaxed);
    let ncpus = smp::num_cpus() as u32;
    let on_ok = on < ncpus || on == ON_CPU_PENDING || on == ON_CPU_RELEASING || on == u32::MAX;
    let stack_ok = t.stack_base != 0 || tid == 0;
    // #214 magic canary adjacent to saved_sp_source.  If a writer
    // scribbled the mid-region of the Thread struct, this should change
    // too — distinguishes "single-byte targeted reset" from "bulk
    // overwrite" corruption.
    let canary_ok = t.canary_around_source == crate::sched::thread::THREAD_CANARY_MAGIC;

    if id_ok && src_ok && state_ok && on_ok && stack_ok && canary_ok {
        return false;
    }

    let n = FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
    if n < 8 {
        crate::println!(
            "THREAD-CANARY-FAIL @{}: tid={} (n={})",
            callsite, tid, n + 1,
        );
        crate::println!(
            "  id={} (expect={}) state={} src={} on_cpu={:#x} stack_base={:#x} task_id={} canary={:#x} (expect={:#x})",
            t.id, tid, state_byte, src, on, t.stack_base, t.task_id,
            t.canary_around_source, crate::sched::thread::THREAD_CANARY_MAGIC,
        );
        crate::println!(
            "  saved_sp={:#x} ipc_frame_sp={:#x} syscall_frame_sp={:#x}",
            t.saved_sp, t.ipc_frame_sp, t.syscall_frame_sp,
        );
        // Dump trans_ring (last 4 transitions).
        let next_pos = t.trans_pos.load(Ordering::Relaxed) as usize;
        for i in 0..4usize {
            let slot = (next_pos + i) & 3;
            let entry = t.trans_ring[slot].load(Ordering::Relaxed);
            if entry == 0 {
                continue;
            }
            let action = (entry & 0xFF) as u8;
            let cpu_e = ((entry >> 8) & 0xFF) as u8;
            let st_e = ((entry >> 16) & 0xFF) as u8;
            let on_e = ((entry >> 24) & 0xFF) as u8;
            let ts = (entry >> 32) as u32;
            crate::println!(
                "  TRANS[{}]: act={} cpu={} st={} on={} ts={}",
                i, action, cpu_e, st_e, on_e, ts,
            );
        }
    }
    true
}

/// #206 saved_sp last-writer log.
///
/// Boot 572 caught `BUG: try_switch tid=4 saved_sp=0x0 ... source=1`.
/// saved_sp_source=1 says try_switch was the last LEGITIMATE writer of
/// saved_sp_source, but saved_sp itself is 0 — meaning something
/// AFTER try_switch's write cleared saved_sp to 0.  This log records
/// the most recent write to saved_sp for each tid so we can identify
/// the actual writer that produced the 0.
///
/// `SAVED_SP_LAST_VALUE[tid]`: the value written.
/// `SAVED_SP_LAST_META[tid]`: packed (callsite_tag<<0 | cpu<<8 | ts32<<32).
///
/// Capped at 256 tids — matches PER_TID_RESCUE_CAP elsewhere.  Beyond
/// that, the log silently no-ops (the bug surfaces at low tids ≤ 64
/// in observed boots, so 256 is plenty).
const SAVED_SP_LOG_CAP: usize = 256;
static SAVED_SP_LAST_VALUE: [core::sync::atomic::AtomicU64; SAVED_SP_LOG_CAP] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; SAVED_SP_LOG_CAP]
};
static SAVED_SP_LAST_META: [core::sync::atomic::AtomicU64; SAVED_SP_LOG_CAP] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; SAVED_SP_LOG_CAP]
};
/// VA→PA continuity probe: at park-time snapshot, capture the PA backing
/// slot[17] (saved RIP) of the iretq frame.  At dispatch-time FBD slot[17]
/// mismatch, walk PT again and compare.  If PAs differ, the kstack VA
/// window was remapped to a different PA while the thread was parked —
/// reading the live frame sees a different physical page than was
/// written at park.  Eliminates the byte-level scribble hypothesis;
/// confirms the VA aliasing hypothesis.
#[cfg(target_arch = "x86_64")]
static IRETQ_SHADOW_SLOT17_PA: [core::sync::atomic::AtomicU64; SAVED_SP_LOG_CAP] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; SAVED_SP_LOG_CAP]
};
/// Per-tid seqlock guarding the {iretq_shadow_sp, IRETQ_SHADOW_SLOT17_PA}
/// pair.  Boot 11amfsq3179 (commit 8c3369b probe) caught a torn write
/// where iretq_shadow_sp was updated to a new value but
/// IRETQ_SHADOW_SLOT17_PA was stale from a prior snapshot — proving
/// concurrent snapshot updates for the same tid can interleave their
/// stores.  Writer wraps the field updates with seq += 1 / seq += 1
/// (odd while in-progress, even when consistent).  Reader at FBD
/// captures the seq before and after reading; if it changed or was
/// odd, the read was torn and we suppress the SLOT17-VA-PA-REMAP log.
#[cfg(target_arch = "x86_64")]
static IRETQ_SHADOW_SEQ: [core::sync::atomic::AtomicU64; SAVED_SP_LOG_CAP] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; SAVED_SP_LOG_CAP]
};

/// #227 concurrent-snapshot detection.  Post-seqlock survey (boots
/// 3189-3204) still caught REMAP fires — proving two writers
/// simultaneously call snapshot_iretq_shadow for the same tid, which
/// the SeqLock can't catch because both writers bump the seq
/// (odd→even→odd→even) without mutual exclusion of the field writes.
///
/// write_saved_sp takes `&mut Thread`, so this should be impossible
/// under sound Rust — but the persistent fires imply a raw-pointer
/// path bypasses the borrow guard.  This counter increments on
/// snapshot entry and decrements on exit; a value > 1 at entry
/// catches the offending caller pair directly, with the caller
/// location reported via #[track_caller].
#[cfg(target_arch = "x86_64")]
static SNAPSHOT_INFLIGHT: [core::sync::atomic::AtomicU32; SAVED_SP_LOG_CAP] = {
    const Z: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    [Z; SAVED_SP_LOG_CAP]
};

/// Validated write to `Thread.saved_sp`.  Verifies the Thread* address is
/// in SLAB_REGION (PML4[509]) before writing; logs SAVED-SP-WRITE-BAD-THREAD
/// with the caller location if not.  Hypothesis: the wild-RIP / iretq-zero
/// corruption family is rooted in some path writing `thread.saved_sp = sp`
/// where `thread` is a stale/corrupted pointer landing on a kstack frame
/// or radix L1 slot instead of a real Thread struct.  This wrapper catches
/// the bad write AT WRITE TIME with the call-site identified.
#[cold]
#[track_caller]
fn log_saved_sp_out_of_range(tid: u32, new_value: u64, kbase: u64, ksize: u64) {
    // Skip per-CPU idle threads.  Each CPU's pcpu.idle_thread_id
    // is a tid that runs on boot/AP stack — its saved_sp lands in
    // PHYS_DIRECT_MAP or the high-half kernel-data range, not in
    // the allocated kstack window.
    let ncpus = smp::num_cpus() as u32;
    for cpu in 0..ncpus {
        let pcpu = smp::get(cpu);
        if pcpu.idle_thread_id.load(Ordering::Relaxed) == tid {
            return;
        }
    }
    let caller = core::panic::Location::caller();
    static BAD_RANGE_LOG: core::sync::atomic::AtomicU32 =
        core::sync::atomic::AtomicU32::new(0);
    let n = BAD_RANGE_LOG.fetch_add(1, Ordering::Relaxed);
    if n < 32 {
        crate::println!(
            "SAVED-SP-WRITE-OUT-OF-RANGE: tid={} new_sp={:#x} kbase={:#x} kend={:#x} caller={}:{} n={}",
            tid, new_value, kbase, kbase.wrapping_add(ksize),
            caller.file(), caller.line(), n,
        );
    }
}

// #208/#233 x86_64 fp-chain scribble scanner gate.  When true, every
// write_saved_sp walks the current rbp chain and flags the first
// return-address slot holding a small constant / non-canonical value
// (the wild-RIP scribble signature).  Whole-kstack coverage: catches the
// scribble wherever it lands in a deep kernel call chain.
#[cfg(target_arch = "x86_64")]
const FP_CHAIN_SCAN_X86: bool = false;

// #228 caller-frame probe: marked #[inline(never)] so write_saved_sp
// has its own kstack frame and we can read the caller's frame at a
// known SP offset above ours.  The 36-boot HW-WP hunt + 12-boot
// stamp-probe stress missed the corruption; targeting the caller
// frame is the next-narrowest window for an upstream scribble.
#[inline(never)]
#[track_caller]
pub fn write_saved_sp(thread: &mut Thread, new_value: u64) {
    let _thread_addr = thread as *const _ as u64;
    // Existing local-frame canary (still useful for catching
    // intra-frame scribble; this and the new caller-frame snapshot
    // together cover both sides of our return-address slot).
    let canary: u64 = 0xDEAD_C0DE_DEAD_C0DE;
    let canary_ptr: *const u64 = &canary;
    // #228 slab-canary check: verify the magic stamped at
    // alloc_thread_entry-time hasn't been scribbled by an unrelated
    // subsystem.  Cheap volatile read of one u64 at page+0x800.
    // Catches "another path wrote into the Thread's 4 KiB phys page"
    // class of bug — exactly what the WP and stack probes missed.
    if let Some(observed) = check_thread_slab_canary(_thread_addr) {
        let caller = core::panic::Location::caller();
        static SLAB_CANARY_LOG: core::sync::atomic::AtomicU32 =
            core::sync::atomic::AtomicU32::new(0);
        let n = SLAB_CANARY_LOG.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            crate::println!(
                "THREAD-SLAB-CANARY-BROKEN: thread={:#x} canary_va={:#x} observed={:#x} expected={:#x} tid={} new_sp={:#x} caller={}:{} n={}",
                _thread_addr,
                (_thread_addr & !0xFFF) + THREAD_SLAB_CANARY_OFFSET,
                observed,
                THREAD_SLAB_CANARY_MAGIC,
                thread.id,
                new_value,
                caller.file(),
                caller.line(),
                n,
            );
        }
    }
    // Caller-frame snapshot.  Capture entry-time SP, then read 16
    // u64s starting at sp + CALLER_FRAME_OFFSET (just above our
    // prologue allocation).  Re-read at exit, log first mismatch.
    // Offset values pick the caller's return-address slot + a
    // 128-byte window of its frame body.
    #[cfg(any(target_arch = "riscv64", target_arch = "aarch64"))]
    let entry_sp: u64 = {
        let v: u64;
        #[cfg(target_arch = "riscv64")]
        unsafe { core::arch::asm!("mv {}, sp", out(reg) v, options(nomem, nostack, preserves_flags)); }
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("mov {}, sp", out(reg) v, options(nomem, nostack, preserves_flags)); }
        v
    };
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
    let entry_sp: u64 = 0;
    // #228 fp-chain walk: with `-C force-frame-pointers=yes` rv64
    // builds emit `addi s0, sp, FRAMESIZE` in every prologue, so s0
    // points at the saved-ra slot's high address.  Walk the chain:
    //   fp - 8  = saved ra of THIS frame
    //   fp - 16 = saved fp = caller's fp
    // ...repeat.  Each saved-ra should be a kernel code address; a
    // 0 or wildly out-of-range value means that frame's ra slot
    // was scribbled, which is the cause=0xc sepc=0x0 return-to-NULL
    // pattern.  Log up to one violation per call to avoid serial
    // floods.
    #[cfg(target_arch = "riscv64")]
    {
        let mut fp: u64;
        unsafe {
            core::arch::asm!(
                "mv {}, s0",
                out(reg) fp,
                options(nomem, nostack, preserves_flags),
            );
        }
        let mut logged_this_call = false;
        for depth in 0..16u32 {
            // Stop walk if fp leaves the kernel RAM range or is
            // misaligned (frame pointers are 16-byte aligned).
            if fp < 0x8000_0000 || fp >= 0x1_0000_0000 || (fp & 0xF) != 0 {
                break;
            }
            let saved_ra = unsafe { ((fp - 8) as *const u64).read_volatile() };
            let saved_fp = unsafe { ((fp - 16) as *const u64).read_volatile() };
            // Natural kstack-bottom terminator: both saved-ra and
            // saved-fp are zero (the page was just zero-filled at
            // thread spawn and we walked off the top of the chain).
            // Stop the walk here; don't flag as corruption.
            if saved_ra == 0 && saved_fp == 0 {
                break;
            }
            // Kernel code lives roughly in 0x8020_0000..0x80a0_0000.
            // Anything outside that range (and especially 0) is bogus
            // ONLY if there's still a chain above (saved_fp suggests
            // more frames).
            let ra_is_bogus = saved_ra == 0
                || saved_ra < 0x8020_0000
                || saved_ra > 0x80a0_0000;
            if ra_is_bogus && !logged_this_call {
                logged_this_call = true;
                let caller = core::panic::Location::caller();
                static FP_CHAIN_LOG: core::sync::atomic::AtomicU32 =
                    core::sync::atomic::AtomicU32::new(0);
                let n = FP_CHAIN_LOG.fetch_add(1, Ordering::Relaxed);
                if n < 16 {
                    crate::println!(
                        "KSTACK-FP-CHAIN-BAD-RA: depth={} fp={:#x} saved_ra={:#x} saved_fp={:#x} tid={} thread={:#x} new_sp={:#x} entry_sp={:#x} caller={}:{} n={}",
                        depth,
                        fp,
                        saved_ra,
                        saved_fp,
                        thread.id,
                        _thread_addr,
                        new_value,
                        entry_sp,
                        caller.file(),
                        caller.line(),
                        n,
                    );
                }
            }
            // Caller's fp must be strictly above (higher addr) ours;
            // stack grows down so each frame's fp is at a higher
            // address than the callee's.  Break on regression.
            if saved_fp <= fp {
                break;
            }
            fp = saved_fp;
        }
    }
    // #208/#233 x86_64 fp-chain walk.  With `-C force-frame-pointers=yes`
    // every Rust prologue is `push rbp; mov rbp, rsp`, so rbp points AT the
    // saved-caller-rbp slot:
    //   [rbp + 0] = saved caller rbp (= caller's frame pointer)
    //   [rbp + 8] = THIS frame's return address (what a later `ret` loads)
    // (differs from rv64, whose s0 points 16 bytes higher.)  Walk the chain
    // and validate each saved-ra: a kernel return address must live in
    // [KERNEL_BASE, kernel_end_vma).  The observed #208 corruption plants a
    // SMALL value (0x0 / 0x20 / 0x202) where a kernel-text address belongs;
    // a later ret/iretq consumes it and jumps wild.  Flag the FIRST bogus
    // ra (rate-limited) — this localizes the corruption to a specific call
    // depth/frame without needing to know the fixed slot in advance.
    #[cfg(target_arch = "x86_64")]
    if FP_CHAIN_SCAN_X86 {
        let kbase = crate::arch::x86_64::boot::KERNEL_BASE_VMA;
        let kend = crate::arch::x86_64::boot::kernel_end_vma() as u64;
        let mut fp: u64;
        unsafe {
            core::arch::asm!(
                "mov {}, rbp",
                out(reg) fp,
                options(nomem, nostack, preserves_flags),
            );
        }
        let mut logged_this_call = false;
        for depth in 0..16u32 {
            // Valid rbp while walking: low identity OR kstack region OR
            // high-half boot/AP/IST stacks.  Mirrors the exception.rs #PF
            // backtrace bounds.  Frame pointers are 8-byte aligned on x86.
            let fp_ok_low = fp >= 0x1000 && fp < 0x8000_0000;
            let fp_ok_kstack = fp >= 0xfffffe0000000000
                && fp < 0xffffffff80000000;
            let fp_ok_high = fp >= 0xffffffff80000000;
            if !(fp_ok_low || fp_ok_kstack || fp_ok_high) || (fp & 7) != 0 {
                break;
            }
            let saved_fp = unsafe { (fp as *const u64).read_volatile() };
            let saved_ra =
                unsafe { (fp.wrapping_add(8) as *const u64).read_volatile() };
            // Natural chain bottom: both slots zero (page was zero-filled at
            // spawn and we walked off the top).  Stop; not corruption.
            if saved_ra == 0 && saved_fp == 0 {
                break;
            }
            // SCRIBBLE signature (precise, low-false-positive): a small
            // constant where a kernel-text address belongs (matches the
            // observed 0x0/0x20/0x202) OR a non-canonical address.  Do NOT
            // flag legit kernel-text addresses (ra in [kbase, kend)).
            let non_canonical = {
                // canonical: top 17 bits all equal sign bit (bit 47).
                let hi = saved_ra >> 47;
                hi != 0 && hi != 0x1FFFF
            };
            let ra_is_bogus =
                (saved_ra != 0 && saved_ra < 0x10000) || non_canonical;
            // Also worth flagging a value that is neither a small scribble
            // nor inside kernel text, but only if it's clearly not a
            // userspace/other-mapping return path; keep it conservative and
            // restrict to the scribble signature above to avoid false fires.
            let _ = (kbase, kend);
            if ra_is_bogus && !logged_this_call {
                logged_this_call = true;
                static FP_CHAIN_LOG_X86: core::sync::atomic::AtomicU32 =
                    core::sync::atomic::AtomicU32::new(0);
                let n = FP_CHAIN_LOG_X86.fetch_add(1, Ordering::Relaxed);
                if n < 16 {
                    crate::println!(
                        "KSTACK-FP-CHAIN-BAD-RA-X86: depth={} fp={:#x} saved_ra={:#x} saved_fp={:#x} tid={} new_sp={:#x}",
                        depth,
                        fp,
                        saved_ra,
                        saved_fp,
                        thread.id,
                        new_value,
                    );
                }
            }
            // Caller's fp must be strictly above (higher addr) ours; stack
            // grows down so each frame's fp is higher than the callee's.
            // Break on regression.
            if saved_fp <= fp {
                break;
            }
            fp = saved_fp;
        }
    }
    // #228 kstack saved-ra mirror: cause=0xc sepc=0x0 in stress runs
    // = ret loaded ra=0 because some frame's saved-ra slot got
    // scribbled.  Snapshot uses a per-CPU static buffer (rather than
    // a local stack array) so it doesn't bloat write_saved_sp's
    // prologue — earlier the 64-word + saved-ra-check variants
    // pushed our prologue to 464 bytes, putting the snapshot offset
    // INSIDE our frame and producing false positives where the body
    // wrote into the snap_entry storage itself.  With per-CPU
    // storage our frame stays ~200 bytes and the +0x100 offset
    // (above prologue) reliably monitors the caller's frame.
    // Offset chosen to clearly land above write_saved_sp's prologue
    // (currently 320 bytes per rv64 disasm; bumped from 0x100 once the
    // snap_entry-on-stack form was retired in favor of the per-CPU
    // buffer, which kept the prologue under 0x140 in earlier builds
    // but recent edits pushed it to 0x140 + room for local s-saves).
    const CALLER_FRAME_OFFSET: u64 = 0x180;
    const SNAP_WORDS: usize = 16;
    let snap_base = entry_sp.wrapping_add(CALLER_FRAME_OFFSET);
    #[cfg(any(target_arch = "riscv64", target_arch = "aarch64"))]
    if entry_sp != 0 && snap_base >= 0x4000_0000 && snap_base < 0x1_0000_0000 {
        let cpu = smp::cpu_id() as usize;
        if cpu < KSTACK_SNAP_MAX_CPUS {
            unsafe {
                KSTACK_SNAP[cpu].base = entry_sp;
                for i in 0..SNAP_WORDS {
                    KSTACK_SNAP[cpu].words[i] =
                        (snap_base as *const u64).add(i).read_volatile();
                }
            }
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        let thread_addr = _thread_addr;
        let in_slab = thread_addr
            >= crate::arch::x86_64::mm::SLAB_REGION_BASE
            && thread_addr
                < crate::arch::x86_64::mm::SLAB_REGION_BASE
                    .wrapping_add(crate::arch::x86_64::mm::PML4_SLOT_SIZE);
        if !in_slab {
            let caller = core::panic::Location::caller();
            static BAD_THREAD_LOG: core::sync::atomic::AtomicU32 =
                core::sync::atomic::AtomicU32::new(0);
            let n = BAD_THREAD_LOG.fetch_add(1, Ordering::Relaxed);
            if n < 32 {
                crate::println!(
                    "SAVED-SP-WRITE-BAD-THREAD: thread={:#x} new_sp={:#x} caller_file_line={}:{} n={}",
                    thread_addr,
                    new_value,
                    caller.file(),
                    caller.line(),
                    n,
                );
            }
        }
    }
    // rv64: slab + identity-mapped RAM at 0x8000_0000..0x1_0000_0000.
    // aarch64: slab identity 0x4000_0000..0xC000_0000 OR
    // SLAB_THREAD_REGION 0xC000_0000..0xFFFF_FFFF (per-Thread VA).
    #[cfg(target_arch = "riscv64")]
    {
        let in_ram = _thread_addr >= 0x8000_0000
            && _thread_addr < 0x1_0000_0000;
        if !in_ram {
            let caller = core::panic::Location::caller();
            static BAD_THREAD_LOG: core::sync::atomic::AtomicU32 =
                core::sync::atomic::AtomicU32::new(0);
            let n = BAD_THREAD_LOG.fetch_add(1, Ordering::Relaxed);
            if n < 32 {
                crate::println!(
                    "SAVED-SP-WRITE-BAD-THREAD: thread={:#x} new_sp={:#x} caller={}:{} n={}",
                    _thread_addr, new_value, caller.file(), caller.line(), n,
                );
            }
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let in_identity = _thread_addr >= 0x4000_0000
            && _thread_addr < 0xC000_0000;
        let in_slab_region = _thread_addr >= 0xC000_0000
            && _thread_addr < 0x1_0000_0000;
        if !in_identity && !in_slab_region {
            let caller = core::panic::Location::caller();
            static BAD_THREAD_LOG: core::sync::atomic::AtomicU32 =
                core::sync::atomic::AtomicU32::new(0);
            let n = BAD_THREAD_LOG.fetch_add(1, Ordering::Relaxed);
            if n < 32 {
                crate::println!(
                    "SAVED-SP-WRITE-BAD-THREAD: thread={:#x} new_sp={:#x} caller={}:{} n={}",
                    _thread_addr, new_value, caller.file(), caller.line(), n,
                );
            }
        }
    }
    // #227 saved_sp range invariant — cheap pre-check, deferred body
    // for cold path so the helper stays inline-cheap.  Filter idles
    // in the cold body since they legitimately run on boot/AP stack.
    {
        let kbase = thread.stack_base as u64;
        let ksize = kstack_size() as u64;
        let in_own_kstack = new_value != 0 && new_value >= kbase
            && new_value < kbase.wrapping_add(ksize);
        if !in_own_kstack && new_value != 0 && kbase != 0 {
            log_saved_sp_out_of_range(thread.id, new_value, kbase, ksize);
        }
    }
    // #228 watchpoint: log every write of 0 to saved_sp.  KEPOCH-BAIL
    // fires deterministically 5×/boot for tid=4 (zero_daemon) reading
    // sp=0.  Either a legitimate writer is passing 0 (caller bug) or
    // some non-write_saved_sp path is scribbling the slot.  If this
    // log fires before/at the same count as KEPOCH-BAIL, it's the
    // former; if it never fires while KEPOCH-BAIL still triggers, it
    // confirms a non-write_saved_sp writer and we need a real hardware
    // watchpoint to catch it.
    if new_value == 0 {
        let caller = core::panic::Location::caller();
        static ZERO_WRITE_LOG: core::sync::atomic::AtomicU32 =
            core::sync::atomic::AtomicU32::new(0);
        let n = ZERO_WRITE_LOG.fetch_add(1, Ordering::Relaxed);
        if n < 32 {
            crate::println!(
                "SAVED-SP-WRITE-ZERO: tid={} cur={:#x} caller={}:{} n={}",
                thread.id, thread.saved_sp,
                caller.file(), caller.line(), n,
            );
        }
    }
    // #228 rv64 hardware watchpoint: arm a S-mode store trigger on
    // tid=4 (zero_daemon)'s saved_sp slot the FIRST time we touch it,
    // so any subsequent non-write_saved_sp store traps Breakpoint and
    // we get the offending PC.  The trap handler disarms after the
    // first hit so we don't loop.  Only arm once per boot.  No
    // println! here — this runs under scheduler critical sections
    // that hold serial-incompatible locks; the trap handler prints
    // when the watchpoint fires.
    #[cfg(any(target_arch = "riscv64", target_arch = "aarch64"))]
    {
        // Per-hart arming.  RISC-V Sdtrig triggers and AArch64 DBGWVR
        // are PER-CPU, so a single global CAS gate would arm only the
        // first CPU that touched tid=4 — writes from the others would
        // sail past unobserved.  We need every CPU to arm its OWN
        // trigger, but each only once.  Use a per-CPU AtomicBool
        // gated by cmdline.  MAX_CPUS bound is generous (16); arms
        // beyond fall through.
        const MAX_CPUS: usize = 16;
        static WP_ARMED_PER_CPU: [core::sync::atomic::AtomicBool; MAX_CPUS] = [
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
            core::sync::atomic::AtomicBool::new(false),
        ];
        let enabled = crate::boot::cmdline::BOOT_CONFIG
            .wp_savedsp
            .load(Ordering::Relaxed) != 0;
        if enabled {
            let cpu = smp::cpu_id() as usize;
            // First CPU to touch tid=4 publishes the address in
            // watchpoint::WATCHED_ADDR via arm().  Subsequent CPUs
            // bootstrap from that on their first call here regardless
            // of which tid they're switching — they don't need to
            // wait for tid=4 to be scheduled on them, which may never
            // happen during boot if zero_daemon stays on CPU 0.
            let candidate_addr: Option<u64> = if thread.id == 4 {
                Some(&thread.saved_sp as *const u64 as u64)
            } else {
                #[cfg(target_arch = "riscv64")]
                let v = crate::arch::riscv64::watchpoint::watched_addr();
                #[cfg(target_arch = "aarch64")]
                let v = crate::arch::aarch64::watchpoint::watched_addr();
                if v != 0 { Some(v) } else { None }
            };
            if let Some(addr) = candidate_addr {
                if cpu < MAX_CPUS
                    && WP_ARMED_PER_CPU[cpu]
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                {
                    #[cfg(target_arch = "riscv64")]
                    crate::arch::riscv64::watchpoint::arm(addr);
                    #[cfg(target_arch = "aarch64")]
                    crate::arch::aarch64::watchpoint::arm(addr);
                    // Aux trigger on the LOCAL CPU's current_thread
                    // slot — wp_savedsp >= 4 only.  current_thread
                    // updates on every context switch; the legit-PC
                    // re-arm path drops the store, so arming the aux
                    // breaks scheduling.  Keep aux behind an explicit
                    // mode so default boots don't wedge.
                    #[cfg(target_arch = "riscv64")]
                    if crate::boot::cmdline::BOOT_CONFIG
                        .wp_savedsp
                        .load(Ordering::Relaxed)
                        >= 4
                    {
                        let pcpu = smp::current();
                        let ct_addr = &pcpu.current_thread as *const _ as u64;
                        crate::arch::riscv64::watchpoint::arm_aux(ct_addr);
                    }
                    // aarch64 alias-VA aux: addr is the
                    // SLAB_THREAD_REGION VA per-instance window
                    // mapping of the Thread struct.  The same
                    // physical page is ALSO mapped in the kernel's
                    // identity range (0x4000_0000..0xC000_0000), so
                    // writes via that alias don't fire the primary.
                    // wp_savedsp >= 4 enables aux on the identity VA.
                    #[cfg(target_arch = "aarch64")]
                    if crate::boot::cmdline::BOOT_CONFIG
                        .wp_savedsp
                        .load(Ordering::Relaxed)
                        >= 4
                    {
                        // AT S1E1W performs the EL1 stage-1 write
                        // translation; PAR_EL1 reports PA on success.
                        let pa: u64;
                        let par: u64;
                        unsafe {
                            core::arch::asm!(
                                "at s1e1w, {}",
                                in(reg) addr,
                                options(nostack, preserves_flags),
                            );
                            core::arch::asm!(
                                "mrs {}, par_el1",
                                out(reg) par,
                                options(nomem, nostack, preserves_flags),
                            );
                        }
                        pa = if par & 1 == 0 {
                            (par & 0x000F_FFFF_FFFF_F000) | (addr & 0xFFF)
                        } else {
                            0
                        };
                        if pa != 0
                            && pa >= 0x4000_0000
                            && pa < 0xC000_0000
                            && pa != addr
                        {
                            crate::arch::aarch64::watchpoint::arm_aux(pa);
                        }
                    }
                }
            }
        }
    }
    thread.saved_sp = new_value;
    // #228 stamp probe: verify the entry-time stack canary survived
    // the function body.  A mismatch means some external write hit
    // our local stack frame between entry and store — strong signal
    // that the corruption surface is intra-function kstack scribble.
    // Volatile read prevents the compiler from constant-folding the
    // check away.
    let canary_check = unsafe { canary_ptr.read_volatile() };
    if canary_check != 0xDEAD_C0DE_DEAD_C0DE {
        let caller = core::panic::Location::caller();
        static CANARY_BREAK_LOG: core::sync::atomic::AtomicU32 =
            core::sync::atomic::AtomicU32::new(0);
        let n = CANARY_BREAK_LOG.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            crate::println!(
                "KSTACK-STAMP-BROKEN: canary={:#x} thread={:#x} tid={} new_sp={:#x} canary_va={:p} caller={}:{} n={}",
                canary_check,
                _thread_addr,
                thread.id,
                new_value,
                canary_ptr,
                caller.file(),
                caller.line(),
                n,
            );
        }
    }
    // Caller-frame diff: re-read SNAP_WORDS u64s above our frame
    // and compare to the entry-time snapshot.  The caller's saved
    // registers + frame body should be stable across our call —
    // any mismatch points at an external write into the caller's
    // kstack region during our execution.
    #[cfg(any(target_arch = "riscv64", target_arch = "aarch64"))]
    if entry_sp != 0 && snap_base >= 0x4000_0000 && snap_base < 0x1_0000_0000 {
        let mut diff_idx: i32 = -1;
        let mut diff_orig: u64 = 0;
        let mut diff_now: u64 = 0;
        let cpu = smp::cpu_id() as usize;
        if cpu < KSTACK_SNAP_MAX_CPUS && unsafe { KSTACK_SNAP[cpu].base } == entry_sp {
            for i in 0..SNAP_WORDS {
                let now = unsafe {
                    (snap_base as *const u64).add(i).read_volatile()
                };
                let orig = unsafe { KSTACK_SNAP[cpu].words[i] };
                if now != orig {
                    diff_idx = i as i32;
                    diff_orig = orig;
                    diff_now = now;
                    break;
                }
            }
        }
        if diff_idx >= 0 {
            let caller = core::panic::Location::caller();
            static FRAME_DIFF_LOG: core::sync::atomic::AtomicU32 =
                core::sync::atomic::AtomicU32::new(0);
            let n = FRAME_DIFF_LOG.fetch_add(1, Ordering::Relaxed);
            if n < 16 {
                crate::println!(
                    "CALLER-FRAME-SCRIBBLE: snap_base={:#x} idx={} orig={:#x} now={:#x} tid={} thread={:#x} new_sp={:#x} caller={}:{} n={}",
                    snap_base,
                    diff_idx,
                    diff_orig,
                    diff_now,
                    thread.id,
                    _thread_addr,
                    new_value,
                    caller.file(),
                    caller.line(),
                    n,
                );
            }
        }
    }
}

#[inline]
#[track_caller]
pub fn record_saved_sp_write(tid: ThreadId, new_value: u64, callsite_tag: u8) {
    let i = tid as usize;
    if i >= SAVED_SP_LOG_CAP {
        return;
    }
    let cpu = smp::cpu_id() as u8;
    let ts32 = (crate::arch::timer::monotonic_ns() & 0xFFFF_FFFF) as u64;
    let meta = (callsite_tag as u64) | ((cpu as u64) << 8) | (ts32 << 32);
    SAVED_SP_LAST_VALUE[i].store(new_value, Ordering::Relaxed);
    SAVED_SP_LAST_META[i].store(meta, Ordering::Relaxed);
    // #208 Probe A: snapshot iretq fields immediately after the saved_sp
    // write so we can detect later corruption.  Cheap (5 reads) and
    // idempotent across writers.
    snapshot_iretq_shadow(tid, new_value);
}

/// Dump the last saved_sp write for `tid` (called from BUG: try_switch path).
pub fn dump_saved_sp_log(tid: ThreadId) {
    let i = tid as usize;
    if i >= SAVED_SP_LOG_CAP {
        return;
    }
    let value = SAVED_SP_LAST_VALUE[i].load(Ordering::Relaxed);
    let meta = SAVED_SP_LAST_META[i].load(Ordering::Relaxed);
    let tag = (meta & 0xFF) as u8;
    let cpu = ((meta >> 8) & 0xFF) as u8;
    let ts32 = (meta >> 32) as u32;
    crate::println!(
        "  SAVED-SP-LAST: tid={} value={:#x} tag={} cpu={} ts={}",
        tid, value, tag, cpu, ts32,
    );
}

/// #208 KSTACK_WRITE_RING — global ring of suspected kstack-VA writes
/// (iretq-frame injects + page zeroings).  Each slot stores
/// (target_va, len, action, cpu, ts_ns).  Queried at PRINT-RET-SCRIBBLE
/// detection: dump entries whose [va, va+len) intersects the SCRIBBLE
/// slot AND ts_ns is within a recent window — identifies WHICH writer
/// scribbled the slot.  Distinguishes "alloc_kstack_zeroed zero-fill"
/// from "init_kernel_frame inject" from "try_switch saved_sp save".
///
/// Action codes:
///   1 = alloc_kstack_zeroed write_bytes(0)  [len = 128 KiB typically]
///   2 = alloc_thread_entry write_bytes(0)   [len = 4 KiB]
///   3 = init_kernel_frame  RIP slot  [len = 8]
///   4 = init_kernel_frame  CS+RFLAGS+RSP+SS slots  [len = 32]
///   5 = init_user_frame  RIP slot  [len = 8]
///   6 = init_user_frame  CS+RFLAGS+RSP+SS slots  [len = 32]
const KSTACK_WRITE_RING_SLOTS: usize = 512;
const KSTACK_WRITE_RING_MASK: usize = KSTACK_WRITE_RING_SLOTS - 1;
static KSTACK_WRITE_RING_VA: [core::sync::atomic::AtomicU64; KSTACK_WRITE_RING_SLOTS] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; KSTACK_WRITE_RING_SLOTS]
};
static KSTACK_WRITE_RING_META: [core::sync::atomic::AtomicU64; KSTACK_WRITE_RING_SLOTS] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; KSTACK_WRITE_RING_SLOTS]
};
static KSTACK_WRITE_RING_POS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

#[inline]
pub fn record_kstack_write(va: u64, len: u32, action: u8) {
    let cpu = smp::cpu_id() as u8;
    let ts_ns = crate::arch::timer::monotonic_ns();
    let meta = (action as u64) | ((cpu as u64) << 8) | ((len as u64) << 16) | (ts_ns << 32);
    let idx = (KSTACK_WRITE_RING_POS.fetch_add(1, Ordering::Relaxed) as usize)
        & KSTACK_WRITE_RING_MASK;
    KSTACK_WRITE_RING_VA[idx].store(va, Ordering::Relaxed);
    KSTACK_WRITE_RING_META[idx].store(meta, Ordering::Relaxed);
}

/// Dump KSTACK_WRITE_RING entries whose [va, va+len) intersects
/// [slot_va, slot_va+8) AND ts_ns is within `window_ns` of `now_ns`.
/// Called from PRINT-RET-SCRIBBLE handler — identifies the writer of
/// the corrupted ret slot.
pub fn dump_kstack_writes_near(slot_va: u64, now_ns: u64, window_ns: u64) {
    let mut hits = 0u32;
    for i in 0..KSTACK_WRITE_RING_SLOTS {
        let va = KSTACK_WRITE_RING_VA[i].load(Ordering::Relaxed);
        if va == 0 {
            continue;
        }
        let meta = KSTACK_WRITE_RING_META[i].load(Ordering::Relaxed);
        let action = (meta & 0xFF) as u8;
        let cpu = ((meta >> 8) & 0xFF) as u8;
        let len = ((meta >> 16) & 0xFFFF) as u32;
        let ts_ns = meta >> 32;
        // Time window check.
        let dt = now_ns.wrapping_sub(ts_ns);
        if dt > window_ns && (ts_ns.wrapping_sub(now_ns)) > window_ns {
            continue;
        }
        // Range intersect: [va, va+len) ∩ [slot_va, slot_va+8) != ∅
        let end = va.saturating_add(len as u64);
        let slot_end = slot_va.saturating_add(8);
        if end <= slot_va || va >= slot_end {
            continue;
        }
        crate::println!(
            "KSTACK-WRITE-NEAR: action={} cpu={} va={:#x} len={} ts_ns={} slot={:#x}",
            action, cpu, va, len, ts_ns, slot_va,
        );
        hits += 1;
        if hits >= 16 {
            break;
        }
    }
    if hits == 0 {
        crate::println!(
            "KSTACK-WRITE-NEAR: NO MATCH slot={:#x} now_ns={} window_ns={}",
            slot_va, now_ns, window_ns,
        );
    }
}

/// #208 kstack epoch probe — counts how many times to log an injection
/// site catching the deferred-free race, rate-limited to avoid log flood.
static KEPOCH_BAIL_LOG_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// #208 Probe A: counter for FRAME-DELTA log lines.
static FRAME_DELTA_LOG_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// #208 RSP0 update ring — per-CPU last 4 set_rsp0 calls.  Slot stores
/// (tid in high 32 | rsp0 in low 32 — truncated for compactness; the
/// full rsp0 is in the companion `RSP0_RING_FULL` slot).  Read by
/// RSP0-MISMATCH probe to attribute "TSS was set up for tid=X with
/// rsp0=Y" vs "TSS never updated for this transition".
const RSP0_RING_SLOTS: usize = 65536;
const RSP0_RING_MASK: usize = RSP0_RING_SLOTS - 1;
const RSP0_RING_TOTAL: usize = smp::MAX_CPUS * RSP0_RING_SLOTS;
static RSP0_RING_FULL: [core::sync::atomic::AtomicU64; RSP0_RING_TOTAL] = {
    const Z: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    [Z; RSP0_RING_TOTAL]
};
static RSP0_RING_TID_TS: [core::sync::atomic::AtomicU64; RSP0_RING_TOTAL] = {
    const Z: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    [Z; RSP0_RING_TOTAL]
};
static RSP0_RING_POS: [core::sync::atomic::AtomicU32; smp::MAX_CPUS] = {
    const Z: core::sync::atomic::AtomicU32 =
        core::sync::atomic::AtomicU32::new(0);
    [Z; smp::MAX_CPUS]
};

/// Append a (target_tid, new_rsp0) record to this CPU's RSP0 ring.
/// Called from gdt::set_rsp0 after the TSS write.
#[inline]
pub fn record_rsp0_update(cpu: u32, target_tid: u32, new_rsp0: u64) {
    let cpu_idx = cpu as usize;
    if cpu_idx >= smp::MAX_CPUS {
        return;
    }
    let pos = RSP0_RING_POS[cpu_idx].fetch_add(1, Ordering::Relaxed) as usize;
    let slot = pos & RSP0_RING_MASK;
    let idx = cpu_idx * RSP0_RING_SLOTS + slot;
    let ts32 = (crate::arch::timer::monotonic_ns() & 0xFFFF_FFFF) as u64;
    let tid_ts = (target_tid as u64) | (ts32 << 32);
    RSP0_RING_FULL[idx].store(new_rsp0, Ordering::Relaxed);
    RSP0_RING_TID_TS[idx].store(tid_ts, Ordering::Relaxed);
}

/// #208 current_thread transition ring — per-CPU last 4 stores.
/// Used together with the RSP0 ring to find "current_thread changed
/// but RSP0 didn't update" paths.  If a tid appears in this ring but
/// NOT in the RSP0 ring, that's the missing update_kernel_stack
/// path we're hunting.
static CT_RING_TID_TS: [core::sync::atomic::AtomicU64; RSP0_RING_TOTAL] = {
    const Z: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    [Z; RSP0_RING_TOTAL]
};
static CT_RING_POS: [core::sync::atomic::AtomicU32; smp::MAX_CPUS] = {
    const Z: core::sync::atomic::AtomicU32 =
        core::sync::atomic::AtomicU32::new(0);
    [Z; smp::MAX_CPUS]
};

/// Record a current_thread store.  Called from every site that writes
/// pcpu.current_thread (idle and non-idle alike).
#[inline]
pub fn record_current_thread_change(cpu: u32, new_tid: u32) {
    let cpu_idx = cpu as usize;
    if cpu_idx >= smp::MAX_CPUS {
        return;
    }
    let pos = CT_RING_POS[cpu_idx].fetch_add(1, Ordering::Relaxed) as usize;
    let slot = pos & RSP0_RING_MASK;
    let idx = cpu_idx * RSP0_RING_SLOTS + slot;
    let ts32 = (crate::arch::timer::monotonic_ns() & 0xFFFF_FFFF) as u64;
    let tid_ts = (new_tid as u64) | (ts32 << 32);
    CT_RING_TID_TS[idx].store(tid_ts, Ordering::Relaxed);
}

/// Dump the last current_thread changes for `cpu` (most-recent first).
pub fn dump_ct_ring(cpu: u32) {
    let cpu_idx = cpu as usize;
    if cpu_idx >= smp::MAX_CPUS {
        return;
    }
    let pos = CT_RING_POS[cpu_idx].load(Ordering::Relaxed) as usize;
    let limit = RSP0_RING_DUMP_LIMIT.min(RSP0_RING_SLOTS);
    for i in 0..limit {
        let slot_pos = (pos.wrapping_sub(1 + i)) & RSP0_RING_MASK;
        let idx = cpu_idx * RSP0_RING_SLOTS + slot_pos;
        let tid_ts = CT_RING_TID_TS[idx].load(Ordering::Relaxed);
        if tid_ts == 0 {
            continue;
        }
        let tid = (tid_ts & 0xFFFF_FFFF) as u32;
        let ts32 = (tid_ts >> 32) as u32;
        crate::println!(
            "  CT-RING[{}]: tid={} ts32={}",
            i, tid, ts32,
        );
    }
}

/// Dump the last RSP0 updates for `cpu` (most-recent first).  Called by
/// the RSP0-MISMATCH probe at fire time.
/// Maximum entries to print in a single ring dump.  The ring itself is
/// large (RSP0_RING_SLOTS) so we can look further back when grepping the
/// log, but each dump only prints this many to keep serial output sane.
const RSP0_RING_DUMP_LIMIT: usize = 256;

pub fn dump_rsp0_ring(cpu: u32) {
    let cpu_idx = cpu as usize;
    if cpu_idx >= smp::MAX_CPUS {
        return;
    }
    let pos = RSP0_RING_POS[cpu_idx].load(Ordering::Relaxed) as usize;
    let limit = RSP0_RING_DUMP_LIMIT.min(RSP0_RING_SLOTS);
    for i in 0..limit {
        let slot_pos = (pos.wrapping_sub(1 + i)) & RSP0_RING_MASK;
        let idx = cpu_idx * RSP0_RING_SLOTS + slot_pos;
        let rsp0 = RSP0_RING_FULL[idx].load(Ordering::Relaxed);
        let tid_ts = RSP0_RING_TID_TS[idx].load(Ordering::Relaxed);
        if tid_ts == 0 {
            continue;
        }
        let tid = (tid_ts & 0xFFFF_FFFF) as u32;
        let ts32 = (tid_ts >> 32) as u32;
        crate::println!(
            "  RSP0-RING[{}]: tid={} rsp0={:#x} ts32={}",
            i, tid, rsp0, ts32,
        );
    }
}

/// #208 Probe A: snapshot the iretq frame slots at park-time so we can
/// detect corruption that happens between park and dispatch.  Stores
/// RIP / CS / RFLAGS / RSP / SS into the Thread's shadow fields.  No-op
/// if `sp` is not within `tid`'s current kstack.
#[inline]
#[track_caller]
pub fn snapshot_iretq_shadow(tid: ThreadId, sp: u64) {
    if sp < 0x10000 {
        return;
    }
    let t = unsafe { thread_mut_from_ref(tid) };
    let sb = t.stack_base as u64;
    let sz = kstack_size() as u64;
    if sb == 0
        || sp < sb
        || sp.saturating_add(EXCEPTION_FRAME_SIZE as u64) > sb + sz
    {
        return;
    }
    // #227 seqlock: bump to odd before any field write so concurrent
    // readers (FBD / watchdog) can detect a torn snapshot.  We bump
    // unconditionally even when the slot index is out of range so the
    // even-on-exit invariant holds.
    #[cfg(target_arch = "x86_64")]
    let seq_idx = {
        let i = tid as usize;
        if i < SAVED_SP_LOG_CAP {
            // #227 concurrent-snapshot detection: increment inflight
            // counter; >0 prior value means another writer is in the
            // critical region NOW.  Log the caller (via #[track_caller])
            // so the offending bypass of `&mut Thread` can be identified.
            let prev = SNAPSHOT_INFLIGHT[i].fetch_add(1, Ordering::AcqRel);
            if prev != 0 {
                static CONCURRENT_LOG: core::sync::atomic::AtomicU32 =
                    core::sync::atomic::AtomicU32::new(0);
                let n = CONCURRENT_LOG.fetch_add(1, Ordering::Relaxed);
                if n < 32 {
                    let caller = core::panic::Location::caller();
                    let cpu = smp::cpu_id();
                    crate::println!(
                        "CONCURRENT-SNAPSHOT: tid={} prev={} cpu={} caller={}:{} n={}",
                        tid, prev, cpu, caller.file(), caller.line(), n,
                    );
                }
            }
            IRETQ_SHADOW_SEQ[i].fetch_add(1, Ordering::Release);
            Some(i)
        } else { None }
    };
    unsafe {
        let frame = sp as *const u64;
        t.iretq_shadow_rip = *frame.add(17);
        t.iretq_shadow_cs = *frame.add(18);
        t.iretq_shadow_rflags = *frame.add(19);
        t.iretq_shadow_rsp = *frame.add(20);
        t.iretq_shadow_ss = *frame.add(21);
        t.iretq_shadow_sp = sp;
    }
    // #227 VA→PA continuity: capture the PA backing slot[17] at park
    // time.  Compared at FBD slot[17] mismatch to detect kstack VA
    // remap-while-parked.  Held inside the seqlock so the {sp, PA}
    // pair is observed atomically by the reader.
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(i) = seq_idx {
            let cr3: u64;
            unsafe {
                core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
            }
            let pml4 = (cr3 & !0xfff) as usize;
            let slot17_va = sp.wrapping_add(17 * 8) as usize;
            let pa = crate::arch::x86_64::mm::translate_va(pml4, slot17_va)
                .unwrap_or(0) as u64;
            IRETQ_SHADOW_SLOT17_PA[i].store(pa, Ordering::Relaxed);
        }
    }
    // #227 seqlock: bump again to return to even.  Total += 2 per
    // snapshot keeps the parity invariant.  Also release the
    // concurrent-snapshot counter.
    #[cfg(target_arch = "x86_64")]
    if let Some(i) = seq_idx {
        IRETQ_SHADOW_SEQ[i].fetch_add(1, Ordering::Release);
        SNAPSHOT_INFLIGHT[i].fetch_sub(1, Ordering::Release);
    }
    unsafe {
        let frame = sp as *const u64;
        // #208 full-frame snapshot — captures all 22 u64 slots so the
        // dispatch-time byte-compare can pinpoint ANY changed slot.
        for i in 0..22 {
            t.iretq_shadow_frame[i] =
                core::ptr::read_volatile(frame.add(i));
        }
    }
    // Extended snapshot — 128 quads (1 KiB) starting at saved_sp
    // going up.  Covers the iretq+GPR area (offsets 0..22, already
    // shadowed in iretq_shadow_frame) plus the calling function's
    // frame contents (offsets 22..128) where corrupted saved-RIP
    // slots that cause wild-ret crashes (boots 1690/1691) would
    // live.  Snapshotted at park, verified at dispatch.
    snapshot_park_stack_ext(tid, sp);
}

/// Per-tid extended-stack snapshot.  Covers 1 KiB of parked-frame
/// memory starting at saved_sp.  Detects peer-CPU writes into the
/// parked thread's calling-function frames (wild-RIP family).
const PARK_STACK_EXT_QUADS: usize = 128;
const PARK_STACK_EXT_CAP: usize = 256;
static PARK_STACK_EXT_SP: [core::sync::atomic::AtomicU64; PARK_STACK_EXT_CAP] = {
    const Z: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    [Z; PARK_STACK_EXT_CAP]
};
// Store as raw u64 cells inside an UnsafeCell-equivalent — we serialize
// access via the dispatch protocol (only one CPU dispatches/parks a
// given tid at a time), so atomic store/load isn't needed.  Use a
// per-tid array.
struct ParkStackExt {
    cells: core::cell::UnsafeCell<[u64; PARK_STACK_EXT_QUADS]>,
}
unsafe impl Sync for ParkStackExt {}
static PARK_STACK_EXT: [ParkStackExt; PARK_STACK_EXT_CAP] = {
    const Z: ParkStackExt = ParkStackExt {
        cells: core::cell::UnsafeCell::new([0u64; PARK_STACK_EXT_QUADS]),
    };
    [Z; PARK_STACK_EXT_CAP]
};

fn snapshot_park_stack_ext(tid: ThreadId, sp: u64) {
    let i = tid as usize;
    if i >= PARK_STACK_EXT_CAP {
        return;
    }
    // Bounds: read only if [sp, sp + 128*8) lies entirely in the
    // thread's kstack.  Otherwise zero the SP marker so dispatch
    // skips verification.
    let t = unsafe { &*(THREAD_TABLE.get(tid) as *const Thread) };
    let sb = t.stack_base as u64;
    let sz = kstack_size() as u64;
    let bytes = (PARK_STACK_EXT_QUADS * 8) as u64;
    if sb == 0 || sp < sb || sp.saturating_add(bytes) > sb + sz {
        PARK_STACK_EXT_SP[i].store(0, Ordering::Relaxed);
        return;
    }
    let cells = unsafe { &mut *PARK_STACK_EXT[i].cells.get() };
    unsafe {
        let p = sp as *const u64;
        for q in 0..PARK_STACK_EXT_QUADS {
            cells[q] = core::ptr::read_volatile(p.add(q));
        }
    }
    PARK_STACK_EXT_SP[i].store(sp, Ordering::Release);
}

/// At-dispatch verification of the extended parked-frame snapshot.
/// Walks the 128 quads above `saved_sp` and logs any mismatch with
/// the value snapshotted at park.  Only fires if `sp` matches the SP
/// at which the snapshot was taken (catches park/resume mismatches
/// too).  Bounded at 32 mismatches per boot to prevent runaway logs.
pub fn check_park_stack_ext(tid: ThreadId, sp: u64) {
    let i = tid as usize;
    if i >= PARK_STACK_EXT_CAP {
        return;
    }
    let snap_sp = PARK_STACK_EXT_SP[i].load(Ordering::Acquire);
    if snap_sp == 0 || snap_sp != sp {
        return;
    }
    static PARK_EXT_DELTA_LOG: core::sync::atomic::AtomicU32 =
        core::sync::atomic::AtomicU32::new(0);
    let cells = unsafe { &*PARK_STACK_EXT[i].cells.get() };
    unsafe {
        let p = sp as *const u64;
        for q in 0..PARK_STACK_EXT_QUADS {
            let live = core::ptr::read_volatile(p.add(q));
            let snap = cells[q];
            if live != snap {
                let n = PARK_EXT_DELTA_LOG.fetch_add(1, Ordering::Relaxed);
                if n < 32 {
                    #[cfg(target_arch = "x86_64")]
                    {
                        use crate::arch::x86_64::serial::{put_byte, put_bytes, put_hex_u64, put_dec_u64};
                        let mut buf = [0u8; 192];
                        let mut k = 0;
                        put_bytes(&mut buf, &mut k, b"PARK-EXT-DELTA: tid=");
                        put_dec_u64(&mut buf, &mut k, tid as u64);
                        put_bytes(&mut buf, &mut k, b" sp=");
                        put_hex_u64(&mut buf, &mut k, sp);
                        put_bytes(&mut buf, &mut k, b" quad=");
                        put_dec_u64(&mut buf, &mut k, q as u64);
                        put_bytes(&mut buf, &mut k, b" addr=");
                        put_hex_u64(&mut buf, &mut k, sp + (q as u64 * 8));
                        put_bytes(&mut buf, &mut k, b" was=");
                        put_hex_u64(&mut buf, &mut k, snap);
                        put_bytes(&mut buf, &mut k, b" now=");
                        put_hex_u64(&mut buf, &mut k, live);
                        put_bytes(&mut buf, &mut k, b" n=");
                        put_dec_u64(&mut buf, &mut k, n as u64);
                        put_byte(&mut buf, &mut k, b'\n');
                        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                    }
                    #[cfg(not(target_arch = "x86_64"))]
                    crate::println!(
                        "PARK-EXT-DELTA: tid={} sp={:#x} quad={} addr={:#x} was={:#x} now={:#x} n={}",
                        tid, sp, q, sp + (q as u64 * 8), snap, live, n,
                    );
                }
            }
        }
    }
}

/// #208 Probe A: compare live iretq slots at `sp` to the shadow recorded
/// at the most recent park.  Logs FRAME-DELTA if any field differs.
/// Skipped if no shadow exists or it was taken for a different sp.
#[inline]
pub fn check_iretq_shadow(tid: ThreadId, sp: u64) {
    check_iretq_shadow_inner(tid, sp, true);
}

/// At-dispatch variant — skips the `state == Blocked` gate because
/// try_switch flips state to Running BEFORE the check fires.  The
/// shadow vs actual comparison at this exact moment captures
/// "frame at saved_sp changed since last park" — which is the
/// #208 STALE-WRITE-RACE complement targeting frame memory rather
/// than the saved_sp field.
#[inline]
pub fn check_iretq_shadow_at_dispatch(tid: ThreadId, sp: u64) {
    check_iretq_shadow_inner(tid, sp, false);
}

#[inline]
fn check_iretq_shadow_inner(tid: ThreadId, sp: u64, require_blocked: bool) {
    // The shadow capture (capture_iretq_shadow) reads x86_64 iretq frame
    // offsets (sp+17*8 = RIP, +18*8 = CS, etc.) and the FRAME-BYTE-DELTA
    // path interprets slot[0..21] against that layout.  On aarch64 the
    // trap frame stores x0..x30 contiguously starting at sp, so slot[0]
    // is just `x0` — which for IPC-parked threads holds the port arg
    // captured at park then gets overwritten with the syscall return
    // value at wake, producing deterministic shadow≠live "deltas" that
    // are just normal IPC return-value writes (see
    // memory/project_frame_byte_delta_aarch64_noise.md).  Until we add
    // arch-specific shadow capture, no-op on non-x86 so the noise stops
    // muddying corruption-family forensics.
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (tid, sp, require_blocked);
    }
    #[cfg(target_arch = "x86_64")]
    check_iretq_shadow_inner_x86(tid, sp, require_blocked);
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn check_iretq_shadow_inner_x86(tid: ThreadId, sp: u64, require_blocked: bool) {
    let t = thread_ref(tid);
    if t.iretq_shadow_sp == 0 || t.iretq_shadow_sp != sp {
        return;
    }
    // Only check for truly-parked threads.  Running threads can
    // legitimately have their frame contents change between snapshot
    // and validate (user-mode RIP advances between successive syscalls
    // at the same kstack_top frame slot).  Boot 619 had 194 noise
    // fires on Running threads; this gate eliminates them so any
    // surviving DELTA actually means "frame at parked address changed."
    if require_blocked && t.state != ThreadState::Blocked {
        return;
    }
    let rip;
    let cs;
    let rflags;
    let rsp;
    let ss;
    unsafe {
        let frame = sp as *const u64;
        rip = core::ptr::read_volatile(frame.add(17));
        cs = core::ptr::read_volatile(frame.add(18));
        rflags = core::ptr::read_volatile(frame.add(19));
        rsp = core::ptr::read_volatile(frame.add(20));
        ss = core::ptr::read_volatile(frame.add(21));
    }
    // RIP/CS/RFLAGS are pushed by the CPU on every exception entry
    // (same-CPL and cross-CPL).  RSP and SS are only pushed on
    // cross-CPL (user→kernel) — for kernel-mode parks they reside in
    // memory beyond the actual iretq frame and contain unrelated
    // kernel-stack data.  Boot 627 fired 13 false positives this way
    // on tid=34 (CS=0x8 same-CPL, SS slot held 0x109491 from prior
    // kernel state).  Only flag deltas in the 3 always-pushed fields,
    // and gate RSP/SS checks on shadow_cs being user CS (0x23).
    let user_iretq = t.iretq_shadow_cs == 0x23;
    let core_changed = rip != t.iretq_shadow_rip
        || cs != t.iretq_shadow_cs
        || rflags != t.iretq_shadow_rflags;
    let ext_changed = user_iretq && (
        rsp != t.iretq_shadow_rsp
        || ss != t.iretq_shadow_ss
    );
    if core_changed || ext_changed {
        let n = FRAME_DELTA_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
        if n < 100 {
            #[cfg(target_arch = "x86_64")]
            {
                use crate::arch::x86_64::serial::{put_byte, put_bytes, put_hex_u64, put_dec_u64};
                let mut buf = [0u8; 320];
                let mut k = 0;
                put_bytes(&mut buf, &mut k, b"FRAME-DELTA: tid=");
                put_dec_u64(&mut buf, &mut k, tid as u64);
                put_bytes(&mut buf, &mut k, b" sp=");
                put_hex_u64(&mut buf, &mut k, sp);
                put_bytes(&mut buf, &mut k, b" src=");
                put_dec_u64(&mut buf, &mut k, t.saved_sp_source as u64);
                let pairs: [(&[u8], u64, u64); 5] = [
                    (b" RIP=", t.iretq_shadow_rip, rip),
                    (b" CS=", t.iretq_shadow_cs, cs),
                    (b" RFLAGS=", t.iretq_shadow_rflags, rflags),
                    (b" RSP=", t.iretq_shadow_rsp, rsp),
                    (b" SS=", t.iretq_shadow_ss, ss),
                ];
                for (label, before, after) in pairs {
                    put_bytes(&mut buf, &mut k, label);
                    put_hex_u64(&mut buf, &mut k, before);
                    put_bytes(&mut buf, &mut k, b"->");
                    put_hex_u64(&mut buf, &mut k, after);
                }
                put_bytes(&mut buf, &mut k, b" n=");
                put_dec_u64(&mut buf, &mut k, n as u64);
                put_byte(&mut buf, &mut k, b'\n');
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            #[cfg(not(target_arch = "x86_64"))]
            crate::println!(
                "FRAME-DELTA: tid={} sp={:#x} src={} RIP={:#x}->{:#x} CS={:#x}->{:#x} RFLAGS={:#x}->{:#x} RSP={:#x}->{:#x} SS={:#x}->{:#x} n={}",
                tid, sp, t.saved_sp_source,
                t.iretq_shadow_rip, rip,
                t.iretq_shadow_cs, cs,
                t.iretq_shadow_rflags, rflags,
                t.iretq_shadow_rsp, rsp,
                t.iretq_shadow_ss, ss,
                n
            );
        }
    }
    // #208 full-frame byte compare — independent of the 5-field check
    // above so we don't lose precision on changes that happen at
    // off-by-non-5-fields offsets (vec, errcode, GPRs).  Scans the
    // full 22-slot shadow and logs EVERY index that differs (capped at
    // 64 total log lines, 22 max per frame so one corrupted frame
    // gets fully captured).  Letting the loop continue past the first
    // mismatch reveals whether neighboring slots share a structure
    // (e.g. consecutive PerCpuData fields) — diagnostic for the
    // cluster-B addresses identified in project-208-percpu-data-match.
    {
        static FRAME_BYTE_DELTA_LOG: core::sync::atomic::AtomicU32 =
            core::sync::atomic::AtomicU32::new(0);
        unsafe {
            let frame_ptr = sp as *const u64;
            let mut per_frame = 0u32;
            for i in 0..22usize {
                let live = core::ptr::read_volatile(frame_ptr.add(i));
                let shadow = t.iretq_shadow_frame[i];
                if shadow != live {
                    // slot[14] is saved RAX.  Syscall dispatch
                    // intentionally overwrites it with the return
                    // value (set_return → set_rax) before iretq, so
                    // shadow=<syscall_nr> → live=0 (or other rc) is
                    // expected — not corruption.  Filter the noise:
                    // skip when slot=14 and shadow is in the syscall-
                    // nr range (< 0x500).  Real corruption with a
                    // wild live value still surfaces.
                    if i == 14 && shadow < 0x500 && live < 0x500 {
                        continue;
                    }
                    // #227 VA→PA continuity check on slot[17] (saved RIP).
                    // Guarded by IRETQ_SHADOW_SEQ AND a re-read of
                    // iretq_shadow_sp inside the seqlock window — the
                    // function-level gate at line 1467 reads
                    // iretq_shadow_sp BEFORE this probe, so a writer
                    // between the gate and seq_a could update
                    // {iretq_shadow_sp, PA} together and the gate's view
                    // would be stale.  Re-checking shadow_sp_now == sp
                    // inside the seqlock window catches that race.
                    #[cfg(target_arch = "x86_64")]
                    if i == 17 && (tid as usize) < SAVED_SP_LOG_CAP {
                        let ti = tid as usize;
                        let seq_a = IRETQ_SHADOW_SEQ[ti].load(Ordering::Acquire);
                        if seq_a & 1 == 0 {
                            // Not in-progress at the start — read pair.
                            let shadow_sp_now = t.iretq_shadow_sp;
                            let park_pa = IRETQ_SHADOW_SLOT17_PA[ti]
                                .load(Ordering::Relaxed);
                            let cr3: u64;
                            core::arch::asm!(
                                "mov {}, cr3", out(reg) cr3,
                                options(nomem, nostack),
                            );
                            let pml4 = (cr3 & !0xfff) as usize;
                            let slot17_va = (frame_ptr as u64)
                                .wrapping_add(17 * 8) as usize;
                            let dispatch_pa =
                                crate::arch::x86_64::mm::translate_va(
                                    pml4, slot17_va,
                                ).unwrap_or(0) as u64;
                            let seq_b = IRETQ_SHADOW_SEQ[ti]
                                .load(Ordering::Acquire);
                            if seq_a == seq_b
                                && shadow_sp_now == sp
                                && park_pa != 0
                                && park_pa != dispatch_pa
                            {
                                crate::println!(
                                    "SLOT17-VA-PA-REMAP: tid={} va={:#x} park_pa={:#x} dispatch_pa={:#x} seq={}",
                                    tid, slot17_va, park_pa, dispatch_pa, seq_a,
                                );
                            }
                        }
                    }
                    let nn = FRAME_BYTE_DELTA_LOG
                        .fetch_add(1, Ordering::Relaxed);
                    if nn < 64 {
                        let cpu = smp::cpu_id();
                        let cur = smp::current().current_thread
                            .load(Ordering::Relaxed);
                        #[cfg(target_arch = "x86_64")]
                        {
                            use crate::arch::x86_64::serial::{put_byte, put_bytes, put_hex_u64, put_dec_u64};
                            let mut buf = [0u8; 192];
                            let mut k = 0;
                            put_bytes(&mut buf, &mut k, b"FRAME-BYTE-DELTA: tid=");
                            put_dec_u64(&mut buf, &mut k, tid as u64);
                            put_bytes(&mut buf, &mut k, b" sp=");
                            put_hex_u64(&mut buf, &mut k, sp);
                            put_bytes(&mut buf, &mut k, b" src=");
                            put_dec_u64(&mut buf, &mut k, t.saved_sp_source as u64);
                            put_bytes(&mut buf, &mut k, b" slot[");
                            put_dec_u64(&mut buf, &mut k, i as u64);
                            put_bytes(&mut buf, &mut k, b"]: shadow=");
                            put_hex_u64(&mut buf, &mut k, shadow);
                            put_bytes(&mut buf, &mut k, b" live=");
                            put_hex_u64(&mut buf, &mut k, live);
                            put_bytes(&mut buf, &mut k, b" cpu=");
                            put_dec_u64(&mut buf, &mut k, cpu as u64);
                            put_bytes(&mut buf, &mut k, b" cur=");
                            put_dec_u64(&mut buf, &mut k, cur as u64);
                            put_bytes(&mut buf, &mut k, b" n=");
                            put_dec_u64(&mut buf, &mut k, nn as u64);
                            put_byte(&mut buf, &mut k, b'\n');
                            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                        }
                        #[cfg(not(target_arch = "x86_64"))]
                        crate::println!(
                            "FRAME-BYTE-DELTA: tid={} sp={:#x} src={} slot[{}]: shadow={:#x} live={:#x} cpu={} cur={} n={}",
                            tid, sp, t.saved_sp_source, i, shadow, live, cpu, cur, nn
                        );
                    }
                    per_frame += 1;
                    if per_frame >= 22 {
                        break;
                    }
                }
            }
        }
    }
}

/// Bump the per-thread kstack epoch.  Call AFTER writing `stack_base`
/// (whether to a new alloc or to 0 on free).  See [[project-kernel-ud-writer-audit]].
#[inline]
pub fn bump_kstack_epoch(t: &mut Thread) {
    t.kstack_epoch = t.kstack_epoch.wrapping_add(1);
}

/// #208 inject-site validator.  Returns true if `sp` is a plausible
/// iretq frame inside `tid`'s current kstack.  Logs (rate-limited) and
/// returns false if `tid` has been freed (stack_base==0) or `sp` falls
/// outside the kstack range.  Callsites are expected to skip the
/// `*mut ExceptionFrame` write when this returns false — that's the
/// deferred-free + stale-saved_sp race we are trying to detect.
#[inline]
pub fn validate_kstack_inject(
    tid: ThreadId,
    sp: u64,
    site: &'static str,
) -> bool {
    let t = thread_ref(tid);
    let sb = t.stack_base as u64;
    let sz = kstack_size() as u64;
    let epoch = t.kstack_epoch;
    let ok = sb != 0
        && sp >= sb
        && sp.checked_add(EXCEPTION_FRAME_SIZE as u64)
            .is_some_and(|end| end <= sb + sz);
    if !ok {
        let n = KEPOCH_BAIL_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
        if n < 100 {
            #[cfg(target_arch = "x86_64")]
            {
                use crate::arch::x86_64::serial::{put_byte, put_bytes, put_hex_u64, put_dec_u64};
                let mut buf = [0u8; 160];
                let mut k = 0;
                put_bytes(&mut buf, &mut k, b"KEPOCH-BAIL: site=");
                put_bytes(&mut buf, &mut k, site.as_bytes());
                put_bytes(&mut buf, &mut k, b" tid=");
                put_dec_u64(&mut buf, &mut k, tid as u64);
                put_bytes(&mut buf, &mut k, b" sp=");
                put_hex_u64(&mut buf, &mut k, sp);
                put_bytes(&mut buf, &mut k, b" stack_base=");
                put_hex_u64(&mut buf, &mut k, sb as u64);
                put_bytes(&mut buf, &mut k, b" size=");
                put_hex_u64(&mut buf, &mut k, sz);
                put_bytes(&mut buf, &mut k, b" epoch=");
                put_dec_u64(&mut buf, &mut k, epoch as u64);
                put_bytes(&mut buf, &mut k, b" n=");
                put_dec_u64(&mut buf, &mut k, n as u64);
                put_byte(&mut buf, &mut k, b'\n');
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            #[cfg(not(target_arch = "x86_64"))]
            crate::println!(
                "KEPOCH-BAIL: site={} tid={} sp={:#x} stack_base={:#x} size={:#x} epoch={} n={}",
                site, tid, sp, sb, sz, epoch, n
            );
        }
    }
    ok
}

/// #204 follow-on: kernel stack guard canary.
///
/// Boots 568/569/570 with `validate_thread_canary` showed Thread struct
/// fields stay clean even when corruption fires (RIP=0x3 → ret popped
/// 3 from stack).  The corruption is in the kernel stack itself, NOT
/// the Thread struct.  This canary catches stack underflow: a known
/// 16-byte magic at the BOTTOM of each kstack (lowest address).  Stack
/// grows down — overflow writes past stack_base — canary gets clobbered
/// first.
///
/// Limitation: catches GRADUAL overflow.  A single large `sub $N, %rsp`
/// frame allocation that jumps past the bottom would miss the canary
/// (writes land below stack_base in adjacent physical memory).  Future
/// upgrade = guard pages with PROT_NONE.
const STACK_CANARY_LO: u64 = 0xCAFEBEEFDEADBEEFu64;
const STACK_CANARY_HI: u64 = 0xFEEDFACEBADC0FFEu64;

/// #208 helper: scan THREAD_TABLE for any live thread whose kstack range
/// contains `v`.  Returns Some((tid, offset_in_kstack)) on hit.  Used at
/// BAD-frame dump time to annotate raw u64 values that look like
/// pointers — instead of staring at `frame[3]=0x5f60520` and wondering
/// what that is, we get `frame[3]=0x5f60520 [kstack tid=8 +0x520]`.
pub fn classify_kstack_value(v: u64) -> Option<(ThreadId, usize)> {
    // Quick range gate: kstacks live in physical kernel-low addresses
    // (below 4 GiB on x86 in current layout).  Saves the table scan for
    // small ints / large user pointers.
    if v < 0x10000 || v >= 0x1_0000_0000 {
        return None;
    }
    let ksz = kstack_size() as u64;
    let cap = RadixTable::capacity();
    for tid in 0..(cap as ThreadId) {
        let ptr = THREAD_TABLE.get(tid) as *const super::thread::Thread;
        if ptr.is_null() {
            continue;
        }
        let sb = unsafe { (*ptr).stack_base } as u64;
        if sb != 0 && v >= sb && v < sb + ksz {
            return Some((tid, (v - sb) as usize));
        }
    }
    None
}

#[inline]
pub fn init_stack_canary(stack_base: usize) {
    if stack_base == 0 {
        return;
    }
    unsafe {
        let p = stack_base as *mut u64;
        p.write_volatile(STACK_CANARY_LO);
        p.add(1).write_volatile(STACK_CANARY_HI);
    }
}

#[inline]
pub fn check_stack_canary(tid: ThreadId, callsite: &str) -> bool {
    use core::sync::atomic::{AtomicU32, Ordering};
    static FAIL_COUNT: AtomicU32 = AtomicU32::new(0);

    let t = thread_ref(tid);
    let sb = t.stack_base;
    if sb == 0 {
        return false; // idle / dead thread, no canary
    }
    // Sanity: stack_base must be either canonical-low (legacy PA / identity)
    // or in KSTACK_REGION (Phase 5b VA isolation, PML4[508]).
    let sb_u64 = sb as u64;
    let canon_low = sb_u64 >= 0x10000 && sb_u64 < 0x0000_8000_0000_0000;
    #[cfg(target_arch = "x86_64")]
    let in_kstack_region = {
        use crate::arch::x86_64::mm::{KSTACK_REGION_BASE, PML4_SLOT_SIZE};
        sb_u64 >= KSTACK_REGION_BASE && sb_u64 < KSTACK_REGION_BASE.wrapping_add(PML4_SLOT_SIZE)
    };
    #[cfg(not(target_arch = "x86_64"))]
    let in_kstack_region = false;
    if !canon_low && !in_kstack_region {
        let n = FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
        if n < 8 {
            crate::println!(
                "STACK-CANARY-FAIL @{}: tid={} stack_base={:#x} OUT-OF-RANGE (n={})",
                callsite, tid, sb, n + 1,
            );
        }
        return true;
    }
    // Phase 5b: kstack VAs in KSTACK_REGION may not be visible from the
    // currently active CR3 (cross-CR3 TLB stale or user PT inheritance
    // window).  Skip the canary read for those addresses to avoid a #PF
    // on the canary read itself.  The real corruption-detection happens
    // via the iretq-frame validator and DR0 probes, not the canary.
    if in_kstack_region {
        return false;
    }
    let (lo, hi) = unsafe {
        let p = sb as *const u64;
        (p.read_volatile(), p.add(1).read_volatile())
    };
    if lo == STACK_CANARY_LO && hi == STACK_CANARY_HI {
        return false;
    }
    let n = FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
    if n < 8 {
        crate::println!(
            "STACK-CANARY-FAIL @{}: tid={} stack_base={:#x} got lo={:#x} hi={:#x} (expect lo={:#x} hi={:#x}) (n={})",
            callsite, tid, sb, lo, hi, STACK_CANARY_LO, STACK_CANARY_HI, n + 1,
        );
        // Read current RSP via inline asm to see how close it is to overflow.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let rsp: u64;
            core::arch::asm!("mov %rsp, {0}", out(reg) rsp, options(att_syntax, nostack, preserves_flags));
            crate::println!(
                "  current_rsp={:#x} stack_top={:#x} headroom={}",
                rsp, sb + kstack_size(), (rsp as usize).saturating_sub(sb),
            );
        }
    }
    true
}

/// on_cpu sentinel (unused — kept for documentation):
/// Old sentinel for threads in deferred-requeue slots. Removed because leaving
/// on_cpu at the CPU number and using a CAS-from-cpu in drain is simpler and
/// avoids the rescue-vs-drain race.
#[allow(dead_code)]
const ON_CPU_DEFERRED: u32 = u32::MAX - 2;

// ---------------------------------------------------------------------------
// Targeted per-tid trace (call/reply slow-path investigation).
// ---------------------------------------------------------------------------
//
// `TRACE_TID` is a single ThreadId.  When non-zero, scheduler/IPC trace
// points emit a one-line ns-stamped log whenever the matched tid is
// involved (either as `current_thread_id()` or as the explicit subject of
// a wake/enqueue).  Set from userspace via `sys_debug_puts` with the
// sentinel payload `b"!TRACE_ME!\n"` — see `sys_debug_puts`.  Initialised
// to 0 at boot (no-trace).
pub static TRACE_TID: AtomicU32 = AtomicU32::new(0);

// Phase-5b stall instrumentation — per-tid wake outcome ring (aarch64-only).
//
// Each entry holds the most recent `wake_parked_thread` outcome for a tid:
//   - `WAKE_TRACE_TID[i]`        : tid this slot is recording (0 = empty)
//   - `WAKE_TRACE_OUTCOME[i]`    : outcome code packed into u32:
//        bits[3:0]   = path code (1=early, 2=fast-path-enq, 3=lost-to-cps,
//                                 4=deferred-local, 5=deferred-ipi,
//                                 6=dup-wake, 7=noop, 8=neither-cas)
//        bits[7:4]   = waker_cpu
//        bits[15:8]  = parking_cpu (when applicable)
//        bits[31:16] = unused
//   - `WAKE_TRACE_TS_NS[i]`      : monotonic_ns at the wake call
//
// Slot is hashed by (tid % WAKE_TRACE_RING).  Last writer wins.
#[cfg(target_arch = "aarch64")]
pub const WAKE_TRACE_RING: usize = 64;
#[cfg(target_arch = "aarch64")]
pub static WAKE_TRACE_TID: [AtomicU32; WAKE_TRACE_RING] = {
    const Z: AtomicU32 = AtomicU32::new(0);
    [Z; WAKE_TRACE_RING]
};
#[cfg(target_arch = "aarch64")]
pub static WAKE_TRACE_OUTCOME: [AtomicU32; WAKE_TRACE_RING] = {
    const Z: AtomicU32 = AtomicU32::new(0);
    [Z; WAKE_TRACE_RING]
};
#[cfg(target_arch = "aarch64")]
pub static WAKE_TRACE_TS_NS: [AtomicU64; WAKE_TRACE_RING] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; WAKE_TRACE_RING]
};

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn record_wake_trace(tid: ThreadId, path_code: u8, waker_cpu: u32, parking_cpu: u32) {
    let slot = (tid as usize) % WAKE_TRACE_RING;
    let v: u32 = (path_code as u32 & 0xF)
        | ((waker_cpu & 0xF) << 4)
        | ((parking_cpu & 0xFF) << 8);
    WAKE_TRACE_TID[slot].store(tid, Ordering::Relaxed);
    WAKE_TRACE_OUTCOME[slot].store(v, Ordering::Relaxed);
    WAKE_TRACE_TS_NS[slot].store(crate::arch::timer::monotonic_ns(), Ordering::Relaxed);
}
#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn record_wake_trace(_tid: ThreadId, _path_code: u8, _waker_cpu: u32, _parking_cpu: u32) {}

/// Emit a trace line if either the current thread or `subject` matches
/// `TRACE_TID`.  Subject = u32::MAX means "current only".
#[inline]
pub fn trace_point(label: &'static str, subject: u32) {
    let want = TRACE_TID.load(Ordering::Relaxed);
    if want == 0 {
        return;
    }
    let cur = current_thread_id();
    if cur as u32 != want && subject != want {
        return;
    }
    let ns = crate::arch::timer::monotonic_ns();
    let cpu = smp::cpu_id();
    crate::println!(
        "[trace tid={} subj={} label={} cpu={} ts={}]",
        cur, subject, label, cpu, ns
    );
}

/// Get a thread reference by ID via radix lookup (lockless).
#[inline]
#[track_caller]
pub fn thread_ref(tid: u32) -> &'static Thread {
    let p = THREAD_TABLE.get(tid) as *const Thread;
    // #233 slab-range guard: on x86_64, Thread structs live in
    // SLAB_THREAD_REGION (one 16 KiB window per Thread, 4 KiB mapped at
    // the TOP).  If THREAD_TABLE[tid] returns a pointer outside this
    // region, the table entry was corrupted — log + dump before the
    // caller dereferences and #GPs.  Tids 0..ncpus are idle threads
    // whose Thread structs come from the boot stack region and predate
    // SLAB_THREAD; allow those through without the check.
    #[cfg(target_arch = "x86_64")]
    {
        let ncpus = smp::num_cpus() as u32;
        if tid >= ncpus && tid < 100 {
            let pu = p as u64;
            let base = crate::arch::x86_64::mm::SLAB_REGION_BASE;
            let end = base.wrapping_add(0x0000_0080_0000_0000);
            if pu < base || pu >= end {
                static OOR_LOG: core::sync::atomic::AtomicU32 =
                    core::sync::atomic::AtomicU32::new(0);
                let n = OOR_LOG.fetch_add(1, Ordering::Relaxed);
                if n < 16 {
                    let loc = core::panic::Location::caller();
                    crate::println!(
                        "THREAD-PTR-OOR: tid={} p={:p} not in SLAB_REGION [{:#x}..{:#x}) n={} at {}:{}",
                        tid, p, base, end, n, loc.file(), loc.line(),
                    );
                }
                // #235 C2e: do NOT deref a NULL/garbage pointer — that
                // crashes the kernel.  Return a sentinel pointer to the
                // BSP idle thread so the caller can recover or fail
                // gracefully.  Real callers should re-validate; this
                // path is meant only to surface bad lookups.
                if pu == 0 {
                    let fallback = THREAD_TABLE.get(0) as *const Thread;
                    return unsafe { &*fallback };
                }
            }
        }
    }
    unsafe { &*p }
}

/// Get a task reference by ID via radix lookup (lockless).
#[inline]
pub fn task_ref(id: TaskId) -> &'static Task {
    let p = TASK_TABLE.get(id) as *const Task;
    unsafe { &*p }
}

/// Get a task reference by ID, returning None if not in ART.
#[inline]
pub fn task_ref_opt(id: TaskId) -> Option<&'static Task> {
    SCHED_TASK_ART
        .lookup(id as u64)
        .map(|val| unsafe { &*(val as *const Task) })
}

/// Get a thread reference by ID, returning None if not in ART.
#[inline]
pub fn thread_ref_opt(id: ThreadId) -> Option<&'static Thread> {
    SCHED_THREAD_ART
        .lookup(id as u64)
        .map(|val| unsafe { &*(val as *const Thread) })
}

// Per-CPU scheduler state lives in dynamic slices sized by num_cpus() and
// installed by `init_dynamic_percpu` (invoked from smp::init_dynamic_percpu
// just after phys::init). See the runtime-nr_cpus plan.
//
// Each array is stored behind an AtomicPtr so it can be published once and
// read cheaply (relaxed load + bounds check) from every call site. The
// accessors panic (via debug_assert!) if called before init_dynamic_percpu.

/// Per-CPU saved frame SP. The exception handler stores the current frame_sp
/// here before calling syscall dispatch, so that park_current_for_ipc() can
/// read it without changing dispatch()'s signature.
static CURRENT_FRAME_SP_PTR: AtomicPtr<AtomicU64> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn current_frame_sp() -> &'static [AtomicU64] {
    let ptr = CURRENT_FRAME_SP_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "CURRENT_FRAME_SP not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Per-CPU pending context switch target SP. When a syscall handler parks the
/// current thread or does a direct handoff, it stores the target thread's SP
/// here. The exception handler checks this after dispatch() returns and uses
/// it as the new SP if non-zero.
static PENDING_SWITCH_SP_PTR: AtomicPtr<AtomicU64> =
    AtomicPtr::new(core::ptr::null_mut());


#[inline]
fn pending_switch_sp() -> &'static [AtomicU64] {
    let ptr = PENDING_SWITCH_SP_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "PENDING_SWITCH_SP not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Per-CPU flag indicating a park-triggered context switch has been staged
/// (pending_switch_sp is set) but the assembly `mov rsp, rax` has not yet
/// completed.  Set by park_current_for_ipc / park_current_for_sleep when
/// they store pending_switch_sp; cleared by `clear_pending_switch()` at
/// exception handler entry (by which time the stack switch is done).
/// `wake_parked_thread` spins on this flag instead of `pending_switch_sp`
/// directly, so that take_pending_switch can safely swap(0) without
/// signalling "stack switch done" prematurely.
static PARK_SWITCH_PENDING_PTR: AtomicPtr<core::sync::atomic::AtomicBool> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
pub fn park_switch_pending() -> &'static [core::sync::atomic::AtomicBool] {
    let ptr = PARK_SWITCH_PENDING_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "PARK_SWITCH_PENDING not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Per-CPU ID of the thread that just parked (IPC or sleep) on this CPU.
/// Set before the park becomes visible to wakers. Cleared by
/// clear_pending_switch at the next exception handler entry, which also
/// clears the per-thread stack_switch_pending flag.
static PARKED_TID_PTR: AtomicPtr<AtomicU32> = AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn parked_tid() -> &'static [AtomicU32] {
    let ptr = PARKED_TID_PTR.load(Ordering::Relaxed);
    if ptr.is_null() {
        // During early init before alloc. Return empty safe slice.
        return &[];
    }
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Per-CPU deferred re-enqueue. When try_switch re-enqueues the previous
/// thread, a work-stealing CPU could dequeue it while this CPU is still
/// physically on its kernel stack (between percpu_enqueue and the assembly
/// `mov rsp, rax`). We defer the enqueue and process it at the start of
/// the next try_switch / voluntary_reschedule / park_current_for_ipc.
/// Encoding: bits [31:0] = tid, bits [39:32] = prio, bits [47:40] = cpu.
/// Sentinel: 0 = no deferred enqueue (tid 0 = idle, never deferred).
static DEFERRED_REQUEUE_PTR: AtomicPtr<AtomicU64> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn deferred_requeue() -> &'static [AtomicU64] {
    let ptr = DEFERRED_REQUEUE_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "DEFERRED_REQUEUE not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Mirror of `dequeue_set_pending`: called from each PENDING→cpu CAS-ok
/// site after the thread successfully transitions to Running.  Clears
/// `pending_set_ns` so the low-threshold rescue diag doesn't false-fire,
/// resets the per-tid one-shot log gate, and bumps the CPU's
/// `dispatch_cas_ok_count` to mirror `dispatch_set_pending_count`.
#[inline]
fn dispatch_cas_ok(pcpu: &smp::PerCpuData, tid: ThreadId) {
    // #135 wake-to-dispatch latency probe: compute (cas_ok_ts - pending_set_ns)
    // and bucket per-CPU before clearing the stamp.  4 sub-buckets per
    // decade × 6 decades covers 1µs..1s with ~78%-resolution per step
    // (10^0.25 ≈ 1.778).  Dumps compute p50/p90/p99/p99.9 from these
    // counts for tail visibility without a wide print.  swap-to-0 so a
    // future dequeue_set_pending stamps a fresh value; load-then-store
    // would race with parallel rescue re-enqueues.
    let pend_ts = thread_ref(tid).pending_set_ns.swap(0, Ordering::Relaxed);
    if pend_ts != 0 {
        // #163 paravirt fix: pending_set_ns + delta in vcpu_runtime so
        // host-pause time doesn't inflate dispatch-latency histograms.
        // Stamp side: dequeue_set_pending uses the same clock.
        let now = crate::arch::timer::vcpu_runtime_ns();
        let delta = now.saturating_sub(pend_ts);
        let bucket = lat_bucket(delta);
        pcpu.dispatch_latency_hist[bucket].fetch_add(1, Ordering::Relaxed);
    }
    if (tid as usize) < PENDING_LOW_LOGGED.len() {
        PENDING_LOW_LOGGED[tid as usize].store(false, Ordering::Relaxed);
    }
    pcpu.dispatch_cas_ok_count.fetch_add(1, Ordering::Relaxed);
    // Layer 3 paravirt: snapshot this CPU's steal-time at the moment of
    // a successful dispatch.  The fast-rescue path on another CPU will
    // read this value and the picking CPU's CURRENT steal to compute
    // "stolen ns since last successful dispatch on last_cpu", a positive
    // confirmation that the picking CPU is host-descheduled (vs. just
    // legitimately busy in a long CLI region — those don't grow steal).
    if let Some(s) = crate::arch::hypervisor::ops().steal_time_ns() {
        pcpu.steal_ns_at_last_dispatch.store(s, Ordering::Relaxed);
    }
}

/// #135 latency histogram cutpoints (ns).  Log-spaced at 10^(0.25·k):
/// 4 sub-buckets per decade × 6 decades covering 1µs..1s.  Buckets:
///   [0]   <1µs (underflow)
///   [1..=24]  the 24 sub-decade ranges
///   [25]  ≥1s (overflow)
/// Use `lat_bucket(ns)` to assign deltas; use `lat_percentile_ns` to
/// compute a percentile from a snapshot of bucket counts.
const LAT_CUTS_NS: [u64; 25] = [
    1_000, 1_778, 3_162, 5_623, 10_000,
    17_783, 31_623, 56_234, 100_000,
    177_828, 316_228, 562_341, 1_000_000,
    1_778_279, 3_162_278, 5_623_413, 10_000_000,
    17_782_794, 31_622_777, 56_234_133, 100_000_000,
    177_827_941, 316_227_766, 562_341_325, 1_000_000_000,
];

#[inline]
fn lat_bucket(delta_ns: u64) -> usize {
    // Linear scan is fine — 25 comparisons, called per dispatch.  A
    // binary search would shave ~4 comparisons but complicates inlining
    // and is not measurable at this site.
    let mut i = 0;
    while i < LAT_CUTS_NS.len() {
        if delta_ns < LAT_CUTS_NS[i] {
            return i;
        }
        i += 1;
    }
    LAT_CUTS_NS.len() // bucket 25 (overflow)
}

/// Estimate the `percentile_x100`-th percentile (e.g. 5000 = p50,
/// 9990 = p99.9) from a 26-element bucket snapshot.  Returns the upper
/// cutpoint of the bucket the threshold falls into — i.e. an upper-
/// bound estimate of the percentile.  For the underflow bucket (delta
/// < 1µs) returns 1µs; for the overflow bucket (delta ≥ 1s) returns
/// `u64::MAX` (rendered as `>=1s` in dumps).
fn lat_percentile_ns(hist: &[u64; 26], percentile_x100: u32) -> u64 {
    let total: u64 = hist.iter().sum();
    if total == 0 {
        return 0;
    }
    // Threshold count: ceil(total * pct / 10000).  We want the first
    // bucket whose cumulative count >= threshold.
    let threshold = ((total as u128) * (percentile_x100 as u128) + 9999) / 10000;
    let mut cum: u128 = 0;
    for (i, &c) in hist.iter().enumerate() {
        cum += c as u128;
        if cum >= threshold {
            if i == 0 {
                return LAT_CUTS_NS[0]; // <1µs bucket → 1µs upper bound
            } else if i < LAT_CUTS_NS.len() {
                return LAT_CUTS_NS[i]; // sub-decade upper bound
            } else {
                return u64::MAX; // overflow
            }
        }
    }
    u64::MAX
}

/// Snapshot a CPU's dispatch_latency_hist into a plain [u64; 26] for
/// percentile computation.  Reads each atomic with Relaxed ordering.
#[inline]
fn lat_snapshot(pcpu: &smp::PerCpuData) -> [u64; 26] {
    let mut h = [0u64; 26];
    for i in 0..26 {
        h[i] = pcpu.dispatch_latency_hist[i].load(Ordering::Relaxed);
    }
    h
}

/// Transition a dequeued thread's on_cpu to ON_CPU_PENDING so try_switch's
/// CAS(ON_CPU_PENDING → cpu) can claim it.
///
/// Idempotent under NEW_INV: every dispatching path expects on_cpu to be
/// ON_CPU_PENDING just before the CAS to a real CPU number.
///
/// #120 dispatch-symmetry: bumps `pcpu.dispatch_set_pending_count` and
/// stamps `pending_set_ns` on the thread.  The matching `cas_ok` site in
/// try_switch / voluntary_reschedule clears `pending_set_ns` and bumps
/// `pcpu.dispatch_cas_ok_count`.  Comparing the two on a CPU-by-CPU basis
/// localizes paths where a thread enters PENDING but never makes it to a
/// successful CAS — the residual oscillation pattern.
#[inline]
fn dequeue_set_pending(tid: ThreadId) {
    // #163 paravirt fix: stamp pending_set_ns in vcpu_runtime so the
    // age computation in the rescue path measures "time waiting on a
    // running vCPU" rather than wall time (which includes host pause).
    // Wall-time stamps produced 100s spurious rescues per boot 49.
    let now = crate::arch::timer::vcpu_runtime_ns();
    thread_ref(tid).pending_set_ns.store(now, Ordering::Relaxed);
    // Layer 3 paravirt: snapshot this CPU's steal-time at pending
    // stamp time.  The fast-rescue path compares against this to
    // detect "host paused the picking CPU DURING this pending wait"
    // — the correct signal, distinct from "since-last-dispatch"
    // (which refreshes every dispatch and underreports the delta).
    let steal_at_pending = crate::arch::hypervisor::ops()
        .steal_time_ns()
        .unwrap_or(0);
    thread_ref(tid).pending_set_steal_ns.store(steal_at_pending, Ordering::Relaxed);
    thread_ref(tid).on_cpu.store(ON_CPU_PENDING, Ordering::Release);
    smp::current()
        .dispatch_set_pending_count
        .fetch_add(1, Ordering::Relaxed);
    record_trans(tid as u32, TRANS_SET_PENDING, thread_ref(tid).state, ON_CPU_PENDING);
}

#[inline]
fn drain_deferred_requeue(cpu: u32) {
    let val = deferred_requeue()[cpu as usize].swap(0, Ordering::AcqRel);
    if val != 0 {
        let tid = (val & 0xFFFFFFFF) as ThreadId;
        let prio = ((val >> 32) & 0xFF) as u8;
        let target = ((val >> 40) & 0xFF) as u32;
        // NEW_INV: the deferred-store path already stored ON_CPU_PENDING
        // before publishing the slot. percpu_enqueue's in_queue swap is
        // the sole double-enqueue guard. No CAS protocol is needed; rescue
        // cannot enqueue a thread with on_cpu=PENDING (it filters PENDING
        // as transient), so there is no racing source of double-enqueues
        // from the rescue path.
        trace_sched(tid, 2); // 2=drain_enq
        set_enq_tag(1); // 1=drain_deferred
        percpu_enqueue(target, prio, tid);
    }
}

// ---------------------------------------------------------------------------
// Per-tid event trace (separate from Thread struct to avoid layout changes)
// ---------------------------------------------------------------------------
// Stores the last scheduling event for each thread. When rescue fires, we
// print this to identify which code path left the thread orphaned.
// Encoding: bits [7:0] = event type, bits [39:8] = cpu, bits [63:40] = seq.
// Events: 1=deferred_store, 2=drain_enq, 3=pick_deq, 4=on_cpu_set,
//         5=on_cpu_clear, 6=state_ready, 7=state_running, 8=rescue_enq,
//         9=wake_enq, 10=wake_no_enq, 11=double_enq, 12=steal_deq,
//         13=park_sleep, 14=park_ipc, 15=sleep_wake, 16=ipc_wake
const TRACE_CAP: usize = 256;
static TRACE_EVENTS: [AtomicU64; TRACE_CAP] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; TRACE_CAP]
};
static TRACE_SEQ: AtomicU64 = AtomicU64::new(1);

#[inline(always)]
fn trace_sched(tid: u32, event: u8) {
    if (tid as usize) < TRACE_CAP {
        let seq = TRACE_SEQ.fetch_add(1, Ordering::Relaxed);
        let cpu = smp::cpu_id() as u64;
        let packed = ((seq & 0xFF_FFFF) << 40) | ((cpu & 0xFFFF_FFFF) << 8) | (event as u64);
        TRACE_EVENTS[tid as usize].store(packed, Ordering::Release);
    }
}

fn trace_last(tid: u32) -> (u8, u32, u32) {
    if (tid as usize) < TRACE_CAP {
        let v = TRACE_EVENTS[tid as usize].load(Ordering::Acquire);
        let event = (v & 0xFF) as u8;
        let cpu = ((v >> 8) & 0xFFFF_FFFF) as u32;
        let seq = ((v >> 40) & 0xFF_FFFF) as u32;
        (event, cpu, seq)
    } else {
        (0, 0, 0)
    }
}

/// Per-CPU deferred kernel stack free. When a thread exits, it can't free
/// its own stack (it's running on it). The address is stored here and freed
/// by the next thread scheduled on that CPU.
static DEFERRED_KSTACK_PTR: AtomicPtr<AtomicUsize> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn deferred_kstack() -> &'static [AtomicUsize] {
    let ptr = DEFERRED_KSTACK_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "DEFERRED_KSTACK not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Per-CPU deferred thread ID — the thread whose kstack is in DEFERRED_KSTACK.
/// When try_switch drains the deferred free, it also sets stack_base=0 on this
/// thread, making the slot eligible for reuse. This prevents a race where a
/// slot is reused while the dead thread is still physically running.
static DEFERRED_THREAD_PTR: AtomicPtr<AtomicUsize> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn deferred_thread() -> &'static [AtomicUsize] {
    let ptr = DEFERRED_THREAD_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "DEFERRED_THREAD not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Per-CPU deferred killed-thread cleanup. When try_switch preempts a
/// killed user thread, it marks it Dead and stores the thread ID here.
/// The next tick() call drains this and does full cleanup (aspace destroy, etc.).
static DEFERRED_KILL_PTR: AtomicPtr<AtomicUsize> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn deferred_kill() -> &'static [AtomicUsize] {
    let ptr = DEFERRED_KILL_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "DEFERRED_KILL not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// #208 source-side liveness guard for the kstack premature-free /
/// phys-realias hypothesis.  The Phase-5 wild-RIP corruption is a write
/// through a kstack VA into another LIVE thread's iretq frame.  Phys
/// double-issue, frame-layout shift, and DM-alias writes are all ruled
/// out; the leading remaining cause is a deferred kstack freed while its
/// owner thread is still LIVE (state != Dead / still queued / current on
/// another CPU), then realloc'd to a new thread — the two then alias the
/// same kstack phys and the new thread's spawn-frame write scribbles the
/// live thread's frame.  The allocator's own double-issue detector is
/// blind to this (a legit free DID happen between the two allocs).
///
/// This guard is DETECTION-ONLY: it scans THREAD_TABLE at each kstack
/// free / alloc and reports any LIVE thread still claiming that phys base,
/// but never changes free/alloc behavior — we want to OBSERVE the race,
/// not mask it.
// Default OFF: 2026-06-16 A/B (7 boots incl. stress) found 0 premature-frees /
// 0 realias while #208 still fired — ruled out the deferred-free race. Kept as
// an opt-in assertion of the (previously comment-only) "freed kstack's owner is
// Dead" invariant; flip true to re-arm.
#[allow(dead_code)]
const KSTACK_LIVENESS_GUARD: bool = false;

/// Find a LIVE thread (state in Running/Ready/Blocked — NOT Dead) whose
/// `stack_phys_base == pa`, excluding `skip_tid` and the per-CPU idle
/// threads.  Returns `(tid, state as u8)` of the first such owner, or
/// None.  Read-only + defensive: the corruption itself can make a
/// `THREAD_TABLE.get(tid)` return a wild pointer, so we bounds-check the
/// pointer is a valid Thread VA in SLAB_THREAD_REGION before dereferencing
/// it (skip out-of-region entries rather than #PF).  Only clearly-live
/// states are flagged — a thread mid-exit that is already `Dead` (its
/// stack legitimately about to be reclaimed) must NOT trip the guard.
///
/// State encoding (matches `ThreadState` discriminants): 0=Ready,
/// 1=Running, 2=Blocked, 3=Dead (we never return Dead).
#[cfg(target_arch = "x86_64")]
fn live_thread_owning_kstack_phys(pa: usize, skip_tid: u32) -> Option<(u32, u8)> {
    if pa == 0 {
        return None;
    }
    let ncpus = smp::num_cpus() as u32;
    // Scan live low tids (mirrors the proactive integrity scan's bounded
    // range; the corruption family is server/thread churn well under 256).
    for tid in ncpus..256u32 {
        if tid == skip_tid {
            continue;
        }
        // Exclude per-CPU idle threads (their kstacks come from boot/AP
        // stack regions, not the kstack window) — same policy as
        // log_saved_sp_out_of_range / thread_ref.
        let mut is_idle = false;
        for cpu in 0..ncpus {
            if smp::get(cpu).idle_thread_id.load(Ordering::Relaxed) == tid {
                is_idle = true;
                break;
            }
        }
        if is_idle {
            continue;
        }
        let p = THREAD_TABLE.get(tid) as u64;
        // DEFENSIVE: skip null (tid not wired) and any pointer that isn't a
        // valid Thread-struct VA — a corrupted table entry must not cause a
        // #PF inside the guard.
        if p == 0 || !is_thread_struct_va(p) {
            continue;
        }
        let t = unsafe { &*(p as *const Thread) };
        if t.stack_phys_base != pa {
            continue;
        }
        let st = t.state;
        // Only flag CLEARLY-LIVE owners.  A thread already in `Dead` is in
        // the legitimate-free window — that's the expected case at a free
        // site and must produce ZERO reports (false-positive bar).
        let code = match st {
            ThreadState::Ready => 0u8,
            ThreadState::Running => 1u8,
            ThreadState::Blocked => 2u8,
            ThreadState::Dead => continue,
        };
        return Some((tid, code));
    }
    None
}

/// Emit the corruption-safe, rate-limited KSTACK-PREMATURE-FREE report.
/// `tid`/`state` are the LIVE owner caught still claiming `pa`; `dead_tid`
/// is the tid this free site believed it was reclaiming (u32::MAX if not
/// yet known).  Uses only the direct-UART `put_*` path (no fmt, no heap)
/// so the line survives a scribbled formatter scratch.
#[cfg(target_arch = "x86_64")]
#[cold]
fn report_kstack_premature_free(tid: u32, state: u8, pa: usize, freeing_cpu: u32, dead_tid: u32) {
    static N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    if N.fetch_add(1, Ordering::Relaxed) >= 16 {
        return;
    }
    use crate::arch::x86_64::serial::{handler_write_bytes, put_bytes, put_dec_u64, put_hex_u64};
    let mut buf = [0u8; 160];
    let mut k = 0;
    put_bytes(&mut buf, &mut k, b"KSTACK-PREMATURE-FREE: live_owner_tid=");
    put_dec_u64(&mut buf, &mut k, tid as u64);
    put_bytes(&mut buf, &mut k, b" state=");
    put_dec_u64(&mut buf, &mut k, state as u64);
    put_bytes(&mut buf, &mut k, b" phys=");
    put_hex_u64(&mut buf, &mut k, pa as u64);
    put_bytes(&mut buf, &mut k, b" freeing_cpu=");
    put_dec_u64(&mut buf, &mut k, freeing_cpu as u64);
    put_bytes(&mut buf, &mut k, b" dead_tid_expected=");
    if dead_tid == u32::MAX {
        put_bytes(&mut buf, &mut k, b"none");
    } else {
        put_dec_u64(&mut buf, &mut k, dead_tid as u64);
    }
    put_bytes(&mut buf, &mut k, b"\n");
    handler_write_bytes(&buf[..k.min(buf.len())]);
}

/// Emit the corruption-safe, rate-limited KSTACK-PHYS-REALIAS report — the
/// realloc side of the same race: the phys allocator just handed back a
/// page that a still-LIVE thread claims as its kstack base.
#[cfg(target_arch = "x86_64")]
#[cold]
fn report_kstack_phys_realias(new_pa: usize, tid: u32, state: u8) {
    static N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    if N.fetch_add(1, Ordering::Relaxed) >= 16 {
        return;
    }
    use crate::arch::x86_64::serial::{handler_write_bytes, put_bytes, put_dec_u64, put_hex_u64};
    let mut buf = [0u8; 128];
    let mut k = 0;
    put_bytes(&mut buf, &mut k, b"KSTACK-PHYS-REALIAS: new_pa=");
    put_hex_u64(&mut buf, &mut k, new_pa as u64);
    put_bytes(&mut buf, &mut k, b" still_owned_by_live_tid=");
    put_dec_u64(&mut buf, &mut k, tid as u64);
    put_bytes(&mut buf, &mut k, b" state=");
    put_dec_u64(&mut buf, &mut k, state as u64);
    put_bytes(&mut buf, &mut k, b"\n");
    handler_write_bytes(&buf[..k.min(buf.len())]);
}

/// Phase-5 kstack-leak fix: drain a prior pending deferred kstack BEFORE a
/// store site overwrites the single per-CPU `deferred_kstack()[cpu]` slot.
///
/// That slot holds at most ONE pending kstack PA to free, but two store
/// sites write it (the try_switch death path and the thread-exit
/// self-defer path), while the only drain runs in try_switch and is
/// skipped whenever the exiting thread is still current (`cur==deferred`).
/// Under rapid same-CPU exits a second store therefore OVERWROTE — and
/// leaked — the first thread's 1 MiB kstack phys.  init's Phase-5 server
/// smoke tests churn ~1000+ threads, leaking ~1 GB on a 2 GB guest →
/// `alloc_kstack_zeroed` fails → `do_spawn_heavy_work FAILED
/// step=kstack_alloc` → the boot wedges at Phase 5.  Calling this before
/// each store frees the prior entry first, bounding the leak to zero.
///
/// Safe to free here: the prior entry belongs to an already-dead thread
/// that has been switched off this CPU.  We never free `exclude_pa` (the
/// stack about to be stored) nor the currently-running stack — the same
/// guard the try_switch drain uses.  The slot is per-CPU, so the CAS only
/// races with this CPU's own try_switch drain; whichever wins is the sole
/// owner and the other no-ops.
fn drain_prior_deferred_kstack(cpu: usize, exclude_pa: usize) {
    let prior = deferred_kstack()[cpu].load(Ordering::Acquire);
    if prior == 0 || prior == exclude_pa {
        return;
    }
    let cur_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let cur_stack = thread_ref(cur_tid).stack_phys_base;
    if prior == cur_stack {
        return; // never free the stack we're executing on
    }
    if deferred_kstack()[cpu]
        .compare_exchange(prior, 0, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return; // the try_switch drain claimed it first
    }
    kstack_pa_audit(prior, kstack_size(), -1, "free-prior");
    kstack_pa_unregister(prior as u64);
    // #208 KSTACK_LIVENESS_GUARD: detection-only — before we free this
    // deferred kstack phys, verify NO still-LIVE thread claims it as its
    // stack base.  The dead tid we believe we're reclaiming is in
    // deferred_thread()[cpu]; peek it as skip_tid + the expected-dead id.
    // If a LIVE owner is found the deferred-free race is the root cause:
    // the page is about to be returned to the allocator while a running/
    // ready/blocked thread still uses it.  We still free (behavior
    // unchanged) so the boot trajectory is identical.
    #[cfg(target_arch = "x86_64")]
    if KSTACK_LIVENESS_GUARD {
        let expected_dead = deferred_thread()[cpu].load(Ordering::Acquire) as u32;
        let skip = if (expected_dead as usize) < RadixTable::capacity() {
            expected_dead
        } else {
            u32::MAX
        };
        if let Some((tid, state)) = live_thread_owning_kstack_phys(prior, skip) {
            report_kstack_premature_free(tid, state, prior, smp::cpu_id(), skip);
        }
    }
    crate::mm::phys::free_pages(crate::mm::page::PhysAddr::new(prior), KSTACK_ORDER);
    let dead_tid = deferred_thread()[cpu].swap(usize::MAX, Ordering::AcqRel);
    if dead_tid < RadixTable::capacity() {
        // Safety: dead thread is Dead, not on any queue or CPU.
        let t = unsafe { thread_mut_from_ref(dead_tid as ThreadId) };
        t.stack_base = 0;
        bump_kstack_epoch(t); // #208
    }
}

const NUM_PRIORITIES: usize = 256;

/// Sentinel value for empty linked-list pointers (head/tail/next/prev).
/// Using 0 (idle thread ID) as sentinel so RunQueue/PerCpuRunQueues initialize
/// to all-zero bytes and land in BSS rather than .data. Idle threads are never
/// enqueued, so ID 0 is safe as "no thread".
const RQ_NIL: u32 = 0;

/// Per-priority run queue — a doubly-linked FIFO list threaded through
/// Thread::run_next / run_prev. No fixed capacity limit.
struct RunQueue {
    head: u32, // First thread (RQ_NIL = empty)
    tail: u32, // Last thread (RQ_NIL = empty)
    len: u32,  // Count of enqueued threads
}

impl RunQueue {
    const fn new() -> Self {
        Self {
            head: RQ_NIL,
            tail: RQ_NIL,
            len: 0,
        }
    }

    /// Append a thread to the tail of the queue.
    fn push(&mut self, tid: ThreadId) {
        let t = thread_ref(tid);
        t.run_next.store(RQ_NIL, Ordering::Relaxed);
        t.run_prev.store(self.tail, Ordering::Relaxed);
        if self.tail != RQ_NIL {
            thread_ref(self.tail).run_next.store(tid, Ordering::Relaxed);
        } else {
            self.head = tid;
        }
        self.tail = tid;
        self.len += 1;
    }

    /// Remove and return the head of the queue.
    fn pop(&mut self) -> Option<ThreadId> {
        if self.head == RQ_NIL {
            return None;
        }
        let tid = self.head;
        let t = thread_ref(tid);
        let next = t.run_next.load(Ordering::Relaxed);
        t.run_next.store(RQ_NIL, Ordering::Relaxed);
        t.run_prev.store(RQ_NIL, Ordering::Relaxed);
        self.head = next;
        if next != RQ_NIL {
            thread_ref(next).run_prev.store(RQ_NIL, Ordering::Relaxed);
        } else {
            self.tail = RQ_NIL;
        }
        self.len -= 1;
        Some(tid)
    }

    /// Unlink an arbitrary thread from the queue (O(1) given its linkage).
    fn unlink(&mut self, tid: ThreadId) {
        let t = thread_ref(tid);
        let prev = t.run_prev.load(Ordering::Relaxed);
        let next = t.run_next.load(Ordering::Relaxed);
        if prev != RQ_NIL {
            thread_ref(prev).run_next.store(next, Ordering::Relaxed);
        } else {
            self.head = next;
        }
        if next != RQ_NIL {
            thread_ref(next).run_prev.store(prev, Ordering::Relaxed);
        } else {
            self.tail = prev;
        }
        t.run_next.store(RQ_NIL, Ordering::Relaxed);
        t.run_prev.store(RQ_NIL, Ordering::Relaxed);
        self.len -= 1;
    }

    /// Search for and remove a thread belonging to the given coscheduling group
    /// that can run on the given CPU.
    #[allow(dead_code)]
    fn find_remove_by_group_for_cpu(&mut self, group: u32, cpu: u32) -> Option<ThreadId> {
        let mut cur = self.head;
        while cur != RQ_NIL {
            let t = thread_ref(cur);
            if t.cosched_group.load(Ordering::Relaxed) == group && t.affinity_mask.test(cpu) {
                self.unlink(cur);
                return Some(cur);
            }
            cur = t.run_next.load(Ordering::Relaxed);
        }
        None
    }

    /// Search for and remove the first thread whose affinity allows it to run
    /// on the given CPU.
    #[allow(dead_code)]
    fn find_remove_for_cpu(&mut self, cpu: u32) -> Option<ThreadId> {
        let mut cur = self.head;
        while cur != RQ_NIL {
            let t = thread_ref(cur);
            if t.affinity_mask.test(cpu) {
                self.unlink(cur);
                return Some(cur);
            }
            cur = t.run_next.load(Ordering::Relaxed);
        }
        None
    }

    /// Search for and remove a thread in the given coscheduling group (no CPU check).
    /// Used by per-CPU queues where affinity is already guaranteed.
    fn find_remove_by_group(&mut self, group: u32) -> Option<ThreadId> {
        let mut cur = self.head;
        while cur != RQ_NIL {
            let t = thread_ref(cur);
            if t.cosched_group.load(Ordering::Relaxed) == group {
                self.unlink(cur);
                return Some(cur);
            }
            cur = t.run_next.load(Ordering::Relaxed);
        }
        None
    }

    /// Search for and remove a thread whose affinity allows `cpu` (for work stealing).
    fn find_remove_with_affinity(&mut self, cpu: u32) -> Option<ThreadId> {
        let mut cur = self.head;
        while cur != RQ_NIL {
            let t = thread_ref(cur);
            if t.affinity_mask.test(cpu) {
                self.unlink(cur);
                return Some(cur);
            }
            cur = t.run_next.load(Ordering::Relaxed);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Per-CPU run queues with active priority bitmap
// ---------------------------------------------------------------------------

/// Per-CPU run queues: 256 linked-list heads + 256-bit active bitmap + EEVDF heap.
/// Each CPU's instance is protected by its own SpinLock in PERCPU_RQ.
struct PerCpuRunQueues {
    queues: [RunQueue; NUM_PRIORITIES],
    active: [u64; 4],
    cosched_burst: u32,
    /// EEVDF d-4 min-heap keyed on virtual deadline.
    eevdf_heap: super::heap::Heap4,
    /// Monotonically advancing virtual time floor.  New/waking threads snap
    /// their vruntime to at least this value so sleepers don't accumulate
    /// unbounded credit.
    eevdf_min_vruntime: u64,
    /// Number of SCHED_NORMAL threads currently in the EEVDF heap.
    eevdf_nr_running: u32,
}

impl PerCpuRunQueues {
    const fn new() -> Self {
        Self {
            queues: [const { RunQueue::new() }; NUM_PRIORITIES],
            active: [0; 4],
            cosched_burst: 0,
            eevdf_heap: super::heap::Heap4::new(),
            eevdf_min_vruntime: 0,
            eevdf_nr_running: 0,
        }
    }

    /// Enqueue a thread at the given priority level.
    fn push(&mut self, prio: u8, tid: ThreadId) {
        self.queues[prio as usize].push(tid);
        self.active[prio as usize / 64] |= 1u64 << (prio as usize % 64);
    }

    /// Dequeue the highest-priority (lowest numeric) thread from the bitmap. O(1).
    fn pop_highest(&mut self) -> Option<ThreadId> {
        for word in 0..4 {
            if self.active[word] != 0 {
                let bit = self.active[word].trailing_zeros() as usize;
                let prio = word * 64 + bit;
                let tid = self.queues[prio].pop()?;
                if self.queues[prio].len == 0 {
                    self.active[word] &= !(1u64 << bit);
                }
                return Some(tid);
            }
        }
        None
    }

    /// Class-aware pick-next: RT bitmap (prio 0-127), then EEVDF heap,
    /// then legacy/demoted bitmap (prio 128-255).
    fn class_pick_next(&mut self) -> Option<ThreadId> {
        // 1. RT: check bitmap words 0-1 (priorities 0-127).
        for word in 0..2 {
            if self.active[word] != 0 {
                let bit = self.active[word].trailing_zeros() as usize;
                let prio = word * 64 + bit;
                let tid = self.queues[prio].pop()?;
                if self.queues[prio].len == 0 {
                    self.active[word] &= !(1u64 << bit);
                }
                return Some(tid);
            }
        }
        // 2. EEVDF: pick eligible thread with earliest deadline.
        if let Some((tid, _deadline)) = self.eevdf_heap.pick_eligible(self.eevdf_min_vruntime) {
            self.eevdf_nr_running -= 1;
            return Some(tid);
        }
        // 3. Legacy/demoted/idle: check bitmap words 2-3 (priorities 128-255).
        for word in 2..4 {
            if self.active[word] != 0 {
                let bit = self.active[word].trailing_zeros() as usize;
                let prio = word * 64 + bit;
                let tid = self.queues[prio].pop()?;
                if self.queues[prio].len == 0 {
                    self.active[word] &= !(1u64 << bit);
                }
                return Some(tid);
            }
        }
        None
    }

    /// Find and dequeue a thread in the given coscheduling group.
    /// Checks RT bitmap queues first, then the EEVDF heap.
    ///
    /// #120 dispatch-symmetry audit (2026-05-09): callers of `pop_for_group`
    /// at `percpu_pick_next_cosched` correctly invoke `dequeue_set_pending`
    /// after the pop, mirroring the `class_pick_next` path. The cosched
    /// dispatch path is NOT asymmetric on the on_cpu transition.
    ///
    /// Separate observation (not addressed here): the EEVDF heap variant
    /// scans `0..n` linearly without the rotating `scan_start` origin used
    /// by `pick_eligible`. If multiple cosched group mates share the same
    /// deadline, the lowest physical position wins back-to-back, which can
    /// reproduce the LIFO-starvation pattern within a cosched burst. Out of
    /// scope for the dispatch-symmetry counter pair, flagged for follow-up.
    fn pop_for_group(&mut self, group: u32) -> Option<ThreadId> {
        // 1. RT bitmap queues (priorities 0-127).
        for word in 0..2 {
            if self.active[word] != 0 {
                let mut bits = self.active[word];
                while bits != 0 {
                    let bit = bits.trailing_zeros() as usize;
                    let prio = word * 64 + bit;
                    if let Some(tid) = self.queues[prio].find_remove_by_group(group) {
                        if self.queues[prio].len == 0 {
                            self.active[word] &= !(1u64 << bit);
                        }
                        return Some(tid);
                    }
                    bits &= !(1u64 << bit);
                }
            }
        }
        // 2. EEVDF heap (SCHED_NORMAL threads).
        if let Some((tid, _key)) = self.eevdf_heap.pop_for_group(group, self.eevdf_min_vruntime) {
            self.eevdf_nr_running -= 1;
            return Some(tid);
        }
        // 3. Legacy/demoted bitmap queues (priorities 128-255).
        for word in 2..4 {
            if self.active[word] != 0 {
                let mut bits = self.active[word];
                while bits != 0 {
                    let bit = bits.trailing_zeros() as usize;
                    let prio = word * 64 + bit;
                    if let Some(tid) = self.queues[prio].find_remove_by_group(group) {
                        if self.queues[prio].len == 0 {
                            self.active[word] &= !(1u64 << bit);
                        }
                        return Some(tid);
                    }
                    bits &= !(1u64 << bit);
                }
            }
        }
        None
    }

    /// Remove a specific thread from the prio-254 queue (for wake_thread boost).
    /// Returns true if the thread was found and removed, false otherwise.
    fn remove_tid(&mut self, tid: ThreadId) -> bool {
        let prio = 254usize;
        let mut cur = self.queues[prio].head;
        while cur != RQ_NIL {
            if cur == tid {
                self.queues[prio].unlink(tid);
                if self.queues[prio].len == 0 {
                    self.active[prio / 64] &= !(1u64 << (prio % 64));
                }
                thread_ref(tid).in_queue.store(false, Ordering::Release);
                return true;
            }
            cur = thread_ref(cur).run_next.load(Ordering::Relaxed);
        }
        false
    }

    /// Check if any threads are enqueued. O(1) via bitmap + heap check.
    fn has_ready(&self) -> bool {
        self.active[0] | self.active[1] | self.active[2] | self.active[3] != 0
            || self.eevdf_nr_running > 0
    }

    /// Steal one thread for `thief_cpu` from lowest-priority queue with ≥2 threads.
    #[allow(dead_code)]
    fn steal_one(&mut self, thief_cpu: u32) -> Option<ThreadId> {
        self.steal_one_min(thief_cpu, 2)
    }

    /// Steal a thread from this run queue, requiring at least `min_len` threads
    /// at that priority level. `min_len=1` allows stealing the only thread
    /// (used by idle CPUs); `min_len=2` preserves at least one for the victim.
    fn steal_one_min(&mut self, thief_cpu: u32, min_len: u32) -> Option<ThreadId> {
        // Try stealing from bitmap queues first (RT and legacy).
        for word in (0..4).rev() {
            if self.active[word] != 0 {
                let mut bits = self.active[word];
                while bits != 0 {
                    // Highest set bit = lowest priority = best to steal
                    let bit = 63 - bits.leading_zeros() as usize;
                    let prio = word * 64 + bit;
                    if self.queues[prio].len >= min_len {
                        if let Some(tid) = self.queues[prio].find_remove_with_affinity(thief_cpu) {
                            if self.queues[prio].len == 0 {
                                self.active[word] &= !(1u64 << bit);
                            }
                            thread_ref(tid).in_queue.store(false, Ordering::Release);
                            return Some(tid);
                        }
                    }
                    bits &= !(1u64 << bit);
                }
            }
        }
        // Try stealing from EEVDF heap (steal earliest-deadline thread).
        if self.eevdf_nr_running >= min_len {
            if let Some((tid, _deadline)) = self.eevdf_heap.pop_min() {
                // Check affinity — if the thread can't run on thief, put it back.
                if thread_ref(tid).affinity_mask.test(thief_cpu) {
                    self.eevdf_nr_running -= 1;
                    thread_ref(tid).in_queue.store(false, Ordering::Release);
                    return Some(tid);
                }
                // Can't run on thief — re-insert with same deadline.
                let t = thread_ref(tid);
                self.eevdf_heap.insert(tid, t.eevdf_deadline);
                // Don't decrement eevdf_nr_running — we put it back.
            }
        }
        None
    }
}

static PERCPU_RQ_PTR: AtomicPtr<SpinLock<PerCpuRunQueues>> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn percpu_rq() -> &'static [SpinLock<PerCpuRunQueues>] {
    let ptr = PERCPU_RQ_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "PERCPU_RQ not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Allocate and install this module's dynamic per-CPU slices.
/// Called by `smp::init_dynamic_percpu` after `phys::init`.
pub(crate) fn init_dynamic_percpu() {
    let n = smp::num_cpus();
    unsafe {
        let s = phys::alloc_static_slice::<AtomicU64>(n);
        CURRENT_FRAME_SP_PTR.store(s.as_mut_ptr(), Ordering::Release);

        let s = phys::alloc_static_slice::<AtomicU64>(n);
        PENDING_SWITCH_SP_PTR.store(s.as_mut_ptr(), Ordering::Release);

        let s = phys::alloc_static_slice::<core::sync::atomic::AtomicBool>(n);
        PARK_SWITCH_PENDING_PTR.store(s.as_mut_ptr(), Ordering::Release);

        let s = phys::alloc_static_slice::<AtomicU32>(n);
        for v in s.iter() { v.store(u32::MAX, Ordering::Relaxed); }
        PARKED_TID_PTR.store(s.as_mut_ptr(), Ordering::Release);

        let s = phys::alloc_static_slice::<AtomicU64>(n);
        DEFERRED_REQUEUE_PTR.store(s.as_mut_ptr(), Ordering::Release);

        let s = phys::alloc_static_slice::<AtomicUsize>(n);
        DEFERRED_KSTACK_PTR.store(s.as_mut_ptr(), Ordering::Release);

        // DEFERRED_THREAD and DEFERRED_KILL sentinel value is usize::MAX,
        // not 0 — alloc_static_slice returns zeroed memory, so explicitly
        // initialize each slot.
        let s = phys::alloc_static_slice::<AtomicUsize>(n);
        for slot in s.iter() {
            slot.store(usize::MAX, Ordering::Relaxed);
        }
        DEFERRED_THREAD_PTR.store(s.as_mut_ptr(), Ordering::Release);

        let s = phys::alloc_static_slice::<AtomicUsize>(n);
        for slot in s.iter() {
            slot.store(usize::MAX, Ordering::Relaxed);
        }
        DEFERRED_KILL_PTR.store(s.as_mut_ptr(), Ordering::Release);

        // PERCPU_RQ: zero-initialized bytes match PerCpuRunQueues::new()
        // (which uses RQ_NIL == 0 sentinels — see comment on RQ_NIL above).
        // SpinLock<T>::new() is also all-zero for the unlocked state.
        let s = phys::alloc_static_slice::<SpinLock<PerCpuRunQueues>>(n);
        PERCPU_RQ_PTR.store(s.as_mut_ptr(), Ordering::Release);

        // Per-CPU enqueue caller tags (debug).
        let s = phys::alloc_static_slice::<core::sync::atomic::AtomicU8>(n);
        ENQ_CALLER_TAG_PTR.store(s.as_mut_ptr(), Ordering::Release);
    }
}

/// Enqueue a thread onto the per-CPU run queue for the given target CPU.
/// The caller must ensure the thread's state is Ready before calling.
/// Routes SCHED_NORMAL threads (not demoted to prio 254) to the EEVDF heap;
/// all others go to the legacy bitmap queue.
/// Debug: per-CPU caller tag for percpu_enqueue tracing (avoids cross-CPU race).
/// 1=drain_deferred, 2=vol_resched, 3=wake_thread, 4=handoff, 5=steal,
/// 6=wake_parked, 7=sleep_timer, 8=spawn, 9=kill_sleep, 10=other
static ENQ_CALLER_TAG_PTR: AtomicPtr<core::sync::atomic::AtomicU8> =
    AtomicPtr::new(core::ptr::null_mut());

fn enq_caller_tags() -> &'static [core::sync::atomic::AtomicU8] {
    let ptr = ENQ_CALLER_TAG_PTR.load(Ordering::Relaxed);
    if ptr.is_null() { return &[]; }
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

fn set_enq_tag(tag: u8) {
    let tags = enq_caller_tags();
    let cpu = smp::cpu_id() as usize;
    if cpu < tags.len() {
        tags[cpu].store(tag, Ordering::Relaxed);
    }
}

fn get_enq_tag() -> u8 {
    let tags = enq_caller_tags();
    let cpu = smp::cpu_id() as usize;
    if cpu < tags.len() { tags[cpu].load(Ordering::Relaxed) } else { 0 }
}

/// Per-source double-enqueue counters for diagnosing thread-loss.
static DOUBLE_ENQ_DRAIN: AtomicU64 = AtomicU64::new(0);
static DOUBLE_ENQ_RESCUE: AtomicU64 = AtomicU64::new(0);
static DOUBLE_ENQ_WAKE: AtomicU64 = AtomicU64::new(0);
static DOUBLE_ENQ_OTHER: AtomicU64 = AtomicU64::new(0);
static ENQ_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Counts phantom-enqueued recoveries: threads found with `in_queue=true`
/// but no actual heap or bitmap membership on their `last_cpu`'s run queue.
/// Driven by `rescue_orphaned_threads_impl`'s self-healing pass.
static RESCUE_PHANTOM: AtomicU64 = AtomicU64::new(0);
/// Per-branch rescue counters in `rescue_orphaned_threads_impl`.  Splits the
/// global `DOUBLE_ENQ_RESCUE` count by which predicate fired so we can tell
/// which orphan pattern is occurring during an IPC stall.
/// `RESCUE_MAX`: orphan path where `on_cpu == u32::MAX`.
/// `RESCUE_STALE_ON_CPU`: Bug A fix branch (commit 712e741) — `on_cpu` claims
/// a real CPU but that CPU's `current_thread` is a different tid.
/// `RESCUE_PENDING`: observed `on_cpu == ON_CPU_PENDING` during the scan.
/// Currently filtered out (transient dispatch state) so no rescue action is
/// taken, but the counter catches how often we observe it.
static RESCUE_MAX: AtomicU64 = AtomicU64::new(0);
static RESCUE_STALE_ON_CPU: AtomicU64 = AtomicU64::new(0);
static RESCUE_PENDING: AtomicU64 = AtomicU64::new(0);
/// #120 sub-pattern A: counts every time the new STUCK_PENDING_AGE check
/// fires its rescue (logs RESCUE-STUCK-PENDING).  Dumped on CALL-TIMEOUT
/// so we can tell whether the rescue is even being entered for orphans.
static RESCUE_STUCK_PENDING_FIRES: AtomicU64 = AtomicU64::new(0);

/// #120 low-threshold PENDING-stuck diagnostic.  Counts the lower-bound (2s)
/// "PENDING-STUCK-LOW" prints — fires when a thread's `pending_set_ns` is
/// older than `PENDING_LOW_THRESHOLD_NS` regardless of whether the 16s
/// rescue threshold is reached.  Lets us see *slow* dispatch oscillations
/// that hard-wedge fixes (commits 644c7b0 / 27cf951) didn't eliminate.
static PENDING_LOW_FIRES: AtomicU64 = AtomicU64::new(0);

/// Counts try_switch / voluntary_reschedule / park CAS_FAIL events
/// that were benign rescue-takeovers (other_cpu == u32::MAX) — the
/// fast-rescue path observed the picking CPU stuck >FAST_RESCUE_NS
/// and CAS-flipped on_cpu PENDING → MAX so the original CPU yields
/// to idle instead of getting killed.  A non-zero count here means
/// the fast-rescue path actually fired and saved a thread.
static CAS_FAIL_RESCUE_BAILS: AtomicU64 = AtomicU64::new(0);

/// Counts fast-rescue PENDING→MAX flips successfully attributed to
/// a host-descheduled picking CPU.  Pairs with CAS_FAIL_RESCUE_BAILS
/// — every successful fast-rescue should produce one increment here
/// and at most one increment on a later try_switch path when the
/// picking CPU resumes.
static FAST_RESCUE_TAKEOVERS: AtomicU64 = AtomicU64::new(0);

/// #198 host-pause-aware peer-steal counters.
/// `HOST_PAUSE_PEERS_DETECTED`: number of (sweep, peer-cpu) pairs where
/// we observed a peer CPU with both last_try_switch_ns AND last_irq_ns
/// stale beyond `HOST_PAUSE_RESCUE_NS`.  Distinct from
/// `IPI_STALE_REROUTES` (wake-side) — this fires from the rescue sweep.
/// `HOST_PAUSE_STEALS`: count of threads actually migrated off a paused
/// peer's run-queue and onto the local CPU.  Each successful migration
/// converts a stranded Ready thread into a dispatched one within the
/// next try_switch on this CPU.
static HOST_PAUSE_PEERS_DETECTED: AtomicU64 = AtomicU64::new(0);
static HOST_PAUSE_STEALS: AtomicU64 = AtomicU64::new(0);

/// #135 false-positive probe: count of try_switch invocations where
/// pick returned the running thread (concurrent re-enqueue + self-pick).
/// In this branch we now clear pending_set_ns so the rescue's stale-stamp
/// false positive no longer fires.  High SELF_PICK_COUNT in a boot
/// indicates a noisy false-enqueue source worth chasing separately.
static SELF_PICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Per-tid "already logged for this PENDING episode" flag, cleared when
/// `pending_set_ns` returns to 0 (CAS-ok path) or when the thread leaves
/// the Ready/Pending state.  Prevents flooding the serial log when the
/// same tid keeps re-PENDING-ing.  Indexed by tid, capped at 256.
static PENDING_LOW_LOGGED: [core::sync::atomic::AtomicBool; 256] = {
    const Z: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    [Z; 256]
};

/// Per-tid rescue counter for the watchdog dump.  Lets us see *which*
/// tids account for the bulk of rescue traffic when a stall storm fires —
/// e.g. r11/r12 saw 38k+ pend rescues with no clue which threads were
/// being repeatedly rescued.  Indexed by tid, capped at 256 (the kernel
/// rarely runs more threads on a focus boot, and we'd rather skip
/// counting for the rare overflow than waste memory).
const PER_TID_RESCUE_CAP: usize = 256;
static RESCUE_PER_TID: [AtomicU64; PER_TID_RESCUE_CAP] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; PER_TID_RESCUE_CAP]
};

#[inline(always)]
fn rescue_per_tid_inc(tid: u32) {
    let i = tid as usize;
    if i < PER_TID_RESCUE_CAP {
        RESCUE_PER_TID[i].fetch_add(1, Ordering::Relaxed);
    }
}

fn percpu_enqueue(target_cpu: u32, prio: u8, tid: ThreadId) {
    // Double-enqueue detection.  Benign race: rescue_orphaned_threads may
    // enqueue a thread that drain_deferred_requeue is about to enqueue.
    // The in_queue swap detects this and the second enqueue is safely
    // skipped.  No println here — this runs in IRQ context and the serial
    // lock would deadlock with concurrent output on other CPUs.
    if thread_ref(tid).in_queue.swap(true, Ordering::AcqRel) {
        trace_sched(tid, 11); // 11=double_enq
        trace_point("percpu_enqueue.skip_in_queue", tid as u32);
        // #135 action=18: percpu_enqueue silent skip (in_queue already true).
        // This is the suspect mechanism for the sleep_wake wedge — if a
        // post-CAS racer leaves in_queue=true on a thread that sleep_wake
        // is trying to enqueue, this branch returns silently and the thread
        // is then state=Ready ∧ on_cpu=PEND ∧ in_queue=true but NOT in any
        // heap, so no pick fires.
        record_trans(tid as u32, 18, thread_ref(tid).state, ON_CPU_PENDING);
        let src = get_enq_tag();
        match src {
            1 => { DOUBLE_ENQ_DRAIN.fetch_add(1, Ordering::Relaxed); }
            7 => { DOUBLE_ENQ_RESCUE.fetch_add(1, Ordering::Relaxed); }
            6 | 3 => { DOUBLE_ENQ_WAKE.fetch_add(1, Ordering::Relaxed); }
            _ => { DOUBLE_ENQ_OTHER.fetch_add(1, Ordering::Relaxed); }
        }
        return; // Don't enqueue again.
    }
    trace_point("percpu_enqueue.insert", tid as u32);
    ENQ_TOTAL.fetch_add(1, Ordering::Relaxed);
    // #120 instrumentation I: per-thread enqueue counter.
    thread_ref(tid).enqueue_count.fetch_add(1, Ordering::Relaxed);
    // #120 instrumentation H: timestamp the Ready-enqueue event.
    thread_ref(tid).last_ready_ns.store(get_monotonic_ns(), Ordering::Relaxed);
    let mut rq = percpu_rq()[target_cpu as usize].lock();
    let t = thread_ref(tid);
    if t.sched_class == SCHED_NORMAL && prio != 254 {
        eevdf_enqueue(&mut rq, tid);
    } else {
        rq.push(prio, tid);
    }
    // #135 action=17: enqueue succeeded.  Record the target CPU so we can
    // see whether the thread landed where sleep_wake intended.
    record_trans(tid as u32, 17, thread_ref(tid).state, target_cpu);
    drop(rq);
    // Boot 544 dispatch starvation fix: every enqueue to a *different* CPU
    // sends a reschedule IPI to the target.  Without this, callers like
    // wake_thread (after choose_wake_target_steal_aware) and spawn fan-out
    // place a Ready thread on a remote heap that may be HLT-idle; nothing
    // wakes that CPU until its next periodic tick, which under dynamic-
    // tick can be MAX_IDLE_NS away.  Boot 544 caught cpu=0 idle for 23 min
    // with 11 entries in its heap.  IPI cost is one vmexit when the target
    // is running and one resched-vector when idle — both negligible vs
    // the cost of dispatch starvation we saw.
    if target_cpu != smp::cpu_id() {
        crate::arch::irq::send_reschedule_ipi(target_cpu);
    }
}

/// Compute EEVDF deadline and insert a thread into the per-CPU heap.
/// Called under the per-CPU RQ lock.
fn eevdf_enqueue(rq: &mut PerCpuRunQueues, tid: ThreadId) {
    let t = unsafe { thread_mut_from_ref(tid) };
    // Compute base virtual time slice and apply latency scaling.
    let weight = t.eevdf_weight as u64;
    let lat_w = t.eevdf_latency_weight as u64;
    let base_slice = (t.default_quantum as u64) * VTIME_UNIT / weight;
    // Lower latency_weight → shorter slice → tighter deadlines → more responsive.
    t.eevdf_slice_vt = ((base_slice * 1024) / lat_w).max(1);

    // Hard-snap vruntime to min_vruntime.  This works in concert with the
    // eligibility filter in class_pick_next: waking threads land at exactly
    // min_vruntime (eligible), while preempted threads have vruntime above
    // min_vruntime (ineligible until others catch up).  The combination
    // provides the EEVDF sleeping-credit benefit — wakers are naturally
    // preferred — without explicit vruntime manipulation below the floor.
    if t.eevdf_vruntime < rq.eevdf_min_vruntime {
        t.eevdf_vruntime = rq.eevdf_min_vruntime;
    }
    // Compute lag: positive = thread is owed CPU (eligible), negative = ahead.
    t.eevdf_lag = rq.eevdf_min_vruntime as i64 - t.eevdf_vruntime as i64;

    // Advance min_vruntime: it's the max of all threads' vruntime at enqueue.
    if t.eevdf_vruntime > rq.eevdf_min_vruntime {
        rq.eevdf_min_vruntime = t.eevdf_vruntime;
    }
    // Set deadline.
    t.eevdf_deadline = t.eevdf_vruntime + t.eevdf_slice_vt;
    // Insert into heap. If full, fall back to bitmap.
    if !rq.eevdf_heap.insert(tid, t.eevdf_deadline) {
        // Heap overflow — fall back to bitmap at the thread's priority.
        rq.push(t.effective_priority, tid);
        return;
    }
    rq.eevdf_nr_running += 1;
}

/// Verify that `tid` is actually present in the EEVDF heap or one of the
/// bitmap-priority queues on `cpu`.  Caller must hold that CPU's `percpu_rq`
/// lock for the duration of the check.
///
/// Used by the rescue self-healing pass to detect "phantom enqueued"
/// threads — `in_queue=true` but no actual queue membership — and re-insert
/// them so the run-queue invariant `in_queue == queue_membership` holds.
fn rq_contains_tid(rq: &PerCpuRunQueues, tid: ThreadId) -> bool {
    // Fast path: EEVDF heap membership is O(1) via the per-thread heap_pos.
    if thread_ref(tid).eevdf_heap_pos != super::heap::HEAP_POS_NONE {
        return true;
    }
    // Bitmap path: walk only the priority queues whose bitmap bits are set.
    // Single-element queues have run_prev=run_next=RQ_NIL, so we can't rely
    // on link fields alone; the head pointer is the source of truth.
    for word in 0..4 {
        let mut bits = rq.active[word];
        while bits != 0 {
            let bit = bits.trailing_zeros() as usize;
            bits &= !(1u64 << bit);
            let prio = word * 64 + bit;
            let mut cur = rq.queues[prio].head;
            while cur != RQ_NIL {
                if cur == tid {
                    return true;
                }
                cur = thread_ref(cur).run_next.load(Ordering::Relaxed);
            }
        }
    }
    false
}

/// Try to steal a thread from another CPU's run queue.
/// Returns the stolen thread's ID, or None.
fn try_steal(cpu: u32) -> Option<ThreadId> {
    try_steal_min(cpu, 2).map(|(tid, victim)| {
        // #135 residual investigation: record steal events into the
        // per-thread transition ring.  Action 19 = STEAL_SUCCESS, the
        // cpu field is the THIEF, on_cpu_enc is the VICTIM CPU.  If a
        // thread shows up as wedged with last_cpu=N and a STEAL entry
        // shortly before the wedge, the orphan happened in the
        // steal → dequeue_set_pending → try_switch CAS path.
        record_trans(tid as u32, 19, thread_ref(tid).state, victim);
        tid
    })
}

/// Try to steal from idle — allows taking the only thread at a priority level.
fn try_steal_for_idle(cpu: u32) -> Option<ThreadId> {
    try_steal_min(cpu, 1).map(|(tid, victim)| {
        record_trans(tid as u32, 19, thread_ref(tid).state, victim);
        tid
    })
}

fn try_steal_min(cpu: u32, min_len: u32) -> Option<(ThreadId, u32)> {
    let online = smp::online_cpus() as usize;
    if online <= 1 {
        return None;
    }
    for i in 1..online {
        let victim = ((cpu as usize + i) % online) as u32;
        if let Some(mut rq) = percpu_rq()[victim as usize].try_lock() {
            if let Some(tid) = rq.steal_one_min(cpu, min_len) {
                return Some((tid, victim));
            }
        }
    }
    None
}

/// #198 host-pause-aware peer-steal.  Scan peer CPUs from the periodic
/// rescue sweep: any peer whose `last_try_switch_ns` AND `last_irq_ns`
/// are both wallclock-stale beyond `HOST_PAUSE_RESCUE_NS` has been
/// host-descheduled by KVM for the full window (both stamps are
/// wallclock — a paused vCPU updates neither).  Drain such peers'
/// run-queues onto the local CPU so stranded Ready threads dispatch
/// within the next try_switch instead of waiting tens of seconds for
/// the host to resume the paused vCPU.
///
/// Boot 555 motivating case: cpu=3 advanced 450 dispatches while peers
/// advanced 300-400k each, a 57s wallclock pause.  Threads on cpu=3's
/// EEVDF heap were stranded the whole time.
///
/// Affinity is preserved: `steal_one_min` filters affinity-pinned
/// threads (bitmap via `find_remove_with_affinity`, EEVDF via
/// `affinity_mask.test`).  Threads bound to the paused CPU stay put.
///
/// Cap per-peer steal count at `HOST_PAUSE_STEAL_CAP` so a single
/// sweep doesn't hold the local CPU's CLI for too long.  The peer
/// will be revisited on the next 100ms sweep tick.
fn rescue_host_paused_peers() {
    const HOST_PAUSE_RESCUE_NS: u64 = 1_500_000_000; // 1.5s
    const HOST_PAUSE_STEAL_CAP: u32 = 8;

    let my_cpu = smp::cpu_id();
    let ncpus = smp::num_cpus();
    if ncpus <= 1 {
        return;
    }
    let now = get_monotonic_ns();
    for c in 0..ncpus.min(16) {
        let c = c as u32;
        if c == my_cpu {
            continue;
        }
        let pc = smp::get(c);
        let lts = pc.last_try_switch_ns.load(Ordering::Relaxed);
        let lirq = pc.last_irq_ns.load(Ordering::Relaxed);
        // Stamps of 0 mean the CPU never ran try_switch / never took an
        // IRQ — boot init transient; don't steal from it.
        if lts == 0 || lirq == 0 {
            continue;
        }
        if now <= lts || now <= lirq {
            continue;
        }
        let ts_age = now - lts;
        let irq_age = now - lirq;
        if ts_age < HOST_PAUSE_RESCUE_NS || irq_age < HOST_PAUSE_RESCUE_NS {
            continue;
        }
        HOST_PAUSE_PEERS_DETECTED.fetch_add(1, Ordering::Relaxed);
        // Drain up to N threads from the paused peer's run-queue onto
        // this CPU.  try_lock so a (briefly) racing access from the
        // peer doesn't deadlock — next sweep will retry.
        let Some(mut rq) = percpu_rq()[c as usize].try_lock() else {
            continue;
        };
        let mut migrated: u32 = 0;
        while migrated < HOST_PAUSE_STEAL_CAP {
            let Some(tid) = rq.steal_one_min(my_cpu, 1) else {
                break;
            };
            migrated += 1;
            HOST_PAUSE_STEALS.fetch_add(1, Ordering::Relaxed);
            drop(rq);
            let prio = thread_ref(tid).prio.load(Ordering::Relaxed);
            set_enq_tag(5); // 5=steal
            percpu_enqueue(my_cpu, prio, tid);
            // Re-lock for the next iteration.
            if let Some(rq2) = percpu_rq()[c as usize].try_lock() {
                rq = rq2;
            } else {
                break;
            }
        }
        // Rate-limited log: first 8 firings only, captures the steady-
        // state pattern without flooding the serial log under sustained
        // host pressure.
        static LOG_COUNT: AtomicU64 = AtomicU64::new(0);
        if migrated > 0 {
            let n = LOG_COUNT.fetch_add(1, Ordering::Relaxed);
            if n < 8 {
                #[cfg(target_arch = "x86_64")]
                {
                    use crate::arch::x86_64::serial::{put_byte, put_bytes, put_dec_u64};
                    let mut buf = [0u8; 160];
                    let mut k = 0;
                    put_bytes(&mut buf, &mut k, b"HOST-PAUSE-RESCUE: my_cpu=");
                    put_dec_u64(&mut buf, &mut k, my_cpu as u64);
                    put_bytes(&mut buf, &mut k, b" paused_peer=");
                    put_dec_u64(&mut buf, &mut k, c as u64);
                    put_bytes(&mut buf, &mut k, b" ts_age_ms=");
                    put_dec_u64(&mut buf, &mut k, ts_age / 1_000_000);
                    put_bytes(&mut buf, &mut k, b" irq_age_ms=");
                    put_dec_u64(&mut buf, &mut k, irq_age / 1_000_000);
                    put_bytes(&mut buf, &mut k, b" migrated=");
                    put_dec_u64(&mut buf, &mut k, migrated as u64);
                    put_bytes(&mut buf, &mut k, b" (n=");
                    put_dec_u64(&mut buf, &mut k, (n + 1) as u64);
                    put_bytes(&mut buf, &mut k, b")\n");
                    crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                }
                #[cfg(not(target_arch = "x86_64"))]
                crate::println!(
                    "HOST-PAUSE-RESCUE: my_cpu={} paused_peer={} ts_age_ms={} irq_age_ms={} migrated={} (n={})",
                    my_cpu, c, ts_age / 1_000_000, irq_age / 1_000_000,
                    migrated, n + 1,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel-held port handlers for task/thread ports
// ---------------------------------------------------------------------------

/// Kernel handler for task ports. Stub — returns empty reply.
fn task_port_handler(
    _port_id: crate::ipc::port::PortId,
    _user_data: usize,
    _msg: &crate::ipc::Message,
) -> crate::ipc::Message {
    crate::ipc::Message::empty()
}

/// Kernel handler for thread ports. Stub — returns empty reply.
fn thread_port_handler(
    _port_id: crate::ipc::port::PortId,
    _user_data: usize,
    _msg: &crate::ipc::Message,
) -> crate::ipc::Message {
    crate::ipc::Message::empty()
}

// ---------------------------------------------------------------------------
// Thread/Task slab/page allocation
// ---------------------------------------------------------------------------

/// Slab size for Thread entries.  Bumped to 1024 after kstack_epoch
/// (#208 probe) push Thread past 512 bytes.
const THREAD_SLAB_SIZE: usize = 1024;
const _: () = assert!(core::mem::size_of::<Thread>() <= THREAD_SLAB_SIZE);

/// #228 kstack snapshot per-CPU buffer.  Avoids growing
/// write_saved_sp's stack frame (which previously pushed saved-ra
/// out of the static probe offset).  Each CPU has its own slot; the
/// helper is reentrant-safe per-CPU because write_saved_sp doesn't
/// recurse on the same hart.
const KSTACK_SNAP_MAX_CPUS: usize = 16;
const KSTACK_SNAP_WORDS: usize = 16;
#[repr(align(64))]
struct KstackSnapSlot {
    base: u64,
    words: [u64; KSTACK_SNAP_WORDS],
}
static mut KSTACK_SNAP: [KstackSnapSlot; KSTACK_SNAP_MAX_CPUS] = [
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
    KstackSnapSlot { base: 0, words: [0; KSTACK_SNAP_WORDS] },
];

/// #228 slab-canary probe: each Thread gets its own 4 KiB phys page;
/// only the first ~1 KiB holds the Thread struct, the rest is unused
/// padding.  We stamp a magic value at offset 0x800 of every Thread
/// page on allocation and verify it at write_saved_sp entry.  An
/// unrelated subsystem scribbling into the Thread page (slab alias
/// from phys-allocator double-issue family, or stray pointer write)
/// breaks the magic, so the verify log identifies *that* path even
/// though direct WP on saved_sp didn't fire.
const THREAD_SLAB_CANARY_OFFSET: u64 = 0x800;
const THREAD_SLAB_CANARY_MAGIC: u64 = 0xF00D_CAFE_C0DE_BABE;

/// Stamp the slab canary at offset 0x800 of the Thread's 4 KiB page.
/// Called once at allocation time.  `thread_va` is whatever address
/// the kernel uses to access the Thread struct — identity VA on rv64,
/// SLAB_THREAD_REGION VA on x86_64/aarch64.  The canary lives within
/// the same 4 KiB page so all three layouts work uniformly.
fn stamp_thread_slab_canary(thread_va: u64) {
    let page_base = thread_va & !0xFFF;
    let canary_addr = page_base + THREAD_SLAB_CANARY_OFFSET;
    unsafe {
        (canary_addr as *mut u64).write_volatile(THREAD_SLAB_CANARY_MAGIC);
    }
}

/// Verify the slab canary placed at allocation time.  Returns the
/// observed value if it doesn't match — caller logs.  Returns None
/// on intact magic.
fn check_thread_slab_canary(thread_va: u64) -> Option<u64> {
    let page_base = thread_va & !0xFFF;
    let canary_addr = page_base + THREAD_SLAB_CANARY_OFFSET;
    let v = unsafe { (canary_addr as *const u64).read_volatile() };
    if v == THREAD_SLAB_CANARY_MAGIC { None } else { Some(v) }
}

fn alloc_thread_entry() -> Option<*mut Thread> {
    #[cfg(target_arch = "x86_64")]
    {
        // Phase 4 (slab-pt-va-isolation): each Thread gets its own 4 KiB
        // phys page mapped into a unique SLAB_THREAD_REGION VA window
        // (16 KiB) with 12 KiB of unmapped guard below.  A stray write
        // to a Thread struct's address from unrelated code (e.g., extent
        // tree or scheduler heap pointer arithmetic landing in the slab
        // region) now faults instead of scribbling a sibling Thread —
        // catches the residual #208 family that survives Phase 5b kstack
        // isolation (canary intact, but Thread fields scribbled).
        let pa = crate::mm::phys::alloc_page()?;
        // #208 KSTACK_WRITE_RING tag: action=2, alloc_thread_entry zero
        // of fresh Thread struct page via identity-map PA.  Same double-
        // map concern as alloc_kstack_zeroed.
        record_kstack_write(
            pa.as_usize() as u64,
            crate::mm::page::page_size() as u32,
            2,
        );
        unsafe {
            core::ptr::write_bytes(
                crate::mm::page::phys_to_kva(pa.as_usize()) as *mut u8,
                0,
                crate::mm::page::page_size(),
            );
        }
        let va_window = crate::arch::x86_64::mm::alloc_slab_thread_va_window();
        let boot_pml4 = {
            let cr3: u64;
            unsafe {
                core::arch::asm!(
                    "mov {}, cr3", out(reg) cr3,
                    options(nomem, nostack, preserves_flags),
                );
            }
            (cr3 & !0xFFF) as usize
        };
        let va = crate::arch::x86_64::mm::map_slab_thread_window(
            boot_pml4, va_window, pa.as_usize(),
        )?;
        let p = va as *mut Thread;
        unsafe {
            core::ptr::write(p, Thread::empty());
        }
        stamp_thread_slab_canary(p as u64);
        Some(p)
    }
    #[cfg(target_arch = "aarch64")]
    {
        // #260 step 2: per-Thread VA window with 12 KiB unmapped guard
        // pages below the mapped 4 KiB Thread page.  Mirrors x86_64's
        // SLAB_THREAD_REGION isolation.  Each Thread:
        //   - owns its own 4 KiB phys page (no shared slab chunks)
        //   - lives at the TOP of a 16 KiB VA window in 0xC000_0000+
        //   - has 12 KiB of unmapped VA below — stray writes computing
        //     a "near-Thread" pointer fault instead of scribbling
        //
        // The mapping lives in a SHARED L2 sub-tree at L1[3] (installed
        // by `setup_tables` for every aspace), so the Thread VA is
        // reachable from every active TTBR0 context.
        let pa = crate::mm::phys::alloc_page()?;
        // Zero the phys page via PHYS_DIRECT_MAP before mapping it into
        // the VA window.  Cheaper than writing through the window VA
        // since identity map is already set up.
        unsafe {
            core::ptr::write_bytes(
                crate::mm::page::phys_to_kva(pa.as_usize()) as *mut u8,
                0,
                crate::mm::page::page_size(),
            );
        }
        let va_window = crate::arch::aarch64::mm::alloc_slab_thread_va_window();
        let va = crate::arch::aarch64::mm::map_slab_thread_window(va_window, pa.as_usize())?;
        let p = va as *mut Thread;
        unsafe {
            core::ptr::write(p, Thread::empty());
        }
        stamp_thread_slab_canary(p as u64);
        Some(p)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        // riscv64/loongarch64/mips64: per-page Thread alloc (step 1
        // of #260) only.  Adding VA-window guards on these arches is
        // a follow-up matching the aarch64 path once each arch has
        // its own SLAB_THREAD_REGION sub-allocator.
        let pa = crate::mm::phys::alloc_page()?;
        let p = crate::mm::page::phys_to_kva(pa.as_usize()) as *mut Thread;
        unsafe {
            core::ptr::write_bytes(p as *mut u8, 0, crate::mm::page::page_size());
            core::ptr::write(p, Thread::empty());
        }
        stamp_thread_slab_canary(p as u64);
        Some(p)
    }
}

#[allow(dead_code)]
fn free_thread_entry(p: *mut Thread) {
    // Phase 4: Thread pages are never freed on either path; the
    // SCHED_THREAD_ART lookup reuses Dead slots (see alloc_thread_id).
    // The phys page leak is bounded by max-tid (the alloc_thread_id
    // pool is finite), and Thread structs survive across spawn/exit
    // cycles via slot reuse — so freeing the page would create a
    // use-after-free for any in-flight observer.
    let _ = p;
}

fn alloc_task_entry() -> Option<*mut Task> {
    // Task is ~1400 bytes — too large for any slab cache, use page allocation.
    let pa = phys::alloc_page()?;
    // #235 Phase 4f: PHYS_DIRECT_MAP kva storage; free_task_entry undoes.
    let p = crate::mm::page::phys_to_kva(pa.as_usize()) as *mut Task;
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, page::page_size());
        core::ptr::write(p, Task::empty());
    }
    Some(p)
}

#[allow(dead_code)]
fn free_task_entry(p: *mut Task) {
    // #233 free poison: overwrite the Task struct with 0xFEEDFACE bytes
    // BEFORE returning the page to the allocator.  Any subsequent
    // dereference via a stale pointer hits the poison pattern
    // (0xFEEDFACE_FEEDFACE u64) instead of stale-but-valid-looking
    // fields, making UAF symptoms loud.  Done before free_page so the
    // page is still mapped + writable.
    unsafe {
        let bytes = p as *mut u8;
        for off in 0..(page::page_size() as isize) {
            core::ptr::write_volatile(bytes.offset(off), 0xCE);
        }
    }
    phys::free_page(PhysAddr::new(crate::mm::page::kva_to_phys(p as usize)));
}

// ---------------------------------------------------------------------------
// ID allocation (lock-free atomic counters)
// ---------------------------------------------------------------------------

/// Monotonic ID counters for thread/task allocation.
static NEXT_THREAD_ID: AtomicU32 = AtomicU32::new(0);
static NEXT_TASK_ID: AtomicU32 = AtomicU32::new(0);

// --- Initialization ---

/// Initialize task 0 and the BSP's idle thread (thread 0).
fn sched_init() {
    TASK_TABLE.init();
    THREAD_TABLE.init();

    let task_ptr = alloc_task_entry().expect("task 0 alloc");
    let task0_port =
        crate::ipc::port::create_kernel_port(task_port_handler, 0).expect("task 0 port");
    unsafe {
        (*task_ptr).id = 0;
        (*task_ptr).active = true;
        (*task_ptr).port_id = task0_port;
    }
    SCHED_TASK_ART.insert(0, task_ptr as usize);
    TASK_TABLE.ensure_l1(0);
    TASK_TABLE.set(0, task_ptr as *mut u8);
    NEXT_TASK_ID.store(1, Ordering::Relaxed);

    let thread_ptr = alloc_thread_entry().expect("thread 0 alloc");
    let thread0_port =
        crate::ipc::port::create_kernel_port(thread_port_handler, 0).expect("thread 0 port");
    // Allocate a proper kernel stack for the BSP idle thread so that
    // update_kernel_stack() sets TSS RSP0 correctly when switching to idle.
    // Without this, stack_base defaults to 0 and RSP0 = 0 + kstack_size(),
    // causing interrupts on the idle CPU to corrupt low memory.
    let bsp_kstack = alloc_kstack_zeroed().expect("thread 0 kstack");
    init_stack_canary(bsp_kstack.as_usize());
    unsafe {
        (*thread_ptr).id = 0;
        (*thread_ptr).state = ThreadState::Running;
        (*thread_ptr).task_id = 0;
        (*thread_ptr).port_id = thread0_port;
        (*thread_ptr).base_priority = 255;
        (*thread_ptr).effective_priority = 255;
        (*thread_ptr).quantum = u32::MAX;
        (*thread_ptr).default_quantum = u32::MAX;
        (*thread_ptr).stack_base = bsp_kstack.as_usize();
        (*thread_ptr).stack_phys_base = bsp_kstack.pa_base.as_usize();
    }
    unsafe { &*thread_ptr }.prio.store(255, Ordering::Relaxed);
    SCHED_THREAD_ART.insert(0, thread_ptr as usize);
    THREAD_TABLE.ensure_l1(0);
    THREAD_TABLE.set(0, thread_ptr as *mut u8);
    NEXT_THREAD_ID.store(1, Ordering::Relaxed);
}

/// Create an idle thread for a secondary CPU. Returns its ThreadId.
/// Caller serializes thread-ART writes via `SPAWN_LOCK`.
fn create_idle_thread() -> Option<ThreadId> {
    let id = NEXT_THREAD_ID.load(Ordering::Relaxed);
    if id as usize >= RadixTable::capacity() {
        return None;
    }
    NEXT_THREAD_ID.store(id + 1, Ordering::Relaxed);

    let ptr = alloc_thread_entry()?;
    let idle_port = crate::ipc::port::create_kernel_port(thread_port_handler, id as usize)?;
    // Allocate a proper kernel stack so update_kernel_stack() sets correct
    // TSS RSP0 when switching to this idle thread.
    let idle_kstack = alloc_kstack_zeroed()?;
    init_stack_canary(idle_kstack.as_usize());
    unsafe {
        (*ptr).id = id;
        (*ptr).state = ThreadState::Running;
        (*ptr).task_id = 0;
        (*ptr).port_id = idle_port;
        (*ptr).base_priority = 255;
        (*ptr).effective_priority = 255;
        (*ptr).quantum = u32::MAX;
        (*ptr).default_quantum = u32::MAX;
        (*ptr).sched_class = super::thread::SCHED_IDLE;
        (*ptr).stack_base = idle_kstack.as_usize();
        (*ptr).stack_phys_base = idle_kstack.pa_base.as_usize();
    }
    let t = unsafe { &*ptr };
    t.prio.store(255, Ordering::Relaxed);
    t.thread_task.store(0, Ordering::Relaxed);

    SCHED_THREAD_ART.insert(id as u64, ptr as usize);
    if !THREAD_TABLE.ensure_l1(id) {
        return None;
    }
    THREAD_TABLE.set(id, ptr as *mut u8);
    Some(id)
}

/// #208 Pattern A: atomic-emit helper for KUSER-SPAWN to replace the
/// 5 format_args!() callsites scattered through scheduler.rs.  Caller
/// passes the entry-tag bytes (b"spawn_user" / b"fork" / etc.) plus an
/// optional numeric entry address (Some for the userspace entry RIP).
#[inline]
#[cfg(target_arch = "x86_64")]
fn log_kuser_spawn(
    tid: ThreadId, task: TaskId, entry: &[u8],
    entry_addr: Option<u64>, prio: u8, q: u32,
) {
    use crate::arch::x86_64::serial::{put_byte, put_bytes, put_hex_u64, put_dec_u64};
    let mut buf = [0u8; 128];
    let mut k = 0;
    put_bytes(&mut buf, &mut k, b"KUSER-SPAWN: tid=");
    put_dec_u64(&mut buf, &mut k, tid as u64);
    put_bytes(&mut buf, &mut k, b" task=");
    put_dec_u64(&mut buf, &mut k, task as u64);
    put_bytes(&mut buf, &mut k, b" entry=");
    if let Some(addr) = entry_addr {
        put_hex_u64(&mut buf, &mut k, addr);
    } else {
        put_bytes(&mut buf, &mut k, entry);
    }
    put_bytes(&mut buf, &mut k, b" prio=");
    put_dec_u64(&mut buf, &mut k, prio as u64);
    put_bytes(&mut buf, &mut k, b" q=");
    put_dec_u64(&mut buf, &mut k, q as u64);
    put_byte(&mut buf, &mut k, b'\n');
    crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
}

/// Find a reusable (Dead) thread slot, or allocate a new one.
/// Caller serializes thread-ART writes via `SPAWN_LOCK`.
fn alloc_thread_id() -> Option<ThreadId> {
    let mut found_id: Option<ThreadId> = None;
    SCHED_THREAD_ART.for_each(|key, val| {
        if found_id.is_some() {
            return;
        }
        if key == 0 {
            return;
        }
        let t = unsafe { &*(val as *const Thread) };
        if t.state == ThreadState::Dead && t.stack_base == 0 {
            found_id = Some(key as ThreadId);
        }
    });
    if let Some(id) = found_id {
        return Some(id);
    }
    let id = NEXT_THREAD_ID.load(Ordering::Relaxed);
    if id as usize >= RadixTable::capacity() {
        crate::println!(
            "[alloc_thread_id] CAP-EXCEEDED next_id={} cap={}",
            id, RadixTable::capacity(),
        );
        return None;
    }
    let ptr = match alloc_thread_entry() {
        Some(p) => p,
        None => {
            let (total, free) = crate::mm::phys::stats();
            crate::println!(
                "[alloc_thread_id] alloc_thread_entry FAILED next_id={} phys_free={}/{}",
                id, free, total,
            );
            return None;
        }
    };
    SCHED_THREAD_ART.insert(id as u64, ptr as usize);
    if !THREAD_TABLE.ensure_l1(id) {
        crate::println!(
            "[alloc_thread_id] THREAD_TABLE.ensure_l1 FAILED next_id={}",
            id,
        );
        return None;
    }
    THREAD_TABLE.set(id, ptr as *mut u8);
    NEXT_THREAD_ID.store(id + 1, Ordering::Relaxed);
    Some(id)
}

/// Find a reusable (inactive) task slot, or allocate a new one.
/// Caller serializes task-ART writes via `SPAWN_LOCK`.
fn alloc_task_id() -> Option<TaskId> {
    let mut found_id: Option<TaskId> = None;
    SCHED_TASK_ART.for_each(|key, val| {
        if found_id.is_some() {
            return;
        }
        if key == 0 {
            return;
        }
        let t = unsafe { &*(val as *const Task) };
        if !t.active && t.exited && t.reaped {
            found_id = Some(key as TaskId);
        }
    });
    if let Some(id) = found_id {
        return Some(id);
    }
    let id = NEXT_TASK_ID.load(Ordering::Relaxed);
    if id as usize >= RadixTable::capacity() {
        crate::println!(
            "[alloc_task_id] CAP-EXCEEDED next_id={} cap={}",
            id, RadixTable::capacity(),
        );
        return None;
    }
    let ptr = match alloc_task_entry() {
        Some(p) => p,
        None => {
            let (total, free) = crate::mm::phys::stats();
            crate::println!(
                "[alloc_task_id] alloc_task_entry FAILED next_id={} phys_free={}/{} ({} KiB free)",
                id, free, total, free * (crate::mm::page::page_size() / 1024),
            );
            return None;
        }
    };
    SCHED_TASK_ART.insert(id as u64, ptr as usize);
    if !TASK_TABLE.ensure_l1(id) {
        crate::println!(
            "[alloc_task_id] TASK_TABLE.ensure_l1 FAILED next_id={}",
            id,
        );
        return None;
    }
    TASK_TABLE.set(id, ptr as *mut u8);
    NEXT_TASK_ID.store(id + 1, Ordering::Relaxed);
    Some(id)
}

/// Create a kernel-mode thread. Caller must hold `SPAWN_LOCK`.
fn create_thread(entry: fn() -> !, priority: u8, quantum: u32) -> Option<ThreadId> {
    let id = alloc_thread_id()?;

    let stack_page = alloc_kstack_zeroed()?;
    let stack_base = stack_page.as_usize();
    let stack_phys_base = stack_page.pa_base.as_usize();
    init_stack_canary(stack_base);
    let stack_top = stack_base + kstack_size();

    // Create a fake exception frame at the top of the stack.
    // When we "return" from the IRQ handler with this thread's SP,
    // restore_regs will load these values and eret/sret to the entry point.
    let frame_sp = stack_top - EXCEPTION_FRAME_SIZE;
    let frame = frame_sp as *mut u64;
    unsafe {
        // Zero the entire frame.
        for i in 0..(EXCEPTION_FRAME_SIZE / 8) {
            *frame.add(i) = 0;
        }

        crate::arch::trapframe::init_kernel_frame(frame, entry as *const () as usize, stack_top);
        // #208 KSTACK_WRITE_RING tag: action=3 = init_kernel_frame
        // installed iretq frame (RIP+CS+RFLAGS+RSP+SS = 5 quadwords)
        // at this kstack VA.  If a later __print on the SAME kstack
        // ends up with its saved-ret-addr coinciding with frame+17..21,
        // KSTACK-WRITE-NEAR will fire on the SCRIBBLE event.
        record_kstack_write(
            frame as u64 + 17 * 8,
            40, // 5 quadwords
            3,
        );
    }

    // Clear killed/affinity flags from any previous occupant of this slot.
    let thread = unsafe { thread_mut_from_ref(id) };
    thread.killed.store(false, Ordering::Release);
    thread
        .affinity_mask
        .store_mask(&cpumask::CpuMask::all(), Ordering::Relaxed);
    thread.last_cpu.store(smp::cpu_id(), Ordering::Relaxed);
    // NEW_INV: on_cpu = ON_CPU_PENDING for any thread about to enter Ready.
    thread.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
    thread.in_queue.store(false, Ordering::Release);

    thread.id = id;
    thread.state = ThreadState::Ready;
    thread.task_id = 0;
    thread.base_priority = priority;
    thread.effective_priority = priority;
    thread.prio.store(priority, Ordering::Relaxed);
    thread.quantum = quantum;
    thread.default_quantum = quantum;
    // #208: set stack_base BEFORE record_saved_sp_write (which calls
    // snapshot_iretq_shadow → would bail if stack_base==0).  Previously
    // record-then-stack_base order silently dropped snapshots for fresh
    // threads, making FBD silent on freshly-created threads.
    // #230 canon-race fix: set canonical BEFORE writing stack_phys_base
    // so periodic sweep can never observe (new_pa, old_canon) state.
    if id < 100 {
        spb_set_canonical(id, stack_phys_base as u64);
    }
    thread.stack_base = stack_base;
    thread.stack_phys_base = stack_phys_base;
    bump_kstack_epoch(thread); // #208
    write_saved_sp(thread, frame_sp as u64);
    record_saved_sp_write(id, frame_sp as u64, 1); // create_thread
    if id < 100 {
        #[cfg(target_arch = "x86_64")]
        {
            use crate::arch::x86_64::serial::{put_byte, put_bytes, put_hex_u64, put_dec_u64};
            let mut buf = [0u8; 96];
            let mut k = 0;
            put_bytes(&mut buf, &mut k, b"KTHREAD-SPAWN: tid=");
            put_dec_u64(&mut buf, &mut k, id as u64);
            put_bytes(&mut buf, &mut k, b" entry=");
            put_hex_u64(&mut buf, &mut k, entry as usize as u64);
            put_bytes(&mut buf, &mut k, b" prio=");
            put_dec_u64(&mut buf, &mut k, priority as u64);
            put_bytes(&mut buf, &mut k, b" q=");
            put_dec_u64(&mut buf, &mut k, quantum as u64);
            put_byte(&mut buf, &mut k, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
        }
        #[cfg(not(target_arch = "x86_64"))]
        crate::println!(
            "KTHREAD-SPAWN: tid={} entry={:#x} prio={} q={}",
            id, entry as usize, priority, quantum,
        );
    }
    thread.sig_mask = 0;
    thread.sig_pending = 0;

    percpu_enqueue(smp::cpu_id(), priority, id);
    Some(id)
}

/// Parent task info snapshot, taken under SPAWN_LOCK so that the heavy
/// work phase (ELF loading, page table setup) can run without holding it.
struct SpawnParentInfo {
    parent_task: u32,
    sid: TaskId,
    ctty_port: u64,
    uid: u32,
    euid: u32,
    gid: u32,
    egid: u32,
    groups_inline: [u32; GROUPS_INLINE],
    groups_overflow: usize,
    ngroups: u32,
    rlimits: [Rlimit; RLIMIT_COUNT],
}

/// Phase 2: do all heavy work (page tables, address space, ELF load, stack,
/// kstack, frame setup, capability grants) WITHOUT holding SPAWN_LOCK.
/// Returns (aspace_id, pt_root, frame_sp, kstack_base, task_port, thread_port) on success.
fn do_spawn_heavy_work(
    task_id: u32,
    thread_id: ThreadId,
    parent: &SpawnParentInfo,
    elf_data: &[u8],
    _priority: u8,
    _quantum: u32,
    arg0: u64,
    arg0_is_port: bool,
    mmio_cap_region: Option<u32>,
) -> Option<(u64, usize, u64, usize, usize, u64, u64)> {
    // #248 per-step probes — log which step returns None so we can
    // pinpoint where do_spawn_heavy_work fails (currently failing on
    // riscv64 SMP=4 for every server past tid=7).
    let task_port = match crate::ipc::port::create_kernel_port(task_port_handler, task_id as usize) {
        Some(p) => p,
        None => {
            crate::println!("[spawn-heavy] FAIL step=task_port task_id={} tid={}", task_id, thread_id);
            return None;
        }
    };
    let thread_port = match crate::ipc::port::create_kernel_port(thread_port_handler, thread_id as usize) {
        Some(p) => p,
        None => {
            crate::println!("[spawn-heavy] FAIL step=thread_port task_id={} tid={}", task_id, thread_id);
            return None;
        }
    };
    // Create a page table with kernel identity mapping.
    let pt_root = match crate::mm::hat::create_user_page_table() {
        Some(r) => r,
        None => {
            crate::println!("[spawn-heavy] FAIL step=pt_root task_id={} tid={}", task_id, thread_id);
            return None;
        }
    };

    // Create address space.
    let aspace_id = match crate::mm::aspace::create(pt_root) {
        Some(a) => a,
        None => {
            crate::println!("[spawn-heavy] FAIL step=aspace_create task_id={} tid={} pt_root={:#x}", task_id, thread_id, pt_root);
            return None;
        }
    };

    // Bootstrap capabilities: grant SEND caps for well-known kernel ports,
    // and full cap for arg0 if it's a valid active port (port passing on spawn).
    {
        // Initialize this task's embedded capspace.
        {
            let tptr = TASK_TABLE.get(task_id) as *mut Task;
            unsafe {
                (*tptr).capspace = crate::cap::CapSpace::new(task_id);
            }
        }
        // Grant SEND cap for initramfs port (well-known kernel service).
        // No namesrv port grant needed — service registry is a syscall now.
        let iramfs =
            crate::io::initramfs::USER_INITRAMFS_PORT.load(core::sync::atomic::Ordering::Acquire);
        if iramfs != u64::MAX {
            crate::cap::grant_send_cap(task_id, iramfs);
        }

        if arg0_is_port {
            crate::cap::grant_full_port_cap(task_id, arg0);
        }

        // Grant parent: SEND|RECV|MANAGE on child task port, SEND|MANAGE on child thread port.
        use crate::cap::capability::Rights;
        let srm = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        let sm = Rights::SEND.union(Rights::MANAGE);
        crate::cap::grant_port_cap(parent.parent_task, task_port, srm);
        crate::cap::grant_port_cap(parent.parent_task, thread_port, sm);
        // Grant child: SEND on own task port, SEND|RECV|MANAGE on own thread port.
        crate::cap::grant_send_cap(task_id, task_port);
        crate::cap::grant_port_cap(task_id, thread_port, srm);
    }

    // If the caller requested an MMIO cap, grant it now — the resulting
    // slot is OR'd into arg0's low 16 bits so the child can call
    // `sys_mmio_map_cap(slot)` as its first MMIO operation. The caller
    // keeps the upper bits of arg0 (e.g. irq<<48) free.
    let arg0 = match mmio_cap_region {
        Some(region_id) => {
            use crate::cap::capability::Rights;
            let rw = Rights::READ.union(Rights::WRITE);
            let slot = match crate::cap::grant_mmio_cap(task_id, region_id, rw) {
                Some(s) => s,
                None => {
                    crate::println!("[spawn-heavy] FAIL step=mmio_cap task_id={} tid={} region={}", task_id, thread_id, region_id);
                    return None;
                }
            };
            debug_assert!(slot < 0x10000, "mmio cap slot doesn't fit in 16 bits");
            (arg0 & !0xFFFFu64) | (slot as u64 & 0xFFFF)
        }
        None => arg0,
    };

    // Load ELF segments into the address space.
    let elf_info = match crate::loader::elf::load_elf(elf_data, aspace_id, pt_root) {
        Ok(e) => e,
        Err(e) => {
            crate::println!("[spawn-heavy] FAIL step=load_elf task_id={} tid={} err={:?}", task_id, thread_id, e);
            return None;
        }
    };
    let entry = elf_info.entry;

    // Flush instruction cache.
    crate::arch::cpu::flush_icache();

    // Map user stack.
    const USER_STACK_TOP: usize = crate::arch::trapframe::USER_STACK_TOP;

    let ps = page::page_size();
    let stack_alloc_pages = 8;
    let stack_mmu_pages = stack_alloc_pages * page::page_mmucount();
    let stack_va = USER_STACK_TOP - stack_alloc_pages * ps;

    let obj_id = match crate::mm::aspace::with_aspace(aspace_id, |aspace| {
        let vma = aspace
            .map_anon(stack_va, stack_mmu_pages, crate::mm::vma::VmaProt::ReadWrite)
            .ok_or(())?;
        Ok::<_, ()>(vma.object_id)
    }) {
        Ok(id) => id,
        Err(_) => {
            crate::println!("[spawn-heavy] FAIL step=stack_map_anon task_id={} tid={} aspace={}", task_id, thread_id, aspace_id);
            return None;
        }
    };

    // Eagerly allocate and map stack pages.
    let mmu_count = page::page_mmucount();
    for page_idx in 0..stack_alloc_pages {
        let page_va = stack_va + page_idx * ps;

        let pa = match crate::mm::object::with_object(obj_id, |obj| {
            obj.ensure_page(page_idx).map(|(pa, _)| pa)
        }) {
            Some(p) => p,
            None => {
                crate::println!("[spawn-heavy] FAIL step=stack_ensure_page task_id={} tid={} obj_id={} page_idx={}", task_id, thread_id, obj_id, page_idx);
                return None;
            }
        };
        let pa_usize = pa.as_usize();

        unsafe {
            core::ptr::write_bytes(crate::mm::page::phys_to_kva(pa_usize) as *mut u8, 0, ps);
        }

        let sw_z = crate::mm::fault::sw_zeroed_bit();
        let pte_flags = crate::mm::hat::USER_RW_FLAGS | sw_z;

        let alloc_len = mmu_count * MMUPAGE_SIZE;
        if let Err(e) =
            crate::mm::hat::map_range(pt_root, page_va, pa_usize, alloc_len, pte_flags)
        {
            crate::println!(
                "[spawn-heavy] FAIL step=user_stack_map_range task_id={} tid={} page_va={:#x} err={:?}",
                task_id, thread_id, page_va, e
            );
            return None;
        }
    }

    // Allocate kernel stack for this thread.
    let kstack_page = match alloc_kstack_zeroed() {
        Some(p) => p,
        None => {
            crate::println!("[spawn-heavy] FAIL step=kstack_alloc task_id={} tid={}", task_id, thread_id);
            return None;
        }
    };
    let kstack_base = kstack_page.as_usize();
    let kstack_phys_base = kstack_page.pa_base.as_usize();
    init_stack_canary(kstack_base);
    let kstack_top = kstack_base + kstack_size();

    // Build a fake exception frame for user-mode entry.
    let frame_sp = kstack_top - EXCEPTION_FRAME_SIZE;
    let frame = frame_sp as *mut u64;
    unsafe {
        for i in 0..(EXCEPTION_FRAME_SIZE / 8) {
            *frame.add(i) = 0;
        }

        crate::arch::trapframe::init_user_frame(frame, entry as usize, USER_STACK_TOP, &[arg0]);
    }

    Some((
        aspace_id,
        pt_root,
        frame_sp as u64,
        kstack_base,
        kstack_phys_base,
        task_port,
        thread_port,
    ))
}

/// Phase 1 of user thread creation: allocate task/thread IDs and read parent info.
/// Caller must hold `SPAWN_LOCK` (which serializes both thread- and task-ART writes).
fn alloc_spawn_ids() -> Option<(u32, ThreadId, SpawnParentInfo)> {
    let task_id = alloc_task_id()?;
    let thread_id = alloc_thread_id()?;
    let caller_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let parent_task = thread_ref(caller_tid).task_id;
    let ptask = task_ref(parent_task);
    let info = SpawnParentInfo {
        parent_task,
        sid: ptask.sid,
        ctty_port: ptask.ctty_port,
        uid: ptask.uid,
        euid: ptask.euid,
        gid: ptask.gid,
        egid: ptask.egid,
        groups_inline: ptask.groups_inline,
        groups_overflow: ptask.groups_overflow,
        ngroups: ptask.ngroups,
        rlimits: ptask.rlimits,
    };
    Some((task_id, thread_id, info))
}

/// Phase 3 of user thread creation: populate task/thread state and add to run queue.
fn finalize_spawn(
    task_id: u32,
    thread_id: ThreadId,
    parent: &SpawnParentInfo,
    aspace_id: u64,
    pt_root: usize,
    priority: u8,
    quantum: u32,
    frame_sp: u64,
    kstack_base: usize,
    kstack_phys_base: usize,
    task_port: u64,
    thread_port: u64,
) {
    // Initialize task fields for a newly spawned process.
    // NOTE: do NOT use `*task = Task::empty()` here — do_spawn_heavy_work() has
    // already set up capset/capspace/cur_ports before this function runs.
    // Only reset fields that could be stale from a reused task slot.
    let task = unsafe { task_mut_from_ref(task_id) };
    task.id = task_id;
    task.active = true;
    task.port_id = task_port;
    task.aspace_id = aspace_id;
    task.page_table_root = pt_root;
    task.exit_code = 0;
    task.exited = false;
    task.reaped = false;
    task.wait_status = 0;
    task.thread_count = 1;
    task.parent_task = parent.parent_task;
    task.pgid = task_id;
    task.sid = parent.sid;
    task.ctty_port = parent.ctty_port;
    task.fg_pgid = 0;
    task.uid = parent.uid;
    task.euid = parent.euid;
    task.gid = parent.gid;
    task.egid = parent.egid;
    task.groups_inline = parent.groups_inline;
    task.groups_overflow = parent.groups_overflow;
    task.ngroups = parent.ngroups;
    task.rlimits = parent.rlimits;
    // Reset fields that finalize_spawn doesn't set but could be stale from slot reuse.
    task.max_ports = 128;
    task.max_threads = 32;
    task.max_pages = 512;
    task.sa_enabled = false;
    task.sig_actions = [const { super::task::SignalAction::default() }; super::task::MAX_SIGNALS];
    task.alarm_deadline_ns = 0;
    task.alarm_interval_ns = 0;
    task.sa_pending.store(false, core::sync::atomic::Ordering::Relaxed);
    task.sa_event.store(0, core::sync::atomic::Ordering::Relaxed);
    task.sa_waiter.store(u32::MAX, core::sync::atomic::Ordering::Relaxed);
    // Spawned processes always start with native personality (not inherited).
    // Fork inherits personality; spawn does not.
    task.personality = super::task::PersonalityId::TelixNative;
    task.syscall_abi = super::task::SyscallAbi::TelixNative;
    task.personality_port = 0;

    let thread = unsafe { thread_mut_from_ref(thread_id) };
    thread.killed.store(false, Ordering::Release);
    thread
        .affinity_mask
        .store_mask(&cpumask::CpuMask::all(), Ordering::Relaxed);
    thread.last_cpu.store(smp::cpu_id(), Ordering::Relaxed);
    // NEW_INV: a freshly-spawned thread enters Ready, so on_cpu must be
    // ON_CPU_PENDING (overrides any stale value from a recycled tid).
    thread.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
    thread.in_queue.store(false, Ordering::Release);
    // #135 reset diagnostic fields on thread reuse.  Without this,
    // enqueue_count / picked_count / trans_ring carry forward from
    // the previous incarnation of this tid, polluting rescue dumps
    // (e.g. enq_n=16M reflecting cumulative not current behavior).
    thread.enqueue_count.store(0, Ordering::Relaxed);
    thread.picked_count.store(0, Ordering::Relaxed);
    thread.trans_pos.store(0, Ordering::Relaxed);
    for i in 0..4 {
        thread.trans_ring[i].store(0, Ordering::Relaxed);
    }

    thread.id = thread_id;
    thread.state = ThreadState::Ready;
    thread.task_id = task_id;
    thread.port_id = thread_port;
    thread.base_priority = priority;
    thread.effective_priority = priority;
    thread.prio.store(priority, Ordering::Relaxed);
    thread.thread_task.store(task_id, Ordering::Relaxed);
    thread.quantum = quantum;
    thread.default_quantum = quantum;
    // #208: stack_base BEFORE record_saved_sp_write (snapshot gate
    // requires stack_base != 0).
    // #230 canon-race fix: set canonical BEFORE writing stack_phys_base.
    if thread_id < 100 {
        spb_set_canonical(thread_id, kstack_phys_base as u64);
    }
    thread.stack_base = kstack_base;
    thread.stack_phys_base = kstack_phys_base;
    bump_kstack_epoch(thread); // #208
    write_saved_sp(thread, frame_sp);
    record_saved_sp_write(thread_id, frame_sp, 2); // spawn_user
    if thread_id < 100 {
        #[cfg(target_arch = "x86_64")]
        log_kuser_spawn(thread_id, task_id, b"spawn_user", None, priority, quantum);
        #[cfg(not(target_arch = "x86_64"))]
        crate::println!(
            "KUSER-SPAWN: tid={} task={} entry=spawn_user prio={} q={}",
            thread_id, task_id, priority, quantum,
        );
    }
    // #208 5f hunt: arm the exception-entry GDT/IDT/CR3 descriptor
    // validator from the first userspace spawn (scheduler up), so it covers
    // ALL Phase-5 death points — the silent triple's location varies boot
    // to boot (some die in FS-server init before tid 34/pipe_srv spawns).
    #[cfg(all(target_arch = "x86_64", feature = "vm_debug_probes"))]
    crate::arch::x86_64::gdt::DESC_VALIDATE_ARMED.store(true, Ordering::Release);
    // #233 DR0 watchpoint on tid 34 (linux_srv main thread)'s iretq frame
    // CS slot.  This is the slot[1] location that's been showing garbage
    // across boots.  Address is kstack_top - 32 (CS slot = regs[18] at
    // frame_sp + 144, and frame_sp = kstack_top - 176, so 144-176=-32).
    // Every CPU lazily re-arms DR0 on this VA at exception entry; ANY
    // write to slot[1] of tid 34's iretq frame fires #DB → diagnostic
    // dump exposes the writer's RIP.
    #[cfg(target_arch = "x86_64")]
    if thread_id == 34 {
        let kstack_top = kstack_base + kstack_size();
        let cs_slot_va = (kstack_top - 32) as u64;
        crate::arch::x86_64::gdt::GLOBAL_SAVED_SP_WATCH_ADDR
            .store(cs_slot_va, Ordering::Release);
        crate::println!(
            "DR0-TID34-CS: armed at {:#x} (kstack_top={:#x})",
            cs_slot_va, kstack_top,
        );
    }
    thread.sig_mask = 0;
    thread.sig_pending = 0;

    let ts = crate::sync::turnstile::alloc_thread_turnstile();
    thread.turnstile.store(ts, Ordering::Relaxed);

    percpu_enqueue(smp::cpu_id(), priority, thread_id);
}

/// Create a new thread in an existing task. Thread ID and port are pre-allocated.
fn create_thread_in_task(
    task_id: u32,
    id: ThreadId,
    entry: u64,
    stack_top: u64,
    arg: u64,
    priority: u8,
    quantum: u32,
    thread_port: u64,
) -> Option<ThreadId> {
    if !task_ref(task_id).active {
        return None;
    }

    let kstack_page = alloc_kstack_zeroed()?;
    let kstack_base = kstack_page.as_usize();
    let kstack_phys_base = kstack_page.pa_base.as_usize();
    init_stack_canary(kstack_base);
    let kstack_top = kstack_base + kstack_size();

    let frame_sp = kstack_top - EXCEPTION_FRAME_SIZE;
    let frame = frame_sp as *mut u64;
    unsafe {
        for i in 0..(EXCEPTION_FRAME_SIZE / 8) {
            *frame.add(i) = 0;
        }

        crate::arch::trapframe::init_user_frame(frame, entry as usize, stack_top as usize, &[arg]);
    }

    let thread = unsafe { thread_mut_from_ref(id) };
    thread.killed.store(false, Ordering::Release);
    thread
        .affinity_mask
        .store_mask(&cpumask::CpuMask::all(), Ordering::Relaxed);
    thread.last_cpu.store(smp::cpu_id(), Ordering::Relaxed);
    // NEW_INV: thread enters Ready, so on_cpu = ON_CPU_PENDING.
    thread.on_cpu.store(ON_CPU_PENDING, Ordering::Release);

    thread.id = id;
    thread.state = ThreadState::Ready;
    thread.task_id = task_id;
    thread.port_id = thread_port;
    thread.base_priority = priority;
    thread.effective_priority = priority;
    thread.prio.store(priority, Ordering::Relaxed);
    thread.thread_task.store(task_id, Ordering::Relaxed);
    thread.quantum = quantum;
    thread.default_quantum = quantum;
    // #208: stack_base BEFORE record (snapshot needs stack_base != 0).
    // #230 canon-race fix: set canonical BEFORE writing stack_phys_base.
    if id < 100 {
        spb_set_canonical(id, kstack_phys_base as u64);
    }
    thread.stack_base = kstack_base;
    thread.stack_phys_base = kstack_phys_base;
    bump_kstack_epoch(thread); // #208
    write_saved_sp(thread, frame_sp as u64);
    record_saved_sp_write(id, frame_sp as u64, 3); // spawn_user variant
    if id < 100 {
        #[cfg(target_arch = "x86_64")]
        log_kuser_spawn(id, task_id, b"", Some(entry as u64), priority, quantum);
        #[cfg(not(target_arch = "x86_64"))]
        crate::println!(
            "KUSER-SPAWN: tid={} task={} entry={:#x} prio={} q={}",
            id, task_id, entry, priority, quantum,
        );
    }
    thread.exit_code = 0;
    thread.sig_mask = 0;
    thread.sig_pending = 0;

    let ts = crate::sync::turnstile::alloc_thread_turnstile();
    thread.turnstile.store(ts, Ordering::Relaxed);

    unsafe { task_mut_from_ref(task_id) }.thread_count += 1;
    percpu_enqueue(smp::cpu_id(), priority, id);
    Some(id)
}

/// Get a mutable reference to a thread via its radix pointer.
/// # Safety: Caller must ensure exclusive access (thread is owned by current CPU,
/// or is Blocked/Dead and not accessible from any other path).
#[inline]
#[track_caller]
pub(crate) unsafe fn thread_mut_from_ref(tid: ThreadId) -> &'static mut Thread {
    let p = THREAD_TABLE.get(tid) as *mut Thread;
    // Validate the returned pointer is in SLAB_REGION (PML4[509], where
    // Thread structs live post VA isolation Phase 4).  Catches every
    // code path that uses a corrupted THREAD_TABLE entry to obtain a
    // mutable Thread ref — not just the saved_sp writer family.
    #[cfg(target_arch = "x86_64")]
    {
        let addr = p as u64;
        if addr != 0 {
            let in_slab = addr
                >= crate::arch::x86_64::mm::SLAB_REGION_BASE
                && addr
                    < crate::arch::x86_64::mm::SLAB_REGION_BASE
                        .wrapping_add(crate::arch::x86_64::mm::PML4_SLOT_SIZE);
            if !in_slab {
                static BAD_TMUT_LOG: core::sync::atomic::AtomicU32 =
                    core::sync::atomic::AtomicU32::new(0);
                let n = BAD_TMUT_LOG.fetch_add(1, Ordering::Relaxed);
                if n < 32 {
                    let caller = core::panic::Location::caller();
                    crate::println!(
                        "THREAD-MUT-BAD-PTR: tid={} ptr={:#x} caller={}:{} n={}",
                        tid,
                        addr,
                        caller.file(),
                        caller.line(),
                        n,
                    );
                }
            }
        }
    }
    unsafe { &mut *p }
}

/// # Safety: Caller must ensure exclusive access to the mutated fields
/// (e.g., current task's sig_actions, written only by owning task).
#[inline]
pub(crate) unsafe fn task_mut_from_ref(id: TaskId) -> &'static mut Task {
    let p = TASK_TABLE.get(id) as *mut Task;
    unsafe { &mut *p }
}

/// Pick next thread from the current CPU's per-CPU run queue.
/// Returns idle_id if nothing is ready.
fn percpu_pick_next(cpu: u32, idle_id: ThreadId) -> ThreadId {
    let mut rq = percpu_rq()[cpu as usize].lock();
    // Class-aware dispatch: RT → EEVDF → legacy.
    if let Some(tid) = rq.class_pick_next() {
        thread_ref(tid).in_queue.store(false, Ordering::Release);
        dequeue_set_pending(tid);
        trace_sched(tid, 3); // 3=pick_deq
        return tid;
    }
    drop(rq);
    // Nothing local — try work stealing.
    if let Some(tid) = try_steal(cpu) {
        thread_ref(tid).in_queue.store(false, Ordering::Release);
        dequeue_set_pending(tid);
        trace_sched(tid, 12); // 12=steal_deq
        return tid;
    }
    idle_id
}

/// #173 fix B: reclaim a stale-`on_cpu` orphan during dispatch claim.
///
/// Precondition: `tid` was just popped from a run queue by the claim helper
/// (so `in_queue == false` — we hold it "in hand"), and the normal claim
/// `CAS(on_cpu, PENDING → cpu)` already FAILED, meaning `on_cpu` is not
/// PENDING.
///
/// The gate=ON wedge (project_gate_on_residual_reframed_host_pressure):
/// some path left a Ready, enqueued thread with `on_cpu` = a *stale* real-CPU
/// number (a CPU that already finished running it).  The old helper dropped
/// such a pick "on the floor", assuming another path owned its lifecycle —
/// but nothing did, so the thread became a permanent orphan (Ready, not in
/// any heap), endlessly re-rescued without ever dispatching (tid=17 bounce).
///
/// This recovers it: if `on_cpu` names a real CPU that is **not** actually
/// running or mid-dispatching `tid` (same `current_thread`/`dispatching_tid`
/// predicate the rescue uses, scheduler.rs:12077-12082), claim it with a
/// single `CAS(stale_cpu → cpu)`.
///
/// Safety (no double-dispatch):
///   * `tid` is in our hand (popped, `in_queue == false`).  A *genuinely*
///     running thread is NOT also sitting in our run queue (single-owner
///     `in_queue`), so we could not have popped it — hence a real-CPU
///     `on_cpu` we observe on a popped thread is necessarily stale.  The
///     `current_thread`/`dispatching_tid` check is a belt-and-suspenders
///     guard against the source-bug's leftover stamp.
///   * The reclaim is a single `compare_exchange(on, cpu)`: it succeeds only
///     while `on_cpu` is still the exact stale value `on`.  A concurrent wake
///     that re-stamps `on_cpu = PENDING`, or a rescue `→ MAX`, makes the CAS
///     fail and we drop (the wake's re-enqueue / rescue then makes it
///     claimable again).  `on_cpu` cannot ABA back to `on`, because the only
///     path that writes a real CPU is a `PENDING → that_cpu` claim, and that
///     CPU cannot claim `tid` while `tid` is in our hand (not in its heap).
///   * Therefore dispatch stays single-arbiter: exactly one CPU wins a CAS
///     into its own id.  Verified by the loom model in
///     tests/loom-claim-helper (`stale_reclaim_*`).
///
/// Returns true iff it claimed `tid` for `cpu` (caller dispatches it).
fn reclaim_stale_on_cpu(tid: ThreadId, cpu: u32) -> bool {
    let on = thread_ref(tid).on_cpu.load(Ordering::Acquire);
    let ncpus = smp::num_cpus() as u32;
    // Only a *real-CPU* on_cpu is a candidate.  PENDING/RELEASING/MAX and
    // other sentinels are >= ncpus and mean "owned by a park/release/rescue
    // lifecycle path" — leave them for that path (the caller drops).
    if on >= ncpus {
        return false;
    }
    // Is the named CPU genuinely running or mid-dispatching tid?  If so this
    // is the legitimate "direct-dispatch raced the heap pick" case — leave it.
    let owner = smp::get(on);
    if owner.current_thread.load(Ordering::Acquire) == tid as u32
        || owner.dispatching_tid.load(Ordering::Acquire) == tid as u32
    {
        return false;
    }
    // Stale orphan — claim it for this CPU.  Single CAS from the observed
    // stale value; any concurrent re-stamp loses us the race (we drop).
    if thread_ref(tid)
        .on_cpu
        .compare_exchange(on, cpu, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        DISPATCH_CLAIM_STALE_RECLAIM.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// #173 Phase 1+2: pop + CAS-claim in one critical section.
///
/// The legacy `percpu_pick_next` pops a thread from the rq, drops the rq
/// lock, then stamps `on_cpu = ON_CPU_PENDING`.  The caller (try_switch /
/// voluntary_reschedule / park_current_for_ipc) does the CAS
/// `PENDING → this_cpu` later.  Between the stamp and the CAS, a host
/// pause can strand the picked thread — the phantom-pending window.
///
/// This helper collapses both steps under the rq lock: pop, then
/// `CAS(on_cpu, PENDING, this_cpu)`.  On CAS success, the thread is
/// claimed and `state = Running` is set here, alongside the matching
/// bookkeeping the legacy CAS-OK path runs (TRANS_CAS_OK record,
/// on_cpu_set_by, dispatch_cas_ok, dispatch_count).  On CAS failure
/// (another path — rescue, wake_thread direct — claimed the thread
/// first), we drop it on the floor and try the next pick.  See
/// `docs/dispatch-protocol-refactor.md` for the full rationale.
///
/// `set_by` tag matches the legacy path's `on_cpu_set_by` constants:
///   1 = try_switch, 2 = vol_resched, 3 = park_ipc.
fn percpu_pick_next_and_claim(
    cpu: u32,
    idle_id: ThreadId,
    pcpu: &smp::PerCpuData,
    set_by: u8,
) -> ThreadId {
    // #173 TCG-sync-tax mitigation: keep the rq-locked critical section
    // minimal (pop + in_queue + CAS only).  All success-side bookkeeping
    // touches per-thread or per-cpu state, never the rq — safe to move
    // outside the lock.  TCG penalty per atomic-under-lock is ~10x KVM
    // and stretches the lock-hold time enough to starve peer CPUs that
    // are stealing or enqueueing onto this rq.
    let claimed: Option<(ThreadId, u8)> = {
        let mut rq = percpu_rq()[cpu as usize].lock();
        let mut result: Option<(ThreadId, u8)> = None;
        loop {
            let tid = match rq.class_pick_next() {
                Some(t) => t,
                None => break,
            };
            thread_ref(tid).in_queue.store(false, Ordering::Release);
            // #173 fix B: publish dispatch intent BEFORE the claim CAS, so a
            // concurrent `reclaim_stale_on_cpu` on another CPU observes this
            // in-flight claim (via `dispatching_tid`) and will NOT mistake our
            // just-claimed thread for a stale orphan and steal it.  Mirrors the
            // legacy path (see try_switch ~7117).  Cleared below if we lose the
            // claim, and overwritten by the next pick; left = tid on success.
            pcpu.dispatching_tid.store(tid as u32, Ordering::Release);
            if thread_ref(tid)
                .on_cpu
                .compare_exchange(ON_CPU_PENDING, cpu, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                || reclaim_stale_on_cpu(tid, cpu)
            {
                result = Some((tid, 3)); // 3=pick_deq trace tag (reclaim shares it)
                break;
            }
            // Normal claim AND stale-reclaim both declined — `tid` is genuinely
            // owned by another path (running/dispatching elsewhere, or parking /
            // RELEASING).  Clear our dispatch intent, then drop on the floor and
            // try the next pick; we've removed it from the rq, which is correct
            // since the owner's lifecycle path (or the rescue backstop) handles
            // it.  See `reclaim_stale_on_cpu` for the gate=ON orphan this branch
            // used to strand (#173 fix B).
            pcpu.dispatching_tid.store(0, Ordering::Release);
            DISPATCH_CLAIM_FAIL.fetch_add(1, Ordering::Relaxed);
        }
        result
    }; // <- rq lock released here
    if let Some((tid, trace_tag)) = claimed {
        // Commit phase — outside the rq lock.  Safe because none of these
        // ops touch rq state.
        record_trans(tid as u32, TRANS_CAS_OK, ThreadState::Running, cpu);
        thread_ref(tid).on_cpu_set_by.store(set_by, Ordering::Relaxed);
        dispatch_cas_ok(pcpu, tid);
        unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Running;
        pcpu.dispatch_count.fetch_add(1, Ordering::Relaxed);
        trace_sched(tid, trace_tag);
        DISPATCH_CLAIM_LOCAL.fetch_add(1, Ordering::Relaxed);
        return tid;
    }
    // Nothing local — try work stealing.  Same pop-then-CAS dance.
    // try_steal acquires the *other* CPU's rq lock internally and drops
    // it before returning, so we're already lock-free here for the
    // commit phase below.
    if let Some(tid) = try_steal(cpu) {
        thread_ref(tid).in_queue.store(false, Ordering::Release);
        // #173 fix B: publish dispatch intent before the claim CAS (see local
        // path above).  Cleared on failure so a reclaimer never sees a stale
        // dispatching_tid for a steal we lost.
        pcpu.dispatching_tid.store(tid as u32, Ordering::Release);
        if thread_ref(tid)
            .on_cpu
            .compare_exchange(ON_CPU_PENDING, cpu, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            || reclaim_stale_on_cpu(tid, cpu)
        {
            record_trans(tid as u32, TRANS_CAS_OK, ThreadState::Running, cpu);
            thread_ref(tid).on_cpu_set_by.store(set_by, Ordering::Relaxed);
            dispatch_cas_ok(pcpu, tid);
            unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Running;
            pcpu.dispatch_count.fetch_add(1, Ordering::Relaxed);
            trace_sched(tid, 12); // 12=steal_deq (same tag as legacy path)
            DISPATCH_CLAIM_STEAL.fetch_add(1, Ordering::Relaxed);
            return tid;
        }
        // CAS failed on a stolen tid — clear intent and return idle.  Phase 1:
        // don't retry try_steal (cost vs benefit unclear).  Phase 2+ may revisit.
        pcpu.dispatching_tid.store(0, Ordering::Release);
        DISPATCH_CLAIM_FAIL.fetch_add(1, Ordering::Relaxed);
    }
    idle_id
}

/// #173: A/B gate for the single-atomic dispatch claim helper.  Default OFF
/// (legacy pick + set-PENDING + CAS two-step) on all arches.
///
/// History: briefly defaulted ON for x86_64 (commit 914a467) after a THRASH=true
/// A/B looked equivalent, but a cleaner THRASH=false A/B (2026-06-15, ~5 boots
/// each) showed gate=ON deep boots top out around Phase 5f-5q while gate=OFF
/// reach Phase 145e/Phase 6 — a consistent multi-phase deep-boot regression.
/// The wake_thread on_cpu=PENDING fix (8b8f82a) closed ONE gate=ON orphan
/// (the #198 tid=17 starvation: rescue17 0 in all A/B boots after it), but a
/// RESIDUAL gate=ON deep-boot disadvantage remains (some other claim-helper
/// interaction, not yet root-caused).  So the default reverts to OFF until that
/// residual is found; rv64 also regresses (task #262).  The machinery stays
/// (helper + park-tail wiring + loom-claim-helper 5/5 + this gate) for the hunt.
///
/// Runtime-togglable via the debug command (1=on, 2=off).  When on, every
/// dispatch pick (try_switch / voluntary_reschedule / park_ipc / park_sleep /
/// park_faulting) routes through `percpu_pick_next_and_claim`, eliminating the
/// phantom-pending window (but exposing the residual deep-boot regression).
pub static DISPATCH_USE_CLAIM_HELPER: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// #173 Phase 3c: cosched-aware variant of `percpu_pick_next_and_claim`.
///
/// Mirrors `percpu_pick_next_cosched`'s prev-group preference and adds
/// **self-pick detection**.  Self-pick occurs in `try_switch` when the
/// picker dequeues `prev_id` (concurrently re-enqueued by a wake or
/// rescue while still running on this CPU).  Legacy code handles it by
/// checking `prev_id == next_id` at the caller; with the claim helper,
/// the CAS `PENDING → cpu` fails on a self-pick because `on_cpu` is
/// already `this_cpu` (not `PENDING`).
///
/// On CAS failure we re-load `on_cpu`: if it equals `cpu`, this is
/// self-pick — the thread is still happily running on us.  Return
/// `prev_id_for_self_pick` so the caller's existing `next_id == prev_id`
/// branch fires naturally and skips the switch.  If `on_cpu` is some
/// other CPU number, a real concurrent claim happened — drop and retry.
///
/// `prev_id_for_self_pick` is the currently-running tid the caller will
/// stay on if self-pick is detected.  Pass `idle_id` if self-pick is
/// not a concern at the caller (the value won't be returned unless the
/// pop matches it, which is rare).
fn percpu_pick_next_cosched_and_claim(
    cpu: u32,
    idle_id: ThreadId,
    prev_group: u32,
    prev_id_for_self_pick: ThreadId,
    pcpu: &smp::PerCpuData,
    set_by: u8,
) -> ThreadId {
    let mut rq = percpu_rq()[cpu as usize].lock();
    // Cosched preference: pop from the same group as prev.
    if prev_group != 0 && rq.cosched_burst < MAX_COSCHED_BURST {
        if let Some(tid) = rq.pop_for_group(prev_group) {
            thread_ref(tid).in_queue.store(false, Ordering::Release);
            if thread_ref(tid)
                .on_cpu
                .compare_exchange(ON_CPU_PENDING, cpu, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                record_trans(tid as u32, TRANS_CAS_OK, ThreadState::Running, cpu);
                thread_ref(tid).on_cpu_set_by.store(set_by, Ordering::Relaxed);
                dispatch_cas_ok(pcpu, tid);
                unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Running;
                pcpu.dispatch_count.fetch_add(1, Ordering::Relaxed);
                rq.cosched_burst += 1;
                COSCHED_HITS.fetch_add(1, Ordering::Relaxed);
                trace_sched(tid, 3);
                DISPATCH_CLAIM_LOCAL.fetch_add(1, Ordering::Relaxed);
                return tid;
            }
            // Self-pick detection on the cosched pop.
            if tid == prev_id_for_self_pick
                && thread_ref(tid).on_cpu.load(Ordering::Acquire) == cpu
            {
                DISPATCH_CLAIM_SELF_PICK.fetch_add(1, Ordering::Relaxed);
                rq.cosched_burst += 1;
                return tid;
            }
            DISPATCH_CLAIM_FAIL.fetch_add(1, Ordering::Relaxed);
        }
    }
    rq.cosched_burst = 0;
    // Class-aware pick + retry loop.
    loop {
        let tid = match rq.class_pick_next() {
            Some(t) => t,
            None => break,
        };
        thread_ref(tid).in_queue.store(false, Ordering::Release);
        if thread_ref(tid)
            .on_cpu
            .compare_exchange(ON_CPU_PENDING, cpu, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            record_trans(tid as u32, TRANS_CAS_OK, ThreadState::Running, cpu);
            thread_ref(tid).on_cpu_set_by.store(set_by, Ordering::Relaxed);
            dispatch_cas_ok(pcpu, tid);
            unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Running;
            pcpu.dispatch_count.fetch_add(1, Ordering::Relaxed);
            trace_sched(tid, 3);
            DISPATCH_CLAIM_LOCAL.fetch_add(1, Ordering::Relaxed);
            return tid;
        }
        // Self-pick: prev_id was popped but still has on_cpu == this_cpu.
        if tid == prev_id_for_self_pick
            && thread_ref(tid).on_cpu.load(Ordering::Acquire) == cpu
        {
            DISPATCH_CLAIM_SELF_PICK.fetch_add(1, Ordering::Relaxed);
            return tid;
        }
        DISPATCH_CLAIM_FAIL.fetch_add(1, Ordering::Relaxed);
    }
    drop(rq);
    // try_steal fallback.
    if let Some(tid) = try_steal(cpu) {
        thread_ref(tid).in_queue.store(false, Ordering::Release);
        if thread_ref(tid)
            .on_cpu
            .compare_exchange(ON_CPU_PENDING, cpu, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            record_trans(tid as u32, TRANS_CAS_OK, ThreadState::Running, cpu);
            thread_ref(tid).on_cpu_set_by.store(set_by, Ordering::Relaxed);
            dispatch_cas_ok(pcpu, tid);
            unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Running;
            pcpu.dispatch_count.fetch_add(1, Ordering::Relaxed);
            trace_sched(tid, 12);
            DISPATCH_CLAIM_STEAL.fetch_add(1, Ordering::Relaxed);
            return tid;
        }
        // try_steal'd a self thread? Extremely unlikely (steal looks at other
        // CPUs' queues), but handle defensively.
        if tid == prev_id_for_self_pick
            && thread_ref(tid).on_cpu.load(Ordering::Acquire) == cpu
        {
            DISPATCH_CLAIM_SELF_PICK.fetch_add(1, Ordering::Relaxed);
            return tid;
        }
        DISPATCH_CLAIM_FAIL.fetch_add(1, Ordering::Relaxed);
    }
    idle_id
}

/// #173 Phase 3c: counter for self-pick observations under the new
/// helper.  Compared against the legacy `SELF_PICK_COUNT` (try_switch
/// line 5913) when validating the migration.
pub static DISPATCH_CLAIM_SELF_PICK: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// #173 Phase 5: rescue-fire splits by gate state.  Under gate ON the
/// claim helper closes the dispatch-side phantom-pending window; any
/// RESCUE-STUCK-PENDING fire is necessarily from an enqueue-side stuck
/// PENDING (Type B in docs/dispatch-protocol-refactor.md).  Tracking
/// the ratio over many stress boots tells us how much rescue burden
/// the new protocol offloads.  When `GATE_ON` fires approach the
/// `GATE_OFF` baseline under matched stress, the helper is not
/// reducing rescue activity — meaning the bug class wasn't a major
/// rescue contributor in practice.  When `GATE_ON` fires are much
/// lower, the helper is doing real work.
pub static RESCUE_STUCK_PENDING_FIRES_GATE_ON: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static RESCUE_STUCK_PENDING_FIRES_GATE_OFF: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// #173 Phase 1 metrics: count successful local claims, successful steal
/// claims, and CAS failures inside `percpu_pick_next_and_claim`.  Used for
/// A/B comparison against the legacy `dispatch_set_pending_count` /
/// `dispatch_cas_ok_count` pair once Phase 2 wires the new helper at a
/// dispatch call site.
pub static DISPATCH_CLAIM_LOCAL: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static DISPATCH_CLAIM_STEAL: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static DISPATCH_CLAIM_FAIL: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// #173 fix B: count of stale-on_cpu orphans the claim helper recovered by
/// resetting on_cpu PENDING + re-enqueueing (instead of floor-dropping them).
/// A non-zero value under gate=ON means the helper is breaking the tid=17
/// orphan-bounce that previously wedged Phase 3-4.  See
/// `reclaim_stale_on_cpu` and project_gate_on_residual_reframed_host_pressure.
pub static DISPATCH_CLAIM_STALE_RECLAIM: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// #173 confirming probe: count of times block_current stored state=Blocked
/// while on_cpu == ON_CPU_PENDING — the torn-creating write of the
/// block_current‖wake_thread race (a concurrent wake stamped on_cpu=PENDING
/// before/while we re-set Blocked, losing the wakeup).  Non-zero confirms the
/// root cause in project_gate_on_residual_reframed_host_pressure.
pub static TORN_BLOCK_FIRES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Pick next thread, preferring a cosched group mate on the current CPU.
/// Coscheduling only applies to RT-class threads in the bitmap queues.
fn percpu_pick_next_cosched(cpu: u32, idle_id: ThreadId, prev_group: u32) -> (ThreadId, bool) {
    let mut rq = percpu_rq()[cpu as usize].lock();
    if prev_group != 0 && rq.cosched_burst < MAX_COSCHED_BURST {
        if let Some(tid) = rq.pop_for_group(prev_group) {
            thread_ref(tid).in_queue.store(false, Ordering::Release);
            dequeue_set_pending(tid);
            trace_sched(tid, 3); // 3=pick_deq
            rq.cosched_burst += 1;
            COSCHED_HITS.fetch_add(1, Ordering::Relaxed);
            return (tid, true);
        }
    }
    rq.cosched_burst = 0;
    // Class-aware dispatch: RT → EEVDF → legacy.
    if let Some(tid) = rq.class_pick_next() {
        thread_ref(tid).in_queue.store(false, Ordering::Release);
        dequeue_set_pending(tid);
        trace_sched(tid, 3); // 3=pick_deq
        return (tid, false);
    }
    drop(rq);
    // Nothing local — try work stealing.
    if let Some(tid) = try_steal(cpu) {
        thread_ref(tid).in_queue.store(false, Ordering::Release);
        dequeue_set_pending(tid);
        trace_sched(tid, 12); // 12=steal_deq
        return (tid, false);
    }
    (idle_id, false)
}

/// Spawn write lock: serializes all spawn/fork/thread-create operations
/// AND the (insert-only) writes to `SCHED_THREAD_ART` / `SCHED_TASK_ART`.
/// This is the only remaining global lock for the scheduler subsystem.
///
/// FIFO-fair + PV-aware: spawn is syscall-driven (sys_spawn/fork/clone/
/// thread_create) and burst-contended during Linux personality task-tree
/// expansion (multi-thread processes, server fan-out).  No IRQ handler
/// takes this lock — timer tick + IPI handlers route through dispatch,
/// not spawn.  Ticket ordering bounds acquisition latency, PV-aware spin
/// keeps timer/IPI flow alive while the holder is host-paused.
static SPAWN_LOCK: crate::sync::TicketSpinLock<()> =
    crate::sync::TicketSpinLock::new(());

pub fn init() {
    sched_init();
    let idle_id = 0; // Thread 0 = BSP idle

    // #173 Phase 5: honor `dispatch_claim_helper=` from kernel cmdline.
    // 0 = leave compile-time default; 1 = force ON; 2 = force OFF.
    let knob = crate::boot::cmdline::BOOT_CONFIG
        .dispatch_claim_helper
        .load(Ordering::Relaxed);
    match knob {
        1 => DISPATCH_USE_CLAIM_HELPER.store(true, Ordering::Relaxed),
        2 => DISPATCH_USE_CLAIM_HELPER.store(false, Ordering::Relaxed),
        _ => {}
    }

    smp::init_bsp(idle_id);
    super::hotplug::mark_online(0);
    crate::println!("  Scheduler initialized (BSP = CPU 0)");
}

/// Called by secondary CPUs to create their idle thread and register.
pub fn init_ap(cpu: u32) {
    let idle_id = {
        let _lock = SPAWN_LOCK.lock_pv_aware();
        create_idle_thread().expect("AP idle thread")
    };
    smp::init_ap(cpu, idle_id);
    super::hotplug::mark_online(cpu);
    crate::println!("  CPU {} scheduler ready (idle thread {})", cpu, idle_id);
}

/// Get the task ID for a given thread (lock-free).
pub fn thread_task_id(tid: ThreadId) -> u32 {
    thread_ref(tid).task_id
}

pub fn spawn(entry: fn() -> !, priority: u8, quantum: u32) -> Option<ThreadId> {
    let _lock = SPAWN_LOCK.lock_pv_aware();
    create_thread(entry, priority, quantum)
}

/// Spawn a new user-mode process from an ELF binary in the initramfs.
/// Creates a new task with its own address space. `arg0` is passed to main().
///
/// Duplicate the parent's groups overflow page for a child task.
/// Must be called outside SCHEDULER lock (allocates a physical page).
/// On success, `parent.groups_overflow` is updated to the child's copy.
/// On failure (OOM), returns false.
fn dup_groups_overflow(parent: &mut SpawnParentInfo) -> bool {
    if parent.ngroups as usize <= GROUPS_INLINE || parent.groups_overflow == 0 {
        return true; // nothing to duplicate
    }
    let page = match crate::mm::phys::alloc_page() {
        Some(p) => p,
        None => return false,
    };
    // #235 Phase 4f: store groups_overflow as kva so deref + copy work
    // without PML4[0] identity.  free_groups_overflow undoes via kva_to_phys.
    let page_kva = crate::mm::page::phys_to_kva(page.as_usize());
    unsafe {
        core::ptr::copy_nonoverlapping(
            parent.groups_overflow as *const u8,
            page_kva as *mut u8,
            parent.ngroups as usize * core::mem::size_of::<u32>(),
        );
    }
    parent.groups_overflow = page_kva;
    true
}

/// Uses a 3-phase lock split: phase 1 (alloc IDs) and phase 3 (finalize)
/// hold SCHEDULER, but phase 2 (ELF loading, page table setup) runs without it.
pub fn spawn_user(elf_name: &[u8], priority: u8, quantum: u32, arg0: u64) -> Option<ThreadId> {
    // Check port_is_active BEFORE locking SCHEDULER to avoid ABBA deadlock.
    let arg0_is_port = arg0 > 0 && crate::ipc::port::port_is_active(arg0);

    // Look up the ELF binary (no locks needed).
    // #149 fix-probe: surface lookup_file misses so spawn failures
    // don't show as opaque "FAILED (spawn)" in init's logs.  Diagnoses
    // both genuine missing-file and parser-state-divergence cases (the
    // kernel-internal PARSED table is built lazily by the first
    // lookup_file caller and would not be visible from initramfs_srv's
    // local copy).
    let elf_data = match crate::io::initramfs::lookup_file(elf_name) {
        Some(d) => d,
        None => {
            crate::println!(
                "[spawn-user] lookup_file MISS name={:?} (len={})",
                core::str::from_utf8(elf_name).unwrap_or("?"),
                elf_name.len(),
            );
            return None;
        }
    };

    // Phase 1: allocate IDs under SPAWN_LOCK.
    let (task_id, thread_id, mut parent) = {
        let _lock = SPAWN_LOCK.lock_pv_aware();
        match alloc_spawn_ids() {
            Some(ids) => ids,
            None => {
                crate::println!(
                    "[spawn-user] alloc_spawn_ids FAILED for name={:?}",
                    core::str::from_utf8(elf_name).unwrap_or("?"),
                );
                return None;
            }
        }
    };

    // Phase 2: heavy work (page tables, ELF load, etc.) without locks.
    let (aspace_id, pt_root, frame_sp, kstack_base, kstack_phys_base, task_port, thread_port) =
        match do_spawn_heavy_work(
            task_id,
            thread_id,
            &parent,
            elf_data,
            priority,
            quantum,
            arg0,
            arg0_is_port,
            None,
        ) {
            Some(r) => r,
            None => {
                crate::println!(
                    "[spawn-user] do_spawn_heavy_work FAILED for name={:?} task_id={} tid={}",
                    core::str::from_utf8(elf_name).unwrap_or("?"),
                    task_id,
                    thread_id,
                );
                return None;
            }
        };

    // Duplicate groups overflow page for child.
    if !dup_groups_overflow(&mut parent) {
        crate::println!(
            "[spawn-user] dup_groups_overflow FAILED for name={:?} task_id={}",
            core::str::from_utf8(elf_name).unwrap_or("?"),
            task_id,
        );
        return None;
    }

    // Phase 3: finalize task/thread state.
    finalize_spawn(
        task_id,
        thread_id,
        &parent,
        aspace_id,
        pt_root,
        priority,
        quantum,
        frame_sp,
        kstack_base,
        kstack_phys_base,
        task_port,
        thread_port,
    );
    Some(thread_id)
}

/// Spawn a driver process with a pre-granted `CapType::Memory` cap for
/// an MMIO region. The resulting cap slot is OR'd into `arg0`'s low 16
/// bits — drivers decode it and pass it to `sys_mmio_map_cap`. Upper
/// bits of `arg0_upper` (typically `irq << 48`) are preserved.
pub fn spawn_user_with_mmio_cap(
    elf_name: &[u8],
    priority: u8,
    quantum: u32,
    arg0_upper: u64,
    mmio_region_id: u32,
) -> Option<ThreadId> {
    // Clear the slot bits the child will overwrite with the cap slot.
    let arg0 = arg0_upper & !0xFFFFu64;

    let elf_data = crate::io::initramfs::lookup_file(elf_name)?;

    let (task_id, thread_id, mut parent) = {
        let _lock = SPAWN_LOCK.lock_pv_aware();
        alloc_spawn_ids()?
    };

    let (aspace_id, pt_root, frame_sp, kstack_base, kstack_phys_base, task_port, thread_port) = do_spawn_heavy_work(
        task_id,
        thread_id,
        &parent,
        elf_data,
        priority,
        quantum,
        arg0,
        false,
        Some(mmio_region_id),
    )?;

    if !dup_groups_overflow(&mut parent) {
        return None;
    }

    finalize_spawn(
        task_id,
        thread_id,
        &parent,
        aspace_id,
        pt_root,
        priority,
        quantum,
        frame_sp,
        kstack_base,
        kstack_phys_base,
        task_port,
        thread_port,
    );
    Some(thread_id)
}

/// Spawn a new user-mode process from ELF data already in kernel memory.
pub fn spawn_user_from_elf(
    elf_data: &[u8],
    priority: u8,
    quantum: u32,
    arg0: u64,
) -> Option<ThreadId> {
    let arg0_is_port = arg0 > 0 && crate::ipc::port::port_is_active(arg0);

    let (task_id, thread_id, mut parent) = {
        let _lock = SPAWN_LOCK.lock_pv_aware();
        alloc_spawn_ids()?
    };

    let (aspace_id, pt_root, frame_sp, kstack_base, kstack_phys_base, task_port, thread_port) = do_spawn_heavy_work(
        task_id,
        thread_id,
        &parent,
        elf_data,
        priority,
        quantum,
        arg0,
        arg0_is_port,
        None,
    )?;

    if !dup_groups_overflow(&mut parent) {
        return None;
    }

    finalize_spawn(
        task_id,
        thread_id,
        &parent,
        aspace_id,
        pt_root,
        priority,
        quantum,
        frame_sp,
        kstack_base,
        kstack_phys_base,
        task_port,
        thread_port,
    );
    Some(thread_id)
}

/// Spawn a user-mode process with data mapped into its address space.
/// Sets arg0, arg1=data_va, arg2=data_len in the child's initial frame.
pub fn spawn_user_with_data(
    elf_name: &[u8],
    priority: u8,
    quantum: u32,
    data: &[u8],
    data_va: usize,
    arg0: u64,
) -> Option<ThreadId> {
    let arg0_is_port = arg0 > 0 && crate::ipc::port::port_is_active(arg0);

    let elf_data = crate::io::initramfs::lookup_file(elf_name)?;

    let (task_id, thread_id, mut parent) = {
        let _lock = SPAWN_LOCK.lock_pv_aware();
        alloc_spawn_ids()?
    };

    // Phase 2: ELF load + stack setup WITHOUT SCHEDULER lock.
    let (aspace_id, pt_root, frame_sp, kstack_base, kstack_phys_base, task_port, thread_port) = do_spawn_heavy_work(
        task_id,
        thread_id,
        &parent,
        elf_data,
        priority,
        quantum,
        arg0,
        arg0_is_port,
        None,
    )?;

    // Map data pages into the child's address space (still no SCHEDULER lock).
    let ps = page::page_size();
    let data_alloc_pages = (data.len() + ps - 1) / ps;
    let data_mmu_pages = data_alloc_pages * page::page_mmucount();
    if data_alloc_pages > 0 {
        let obj_id = crate::mm::aspace::with_aspace(aspace_id, |aspace| {
            let vma = aspace
                .map_anon(data_va, data_mmu_pages, crate::mm::vma::VmaProt::ReadOnly)
                .ok_or(())?;
            Ok::<_, ()>(vma.object_id)
        })
        .ok()?;

        let mmu_count = page::page_mmucount();
        let sw_z = crate::mm::fault::sw_zeroed_bit();
        let pte_flags = crate::mm::hat::USER_RO_FLAGS | sw_z;

        for page_idx in 0..data_alloc_pages {
            let page_va = data_va + page_idx * ps;
            let pa = crate::mm::object::with_object(obj_id, |obj| {
                obj.ensure_page(page_idx).map(|(pa, _)| pa)
            })?;
            let pa_usize = pa.as_usize();

            unsafe {
                core::ptr::write_bytes(crate::mm::page::phys_to_kva(pa_usize) as *mut u8, 0, ps);
                let copy_start = page_idx * ps;
                let copy_end = (copy_start + ps).min(data.len());
                if copy_start < data.len() {
                    core::ptr::copy_nonoverlapping(
                        data[copy_start..copy_end].as_ptr(),
                        crate::mm::page::phys_to_kva(pa_usize) as *mut u8,
                        copy_end - copy_start,
                    );
                }
            }

            let alloc_len = mmu_count * MMUPAGE_SIZE;
            if let Err(e) =
                crate::mm::hat::map_range(pt_root, page_va, pa_usize, alloc_len, pte_flags)
            {
                crate::println!(
                    "[spawn-data] map_range FAIL page_va={:#x} pa={:#x} len={:#x} err={:?}",
                    page_va, pa_usize, alloc_len, e
                );
                return None;
            }
        }
    }

    // Set arg1 = data_va, arg2 = data_len in the thread's exception frame.
    let frame = frame_sp as *mut u64;
    unsafe {
        crate::arch::trapframe::set_frame_arg(frame, 1, data_va as u64);
        crate::arch::trapframe::set_frame_arg(frame, 2, data.len() as u64);
    }

    if !dup_groups_overflow(&mut parent) {
        return None;
    }

    // Phase 3: finalize under SCHEDULER lock.
    finalize_spawn(
        task_id,
        thread_id,
        &parent,
        aspace_id,
        pt_root,
        priority,
        quantum,
        frame_sp,
        kstack_base,
        kstack_phys_base,
        task_port,
        thread_port,
    );
    Some(thread_id)
}

/// Create a new thread in the caller's task. Returns thread ID or None.
pub fn thread_create(task_id: u32, entry: u64, stack_top: u64, arg: u64) -> Option<ThreadId> {
    let (priority, quantum) = {
        let caller_tid = smp::current().current_thread.load(Ordering::Relaxed);
        let caller = thread_ref(caller_tid);
        (caller.base_priority, caller.default_quantum)
    };
    // Allocate thread ID under SPAWN_LOCK.
    let thread_id = {
        let _lock = SPAWN_LOCK.lock_pv_aware();
        alloc_thread_id()?
    };
    // Create kernel-held port for the new thread.
    let thread_port =
        crate::ipc::port::create_kernel_port(thread_port_handler, thread_id as usize)?;
    // Finalize thread creation.
    let result = create_thread_in_task(
        task_id,
        thread_id,
        entry,
        stack_top,
        arg,
        priority,
        quantum,
        thread_port,
    );
    // Grant caps on the new thread's port.
    if result.is_some() {
        use crate::cap::capability::Rights;
        let srm = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        crate::cap::grant_port_cap(task_id, thread_port, srm);
    }
    result
}

/// Check if a thread has exited and return its exit code.
/// Returns Some(exit_code) if dead and in the same task, None otherwise.
#[allow(dead_code)]
pub fn thread_join_poll(tid: ThreadId, caller_task: u32) -> Option<i32> {
    let t = thread_ref_opt(tid)?;
    if t.task_id != caller_task {
        return None;
    }
    if t.state == ThreadState::Dead {
        Some(t.exit_code)
    } else {
        None
    }
}

/// Blocking thread_join: if target is already dead return its exit code,
/// otherwise register as waiter and block until it exits.
pub fn thread_join_block(tid: ThreadId, caller_task: u32) -> u64 {
    {
        let t_ref = match thread_ref_opt(tid) {
            Some(t) => t,
            None => return u64::MAX,
        };
        if t_ref.task_id != caller_task {
            return u64::MAX;
        }
        if t_ref.state == ThreadState::Dead {
            return t_ref.exit_code as u64;
        }
        // Register ourselves as the join waiter.
        let caller_tid = current_thread_id();
        // Safe: only one joiner per thread, and the target is alive.
        unsafe { thread_mut_from_ref(tid) }.join_waiter = caller_tid;
        // Clear wakeup flag before blocking.
        thread_ref(caller_tid)
            .wakeup
            .store(false, Ordering::Release);
        // Re-check: the target may have exited between the first Dead
        // check and join_waiter registration.  If it raced and didn't see
        // our waiter, we must not block (nobody would wake us).
        if thread_ref(tid).state == ThreadState::Dead {
            unsafe { thread_mut_from_ref(tid) }.join_waiter = u32::MAX;
            return thread_ref(tid).exit_code as u64;
        }
    }
    // Block until the target thread wakes us via exit_current_thread.
    block_current(BlockReason::FutexWait);
    // Re-read exit code (lock-free).
    thread_ref(tid).exit_code as u64
}

/// Get the task ID of the current thread.
#[allow(dead_code)]
pub fn current_task_id() -> TaskId {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    thread_ref(tid)
        .thread_task
        .load(core::sync::atomic::Ordering::Relaxed)
}

/// Get the page table root of the current thread's task.
#[allow(dead_code)]
pub fn current_page_table_root() -> usize {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let task_id = thread_ref(tid).task_id;
    task_ref(task_id).page_table_root
}

/// Called from the timer IRQ handler. Takes the current kernel SP
/// Drain deferred killed-thread cleanup on this CPU.
/// Called at the start of each tick, while running on a live thread's stack.
fn drain_deferred_kills() {
    let cpu = smp::cpu_id() as usize;
    let tid = deferred_kill()[cpu].swap(usize::MAX, Ordering::AcqRel);
    if tid == usize::MAX || tid >= RadixTable::capacity() {
        return;
    }
    let tid = tid as ThreadId;
    let thread = thread_ref(tid);
    let task_id = thread.task_id;

    // Clean up turnstile state.
    crate::sync::turnstile::cleanup_blocked(tid);
    let tptr = THREAD_TABLE.get(tid) as *const super::thread::Thread;
    let ts_addr = unsafe { (*tptr).turnstile.swap(0, Ordering::Relaxed) };
    crate::sync::turnstile::free_thread_turnstile(ts_addr);

    // Destroy the thread's port.
    let thread_port = thread.port_id;
    if thread_port != 0 {
        crate::ipc::port::destroy(thread_port);
    }

    // Check if this was the last thread in its task.
    let task = unsafe { &*(TASK_TABLE.get(task_id) as *const Task) };
    if task.exited {
        // Switch to boot page table before freeing user page tables.
        let pt_root = task.page_table_root;
        if pt_root != 0 {
            let boot_root = crate::mm::hat::boot_page_table_root();
            crate::mm::hat::switch_page_table(boot_root);
        }

        // Free groups overflow.
        let tptr = TASK_TABLE.get(task_id) as *mut Task;
        unsafe {
            (*tptr).free_groups_overflow();
        }

        // Destroy address space.
        let aspace_id = task.aspace_id;
        if aspace_id != 0 {
            crate::mm::aspace::destroy(aspace_id);
        }

        // Restore current thread's page table (we switched to boot PT above).
        if pt_root != 0 {
            let cur_tid = smp::current().current_thread.load(Ordering::Relaxed);
            let cur_task = thread_ref(cur_tid).task_id;
            let cur_root = unsafe { (*(TASK_TABLE.get(cur_task) as *const Task)).page_table_root };
            if cur_root != 0 {
                crate::mm::hat::switch_page_table(cur_root);
            }
        }

        // Auto-reap zombie children.
        let mut zombie_ports = [0u64; 32];
        let mut nz = 0usize;
        SCHED_TASK_ART.for_each(|key, val| {
            if key == 0 {
                return;
            }
            let child = unsafe { &mut *(val as *mut Task) };
            if child.parent_task == task_id && child.exited && !child.reaped {
                child.reaped = true;
                if child.port_id != 0 && nz < 32 {
                    zombie_ports[nz] = child.port_id;
                    child.port_id = 0;
                    nz += 1;
                }
            }
        });
        for i in 0..nz {
            crate::ipc::port::destroy(zombie_ports[i]);
        }
    }
}

/// (pointing to the saved exception frame). Returns the SP to use
/// for restore_regs — either the same SP (no switch) or a different
/// thread's SP (preemption).
/// Interval between ticks in nanoseconds (10ms = 100 Hz equivalent).
const TICK_INTERVAL_NS: u64 = 10_000_000;

/// Handle a reschedule IPI (dedicated vector, no tick processing).
/// Called when a remote CPU enqueues a thread on our run queue while we
/// are idle.  Only runs try_switch() to pick up the newly-enqueued thread.
pub fn reschedule_ipi(current_sp: u64) -> u64 {
    let result = try_switch(current_sp);
    // Reprogram the timer for the (possibly new) running thread.
    let cpu = smp::cpu_id();
    let pcpu = smp::get(cpu);
    let is_idle = pcpu.current_thread.load(core::sync::atomic::Ordering::Relaxed)
        == pcpu.idle_thread_id.load(core::sync::atomic::Ordering::Relaxed);
    let next = compute_next_event(cpu, is_idle);
    crate::arch::timer::program_oneshot_ns(next);
    result
}

// =========================================================================
// PROACTIVE radix / THREAD_TABLE integrity scan (#208 / #233).
//
// The #208 wild-pointer-write corruption family overwrites a struct-pointer
// slot so that `THREAD_TABLE.get(tid)` later returns a kstack-region VA
// (0xFFFF_FE00_xxxx) or a stray SLAB VA instead of a valid Thread-struct VA
// in SLAB_THREAD_REGION (0xFFFF_FE80_xxxx).  Phys double-allocation has been
// ruled out (0/11 boots) — it is a wild CPU write through a mis-computed
// destination pointer (see project_phase5_spawn_heavy_wedge_2026_06_14).
//
// The reactive `VALIDATOR-BAD-TREF` guard in exception::validate_iretq_frame
// only fires for the faulting tid at iretq time — too late and too narrow.
// This proactive scan runs at the timer tick (frequent, cheap) and:
//   1. validates THREAD_TABLE's radix L0 page + L0[0] entry are sane
//      pointers (the L0/L1 pages live in PHYS_DIRECT_MAP, never in the
//      kstack/SLAB regions),
//   2. validates the CURRENT thread's THREAD_TABLE.get(tid) is in
//      SLAB_THREAD_REGION (catches the corrupted tid the next time it is
//      scheduled — a tight window after the scribble),
//   3. once every 256 ticks, does a bounded full scan of low tids.
// On the FIRST detected corruption it latches a one-shot AtomicBool and
// emits a single corruption-safe direct-UART block + the SET-LOG trajectory
// + the phys event ring for the bad pointer's chunk, to capture
// write-provenance context.
//
// Read-only checks + a one-shot latch: does not perturb scheduling.
// =========================================================================

/// Master gate for the proactive radix/THREAD_TABLE integrity scan.
/// Default OFF — validated false-positive-free (6 boots) but targets the rarer
/// table-entry-corruption face; the common Phase-5 face is the kstack-frame-slot
/// scribble (separate HW-WP probe). Flip true to re-arm as a regression guard.
const RADIX_INTEGRITY_SCAN: bool = false;

/// One-shot latch: the corruption is caught once with full context; we then
/// stay quiet so a meltdown cascade doesn't flood the UART (the SET-LOG /
/// evt-ring dumps after the cascade started would be noise anyway).
#[cfg(target_arch = "x86_64")]
static RADIX_INTEGRITY_FAILED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// True iff `p` is a valid Thread-struct VA (in SLAB_THREAD_REGION /
/// SLAB_REGION, PML4[509]).  A pointer here is what `THREAD_TABLE.get(tid)`
/// must return for a live thread; a kstack VA / direct-map VA / garbage
/// here is the #208 corruption signature.
#[cfg(target_arch = "x86_64")]
#[inline]
fn is_thread_struct_va(p: u64) -> bool {
    use crate::arch::x86_64::mm::{PML4_SLOT_SIZE, SLAB_REGION_BASE};
    p >= SLAB_REGION_BASE && p < SLAB_REGION_BASE.wrapping_add(PML4_SLOT_SIZE)
}

/// True iff `p` is a sane radix backing-page VA.  The radix L0 page and all
/// L1 pages are allocated via `phys::alloc_page()` and stored as
/// `phys_to_kva(pa)` (radix.rs init/ensure_l1), so a healthy L0 page / L0[0]
/// L1-page pointer lives in PHYS_DIRECT_MAP (PML4[507]).  A value in the
/// kstack/SLAB region here means L0/L0[0] itself was scribbled.
#[cfg(target_arch = "x86_64")]
#[inline]
fn is_radix_backing_va(p: u64) -> bool {
    use crate::arch::x86_64::mm::{PHYS_DIRECT_MAP_BASE, PML4_SLOT_SIZE};
    p >= PHYS_DIRECT_MAP_BASE && p < PHYS_DIRECT_MAP_BASE.wrapping_add(PML4_SLOT_SIZE)
}

/// Emit the one-shot RADIX-INTEGRITY-FAIL block + provenance dumps.  Uses
/// only the corruption-safe direct-UART `put_*` path (no fmt machinery, no
/// heap) so the dump survives even when the formatter scratch is scribbled
/// (the boot-1823 failure mode).  `got` is the bad pointer, `l0` / `l0_0`
/// are the raw radix L0 page addr + L0[0] entry, `which` is a short tag.
#[cfg(target_arch = "x86_64")]
#[cold]
fn radix_integrity_report(which: &[u8], tid: u32, got: u64, l0: u64, l0_0: u64, cpu: u32, tick: u64) {
    // One-shot: only the FIRST detection prints (latch via swap).
    if RADIX_INTEGRITY_FAILED.swap(true, Ordering::SeqCst) {
        return;
    }
    use crate::arch::x86_64::serial::{handler_write_bytes, put_bytes, put_dec_u64, put_hex_u64};
    let mut buf = [0u8; 256];
    let mut k = 0;
    put_bytes(&mut buf, &mut k, b"RADIX-INTEGRITY-FAIL: which=");
    put_bytes(&mut buf, &mut k, which);
    put_bytes(&mut buf, &mut k, b" tid=");
    put_dec_u64(&mut buf, &mut k, tid as u64);
    put_bytes(&mut buf, &mut k, b" got=");
    put_hex_u64(&mut buf, &mut k, got);
    put_bytes(&mut buf, &mut k, b" expected=SLAB_REGION[");
    put_hex_u64(&mut buf, &mut k, crate::arch::x86_64::mm::SLAB_REGION_BASE);
    put_bytes(&mut buf, &mut k, b"..");
    put_hex_u64(
        &mut buf,
        &mut k,
        crate::arch::x86_64::mm::SLAB_REGION_BASE
            .wrapping_add(crate::arch::x86_64::mm::PML4_SLOT_SIZE),
    );
    put_bytes(&mut buf, &mut k, b") L0=");
    put_hex_u64(&mut buf, &mut k, l0);
    put_bytes(&mut buf, &mut k, b" L0[0]=");
    put_hex_u64(&mut buf, &mut k, l0_0);
    put_bytes(&mut buf, &mut k, b" cpu=");
    put_dec_u64(&mut buf, &mut k, cpu as u64);
    put_bytes(&mut buf, &mut k, b" tick=");
    put_dec_u64(&mut buf, &mut k, tick);
    put_bytes(&mut buf, &mut k, b"\n");
    handler_write_bytes(&buf[..k.min(buf.len())]);

    // Write-provenance context: SET-LOG trajectory for this tid (last
    // legitimate set + recent op history) — same dumper VALIDATOR-BAD-TREF
    // uses, also direct-UART.
    crate::sched::radix::dump_set_log_for_tid(tid);

    // Phys event ring for the bad pointer's chunk: if `got` is a
    // PHYS_DIRECT_MAP VA we can recover its PA and dump the alloc/free
    // history of that chunk.  (kstack/SLAB VAs aren't direct-map PAs, so
    // only attempt this when `got` is in the direct map.)
    if is_radix_backing_va(got) {
        let pa = (got - crate::arch::x86_64::mm::PHYS_DIRECT_MAP_BASE) as usize;
        let chunk_size = 64 * crate::mm::page::page_size();
        crate::mm::phys::dump_evt_ring_for_chunk(pa / chunk_size);
    }
}

/// Proactive integrity scan — called from `tick()` on every CPU.  Cheap:
/// 2 atomic loads for the L0 check + 1 radix get for the current thread,
/// plus a bounded full scan once every 256 ticks.  All read-only; reports
/// the first corruption once via `radix_integrity_report`.
#[cfg(target_arch = "x86_64")]
#[inline]
fn radix_integrity_scan(cpu: u32, tick_count: u64) {
    if !RADIX_INTEGRITY_SCAN {
        return;
    }
    // Fast exit once we've already caught + reported the first event.
    if RADIX_INTEGRITY_FAILED.load(Ordering::Relaxed) {
        return;
    }

    // (1) Radix L0 page + L0[0] entry sanity.  raw_l0_slots() returns
    // (l0_page_addr, L0[0], *(L0[0]+0x20)) all via volatile reads.
    let (l0, l0_0, _l1_4) = THREAD_TABLE.raw_l0_slots();
    // L0 page must be a non-null radix backing VA (direct map).  Before
    // init() runs l0 is 0 — treat null as "not yet initialized", not a
    // corruption (the scan only fires once threads exist anyway).
    if l0 != 0 && !is_radix_backing_va(l0) {
        radix_integrity_report(b"L0-page", 0, l0, l0, l0_0, cpu, tick_count);
        return;
    }
    // L0[0] holds the L1-page pointer for tids 0..fanout-1 — it must point
    // into the radix backing region.  Null means the L1 page for the first
    // fanout block hasn't been allocated yet (legitimate very early), so
    // only flag a NON-null L0[0] that's out of the backing region.
    if l0 != 0 && l0_0 != 0 && !is_radix_backing_va(l0_0) {
        radix_integrity_report(b"L0[0]", 0, l0_0, l0, l0_0, cpu, tick_count);
        return;
    }

    // (2) Current thread's THREAD_TABLE.get(tid) must be a valid Thread*.
    // Skip idle tids (< ncpus): their Thread structs come from the boot
    // stack region and predate SLAB_THREAD (mirrors thread_ref's policy).
    // Skip null (tid not yet wired into the table).
    let ncpus = smp::num_cpus() as u32;
    let cur = smp::current().current_thread.load(Ordering::Relaxed);
    if cur >= ncpus {
        let p = THREAD_TABLE.get(cur) as u64;
        if p != 0 && !is_thread_struct_va(p) {
            radix_integrity_report(b"current", cur, p, l0, l0_0, cpu, tick_count);
            return;
        }
    }

    // (3) Bounded full scan once every 256 ticks (BSP only to avoid N-CPU
    // duplication): check live low tids' Thread* land in SLAB_REGION.
    // Cheap — 256 radix gets — and catches a corrupted tid even when it
    // isn't the one currently running on any CPU.
    if cpu == 0 && (tick_count & 0xff) == 0 {
        for tid in ncpus..256u32 {
            let p = THREAD_TABLE.get(tid) as u64;
            if p != 0 && !is_thread_struct_va(p) {
                radix_integrity_report(b"fullscan", tid, p, l0, l0_0, cpu, tick_count);
                return;
            }
        }
    }
}

pub fn tick(current_sp: u64) -> u64 {
    // Record per-CPU last-tick timestamp + update max-gap.  Diagnostic
    // for wake-latency tail: if a CPU's tick stops firing for seconds,
    // we'd see PER_CPU_TICK_MAX_GAP_NS blow up to match.  Healthy ticks
    // produce gaps near TICK_INTERVAL_NS.
    {
        let cpu = smp::cpu_id() as usize;
        if cpu < smp::MAX_CPUS {
            let now = get_monotonic_ns();
            let prev = PER_CPU_LAST_TICK_NS[cpu].swap(now, Ordering::Relaxed);
            // Companion vcpu_runtime stamp for paravirt-aware heuristics
            // (see PER_CPU_LAST_TICK_VCPU_NS docstring).  Updated in lockstep
            // with the wallclock stamp above so any reader can correlate.
            PER_CPU_LAST_TICK_VCPU_NS[cpu].store(
                crate::arch::timer::vcpu_runtime_ns(),
                Ordering::Relaxed,
            );
            if prev != 0 {
                let gap = now.saturating_sub(prev);
                let mut max = PER_CPU_TICK_MAX_GAP_NS.load(Ordering::Relaxed);
                while gap > max {
                    match PER_CPU_TICK_MAX_GAP_NS.compare_exchange_weak(
                        max, gap, Ordering::Relaxed, Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(seen) => max = seen,
                    }
                }
                // #135 host vCPU desched probe: log when this CPU's tick
                // gap exceeds 500ms.  Rate-limited per-CPU to 30 events to
                // avoid flooding when host load is consistently high.
                if gap > 500_000_000 {
                    static TICK_GAP_LOG_COUNT: [core::sync::atomic::AtomicU32; 4] = [
                        core::sync::atomic::AtomicU32::new(0),
                        core::sync::atomic::AtomicU32::new(0),
                        core::sync::atomic::AtomicU32::new(0),
                        core::sync::atomic::AtomicU32::new(0),
                    ];
                    let slot = cpu.min(3);
                    let n = TICK_GAP_LOG_COUNT[slot]
                        .fetch_add(1, Ordering::Relaxed);
                    if n < 30 {
                        #[cfg(target_arch = "x86_64")]
                        {
                            use crate::arch::x86_64::serial::{put_byte, put_bytes, put_dec_u64};
                            let mut buf = [0u8; 128];
                            let mut k = 0;
                            put_bytes(&mut buf, &mut k, b"TICK-GAP: cpu=");
                            put_dec_u64(&mut buf, &mut k, cpu as u64);
                            put_bytes(&mut buf, &mut k, b" gap_ms=");
                            put_dec_u64(&mut buf, &mut k, gap / 1_000_000);
                            put_bytes(&mut buf, &mut k, b" (n=");
                            put_dec_u64(&mut buf, &mut k, (n + 1) as u64);
                            put_bytes(&mut buf, &mut k, b") -- host vCPU likely descheduled\n");
                            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                        }
                        #[cfg(not(target_arch = "x86_64"))]
                        crate::println!(
                            "TICK-GAP: cpu={} gap_ms={} (n={}) — host vCPU likely descheduled",
                            cpu, gap / 1_000_000, n + 1,
                        );
                    }
                }
            }
        }
    }

    // #208 / #233 proactive radix / THREAD_TABLE integrity scan.  Runs on
    // every tick on every CPU; one-shot latched + read-only (see
    // radix_integrity_scan).  Per-CPU tick counter drives the periodic
    // full-scan cadence without contending a shared counter.
    #[cfg(target_arch = "x86_64")]
    {
        static SCAN_TICKS: [core::sync::atomic::AtomicU64; smp::MAX_CPUS] =
            [const { core::sync::atomic::AtomicU64::new(0) }; smp::MAX_CPUS];
        let cpu = smp::cpu_id();
        if (cpu as usize) < smp::MAX_CPUS {
            let n = SCAN_TICKS[cpu as usize].fetch_add(1, Ordering::Relaxed);
            radix_integrity_scan(cpu, n);
        }
    }

    check_sleep_timers();
    check_alarm_timers();
    check_interval_timers();

    // #155 reconciliation probe — BSP only, internally rate-limited
    // to one sample per 1024 ticks.  Logs when free_count_global drifts
    // away from sum-of-per-chunk-fc (or back to consistent).
    if smp::cpu_id() == 0 {
        crate::mm::phys::verify_global_counter();
    }

    // Drain deferred killed-thread cleanup from the previous tick.
    drain_deferred_kills();

    // IPC watchdog: on CPU 0, check for stalled IPC every ~5 seconds.
    // If no IPC send/recv has occurred since the last check, dump blocked
    // thread states to help diagnose flaky hangs.
    {
        use core::sync::atomic::AtomicU64;
        static WATCHDOG_TICK: AtomicU64 = AtomicU64::new(0);
        static LAST_IPC_COUNT: AtomicU64 = AtomicU64::new(0);
        static STALL_COUNT: AtomicU64 = AtomicU64::new(0);
        let cpu = smp::cpu_id();
        if cpu == 0 {
            let n = WATCHDOG_TICK.fetch_add(1, Ordering::Relaxed);
            // #135 periodic CLI residency dump (every 1s ≈ 100 ticks) to
            // catch large CLI regions BEFORE the first RESCUE-STUCK-PENDING
            // contaminates the readings with rescue-path print storms.
            // Only logs when cli_max changes on any CPU (monotonic max), so
            // the log doesn't repeat constant values.
            static CLI_MAX_SEEN: [core::sync::atomic::AtomicU64; 4] = [
                core::sync::atomic::AtomicU64::new(0),
                core::sync::atomic::AtomicU64::new(0),
                core::sync::atomic::AtomicU64::new(0),
                core::sync::atomic::AtomicU64::new(0),
            ];
            if n > 0 && n % 100 == 0 {
                let mut changed = false;
                for c in 0..4u32.min(smp::num_cpus() as u32) {
                    let pc = smp::get(c);
                    let cur_max = pc.cli_max_cycles.load(Ordering::Relaxed);
                    let prev = CLI_MAX_SEEN[c as usize].load(Ordering::Relaxed);
                    if cur_max > prev {
                        CLI_MAX_SEEN[c as usize].store(cur_max, Ordering::Relaxed);
                        changed = true;
                    }
                }
                if changed {
                    for c in 0..4u32.min(smp::num_cpus() as u32) {
                        let pc = smp::get(c);
                        let max = pc.cli_max_cycles.load(Ordering::Relaxed);
                        let tot = pc.cli_total_cycles.load(Ordering::Relaxed);
                        let cnt = pc.cli_count.load(Ordering::Relaxed);
                        #[cfg(target_arch = "x86_64")]
                        {
                            use crate::arch::x86_64::serial::{put_byte, put_bytes, put_dec_u64};
                            let mut buf = [0u8; 128];
                            let mut k = 0;
                            put_bytes(&mut buf, &mut k, b"CLI-MAX-TICK: cpu=");
                            put_dec_u64(&mut buf, &mut k, c as u64);
                            put_bytes(&mut buf, &mut k, b" tick=");
                            put_dec_u64(&mut buf, &mut k, n);
                            put_bytes(&mut buf, &mut k, b" max=");
                            put_dec_u64(&mut buf, &mut k, max);
                            put_bytes(&mut buf, &mut k, b" total=");
                            put_dec_u64(&mut buf, &mut k, tot);
                            put_bytes(&mut buf, &mut k, b" count=");
                            put_dec_u64(&mut buf, &mut k, cnt);
                            put_byte(&mut buf, &mut k, b'\n');
                            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                        }
                        #[cfg(not(target_arch = "x86_64"))]
                        crate::println!(
                            "CLI-MAX-TICK: cpu={} tick={} max={} total={} count={}",
                            c, n, max, tot, cnt,
                        );
                        // #135 cli_max-per-callsite: also dump the top-N
                        // CLI offenders for this CPU when cli_max changed.
                        // Triggered on the same monotonic-growth gate as
                        // CLI-MAX-TICK so the log doesn't repeat steady-state
                        // entries.  N=8 selection sort = 64 cmps, fine.
                        let mut idx: [usize; smp::CLI_TOP_N] = [0usize; smp::CLI_TOP_N];
                        for i in 0..smp::CLI_TOP_N { idx[i] = i; }
                        let cyc: [u64; smp::CLI_TOP_N] = {
                            let mut a = [0u64; smp::CLI_TOP_N];
                            for i in 0..smp::CLI_TOP_N {
                                a[i] = pc.cli_top[i].cycles.load(Ordering::Relaxed);
                            }
                            a
                        };
                        for i in 0..smp::CLI_TOP_N {
                            for j in (i + 1)..smp::CLI_TOP_N {
                                if cyc[idx[j]] > cyc[idx[i]] {
                                    idx.swap(i, j);
                                }
                            }
                        }
                        let mut printed = 0usize;
                        for &i in idx.iter() {
                            let r = pc.cli_top[i].rip.load(Ordering::Relaxed);
                            let cy = pc.cli_top[i].cycles.load(Ordering::Relaxed);
                            let ct = pc.cli_top[i].count.load(Ordering::Relaxed);
                            if r == 0 || cy == 0 { continue; }
                            #[cfg(target_arch = "x86_64")]
                            {
                                use crate::arch::x86_64::serial::{put_byte, put_bytes, put_hex_u64, put_dec_u64};
                                let mut buf = [0u8; 160];
                                let mut k = 0;
                                put_bytes(&mut buf, &mut k, b"CLI-TOP-TICK: cpu=");
                                put_dec_u64(&mut buf, &mut k, c as u64);
                                put_bytes(&mut buf, &mut k, b" tick=");
                                put_dec_u64(&mut buf, &mut k, n);
                                put_bytes(&mut buf, &mut k, b" slot=");
                                put_dec_u64(&mut buf, &mut k, printed as u64);
                                put_bytes(&mut buf, &mut k, b" rip=");
                                put_hex_u64(&mut buf, &mut k, r);
                                put_bytes(&mut buf, &mut k, b" max=");
                                put_dec_u64(&mut buf, &mut k, cy);
                                put_bytes(&mut buf, &mut k, b" count=");
                                put_dec_u64(&mut buf, &mut k, ct);
                                put_byte(&mut buf, &mut k, b'\n');
                                crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                            }
                            #[cfg(not(target_arch = "x86_64"))]
                            crate::println!(
                                "CLI-TOP-TICK: cpu={} tick={} slot={} rip=0x{:x} max={} count={}",
                                c, n, printed, r, cy, ct,
                            );
                            printed += 1;
                        }
                    }
                }
            }
            // #208 periodic FRAME-DELTA sweep — walks all Blocked threads
            // every ~1s and verifies their iretq_shadow_frame against the
            // current contents at saved_sp.  Catches corruption that lands
            // between two park-resume cycles (the at-dispatch check only
            // sees the SAME park cycle's write; a peer write that's later
            // overwritten by a subsequent legitimate park would be invisible
            // at dispatch).
            if n > 0 && n % 100 == 0 {
                static SWEEP_SCAN_LOG: core::sync::atomic::AtomicU32 =
                    core::sync::atomic::AtomicU32::new(0);
                let max_tid = NEXT_THREAD_ID.load(Ordering::Relaxed).min(256);
                let mut checked = 0u32;
                for tid in 1..max_tid {
                    let t = unsafe { &*(THREAD_TABLE.get(tid) as *const Thread) };
                    if t.task_id == 0 {
                        continue;
                    }
                    // #230 SPB periodic check: cheap canonical comparison
                    // for early tids (<100) on every sweep — catches
                    // Thread-slab corruption between create and exit, not
                    // just at drain/kill/exit code paths.
                    if (tid as usize) < SPB_CANONICAL_MAX {
                        spb_check(tid, t.stack_phys_base as u64, "periodic_sweep");
                    }
                    // #230 kstack canary sweep: detect mid-flight stack
                    // overflow / scribble of low-end sentinel.  Skips
                    // in_kstack_region tids automatically (cross-CR3
                    // visibility — see check_stack_canary impl).
                    let _ = check_stack_canary(tid, "periodic_sweep");
                    // #230 stack-overflow near-miss probe: detect tids
                    // whose saved_sp is within 4 KiB of the low end of
                    // the kstack — about to overwrite the canary on the
                    // next push.  Fires BEFORE corruption; canary fires
                    // AFTER.  Combined catches both windows.
                    if (tid as usize) < SPB_CANONICAL_MAX && t.stack_base != 0 {
                        let sp = t.iretq_shadow_sp;
                        let sb = t.stack_base as u64;
                        let kstack_lim = sb + kstack_size() as u64;
                        if sp >= sb && sp <= kstack_lim
                            && (sp - sb) < 0x1000
                        {
                            static HWM_LOG: core::sync::atomic::AtomicU32 =
                                core::sync::atomic::AtomicU32::new(0);
                            let n = HWM_LOG.fetch_add(1, Ordering::Relaxed);
                            if n < 8 {
                                crate::println!(
                                    "STACK-HWM-NEAR: tid={} sp={:#x} stack_base={:#x} \
                                     remaining={} n={}",
                                    tid, sp, sb, sp - sb, n,
                                );
                            }
                        }
                    }
                    let sp = t.iretq_shadow_sp;
                    if sp == 0 {
                        continue;
                    }
                    // Blocked threads are always safe to check (parked at
                    // saved_sp, no legitimate writer).
                    let is_blocked = t.state == ThreadState::Blocked;
                    // Ready threads with KERNEL-CS shadow are typically
                    // freshly-created (init_kernel_frame set CS=0x8) and
                    // haven't been dispatched yet — also safe.  Ready with
                    // user-CS shadow means a previously-dispatched user
                    // thread that re-Ready'd via wake_thread; its iretq
                    // frame may legitimately have advanced (boot 1753 noise).
                    let is_fresh_ready = t.state == ThreadState::Ready
                        && t.iretq_shadow_cs == 0x08;
                    if !is_blocked && !is_fresh_ready {
                        continue;
                    }
                    check_iretq_shadow_at_dispatch(tid, sp);
                    check_park_stack_ext(tid, sp);
                    checked += 1;
                }
                // #230 TSS.RSP0 cross-CPU audit: for each online CPU,
                // verify its TSS.RSP0 falls within the current_thread's
                // kstack range.  If the TSS points to a DIFFERENT
                // thread's kstack (peer's, or a freed one), that's the
                // smoking gun for the #229 RSP0 cross-confusion hypothesis.
                #[cfg(target_arch = "x86_64")]
                {
                    let ncpu = smp::online_cpus();
                    for cpu in 0..ncpu {
                        let pcpu = smp::get(cpu);
                        // #232 Acquire pairs with set_current_thread's
                        // Release store: if we read NEW tid here, we're
                        // guaranteed to also see the corresponding TSS
                        // write that happened before the Release.
                        let cur_tid = pcpu.current_thread.load(Ordering::Acquire);
                        if cur_tid == 0 || (cur_tid as usize) >= max_tid as usize {
                            continue;
                        }
                        let t = unsafe { &*(THREAD_TABLE.get(cur_tid) as *const Thread) };
                        if t.stack_base == 0 {
                            continue;
                        }
                        // Read tss_for(cpu).rsp0 via gdt helper that takes
                        // an explicit CPU index, not just the current
                        // CPU's TSS (we're sweeping every CPU's TSS).
                        let actual = crate::arch::x86_64::gdt::tss_rsp0_for(cpu as usize);
                        let sb = t.stack_base as u64;
                        let st = sb + kstack_size() as u64;
                        if actual < sb || actual > st {
                            static MISMATCH_LOG: core::sync::atomic::AtomicU32 =
                                core::sync::atomic::AtomicU32::new(0);
                            let m = MISMATCH_LOG.fetch_add(1, Ordering::Relaxed);
                            if m < 8 {
                                crate::println!(
                                    "TSS-RSP0-AUDIT: cpu={} cur_tid={} tss_rsp0={:#x} \
                                     expected_kstack=[{:#x}..{:#x}) n={}",
                                    cpu, cur_tid, actual, sb, st, m,
                                );
                            }
                        }
                    }
                }
                let nlog = SWEEP_SCAN_LOG.fetch_add(1, Ordering::Relaxed);
                if nlog < 3 || nlog % 10 == 0 {
                    #[cfg(target_arch = "x86_64")]
                    {
                        use crate::arch::x86_64::serial::{put_byte, put_bytes, put_dec_u64};
                        let mut buf = [0u8; 96];
                        let mut k = 0;
                        put_bytes(&mut buf, &mut k, b"PERIODIC-SHADOW-SWEEP: tick=");
                        put_dec_u64(&mut buf, &mut k, n);
                        put_bytes(&mut buf, &mut k, b" checked=");
                        put_dec_u64(&mut buf, &mut k, checked as u64);
                        put_bytes(&mut buf, &mut k, b" max_tid=");
                        put_dec_u64(&mut buf, &mut k, max_tid as u64);
                        put_byte(&mut buf, &mut k, b'\n');
                        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                    }
                    #[cfg(not(target_arch = "x86_64"))]
                    crate::println!(
                        "PERIODIC-SHADOW-SWEEP: tick={} checked={} max_tid={}",
                        n, checked, max_tid,
                    );
                }
            }
            // Check roughly every 5 seconds (tick ≈ 10ms → 500 ticks).
            if n > 0 && n % 500 == 0 {
                let sends = crate::sched::stats::IPC_SENDS.load(Ordering::Relaxed);
                let recvs = crate::sched::stats::IPC_RECVS.load(Ordering::Relaxed);
                let total = sends.wrapping_add(recvs);
                let last = LAST_IPC_COUNT.swap(total, Ordering::Relaxed);
                if total == last {
                    let sc = STALL_COUNT.fetch_add(1, Ordering::Relaxed);
                    if sc < 3 {
                        // First stall detection — dump per-CPU and thread states.
                        // Per-arch IPI counters for validating the tickless-SMP
                        // IPI fix at a glance.  Both aarch64 SGIs and riscv64
                        // S-mode software IRQs share this column.
                        #[cfg(target_arch = "aarch64")]
                        let (sgi_s, sgi_r) = (
                            crate::arch::aarch64::irq::SGI_SEND_COUNT
                                .load(Ordering::Relaxed),
                            crate::arch::aarch64::irq::SGI_RECV_COUNT
                                .load(Ordering::Relaxed),
                        );
                        #[cfg(target_arch = "riscv64")]
                        let (sgi_s, sgi_r) = (
                            crate::arch::riscv64::trap::SGI_SEND_COUNT
                                .load(Ordering::Relaxed),
                            crate::arch::riscv64::trap::SGI_RECV_COUNT
                                .load(Ordering::Relaxed),
                        );
                        #[cfg(target_arch = "loongarch64")]
                        let (sgi_s, sgi_r) = (
                            crate::arch::loongarch64::trap::SGI_SEND_COUNT
                                .load(Ordering::Relaxed),
                            crate::arch::loongarch64::trap::SGI_RECV_COUNT
                                .load(Ordering::Relaxed),
                        );
                        #[cfg(target_arch = "x86_64")]
                        let (sgi_s, sgi_r) = (
                            crate::arch::x86_64::lapic::IPI_SEND_COUNT
                                .load(Ordering::Relaxed),
                            crate::arch::x86_64::lapic::IPI_RECV_COUNT
                                .load(Ordering::Relaxed),
                        );
                        #[cfg(not(any(
                            target_arch = "x86_64",
                            target_arch = "aarch64",
                            target_arch = "riscv64",
                            target_arch = "loongarch64",
                        )))]
                        let (sgi_s, sgi_r): (u64, u64) = (0, 0);
                        let wake_count = SLEEP_WAKE_LATENCY_COUNT.load(Ordering::Relaxed);
                        let wake_total = SLEEP_WAKE_LATENCY_NS_TOTAL.load(Ordering::Relaxed);
                        let wake_max = SLEEP_WAKE_LATENCY_NS_MAX.load(Ordering::Relaxed);
                        let wake_avg_us = if wake_count > 0 {
                            (wake_total / 1000) / wake_count
                        } else {
                            0
                        };
                        let wake_max_us = wake_max / 1000;
                        let b0 = SLEEP_WAKE_LATENCY_BUCKETS[0].load(Ordering::Relaxed);
                        let b1 = SLEEP_WAKE_LATENCY_BUCKETS[1].load(Ordering::Relaxed);
                        let b2 = SLEEP_WAKE_LATENCY_BUCKETS[2].load(Ordering::Relaxed);
                        let b3 = SLEEP_WAKE_LATENCY_BUCKETS[3].load(Ordering::Relaxed);
                        let b4 = SLEEP_WAKE_LATENCY_BUCKETS[4].load(Ordering::Relaxed);
                        let b5 = SLEEP_WAKE_LATENCY_BUCKETS[5].load(Ordering::Relaxed);
                        let b6 = SLEEP_WAKE_LATENCY_BUCKETS[6].load(Ordering::Relaxed);
                        let tick_max_gap_us = PER_CPU_TICK_MAX_GAP_NS.load(Ordering::Relaxed) / 1000;
                        let stale_retarget = STALE_TARGET_RETARGET_COUNT.load(Ordering::Relaxed);
                        let steal_us = crate::arch::hypervisor::ops()
                            .steal_time_ns()
                            .map(|ns| ns / 1000)
                            .unwrap_or(u64::MAX);
                        crate::println!("WATCHDOG: IPC stall detected (sends={} recvs={}) double_enq: drain={} rescue={} wake={} other={} total_enq={} rescue=(max={} stale={} pend={} phantom={} fast_takeover={} cas_fail_bail={} wake_reroute={}) sgi=(s={} r={}) forced_preempt={} wake_lat=(n={} avg_us={} max_us={}) wake_hist=(<100us:{} <1ms:{} <10ms:{} <100ms:{} <1s:{} <10s:{} >=10s:{}) tick_max_gap_us={} stale_retarget={} bsp_steal_us={} hv={:?}",
                            sends, recvs,
                            DOUBLE_ENQ_DRAIN.load(Ordering::Relaxed),
                            DOUBLE_ENQ_RESCUE.load(Ordering::Relaxed),
                            DOUBLE_ENQ_WAKE.load(Ordering::Relaxed),
                            DOUBLE_ENQ_OTHER.load(Ordering::Relaxed),
                            ENQ_TOTAL.load(Ordering::Relaxed),
                            RESCUE_MAX.load(Ordering::Relaxed),
                            RESCUE_STALE_ON_CPU.load(Ordering::Relaxed),
                            RESCUE_PENDING.load(Ordering::Relaxed),
                            RESCUE_PHANTOM.load(Ordering::Relaxed),
                            FAST_RESCUE_TAKEOVERS.load(Ordering::Relaxed),
                            CAS_FAIL_RESCUE_BAILS.load(Ordering::Relaxed),
                            STEAL_AWARE_REROUTES.load(Ordering::Relaxed),
                            sgi_s, sgi_r,
                            FORCED_PREEMPT_COUNT.load(Ordering::Relaxed),
                            wake_count, wake_avg_us, wake_max_us,
                            b0, b1, b2, b3, b4, b5, b6,
                            tick_max_gap_us, stale_retarget,
                            steal_us, crate::arch::hypervisor::kind());
                        // #173 Phase 5: gate-split rescue fires + claim-helper
                        // counters.  Tracked across stress boots to decide
                        // whether the new dispatch helper is closing real
                        // bug-class fires.  GATE_ON ≪ GATE_OFF under matched
                        // stress → helper does measurable work.
                        crate::println!(
                            "DISPATCH-DIAG: gate={} stuck_gate_on={} stuck_gate_off={} claim_fail={} claim_self_pick={}",
                            if DISPATCH_USE_CLAIM_HELPER.load(Ordering::Relaxed) { "ON" } else { "OFF" },
                            RESCUE_STUCK_PENDING_FIRES_GATE_ON.load(Ordering::Relaxed),
                            RESCUE_STUCK_PENDING_FIRES_GATE_OFF.load(Ordering::Relaxed),
                            DISPATCH_CLAIM_FAIL.load(Ordering::Relaxed),
                            DISPATCH_CLAIM_SELF_PICK.load(Ordering::Relaxed),
                        );
                        // Per-CPU state: what each CPU is running, RQ sizes
                        let ncpus = smp::num_cpus();
                        for c in 0..ncpus {
                            let pc = smp::get(c as u32);
                            let cur = pc.current_thread.load(Ordering::Relaxed);
                            let idle = pc.idle_thread_id.load(Ordering::Relaxed);
                            let rq = percpu_rq()[c].lock();
                            let rq_len = rq.eevdf_nr_running;
                            let has_rdy = rq.has_ready();
                            drop(rq);
                            let is_idle = cur == idle;
                            let def_v = deferred_requeue()[c].load(Ordering::Relaxed);
                            let def_tid = if def_v != 0 { (def_v & 0xFFFFFFFF) as u32 } else { 0 };
                            let cur_task = thread_ref(cur as u32).task_id;
                            let cur_blk = unsafe { &*(THREAD_TABLE.get(cur as u32) as *const Thread) }.blocked_on;
                            let rescue_stuck = pc.rescue_stuck_pending_count.load(Ordering::Relaxed);
                            let hist = lat_snapshot(pc);
                            let n: u64 = hist.iter().sum();
                            let p50 = lat_percentile_ns(&hist, 5000);
                            let p90 = lat_percentile_ns(&hist, 9000);
                            let p99 = lat_percentile_ns(&hist, 9900);
                            let p999 = lat_percentile_ns(&hist, 9990);
                            crate::println!("  cpu{}: cur=tid{} task={} idle={} rq_eevdf={} has_ready={} def={} blk={:?} rescue_stuck={} lat_ns(n={} p50={} p90={} p99={} p999={})",
                                c, cur, cur_task, is_idle, rq_len, has_rdy, def_tid, cur_blk, rescue_stuck,
                                n, p50, p90, p99, p999);
                        }
                        let max_tid = NEXT_THREAD_ID.load(Ordering::Relaxed).min(200);
                        for tid in 1..max_tid {
                            let t = unsafe { &*(THREAD_TABLE.get(tid) as *const Thread) };
                            if t.task_id != 0 && t.state != ThreadState::Dead {
                                let park = t.park_state.load(Ordering::Relaxed);
                                let wakeup = t.wakeup.load(Ordering::Relaxed);
                                let on_cpu = t.on_cpu.load(Ordering::Relaxed);
                                let in_q = t.in_queue.load(Ordering::Relaxed);
                                let last_cpu = t.last_cpu.load(Ordering::Relaxed);
                                let prio = t.prio.load(Ordering::Relaxed);
                                // Show on_cpu/in_q for all non-Running threads so
                                // stale-on-cpu orphans are visible in the dump.
                                if t.state == ThreadState::Running {
                                    continue;
                                }
                                crate::println!(
                                    "  tid={} {:?} {:?} park={} wake={} prio={} on_cpu={} in_q={} last_cpu={} task={}",
                                    tid, t.state, t.blocked_on, park, wakeup, prio, on_cpu, in_q, last_cpu, t.task_id);
                            }
                        }
                        // Top-N rescued tids: which tids dominate the rescue
                        // storm?  When pend / stale_on_cpu / max counts are
                        // huge but spread across many tids, the bug is
                        // structural; when they pile on a single tid, the
                        // bug is in that tid's wakeup path.  Print the top
                        // 5 by rescue count.
                        let mut top_idx = [0usize; 5];
                        let mut top_cnt = [0u64; 5];
                        for i in 1..PER_TID_RESCUE_CAP {
                            let c = RESCUE_PER_TID[i].load(Ordering::Relaxed);
                            if c == 0 { continue; }
                            // Insert into descending top-5.
                            let mut j = 5;
                            while j > 0 && c > top_cnt[j - 1] { j -= 1; }
                            if j < 5 {
                                let mut k = 4;
                                while k > j { top_cnt[k] = top_cnt[k - 1]; top_idx[k] = top_idx[k - 1]; k -= 1; }
                                top_cnt[j] = c;
                                top_idx[j] = i;
                            }
                        }
                        if top_cnt[0] > 0 {
                            crate::println!(
                                "  rescue top: tid{}={} tid{}={} tid{}={} tid{}={} tid{}={}",
                                top_idx[0], top_cnt[0],
                                top_idx[1], top_cnt[1],
                                top_idx[2], top_cnt[2],
                                top_idx[3], top_cnt[3],
                                top_idx[4], top_cnt[4]);
                        }

                        // Phase-5b stall instrumentation (aarch64-only).
                        #[cfg(target_arch = "aarch64")]
                        {
                            let now = get_monotonic_ns();
                            let ncpus_a = smp::num_cpus().min(16);
                            for c in 0..ncpus_a {
                                let send_ts = crate::arch::aarch64::irq::PER_CPU_IPI_SEND_TS_NS[c]
                                    .load(Ordering::Relaxed);
                                let recv_ts = crate::arch::aarch64::irq::PER_CPU_IPI_RECV_TS_NS[c]
                                    .load(Ordering::Relaxed);
                                let send_n  = crate::arch::aarch64::irq::PER_CPU_IPI_SEND_COUNT[c]
                                    .load(Ordering::Relaxed);
                                let recv_n  = crate::arch::aarch64::irq::PER_CPU_IPI_RECV_COUNT[c]
                                    .load(Ordering::Relaxed);
                                let ex_n    = crate::arch::aarch64::irq::PER_CPU_EXCEPTION_ENTRY_COUNT[c]
                                    .load(Ordering::Relaxed);
                                let cps_n   = crate::arch::aarch64::irq::PER_CPU_CLEAR_SWITCH_COUNT[c]
                                    .load(Ordering::Relaxed);
                                let send_age_us = if send_ts != 0 { (now.saturating_sub(send_ts)) / 1000 } else { 0 };
                                let recv_age_us = if recv_ts != 0 { (now.saturating_sub(recv_ts)) / 1000 } else { 0 };
                                let lat_us = if recv_ts >= send_ts && send_ts != 0 {
                                    (recv_ts - send_ts) / 1000
                                } else {
                                    u64::MAX
                                };
                                crate::println!(
                                    "  AA64-IPI cpu{}: send=(n={} age_us={}) recv=(n={} age_us={}) lat_us={} ex_n={} cps_n={} pkpend={} parked_tid={}",
                                    c, send_n, send_age_us, recv_n, recv_age_us, lat_us,
                                    ex_n, cps_n,
                                    park_switch_pending()[c].load(Ordering::Relaxed),
                                    parked_tid()[c].load(Ordering::Relaxed),
                                );
                            }
                            // Recent wake_parked_thread outcomes (top-N slots
                            // with non-zero tid).  Path codes:
                            // 1=early, 2=fast-enq, 3=lost-cps, 4=def-local,
                            // 5=def-ipi, 6=dup, 7=neither-cas-noop.
                            let mut printed = 0u32;
                            for i in 0..WAKE_TRACE_RING {
                                let t = WAKE_TRACE_TID[i].load(Ordering::Relaxed);
                                if t == 0 { continue; }
                                let v = WAKE_TRACE_OUTCOME[i].load(Ordering::Relaxed);
                                let ts = WAKE_TRACE_TS_NS[i].load(Ordering::Relaxed);
                                let path = v & 0xF;
                                let waker_cpu = (v >> 4) & 0xF;
                                let park_cpu = (v >> 8) & 0xFF;
                                let age_us = if ts != 0 { now.saturating_sub(ts) / 1000 } else { 0 };
                                crate::println!(
                                    "  AA64-WAKE tid={} path={} waker_cpu={} park_cpu={} age_us={}",
                                    t, path, waker_cpu, park_cpu, age_us
                                );
                                printed += 1;
                                if printed >= 16 { break; }
                            }
                            // Per-thread stack_switch_pending for blocked threads.
                            let max_tid = NEXT_THREAD_ID.load(Ordering::Relaxed).min(64);
                            for tid in 1..max_tid {
                                let t = unsafe { &*(THREAD_TABLE.get(tid) as *const Thread) };
                                if t.task_id == 0 || t.state == ThreadState::Dead { continue; }
                                let park = t.park_state.load(Ordering::Relaxed);
                                let ssp = t.stack_switch_pending.load(Ordering::Relaxed);
                                if park != 0 || ssp {
                                    crate::println!(
                                        "  AA64-PARK tid={} park_state={} stack_switch_pending={} state={:?} blocked_on={:?} on_cpu={} last_cpu={}",
                                        tid, park, ssp, t.state, t.blocked_on,
                                        t.on_cpu.load(Ordering::Relaxed),
                                        t.last_cpu.load(Ordering::Relaxed),
                                    );
                                }
                            }
                        }
                    }
                    // On every stall tick, attempt to rescue orphaned threads.
                    // TOCTOU false positives are harmless: DOUBLE-ENQ handler
                    // detects and skips redundant enqueues.
                    // Also rescue CallReply-blocked threads (rescue_parked=true)
                    // since IPC is confirmed stalled.
                    // IPC is confirmed stalled for 5+ seconds — force-drain
                    // ALL remote deferred slots.  The assembly switch window
                    // is <1µs; 5s of confirmed stall means it completed eons
                    // ago.  Also send IPIs to kick timer-dead CPUs.
                    {
                        let ncpus_w = smp::num_cpus();
                        for cw in 0..ncpus_w.min(16) {
                            drain_deferred_requeue(cw as u32);
                            if cw as u32 != cpu {
                                crate::arch::irq::send_reschedule_ipi(cw as u32);
                            }
                        }
                    }
                    rescue_orphaned_threads_impl(true);
                } else {
                    STALL_COUNT.store(0, Ordering::Relaxed);
                }
            }
        }
    }

    // Periodic orphan rescue: every 10 ticks (~100ms), scan for Ready
    // threads stuck outside all queues.  Runs on CPU 0 only.
    // Must not run too frequently — running every 2 ticks causes false-
    // positive rescues by catching threads in the transient window
    // between state=Ready and percpu_enqueue in check_sleep_timers
    // (cross-CPU race).  10 ticks gives all CPUs time to drain deferred
    // slots and complete enqueues.
    {
        static RESCUE_COUNTER: AtomicU64 = AtomicU64::new(0);
        static RESCUE_LOCK: AtomicU32 = AtomicU32::new(0);
        let rt = RESCUE_COUNTER.fetch_add(1, Ordering::Relaxed);
        // All CPUs contribute; fire every ~40 ticks with 4 CPUs (~100ms).
        if rt > 0 && rt % 40 == 0 {
            if RESCUE_LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                rescue_orphaned_threads_impl(false);
                RESCUE_LOCK.store(0, Ordering::Release);
            }
        }
    }

    // Heartbeat: every ~250ms, a live CPU sends reschedule IPIs and
    // drains stale remote deferred-requeue slots.  All CPUs contribute
    // to a global tick counter; every 100 increments (~250ms with 4
    // CPUs at 10ms ticks), one CPU CAS-wins the HEARTBEAT_LOCK and
    // performs the work.  This survives any single CPU being timer-dead.
    //
    // Stale-slot age: DEFERRED_STALE[c] counts consecutive heartbeat
    // rounds with CPU c's slot non-zero.  Age >=1 means occupied for
    // >=250ms — safe to drain (switch window is <1µs).
    {
        static DEFERRED_STALE: [AtomicU32; 16] = {
            const Z: AtomicU32 = AtomicU32::new(0);
            [Z; 16]
        };
        // Periodic Layer-3 counter dump (unconditional, ~1Hz aggregated
        // across all CPUs at 4 cpus × 25-tick period).  Surfaces
        // FAST_RESCUE_TAKEOVERS, CAS_FAIL_RESCUE_BAILS,
        // STEAL_AWARE_REROUTES, and ASYNC_PF_EVENTS without needing
        // the WATCHDOG IPC-stall trigger to fire.  Lets us see
        // whether the recent paravirt fixes are firing under stress.
        static LAYER3_DIAG_COUNTER: AtomicU64 = AtomicU64::new(0);
        static LAYER3_DIAG_LOCK: AtomicU32 = AtomicU32::new(0);
        let l3 = LAYER3_DIAG_COUNTER.fetch_add(1, Ordering::Relaxed);
        // Lowered from 100 → 10 (10× more frequent emit) so slow archs
        // (mips64 TCG, riscv64 under heavy stress) reach the LAYER3 site
        // within reasonable wallclock budgets.  Cost: a bit more serial
        // noise on fast archs.  Reversible.
        if l3 > 0 && l3 % 10 == 0 {
            if LAYER3_DIAG_LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                let frt = FAST_RESCUE_TAKEOVERS.load(Ordering::Relaxed);
                let cfb = CAS_FAIL_RESCUE_BAILS.load(Ordering::Relaxed);
                let sar = STEAL_AWARE_REROUTES.load(Ordering::Relaxed);
                let isr = IPI_STALE_REROUTES.load(Ordering::Relaxed);
                let hpd = HOST_PAUSE_PEERS_DETECTED.load(Ordering::Relaxed);
                let hps = HOST_PAUSE_STEALS.load(Ordering::Relaxed);
                #[cfg(target_arch = "x86_64")]
                let apf = crate::arch::x86_64::exception::async_pf_event_count();
                #[cfg(not(target_arch = "x86_64"))]
                let apf: u64 = 0;
                if frt | cfb | sar | isr | apf | hpd | hps != 0 {
                    #[cfg(target_arch = "x86_64")]
                    {
                        use crate::arch::x86_64::serial::{put_byte, put_bytes, put_dec_u64};
                        let mut buf = [0u8; 256];
                        let mut k = 0;
                        let fields: [(&[u8], u64); 7] = [
                            (b"LAYER3-DIAG: fast_takeover=", frt),
                            (b" cas_fail_bail=", cfb),
                            (b" wake_reroute=", sar),
                            (b" ipi_stale_reroute=", isr),
                            (b" async_pf=", apf),
                            (b" host_pause_peers=", hpd),
                            (b" host_pause_steals=", hps),
                        ];
                        for (label, val) in fields {
                            put_bytes(&mut buf, &mut k, label);
                            put_dec_u64(&mut buf, &mut k, val);
                        }
                        put_byte(&mut buf, &mut k, b'\n');
                        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                    }
                    #[cfg(not(target_arch = "x86_64"))]
                    crate::println!(
                        "LAYER3-DIAG: fast_takeover={} cas_fail_bail={} wake_reroute={} ipi_stale_reroute={} async_pf={} host_pause_peers={} host_pause_steals={}",
                        frt, cfb, sar, isr, apf, hpd, hps,
                    );
                }
                // #208 B2 RSP0-refresh visibility: total = user-return iretqs
                // that ran the refresher; fixed = those where it CORRECTED a
                // stale RSP0 (proves it closes a window other paths missed);
                // skip = IST/non-kstack returns intentionally left untouched.
                #[cfg(target_arch = "x86_64")]
                {
                    use crate::arch::x86_64::serial::{put_byte, put_bytes, put_dec_u64};
                    let rt = crate::arch::x86_64::exception::RSP0_REFRESH_TOTAL
                        .load(Ordering::Relaxed);
                    let rf = crate::arch::x86_64::exception::RSP0_REFRESH_FIXED
                        .load(Ordering::Relaxed);
                    let rs = crate::arch::x86_64::exception::RSP0_REFRESH_SKIP
                        .load(Ordering::Relaxed);
                    if rt | rf | rs != 0 {
                        let mut buf = [0u8; 96];
                        let mut k = 0;
                        put_bytes(&mut buf, &mut k, b"RSP0-DIAG: total=");
                        put_dec_u64(&mut buf, &mut k, rt);
                        put_bytes(&mut buf, &mut k, b" fixed=");
                        put_dec_u64(&mut buf, &mut k, rf);
                        put_bytes(&mut buf, &mut k, b" skip_ist=");
                        put_dec_u64(&mut buf, &mut k, rs);
                        put_byte(&mut buf, &mut k, b'\n');
                        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                    }
                }
                // #173 Phase 5: gate-split rescue + claim-helper counters.
                // Emit unconditionally so A/B comparison runs (gate OFF vs ON)
                // both produce a baseline trail for the same time interval.
                let gate_on = DISPATCH_USE_CLAIM_HELPER.load(Ordering::Relaxed);
                let stuck_on = RESCUE_STUCK_PENDING_FIRES_GATE_ON.load(Ordering::Relaxed);
                let stuck_off = RESCUE_STUCK_PENDING_FIRES_GATE_OFF.load(Ordering::Relaxed);
                let claim_fail = DISPATCH_CLAIM_FAIL.load(Ordering::Relaxed);
                let claim_self_pick = DISPATCH_CLAIM_SELF_PICK.load(Ordering::Relaxed);
                let stale_reclaim = DISPATCH_CLAIM_STALE_RECLAIM.load(Ordering::Relaxed);
                let torn_block = TORN_BLOCK_FIRES.load(Ordering::Relaxed);
                crate::println!(
                    "DISPATCH-DIAG: gate={} stuck_gate_on={} stuck_gate_off={} claim_fail={} claim_self_pick={} stale_reclaim={} torn_block={}",
                    if gate_on { "ON" } else { "OFF" },
                    stuck_on, stuck_off, claim_fail, claim_self_pick, stale_reclaim, torn_block,
                );
                LAYER3_DIAG_LOCK.store(0, Ordering::Release);
            }
        }

        static HEARTBEAT_COUNTER: AtomicU64 = AtomicU64::new(0);
        static HEARTBEAT_LOCK: AtomicU32 = AtomicU32::new(0);
        let hb = HEARTBEAT_COUNTER.fetch_add(1, Ordering::Relaxed);
        if hb > 0 && hb % 100 == 0 {
            if HEARTBEAT_LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                let cpu = smp::cpu_id();
                let ncpus = smp::num_cpus();
                for c in 0..ncpus.min(16) {
                    if c as u32 != cpu {
                        crate::arch::irq::send_reschedule_ipi(c as u32);
                    }
                    let slot = deferred_requeue()[c].load(Ordering::Relaxed);
                    if slot != 0 {
                        let age = DEFERRED_STALE[c].fetch_add(1, Ordering::Relaxed);
                        if age >= 1 {
                            drain_deferred_requeue(c as u32);
                            DEFERRED_STALE[c].store(0, Ordering::Relaxed);
                        }
                    } else {
                        DEFERRED_STALE[c].store(0, Ordering::Relaxed);
                    }
                }
                HEARTBEAT_LOCK.store(0, Ordering::Release);
            }
        }
    }

    // CallReply timeout: every 50 ticks (~500ms), sweep for call/reply
    // threads stuck longer than CALL_REPLY_TIMEOUT_NS. Unlike the WATCHDOG
    // (which requires zero IPC activity system-wide), this fires
    // unconditionally and uses per-thread timestamps to catch individual
    // stuck calls while other IPC traffic continues.
    {
        static CALL_TIMEOUT_COUNTER: AtomicU64 = AtomicU64::new(0);
        static CALL_TIMEOUT_LOCK: AtomicU32 = AtomicU32::new(0);
        let ct = CALL_TIMEOUT_COUNTER.fetch_add(1, Ordering::Relaxed);
        // All CPUs contribute; fire every ~200 ticks (~500ms with 4 CPUs).
        if ct > 0 && ct % 200 == 0 {
            if CALL_TIMEOUT_LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                call_reply_timeout_sweep();
                CALL_TIMEOUT_LOCK.store(0, Ordering::Release);
            }
        }
    }

    let result = try_switch(current_sp);

    // If try_switch performed a context switch, clear need_resched since
    // the switch already satisfied the preemption request.
    let cpu = smp::cpu_id();
    let pcpu = smp::get(cpu);
    if result != current_sp {
        pcpu.need_resched.store(false, Ordering::Relaxed);
    }

    // Compute and program the next timer event (dynamic tick).
    let is_idle = pcpu.current_thread.load(Ordering::Relaxed)
        == pcpu.idle_thread_id.load(Ordering::Relaxed);
    let next = compute_next_event(cpu, is_idle);
    crate::arch::timer::program_oneshot_ns(next);

    result
}

/// Compute the earliest timer event this CPU needs to wake for.
/// Returns an absolute deadline in nanoseconds since boot.
fn compute_next_event(cpu: u32, is_idle: bool) -> u64 {
    let now = get_monotonic_ns();
    let mut earliest = now + MAX_IDLE_NS; // cap: 1 second

    // 1. Quantum deadline: if running a real thread, wake when its quantum expires.
    if !is_idle {
        let tid = smp::get(cpu).current_thread.load(Ordering::Relaxed);
        let q = unsafe { thread_mut_from_ref(tid) }.quantum;
        if q != u32::MAX {
            earliest = earliest.min(now + (q as u64) * TICK_INTERVAL_NS);
        }
    }

    // 2. Sleep queue head (O(1) peek, no lock).
    let head = SLEEP_QUEUE_HEAD.load(Ordering::Acquire);
    if head != u32::MAX {
        let head_deadline = unsafe { thread_mut_from_ref(head) }.sleep_deadline_ns;
        if head_deadline != 0 {
            earliest = earliest.min(head_deadline);
        }
    }

    // 3. Cached alarm deadline.
    let alarm = EARLIEST_ALARM_NS.load(Ordering::Relaxed);
    if alarm != 0 {
        earliest = earliest.min(alarm);
    }

    // 4. Cached interval timer deadline.
    let interval = EARLIEST_INTERVAL_NS.load(Ordering::Relaxed);
    if interval != 0 {
        earliest = earliest.min(interval);
    }

    // 5. Deferred kills need draining within one tick.
    if deferred_kill()[cpu as usize].load(Ordering::Relaxed) != 0 {
        earliest = earliest.min(now + TICK_INTERVAL_NS);
    }

    // 6. When idle, check if a remote CPU enqueued work after try_switch
    //    checked the queue.  Without this, the newly-enqueued thread could
    //    sit in the run queue for up to MAX_IDLE_NS (1 second).
    if is_idle {
        let rq = percpu_rq()[cpu as usize].lock();
        let has_work = rq.has_ready();
        drop(rq);
        if has_work {
            earliest = earliest.min(now + 1_000); // 1 μs — wake ASAP
        }
    }

    // Floor: never less than 1 microsecond from now.
    earliest.max(now + 1_000)
}

/// Attempt to switch threads on the current CPU.
/// Uses only per-CPU run queue locks — does NOT take the global SCHEDULER lock.
fn try_switch(current_sp: u64) -> u64 {
    let cpu = smp::cpu_id();
    // #135: stamp last try_switch entry so rescue can detect dead CPUs.
    smp::get(cpu)
        .last_try_switch_ns
        .store(get_monotonic_ns(), Ordering::Relaxed);
    drain_deferred_requeue(cpu);
    let pcpu = smp::get(cpu);
    let idle_id_for_load = pcpu.idle_thread_id.load(Ordering::Relaxed);

    // #135 dispatch-bug investigation: per-cpu rate-limited try_switch trace.
    // Each line: prev/idle/has_ready/quantum so we can see who's running on
    // each CPU.  Per-CPU array of counters means cpu=1 etc. each get their
    // own 200-line quota — needed to see init (which lands on a non-bsp CPU
    // when SMP>1).
    static TS_TRACE_COUNT: [core::sync::atomic::AtomicU32; 8] = {
        const Z: core::sync::atomic::AtomicU32 =
            core::sync::atomic::AtomicU32::new(0);
        [Z; 8]
    };
    let trace_on = (cpu as usize) < TS_TRACE_COUNT.len() && {
        let n = TS_TRACE_COUNT[cpu as usize].fetch_add(1, Ordering::Relaxed);
        n < 200
    };
    if trace_on {
        let cur_tid = pcpu.current_thread.load(Ordering::Relaxed);
        let rq_has_ready = {
            let rq = percpu_rq()[cpu as usize].lock();
            let r = rq.has_ready();
            drop(rq);
            r
        };
        let quantum = thread_ref(cur_tid).quantum;
        let dq = thread_ref(cur_tid).default_quantum;
        let yield_asap = thread_ref(cur_tid).yield_asap.load(Ordering::Acquire);
        #[cfg(target_arch = "x86_64")]
        {
            use crate::arch::x86_64::serial::{put_byte, put_bytes, put_dec_u64};
            let mut buf = [0u8; 128];
            let mut k = 0;
            put_bytes(&mut buf, &mut k, b"TS-IN: cpu=");
            put_dec_u64(&mut buf, &mut k, cpu as u64);
            put_bytes(&mut buf, &mut k, b" prev=");
            put_dec_u64(&mut buf, &mut k, cur_tid as u64);
            put_bytes(&mut buf, &mut k, b" idle=");
            put_dec_u64(&mut buf, &mut k, idle_id_for_load as u64);
            put_bytes(&mut buf, &mut k, b" has_ready=");
            put_bytes(&mut buf, &mut k, if rq_has_ready { b"true" } else { b"false" });
            put_bytes(&mut buf, &mut k, b" quantum=");
            put_dec_u64(&mut buf, &mut k, quantum as u64);
            put_bytes(&mut buf, &mut k, b" dq=");
            put_dec_u64(&mut buf, &mut k, dq as u64);
            put_bytes(&mut buf, &mut k, b" yield=");
            put_bytes(&mut buf, &mut k, if yield_asap { b"true" } else { b"false" });
            put_byte(&mut buf, &mut k, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
        }
        #[cfg(not(target_arch = "x86_64"))]
        crate::println!(
            "TS-IN: cpu={} prev={} idle={} has_ready={} quantum={} dq={} yield={}",
            cpu, cur_tid, idle_id_for_load, rq_has_ready, quantum, dq, yield_asap,
        );
    }

    // First-dispatch probe: log when a tid is picked to run for the FIRST
    // time after its spawn.  Tells us which CPU eventually claims newly-
    // created threads.  One-shot per tid (256-slot bitmap).
    static FIRST_DISPATCH_LOGGED: [core::sync::atomic::AtomicBool; 256] = {
        const Z: core::sync::atomic::AtomicBool =
            core::sync::atomic::AtomicBool::new(false);
        [Z; 256]
    };
    fn maybe_log_first_dispatch(cpu: u32, tid: u32) {
        if (tid as usize) < FIRST_DISPATCH_LOGGED.len() {
            if !FIRST_DISPATCH_LOGGED[tid as usize]
                .swap(true, Ordering::Relaxed)
            {
                #[cfg(target_arch = "x86_64")]
                {
                    use crate::arch::x86_64::serial::{put_byte, put_bytes, put_dec_u64};
                    let mut buf = [0u8; 64];
                    let mut k = 0;
                    put_bytes(&mut buf, &mut k, b"FIRST-DISP: cpu=");
                    put_dec_u64(&mut buf, &mut k, cpu as u64);
                    put_bytes(&mut buf, &mut k, b" tid=");
                    put_dec_u64(&mut buf, &mut k, tid as u64);
                    put_byte(&mut buf, &mut k, b'\n');
                    crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                }
                #[cfg(not(target_arch = "x86_64"))]
                crate::println!("FIRST-DISP: cpu={} tid={}", cpu, tid);
            }
        }
    }
    let cur_for_load = pcpu.current_thread.load(Ordering::Relaxed);
    super::hotplug::tick_load(cpu, cur_for_load == idle_id_for_load);

    // Drain deferred kernel stack free from a previous exit on this CPU.
    let deferred = deferred_kstack()[cpu as usize].load(Ordering::Acquire);
    if deferred != 0 {
        let cur_tid = pcpu.current_thread.load(Ordering::Relaxed);
        // Safety: cur_tid is Running on this CPU, we own it.
        // Phase 5b: deferred_kstack holds PHYS base (not VA); compare with
        // current thread's stack_phys_base so we never free a stack we're
        // running on.
        let cur_stack = thread_ref(cur_tid).stack_phys_base;
        spb_check(cur_tid, cur_stack as u64, "drain_cur_check");
        if cur_stack != deferred {
            deferred_kstack()[cpu as usize].store(0, Ordering::Release);
            kstack_pa_audit(deferred, kstack_size(), -1, "free");
            kstack_pa_unregister(deferred as u64);
            // #208 KSTACK_LIVENESS_GUARD: detection-only liveness check at
            // the try_switch death-path free (the second of two kstack free
            // sites).  Same guard as drain_prior_deferred_kstack: catch a
            // still-LIVE owner of this phys before it returns to the
            // allocator.  Behavior unchanged — we still free.
            #[cfg(target_arch = "x86_64")]
            if KSTACK_LIVENESS_GUARD {
                let expected_dead =
                    deferred_thread()[cpu as usize].load(Ordering::Acquire) as u32;
                let skip = if (expected_dead as usize) < RadixTable::capacity() {
                    expected_dead
                } else {
                    u32::MAX
                };
                if let Some((tid, state)) = live_thread_owning_kstack_phys(deferred, skip) {
                    report_kstack_premature_free(tid, state, deferred, cpu, skip);
                }
            }
            crate::mm::phys::free_pages(crate::mm::page::PhysAddr::new(deferred), KSTACK_ORDER);
            let dead_tid = deferred_thread()[cpu as usize].swap(usize::MAX, Ordering::AcqRel);
            if dead_tid < RadixTable::capacity() {
                // Safety: dead thread is Dead, not on any queue or CPU.
                let t = unsafe { thread_mut_from_ref(dead_tid as ThreadId) };
                t.stack_base = 0;
                bump_kstack_epoch(t); // #208
            }
        }
    }

    let pcpu = smp::current();
    let prev_id = pcpu.current_thread.load(Ordering::Relaxed);
    let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

    // Decide if preemption is needed (lockless — we own the running thread).
    if prev_id == idle_id {
        // Idle thread: preempt if local queue has work. Also try stealing
        // from other CPUs (with min_len=1) to pick up threads that were
        // demoted to prio 254 by block_current and are stuck on a busy CPU.
        let rq = percpu_rq()[cpu as usize].lock();
        let has_work = rq.has_ready();
        drop(rq);
        if !has_work {
            match try_steal_for_idle(cpu) {
                Some(tid) => {
                    let prio = thread_ref(tid).prio.load(Ordering::Relaxed);
                    set_enq_tag(5); // 5=steal
                    percpu_enqueue(cpu, prio, tid);
                }
                None => {
                    crate::sync::rcu::rcu_quiescent();
                    return current_sp;
                }
            }
        }
    } else {
        if thread_ref(prev_id).yield_asap.load(Ordering::Acquire) {
            // Will preempt — continue below.
        } else {
            // Lazy preemption: when nothing else is ready on this CPU,
            // there's no one to switch to anyway, so skip the quantum
            // decrement entirely.  Without this, every tick still
            // burned CPU on the saturating_sub + write even when the
            // current thread had no contender — and at low quanta
            // (default_quantum=1 in r28) the per-tick CS rate exceeded
            // TICK_INTERVAL_NS, livelocking the system.  With this
            // check, ticks-with-no-contender are pure no-ops, and
            // quantum is only spent during actual contention.
            let has_contender = {
                let rq = percpu_rq()[cpu as usize].lock();
                let ready = rq.has_ready();
                drop(rq);
                ready
            };
            if has_contender {
                // Safety: prev_id is Running on this CPU, we own it.
                let t = unsafe { thread_mut_from_ref(prev_id) };
                // Advance EEVDF virtual runtime for fair accounting.
                // Preemption is still quantum-based for stability; EEVDF
                // deadlines drive dispatch order (earliest-deadline-first)
                // via class_pick_next.
                if t.sched_class == SCHED_NORMAL && t.effective_priority != 254 {
                    let weight = t.eevdf_weight as u64;
                    t.eevdf_vruntime += VTIME_UNIT / weight;
                }
                t.quantum = t.quantum.saturating_sub(1);
                if t.quantum != 0 {
                    crate::sync::rcu::rcu_quiescent();
                    return current_sp; // No preemption needed.
                }
                t.quantum = t.default_quantum;
            } else {
                // No contender — current thread retains quantum, fall
                // through to RCU quiescence and return without picking
                // a "next" thread.
                crate::sync::rcu::rcu_quiescent();
                return current_sp;
            }
        }
    }

    // Clear yield_asap.
    thread_ref(prev_id)
        .yield_asap
        .store(false, Ordering::Release);

    // Pick next thread from per-CPU queue.
    let prev_group = thread_ref(prev_id).cosched_group.load(Ordering::Relaxed);
    // #173 Phase 3c: gated cosched dispatch.  The cosched-claim helper
    // handles self-pick INTERNALLY by returning `prev_id` when CAS-fail
    // detects `on_cpu == cpu`, so the existing `prev_id == next_id`
    // branch below fires naturally.  No state restore is needed for the
    // self-pick path because the helper never stamped `pending_set_ns`
    // or moved `on_cpu` to `PENDING` (those were the legacy artifacts).
    let claimed_by_helper =
        DISPATCH_USE_CLAIM_HELPER.load(Ordering::Relaxed);
    let (next_id, _cosched) = if claimed_by_helper {
        let pcpu_for_helper = smp::current();
        let nid = percpu_pick_next_cosched_and_claim(
            cpu, idle_id, prev_group, prev_id,
            pcpu_for_helper, 1, /* set_by=1 (try_switch) */
        );
        (nid, false)
    } else {
        percpu_pick_next_cosched(cpu, idle_id, prev_group)
    };

    if prev_id == next_id {
        // Self-pick: `prev_id` was popped but is still running on us.
        // Legacy path needed to restore on_cpu=cpu and clear
        // pending_set_ns / PENDING_LOW_LOGGED because dequeue_set_pending
        // had stamped them.  Claim helper never stamped them in the
        // self-pick case (CAS failed before the bookkeeping ran), so the
        // restore is unnecessary for that branch.
        if prev_id != idle_id {
            if !claimed_by_helper {
                thread_ref(prev_id).on_cpu.store(cpu, Ordering::Release);
                // #135 self-pick PENDING-STUCK-LOW false-positive fix:
                // percpu_pick_next_cosched called dequeue_set_pending which
                // stamped pending_set_ns to "now" and set on_cpu=PENDING.
                // We just restored on_cpu but the stale stamp would survive
                // until the next REAL preemption, then the rescue sweep would
                // compute age_ns from this stale stamp and fire PENDING-STUCK-
                // LOW falsely on a thread that ran continuously between.
                // Mirror what dispatch_cas_ok does on the real dispatch path:
                // clear pending_set_ns and reset PENDING_LOW_LOGGED.
                thread_ref(prev_id).pending_set_ns.store(0, Ordering::Relaxed);
                if (prev_id as usize) < PENDING_LOW_LOGGED.len() {
                    PENDING_LOW_LOGGED[prev_id as usize].store(false, Ordering::Relaxed);
                }
            }
            SELF_PICK_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        crate::sync::rcu::rcu_quiescent();
        return current_sp;
    }

    crate::sched::stats::CONTEXT_SWITCHES.fetch_add(1, Ordering::Relaxed);
    crate::trace::trace_event(crate::trace::EVT_CTX_SWITCH, prev_id, next_id);

    // Wake-to-dispatch latency: if this thread carries a non-zero
    // wake_pending_ts_ns, this is the first dispatch since wake.
    // Swap-to-0 to avoid double-counting if try_switch picks the same
    // thread again before the next park.  Accumulates total + count
    // for running average, and tracks the running max.
    {
        let pending = thread_ref(next_id)
            .wake_pending_ts_ns
            .swap(0, Ordering::Relaxed);
        if pending != 0 {
            let now = get_monotonic_ns();
            let lat = now.saturating_sub(pending);
            SLEEP_WAKE_LATENCY_NS_TOTAL.fetch_add(lat, Ordering::Relaxed);
            SLEEP_WAKE_LATENCY_COUNT.fetch_add(1, Ordering::Relaxed);
            let mut prev_max = SLEEP_WAKE_LATENCY_NS_MAX.load(Ordering::Relaxed);
            while lat > prev_max {
                match SLEEP_WAKE_LATENCY_NS_MAX.compare_exchange_weak(
                    prev_max,
                    lat,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(seen) => prev_max = seen,
                }
            }
            // Histogram bucket: log10-ish, see SLEEP_WAKE_LATENCY_BUCKETS
            // declaration for the bin definitions.
            let bucket = if lat < 100_000 { 0 }              // <100us
                else if lat < 1_000_000 { 1 }                // <1ms
                else if lat < 10_000_000 { 2 }               // <10ms
                else if lat < 100_000_000 { 3 }              // <100ms
                else if lat < 1_000_000_000 { 4 }            // <1s
                else if lat < 10_000_000_000 { 5 }           // <10s
                else { 6 };                                  // >=10s
            SLEEP_WAKE_LATENCY_BUCKETS[bucket].fetch_add(1, Ordering::Relaxed);
        }
    }

    // Save current thread's SP. Safety: we own the running thread.
    let prev_task;
    {
        let prev_t = unsafe { thread_mut_from_ref(prev_id) };
        // Probe #208: log idle's saved_sp writes.  Boot 582 caught
        // idle.saved_sp pointing into executable code (frame[0..21] = real
        // x86 instruction bytes) and into other threads' kstacks (BAD frame
        // fires with src=1, tid=0).  Every (cpu, current_sp, in_kstack)
        // tuple here helps attribute the exact moment the bad value lands
        // — whether current_sp itself is bogus on entry, or prev_id is
        // stale-pointing at idle while the real running thread is something
        // else.  Rate-limited per CPU to avoid log flood.
        if prev_id == idle_id_for_load {
            static IDLE_SP_TRACE_COUNT: [core::sync::atomic::AtomicU32; 8] = {
                const Z: core::sync::atomic::AtomicU32 =
                    core::sync::atomic::AtomicU32::new(0);
                [Z; 8]
            };
            if (cpu as usize) < IDLE_SP_TRACE_COUNT.len() {
                let n = IDLE_SP_TRACE_COUNT[cpu as usize]
                    .fetch_add(1, Ordering::Relaxed);
                if n < 200 {
                    let kbase = prev_t.stack_base;
                    let kend = kbase as u64 + kstack_size() as u64;
                    let in_kstack = (current_sp >= kbase as u64) && (current_sp < kend);
                    #[cfg(target_arch = "x86_64")]
                    {
                        use crate::arch::x86_64::serial::{put_byte, put_bytes, put_hex_u64, put_dec_u64};
                        let mut buf = [0u8; 192];
                        let mut k = 0;
                        put_bytes(&mut buf, &mut k, b"IDLE-SP-WRITE: cpu=");
                        put_dec_u64(&mut buf, &mut k, cpu as u64);
                        put_bytes(&mut buf, &mut k, b" prev=");
                        put_dec_u64(&mut buf, &mut k, prev_id as u64);
                        put_bytes(&mut buf, &mut k, b" new_sp=");
                        put_hex_u64(&mut buf, &mut k, current_sp);
                        put_bytes(&mut buf, &mut k, b" idle_kstack=[");
                        put_hex_u64(&mut buf, &mut k, kbase as u64);
                        put_bytes(&mut buf, &mut k, b"..");
                        put_hex_u64(&mut buf, &mut k, kend);
                        put_bytes(&mut buf, &mut k, b") in_kstack=");
                        put_bytes(&mut buf, &mut k, if in_kstack { b"true" } else { b"false" });
                        put_bytes(&mut buf, &mut k, b" n=");
                        put_dec_u64(&mut buf, &mut k, n as u64);
                        put_byte(&mut buf, &mut k, b'\n');
                        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                    }
                    #[cfg(not(target_arch = "x86_64"))]
                    crate::println!(
                        "IDLE-SP-WRITE: cpu={} prev={} new_sp={:#x} idle_kstack=[{:#x}..{:#x}) in_kstack={} n={}",
                        cpu, prev_id, current_sp, kbase, kend, in_kstack, n
                    );
                }
            }
        }
        // #208 tid-reuse race fix: validate that current_sp falls inside
        // prev_t's current kstack BEFORE writing saved_sp.  If the
        // deferred-free + alloc_thread_id reuse race fired between the
        // top of try_switch and here, prev_t has been recycled for a
        // NEW thread with a different kstack — writing current_sp (a
        // stale address from the OLD incarnation) would corrupt NEW's
        // already-correct saved_sp set by spawn_user/clone.  Skip the
        // write in that case.  Idle is exempt because it runs on the
        // boot stack (sp legitimately outside its allocated kstack).
        // Captured by KEPOCH-BAIL: site=try_switch.save boot 595.
        let save_ok = prev_id == idle_id_for_load
            || validate_kstack_inject(prev_id, current_sp, "try_switch.save");
        if save_ok {
            write_saved_sp(prev_t, current_sp);
            record_saved_sp_write(prev_id, current_sp, 4); // try_switch
            prev_t.saved_sp_source = 1; // try_switch
        } else if prev_id != idle_id_for_load {
            // #250 cross-CPU active-while-deferred-free probe.  When the
            // validator bails on prev_id (stack_base=0, recycled slot,
            // sp out of range), check whether any PEER CPU still has
            // current_thread == prev_id.  If so, that peer was about to
            // dispatch a thread we already think is dead — proves the
            // deferred-free + concurrent dispatch race that
            // memory/project_riscv64_stack_base_writer_audit.md hypothesizes.
            // Rate-limited; cheap (NCPUS atomic loads).  See
            // memory/project_riscv64_corruption_family_observed.md.
            static PEER_HIT_LOG: core::sync::atomic::AtomicU32 =
                core::sync::atomic::AtomicU32::new(0);
            let n_cpus = smp::MAX_CPUS as u32;
            let mut peer_with_prev: i32 = -1;
            for c in 0..n_cpus {
                if c == cpu {
                    continue;
                }
                let peer_cur = smp::get(c).current_thread.load(Ordering::Relaxed);
                if peer_cur as usize == prev_id as usize {
                    peer_with_prev = c as i32;
                    break;
                }
            }
            if peer_with_prev >= 0 {
                let nn = PEER_HIT_LOG.fetch_add(1, Ordering::Relaxed);
                if nn < 32 {
                    crate::println!(
                        "TS-SAVE-PEER-ACTIVE: cpu={} prev={} peer_cpu={} sp={:#x} n={}",
                        cpu, prev_id, peer_with_prev, current_sp, nn
                    );
                }
            }
        }
        let mut prev_prio = prev_t.effective_priority;
        prev_task = prev_t.task_id;
        // If the thread was demoted by block_current and has been woken
        // (wakeup flag set), restore its base priority so it gets
        // re-enqueued at the correct level instead of being starved.
        if prev_prio > prev_t.base_priority {
            let current_prio = thread_ref(prev_id).prio.load(Ordering::Acquire);
            if thread_ref(prev_id).wakeup.load(Ordering::Acquire) || current_prio < prev_prio {
                prev_t.effective_priority = prev_t.base_priority;
                thread_ref(prev_id)
                    .prio
                    .store(prev_t.base_priority, Ordering::Release);
                prev_prio = prev_t.base_priority;
            }
        }
        // NEW_INV: while state=Ready, on_cpu MUST be ON_CPU_PENDING. The
        // store to ON_CPU_PENDING is performed BEFORE the slot fill (below)
        // and BEFORE state=Ready, so rescue's stale-on-cpu predicate cannot
        // observe (state=Ready, on_cpu=cpu_real) — that combination is now
        // impossible by construction. drain_deferred_requeue therefore needs
        // no CAS to detect rescue-races; it just enqueues unconditionally.
        // Don't re-enqueue Dead threads (they are exiting).
        if prev_id != idle_id
            && prev_t.state != ThreadState::Dead
            && prev_t.state != ThreadState::Blocked
        {
            // #135 real-block: if prev set state=Blocked (via block_current),
            // we do NOT deferred_requeue here.  The thread leaves the
            // runqueue entirely until wake_thread re-enqueues it at base
            // priority.  We still need to mark on_cpu as not-running so
            // rescue's stale-on-cpu predicate doesn't misfire.  Done in
            // the surrounding block below — see the matching else arm.
            //
            // If the thread was killed, mark Dead + defer full cleanup
            // so it doesn't keep getting scheduled.
            if thread_ref(prev_id).killed.load(Ordering::Relaxed) {
                prev_t.state = ThreadState::Dead;
                prev_t.exit_code = -9;
                let waiter = prev_t.join_waiter;
                prev_t.join_waiter = u32::MAX;
                if waiter != u32::MAX {
                    wake_thread(waiter);
                }
                let task_id = prev_t.task_id;
                let task = unsafe { task_mut_from_ref(task_id) };
                task.thread_count -= 1;
                if task.thread_count == 0 {
                    task.exit_code = -9;
                    task.exited = true;
                    task.active = false;
                    task.wait_status = ((-9i32 & 0xFF) << 8) | 9; // killed by signal 9
                    send_signal_to_task(task.parent_task, super::task::SIGCHLD);
                    wake_wait_child_threads(task.parent_task);
                }
                // Queue for deferred resource cleanup on next tick.
                deferred_kill()[cpu as usize].store(prev_id as usize, Ordering::Release);
                // Also defer kstack free.
                // Phase 5b: store PHYS base (not VA) so the deferred drain
                // can pass it to phys::free_pages directly.
                let kstack_phys_base = prev_t.stack_phys_base;
                spb_check(prev_id, kstack_phys_base as u64, "kill_defer");
                // Phase-5 leak fix: free any prior pending deferred kstack
                // before overwriting the single-slot — otherwise a rapid
                // second exit on this CPU leaks the first thread's kstack.
                drain_prior_deferred_kstack(cpu as usize, kstack_phys_base);
                deferred_thread()[cpu as usize].store(prev_id as usize, Ordering::Release);
                deferred_kstack()[cpu as usize].store(kstack_phys_base, Ordering::Release);
            } else {
                // Defer re-enqueue: prevent work-stealing from picking up
                // prev while this CPU is still on its kernel stack.
                //
                // #208 Fix D: store ON_CPU_RELEASING (not PENDING) here.
                // RELEASING is treated as "parked" by rescue (it's > ncpus,
                // so on_cpu<ncpus predicate fails) but the dispatch CAS at
                // line ~4388 only accepts PENDING, so peer CPUs cannot pick
                // prev up.  `transition_release_to_pending(prev_id)` is
                // called just before each post-park-side return so prev
                // becomes dispatchable only AFTER all try_switch bookkeeping
                // is complete — closing the migration-handoff race window
                // that previously let cpu_new dispatch prev while cpu_old
                // still held its kstack.
                thread_ref(prev_id).on_cpu.store(ON_CPU_RELEASING, Ordering::Release);
                record_trans(prev_id as u32, 7, prev_t.state, ON_CPU_RELEASING);
                let packed = (prev_id as u64) | ((prev_prio as u64) << 32) | ((cpu as u64) << 40);
                let old_deferred = deferred_requeue()[cpu as usize].swap(packed, Ordering::AcqRel);
                if old_deferred != 0 {
                    // Defensive: try_switch entry already drained this slot
                    // (line ~2521), so old_deferred should be 0. If somehow
                    // non-zero, the lost tid already has on_cpu=PENDING under
                    // NEW_INV; just enqueue. percpu_enqueue's in_queue swap
                    // is the double-enqueue guard.
                    let lost_tid = (old_deferred & 0xFFFFFFFF) as u32;
                    let lost_prio = ((old_deferred >> 32) & 0xFF) as u8;
                    let lost_target = ((old_deferred >> 40) & 0xFF) as u32;
                    crate::println!(
                        "DEFERRED-OVERWRITE(try_switch): cpu={} lost tid={} prio={} replaced by tid={} prio={}",
                        cpu, lost_tid, lost_prio, prev_id, prev_prio
                    );
                    set_enq_tag(10); // 10=overwrite_rescue
                    percpu_enqueue(lost_target, lost_prio, lost_tid);
                }
                prev_t.state = ThreadState::Ready;
                trace_sched(prev_id, 1); // 1=deferred_store
            }
        } else if prev_id != idle_id && prev_t.state == ThreadState::Blocked {
            // #135 real-block: mark on_cpu so rescue/work-stealing leaves
            // us alone.  We are NOT in any runqueue — wake_thread will
            // re-enqueue when wakeup arrives.
            // #208 Fix D: use ON_CPU_RELEASING (see Fix-D notes at the
            // deferred-requeue branch above and at
            // transition_release_to_pending).
            thread_ref(prev_id).on_cpu.store(ON_CPU_RELEASING, Ordering::Release);
            record_trans(prev_id as u32, 10, ThreadState::Blocked, ON_CPU_RELEASING);
        }
    }

    // Switch page tables if crossing task boundaries.
    let next_task = thread_ref(next_id).task_id;
    if prev_task != next_task {
        // Need task data — access via TASK_TABLE (lockless).
        let next_root = {
            let tptr = TASK_TABLE.get(next_task) as *const Task;
            if !tptr.is_null() {
                unsafe { (*tptr).page_table_root }
            } else {
                0
            }
        };
        if next_root != 0 {
            crate::mm::hat::switch_page_table(next_root);
        } else {
            let kern_root = crate::mm::hat::kernel_pt_root();
            if kern_root != 0 {
                crate::mm::hat::switch_page_table(kern_root);
            }
        }
    }

    crate::arch::trapframe::update_kernel_stack(next_id as u32, thread_ref(next_id).stack_base + kstack_size());

    // Restore TLS base register for the next thread.
    // Always write FSBASE so stale values from another thread don't leak.
    crate::arch::cpu::set_tls(thread_ref(next_id).tls_base);

    // Double-scheduling detection: CAS on_cpu from ON_CPU_PENDING→cpu.
    // dequeue_set_pending only sets ON_CPU_PENDING for threads that were
    // parked (on_cpu=MAX) or already pending. If on_cpu is a real CPU
    // number (spurious rescue enqueue of a Running thread), CAS fails.
    // Skip for idle threads (per-CPU, never enqueued, can't be double-scheduled).
    //
    // dispatching_tid: published BEFORE the CAS so rescue's stale_on_cpu
    // predicate (state=Ready, on_cpu=cpu_real, current_thread=prev_id) can
    // observe "this CPU is in the middle of dispatching tid" and skip.
    // Cleared AFTER the current_thread store so rescue never sees a thread
    // that has on_cpu=cpu but is neither dispatching nor current_thread.
    if next_id != idle_id {
        pcpu.dispatching_tid.store(next_id, Ordering::Release);
        if claimed_by_helper {
            // Phase 3c: helper already CAS'd PENDING→cpu under rq.lock
            // and ran the matching bookkeeping (TRANS_CAS_OK,
            // on_cpu_set_by=1, dispatch_cas_ok, state=Running,
            // dispatch_count).  Still need the try_switch-specific:
            // trace_point("cas_ok"), trace_sched(4), first-dispatch log,
            // dispatch_streak.
            trace_point("try_switch.cas_ok", next_id as u32);
            trace_sched(next_id, 4); // 4=on_cpu_set
            maybe_log_first_dispatch(cpu, next_id);
            let prev_picked =
                pcpu.last_dispatched_tid.swap(next_id as u32, Ordering::Relaxed);
            if prev_picked == next_id as u32 {
                pcpu.dispatch_streak.fetch_add(1, Ordering::Relaxed);
            } else {
                pcpu.dispatch_streak.store(1, Ordering::Relaxed);
            }
        } else if let Err(other_cpu) = thread_ref(next_id).on_cpu.compare_exchange(
            ON_CPU_PENDING, cpu, Ordering::AcqRel, Ordering::Acquire,
        ) {
            trace_point("try_switch.cas_fail", next_id as u32);
            record_trans(next_id as u32, TRANS_CAS_FAIL, thread_ref(next_id).state, other_cpu);
            // CAS is the dispatch-lease mutex: at most one CPU wins
            // PENDING→cpu per cycle.  If we lost, the thread is owned
            // by `other_cpu` (could be MAX after a fast-rescue takeover,
            // could be a real CPU after a rescued+redispatched thread).
            // Either way, just yield to idle.  The previous "kill on
            // any non-PENDING value" was defensive paranoia: with CAS
            // already preventing double-dispatch, the kill could only
            // ever destroy a legitimately-running thread, never prevent
            // a buggy state.  Surface the loss in a counter for
            // visibility; no print (cold path that occasionally
            // hot-fires under host pressure).
            CAS_FAIL_RESCUE_BAILS.fetch_add(1, Ordering::Relaxed);
            pcpu.dispatching_tid.store(0, Ordering::Release);
            let idle_sp = thread_ref(idle_id).saved_sp;
            unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
            set_current_thread(pcpu, idle_id);
            // #208 Fix D: release prev to PENDING just before returning,
            // so peer CPUs can now dispatch it (asm `mov rsp, rax`
            // immediately follows this return).
            transition_release_to_pending(prev_id);
            return idle_sp;
        } else {
            trace_point("try_switch.cas_ok", next_id as u32);
            record_trans(next_id as u32, TRANS_CAS_OK, ThreadState::Running, cpu);
            thread_ref(next_id).on_cpu_set_by.store(1, Ordering::Relaxed); // 1=try_switch
            // #120 dispatch-symmetry: clear pending state + bump cas_ok counter.
            dispatch_cas_ok(pcpu, next_id);
            // Set Running IMMEDIATELY after CAS to close the TOCTOU window:
            // between CAS(on_cpu=cpu) and state=Running, rescue sees
            // state=Ready + on_cpu=cpu + current_thread≠tid → false orphan.
            unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
            trace_sched(next_id, 4); // 4=on_cpu_set
            // #135 first-dispatch probe — log the first time each tid is picked.
            maybe_log_first_dispatch(cpu, next_id);
            // #120 dispatch-pattern diagnostic: count + same-tid streak.
            pcpu.dispatch_count.fetch_add(1, Ordering::Relaxed);
            let prev_picked = pcpu.last_dispatched_tid.swap(next_id as u32, Ordering::Relaxed);
            if prev_picked == next_id as u32 {
                pcpu.dispatch_streak.fetch_add(1, Ordering::Relaxed);
            } else {
                pcpu.dispatch_streak.store(1, Ordering::Relaxed);
            }
        }
    } else {
        // Idle thread: no CAS needed, just set Running.
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
    }

    // Activate next thread.
    let next_t = unsafe { thread_mut_from_ref(next_id) };
    trace_sched(next_id, 7); // 7=state_running
    set_current_thread(pcpu, next_id);
    // Clear dispatching_tid: dispatch is fully visible — on_cpu=cpu,
    // state=Running, current_thread=tid all observable to other CPUs.
    if next_id != idle_id {
        pcpu.dispatching_tid.store(0, Ordering::Release);
    }
    thread_ref(next_id).last_cpu.store(cpu, Ordering::Relaxed);

    // RCU quiescent state: all syscall read-side references from the
    // previous timeslice are now dead.  Process deferred frees.
    crate::sync::rcu::rcu_quiescent();

    // Sanity check: saved_sp must be within the thread's kstack, and the
    // CS/RIP fields in the exception frame must be valid.
    {
        let sp = next_t.saved_sp;
        let kbase = next_t.stack_base;
        let kend = kbase as u64 + kstack_size() as u64;
        let is_idle = next_id == idle_id;
        // #204 probe: validate next_t at switch-in.  Fires CONCURRENTLY
        // with the BUG: try_switch check below — its job is to confirm
        // whether the corruption is isolated to saved_sp/stack_base
        // (existing check) or spread across the whole Thread struct
        // (canary check covers id, state, src, on_cpu).
        validate_thread_canary(next_id, "try_switch.next");
        // #205 stack guard canary — catches kernel stack overflow on
        // the thread we're switching into.  If clobbered, we've
        // localized the corruption to writes near stack_base.
        check_stack_canary(next_id, "try_switch.next");
        // #208 FRAME-DELTA at dispatch — compare iretq frame contents
        // at saved_sp against the shadow taken at park-time.  STALE-WRITE
        // showed saved_sp itself is correct; this catches the
        // complement: frame memory at saved_sp got overwritten since
        // last park.  Skips the state==Blocked gate because state was
        // just flipped to Running for this dispatch.
        if !is_idle {
            check_iretq_shadow_at_dispatch(next_id, sp);
            // Extended-stack snapshot check (1 KiB above saved_sp) —
            // catches wild-RIP-family corruption in calling-function
            // frames where iretq_shadow_frame (22 quads) doesn't reach.
            check_park_stack_ext(next_id, sp);
        }
        // #208 STALE-WRITE invariant: every legitimate writer of
        // `saved_sp` pairs the field write with `record_saved_sp_write`.
        // If `t.saved_sp != SAVED_SP_LAST_VALUE[tid]` at dispatch, some
        // path is writing saved_sp WITHOUT going through the canonical
        // record path — and that path is the unknown corruption source.
        // Skip idle (its saved_sp may legitimately differ — it runs on
        // the boot/AP stack instead of its allocated kstack).  Skip if
        // recorded == 0 (no write recorded yet — fresh slot).
        if !is_idle && (next_id as usize) < SAVED_SP_LOG_CAP {
            let rec_value = SAVED_SP_LAST_VALUE[next_id as usize]
                .load(Ordering::Relaxed);
            if rec_value != 0 && rec_value != sp {
                static STALE_WRITE_LOG_COUNT:
                    core::sync::atomic::AtomicU32 =
                    core::sync::atomic::AtomicU32::new(0);
                let n = STALE_WRITE_LOG_COUNT.fetch_add(
                    1, Ordering::Relaxed,
                );
                if n < 16 {
                    let rec_meta = SAVED_SP_LAST_META[next_id as usize]
                        .load(Ordering::Relaxed);
                    let tag = (rec_meta & 0xFF) as u8;
                    let cpu_logged = ((rec_meta >> 8) & 0xFF) as u8;
                    let ts32 = (rec_meta >> 32) as u32;
                    crate::println!(
                        "STALE-WRITE-RACE: tid={} actual_sp={:#x} recorded={:#x} (writer_tag={} cpu={} ts32={}) src={} n={}",
                        next_id, sp, rec_value, tag, cpu_logged, ts32,
                        next_t.saved_sp_source, n
                    );
                }
            }
        }
        // Idle threads run on boot stacks (ring 0), not their allocated kstack.
        // Their saved_sp is legitimately outside the kstack range — skip the check.
        if !is_idle && (sp < kbase as u64 || sp >= kend) {
            #[cfg(target_arch = "x86_64")]
            {
                use crate::arch::x86_64::serial::{put_bytes, put_hex_u64, put_dec_u64};
                let mut buf = [0u8; 192];
                let mut k = 0;
                put_bytes(&mut buf, &mut k, b"BUG: try_switch: tid=");
                put_dec_u64(&mut buf, &mut k, next_id as u64);
                put_bytes(&mut buf, &mut k, b" saved_sp=");
                put_hex_u64(&mut buf, &mut k, sp);
                put_bytes(&mut buf, &mut k, b" OUTSIDE kstack ");
                put_hex_u64(&mut buf, &mut k, kbase as u64);
                put_bytes(&mut buf, &mut k, b"..");
                put_hex_u64(&mut buf, &mut k, kend);
                put_bytes(&mut buf, &mut k, b" (source=");
                put_dec_u64(&mut buf, &mut k, next_t.saved_sp_source as u64);
                put_bytes(&mut buf, &mut k, b")\n");
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            #[cfg(not(target_arch = "x86_64"))]
            crate::println!(
                "BUG: try_switch: tid={} saved_sp={:#x} OUTSIDE kstack {:#x}..{:#x} (source={})",
                next_id, sp, kbase, kend, next_t.saved_sp_source
            );
            dump_saved_sp_log(next_id);
            crate::println!(
                "  prev={} next={} task={} state={:?}",
                prev_id, next_id, next_t.task_id, next_t.state
            );
            // Kill this thread and switch to idle instead — restoring from
            // an out-of-range saved_sp would corrupt the CPU state (#DE/#GP).
            thread_ref(next_id).killed.store(true, Ordering::Release);
            let idle_sp = thread_ref(idle_id).saved_sp;
            unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
            set_current_thread(pcpu, idle_id);
            // #208 Fix D: release prev → PENDING just before return.
            transition_release_to_pending(prev_id);
            return idle_sp;
        }
        // Check for corrupt exception frame (architecture-specific).
        #[cfg(target_arch = "x86_64")]
        if !is_idle && sp >= kbase as u64 && sp < kend {
            // x86_64: CS must be 0x08 (kernel) or 0x23 (user), RIP must be > 64K.
            let rip = unsafe { *((sp as usize + 136) as *const u64) };
            let cs = unsafe { *((sp as usize + 144) as *const u64) };
            let bad_cs = cs != 0x08 && cs != 0x23;
            let bad_rip = rip < 0x10000; // no code below 64K in kernel or user
            if bad_cs || bad_rip {
                {
                    use crate::arch::x86_64::serial::{put_bytes, put_hex_u64, put_dec_u64};
                    let mut buf = [0u8; 224];
                    let mut k = 0;
                    put_bytes(&mut buf, &mut k, b"BUG: try_switch: tid=");
                    put_dec_u64(&mut buf, &mut k, next_id as u64);
                    put_bytes(&mut buf, &mut k, b" bad frame RIP=");
                    put_hex_u64(&mut buf, &mut k, rip);
                    put_bytes(&mut buf, &mut k, b" CS=");
                    put_hex_u64(&mut buf, &mut k, cs);
                    put_bytes(&mut buf, &mut k, b" sp=");
                    put_hex_u64(&mut buf, &mut k, sp);
                    put_bytes(&mut buf, &mut k, b" src=");
                    put_dec_u64(&mut buf, &mut k, next_t.saved_sp_source as u64);
                    put_bytes(&mut buf, &mut k, b" prev=");
                    put_dec_u64(&mut buf, &mut k, prev_id as u64);
                    put_bytes(&mut buf, &mut k, b" task=");
                    put_dec_u64(&mut buf, &mut k, next_t.task_id as u64);
                    put_bytes(&mut buf, &mut k, b"\n");
                    crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                }
                // Skip this thread — mark killed and pick idle instead.
                thread_ref(next_id).killed.store(true, Ordering::Release);
                let idle_sp = thread_ref(idle_id).saved_sp;
                // #208 fallback-safety: BEFORE switching to idle, sanity-check
                // idle's saved_sp.  Boot 11amfsq841 showed idle.saved_sp =
                // 0xffffffff9df27900 (HIGH-VMA kernel data, in_kstack=false).
                // Dispatching to that would set RSP to kernel-data memory →
                // push/pop corrupt code or trigger #PF cascade → triple-fault.
                // If idle is also corrupt, halt this CPU instead of restoring
                // to a known-bad sp.  The other CPUs continue.
                let idle_t = thread_ref(idle_id);
                let idle_kbase = idle_t.stack_base as u64;
                let idle_kend = idle_kbase + kstack_size() as u64;
                let idle_sp_in_kstack =
                    idle_sp >= idle_kbase && idle_sp < idle_kend;
                if !idle_sp_in_kstack {
                    {
                        use crate::arch::x86_64::serial::{put_bytes, put_hex_u64, put_dec_u64};
                        let mut buf = [0u8; 224];
                        let mut k = 0;
                        put_bytes(&mut buf, &mut k, b"BUG: try_switch fallback: idle saved_sp=");
                        put_hex_u64(&mut buf, &mut k, idle_sp);
                        put_bytes(&mut buf, &mut k, b" also OUTSIDE idle kstack ");
                        put_hex_u64(&mut buf, &mut k, idle_kbase);
                        put_bytes(&mut buf, &mut k, b"..");
                        put_hex_u64(&mut buf, &mut k, idle_kend);
                        put_bytes(&mut buf, &mut k, b" -- halting CPU ");
                        put_dec_u64(&mut buf, &mut k, cpu as u64);
                        put_bytes(&mut buf, &mut k, b"\n");
                        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                    }
                    crate::arch::irq::disable();
                    loop {
                        unsafe { core::arch::asm!("hlt"); }
                    }
                }
                unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
                set_current_thread(pcpu, idle_id);
                // #208 Fix D: release prev → PENDING just before return.
                transition_release_to_pending(prev_id);
                return idle_sp;
            }
        }
        #[cfg(target_arch = "aarch64")]
        if !is_idle && sp >= kbase as u64 && sp < kend {
            // aarch64: ELR_EL1 at frame[32] (offset 256) must be > 64K.
            let elr = unsafe { *((sp as usize + 256) as *const u64) };
            if elr < 0x10000 {
                crate::println!(
                    "BUG: try_switch: tid={} bad frame ELR={:#x} sp={:#x} src={} prev={} task={}",
                    next_id, elr, sp, next_t.saved_sp_source, prev_id, next_t.task_id
                );
                thread_ref(next_id).killed.store(true, Ordering::Release);
                let idle_sp = thread_ref(idle_id).saved_sp;
                unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
                set_current_thread(pcpu, idle_id);
                // #208 Fix D: release prev → PENDING just before return.
                transition_release_to_pending(prev_id);
                return idle_sp;
            }
        }
    }
    // #208 Fix D: release prev → PENDING just before returning new_sp.
    // The asm caller will `mov rsp, rax` (= next_t.saved_sp) immediately
    // after this, moving cpu_old off prev's kstack within a few
    // instructions.  Peer CPUs may then dispatch prev with reasonable
    // confidence that the kstack is no longer being mutated.
    transition_release_to_pending(prev_id);
    next_t.saved_sp
}

/// Voluntarily reschedule from syscall context.
/// The trap handler must have already called `store_frame_sp()`.
/// If another thread is runnable, sets PENDING_SWITCH_SP so the trap
/// handler performs the context switch on return.
pub fn voluntary_reschedule() {
    // Disable IRQs for the entire function.
    let _irq_saved = crate::arch::irq::disable();

    let cpu = smp::cpu_id();
    drain_deferred_requeue(cpu);
    let pcpu = smp::current();
    let cur_id = pcpu.current_thread.load(Ordering::Relaxed);
    let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

    // Save frame SP into thread struct.
    let frame_sp = unsafe { thread_mut_from_ref(cur_id) }.syscall_frame_sp;
    let cur_prio;
    let cur_task;
    {
        let t = unsafe { thread_mut_from_ref(cur_id) };
        // #208 KEPOCH guard: skip if frame_sp falls outside cur_id's kstack.
        if validate_kstack_inject(cur_id, frame_sp, "voluntary_resched") {
            write_saved_sp(t, frame_sp);
            record_saved_sp_write(cur_id, frame_sp, 5); // voluntary_reschedule
            t.saved_sp_source = 2; // voluntary_reschedule
        }
        cur_prio = t.effective_priority;
        cur_task = t.task_id;
        // NOTE: state stays Running here. Set to Ready AFTER the deferred
        // store to close the orphan window (see try_switch for rationale).
    }

    // Check if there's another runnable thread before yielding.
    // We DON'T enqueue cur first — see below for why.
    // #173 Phase 2: gated dispatch — when the claim helper is enabled,
    // pop + CAS happen under the rq lock and we skip the post-pick CAS
    // below.  Legacy path is the default until A/B validation confirms
    // the new protocol under stress.
    let claimed_by_helper =
        DISPATCH_USE_CLAIM_HELPER.load(Ordering::Relaxed);
    let next_id = if claimed_by_helper {
        percpu_pick_next_and_claim(cpu, idle_id, pcpu, 2 /* vol_resched */)
    } else {
        percpu_pick_next(cpu, idle_id)
    };

    if next_id == idle_id {
        // No other thread to run — stay Running.
        return;
    }

    crate::sched::stats::CONTEXT_SWITCHES.fetch_add(1, Ordering::Relaxed);

    // Switch page tables if crossing task boundaries.
    let next_task = thread_ref(next_id).task_id;
    if cur_task != next_task {
        let next_root = {
            let tptr = TASK_TABLE.get(next_task) as *const Task;
            if !tptr.is_null() {
                unsafe { (*tptr).page_table_root }
            } else {
                0
            }
        };
        if next_root != 0 {
            crate::mm::hat::switch_page_table(next_root);
        } else {
            let kern_root = crate::mm::hat::kernel_pt_root();
            if kern_root != 0 {
                crate::mm::hat::switch_page_table(kern_root);
            }
        }
    }

    crate::arch::trapframe::update_kernel_stack(next_id as u32, thread_ref(next_id).stack_base + kstack_size());

    // NEW_INV: cur.on_cpu = ON_CPU_PENDING is stored BEFORE the slot fill and
    // BEFORE state=Ready, so rescue's stale-on-cpu predicate cannot observe
    // (state=Ready ∧ on_cpu=cpu_real). The slot's `target` field still
    // encodes cpu_real so drain knows which RQ to enqueue on.
    //
    // Defer re-enqueue of cur instead of percpu_enqueue. We are still on
    // cur's kernel stack — the assembly `mov rsp, rax` hasn't executed yet.
    // If we percpu_enqueue now, another CPU could steal cur and switch to
    // its stack while we're still using it (stack use-after-free → #DE/#GP).
    // Deferred_requeue is per-CPU: only drained by the NEXT scheduling event
    // on THIS CPU (or by remote drain after the 250ms+ stale-slot guard,
    // long after the assembly switch has completed).
    if cur_id != idle_id {
        thread_ref(cur_id).on_cpu.store(ON_CPU_PENDING, Ordering::Release);
        record_trans(cur_id as u32, 7, thread_ref(cur_id).state, ON_CPU_PENDING);
        let packed = (cur_id as u64) | ((cur_prio as u64) << 32) | ((cpu as u64) << 40);
        let old_deferred = deferred_requeue()[cpu as usize].swap(packed, Ordering::AcqRel);
        if old_deferred != 0 {
            // Defensive: voluntary_reschedule entry drains this slot first
            // (line ~2873), so old_deferred should be 0. If somehow non-zero,
            // the lost tid already has on_cpu=PENDING under NEW_INV.
            let lost_tid = (old_deferred & 0xFFFFFFFF) as u32;
            let lost_prio = ((old_deferred >> 32) & 0xFF) as u8;
            let lost_target = ((old_deferred >> 40) & 0xFF) as u32;
            crate::println!(
                "DEFERRED-OVERWRITE(vol_resched): cpu={} lost tid={} prio={} replaced by tid={} prio={}",
                cpu, lost_tid, lost_prio, cur_id, cur_prio
            );
            set_enq_tag(10);
            percpu_enqueue(lost_target, lost_prio, lost_tid);
        }
        // Set state=Ready AFTER on_cpu=PENDING and slot fill. On x86 TSO,
        // the prior Release store of PENDING is visible to any CPU that
        // observes state=Ready, so the orphan window is closed.
        unsafe { thread_mut_from_ref(cur_id) }.state = ThreadState::Ready;
        trace_sched(cur_id, 1); // 1=deferred_store
    }

    // Claim on_cpu for next (ON_CPU_PENDING → cpu).
    if next_id != idle_id {
        pcpu.dispatching_tid.store(next_id, Ordering::Release);
        // #173 Phase 2: when the claim helper ran above, it already
        // CAS'd on_cpu PENDING→cpu under the rq lock and ran the matching
        // bookkeeping (TRANS_CAS_OK, on_cpu_set_by, dispatch_cas_ok,
        // dispatch_count, state=Running).  Skip the redundant CAS path.
        // We still maintain dispatch_streak here for parity since the
        // helper doesn't touch it.
        if claimed_by_helper {
            let prev_picked = pcpu
                .last_dispatched_tid
                .swap(next_id as u32, Ordering::Relaxed);
            if prev_picked == next_id as u32 {
                pcpu.dispatch_streak.fetch_add(1, Ordering::Relaxed);
            } else {
                pcpu.dispatch_streak.store(1, Ordering::Relaxed);
            }
        } else if let Err(other_cpu) = thread_ref(next_id).on_cpu.compare_exchange(
            ON_CPU_PENDING, cpu, Ordering::AcqRel, Ordering::Acquire,
        ) {
            record_trans(next_id as u32, TRANS_CAS_FAIL, thread_ref(next_id).state, other_cpu);
            // See try_switch CAS_FAIL — benign regardless of other_cpu.
            CAS_FAIL_RESCUE_BAILS.fetch_add(1, Ordering::Relaxed);
            pcpu.dispatching_tid.store(0, Ordering::Release);
            // Undo: stay on cur_id. Drain our deferred store (it was cur).
            deferred_requeue()[cpu as usize].store(0, Ordering::Release);
            let t = unsafe { thread_mut_from_ref(cur_id) };
            t.state = ThreadState::Running;
            if cur_id != idle_id {
                thread_ref(cur_id).on_cpu.store(cpu, Ordering::Release);
            }
            // Undo page table and kernel stack changes that were made above
            // before we discovered the double-schedule. We're staying on
            // cur_id, so restore cur's page table and kernel stack pointer.
            if cur_task != next_task {
                let cur_root = {
                    let tptr = TASK_TABLE.get(cur_task) as *const Task;
                    if !tptr.is_null() {
                        unsafe { (*tptr).page_table_root }
                    } else {
                        0
                    }
                };
                if cur_root != 0 {
                    crate::mm::hat::switch_page_table(cur_root);
                }
            }
            crate::arch::trapframe::update_kernel_stack(
                cur_id as u32,
                thread_ref(cur_id).stack_base + kstack_size(),
            );
            return;
        } else {
            record_trans(next_id as u32, TRANS_CAS_OK, ThreadState::Running, cpu);
            thread_ref(next_id).on_cpu_set_by.store(2, Ordering::Relaxed); // 2=vol_resched
            // #120 dispatch-symmetry: clear pending state + bump cas_ok counter.
            dispatch_cas_ok(pcpu, next_id);
            // Set Running IMMEDIATELY after CAS — close TOCTOU window (see try_switch).
            unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
            // #120 dispatch-pattern diagnostic (vol_resched path).
            pcpu.dispatch_count.fetch_add(1, Ordering::Relaxed);
            let prev_picked = pcpu.last_dispatched_tid.swap(next_id as u32, Ordering::Relaxed);
            if prev_picked == next_id as u32 {
                pcpu.dispatch_streak.fetch_add(1, Ordering::Relaxed);
            } else {
                pcpu.dispatch_streak.store(1, Ordering::Relaxed);
            }
        }
    } else {
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
    }

    let next_t = unsafe { thread_mut_from_ref(next_id) };
    set_current_thread(pcpu, next_id);
    if next_id != idle_id {
        pcpu.dispatching_tid.store(0, Ordering::Release);
    }
    let next_sp = next_t.saved_sp;

    pending_switch_sp()[cpu as usize].store(next_sp, Ordering::Release);

    // Reprogram the timer so the deferred slot (holding cur_id) is drained
    // promptly.  Without this, the timer stays at the previous tick's value
    // (up to 200ms in the future), leaving the deferred thread un-enqueued
    // until rescue IPIs the CPU ~100ms later.
    crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);
    // Leave IRQs disabled — exception handler consumes pending_switch.
}

// --- Coscheduling ---

/// Maximum consecutive cosched picks before yielding to other threads.
const MAX_COSCHED_BURST: u32 = 4;

/// Count of coscheduling hits (for testing/diagnostics).
pub static COSCHED_HITS: AtomicU64 = AtomicU64::new(0);

// --- Scheduler Activations ---
// SA_PENDING, SA_EVENT, SA_WAITER are now embedded in Task struct,
// accessed via TASK_TABLE radix lookup for lockless access.

/// Set YIELD_ASAP for a thread, causing it to be preempted on the next timer tick.
pub fn set_yield_asap(tid: ThreadId) {
    thread_ref(tid).yield_asap.store(true, Ordering::Release);
}

/// Clear the wakeup flag for a thread. Must be called while holding the
/// relevant lock (turnstile bucket etc.) BEFORE adding the thread as a waiter,
/// to prevent a lost-wakeup race where wake_thread() sets the flag between
/// the lock drop and block_current's flag clear.
pub fn clear_wakeup_flag(tid: ThreadId) {
    thread_ref(tid).wakeup.store(false, Ordering::Release);
}

/// Block the current thread with the given reason.
/// The thread will be preempted on the next timer tick and will not
/// be re-enqueued until `wake_thread()` is called.
///
/// IMPORTANT: The caller must call `clear_wakeup_flag(tid)` while holding
/// the relevant lock, BEFORE adding itself as a waiter and dropping the lock.
pub fn block_current(_reason: BlockReason) {
    let tid = current_thread_id();
    // #135 deadlock probe: rate-limited per-tid log of who's blocking and why.
    {
        static BC_LOG_COUNT: [core::sync::atomic::AtomicU32; 16] = {
            const Z: core::sync::atomic::AtomicU32 =
                core::sync::atomic::AtomicU32::new(0);
            [Z; 16]
        };
        if (tid as usize) < BC_LOG_COUNT.len() {
            let n = BC_LOG_COUNT[tid as usize].fetch_add(1, Ordering::Relaxed);
            if n < 10 {
                let reason_tag: u32 = match _reason {
                    BlockReason::None => 0,
                    BlockReason::PortRecv(_) => 1,
                    BlockReason::PortSend(_) => 2,
                    BlockReason::PortSetRecv(_) => 3,
                    BlockReason::FutexWait => 4,
                    BlockReason::ActivationWait => 5,
                    BlockReason::ZeroPool => 6,
                    BlockReason::Sleep => 7,
                    BlockReason::PagerFault => 8,
                    BlockReason::PagerWait => 9,
                    BlockReason::WaitChild => 10,
                    BlockReason::PersonalityWait => 11,
                    BlockReason::Kswapd => 12,
                    BlockReason::SvcLookup => 13,
                    BlockReason::CallReply(_) => 14,
                    BlockReason::SuspendedMemPressure => 15,
                };
                let task_id = thread_ref(tid).task_id;
                #[cfg(target_arch = "x86_64")]
                {
                    use crate::arch::x86_64::serial::{put_byte, put_bytes, put_dec_u64};
                    let mut buf = [0u8; 64];
                    let mut k = 0;
                    put_bytes(&mut buf, &mut k, b"BC: tid=");
                    put_dec_u64(&mut buf, &mut k, tid as u64);
                    put_bytes(&mut buf, &mut k, b" task=");
                    put_dec_u64(&mut buf, &mut k, task_id as u64);
                    put_bytes(&mut buf, &mut k, b" reason=");
                    put_dec_u64(&mut buf, &mut k, reason_tag as u64);
                    put_byte(&mut buf, &mut k, b'\n');
                    crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                }
                #[cfg(not(target_arch = "x86_64"))]
                crate::println!(
                    "BC: tid={} task={} reason={}",
                    tid, task_id, reason_tag
                );
            }
        }
    }
    if matches!(_reason, BlockReason::CallReply(_)) {
        trace_point("block_current.CallReply", tid as u32);
    } else {
        trace_point("block_current.entry", tid as u32);
    }
    // #135 real-block: set state=Blocked + blocked_on=reason so try_switch
    // skips deferred_requeue (see try_switch state check) and the thread
    // leaves the runqueue entirely.  Previously this was a spin-wait with
    // a +1 priority demotion, which caused zero_daemon (base=1, demoted=2)
    // and kswapd (base=200, demoted=201) to monopolise EEVDF dispatch on
    // SMP=1 — startup_thread (base=60) never got a slice, Phase 3 never
    // ran, boot wedged in early kernel.  Real block: blocked threads truly
    // leave the runqueue; wake_thread re-enqueues them at base priority.
    let tref = thread_ref(tid);
    unsafe { thread_mut_from_ref(tid) }.blocked_on = _reason;
    // Signal the scheduler to preempt us on the next timer tick instead of
    // waiting for the full quantum.  Combined with state=Blocked this means
    // try_switch picks another thread and does NOT re-enqueue us.
    tref.yield_asap.store(true, Ordering::Release);
    // With dynamic tick, the timer might be programmed far in the future.
    // Reprogram it to fire within one tick so we get preempted promptly.
    crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);
    // Enable interrupts so the timer can preempt us.
    let saved = crate::arch::irq::save_and_enable();
    // #208 zero_daemon corruption-family fix: force at least one WFI
    // cycle before allowing wakeup-based exit.  Previously, if a
    // wake_thread arrived in the window between the caller's
    // clear_wakeup_flag and block_current's first wakeup check, the
    // loop broke immediately — no IRQ ever fired, so try_switch never
    // ran with prev=tid, so saved_sp stayed pinned at create_thread's
    // initial frame_sp.  zero_daemon then runs again, its calls
    // overwrite that frame, and the next dispatch reads a corrupted
    // iretq frame (RIP=0/CS=0) → kernel detects "BUG: try_switch bad
    // frame" → kills zero_daemon → boot resets.
    //
    // The `yielded` gate ensures we WFI at least once, which fires
    // at minimum the just-programmed timer IRQ; that IRQ runs
    // try_switch with prev=tid (yield_asap was set above), which
    // saves saved_sp to a valid IRQ frame via the try_switch.save
    // path.  Subsequent dispatches then iretq from a valid frame.
    //
    // Killed remains an immediate exit (thread is being torn down,
    // no need to preserve restart state).
    let mut yielded = false;
    loop {
        // Set state=Blocked before each WFI iteration.  Wake_thread will
        // CAS this back to Ready and enqueue when wakeup arrives.  Set
        // BEFORE the wakeup load (Release/Acquire pair) so the race
        // between this thread's wakeup check and a concurrent wake_thread
        // resolves correctly: either we see wakeup=true here (exit
        // immediately), or wake_thread sees state=Blocked and enqueues us
        // (we resume after WFI via normal dispatch).
        // #173 confirming probe: if a concurrent wake_thread already stamped
        // on_cpu=ON_CPU_PENDING (Blocked→Ready transition in flight) and we are
        // about to (re)set state=Blocked, that is the torn-creating write of the
        // block_current‖wake race — the wakeup will be lost (we stay parked while
        // the wake's Ready/enqueue is clobbered).  Count + rate-limited log.
        if tref.on_cpu.load(Ordering::Acquire) == ON_CPU_PENDING {
            let n = TORN_BLOCK_FIRES.fetch_add(1, Ordering::Relaxed);
            if n < 12 {
                let task_id = thread_ref(tid).task_id;
                let rtag: u32 = match _reason { BlockReason::FutexWait => 4, _ => 99 };
                crate::println!(
                    "TORN-BLOCK: tid={} task={} reason={} on_cpu=PENDING wakeup={} yielded={} (block_current racing wake)",
                    tid, task_id, rtag, tref.wakeup.load(Ordering::Relaxed), yielded
                );
            }
        }
        unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Blocked;
        record_trans(tid as u32, 13, ThreadState::Blocked, tref.on_cpu.load(Ordering::Relaxed));
        if tref.killed.load(Ordering::Acquire) {
            break;
        }
        if yielded && tref.wakeup.load(Ordering::Acquire) {
            break;
        }
        // Reprogram the timer to fire within one tick so try_switch runs
        // and picks another thread (we're state=Blocked, so the deferred-
        // requeue path skips us).
        crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);
        // Re-arm yield_asap — try_switch clears it when it preempts.
        tref.yield_asap.store(true, Ordering::Release);
        // WFI until next interrupt.  When we resume here (after wake +
        // re-enqueue + dispatch), state has been set to Running by
        // try_switch.  Loop top will reset state=Blocked if we didn't
        // see the wakeup — handles spurious wake.
        crate::arch::irq::wait_for_interrupt();
        yielded = true;
    }
    // We're returning to running state.  state=Blocked → Running.
    unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Running;
    unsafe { thread_mut_from_ref(tid) }.blocked_on = BlockReason::None;
    tref.yield_asap.store(false, Ordering::Release);
    // Re-apply this thread's TLS base in case it was modified while blocked
    // (e.g. by personality_set_tls from the personality server). block_current
    // is a spin-wait — the thread never goes through try_switch on wake-up,
    // so FSBASE would otherwise stay stale until a context switch.
    crate::arch::cpu::set_tls(tref.tls_base);
    // #208 root-cause fix: block_current bypasses try_switch on wake-up (see
    // the FSBASE note above) — so TSS.RSP0 is ALSO left stale.  While we were
    // parked, a timer-driven try_switch ran another thread on this CPU and set
    // TSS.RSP0 to THAT thread's kstack top.  We resume here without going
    // through set_current_thread, so RSP0 keeps pointing at the other thread's
    // kstack.  block_current returns up to the syscall handler → iretq back to
    // userspace; this thread's NEXT user→kernel transition (int 0x80) would
    // then push its entire iret frame (vector 0x80, RFLAGS 0x202, user CS/SS/
    // RSP/RIP) onto the WRONG thread's live kstack, scribbling a return-address
    // or spilled-register slot → the Phase-5 wild-RIP / corrupted-tid (#208)
    // family.  This is the missing twin of the FSBASE re-apply: re-establish
    // TSS.RSP0 for THIS thread before returning.  (Caught by TSS-RSP0-AUDIT
    // pointing at a peer's kstack; DEFENSIVE-RSP0-FIX never fired because that
    // re-check lives only in finalize_release_after_stack_switch, which the
    // block_current wake path skips.)
    #[cfg(target_arch = "x86_64")]
    {
        let kbase = tref.stack_base;
        if kbase != 0 {
            crate::arch::trapframe::update_kernel_stack(
                tid as u32,
                kbase + kstack_size(),
            );
        }
    }
    // #136 saved_sp re-sync: while we were spinning, timer-driven
    // try_switch (line 3046) may have overwritten saved_sp with a deep
    // kernel SP from the timer trap entry.  After wake-up the caller
    // returns up the stack to the original syscall x86_exception_handler,
    // which uses the LOCAL frame_sp for iretq — so for the IPI/syscall
    // entry path that's fine.  BUT: if this thread is then preempted
    // AGAIN before iretq fires (e.g. via check_preempt_on_return →
    // voluntary_reschedule), voluntary_reschedule reads saved_sp via
    // syscall_frame_sp — which is correct.  Hmm — most paths are OK.
    //
    // The pathological case (per loom-clone-thread-iretq + Phase 200a
    // boot 656): a CLONE_THREAD child's syscall blocks here, gets
    // preempted, wakes back up on a different CPU.  The next dispatch
    // for this thread restores saved_sp = the OLD timer-trap deep SP,
    // not the user trap frame.  Mirror park_current_for_ipc's explicit
    // re-sync (line 5691) here too: re-establish the invariant before
    // returning that saved_sp == syscall_frame_sp.
    // #208 KEPOCH guard.
    let _fsp_resync = tref.syscall_frame_sp;
    if validate_kstack_inject(tid, _fsp_resync, "resync_clone") {
        let t = unsafe { thread_mut_from_ref(tid) };
        write_saved_sp(t, _fsp_resync);
        record_saved_sp_write(tid, _fsp_resync, 6); // resync clone-thread
    }
    crate::arch::irq::restore(saved);
}

/// Raise a thread's effective priority to `new_prio` *if* that represents a
/// priority increase (i.e. a lower numeric value in Telix's convention where
/// 0 = highest, 254 = lowest non-idle). Returns the thread's prior
/// `effective_priority` so the caller can save it for later restoration.
///
/// Used by IPC priority-inheritance donation (`call_reply::donate_priority`).
/// Writes both the `prio` atomic (read by try_switch and wake_thread) and
/// the per-thread `effective_priority` field.
///
/// NOTE: This does not re-enqueue a ready thread at the new priority — the
/// next try_switch tick will pick up the change via the `prio` atomic. For
/// the IPC donation use case, the server is either currently running (just
/// returned from recv_with_cap) or about to be woken (DirectTransfer), so
/// no mid-queue re-sorting is required.
pub fn raise_thread_priority_to(tid: ThreadId, new_prio: u8) -> u8 {
    let tref = thread_ref(tid);
    let old = tref.effective_priority;
    if new_prio < old {
        tref.prio.store(new_prio, Ordering::Release);
        unsafe { thread_mut_from_ref(tid) }.effective_priority = new_prio;
    }
    old
}

/// Restore a thread's effective priority to a saved value. Counterpart to
/// `raise_thread_priority_to`; called when IPC donation is unwound.
///
/// Unconditional write: callers record the exact pre-donation value and
/// expect that value to be re-installed on any terminal path (reply,
/// caller death, server death).
pub fn restore_thread_priority(tid: ThreadId, saved_prio: u8) {
    let tref = thread_ref(tid);
    tref.prio.store(saved_prio, Ordering::Release);
    unsafe { thread_mut_from_ref(tid) }.effective_priority = saved_prio;
}

/// Layer 3 paravirt: steal-aware wake-target selection.  When the
/// caller's natural enqueue target (`default_cpu`) has accumulated
/// significant host-steal since its last successful dispatch, prefer
/// a less-stolen CPU instead.  This breaks the thrashing pattern
/// where waking threads land on a host-paused CPU, pend for seconds,
/// get rescued to a fresh CPU, then run briefly and re-pend on the
/// SAME host-paused CPU because last_cpu drives the next wake target.
///
/// Returns `default_cpu` when:
///   - steal-time isn't available (bare metal / pre-init),
///   - only one CPU online,
///   - `default_cpu` has less than `HEAVY_STEAL_NS` of recent steal,
///   - or no other CPU has materially less recent steal.
///
/// Cost: one steal-time MSR-page read per CPU (small fixed-size loop;
/// NR_CPUS is 4–8 in typical Telix configurations).  Cold path —
/// called only from wake_thread / wake_parked_thread, not from the
/// dispatch loop.
fn choose_wake_target_steal_aware(default_cpu: u32) -> u32 {
    const HEAVY_STEAL_NS: u64 = 200_000_000; // 200ms — same threshold as fast-rescue
    const ADVANTAGE_NS: u64 = 100_000_000; // must beat default by ≥100ms to migrate
    // Layer 4 paravirt: IPI-delivery health.  A vCPU can be online and
    // dispatching but persistently not receive IPIs sent to it (residual
    // #135 / virt-IPI-delivery pathology).  Steal-time can't see this —
    // the CPU isn't being stolen, it just isn't getting woken up.  If
    // the default target's IPI-receipt latency exceeds its own adaptive
    // EWMA threshold (Stage-1 autotune: μ + K·MAD, bounded by absolute
    // floor/ceiling), AND a peer has fresh IPI activity, reroute there.
    //
    // Stage 1 replaces the hand-coded IPI_STALE_NS with a per-CPU
    // adaptive threshold derived from the EWMA mean/MAD of inter-
    // arrival times, updated at every IPI handler entry (see
    // arch::x86_64::exception).  The hand-coded floor/ceiling guard
    // against (a) under-sampled CPUs whose EWMA is meaningless and
    // (b) absurd outliers regardless of estimated variance.
    const IPI_STALE_FLOOR_NS: u64 = 200_000_000;  // never trigger below this
    const IPI_STALE_CEIL_NS: u64 = 5_000_000_000; // always trigger by this
    const IPI_THRESHOLD_K: u64 = 4;               // μ + K·MAD multiplier
    const IPI_FRESH_NS: u64 = 200_000_000;        // peer must have one within 200ms
    let ncpus = smp::num_cpus() as u32;
    if ncpus <= 1 {
        return default_cpu;
    }
    let recent_steal = |cpu: u32| -> u64 {
        let pc = smp::get(cpu);
        let steal_now = crate::arch::hypervisor::ops()
            .steal_time_ns_of_cpu(cpu)
            .unwrap_or(0);
        let steal_at_disp = pc.steal_ns_at_last_dispatch.load(Ordering::Relaxed);
        steal_now.saturating_sub(steal_at_disp)
    };
    let now_ns = get_monotonic_ns();
    let ipi_staleness = |cpu: u32| -> u64 {
        let pc = smp::get(cpu);
        let last = pc.last_ipi_recv_ns.load(Ordering::Relaxed);
        if last == 0 { 0 } else { now_ns.saturating_sub(last) }
    };
    // Stage-1 adaptive threshold for IPI staleness on a candidate CPU.
    // Returns the staleness duration above which we consider that CPU
    // "IPI-starved" — used to gate the reroute decision below.
    let ipi_stale_threshold = |cpu: u32| -> u64 {
        let pc = smp::get(cpu);
        let mean = pc.ipi_interarrival_mean_ns.load(Ordering::Relaxed);
        let mad = pc.ipi_interarrival_mad_ns.load(Ordering::Relaxed);
        // Pre-EWMA bootstrap: if no data yet, be conservative (only fire
        // at the absolute ceiling).
        if mean == 0 {
            return IPI_STALE_CEIL_NS;
        }
        let adaptive = mean.saturating_add(mad.saturating_mul(IPI_THRESHOLD_K));
        adaptive.max(IPI_STALE_FLOOR_NS).min(IPI_STALE_CEIL_NS)
    };

    let default_steal = recent_steal(default_cpu);
    let default_ipi_stale = ipi_staleness(default_cpu);
    let default_threshold = ipi_stale_threshold(default_cpu);

    // Tier 1: heavy host steal on default → look for less-stolen peer
    // that is ALSO not IPI-starved.  Boot 534 surfaced the trap: an
    // IPI-starved vCPU (cpu=3 in that boot, 627 IPIs/hour vs peers'
    // 18000+) has near-zero accumulated steal_time precisely because
    // the host isn't bothering to schedule it.  A naive least-stolen
    // pick would route work to that vCPU, where it would then never
    // be woken.  Filter candidates by IPI freshness before comparing.
    if default_steal >= HEAVY_STEAL_NS {
        let mut best_cpu = default_cpu;
        let mut best_steal = default_steal;
        for c in 0..ncpus {
            if c == default_cpu { continue; }
            if ipi_staleness(c) >= ipi_stale_threshold(c) {
                // IPI-starved peer — would be a worse target than the
                // host-stolen default.  Skip.
                continue;
            }
            let s = recent_steal(c);
            if s + ADVANTAGE_NS <= best_steal {
                best_steal = s;
                best_cpu = c;
            }
        }
        if best_cpu != default_cpu {
            STEAL_AWARE_REROUTES.fetch_add(1, Ordering::Relaxed);
        }
        return best_cpu;
    }

    // Tier 2: IPI-delivery shortage on default → look for an IPI-fresh peer.
    // Threshold is per-CPU adaptive (μ + K·MAD bounded by floor/ceiling).
    // Only fires when at least one peer has fresh IPI activity (≤200ms),
    // so we don't misroute at boot when no IPIs have fired anywhere yet.
    if default_ipi_stale >= default_threshold {
        for c in 0..ncpus {
            if c == default_cpu { continue; }
            if ipi_staleness(c) <= IPI_FRESH_NS {
                IPI_STALE_REROUTES.fetch_add(1, Ordering::Relaxed);
                return c;
            }
        }
    }

    default_cpu
}

/// Counts wake-target reroutes by `choose_wake_target_steal_aware`.
/// Each increment is one wake_thread / wake_parked_thread call that
/// chose a different CPU than the caller's natural choice because
/// the default was being heavily host-stolen.  Surfaced in the
/// WATCHDOG IPC-stall dump alongside fast_takeover.
static STEAL_AWARE_REROUTES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Counts wake-target reroutes triggered by IPI-delivery staleness on
/// the default target.  Distinct from `STEAL_AWARE_REROUTES`: this
/// fires when the default vCPU is *not* being host-stolen but simply
/// isn't receiving IPIs (residual #135 / virt-IPI pathology).  Without
/// this signal, steal-aware routing leaves these wakeups on a vCPU
/// that won't be reached and the rescue has to migrate every wake-
/// pending pair via the slow 1.5–3s timeout path.
static IPI_STALE_REROUTES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Wake a blocked thread, making it runnable.
pub fn wake_thread(tid: ThreadId) {
    let tref = thread_ref(tid);
    tref.wakeup.store(true, Ordering::Release);
    // Clear yield_asap so the thread isn't preempted on the very next tick
    // before it can check the wakeup flag and exit block_current.
    tref.yield_asap.store(false, Ordering::Release);
    // #135 real-block: if the thread is state=Blocked (off the runqueue
    // entirely), transition to Ready and enqueue at base priority.  This
    // is the wake path for block_current's real-block.  Done BEFORE the
    // demoted-prio path below: blocked threads aren't demoted any more.
    //
    // Acquire fence (via the load ordering) ensures we observe the
    // block_current's state=Blocked store after our wakeup=true Release.
    {
        let state = thread_ref(tid).state;
        if state == ThreadState::Blocked {
            // Boot 551 #192 fix: if the thread is parked on a turnstile
            // (`ts_blocked_on != 0`), remove it from that list and clear
            // `ts_blocked_on` BEFORE transitioning to Ready.  Without
            // this, the woken thread runs and calls a syscall that
            // tries to park on a different turnstile via `ts_enqueue`,
            // which unconditionally `tref.ts_next.store(NIL)` —
            // breaking the prior list's forward chain at that point
            // (boot 545/548 wc>walked corruption shape).  The new
            // `TS-DOUBLE-ENQ` guard in `ts_enqueue` would catch this
            // and refuse, but the legitimate fix is to never leave a
            // turnstile-parked thread Ready with `ts_blocked_on` set.
            // `cleanup_blocked` does the right dance: swap-zero the
            // field, take the right bucket lock, ts_remove, hamt_remove
            // if empty, attach TS to thread or free.
            if tref.ts_blocked_on.load(Ordering::Relaxed) != 0 {
                crate::sync::turnstile::cleanup_blocked(tid);
            }
            // Transition Blocked → Ready and enqueue at base prio.  Use
            // the *waker's* CPU as the enqueue target because (a) we hold
            // its run-queue contended only by other CPUs' rescue paths,
            // (b) cache locality if the wake-event data was just
            // produced on this CPU.  percpu_enqueue's in_queue swap is
            // the double-enqueue guard if a concurrent path also
            // enqueues.
            // NEW_INV: on_cpu must be ON_CPU_PENDING before state=Ready.  Every
            // other wake/Ready-transition site does this store; wake_thread was
            // the lone gap.  Without it the woken thread keeps the stale CPU it
            // last ran on before blocking, so the #173 claim helper's pop+CAS
            // (PENDING->cpu) on the next pick FAILS (on_cpu != PENDING) and the
            // helper DROPS it off the heap -> orphan (Ready, on_cpu=realcpu, not
            // enqueued), which the rescue then bounces cpu-to-cpu: the #198
            // tid=17 (compositor_srv) starvation.  Benign under the legacy pick
            // (dequeue_set_pending overwrote on_cpu=PENDING after the pop), but
            // an orphan source under the claim helper (gate=ON default on x86_64).
            tref.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
            unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Ready;
            record_trans(tid as u32, 14, ThreadState::Ready, ON_CPU_PENDING);
            tref.prio.store(tref.base_priority, Ordering::Release);
            unsafe { thread_mut_from_ref(tid) }.effective_priority =
                tref.base_priority;
            // Layer 3 paravirt: steal-aware target.  Default = waker's
            // CPU (cache locality), but reroute to a less-stolen CPU
            // when the waker is being host-paused — the woken thread
            // would otherwise pend on this stolen CPU and thrash
            // through the rescue path.
            let target_cpu = choose_wake_target_steal_aware(smp::cpu_id());
            set_enq_tag(3); // 3=wake_thread
            percpu_enqueue(target_cpu, tref.base_priority, tid);
            // Reprogram timer so try_switch runs and picks us up promptly.
            crate::arch::timer::program_oneshot_ns(
                get_monotonic_ns() + TICK_INTERVAL_NS
            );
            // If the woken thread had been running on a different CPU,
            // and that CPU is currently HLT-idle, no try_switch will
            // run there until an interrupt arrives.  Send a reschedule
            // IPI so it picks up the queue change (parallels the
            // existing demoted-prio path below + the wake_parked_thread
            // IPI sites — without it, blocked-then-woken threads can
            // sit in the queue indefinitely on idle CPUs).
            let old_cpu = tref.last_cpu.load(Ordering::Relaxed);
            if old_cpu != target_cpu
                && (old_cpu as usize) < crate::sched::smp::num_cpus()
            {
                crate::arch::irq::send_reschedule_ipi(old_cpu);
            }
            return;
        }
    }
    // If the thread was demoted by block_current, restore its priority
    // and send an IPI so it exits the WFI loop promptly.
    let demoted_prio = tref.prio.load(Ordering::Acquire);
    let base = tref.base_priority;
    if demoted_prio > base {
        // Restore prio to base BEFORE attempting remove.
        tref.prio.store(base, Ordering::Release);

        let old_cpu = tref.last_cpu.load(Ordering::Relaxed);
        let waker_cpu = smp::cpu_id();
        // Remove from old CPU's queue and re-enqueue at base prio.
        let removed = {
            if old_cpu as usize == waker_cpu as usize {
                if let Some(mut rq) = percpu_rq()[old_cpu as usize].try_lock() {
                    rq.remove_tid(tid)
                } else {
                    false
                }
            } else {
                let mut rq = percpu_rq()[old_cpu as usize].lock();
                rq.remove_tid(tid)
            }
        };
        if removed {
            trace_sched(tid, 9); // 9=wake_enq
            set_enq_tag(3); // 3=wake_thread
            percpu_enqueue(waker_cpu, base, tid);
        } else {
            trace_sched(tid, 10); // 10=wake_no_enq
            if old_cpu != waker_cpu {
                crate::arch::irq::send_reschedule_ipi(old_cpu);
            }
        }
    }
    // If a DIFFERENT thread with higher priority was woken on this CPU,
    // set need_resched so check_preempt_on_return triggers an immediate
    // voluntary reschedule at the next syscall return boundary.
    // Skip when waking ourselves (e.g., sleep timer waking us from block_current).
    {
        let waker_cpu = smp::cpu_id();
        let pcpu = smp::get(waker_cpu);
        let cur_tid = pcpu.current_thread.load(Ordering::Relaxed);
        if tid != cur_tid {
            let cur_prio = thread_ref(cur_tid).effective_priority;
            let woken_prio = tref.base_priority;
            if woken_prio < cur_prio {
                pcpu.need_resched.store(true, Ordering::Release);
                // Reprogram timer to fire within one tick for prompt preemption.
                // Under dynamic tick, the timer may be set far out (up to
                // MAX_IDLE_NS) if the CPU was idle. With IRQs enabled during
                // syscalls, this ensures the timer fires mid-syscall and
                // try_switch() preempts to the higher-priority thread.
                crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);
            }
        }
    }
    // Handle IPC-parked threads (park_current_for_ipc with PARK_COMMITTED).
    // These threads are off-CPU and can only be woken by wake_parked_thread,
    // which requires coordination with frame injection (inject_recv_into_frame).
    //
    // For CallReply-blocked threads, we use the reply cap's state CAS as a
    // coordination mechanism: CAS the cap PENDING→ABANDONED.  If we win,
    // the server's future fulfill() will see ABANDONED and skip frame
    // injection + wake.  If the server already fulfilled, our CAS fails and
    // the server owns the wake.  This avoids the frame corruption race.
    //
    // BUT: only fire the abandon path when the wake represents a *genuine*
    // interruption — i.e., the thread has been killed or has a pending
    // unmasked signal.  Incidental wake_thread calls (a stale wake left
    // over from a previous block_current iteration, a port_wake_one for an
    // earlier turnstile membership, an IPI-driven reschedule attempt) must
    // NOT cancel a legitimate in-flight call/reply.  Cancelling such a call
    // not only frees the cap slot prematurely (allowing reuse before the
    // server replies — the server's fulfill then fails harmlessly, but the
    // caller has been mis-informed via CALL_REPLY_INTERRUPTED) but, in the
    // worst case under rapid call cycles, can race with a fresh sys_call
    // that has just re-published `blocked_on = CallReply(new_slot)` after
    // park_state has been re-armed to PARK_COMMITTED — abandoning a brand-
    // new pending cap with no actual interrupt request behind the wake.
    {
        let park = tref.park_state.load(Ordering::Acquire);
        if park == PARK_COMMITTED {
            let t = unsafe { &*(THREAD_TABLE.get(tid) as *const Thread) };
            // Only abandon if there's a genuine interrupt request: thread
            // killed, or a deliverable (unmasked) signal pending.  This
            // mirrors the syscall-return signal-check predicate.
            let killed = tref.killed.load(Ordering::Acquire);
            let has_signal = (t.sig_pending & !t.sig_mask) != 0;
            if (killed || has_signal) && let BlockReason::CallReply(slot) = t.blocked_on {
                if crate::ipc::call_reply::abandon_for_interrupt(slot, tid) {
                    // We won: cap is ABANDONED. Inject an interrupted-call
                    // error into the thread's saved frame so userspace sees a
                    // clean error rather than stale register values.
                    let sp = thread_saved_sp(tid);
                    if sp != 0 && validate_kstack_inject(tid, sp, "abandon_interrupt") {
                        let tag = crate::ipc::call_reply::CALL_REPLY_INTERRUPTED;
                        unsafe {
                            use crate::arch::trapframe::ExceptionFrame;
                            let frame = &mut *(sp as *mut ExceptionFrame);
                            crate::syscall::handlers::set_return(frame, 0);
                            crate::syscall::handlers::set_reg(frame, 1, tag);
                            crate::syscall::handlers::set_reg(frame, 2, 0);
                            crate::syscall::handlers::set_reg(frame, 3, 0);
                            crate::syscall::handlers::set_reg(frame, 4, 0);
                            crate::syscall::handlers::set_reg(frame, 5, 0);
                            crate::syscall::handlers::set_reg(frame, 6, 0);
                            crate::syscall::handlers::set_reg(frame, 7, 0);
                        }
                    }
                    // Free the cap slot (leases/donation already unwound by
                    // abandon_for_interrupt).
                    let cap_gen = crate::ipc::call_reply::REPLY_CAPS[slot as usize]
                        .generation
                        .load(Ordering::Acquire);
                    crate::ipc::call_reply::free(
                        (slot as u64) | ((cap_gen as u64) << 32),
                    );
                    wake_parked_thread(tid);
                }
                // If abandon_for_interrupt returned false, the server already
                // fulfilled or is mid-reply. Its wake_parked_thread will
                // handle the wake. Nothing more to do.
            }
            // For non-CallReply COMMITTED threads (PortRecv, PagerFault),
            // their legitimate wakers will handle them. Signal delivery for
            // those block types is a future enhancement.
        }
    }
    // Signal all CPUs so any core spinning in block_current's WFE wakes immediately.
    crate::arch::irq::send_event();
}

// ── #164 Memory-scheduler suspend/resume ───────────────────────────
//
// VMS-style balance set: when memory pressure persists past what the
// admission gate (#160 Stage 3) can refuse, the long-term scheduler
// picks an existing task as the eviction candidate and suspends ALL
// its threads.  WSCLOCK then evicts the suspended task's working set
// aggressively (its pages have no active references and become
// reclaim-first).  When pressure drops, resume_task brings the threads
// back to Ready; the page-fault path demand-pages the working set
// from swap.

/// Number of threads transitioned by the most recent suspend/resume
/// call, surfaced for diagnostics in the WATCHDOG dump.
static LAST_SUSPEND_COUNT: AtomicU32 = AtomicU32::new(0);
static LAST_RESUME_COUNT: AtomicU32 = AtomicU32::new(0);

/// #164 Suspend every thread of `task_id`.  Ready/Running threads
/// transition to Blocked with reason=SuspendedMemPressure.  Threads
/// already Blocked for other reasons are left alone (their original
/// wakeup will fire normally; if they re-enter Ready while their task
/// is still suspended, resume_task will catch them next pass — or, in
/// the strict policy, we'd convert them too).  Dead threads are
/// skipped.  Returns the count of threads transitioned.
pub fn suspend_task(task_id: u32) -> u32 {
    let mut transitioned = 0u32;
    SCHED_THREAD_ART.for_each(|key, val| {
        let t = unsafe { &*(val as *const Thread) };
        if t.task_id != task_id {
            return;
        }
        match t.state {
            ThreadState::Ready | ThreadState::Running => {
                let tid = key as u32;
                let tref = thread_ref(tid);
                unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Blocked;
                unsafe { thread_mut_from_ref(tid) }.blocked_on =
                    BlockReason::SuspendedMemPressure;
                record_trans(tid, 16, ThreadState::Blocked, tref.on_cpu.load(Ordering::Relaxed));
                transitioned += 1;
            }
            _ => {}
        }
    });
    LAST_SUSPEND_COUNT.store(transitioned, Ordering::Relaxed);
    if transitioned > 0 {
        crate::println!(
            "[mem-sched] SUSPEND task={} ({} threads transitioned)",
            task_id, transitioned,
        );
    }
    transitioned
}

/// #164 Resume every thread of `task_id` that was suspended by
/// `suspend_task`.  Transitions Blocked+SuspendedMemPressure threads
/// to Ready and enqueues them at base priority.  Other Blocked
/// threads (e.g., real IPC waits) stay put.  Returns the count of
/// threads transitioned.
pub fn resume_task(task_id: u32) -> u32 {
    let mut transitioned = 0u32;
    SCHED_THREAD_ART.for_each(|key, val| {
        let t = unsafe { &*(val as *const Thread) };
        if t.task_id != task_id {
            return;
        }
        if t.state == ThreadState::Blocked
            && matches!(t.blocked_on, BlockReason::SuspendedMemPressure)
        {
            let tid = key as u32;
            let tref = thread_ref(tid);
            // Boot 552 #196 sweep: parallel to wake_thread (eda25f4) — a
            // thread suspended by mem-pressure might have been on a
            // turnstile when suspended.  Resume must remove it from the
            // stale turnstile so subsequent ts_enqueue (when it parks
            // again on a new port) doesn't clobber the prior list.
            if tref.ts_blocked_on.load(Ordering::Relaxed) != 0 {
                crate::sync::turnstile::cleanup_blocked(tid);
            }
            unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Ready;
            unsafe { thread_mut_from_ref(tid) }.blocked_on = BlockReason::None;
            record_trans(tid, 17, ThreadState::Ready, tref.on_cpu.load(Ordering::Relaxed));
            tref.prio.store(tref.base_priority, Ordering::Release);
            // Enqueue on the current CPU for cache locality at resume time.
            let target_cpu = smp::cpu_id();
            set_enq_tag(4); // 4=resume_task
            percpu_enqueue(target_cpu, tref.base_priority, tid);
            transitioned += 1;
        }
    });
    LAST_RESUME_COUNT.store(transitioned, Ordering::Relaxed);
    if transitioned > 0 {
        crate::println!(
            "[mem-sched] RESUME task={} ({} threads transitioned)",
            task_id, transitioned,
        );
    }
    transitioned
}

/// #164 read-only accessors for diagnostics.
pub fn last_suspend_count() -> u32 {
    LAST_SUSPEND_COUNT.load(Ordering::Relaxed)
}

/// #164 Pick the best suspend candidate for memory-pressure eviction.
/// Selection criterion: maximum working-set among non-kernel,
/// non-already-suspended tasks.  Larger WS means more memory reclaimed
/// per suspend.  Returns None if no eligible candidate exists.
///
/// Future iterations can refine the score (priority weighting,
/// last-touched-time bias, balance-set tunables).  For now: just WS.
pub fn pick_suspend_candidate() -> Option<u32> {
    let mut best_task_id: Option<u32> = None;
    let mut best_ws: u32 = 0;
    SCHED_TASK_ART.for_each(|key, val| {
        let task_id = key as u32;
        if task_id == 0 {
            return;  // kernel task — never suspend
        }
        let task = unsafe { &*(val as *const Task) };
        if !task.active || task.exited {
            return;
        }
        let aspace_id = task.aspace_id;
        if aspace_id == 0 {
            return;  // no aspace, nothing to evict
        }
        // Skip if ANY thread of this task is already SuspendedMemPressure.
        let mut already_suspended = false;
        SCHED_THREAD_ART.for_each(|tkey, tval| {
            let t = unsafe { &*(tval as *const Thread) };
            if t.task_id == task_id
                && t.state == ThreadState::Blocked
                && matches!(t.blocked_on, BlockReason::SuspendedMemPressure)
            {
                already_suspended = true;
                let _ = tkey;
            }
        });
        if already_suspended {
            return;
        }
        let ws = crate::mm::aspace::working_set(aspace_id);
        if ws > best_ws {
            best_ws = ws;
            best_task_id = Some(task_id);
        }
    });
    best_task_id
}

/// #164 Try to evict an existing task's working set wholesale to relieve
/// memory pressure.  Picks a candidate via `pick_suspend_candidate`,
/// suspends its threads, then aggressively scans its aspace with WSCLOCK
/// to drive eviction.  Returns Some((task_id, pages_freed)) on success,
/// None if no candidate or eviction failed.
///
/// Note: the FIRST scan immediately after suspend mostly just clears
/// access bits (since the threads were just running).  The actual
/// eviction happens on subsequent kswapd cycles — the suspended threads
/// don't touch their pages, so the bits stay clear and the pages
/// become reclaim-eligible.  This function returns immediately after
/// kicking off the first scan; full reclaim takes 1-2 more kswapd
/// cycles.
pub fn try_balance_set_evict() -> Option<(u32, usize)> {
    let candidate = pick_suspend_candidate()?;
    let task = task_ref(candidate);
    // Re-validate post-pick: between iteration and suspend, the task
    // could have exited and its slot been recycled.  If active is
    // false now, bail rather than suspend a fresh tenant of the same
    // slot.
    if !task.active || task.exited {
        return None;
    }
    let aspace_id = task.aspace_id;
    if aspace_id == 0 {
        return None;
    }
    let ws_before = crate::mm::aspace::working_set(aspace_id);
    let transitioned = suspend_task(candidate);
    if transitioned == 0 {
        return None;
    }
    // Aggressive first-pass scan to clear access bits.  Use a target
    // 4× the kswapd cadence so we sweep the full aspace if reasonable.
    let target = (ws_before as usize).saturating_mul(2).max(256);
    let scan = crate::mm::wsclock::scan(aspace_id, target);
    crate::mm::stats::BALANCE_SET_EVICTS
        .fetch_add(1, Ordering::Relaxed);
    crate::mm::stats::BALANCE_SET_SUSPENDED
        .fetch_add(transitioned as u64, Ordering::Relaxed);
    crate::println!(
        "[mem-sched] EVICT task={} aspace={} ws_before={} suspended={} target={} freed={} cleared={}",
        candidate, aspace_id, ws_before, transitioned, target,
        scan.pages_freed, scan.ptes_cleared,
    );
    Some((candidate, scan.pages_freed))
}

pub fn last_resume_count() -> u32 {
    LAST_RESUME_COUNT.load(Ordering::Relaxed)
}

/// #164 Find one suspended task to resume.  Simple FIFO-ish policy:
/// return the lowest-task_id task that has at least one
/// SuspendedMemPressure thread.  No timestamps required — when more
/// than one task is suspended, prefer the one allocated earliest as a
/// rough age proxy.  Future iterations could track a "suspended_at"
/// timestamp on Task for true FIFO, but for now the task_id is good
/// enough since task IDs are assigned in approximately allocation
/// order.
pub fn pick_resume_candidate() -> Option<u32> {
    let mut best: Option<u32> = None;
    SCHED_THREAD_ART.for_each(|_, val| {
        let t = unsafe { &*(val as *const Thread) };
        if t.state == ThreadState::Blocked
            && matches!(t.blocked_on, BlockReason::SuspendedMemPressure)
        {
            match best {
                None => best = Some(t.task_id),
                Some(prev) if t.task_id < prev => best = Some(t.task_id),
                _ => {}
            }
        }
    });
    best
}

/// #164 Try to resume a suspended task when memory pressure has eased.
/// Returns Some(task_id) if one was resumed.
pub fn try_balance_set_resume() -> Option<u32> {
    let candidate = pick_resume_candidate()?;
    let transitioned = resume_task(candidate);
    if transitioned == 0 {
        return None;
    }
    Some(candidate)
}

/// Called on syscall return. If need_resched was set (by wake_thread or a
/// blocking path on this CPU), perform an immediate voluntary reschedule so
/// the higher-priority thread runs without waiting for the next timer tick.
pub fn check_preempt_on_return() {
    // If a context switch is already staged (from park_current_for_ipc,
    // voluntary_reschedule, or handoff_to during this syscall), don't
    // call voluntary_reschedule again — it would read the switched-to
    // thread's stale syscall_frame_sp and corrupt its saved_sp.
    if has_pending_switch() {
        return;
    }
    let cpu = smp::cpu_id();
    let pcpu = smp::get(cpu);
    if pcpu.need_resched.swap(false, Ordering::AcqRel) {
        voluntary_reschedule();
    }
}

/// Check if a thread has been marked for kill.
pub fn is_killed(tid: ThreadId) -> bool {
    thread_ref(tid).killed.load(Ordering::Acquire)
}

/// Check if a thread is in Dead state (already exiting/exited).
pub fn is_dead(tid: ThreadId) -> bool {
    thread_ref(tid).state == ThreadState::Dead
}

/// Kill all threads in the task that `tid` belongs to.
/// Returns true if the thread was found and the kill signal was sent.
/// Kill all threads in the task that thread `tid` belongs to.
pub fn kill_task(tid: ThreadId) -> bool {
    if tid as usize >= RadixTable::capacity() {
        return false;
    }
    let task_id = {
        let target_thread = match thread_ref_opt(tid) {
            Some(t) => t,
            None => return false,
        };
        if target_thread.state == ThreadState::Dead && target_thread.stack_base == 0 {
            return false;
        }
        target_thread.task_id
    };
    kill_task_by_id(task_id)
}

/// Kill all threads in the given task (by task_id).
pub fn kill_task_by_id(task_id: TaskId) -> bool {
    const MAX_KILL: usize = 64;
    let mut to_kill = [0u32; MAX_KILL];
    let mut kill_count = 0usize;
    {
        let task = match task_ref_opt(task_id) {
            Some(t) => t,
            None => return false,
        };
        if !task.active {
            return false;
        }
        SCHED_THREAD_ART.for_each(|key, val| {
            let t = unsafe { &*(val as *const Thread) };
            if t.task_id == task_id && t.state != ThreadState::Dead && t.stack_base != 0 {
                t.killed.store(true, Ordering::Release);
                if kill_count < MAX_KILL {
                    to_kill[kill_count] = key as u32;
                    kill_count += 1;
                }
            }
        });
    }
    for i in 0..kill_count {
        let tid = to_kill[i] as ThreadId;
        // If the thread is sleeping, remove from sleep queue and enqueue directly
        // so it exits promptly instead of waiting for the deadline.
        let t = unsafe { thread_mut_from_ref(tid) };
        if t.state == ThreadState::Blocked && matches!(t.blocked_on, BlockReason::Sleep) {
            sleep_queue_remove(tid);
            // Wait for the thread's parking stack switch to complete.
            while thread_ref(tid).stack_switch_pending.load(Ordering::Acquire) {
                core::hint::spin_loop();
            }
            // NEW_INV: on_cpu must be ON_CPU_PENDING before state=Ready
            // (was u32::MAX from park_for_sleep).
            thread_ref(tid).on_cpu.store(ON_CPU_PENDING, Ordering::Release);
            // #135 action=20: kill_thread waking a Sleep-blocked victim.
            // If a rescue captures a tid whose TRANS-RING ends with
            // action=20 just before the orphan signature, the victim
            // was kill-promoted out of sleep and the wake path didn't
            // complete percpu_enqueue.  Otherwise this path is rare
            // (only fires during kill_thread on a Sleep-blocked target).
            record_trans(tid as u32, 20, ThreadState::Ready, ON_CPU_PENDING);
            t.state = ThreadState::Ready;
            t.blocked_on = BlockReason::None;
            t.sleep_deadline_ns = 0;
            let target = t.last_cpu.load(Ordering::Relaxed);
            set_enq_tag(9); // 9=kill_sleep
            // Layer 3/4 paravirt: avoid waking onto a starved/stolen CPU.
            let target = choose_wake_target_steal_aware(target);
            percpu_enqueue(target, t.effective_priority, tid);
        } else {
            wake_thread(tid);
        }
    }
    kill_count > 0
}

/// Send a signal to a task (process-directed). Queues on the first
/// thread in the task that has the signal unmasked, or the first thread.
/// SIGKILL always uses the old kill path (immediate termination).
pub fn send_signal_to_task(task_id: u32, sig: u32) -> bool {
    use super::task::{MAX_SIGNALS, SIGKILL, sig_bit};
    if sig < 1 || sig > MAX_SIGNALS as u32 {
        return false;
    }
    if sig == SIGKILL {
        return kill_task_by_id(task_id);
    }

    let bit = sig_bit(sig);

    // Check handler disposition (lock-free).
    let task = match task_ref_opt(task_id) {
        Some(t) => t,
        None => return false,
    };
    if !task.active {
        return false;
    }
    let action = &task.sig_actions[(sig - 1) as usize];
    if action.handler == super::task::SigHandler::Ignore {
        return true; // accepted but ignored
    }
    if action.handler == super::task::SigHandler::Default && !super::task::sig_default_is_term(sig)
    {
        return true;
    }

    // Find a thread to receive: prefer one with signal unmasked.
    let mut target: Option<u32> = None;
    let mut any_thread: Option<u32> = None;
    SCHED_THREAD_ART.for_each(|key, val| {
        if target.is_some() {
            return;
        }
        let t = unsafe { &*(val as *const Thread) };
        if t.task_id == task_id && t.state != ThreadState::Dead && t.stack_base != 0 {
            if any_thread.is_none() {
                any_thread = Some(key as u32);
            }
            if t.sig_mask & bit == 0 {
                target = Some(key as u32);
            }
        }
    });
    let tid = match target.or(any_thread) {
        Some(t) => t,
        None => return false,
    };

    // Safe: sig_pending is only ORed (no lost updates for single-bit sets).
    unsafe { thread_mut_from_ref(tid) }.sig_pending |= bit;

    // Wake the target thread so it can deliver the signal.
    wake_thread(tid as ThreadId);
    true
}

/// Send a signal to a specific thread.
pub fn send_signal_to_thread(tid: ThreadId, sig: u32) -> bool {
    use super::task::{MAX_SIGNALS, SIGKILL, sig_bit};
    if sig < 1 || sig > MAX_SIGNALS as u32 {
        return false;
    }
    if tid as usize >= RadixTable::capacity() {
        return false;
    }
    if sig == SIGKILL {
        return kill_task(tid);
    }

    let bit = sig_bit(sig);
    let t = match thread_ref_opt(tid) {
        Some(t) => t,
        None => return false,
    };
    if t.state == ThreadState::Dead || t.stack_base == 0 {
        return false;
    }
    // Safe: sig_pending is only ORed (single-bit set, no lost updates).
    unsafe { thread_mut_from_ref(tid) }.sig_pending |= bit;
    wake_thread(tid);
    true
}

/// Get and clear the next deliverable signal for the current thread.
/// Returns Some(signal_number) if there's a pending, unmasked signal.
pub fn dequeue_signal() -> Option<u32> {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let t = thread_ref(tid);
    let deliverable = t.sig_pending & !t.sig_mask;
    if deliverable == 0 {
        return None;
    }
    // Find lowest-numbered signal.
    let bit_idx = deliverable.trailing_zeros();
    let sig = bit_idx + 1;
    // Safe: only the current thread dequeues its own signals.
    unsafe { thread_mut_from_ref(tid) }.sig_pending &= !(1u64 << bit_idx);
    Some(sig)
}

/// Get the signal action for a signal in the current thread's task.
pub fn get_signal_action(sig: u32) -> Option<super::task::SignalAction> {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let task_id = thread_ref(tid).task_id;
    let task = task_ref(task_id);
    if sig < 1 || sig > super::task::MAX_SIGNALS as u32 {
        return None;
    }
    Some(task.sig_actions[(sig - 1) as usize])
}

/// Set signal action for the current task. Returns previous action.
pub fn set_signal_action(
    sig: u32,
    action: super::task::SignalAction,
) -> Option<super::task::SignalAction> {
    use super::task::{MAX_SIGNALS, UNCATCHABLE, sig_bit};
    if sig < 1 || sig > MAX_SIGNALS as u32 {
        return None;
    }
    if sig_bit(sig) & UNCATCHABLE != 0 {
        return None;
    } // can't change SIGKILL/SIGSTOP
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let task_id = thread_ref(tid).task_id;
    let old = task_ref(task_id).sig_actions[(sig - 1) as usize];
    // Safe: only the current task modifies its own sig_actions.
    unsafe { task_mut_from_ref(task_id) }.sig_actions[(sig - 1) as usize] = action;
    Some(old)
}

/// Set the signal mask for the current thread. Returns old mask.
pub fn set_signal_mask(new_mask: u64) -> u64 {
    use super::task::UNCATCHABLE;
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let old = thread_ref(tid).sig_mask;
    // Cannot mask SIGKILL or SIGSTOP.
    // Safe: only the current thread modifies its own sig_mask.
    unsafe { thread_mut_from_ref(tid) }.sig_mask = new_mask & !UNCATCHABLE;
    old
}

/// Get the signal mask for the current thread.
pub fn get_signal_mask() -> u64 {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    thread_ref(tid).sig_mask
}

/// Get the pending signal set for the current thread.
pub fn get_signal_pending() -> u64 {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    thread_ref(tid).sig_pending
}

// --- Phase 43: Process groups, sessions, controlling terminals ---

/// Set the process group ID of a task.
/// pid=0 means current task. pgid=0 means set pgid=pid.
/// Returns 0 on success, u64::MAX on error.
pub fn setpgid(pid: u32, pgid: u32) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let my_task = thread_ref(my_tid).task_id;

    let target_task = if pid == 0 { my_task } else { pid };

    match task_ref_opt(target_task) {
        Some(t) if t.active => {}
        _ => return u64::MAX,
    }
    if target_task != my_task && task_ref(target_task).parent_task != my_task {
        return u64::MAX;
    }

    let new_pgid = if pgid == 0 { target_task } else { pgid };
    let target_sid = task_ref(target_task).sid;

    if new_pgid != target_task {
        let mut found = false;
        SCHED_TASK_ART.for_each(|_key, val| {
            if found {
                return;
            }
            let t = unsafe { &*(val as *const Task) };
            if t.active && t.sid == target_sid && t.pgid == new_pgid {
                found = true;
            }
        });
        if !found {
            return u64::MAX;
        }
    }

    // Safe: only the owning task or its parent modifies pgid.
    unsafe { task_mut_from_ref(target_task) }.pgid = new_pgid;
    0
}

/// Get the process group ID of a task.
/// pid=0 means current task.
pub fn getpgid(pid: u32) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let target_task = if pid == 0 {
        thread_ref(my_tid).task_id
    } else {
        pid
    };
    match task_ref_opt(target_task) {
        Some(t) if t.active => {
            // Return group leader's task port_id (not raw task_id).
            task_ref(t.pgid).port_id
        }
        _ => u64::MAX,
    }
}

/// Create a new session. The calling task becomes the session leader.
/// Returns the new session ID (= task_id) or u64::MAX on error.
pub fn setsid() -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let my_task = thread_ref(my_tid).task_id;

    let current_pgid = task_ref(my_task).pgid;
    if current_pgid == my_task {
        let mut conflict = false;
        SCHED_TASK_ART.for_each(|_key, val| {
            if conflict {
                return;
            }
            let t = unsafe { &*(val as *const Task) };
            if t.active && t.id != my_task && t.pgid == my_task {
                conflict = true;
            }
        });
        if conflict {
            return u64::MAX;
        }
    }

    // Safe: only the current task modifies its own session/pgroup.
    let task = unsafe { task_mut_from_ref(my_task) };
    task.sid = my_task;
    task.pgid = my_task;
    task.ctty_port = 0;
    task.port_id
}

/// Get the session ID of a task.
/// pid=0 means current task.
pub fn getsid(pid: u32) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let target_task = if pid == 0 {
        thread_ref(my_tid).task_id
    } else {
        pid
    };
    match task_ref_opt(target_task) {
        Some(t) if t.active => {
            // Return session leader's task port_id.
            task_ref(t.sid).port_id
        }
        _ => u64::MAX,
    }
}

/// Set the foreground process group for the controlling terminal.
/// The caller must be in the same session as the ctty.
pub fn tcsetpgrp(pgid: u32) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let my_task = thread_ref(my_tid).task_id;

    if task_ref(my_task).ctty_port == 0 {
        return u64::MAX;
    }

    let my_sid = task_ref(my_task).sid;
    let mut found = false;
    SCHED_TASK_ART.for_each(|_key, val| {
        if found {
            return;
        }
        let t = unsafe { &*(val as *const Task) };
        if t.active && t.sid == my_sid && t.pgid == pgid {
            found = true;
        }
    });
    if !found {
        return u64::MAX;
    }

    // Store the foreground pgid in the session leader.
    // Safe: only tasks in the session modify fg_pgid, serialized by convention.
    match task_ref_opt(my_sid) {
        Some(t) if t.active => {
            unsafe { task_mut_from_ref(my_sid) }.fg_pgid = pgid;
            0
        }
        _ => u64::MAX,
    }
}

/// Get the foreground process group for the controlling terminal.
pub fn tcgetpgrp() -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let my_task = thread_ref(my_tid).task_id;

    if task_ref(my_task).ctty_port == 0 {
        return u64::MAX;
    }

    let my_sid = task_ref(my_task).sid;
    let mut raw_pgid = u32::MAX;
    SCHED_TASK_ART.for_each(|_key, val| {
        if raw_pgid != u32::MAX {
            return;
        }
        let t = unsafe { &*(val as *const Task) };
        if t.active && t.id == my_sid {
            raw_pgid = t.fg_pgid;
        }
    });
    if raw_pgid == u32::MAX || raw_pgid == 0 {
        u64::MAX
    } else {
        // Return group leader's task port_id.
        task_ref(raw_pgid).port_id
    }
}

/// Send a signal to all tasks in a process group.
pub fn send_signal_to_pgroup(pgid: u32, sig: u32) -> bool {
    use super::task::MAX_SIGNALS;
    if sig < 1 || sig > MAX_SIGNALS as u32 {
        return false;
    }

    let mut task_ids = [0u32; 64];
    let mut count = 0usize;
    SCHED_TASK_ART.for_each(|_key, val| {
        let t = unsafe { &*(val as *const Task) };
        if t.active && t.pgid == pgid && count < 64 {
            task_ids[count] = t.id;
            count += 1;
        }
    });

    if count == 0 {
        return false;
    }

    let mut any = false;
    for i in 0..count {
        if send_signal_to_task(task_ids[i], sig) {
            any = true;
        }
    }
    any
}

/// Set the controlling terminal for the current session.
/// Only the session leader can do this, and only if it has no ctty yet.
pub fn set_ctty(port: u64) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let my_task = thread_ref(my_tid).task_id;

    let task = task_ref(my_task);
    // Must be session leader.
    if task.sid != my_task {
        return u64::MAX;
    }
    // Must not already have a ctty.
    if task.ctty_port != 0 {
        return u64::MAX;
    }

    // Propagate ctty to all tasks in this session.
    let sid = my_task;
    SCHED_TASK_ART.for_each(|_key, val| {
        let t = unsafe { &mut *(val as *mut Task) };
        if t.active && t.sid == sid {
            t.ctty_port = port;
        }
    });
    0
}

#[allow(dead_code)]
pub fn current_thread_id() -> ThreadId {
    smp::current().current_thread.load(Ordering::Relaxed)
}

/// Kill all other threads in the current thread's task (for execve).
/// Marks them as Dead and dequeues from run queues. Returns the number killed.
pub fn kill_other_threads_in_task() -> usize {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let task_id = thread_ref(my_tid).task_id;
    let mut killed = 0;

    SCHED_THREAD_ART.for_each(|key, val| {
        if key == my_tid as u64 {
            return;
        }
        let t = unsafe { &mut *(val as *mut Thread) };
        if t.task_id == task_id && t.state != ThreadState::Dead {
            t.state = ThreadState::Dead;
            t.exit_code = -9;
            t.killed.store(true, Ordering::Release);
            killed += 1;
        }
    });

    // Set thread_count to 1 (just us).
    // Safe: only the current task's last thread calls this (execve).
    unsafe { task_mut_from_ref(task_id) }.thread_count = 1;
    killed
}

/// Kill all other threads in a specific task (for personality-delegated execve).
/// Keeps `keep_tid` alive, kills everything else in the task.
pub fn kill_other_threads_for_task(task_id: u32, keep_tid: u32) -> usize {
    let mut killed = 0;

    SCHED_THREAD_ART.for_each(|key, val| {
        if key == keep_tid as u64 {
            return;
        }
        let t = unsafe { &mut *(val as *mut Thread) };
        if t.task_id == task_id && t.state != ThreadState::Dead {
            t.state = ThreadState::Dead;
            t.exit_code = -9;
            t.killed.store(true, Ordering::Release);
            killed += 1;
        }
    });

    if killed > 0 {
        unsafe { task_mut_from_ref(task_id) }.thread_count = 1;
    }
    killed
}

/// Find a thread in the given task that is blocked on PersonalityWait.
/// Returns the ThreadId, or u32::MAX if none found.
pub fn find_personality_waiter(task_id: u32) -> ThreadId {
    use super::thread::BlockReason;
    let mut found: ThreadId = u32::MAX;
    SCHED_THREAD_ART.for_each(|_key, val| {
        if found != u32::MAX {
            return;
        }
        let t = unsafe { &*(val as *const Thread) };
        if t.task_id == task_id && t.blocked_on == BlockReason::PersonalityWait {
            found = t.id;
        }
    });
    found
}

/// Update the task's page table root after execve replaces the address space.
pub fn update_task_page_table(new_pt_root: usize) {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let task_id = thread_ref(my_tid).task_id;
    // Safe: only the current task updates its own page table root (execve).
    unsafe { task_mut_from_ref(task_id) }.page_table_root = new_pt_root;
}

/// Get the address space ID of the current thread's task.
/// Returns 0 if the thread/task has no address space (kernel context).
pub fn current_aspace_id() -> u64 {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let thread = thread_ref(tid);
    let task = task_ref(thread.task_id);
    task.aspace_id
}

/// Fork the current task: clone address space (COW), create child task+thread.
/// Returns the child thread ID (>0) to the parent, or 0 if fork failed.
/// The child will return 0 from this syscall (set in its exception frame).
pub fn fork_current() -> u64 {
    let cpu = smp::cpu_id() as usize;
    let tid = smp::get(cpu as u32).current_thread.load(Ordering::Relaxed);
    let parent_frame_sp = unsafe { thread_mut_from_ref(tid) }.syscall_frame_sp;
    if parent_frame_sp == 0 {
        return u64::MAX;
    }

    // Enforce RLIMIT_NPROC (lock-free).
    {
        let tid = smp::current().current_thread.load(Ordering::Relaxed);
        let task_id = thread_ref(tid).task_id;
        let task = task_ref(task_id);
        let uid = task.uid;
        let nproc_limit = task.rlimits[super::task::RLIMIT_NPROC as usize].cur;
        if nproc_limit != super::task::RLIM_INFINITY {
            let mut count = 0u64;
            SCHED_TASK_ART.for_each(|key, val| {
                if key == 0 {
                    return;
                }
                let t = unsafe { &*(val as *const Task) };
                if t.active && t.uid == uid {
                    count += 1;
                }
            });
            if count >= nproc_limit {
                return u64::MAX;
            }
        }
    }

    // Gather parent info (lock-free).
    let (
        _parent_tid,
        parent_task_id,
        parent_aspace_id,
        parent_priority,
        parent_quantum,
        parent_sig_mask,
        parent_tls_base,
    ) = {
        let tid = smp::current().current_thread.load(Ordering::Relaxed);
        let thread = thread_ref(tid);
        let task = task_ref(thread.task_id);
        (
            tid,
            thread.task_id,
            task.aspace_id,
            thread.base_priority,
            thread.default_quantum,
            thread.sig_mask,
            thread.tls_base,
        )
    };

    // Clone the address space (COW). This is done outside the scheduler lock
    // because it acquires ASPACES and OBJECTS locks.
    let (child_aspace_id, child_pt_root) = match crate::mm::aspace::clone_for_cow(parent_aspace_id)
    {
        Some(x) => x,
        None => return u64::MAX,
    };

    // Create kernel-held port for child task (outside scheduler lock).
    // We don't know child_task_id yet, so use 0 temporarily — updated in finalize.
    // Actually, we allocate task_id first, then create the port.

    // Create child task and thread under the scheduler lock.
    // Snapshot parent groups + credentials while holding lock.
    let (
        child_task_id,
        parent_pgid,
        parent_sid,
        parent_ctty,
        parent_uid,
        parent_euid,
        parent_gid,
        parent_egid,
        parent_groups_inline,
        parent_groups_overflow,
        parent_ngroups,
        parent_rlimits,
        parent_personality,
        parent_syscall_abi,
        parent_personality_port,
    ) = {
        let _lock = SPAWN_LOCK.lock_pv_aware();
        let child_task_id = match alloc_task_id() {
            Some(id) => id,
            None => return u64::MAX,
        };
        let ptask = task_ref(parent_task_id);
        (
            child_task_id,
            ptask.pgid,
            ptask.sid,
            ptask.ctty_port,
            ptask.uid,
            ptask.euid,
            ptask.gid,
            ptask.egid,
            ptask.groups_inline,
            ptask.groups_overflow,
            ptask.ngroups,
            ptask.rlimits,
            ptask.personality,
            ptask.syscall_abi,
            ptask.personality_port,
        )
    };

    // Outside SCHEDULER lock: create task port + duplicate groups overflow page.
    let child_task_port =
        match crate::ipc::port::create_kernel_port(task_port_handler, child_task_id as usize) {
            Some(p) => p,
            None => return u64::MAX,
        };
    let child_groups_overflow =
        if parent_ngroups as usize > GROUPS_INLINE && parent_groups_overflow != 0 {
            match crate::mm::phys::alloc_page() {
                Some(p) => {
                    // #235 Phase 4f: store child groups_overflow as kva.
                    let kva = crate::mm::page::phys_to_kva(p.as_usize());
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            parent_groups_overflow as *const u8,
                            kva as *mut u8,
                            parent_ngroups as usize * core::mem::size_of::<u32>(),
                        );
                    }
                    kva
                }
                None => return u64::MAX,
            }
        } else {
            0
        };
    // Set up child task. Re-initialize to empty first to avoid stale fields
    // from a reused task slot (e.g., max_ports from a previous SYS_SET_RLIMIT).
    {
        let task = unsafe { task_mut_from_ref(child_task_id) };
        *task = Task::empty();
        task.id = child_task_id;
        task.active = true;
        task.port_id = child_task_port;
        task.aspace_id = child_aspace_id;
        task.page_table_root = child_pt_root;
        task.exit_code = 0;
        task.exited = false;
        task.reaped = false;
        task.wait_status = 0;
        task.thread_count = 1;
        task.parent_task = parent_task_id;
        // Fork inherits parent's process group, session, ctty, credentials, and rlimits.
        task.pgid = parent_pgid;
        task.sid = parent_sid;
        task.ctty_port = parent_ctty;
        task.fg_pgid = 0; // Only session leader tracks fg_pgid.
        task.uid = parent_uid;
        task.euid = parent_euid;
        task.gid = parent_gid;
        task.egid = parent_egid;
        task.groups_inline = parent_groups_inline;
        task.groups_overflow = child_groups_overflow;
        task.ngroups = parent_ngroups;
        task.rlimits = parent_rlimits;
        // Fork inherits parent's personality (foreign OS emulation state).
        task.personality = parent_personality;
        task.syscall_abi = parent_syscall_abi;
        task.personality_port = parent_personality_port;
    }

    // Bootstrap capabilities: copy parent's capset and grant well-known port caps.
    {
        // Copy the fast-path capset so child inherits parent's port access.
        crate::cap::capset_copy(parent_task_id, child_task_id);

        // Initialize child's embedded capspace.
        {
            let tptr = TASK_TABLE.get(child_task_id) as *mut Task;
            unsafe {
                (*tptr).capspace = crate::cap::CapSpace::new(child_task_id);
            }
        }
        // Grant SEND caps for well-known kernel ports.
        let iramfs =
            crate::io::initramfs::USER_INITRAMFS_PORT.load(core::sync::atomic::Ordering::Acquire);
        if iramfs != u64::MAX {
            crate::cap::grant_send_cap(child_task_id, iramfs);
        }

        // Grant parent and child caps on the child's task port.
        use crate::cap::capability::Rights;
        let srm = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        crate::cap::grant_port_cap(parent_task_id, child_task_port, srm);
        crate::cap::grant_send_cap(child_task_id, child_task_port);
    }

    // Allocate kernel stack for child thread.
    let kstack_page = match alloc_kstack_zeroed() {
        Some(p) => p,
        None => return u64::MAX,
    };
    let kstack_base = kstack_page.as_usize();
    let kstack_phys_base = kstack_page.pa_base.as_usize();
    init_stack_canary(kstack_base);
    let kstack_top = kstack_base + kstack_size();

    // Copy parent's exception frame to child's kernel stack.
    let child_frame_sp = kstack_top - EXCEPTION_FRAME_SIZE;
    unsafe {
        core::ptr::copy_nonoverlapping(
            parent_frame_sp as *const u8,
            child_frame_sp as *mut u8,
            EXCEPTION_FRAME_SIZE,
        );
    }

    // Set child's return value to 0.
    {
        let child_frame =
            unsafe { &mut *(child_frame_sp as *mut crate::syscall::handlers::ExceptionFrame) };
        crate::syscall::handlers::set_return(child_frame, 0);
    }

    // Allocate child thread ID under SPAWN_LOCK.
    let child_tid = match {
        let _lock = SPAWN_LOCK.lock_pv_aware();
        alloc_thread_id()
    } {
        Some(id) => id,
        None => return u64::MAX,
    };
    let child_thread_port =
        match crate::ipc::port::create_kernel_port(thread_port_handler, child_tid as usize) {
            Some(p) => p,
            None => return u64::MAX,
        };

    // Clear killed/affinity flags.
    let thread = unsafe { thread_mut_from_ref(child_tid) };
    thread.killed.store(false, Ordering::Release);
    thread
        .affinity_mask
        .store_mask(&cpumask::CpuMask::all(), Ordering::Relaxed);
    thread.last_cpu.store(smp::cpu_id(), Ordering::Relaxed);
    // NEW_INV: child enters Ready, so on_cpu = ON_CPU_PENDING.
    thread.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
    thread.in_queue.store(false, Ordering::Release);

    thread.id = child_tid;
    thread.state = ThreadState::Ready;
    thread.task_id = child_task_id;
    thread.port_id = child_thread_port;
    thread.base_priority = parent_priority;
    thread.effective_priority = parent_priority;
    thread.prio.store(parent_priority, Ordering::Relaxed);
    thread.thread_task.store(child_task_id, Ordering::Relaxed);
    thread.quantum = parent_quantum;
    thread.default_quantum = parent_quantum;
    // #230 canon-race fix: set canonical BEFORE writing stack_phys_base.
    if child_tid < 100 {
        spb_set_canonical(child_tid, kstack_phys_base as u64);
    }
    // #208: stack_base BEFORE record (snapshot needs stack_base != 0).
    thread.stack_base = kstack_base;
    thread.stack_phys_base = kstack_phys_base;
    bump_kstack_epoch(thread); // #208
    write_saved_sp(thread, child_frame_sp as u64);
    record_saved_sp_write(child_tid, child_frame_sp as u64, 7); // fork
    if child_tid < 100 {
        #[cfg(target_arch = "x86_64")]
        log_kuser_spawn(child_tid, child_task_id, b"fork", None, parent_priority, parent_quantum);
        #[cfg(not(target_arch = "x86_64"))]
        crate::println!(
            "KUSER-SPAWN: tid={} task={} entry=fork prio={} q={}",
            child_tid, child_task_id, parent_priority, parent_quantum,
        );
    }
    thread.exit_code = 0;
    thread.sig_mask = parent_sig_mask;
    thread.sig_pending = 0;
    // Inherit FSBASE from parent — see fork_for_task for details.
    thread.tls_base = parent_tls_base;

    percpu_enqueue(smp::cpu_id(), parent_priority, child_tid);

    // Grant caps on the child's thread port.
    {
        use crate::cap::capability::Rights;
        let srm = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        let sm = Rights::SEND.union(Rights::MANAGE);
        crate::cap::grant_port_cap(parent_task_id, child_thread_port, sm);
        crate::cap::grant_port_cap(child_task_id, child_thread_port, srm);
    }

    // Return child task port_id to parent (nonzero = parent, 0 = child).
    child_task_port
}

/// Fork a target task on behalf of a personality server.
///
/// Same semantics as `fork_current()` but operates on `target_task_id` / `target_tid`
/// instead of the calling thread. The target must be blocked in PersonalityWait.
/// Returns the child task's port_id, or u64::MAX on error.
pub fn fork_for_task(target_task_id: u32, target_tid: u32) -> u64 {
    // Read target's personality exception frame (not saved_sp, which gets
    // overwritten by context switches during block_current spin-wait).
    let parent_frame_sp = thread_ref(target_tid).personality_frame_sp as usize;
    if parent_frame_sp == 0 {
        return u64::MAX;
    }

    // Gather parent info from target task/thread (lock-free).
    let parent_task_id = target_task_id;
    let parent_aspace_id;
    let parent_priority;
    let parent_quantum;
    let parent_sig_mask;
    let parent_tls_base;
    {
        let thread = thread_ref(target_tid);
        let task = task_ref(target_task_id);
        parent_aspace_id = task.aspace_id;
        parent_priority = thread.base_priority;
        parent_quantum = thread.default_quantum;
        parent_sig_mask = thread.sig_mask;
        parent_tls_base = thread.tls_base;

        // RLIMIT_NPROC check.
        let uid = task.uid;
        let nproc_limit = task.rlimits[super::task::RLIMIT_NPROC as usize].cur;
        if nproc_limit != super::task::RLIM_INFINITY {
            let mut count = 0u64;
            SCHED_TASK_ART.for_each(|key, val| {
                if key == 0 { return; }
                let t = unsafe { &*(val as *const Task) };
                if t.active && t.uid == uid { count += 1; }
            });
            if count >= nproc_limit {
                return u64::MAX;
            }
        }
    }

    // Clone the address space (COW).
    let (child_aspace_id, child_pt_root) = match crate::mm::aspace::clone_for_cow(parent_aspace_id)
    {
        Some(x) => x,
        None => return u64::MAX,
    };

    // Snapshot parent credentials/groups under SPAWN_LOCK.
    let (
        child_task_id,
        parent_pgid, parent_sid, parent_ctty,
        parent_uid, parent_euid, parent_gid, parent_egid,
        parent_groups_inline, parent_groups_overflow, parent_ngroups,
        parent_rlimits,
        parent_personality, parent_syscall_abi, parent_personality_port,
    ) = {
        let _lock = SPAWN_LOCK.lock_pv_aware();
        let child_task_id = match alloc_task_id() {
            Some(id) => id,
            None => return u64::MAX,
        };
        let ptask = task_ref(parent_task_id);
        (
            child_task_id,
            ptask.pgid, ptask.sid, ptask.ctty_port,
            ptask.uid, ptask.euid, ptask.gid, ptask.egid,
            ptask.groups_inline, ptask.groups_overflow, ptask.ngroups,
            ptask.rlimits,
            ptask.personality, ptask.syscall_abi, ptask.personality_port,
        )
    };

    // Create child task port.
    let child_task_port =
        match crate::ipc::port::create_kernel_port(task_port_handler, child_task_id as usize) {
            Some(p) => p,
            None => return u64::MAX,
        };

    // Duplicate groups overflow page if needed.
    let child_groups_overflow =
        if parent_ngroups as usize > GROUPS_INLINE && parent_groups_overflow != 0 {
            match crate::mm::phys::alloc_page() {
                Some(p) => {
                    // #235 Phase 4f: store child groups_overflow as kva.
                    let kva = crate::mm::page::phys_to_kva(p.as_usize());
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            parent_groups_overflow as *const u8,
                            kva as *mut u8,
                            parent_ngroups as usize * core::mem::size_of::<u32>(),
                        );
                    }
                    kva
                }
                None => return u64::MAX,
            }
        } else {
            0
        };

    // Initialize child task struct.
    {
        let task = unsafe { task_mut_from_ref(child_task_id) };
        *task = Task::empty();
        task.id = child_task_id;
        task.active = true;
        task.port_id = child_task_port;
        task.aspace_id = child_aspace_id;
        task.page_table_root = child_pt_root;
        task.exit_code = 0;
        task.exited = false;
        task.reaped = false;
        task.wait_status = 0;
        task.thread_count = 1;
        task.parent_task = parent_task_id;
        task.pgid = parent_pgid;
        task.sid = parent_sid;
        task.ctty_port = parent_ctty;
        task.fg_pgid = 0;
        task.uid = parent_uid;
        task.euid = parent_euid;
        task.gid = parent_gid;
        task.egid = parent_egid;
        task.groups_inline = parent_groups_inline;
        task.groups_overflow = child_groups_overflow;
        task.ngroups = parent_ngroups;
        task.rlimits = parent_rlimits;
        task.personality = parent_personality;
        task.syscall_abi = parent_syscall_abi;
        task.personality_port = parent_personality_port;
    }

    // Bootstrap capabilities.
    {
        crate::cap::capset_copy(parent_task_id, child_task_id);
        {
            let tptr = TASK_TABLE.get(child_task_id) as *mut Task;
            unsafe { (*tptr).capspace = crate::cap::CapSpace::new(child_task_id); }
        }
        let iramfs =
            crate::io::initramfs::USER_INITRAMFS_PORT.load(core::sync::atomic::Ordering::Acquire);
        if iramfs != u64::MAX {
            crate::cap::grant_send_cap(child_task_id, iramfs);
        }
        use crate::cap::capability::Rights;
        let srm = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        crate::cap::grant_port_cap(parent_task_id, child_task_port, srm);
        crate::cap::grant_send_cap(child_task_id, child_task_port);
    }

    // Allocate kernel stack for child thread.
    let kstack_page = match alloc_kstack_zeroed() {
        Some(p) => p,
        None => return u64::MAX,
    };
    let kstack_base = kstack_page.as_usize();
    let kstack_phys_base = kstack_page.pa_base.as_usize();
    init_stack_canary(kstack_base);
    let kstack_top = kstack_base + kstack_size();

    // Copy target's exception frame to child's kernel stack.
    let child_frame_sp = kstack_top - EXCEPTION_FRAME_SIZE;
    unsafe {
        core::ptr::copy_nonoverlapping(
            parent_frame_sp as *const u8,
            child_frame_sp as *mut u8,
            EXCEPTION_FRAME_SIZE,
        );
    }

    // Set child's return value to 0.
    {
        let child_frame =
            unsafe { &mut *(child_frame_sp as *mut crate::syscall::handlers::ExceptionFrame) };
        crate::syscall::handlers::set_return(child_frame, 0);
    }

    // Allocate child thread ID.
    let child_tid = match {
        let _lock = SPAWN_LOCK.lock_pv_aware();
        alloc_thread_id()
    } {
        Some(id) => id,
        None => return u64::MAX,
    };
    let child_thread_port =
        match crate::ipc::port::create_kernel_port(thread_port_handler, child_tid as usize) {
            Some(p) => p,
            None => return u64::MAX,
        };

    // Initialize child thread.
    let thread = unsafe { thread_mut_from_ref(child_tid) };
    thread.killed.store(false, Ordering::Release);
    thread.affinity_mask.store_mask(&cpumask::CpuMask::all(), Ordering::Relaxed);
    thread.last_cpu.store(smp::cpu_id(), Ordering::Relaxed);
    // NEW_INV: child enters Ready, so on_cpu = ON_CPU_PENDING.
    thread.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
    thread.in_queue.store(false, Ordering::Release);

    thread.id = child_tid;
    thread.state = ThreadState::Ready;
    thread.task_id = child_task_id;
    thread.port_id = child_thread_port;
    thread.base_priority = parent_priority;
    thread.effective_priority = parent_priority;
    thread.prio.store(parent_priority, Ordering::Relaxed);
    thread.thread_task.store(child_task_id, Ordering::Relaxed);
    thread.quantum = parent_quantum;
    thread.default_quantum = parent_quantum;
    // #230 canon-race fix: set canonical BEFORE writing stack_phys_base.
    if child_tid < 100 {
        spb_set_canonical(child_tid, kstack_phys_base as u64);
    }
    // #208: stack_base BEFORE record (snapshot needs stack_base != 0).
    thread.stack_base = kstack_base;
    thread.stack_phys_base = kstack_phys_base;
    bump_kstack_epoch(thread); // #208
    write_saved_sp(thread, child_frame_sp as u64);
    record_saved_sp_write(child_tid, child_frame_sp as u64, 8); // clone variant
    if child_tid < 100 {
        #[cfg(target_arch = "x86_64")]
        log_kuser_spawn(child_tid, child_task_id, b"clone", None, parent_priority, parent_quantum);
        #[cfg(not(target_arch = "x86_64"))]
        crate::println!(
            "KUSER-SPAWN: tid={} task={} entry=clone prio={} q={}",
            child_tid, child_task_id, parent_priority, parent_quantum,
        );
    }
    thread.exit_code = 0;
    thread.sig_mask = parent_sig_mask;
    thread.sig_pending = 0;
    // Inherit FSBASE from parent.  Without this, the child wakes with
    // tls_base=0, and any compiler-emitted `%fs:0x28` access (e.g. glibc's
    // internal stack-canary loads) faults on first context switch
    // (project_step_g_flakes.md: CR2=0x28, RIP in compositor canary check).
    thread.tls_base = parent_tls_base;

    percpu_enqueue(smp::cpu_id(), parent_priority, child_tid);

    // Grant caps on child's thread port.
    {
        use crate::cap::capability::Rights;
        let srm = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        let sm = Rights::SEND.union(Rights::MANAGE);
        crate::cap::grant_port_cap(parent_task_id, child_thread_port, sm);
        crate::cap::grant_port_cap(child_task_id, child_thread_port, srm);
    }

    child_task_port
}

/// Clone a new thread within the same task (CLONE_VM | CLONE_THREAD semantics).
///
/// Copies the parent thread's exception frame, sets return value to 0, applies
/// the new stack pointer and TLS base.  The new thread resumes at the same IP
/// as the parent — exactly what Linux clone(CLONE_VM|CLONE_THREAD) expects.
///
/// `tls_base` of 0 means "inherit from parent" (matches Linux clone semantics
/// when CLONE_SETTLS is not set — the child inherits the parent's TLS, NOT a
/// zero TLS base, otherwise glibc internal `%fs:0xN` accesses fault).
///
/// Returns the new thread's port_id, or u64::MAX on error.
pub fn clone_thread_in_task(
    task_id: u32,
    parent_tid: u32,
    child_stack: u64,
    tls_base: u64,
) -> u64 {
    // Read parent's saved personality exception frame.
    let parent_frame_sp = thread_ref(parent_tid).personality_frame_sp as usize;
    if parent_frame_sp == 0 {
        return u64::MAX;
    }

    let parent_priority = thread_ref(parent_tid).base_priority;
    let parent_quantum = thread_ref(parent_tid).default_quantum;
    let parent_sig_mask = thread_ref(parent_tid).sig_mask;

    // Allocate kernel stack for the new thread.
    let kstack_page = match alloc_kstack_zeroed() {
        Some(p) => p,
        None => return u64::MAX,
    };
    let kstack_base = kstack_page.as_usize();
    let kstack_phys_base = kstack_page.pa_base.as_usize();
    init_stack_canary(kstack_base);
    let kstack_top = kstack_base + kstack_size();

    // Copy parent's exception frame to the new thread's kernel stack.
    let child_frame_sp = kstack_top - EXCEPTION_FRAME_SIZE;
    unsafe {
        core::ptr::copy_nonoverlapping(
            parent_frame_sp as *const u8,
            child_frame_sp as *mut u8,
            EXCEPTION_FRAME_SIZE,
        );
    }

    // Set return value to 0 (child sees clone() return 0).
    {
        let child_frame =
            unsafe { &mut *(child_frame_sp as *mut crate::syscall::handlers::ExceptionFrame) };
        crate::syscall::handlers::set_return(child_frame, 0);
        // Set child's user stack pointer.
        if child_stack != 0 {
            crate::arch::trapframe::set_user_sp(child_frame, child_stack as usize);
        }
    }

    // Allocate thread ID and port.
    let child_tid = match {
        let _lock = SPAWN_LOCK.lock_pv_aware();
        alloc_thread_id()
    } {
        Some(id) => id,
        None => return u64::MAX,
    };
    let child_thread_port =
        match crate::ipc::port::create_kernel_port(thread_port_handler, child_tid as usize) {
            Some(p) => p,
            None => return u64::MAX,
        };

    // Initialize the new thread — same task, shared address space.
    let thread = unsafe { thread_mut_from_ref(child_tid) };
    thread.killed.store(false, Ordering::Release);
    thread.affinity_mask.store_mask(&cpumask::CpuMask::all(), Ordering::Relaxed);
    thread.last_cpu.store(smp::cpu_id(), Ordering::Relaxed);
    // NEW_INV: child enters Ready, so on_cpu = ON_CPU_PENDING.
    thread.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
    thread.in_queue.store(false, Ordering::Release);

    thread.id = child_tid;
    thread.state = ThreadState::Ready;
    thread.task_id = task_id;
    thread.port_id = child_thread_port;
    thread.base_priority = parent_priority;
    thread.effective_priority = parent_priority;
    thread.prio.store(parent_priority, Ordering::Relaxed);
    thread.thread_task.store(task_id, Ordering::Relaxed);
    thread.quantum = parent_quantum;
    thread.default_quantum = parent_quantum;
    // #230 canon-race fix: set canonical BEFORE writing stack_phys_base.
    if child_tid < 100 {
        spb_set_canonical(child_tid, kstack_phys_base as u64);
    }
    // #208: stack_base BEFORE record (snapshot needs stack_base != 0).
    thread.stack_base = kstack_base;
    thread.stack_phys_base = kstack_phys_base;
    bump_kstack_epoch(thread); // #208
    write_saved_sp(thread, child_frame_sp as u64);
    record_saved_sp_write(child_tid, child_frame_sp as u64, 9); // clone-third
    if child_tid < 100 {
        #[cfg(target_arch = "x86_64")]
        log_kuser_spawn(child_tid, task_id, b"clone3", None, parent_priority, parent_quantum);
        #[cfg(not(target_arch = "x86_64"))]
        crate::println!(
            "KUSER-SPAWN: tid={} task={} entry=clone3 prio={} q={}",
            child_tid, task_id, parent_priority, parent_quantum,
        );
    }
    thread.exit_code = 0;
    thread.sig_mask = parent_sig_mask;
    thread.sig_pending = 0;
    // tls_base = 0 means "inherit from parent" (Linux clone without CLONE_SETTLS).
    thread.tls_base = if tls_base == 0 {
        thread_ref(parent_tid).tls_base
    } else {
        tls_base
    };

    let ts = crate::sync::turnstile::alloc_thread_turnstile();
    thread.turnstile.store(ts, Ordering::Relaxed);

    unsafe { task_mut_from_ref(task_id) }.thread_count += 1;
    percpu_enqueue(smp::cpu_id(), parent_priority, child_tid);

    // Grant caps on the new thread's port.
    {
        use crate::cap::capability::Rights;
        let srm = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        crate::cap::grant_port_cap(task_id, child_thread_port, srm);
    }

    child_thread_port
}

/// Wait for a child of the given target task (non-blocking).
///
/// Like `wait4()` but scans children of `target_task_id` instead of the calling
/// task. Always returns immediately (like WNOHANG behavior).
/// Returns (child_port, child_id, wait_status) or (0, -1, 0) for ECHILD.
pub fn wait4_for_task(target_task_id: u32, pid: i64, flags: u32) -> (u64, i32, i32) {
    let my_pgid = task_ref(target_task_id).pgid;

    let mut found: Option<(u32, i32)> = None;
    let mut has_children = false;
    SCHED_TASK_ART.for_each(|key, val| {
        if found.is_some() || key == 0 { return; }
        let task = unsafe { &*(val as *const Task) };
        if task.parent_task != target_task_id { return; }

        let matches = match pid {
            -1 => true,
            0 => task.pgid == my_pgid,
            p if p > 0 => task.id == p as TaskId,
            p => task.pgid == (-p) as TaskId,
        };
        if !matches { return; }
        has_children = true;

        if task.exited && !task.reaped {
            found = Some((task.id, task.wait_status));
        }
    });

    if let Some((child_id, status)) = found {
        let t = unsafe { task_mut_from_ref(child_id) };
        t.reaped = true;
        let port_id = t.port_id;
        t.port_id = 0;
        if port_id != 0 {
            crate::ipc::port::destroy(port_id);
        }
        (port_id, child_id as i32, status)
    } else if !has_children {
        (0, -1, 0)
    } else {
        (0, 0, 0)
    }
}

/// Terminate the current thread and destroy its task's resources.
/// This function never returns.
pub fn exit_current_thread(exit_code: i32) -> ! {
    // DIAG: confirm this fires for clone3_test child.  Will remove
    // once #136 INVOL-EXIT validation completes.
    {
        let _tmp_tid = smp::current().current_thread.load(Ordering::Relaxed);
        let _tmp_task = thread_ref(_tmp_tid).task_id;
        #[cfg(target_arch = "x86_64")]
        {
            use crate::arch::x86_64::serial::{put_byte, put_bytes, put_hex_u64, put_dec_u64};
            let mut buf = [0u8; 96];
            let mut k = 0;
            put_bytes(&mut buf, &mut k, b"EXIT-THREAD-ENTRY: tid=");
            put_dec_u64(&mut buf, &mut k, _tmp_tid as u64);
            put_bytes(&mut buf, &mut k, b" task=");
            put_dec_u64(&mut buf, &mut k, _tmp_task as u64);
            put_bytes(&mut buf, &mut k, b" exit=");
            if exit_code < 0 {
                put_byte(&mut buf, &mut k, b'-');
                put_dec_u64(&mut buf, &mut k, (-(exit_code as i64)) as u64);
            } else {
                put_dec_u64(&mut buf, &mut k, exit_code as u64);
            }
            put_byte(&mut buf, &mut k, b'\n');
            crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
        }
        #[cfg(not(target_arch = "x86_64"))]
        crate::println!(
            "EXIT-THREAD-ENTRY: tid={} task={} exit={}",
            _tmp_tid, _tmp_task, exit_code
        );
        // Reset-on-exit of IRETQ/FWD probe counters was tried here but
        // correlated with 4/4 boot wedges before init produced output.
        // Reverted; tid reuse still quenches trace, but that's a smaller
        // problem than boots not progressing.  Investigate at lower
        // priority: maybe call from a different lifecycle hook (e.g.,
        // task_create instead of thread_exit), or use a per-task-id
        // counter that doesn't get reused on the same boot.
    }
    let (
        tid,
        is_last_thread,
        aspace_id,
        pt_root,
        kstack_base,
        parent_task_id,
        _task_port,
        thread_port,
        task_personality_port,
        task_id_for_exit,
    ) = {
        let pcpu = smp::current();
        let tid = pcpu.current_thread.load(Ordering::Relaxed);
        // Safe: we are the running thread; no contention on our own state.
        let thread = unsafe { thread_mut_from_ref(tid) };
        thread.state = ThreadState::Dead;
        thread.exit_code = exit_code;
        let thread_port = thread.port_id;
        // Wake any thread blocked in thread_join() on us.
        let waiter = thread.join_waiter;
        thread.join_waiter = u32::MAX;
        if waiter != u32::MAX {
            wake_thread(waiter);
        }
        let task_id = thread.task_id;
        // Phase 5b: use stack_phys_base for deferred_kstack (PA, not VA).
        let kstack_base = thread.stack_phys_base;
        spb_check(tid, kstack_base as u64, "exit_defer");
        // NOTE: Do NOT set stack_base=0 here. The thread is still running on
        // its CPU. Setting it to 0 would allow alloc_thread_id to reuse the
        // slot before we're actually off the CPU. Instead, try_switch will set
        // stack_base=0 when it drains DEFERRED_KSTACK (proving the dead thread
        // has been context-switched away).
        // Safe: thread_count decrement needs care for multi-threaded tasks.
        // Use saturating_sub: if a killed thread was already decremented by
        // the scheduler's killed-thread path (try_switch), avoid underflow.
        let task = unsafe { task_mut_from_ref(task_id) };
        task.thread_count = task.thread_count.saturating_sub(1);
        let is_last = task.thread_count == 0;
        let parent_task_id = task.parent_task;
        let task_port = task.port_id;
        let task_personality_port = task.personality_port;
        if is_last {
            task.exit_code = exit_code;
            task.exited = true;
            task.active = false;
            // Encode POSIX wait status: normal exit = (code & 0xFF) << 8.
            task.wait_status = (exit_code & 0xFF) << 8;
        }
        let aspace_id = task.aspace_id;
        let pt_root = task.page_table_root;
        (
            tid,
            is_last,
            aspace_id,
            pt_root,
            kstack_base,
            parent_task_id,
            task_port,
            thread_port,
            task_personality_port,
            task_id,
        )
    };

    // #136 involuntary-exit cleanup: when a thread of a Linux-personality
    // task dies via SIGSEGV/etc. without calling __NR_EXIT, linux_srv
    // never runs handle_exit_thread, so the thread's CLONE_CHILD_CLEARTID
    // address isn't cleared and any FUTEX_WAIT on it (typically
    // pthread_join) hangs forever.  Synthesize a __NR_EXIT message and
    // fire it at linux_srv from kernel context so the cleanup happens.
    //
    // Skip when is_last_thread because:
    //   (a) the leader thread's __NR_EXIT is treated as __NR_EXIT_GROUP
    //       by handle_exit_thread (PROC_TABLE[pi].port == caller_port),
    //       which is the right semantic for "process died"
    //   (b) handle_exit_group also tears down PROC_TABLE state, which we
    //       want to happen exactly once
    //
    // exit_code < 0 marks involuntary exit (signal numbers are negative
    // by Telix convention here): we always want the cleanup, but the
    // log line is more interesting for involuntary deaths.  Fire for
    // all non-last-thread Linux exits to keep behavior uniform.
    if task_personality_port != 0 && !is_last_thread && thread_port != 0 {
        // Tag = (__NR_EXIT=60) | (caller_port << 32).  This matches the
        // shape forward_to_server uses for syscall-forwarded messages.
        const NR_EXIT_LINUX: u64 = 60;
        let msg = crate::ipc::Message {
            tag: NR_EXIT_LINUX | (thread_port << 32),
            data: [exit_code as i64 as u64, 0, 0, 0, 0, 0],
        };
        let send_result = crate::ipc::port::try_send(task_personality_port, msg);
        // Print for ALL non-last-thread Linux exits (voluntary + signal),
        // so we can confirm the cleanup forwarding fires.  Voluntary
        // __NR_EXIT from glibc's pthread bootstrap goes through the
        // kernel's direct shortcut at handlers.rs:262, bypassing
        // linux_srv — without this forward, CLEARTID + FUTEX_WAKE
        // never happen and pthread_join hangs forever.
        crate::println!(
            "INVOL-EXIT: linux thread tid={} task={} port={:#x} exit={} send={}",
            tid, task_id_for_exit, thread_port, exit_code,
            if send_result.is_ok() { "ok" } else { "FAILED" }
        );
    }

    // If the dying thread is holding a reply-cap, deliver a server-died
    // reply to the parked caller so they don't hang forever.
    {
        let tref = thread_ref(tid);
        let handle = tref
            .held_reply_cap
            .swap(u64::MAX, Ordering::AcqRel);
        if handle != u64::MAX {
            let died = crate::ipc::Message::new(
                crate::ipc::call_reply::CALL_REPLY_SERVER_DIED,
                [0; 6],
            );
            match crate::ipc::call_reply::fulfill(handle, &died) {
                crate::ipc::call_reply::FulfillResult::WakeCaller(caller_tid) => {
                    // Inject into the caller's parked frame, then wake.
                    let sp = thread_saved_sp(caller_tid);
                    if sp != 0 && validate_kstack_inject(caller_tid, sp, "server_died") {
                        unsafe {
                            use crate::arch::trapframe::ExceptionFrame;
                            let frame = &mut *(sp as *mut ExceptionFrame);
                            crate::syscall::handlers::set_return(frame, 0);
                            crate::syscall::handlers::set_reg(frame, 1, died.tag);
                            crate::syscall::handlers::set_reg(frame, 2, 0);
                            crate::syscall::handlers::set_reg(frame, 3, 0);
                            crate::syscall::handlers::set_reg(frame, 4, 0);
                            crate::syscall::handlers::set_reg(frame, 5, 0);
                            crate::syscall::handlers::set_reg(frame, 6, 0);
                            crate::syscall::handlers::set_reg(frame, 7, 0);
                        }
                    }
                    wake_parked_thread(caller_tid);
                }
                _ => {}
            }
            // free() revokes any grant leases on the cap and returns the
            // slot to the pool. Crucial here: the server is dying, so any
            // grants the caller made into its aspace must be released now
            // to avoid dangling mappings.
            crate::ipc::call_reply::free(handle);
        }

        // Caller-death: if this thread is parked in sys_call (or was about
        // to be), abandon any Pending cap it owns. abandon() revokes its
        // leases so a later server reply cannot reach into a dead aspace.
        crate::ipc::call_reply::abandon_all_for_caller(tid);
    }

    // Clean up turnstile state: dequeue from any wait queue, free pre-allocated turnstile.
    crate::sync::turnstile::cleanup_blocked(tid);
    let tptr = THREAD_TABLE.get(tid) as *const super::thread::Thread;
    let ts_addr = unsafe { (*tptr).turnstile.swap(0, Ordering::Relaxed) };
    crate::sync::turnstile::free_thread_turnstile(ts_addr);

    // Destroy the thread's kernel-held port (outside SCHEDULER lock for lock ordering).
    if thread_port != 0 {
        crate::ipc::port::destroy(thread_port);
    }

    // If this was the last thread (task became zombie), notify parent.
    if is_last_thread {
        // Send SIGCHLD to parent task.
        send_signal_to_task(parent_task_id, super::task::SIGCHLD);
        // Wake any parent threads blocked in WaitChild.
        wake_wait_child_threads(parent_task_id);
    }

    // Only destroy task resources when the last thread exits.
    if is_last_thread {
        // Switch to kernel/boot page table before freeing user page table.
        if pt_root != 0 {
            {
                let boot_root = crate::mm::hat::boot_page_table_root();
                crate::mm::hat::switch_page_table(boot_root);
            }
        }

        // Free groups overflow page if allocated.
        {
            let exit_task_id = thread_ref(tid).task_id;
            let tptr = TASK_TABLE.get(exit_task_id) as *mut Task;
            unsafe {
                (*tptr).free_groups_overflow();
            }
        }

        // Destroy address space (frees VMAs, backing pages, and PT tree).
        if aspace_id != 0 {
            crate::mm::aspace::destroy(aspace_id);
        }
    }

    // NOTE: Do NOT destroy the task port here — the parent still needs it
    // to call waitpid/wait4 (which resolve port_id → task_id). The task
    // port is destroyed when the zombie is reaped.

    // Auto-reap zombie children of this exiting task (prevent zombie leaks).
    if is_last_thread {
        let my_task_id = thread_ref(tid).task_id;
        let mut zombie_ports = [0u64; 32];
        let mut nz = 0usize;
        // Lock-free: only the parent task reaps its zombie children.
        SCHED_TASK_ART.for_each(|key, val| {
            if key == 0 {
                return;
            }
            let task = unsafe { &mut *(val as *mut Task) };
            if task.parent_task == my_task_id && task.exited && !task.reaped {
                task.reaped = true;
                if task.port_id != 0 && nz < 32 {
                    zombie_ports[nz] = task.port_id;
                    task.port_id = 0;
                    nz += 1;
                }
            }
        });
        for i in 0..nz {
            crate::ipc::port::destroy(zombie_ports[i]);
        }
    }

    // Defer freeing our own kernel stack — we're running on it.
    // Also store our thread ID so try_switch can mark the slot as reusable.
    let cpu = smp::cpu_id();
    // Phase-5 leak fix: drain any prior pending deferred kstack (a thread
    // that exited on this CPU before its slot was drained) before we
    // overwrite the single slot with our own — otherwise that prior 1 MiB
    // kstack leaks.  This is the dominant leak: each exiting thread defers
    // its own stack here, and rapid same-CPU exits clobber each other.
    drain_prior_deferred_kstack(cpu as usize, kstack_base);
    deferred_thread()[cpu as usize].store(tid as usize, Ordering::Release);
    deferred_kstack()[cpu as usize].store(kstack_base, Ordering::Release);

    // Enable interrupts so the timer can preempt us (we may be in a syscall
    // handler where hardware masked IRQs on exception entry).
    crate::arch::irq::enable();

    // Request immediate preemption on the next tick so we don't waste a
    // full quantum spinning.  Don't use WFI/HLT here: on the next timer
    // IRQ, try_switch() will switch us to a different thread, and on the
    // tick after that it will free our kstack page.  HLT's resume path
    // needs a valid stack, and spin_loop() is purely in-register.
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    thread_ref(tid).yield_asap.store(true, Ordering::Release);
    loop {
        core::hint::spin_loop();
    }
}

// --- IRQ helpers for blocking paths (delegate to arch::irq) ---

/// Save current interrupt state and enable IRQs. Returns saved state.
/// Public so drivers (e.g. virtio_blk) can use polling with WFI.
#[inline(always)]
#[allow(dead_code)]
pub fn arch_irq_save_enable() -> usize {
    crate::arch::irq::save_and_enable()
}

/// Restore interrupt state.
/// Public so drivers (e.g. virtio_blk) can use polling with WFI.
#[inline(always)]
#[allow(dead_code)]
pub fn arch_irq_restore(saved: usize) {
    crate::arch::irq::restore(saved);
}

/// Wait for next interrupt (WFI/HLT). Public for sys_yield.
#[inline(always)]
#[allow(dead_code)]
pub fn arch_wait_for_irq() {
    crate::arch::irq::wait_for_interrupt();
}

/// Check if a child thread's task has exited. Returns exit code if so.
/// Also reaps the child (marks reaped=true) so the task slot can be reused.
pub fn waitpid(child_task_id: TaskId) -> Option<i32> {
    let task = match task_ref_opt(child_task_id) {
        Some(t) => t,
        None => return None,
    };
    if !task.exited {
        return None;
    }
    let port_id = task.port_id;
    let code = task.exit_code;
    // Safe: only the parent reaps a child, and only once.
    let t = unsafe { task_mut_from_ref(child_task_id) };
    t.reaped = true;
    t.port_id = 0; // prevent double-destroy
    if port_id != 0 {
        crate::ipc::port::destroy(port_id);
    }
    Some(code)
}

/// POSIX wait flags.
pub const WNOHANG: u32 = 1;
#[allow(dead_code)]
pub const WUNTRACED: u32 = 2;
#[allow(dead_code)]
pub const WCONTINUED: u32 = 8;

/// Wake all threads in a given task that are blocked in WaitChild.
fn wake_wait_child_threads(task_id: TaskId) {
    let mut to_wake = [0u32; 64];
    let mut count = 0usize;
    SCHED_THREAD_ART.for_each(|key, val| {
        let t = unsafe { &*(val as *const Thread) };
        if t.task_id == task_id
            && t.state != ThreadState::Dead
            && t.stack_base != 0
            && t.blocked_on == BlockReason::WaitChild
        {
            if count < 64 {
                to_wake[count] = key as u32;
                count += 1;
            }
        }
    });
    for i in 0..count {
        wake_thread(to_wake[i]);
    }
}

/// Enhanced wait4: wait for child process exit with POSIX semantics.
///
/// `pid` semantics:
///   - pid > 0: wait for child with task_id == pid
///   - pid == -1: wait for any child
///   - pid == 0: wait for any child in caller's process group
///   - pid < -1: wait for any child in process group |pid|
///
/// Returns (child_task_port_id, child_task_id, wait_status) or (0, -1, 0) on error,
/// or (0, 0, 0) for WNOHANG with no exited child.
pub fn wait4(pid: i64, flags: u32) -> (u64, i32, i32) {
    let tid = current_thread_id();

    loop {
        let my_task_id = thread_ref(tid).task_id;
        let my_pgid = task_ref(my_task_id).pgid;

        // Scan for a matching exited (zombie) child (lock-free).
        let mut found: Option<(u32, i32)> = None;
        let mut has_children = false;
        SCHED_TASK_ART.for_each(|key, val| {
            if found.is_some() {
                return;
            }
            if key == 0 {
                return;
            }
            let task = unsafe { &*(val as *const Task) };
            if task.parent_task != my_task_id {
                return;
            }

            // Check pid filter.
            let matches = match pid {
                -1 => true,                           // any child
                0 => task.pgid == my_pgid,            // same pgroup
                p if p > 0 => task.id == p as TaskId, // specific task
                p => task.pgid == (-p) as TaskId,     // specific pgroup
            };
            if !matches {
                return;
            }
            has_children = true;

            if task.exited && !task.reaped {
                found = Some((task.id, task.wait_status));
            }
        });

        if let Some((child_id, status)) = found {
            // Reap the child. Safe: only the parent reaps, and only once.
            let t = unsafe { task_mut_from_ref(child_id) };
            t.reaped = true;
            let port_id = t.port_id;
            t.port_id = 0; // prevent double-destroy
            if port_id != 0 {
                crate::ipc::port::destroy(port_id);
            }
            return (port_id, child_id as i32, status);
        } else if !has_children {
            // No matching children at all — ECHILD.
            return (0, -1, 0);
        } else if flags & WNOHANG != 0 {
            return (0, 0, 0);
        } else {
            // Block: set blocked_on before entering block_current.
            clear_wakeup_flag(tid);
            unsafe { thread_mut_from_ref(tid) }.blocked_on = BlockReason::WaitChild;
            block_current(BlockReason::WaitChild);
        }
    }
}

/// Boost a thread's effective priority if `to_prio` is higher (lower number).
/// Lock-free: uses atomic CAS on prio + direct write to effective_priority.
///
/// For EEVDF (SCHED_NORMAL) threads boosted into the RT range (< 128),
/// the thread is temporarily promoted to SCHED_RT so that `percpu_enqueue`
/// routes it to the RT bitmap on its next enqueue.  If the thread is
/// currently sitting in an EEVDF heap, we tighten its deadline to zero
/// so that it is the next thread picked from the heap, after which the
/// RT routing kicks in.
pub fn boost_priority(tid: ThreadId, to_prio: u8) {
    let tref = thread_ref(tid);
    // CAS loop: only boost if current prio is lower (higher number).
    loop {
        let cur = tref.prio.load(Ordering::Relaxed);
        if to_prio >= cur {
            break;
        } // already at equal or higher priority
        if tref
            .prio
            .compare_exchange_weak(cur, to_prio, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            let t = unsafe { thread_mut_from_ref(tid) };
            t.effective_priority = to_prio;
            // Promote SCHED_NORMAL → SCHED_RT for priority inheritance.
            // On next enqueue, percpu_enqueue will route to the RT bitmap.
            if t.sched_class == SCHED_NORMAL && to_prio < 128 {
                t.sched_class = super::thread::SCHED_RT;
                // If the thread is in an EEVDF heap, tighten its deadline
                // to zero so it is picked first at the next class_pick_next.
                let heap_pos = t.eevdf_heap_pos;
                if heap_pos != super::heap::HEAP_POS_NONE {
                    let cpu = tref.last_cpu.load(Ordering::Relaxed) as usize;
                    let mut rq = percpu_rq()[cpu].lock();
                    // Re-check under lock — may have been popped or stolen.
                    let pos = t.eevdf_heap_pos;
                    if pos != super::heap::HEAP_POS_NONE {
                        rq.eevdf_heap.decrease_key(pos as usize, 0);
                    }
                }
            }
            break;
        }
    }
}

/// Reset a thread's effective priority back to its base priority.
/// Lock-free: uses atomic store on prio + direct write to effective_priority.
///
/// If the thread was temporarily promoted to SCHED_RT by `boost_priority`,
/// restore it to SCHED_NORMAL so subsequent enqueues route through EEVDF.
pub fn reset_priority(tid: ThreadId) {
    let tref = thread_ref(tid);
    let base = tref.base_priority;
    tref.prio.store(base, Ordering::Release);
    let t = unsafe { thread_mut_from_ref(tid) };
    t.effective_priority = base;
    // Restore scheduling class if temporarily promoted by PI.
    // (No threads are permanently SCHED_RT today; SCHED_IDLE is never boosted.)
    if t.sched_class == super::thread::SCHED_RT {
        t.sched_class = SCHED_NORMAL;
    }
}

/// Get a thread's current effective priority (lock-free).
pub fn thread_effective_priority(tid: ThreadId) -> u8 {
    if (tid as usize) < RadixTable::capacity() {
        thread_ref(tid).prio.load(Ordering::Acquire)
    } else {
        255
    }
}

/// Boost receiver's priority from the sender (no-op for queued messages).
///
/// Priority inheritance for IPC is handled via two mechanisms:
/// 1. call/reply: the reply-cap mechanism in recv_with_cap does
///    donate_priority from the caller's thread — this is authoritative.
/// 2. DirectTransfer (send): the sys_send/sys_send_nb handlers call
///    boost_priority directly with the sender's effective priority when
///    a parked receiver is found.
///
/// For queued messages there is no synchronous relationship between
/// sender and receiver, so no priority inheritance is needed.
#[inline(always)]
pub fn boost_priority_from_sender(_receiver_tid: ThreadId, _data4: &mut u64) {
    // Intentional no-op — see doc comment above.
}

// --- L4-style handoff scheduling ---

/// Store the current frame SP for use by park/handoff functions.
/// Called by the arch exception handler before dispatching a syscall.
pub fn store_frame_sp(sp: u64) {
    let cpu = smp::cpu_id() as usize;
    current_frame_sp()[cpu].store(sp, Ordering::Release);
    // Also store per-thread so the value survives preemptive CPU migration.
    let tid = smp::get(cpu as u32).current_thread.load(Ordering::Relaxed);
    // #208 sentinel write guard: if current_thread.load(Relaxed) observed a
    // transient 0 (e.g. between two valid set_current_thread stores on a
    // peer CPU, before the new value globally propagates), writing to
    // THREAD_TABLE[0].syscall_frame_sp would corrupt the sentinel slot.
    // Boot 1750 wild-RIP traced to exactly this: the sentinel slot held a
    // freshly-created thread's saved_sp value (kstack VA), which later
    // surfaced as a wild execute-target via the block_current resync path.
    //
    // Bail and increment a counter so we can see how often it fires.
    // Skipping the per-thread store leaves only the per-CPU current_frame_sp
    // updated — which is what existed before the per-thread mirror was
    // added and still correctly serves the syscall_frame_sp consumers on
    // the local CPU.  Consumers that walk per-thread on remote CPUs
    // would temporarily miss this one entry; that window is tiny because
    // by the next store_frame_sp call current_thread will have settled.
    if tid == 0 || (tid as usize) >= RadixTable::capacity() {
        static SENTINEL_GUARD_HITS: core::sync::atomic::AtomicU64 =
            core::sync::atomic::AtomicU64::new(0);
        let n = SENTINEL_GUARD_HITS
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if n < 32 {
            crate::println!(
                "STORE-FRAME-SP-GUARD: cpu={} sp={:#x} tid={} (sentinel, skipped) n={}",
                cpu, sp, tid, n,
            );
        }
        return;
    }
    unsafe { thread_mut_from_ref(tid) }.syscall_frame_sp = sp;
}

/// Read the current exception frame SP for a given CPU.
pub fn read_frame_sp(cpu: usize) -> u64 {
    current_frame_sp()[cpu].load(Ordering::Acquire)
}

/// Take (read and clear) any pending context switch SP.
/// Called by the arch exception handler after syscall dispatch returns.
/// Returns 0 if no switch is pending.
pub fn take_pending_switch() -> u64 {
    let cpu = smp::cpu_id() as usize;
    pending_switch_sp()[cpu].swap(0, Ordering::AcqRel)
}

/// Clear the park-switch-pending flag for the given CPU.  Called at the
/// **start** of the arch exception handler — by that point the previous
/// exception's `mov rsp, rax` (stack switch) has completed and the old
/// thread's kernel stack is no longer in use.  This unblocks
/// `wake_parked_thread`'s spin-wait.
pub fn clear_pending_switch(cpu: usize) {
    // Phase-5b stall instrumentation (aarch64-only).  If aarch64 IRQ
    // entry never calls this, this counter stays 0 — direct evidence
    // that the parking CPU never clears `stack_switch_pending`, so
    // `wake_parked_thread` is forced down the IPI path forever.
    #[cfg(target_arch = "aarch64")]
    {
        if cpu < crate::arch::aarch64::irq::PER_CPU_CLEAR_SWITCH_COUNT.len() {
            crate::arch::aarch64::irq::PER_CPU_CLEAR_SWITCH_COUNT[cpu]
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    park_switch_pending()[cpu].store(false, Ordering::Release);
    // Also clear the per-thread stack_switch_pending for whatever thread
    // was parked on this CPU. The assembly stack switch is now complete.
    let pt = parked_tid();
    if cpu < pt.len() {
        let tid = pt[cpu].swap(u32::MAX, Ordering::AcqRel);
        if tid != u32::MAX {
            let tref = thread_ref(tid);
            tref.stack_switch_pending.store(false, Ordering::Release);

            // SeqCst fence — pairs with the matching fence in
            // `wake_parked_thread` between its CAS PARK_COMMITTED→PARK_WOKEN
            // and its load of `stack_switch_pending`.  Loom found that on
            // a non-TSO ISA (aarch64/riscv64) a waker's Acquire load of
            // `stack_switch_pending` after observing PARK_COMMITTED can
            // legally return the older `true` value (set by
            // `park_current_for_ipc` before its commit-CAS), missing this
            // CPU's later `store(false)` — even though program order on
            // *this* CPU is store-false then CAS-WOKEN→NONE.  Without a
            // total order across the two variables the waker takes the
            // slow IPI path, the IPI lands here after `parked_tid` has
            // been swapped to MAX, and no-one ever enqueues the woken
            // thread → permanent lost wakeup.  SeqCst fences on both
            // sides give us a single total order: either this store(false)
            // is before the waker's load (waker reads false, takes fast
            // path), or our CAS reads PARK_WOKEN (we win arbitration and
            // enqueue here).  x86 TSO already provides this implicitly,
            // so the fence is a no-op there in practice.
            core::sync::atomic::fence(Ordering::SeqCst);

            // Self-enqueue handshake: if a wake already fired while we
            // were stack-switching, it left park_state = PARK_WOKEN and
            // skipped the enqueue (waiting for us).  CAS WOKEN → NONE
            // to claim ownership; if we win, do the percpu_enqueue
            // here on the local (parking) CPU.  If wake's fast path
            // beat us, the CAS fails and we no-op.
            if tref
                .park_state
                .compare_exchange(PARK_WOKEN, PARK_NONE, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let prio = tref.prio.load(Ordering::Acquire);
                tref.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
                unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Ready;
                record_trans(tid as u32, 11, ThreadState::Ready, ON_CPU_PENDING);
                trace_sched(tid, 16); // 16 = ipc_wake (deferred enqueue path)
                set_enq_tag(8); // 8 = clear_pending_switch deferred enqueue
                percpu_enqueue(cpu as u32, prio, tid);
                // We're already on the parking CPU and about to return
                // from the exception that triggered this clear; setting
                // need_resched ensures the return picks up the newly
                // enqueued thread.
                smp::get(cpu as u32).need_resched.store(true, Ordering::Release);
                trace_point("clear_pending_switch.deferred_enqueue", tid as u32);
            }
        }
    }
}

/// Check if a pending context switch is queued on this CPU.
/// Used by syscall dispatch to detect that park_current_for_ipc or handoff_to
/// changed `current_thread` — callers must skip thread-specific epilogue
/// (signal delivery, is_killed) since those queries would use the wrong thread.
pub fn has_pending_switch() -> bool {
    let cpu = smp::cpu_id() as usize;
    pending_switch_sp()[cpu].load(Ordering::Acquire) != 0
}

/// Get a thread's IPC-injection frame SP. Used by inject_recv_into_frame
/// and inject_fault_into_frame to write into a parked thread's syscall
/// exception frame. Returns ipc_frame_sp (set by pre_save_frame), which
/// is immune to timer-driven try_switch overwriting saved_sp.
pub fn thread_saved_sp(tid: ThreadId) -> u64 {
    let t = thread_ref(tid);
    let ipc = t.ipc_frame_sp;
    if ipc != 0 { ipc } else { t.saved_sp }
}

/// Park the current thread for IPC (true off-CPU park).
/// Saves the current SP from CURRENT_FRAME_SP, marks the thread Blocked,
/// picks the next runnable thread, and stores its SP in PENDING_SWITCH_SP.
/// The exception handler will complete the switch on return.
///
/// Park state constants for the IPC park protocol.
/// See `park_current_for_ipc` and `wake_parked_thread`.
pub const PARK_NONE: u8 = 0;
pub const PARK_ENQUEUED: u8 = 1;
pub const PARK_COMMITTED: u8 = 2;
/// Wake fired while the thread was at COMMITTED but its parking CPU
/// hadn't completed the assembly stack switch yet.  Whoever first
/// CAS's `WOKEN → NONE` claims responsibility for `percpu_enqueue`-ing
/// the thread:
///   - `wake_parked_thread` itself, if it observes `stack_switch_pending`
///     already cleared (fast path: stack switch was already done).
///   - `clear_pending_switch` on the parking CPU, on its next exception
///     entry after the assembly switch completes.
/// The arbitration eliminates the unbounded spin that the previous
/// design had in `wake_parked_thread` (waiting for the parking CPU to
/// finish its `mov rsp, rax` switch); under KVM virt-timer coalescing
/// that spin was the dominant cost of `sys_reply` (~17 ms avg of 24 ms
/// total handler time per boot 418's reply-time split data).
pub const PARK_WOKEN: u8 = 3;

/// Pre-save the current exception frame pointer into the thread's `saved_sp`
/// and set park_state to PARK_ENQUEUED.
///
/// Must be called BEFORE the thread becomes visible in a HAMT turnstile
/// (via `port_enqueue_with_check`), so that if a sender dequeues the thread
/// and calls `inject_recv_into_frame` before `park_current_for_ipc` runs,
/// the injection writes to the correct frame.
pub fn pre_save_frame(tid: ThreadId) {
    let frame_sp = unsafe { thread_mut_from_ref(tid) }.syscall_frame_sp;
    let t = unsafe { thread_mut_from_ref(tid) };
    // #208 KEPOCH guard.
    if validate_kstack_inject(tid, frame_sp, "pre_save_frame") {
        write_saved_sp(t, frame_sp);
        record_saved_sp_write(tid, frame_sp, 10); // pre_save_frame
        t.saved_sp_source = 3; // pre_save_frame
        t.ipc_frame_sp = frame_sp;

        // #208 DR0 arm.  On the FIRST pre_save_frame for any non-idle
        // tid, set DR0 to watch writes to its iretq CS slot (offset
        // +144 from saved_sp).  Catches the writer that corrupts
        // iretq fields.  Single-CPU watch.  We don't pick a specific
        // tid because the corruption hits various ones — first parker
        // is good enough.
        #[cfg(target_arch = "x86_64")]
        {
            static DR0_ARMED: core::sync::atomic::AtomicBool =
                core::sync::atomic::AtomicBool::new(false);
            let idle_id = smp::current()
                .idle_thread_id
                .load(Ordering::Relaxed);
            if tid != idle_id
                && !DR0_ARMED.swap(true, Ordering::Relaxed)
            {
                let cs_slot = frame_sp + 144;
                crate::arch::x86_64::gdt::dr0_set_watch_write_qword(cs_slot);
                crate::println!(
                    "DR0-ARM: tid={} cs_slot={:#x} cpu={}",
                    tid, cs_slot, smp::cpu_id(),
                );
            }
        }
    }
    // Clear stale wakeup flag from a prior block_current iteration. Without
    // this, a SIGCHLD that called wake_thread on a thread that then exited
    // block_current and did a fresh sys_call would leave wakeup=true across
    // the park boundary, making rescue_orphaned_threads falsely detect the
    // new call as stuck.
    thread_ref(tid).wakeup.store(false, Ordering::Release);
    // Publish saved_sp/ipc_frame_sp before becoming visible. The Release on
    // park_state ensures both fields are visible to any thread that reads
    // park_state ≥ 1.
    thread_ref(tid).park_state.store(PARK_ENQUEUED, Ordering::Release);
}

/// Unlike block_current() which spins on-CPU, this truly takes the thread
/// off the run queue and saves its frame for later injection by a sender.
///
/// Uses a CAS-based state machine with `wake_parked_thread` to handle the
/// race where a sender dequeues and wakes us between HAMT enqueue and this
/// function. The caller must have already called `pre_save_frame()` (which
/// sets park_state = PARK_ENQUEUED) and `port_enqueue_with_check()`.
pub fn park_current_for_ipc(reason: BlockReason) {
    // Disable IRQs for the entire function. With preemptive syscalls, a
    // timer firing after state=Blocked would let try_switch see a Blocked
    // thread still on-CPU, overwrite state to Ready, and re-enqueue it —
    // creating a double-schedule with the IPC HAMT entry.
    let irq_saved = crate::arch::irq::disable();

    let cpu = smp::cpu_id() as usize;
    drain_deferred_requeue(cpu as u32);

    let cpu_idx = cpu as u32;
    let pcpu = smp::current();
    let tid = pcpu.current_thread.load(Ordering::Relaxed) as usize;
    let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

    // #204 probe: validate Thread struct on park entry — catches
    // corruption that happened during the thread's last quantum.
    validate_thread_canary(tid as ThreadId, "park_ipc.entry");
    // #205 probe: check kernel stack guard canary.  If overflowed,
    // catches the corruption from project_ts_inv_is_thread_corruption.
    check_stack_canary(tid as ThreadId, "park_ipc.entry");

    // Re-assign saved_sp from syscall_frame_sp. pre_save_frame set it
    // earlier, but try_switch may have overwritten saved_sp if a timer
    // preempted us between pre_save_frame and this point.
    // syscall_frame_sp is set once at syscall entry (store_frame_sp) and
    // never touched by try_switch, so it always holds the correct value.
    let t = unsafe { thread_mut_from_ref(tid as ThreadId) };
    let _fsp_park_ipc = t.syscall_frame_sp;
    // #208 KEPOCH guard.
    if validate_kstack_inject(tid as ThreadId, _fsp_park_ipc, "park_ipc") {
        write_saved_sp(t, _fsp_park_ipc);
        record_saved_sp_write(tid as ThreadId, _fsp_park_ipc, 11); // park_ipc
        t.saved_sp_source = 3; // park_ipc
    }
    t.state = ThreadState::Blocked;
    t.blocked_on = reason;

    // Record vCPU-runtime time for CallReply timeout sweep.  Using
    // vcpu_runtime_ns rather than wallclock monotonic_ns makes the 30s
    // CALL_REPLY_TIMEOUT_NS robust to KVM host descheduling: a long
    // host pause (200s+ TICK-GAP observed) advances wallclock but not
    // vcpu_runtime, so an in-flight call doesn't get falsely abandoned
    // with CALL_REPLY_SERVER_DIED.  Paravirt Layer 1 defensive fix —
    // see project_scheduler_paravirt_robustness.
    if matches!(reason, BlockReason::CallReply(_)) {
        thread_ref(tid as ThreadId).call_blocked_ns.store(
            crate::arch::timer::vcpu_runtime_ns(),
            Ordering::Release,
        );
        trace_point("park_ipc.CallReply", tid as u32);
    }

    // Release on_cpu BEFORE committing park_state. Once park_state is
    // COMMITTED, wake_parked_thread may re-enqueue us on any CPU. If
    // on_cpu still holds a stale CPU value at that point, the scheduling
    // CPU's CAS will fail (DOUBLE-SCHED). By clearing on_cpu first, we
    // ensure the re-enqueued thread passes the CAS.
    if (tid as ThreadId) != idle_id {
        thread_ref(tid as ThreadId).on_cpu.store(u32::MAX, Ordering::Release);
        // #135 action=21: park_ipc set on_cpu=MAX.  This is the IPC
        // call/reply blocking path.  If a rescue captures a tid whose
        // TRANS-RING ends with action=21 just before the orphan signature
        // (on_cpu=PEND, in_q=false, heap_pos=NONE), the orphan was
        // produced by an IPC park whose wake_parked_thread didn't
        // complete the percpu_enqueue (action=12 would normally follow).
        record_trans(tid as u32, 21, ThreadState::Blocked, u32::MAX);
    }
    trace_sched(tid as u32, 14); // 14=park_ipc (state=Blocked, on_cpu=MAX)

    // Mark per-thread stack_switch_pending BEFORE park_state CAS. Once
    // COMMITTED, wake_parked_thread may fire on another CPU. It spins on
    // this per-thread flag (not the per-CPU one) to wait for our assembly
    // stack switch. Cleared by clear_pending_switch at exception entry.
    thread_ref(tid as ThreadId).stack_switch_pending.store(true, Ordering::Release);
    parked_tid()[cpu].store(tid as u32, Ordering::Release);

    // Try to commit the park: CAS PARK_ENQUEUED → PARK_COMMITTED.
    // If this fails, wake_parked_thread already CAS'd PARK_ENQUEUED → PARK_NONE,
    // meaning a sender woke us before we could switch out. The message is
    // already injected into our saved frame — just undo Blocked and return.
    if thread_ref(tid as ThreadId)
        .park_state
        .compare_exchange(PARK_ENQUEUED, PARK_COMMITTED, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // Early wake — no switch will happen. Clear per-thread flag.
        thread_ref(tid as ThreadId).stack_switch_pending.store(false, Ordering::Release);
        parked_tid()[cpu].store(u32::MAX, Ordering::Release);
        // Restore on_cpu.
        if (tid as ThreadId) != idle_id {
            thread_ref(tid as ThreadId).on_cpu.store(cpu_idx, Ordering::Release);
        }
        // #202 TS wake gap #4: if wake_parked_thread's `ts_blocked_on
        // != 0` check ran BEFORE port_enqueue_with_check set the field,
        // its defensive cleanup_blocked was skipped — and the early-wake
        // CAS that put us here still won.  We now hold a non-zero
        // ts_blocked_on but no actual park is going to happen.  Without
        // cleanup, the next recv_or_park's ts_enqueue trips the
        // TS-DOUBLE-ENQ guard on the same TS (boot 554 tid=19 pattern).
        // cleanup_blocked is idempotent (swap-zero short-circuits when
        // already 0), so this is safe even when the waker already
        // cleaned up.
        if thread_ref(tid as ThreadId)
            .ts_blocked_on
            .load(Ordering::Relaxed)
            != 0
        {
            crate::sync::turnstile::cleanup_blocked(tid as u32);
        }
        t.state = ThreadState::Running;
        return;
    }

    // Read SA state (lock-free).
    let parked_task_id = t.task_id;
    let sa_enabled = task_ref(parked_task_id).sa_enabled;

    // Pick next thread from per-CPU queue (don't re-enqueue current — it's Blocked).
    // #173 Phase 3: gated dispatch — same pattern as voluntary_reschedule
    // (Phase 2).  Parker has no self-pick issue: tid is going Blocked, so
    // it's not in the rq at this point.
    let claimed_by_helper =
        DISPATCH_USE_CLAIM_HELPER.load(Ordering::Relaxed);
    let next_id = if claimed_by_helper {
        percpu_pick_next_and_claim(cpu_idx, idle_id, pcpu, 3 /* park_ipc */)
    } else {
        percpu_pick_next(cpu_idx, idle_id)
    };
    let prev_task = thread_ref(tid as ThreadId).task_id;
    let next_task = thread_ref(next_id).task_id;
    if prev_task != next_task {
        let next_root = {
            let tptr = TASK_TABLE.get(next_task) as *const Task;
            if !tptr.is_null() {
                unsafe { (*tptr).page_table_root }
            } else {
                0
            }
        };
        if next_root != 0 {
            crate::mm::hat::switch_page_table(next_root);
        } else {
            let kern_root = crate::mm::hat::kernel_pt_root();
            if kern_root != 0 {
                crate::mm::hat::switch_page_table(kern_root);
            }
        }
    }

    crate::arch::trapframe::update_kernel_stack(next_id as u32, thread_ref(next_id).stack_base + kstack_size());

    // on_cpu for parked thread was released above (before park_state CAS).
    // Claim on_cpu for next (ON_CPU_PENDING → cpu).
    if next_id != idle_id {
        if claimed_by_helper {
            // Helper ran the CAS + bookkeeping under rq.lock already.
        } else if let Err(other_cpu) = thread_ref(next_id).on_cpu.compare_exchange(
            ON_CPU_PENDING, cpu_idx, Ordering::AcqRel, Ordering::Acquire,
        ) {
            record_trans(next_id as u32, TRANS_CAS_FAIL, thread_ref(next_id).state, other_cpu);
            // See try_switch CAS_FAIL — benign regardless of other_cpu.
            CAS_FAIL_RESCUE_BAILS.fetch_add(1, Ordering::Relaxed);
            // Pick idle instead.
            let idle_sp2 = thread_ref(idle_id).saved_sp;
            unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
            set_current_thread(pcpu, idle_id);
            pending_switch_sp()[cpu].store(idle_sp2, Ordering::Release);
            return;
        } else {
            record_trans(next_id as u32, TRANS_CAS_OK, ThreadState::Running, cpu_idx);
            thread_ref(next_id).on_cpu_set_by.store(3, Ordering::Relaxed); // 3=park_ipc
            // #120 dispatch-symmetry: clear pending state + bump cas_ok counter.
            dispatch_cas_ok(pcpu, next_id);
            // Set Running IMMEDIATELY after CAS — close TOCTOU window (see try_switch).
            unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
        }
    } else {
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
    }

    // Safety: next_id was just dequeued, we own it.
    let next_t = unsafe { thread_mut_from_ref(next_id) };
    set_current_thread(pcpu, next_id);
    let next_sp = next_t.saved_sp;

    // Sanity check: saved_sp must be within the thread's kstack.
    // Idle threads run on boot stacks (ring 0), not their allocated kstack.
    {
        let is_idle = next_id == idle_id;
        let kbase = next_t.stack_base;
        let kend = kbase as u64 + kstack_size() as u64;
        if !is_idle && (next_sp < kbase as u64 || next_sp >= kend) {
            #[cfg(target_arch = "x86_64")]
            {
                use crate::arch::x86_64::serial::{put_bytes, put_hex_u64, put_dec_u64};
                let mut buf = [0u8; 192];
                let mut k = 0;
                put_bytes(&mut buf, &mut k, b"BUG: park_ipc: tid=");
                put_dec_u64(&mut buf, &mut k, next_id as u64);
                put_bytes(&mut buf, &mut k, b" saved_sp=");
                put_hex_u64(&mut buf, &mut k, next_sp);
                put_bytes(&mut buf, &mut k, b" OUTSIDE kstack ");
                put_hex_u64(&mut buf, &mut k, kbase as u64);
                put_bytes(&mut buf, &mut k, b"..");
                put_hex_u64(&mut buf, &mut k, kend);
                put_bytes(&mut buf, &mut k, b" (source=");
                put_dec_u64(&mut buf, &mut k, next_t.saved_sp_source as u64);
                put_bytes(&mut buf, &mut k, b")\n");
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            #[cfg(not(target_arch = "x86_64"))]
            crate::println!(
                "BUG: park_ipc: tid={} saved_sp={:#x} OUTSIDE kstack {:#x}..{:#x} (source={})",
                next_id, next_sp, kbase, kend, next_t.saved_sp_source
            );
            // Kill this thread and switch to idle instead.
            thread_ref(next_id).killed.store(true, Ordering::Release);
            let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);
            let idle_sp = thread_ref(idle_id).saved_sp;
            unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
            set_current_thread(pcpu, idle_id);
            pending_switch_sp()[cpu].store(idle_sp, Ordering::Release);
            return;
        }
    }

    // Reprogram the one-shot timer so this CPU gets a tick within one
    // interval. Without this, the dynamic tick may have the timer set far
    // in the future (up to MAX_IDLE_NS = 1s). If a remote CPU wakes us via
    // wake_parked_thread and enqueues on this CPU, the enqueued thread would
    // sit in the run queue until the next timer fires. A prompt tick ensures
    // try_switch() picks it up quickly.
    crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);

    // Mark that this CPU has a park-triggered stack switch pending.
    // wake_parked_thread spins on this flag to wait for our assembly switch.
    park_switch_pending()[cpu].store(true, Ordering::Release);

    // Store pending_switch and do SA notification BEFORE restoring IRQs.
    // With preemptive syscalls, a timer between current_thread update and
    // the exception handler consuming pending_switch would corrupt state:
    // try_switch would see the wrong current_thread on the old thread's stack.
    pending_switch_sp()[cpu].store(next_sp, Ordering::Release);

    // Scheduler activation: notify userspace that a kthread blocked.
    if sa_enabled {
        let tptr = TASK_TABLE.get(parked_task_id) as *mut Task;
        let task = unsafe { &*tptr };
        let waiter = task.sa_waiter.load(Ordering::Acquire);
        if waiter != u32::MAX && waiter as usize != tid {
            task.sa_event.store(tid as u64, Ordering::Release);
            task.sa_pending.store(true, Ordering::Release);
            wake_thread(waiter);
        }
    }

    // Leave IRQs disabled — the exception handler will consume pending_switch
    // and perform the actual stack switch via iretq/eret/sret. Restoring IRQs
    // here would open a window where current_thread != physical stack.
    let _ = irq_saved;
}

/// #240 / #216 follow-up: park the current thread on async-PF when the
/// fault was taken on IST 4 (#216 Phase 3).
///
/// The standard `async_pf_park` → `block_current` path spin-WFIs on the
/// caller's stack.  When the caller is on IST 4, a subsequent #PF on the
/// same CPU pushes its CPU-saved iretq frame at IST4_TOP, overlaying
/// ours — when we eventually resume, we iretq from a corrupted frame.
///
/// This helper avoids that by performing the park as a direct synthetic
/// dispatch (no block_current):
///
///   1. Copies the 22-quad frame (15 gpregs from `__isr_common`'s
///      prologue + 2 quads vector/error + 5-quad CPU iretq) from IST 4
///      to the faulting thread's kstack at `stack_top - 22*8`.
///   2. Sets the thread's `saved_sp` to the kstack copy.  When
///      `wake_thread` re-enqueues us and a future `try_switch` picks us
///      up, the asm postlude pops from the kstack copy and iretqs back
///      to user mode — re-executing the faulting instruction with the
///      page now present.
///   3. Marks the thread `Blocked / PagerWait`, releases on_cpu.
///   4. Picks the next thread and returns its `saved_sp`.  The asm
///      postlude (`mov rsp, rax; pop gpregs; iretq`) lands us on the
///      next thread's frame.
///
/// On failure (CAS race on next pick, or new_sp out of kstack range)
/// returns the original `frame_sp` so the caller's normal path
/// continues with the legacy block_current fallback.
///
/// Caller invariants: `frame_sp` is the SP at handle_page_fault_x86's
/// entry (the same SP `__isr_common` saved into r12).  The full 22
/// quads at that location are the live iretq+gpregs frame.  The thread
/// is NOT idle.  IRQs may be either enabled or disabled on entry —
/// this helper disables them for its duration.
#[cfg(target_arch = "x86_64")]
pub fn park_faulting_from_ist(frame_sp: u64) -> u64 {
    let irq_saved = crate::arch::irq::disable();

    let tid = current_thread_id();
    let pcpu = smp::current();
    let cpu = smp::cpu_id();
    let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed) as ThreadId;

    if tid == idle_id {
        let _ = irq_saved;
        return frame_sp;
    }

    let t = unsafe { thread_mut_from_ref(tid) };
    let kbase = t.stack_base as u64;
    let ksize = kstack_size() as u64;
    let ktop = kbase + ksize;

    // Frame layout per kernel/src/arch/x86_64/vectors.S:
    //   15 gpregs + 2 quads (vector_number, error_code) + 5 iretq = 22 quads.
    const FRAME_QUADS: usize = 22;
    let frame_bytes = (FRAME_QUADS as u64) * 8;
    let new_sp = ktop.saturating_sub(frame_bytes);

    if new_sp < kbase || new_sp + frame_bytes > ktop {
        // kstack too small for the frame — shouldn't happen at 1 MiB
        // kstack sizes; fall back.
        let _ = irq_saved;
        return frame_sp;
    }

    // Copy the IST 4 frame contents to kstack.  Validated kstack range
    // above so `new_sp` is in this thread's own kstack.
    unsafe {
        let src = frame_sp as *const u64;
        let dst = new_sp as *mut u64;
        for i in 0..FRAME_QUADS {
            dst.add(i).write(src.add(i).read());
        }
    }

    // Publish the kstack frame as the parked thread's saved state.
    write_saved_sp(t, new_sp);
    record_saved_sp_write(tid, new_sp, 13); // 13 = park_faulting_from_ist
    t.saved_sp_source = 7; // 7 = park_faulting_from_ist
    t.state = ThreadState::Blocked;
    t.blocked_on = crate::sched::thread::BlockReason::PagerWait;

    thread_ref(tid).on_cpu.store(u32::MAX, Ordering::Release);
    record_trans(tid as u32, 22, ThreadState::Blocked, u32::MAX);

    // Pick next and dispatch — mirrors park_current_for_ipc's tail
    // without the IPC-specific arbitration (no port, no PARK_ENQUEUED
    // CAS dance — this thread is being parked unconditionally on
    // PagerWait, and only async_pf_wake will re-enqueue it).
    // #173: gated dispatch — this thread is going Blocked, so no self-pick
    // concern.  Routes the pick through the atomic claim helper when the
    // gate is on so this park tail can't leave a stranded PENDING.
    let next_id = if DISPATCH_USE_CLAIM_HELPER.load(Ordering::Relaxed) {
        percpu_pick_next_and_claim(cpu, idle_id, pcpu, 3 /* park */)
    } else {
        percpu_pick_next(cpu, idle_id)
    };

    let prev_task = t.task_id;
    let next_task = thread_ref(next_id).task_id;
    if prev_task != next_task {
        let next_root = {
            let tptr = TASK_TABLE.get(next_task) as *const Task;
            if !tptr.is_null() {
                unsafe { (*tptr).page_table_root }
            } else {
                0
            }
        };
        if next_root != 0 {
            crate::mm::hat::switch_page_table(next_root);
        } else {
            let kern_root = crate::mm::hat::kernel_pt_root();
            if kern_root != 0 {
                crate::mm::hat::switch_page_table(kern_root);
            }
        }
    }

    crate::arch::trapframe::update_kernel_stack(
        next_id as u32,
        thread_ref(next_id).stack_base + kstack_size(),
    );

    if next_id != idle_id {
        pcpu.dispatching_tid.store(next_id, Ordering::Release);
        if thread_ref(next_id)
            .on_cpu
            .compare_exchange(ON_CPU_PENDING, cpu, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            CAS_FAIL_RESCUE_BAILS.fetch_add(1, Ordering::Relaxed);
            pcpu.dispatching_tid.store(0, Ordering::Release);
            let idle_sp = thread_ref(idle_id).saved_sp;
            unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
            set_current_thread(pcpu, idle_id);
            let _ = irq_saved;
            return idle_sp;
        }
        record_trans(next_id as u32, TRANS_CAS_OK, ThreadState::Running, cpu);
        thread_ref(next_id).on_cpu_set_by.store(7, Ordering::Relaxed); // 7=park_from_ist
        dispatch_cas_ok(pcpu, next_id);
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
        pcpu.dispatching_tid.store(0, Ordering::Release);
    } else {
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
    }

    set_current_thread(pcpu, next_id);
    let next_sp = thread_ref(next_id).saved_sp;
    let _ = irq_saved;
    next_sp
}

/// Wake a parked thread by marking it Ready and enqueueing it.
///
/// Uses a CAS-based state machine with `park_current_for_ipc`:
/// - CAS PARK_ENQUEUED → PARK_NONE: early wake (thread not yet off-CPU).
///   The thread is still running; park_current_for_ipc's CAS will fail and
///   it will skip the context switch. We must NOT enqueue (thread is running).
/// - CAS PARK_COMMITTED → PARK_NONE: normal wake (thread is off-CPU).
///   Set state = Ready and enqueue on a run queue.
pub fn wake_parked_thread(tid: ThreadId) {
    let tref = thread_ref(tid);
    trace_point("wake_parked.entry", tid as u32);
    // #204 probe: validate Thread struct of target on wake entry —
    // catches corruption between the time the parker set up its state
    // and the waker reaches it.
    validate_thread_canary(tid, "wake_parked.entry");
    // #205 stack guard canary on wake target.
    check_stack_canary(tid, "wake_parked.entry");

    // Boot 553 #196 sweep: defensive turnstile cleanup.  Most callers
    // (port_dequeue_one in wake_recv_waiter, DirectTransfer in
    // send_direct) dequeue from the turnstile BEFORE calling
    // wake_parked_thread, so by the time we get here ts_blocked_on=0.
    // BUT: rescue paths (scheduler.rs:4410 abandon, 7213 stuck-pending,
    // 8089 server-died) call wake_parked_thread directly on a tid
    // that may still be linked.  Without this cleanup, the woken
    // thread runs, calls a new recv_or_park, and ts_enqueue's
    // double-enqueue guard fires (boot 553 caught tid=19 still on
    // TS at position 3 after never being dequeued).  cleanup_blocked
    // is a no-op when ts_blocked_on=0 so the common-path cost is
    // a single relaxed load.
    if tref.ts_blocked_on.load(Ordering::Relaxed) != 0 {
        crate::sync::turnstile::cleanup_blocked(tid);
    }

    // Try early wake: CAS PARK_ENQUEUED → PARK_NONE.
    // If the thread hasn't committed to parking yet, just prevent the park.
    // park_current_for_ipc's CAS(ENQUEUED→COMMITTED) will fail and it will
    // undo its Blocked state and continue running.
    if tref
        .park_state
        .compare_exchange(PARK_ENQUEUED, PARK_NONE, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        trace_point("wake_parked.early_wake", tid as u32);
        record_wake_trace(tid, 1, smp::cpu_id(), u32::MAX);
        unsafe { thread_mut_from_ref(tid) }.ipc_frame_sp = 0;
        return;
    }

    // Try normal wake: CAS PARK_COMMITTED → PARK_WOKEN.
    // Thread is at COMMITTED, but its parking CPU may not have completed
    // the assembly stack switch yet.  Transition to PARK_WOKEN and let
    // arbitration decide who enqueues:
    //   - This wake's fast path (if stack_switch_pending is already false)
    //   - clear_pending_switch on the parking CPU (deferred path)
    // The CAS PARK_WOKEN → PARK_NONE is the arbitration: whoever wins
    // does the enqueue, the other no-ops.  No spin.
    if tref
        .park_state
        .compare_exchange(PARK_COMMITTED, PARK_WOKEN, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        trace_point("wake_parked.committed_wake", tid as u32);
        unsafe { thread_mut_from_ref(tid) }.ipc_frame_sp = 0;
        let waker_cpu = smp::cpu_id();
        let parking_cpu = tref.last_cpu.load(Ordering::Relaxed);

        // SeqCst fence — pairs with the matching fence in
        // `clear_pending_switch` between its `stack_switch_pending.store(false)`
        // and its CAS PARK_WOKEN→PARK_NONE.  Loom found that on a non-TSO
        // ISA (aarch64/riscv64) without this fence the Acquire load below
        // can legally observe the *older* `true` value — set by
        // `park_current_for_ipc` before its commit-CAS — even though the
        // parking CPU's `clear_pending_switch` has already stored `false`
        // and given up on the WOKEN→NONE CAS (which then fails because we
        // hadn't reached this point yet).  Result: we'd take the slow IPI
        // path, but `parked_tid` is already MAX so the IPI's
        // `clear_pending_switch` no-ops → permanent lost wakeup.  With
        // SeqCst fences on both sides, store(false) and the load below
        // are totally ordered, so either we read `false` and take the
        // fast path, or `clear_pending_switch` reads `PARK_WOKEN` and
        // enqueues on its side.  x86 TSO already provides this implicitly.
        // Surgical fence preferred over upgrading the bool's load/store to
        // SeqCst because only this one fast-path read needs the
        // cross-variable ordering — the spin-wait readers at handlers.rs
        // L843, scheduler.rs L3526 / L6303 reload until they see false and
        // are not vulnerable to the stale-read window.
        core::sync::atomic::fence(Ordering::SeqCst);

        // Fast path: stack switch already complete.  We can safely do
        // the enqueue ourselves and apply steal-to-waker re-targeting.
        if !tref.stack_switch_pending.load(Ordering::Acquire) {
            if tref
                .park_state
                .compare_exchange(PARK_WOKEN, PARK_NONE, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let prio = tref.prio.load(Ordering::Acquire);
                // Layer 3 paravirt: steal-aware target.  Default to the
                // parking CPU (where the thread last ran) but reroute
                // when that CPU is currently being host-stolen so the
                // re-dispatch doesn't immediately pend.
                let target = choose_wake_target_steal_aware(parking_cpu);
                // NEW_INV: store ON_CPU_PENDING BEFORE state=Ready.
                tref.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
                unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Ready;
                record_trans(tid as u32, 12, ThreadState::Ready, ON_CPU_PENDING);
                trace_sched(tid, 16);
                set_enq_tag(6);
                percpu_enqueue(target, prio, tid);
                if target == waker_cpu {
                    smp::get(waker_cpu).need_resched.store(true, Ordering::Release);
                    crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);
                    trace_point("wake_parked.local_resched", tid as u32);
                } else {
                    crate::arch::irq::send_reschedule_ipi(target);
                    trace_point("wake_parked.remote_ipi", tid as u32);
                }
                record_wake_trace(tid, 2, waker_cpu, parking_cpu);
                return;
            }
            // CAS failed: clear_pending_switch beat us.  It already
            // enqueued.  Done.
            trace_point("wake_parked.lost_to_cps", tid as u32);
            record_wake_trace(tid, 3, waker_cpu, parking_cpu);
            return;
        }

        // Slow path: stack switch still pending.  Don't enqueue here.
        // Send IPI so the parking CPU wakes from HLT and runs its
        // exception entry — clear_pending_switch will then see
        // PARK_WOKEN and do the enqueue locally.  This is what
        // eliminates the unbounded spin: wake's worst-case latency
        // is now bounded by the IPI delivery + parking CPU's
        // exception entry path, not by the parking CPU's vCPU
        // de-scheduling under KVM.
        if parking_cpu == waker_cpu {
            // We are the parking CPU (rare — wake fired while still on
            // syscall path before exception return).  Set need_resched
            // and reprogram timer so exception entry runs promptly.
            smp::get(waker_cpu).need_resched.store(true, Ordering::Release);
            crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);
            trace_point("wake_parked.deferred_local", tid as u32);
            record_wake_trace(tid, 4, waker_cpu, parking_cpu);
        } else {
            crate::arch::irq::send_reschedule_ipi(parking_cpu);
            trace_point("wake_parked.deferred_ipi", tid as u32);
            record_wake_trace(tid, 5, waker_cpu, parking_cpu);
        }
    } else {
        // Both CAS operations failed — park_state is now NONE or WOKEN.
        // If WOKEN, an earlier wake already fired and the enqueue path is
        // in flight (either via clear_pending_switch or the previous
        // wake's fast path) — duplicate wake is a no-op.
        // If NONE, the thread was already woken or never parked.  If this
        // happens on a thread that was just dequeued from the turnstile
        // for IPC injection, the injected message is lost (thread is
        // already running and will return with stale frame data).
        let state = tref.park_state.load(Ordering::Acquire);
        if state == PARK_WOKEN {
            trace_point("wake_parked.dup_wake", tid as u32);
            record_wake_trace(tid, 6, smp::cpu_id(), u32::MAX);
            return;
        }
        record_wake_trace(tid, 7, smp::cpu_id(), u32::MAX);
        let tstate = unsafe { thread_mut_from_ref(tid) }.state;
        let blocked = unsafe { thread_mut_from_ref(tid) }.blocked_on;
        crate::println!(
            "WAKE-PARK-NOOP: tid={} park_state={} thread_state={:?} blocked_on={:?} on_cpu={}",
            tid, state, tstate, blocked, tref.on_cpu.load(Ordering::Relaxed)
        );
    }
}

/// Force-wake CallReply-blocked threads that have been parked longer than
/// CALL_REPLY_TIMEOUT_NS.  Uses the same abandon_for_interrupt CAS as the
/// signal-interrupt path to safely coordinate with concurrent server replies.
/// Called periodically from tick() on CPU 0 (~every 1 second).
///
/// 30s (was 10s) — under heavy lib-load contention (e.g. concurrent
/// xeyes + Xwayland forks each opening 50+ shared libraries through
/// initramfs_srv) a single grant-based read can take >10s of wall-clock
/// while waiting in linux_srv's IPC queue.  The 10s timeout would fire
/// SERVER_DIED on a perfectly healthy chain, causing linux_srv's
/// mmap-fill loop to surface the partial fill as EIO ("file too short"
/// / "failed to map segment from shared object") and Xwayland to bail.
/// 30s is generous enough to ride out boot-time queue spikes without
/// papering over an actual server hang.
const CALL_REPLY_TIMEOUT_NS: u64 = 30_000_000_000; // 30 seconds

#[cold]
#[inline(never)]
fn call_reply_timeout_sweep() {
    // vcpu_runtime_ns matches the scale used to stamp call_blocked_ns
    // in park_ipc — see commentary there.  Host pauses don't advance
    // either, so the 30s threshold reflects real in-guest blocked time.
    let now = crate::arch::timer::vcpu_runtime_ns();
    let max_tid = NEXT_THREAD_ID.load(Ordering::Relaxed).min(200);
    for tid in 1..max_tid {
        let t = unsafe { &*(THREAD_TABLE.get(tid) as *const Thread) };
        if t.task_id == 0 || t.state != ThreadState::Blocked {
            continue;
        }
        let slot = match t.blocked_on {
            BlockReason::CallReply(s) => s,
            _ => continue,
        };
        let park = t.park_state.load(Ordering::Acquire);
        if park != PARK_COMMITTED {
            continue;
        }
        let blocked_ns = t.call_blocked_ns.load(Ordering::Acquire);
        if blocked_ns == 0 || now.saturating_sub(blocked_ns) < CALL_REPLY_TIMEOUT_NS {
            continue;
        }
        // Thread has been in CallReply for >10s. Force-wake with SERVER_DIED.
        if crate::ipc::call_reply::abandon_for_interrupt(slot, tid as u32) {
            let sp = thread_saved_sp(tid as ThreadId);
            if sp != 0 && validate_kstack_inject(tid as ThreadId, sp, "callreply_timeout") {
                let tag = crate::ipc::call_reply::CALL_REPLY_SERVER_DIED;
                unsafe {
                    use crate::arch::trapframe::ExceptionFrame;
                    let frame = &mut *(sp as *mut ExceptionFrame);
                    crate::syscall::handlers::set_return(frame, 0);
                    crate::syscall::handlers::set_reg(frame, 1, tag);
                    crate::syscall::handlers::set_reg(frame, 2, 0);
                    crate::syscall::handlers::set_reg(frame, 3, 0);
                    crate::syscall::handlers::set_reg(frame, 4, 0);
                    crate::syscall::handlers::set_reg(frame, 5, 0);
                    crate::syscall::handlers::set_reg(frame, 6, 0);
                    crate::syscall::handlers::set_reg(frame, 7, 0);
                }
            }
            // Free the cap slot (leases/donation already unwound by abandon).
            let cap_gen = crate::ipc::call_reply::REPLY_CAPS[slot as usize]
                .generation
                .load(Ordering::Acquire);
            crate::ipc::call_reply::free((slot as u64) | ((cap_gen as u64) << 32));
            // Clear the timestamp so we don't re-fire on next sweep.
            t.call_blocked_ns.store(0, Ordering::Relaxed);
            crate::println!(
                "CALL-TIMEOUT: tid={} slot={} task={} port={:#x} tag={:#x} blocked_for={}ms",
                tid, slot, t.task_id, t.call_dest_port, t.call_tag,
                (now - blocked_ns) / 1_000_000
            );
            // Per-CPU dispatch state on CALL-TIMEOUT (#120 instrument G):
            // tells us whether the orphan tid is queue-depth-starved (CPUs
            // busy with other work) or whether dispatch-trigger is lost
            // (CPUs idle but not picking up the orphan).
            {
                let ncpus = crate::sched::smp::num_cpus().min(8);
                let stuck_pending_fires = RESCUE_STUCK_PENDING_FIRES.load(Ordering::Relaxed);
                let rescue_pending = RESCUE_PENDING.load(Ordering::Relaxed);
                let pending_low_fires = PENDING_LOW_FIRES.load(Ordering::Relaxed);
                let self_pick_count = SELF_PICK_COUNT.load(Ordering::Relaxed);
                // #173 Phase 5: gate-split rescue fires + claim-helper counters.
                // GATE_ON ≪ GATE_OFF under matched stress → helper does real work.
                // GATE_ON ≈ GATE_OFF → Type A was a minor contributor; helper still
                // closes the structural bug but isn't a measurable perf win.
                let gate_state = DISPATCH_USE_CLAIM_HELPER.load(Ordering::Relaxed);
                let stuck_gate_on = RESCUE_STUCK_PENDING_FIRES_GATE_ON.load(Ordering::Relaxed);
                let stuck_gate_off = RESCUE_STUCK_PENDING_FIRES_GATE_OFF.load(Ordering::Relaxed);
                let claim_fail = DISPATCH_CLAIM_FAIL.load(Ordering::Relaxed);
                let claim_self_pick = DISPATCH_CLAIM_SELF_PICK.load(Ordering::Relaxed);
                crate::println!(
                    "  CPU-DIAG: rescue_stuck_pending_fires={} rescue_pending_obs={} pending_low_fires={} self_pick={}",
                    stuck_pending_fires, rescue_pending, pending_low_fires, self_pick_count
                );
                crate::println!(
                    "  DISPATCH-DIAG: gate={} stuck_gate_on={} stuck_gate_off={} claim_fail={} claim_self_pick={}",
                    if gate_state { "ON" } else { "OFF" },
                    stuck_gate_on, stuck_gate_off, claim_fail, claim_self_pick
                );
                for c in 0..ncpus {
                    let pcpu = crate::sched::smp::get(c as u32);
                    let cur = pcpu.current_thread.load(Ordering::Acquire);
                    let dispatching = pcpu.dispatching_tid.load(Ordering::Acquire);
                    let need_resched = pcpu.need_resched.load(Ordering::Acquire);
                    // #120 instrumentation J: run-queue depth (try_lock to avoid
                    // contending the rq if some CPU is mid-dispatch).
                    // Snapshot up to 8 EEVDF heap entries for vruntime/deadline
                    // dump — disambiguates "heap stuck because nothing eligible"
                    // (vruntime > min_vruntime for all) vs "phantom heap entries"
                    // (heap holds tids whose state is no longer Ready).
                    let mut entries: [(u32, u64, u64, u8); 8] = [(0, 0, 0, 0); 8];
                    let mut entries_n: usize = 0;
                    let mut min_vrt: u64 = 0;
                    let (rq_eevdf_count, rq_locked) =
                        if (c as usize) < percpu_rq().len() {
                            if let Some(rq) = percpu_rq()[c as usize].try_lock() {
                                let n = rq.eevdf_nr_running;
                                let any_rt = rq.active[0] != 0 || rq.active[1] != 0;
                                let any_legacy = rq.active[2] != 0 || rq.active[3] != 0;
                                min_vrt = rq.eevdf_min_vruntime;
                                rq.eevdf_heap.for_each_entry(|tid, key| {
                                    if entries_n < 8 {
                                        let tt = thread_ref(tid);
                                        let vrt = tt.eevdf_vruntime;
                                        let st = tt.state as u8;
                                        entries[entries_n] = (tid, key, vrt, st);
                                        entries_n += 1;
                                    }
                                });
                                drop(rq);
                                (n as u64, (any_rt, any_legacy))
                            } else {
                                (u64::MAX, (false, false))
                            }
                        } else {
                            (0, (false, false))
                        };
                    let disp_n = pcpu.dispatch_count.load(Ordering::Relaxed);
                    let disp_last = pcpu.last_dispatched_tid.load(Ordering::Relaxed);
                    let disp_streak = pcpu.dispatch_streak.load(Ordering::Relaxed);
                    let set_pend = pcpu.dispatch_set_pending_count.load(Ordering::Relaxed);
                    let cas_ok   = pcpu.dispatch_cas_ok_count.load(Ordering::Relaxed);
                    let rescue_stuck = pcpu.rescue_stuck_pending_count.load(Ordering::Relaxed);
                    let hist = lat_snapshot(pcpu);
                    let n: u64 = hist.iter().sum();
                    let p50 = lat_percentile_ns(&hist, 5000);
                    let p90 = lat_percentile_ns(&hist, 9000);
                    let p99 = lat_percentile_ns(&hist, 9900);
                    let p999 = lat_percentile_ns(&hist, 9990);
                    crate::println!(
                        "  CPU-DIAG: cpu={} current_thread={} dispatching_tid={} need_resched={} eevdf_n={} eevdf_min_vrt={} rt_pending={} legacy_pending={} dispatches={} last_disp_tid={} streak={} set_pend={} cas_ok={} pend_minus_cas={} rescue_stuck={} lat_ns(n={} p50={} p90={} p99={} p999={})",
                        c, cur, dispatching, need_resched,
                        rq_eevdf_count, min_vrt, rq_locked.0, rq_locked.1,
                        disp_n, disp_last, disp_streak,
                        set_pend, cas_ok, set_pend.saturating_sub(cas_ok),
                        rescue_stuck,
                        n, p50, p90, p99, p999
                    );
                    for i in 0..entries_n {
                        let (etid, ekey, evrt, est) = entries[i];
                        let eligible = evrt <= min_vrt;
                        crate::println!(
                            "    EEVDF[{}]: tid={} deadline={} vruntime={} state={} eligible={}",
                            i, etid, ekey, evrt, est, eligible
                        );
                    }
                }
            }
            // Diagnostic dump for #120: per-port wake counters + state of
            // threads in the destination port's owning aspace.  If
            // wake_no_parker > 0 while parkers exist, we have direct
            // evidence of the wake_recv_waiter race window.
            if let Some(p) = crate::ipc::port::port_ref(t.call_dest_port) {
                let calls    = p.diag_wake_calls.load(Ordering::Relaxed);
                let no_park  = p.diag_wake_no_parker.load(Ordering::Relaxed);
                let inj_ok   = p.diag_wake_inject_ok.load(Ordering::Relaxed);
                let reenq    = p.diag_wake_reenq.load(Ordering::Relaxed);
                let recv_h   = p.recv_holder.load(Ordering::Relaxed);
                let (deq_hamt_miss, deq_ts_empty_ok, deq_ts_empty_bug) =
                    crate::sync::turnstile::deq_counters();
                let inv_fails = crate::sync::turnstile::TS_INVARIANT_FAILS
                    .load(Ordering::Relaxed);
                crate::println!(
                    "  PORT-DIAG: wake_calls={} no_parker={} inject_ok={} reenq={} recv_holder={} deq_miss=(hamt={} empty_ok={} empty_bug={}) inv_fails={}",
                    calls, no_park, inj_ok, reenq, recv_h,
                    deq_hamt_miss, deq_ts_empty_ok, deq_ts_empty_bug,
                    inv_fails
                );
                // Cross-check: does the HAMT actually map (port_id, RECV_PARK)
                // to a turnstile right now?  If hamt_found=false while parked
                // threads have ts_blocked_on != 0, we have proof of HAMT/turnstile
                // divergence (orphan turnstile — the bug we're hunting).
                let (hamt_found_park, hamt_ts_park) = crate::sync::turnstile::lookup_port_turnstile(
                    t.call_dest_port,
                    crate::sync::turnstile::KEY_PORT_RECV_PARK,
                );
                let (hamt_found_recv, hamt_ts_recv) = crate::sync::turnstile::lookup_port_turnstile(
                    t.call_dest_port,
                    crate::sync::turnstile::KEY_PORT_RECV,
                );
                crate::println!(
                    "  PORT-DIAG: hamt_lookup RECV_PARK={{found={} ts={:#x}}} RECV={{found={} ts={:#x}}}",
                    hamt_found_park, hamt_ts_park, hamt_found_recv, hamt_ts_recv
                );
                // Walk threads in the recv-holder's task and print any blocked
                // on this very port.  Cap at 8 to avoid log flood.
                if recv_h != u32::MAX {
                    let mut printed = 0u32;
                    SCHED_THREAD_ART.for_each(|_key, val| {
                        if printed >= 8 { return; }
                        let other = unsafe { &*(val as *const Thread) };
                        if other.task_id != recv_h
                            || other.state == ThreadState::Dead
                        {
                            return;
                        }
                        if let BlockReason::PortRecv(rp) = other.blocked_on {
                            if rp == t.call_dest_port {
                                // ts_blocked_on disambiguates #120 sub-patterns:
                                //   != 0  → thread IS on a turnstile (port_dequeue_one
                                //          buggy, or different key, or contention).
                                //   == 0  → thread was dequeued from turnstile but
                                //          state never transitioned Blocked → Ready.
                                // last_ready_ns shows whether the thread has been
                                // Ready since long ago (orphan) or recently (oscillating).
                                // enqueue_count: 1 = just one wake; >1 = rescue
                                // re-enqueued repeatedly but dispatch keeps missing.
                                let now_ns = get_monotonic_ns();
                                let lr = other.last_ready_ns.load(Ordering::Relaxed);
                                let ready_age_ms = if lr > 0 { (now_ns - lr) / 1_000_000 } else { 0 };
                                let ts_addr = other.ts_blocked_on.load(Ordering::Relaxed);
                                crate::println!(
                                    "  PORT-DIAG: dest tid={} state={:?} blocked_on=PortRecv({:#x}) on_cpu={} ts_blocked_on={:#x} enq_count={} ready_age_ms={}",
                                    other.id, other.state, rp,
                                    other.on_cpu.load(Ordering::Relaxed),
                                    ts_addr,
                                    other.enqueue_count.load(Ordering::Relaxed),
                                    ready_age_ms,
                                );
                                // If ts_blocked_on != 0, decode the turnstile so
                                // we know which key/port it's actually registered
                                // under — flags HAMT-orphan turnstiles directly.
                                if let Some((k, asp, va, wc, h)) =
                                    unsafe { crate::sync::turnstile::turnstile_info(ts_addr) }
                                {
                                    let hamt_match = (hamt_found_park && hamt_ts_park == ts_addr)
                                        || (hamt_found_recv && hamt_ts_recv == ts_addr);
                                    crate::println!(
                                        "    TS@{:#x}: key_type={} aspace={} va={:#x} waiter_count={} hash={:#x} hamt_match={}",
                                        ts_addr, k, asp, va, wc, h, hamt_match,
                                    );
                                }
                                printed += 1;
                            }
                        }
                    });
                }
            }
            wake_parked_thread(tid as ThreadId);
        }
    }
}

/// Scan for threads stuck in Ready state that are not in any run queue
/// or deferred-requeue slot.  Re-enqueue them so the system self-heals.
///
/// `rescue_parked`: if true, also scan for CallReply-blocked threads stuck
/// in COMMITTED with wakeup=true and inject SERVER_DIED. Only set this
/// during confirmed IPC stalls (watchdog), not on periodic sweeps, to
/// avoid prematurely killing legitimate slow IPC calls.
/// Per-thread orphan age counter: tracks how many consecutive rescue sweeps
/// a thread has appeared orphaned.  Only rescue when age >= 2 to filter out
/// false positives from the narrow dequeue window (in_queue=false before
/// on_cpu=ON_CPU_PENDING in percpu_pick_next).
static ORPHAN_AGE: [AtomicU32; 256] = {
    const Z: AtomicU32 = AtomicU32::new(0);
    [Z; 256]
};

#[cold]
#[inline(never)]
fn rescue_orphaned_threads_impl(rescue_parked: bool) {
    // Drain the local CPU's deferred slot first. This prevents the scenario
    // where a thread is stuck in the same CPU's deferred slot and rescue
    // can't IPI itself to unstick it. Safe because rescue only runs from
    // tick(), which is called from the timer IRQ handler after the stack
    // switch from the previous try_switch has completed.
    // NOTE: we MUST NOT drain remote CPUs' deferred slots — the remote CPU
    // may still be between the deferred store and the assembly stack switch.
    drain_deferred_requeue(smp::cpu_id());

    // #198 host-pause-aware peer-steal.  Before scanning threads, scan
    // peer CPUs: any peer whose tick + try_switch stamps are both
    // stale-wallclock for >1.5s has been host-descheduled.  Drain its
    // run-queue onto this CPU so stranded Ready threads dispatch now
    // instead of waiting for the host to resume the paused vCPU.
    rescue_host_paused_peers();

    let max_tid = NEXT_THREAD_ID.load(Ordering::Relaxed).min(200);
    let ncpus = smp::num_cpus();
    for tid in 1..max_tid {
        let t = unsafe { &*(THREAD_TABLE.get(tid) as *const Thread) };
        if t.task_id == 0 || t.state != ThreadState::Ready {
            // Not a candidate — reset orphan age and the low-threshold log gate.
            if (tid as usize) < ORPHAN_AGE.len() { ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed); }
            if (tid as usize) < PENDING_LOW_LOGGED.len() {
                PENDING_LOW_LOGGED[tid as usize].store(false, Ordering::Relaxed);
            }
            continue;
        }
        let on = t.on_cpu.load(Ordering::Acquire);
        let inq = t.in_queue.load(Ordering::Acquire);
        // Check for orphaned threads: on_cpu==MAX (never scheduled or cleared
        // by park), OR stale on_cpu (claims a CPU but that CPU is running a
        // different thread).  Skip ON_CPU_PENDING (transient state during
        // scheduling — rescuing it causes DOUBLE-SCHED).
        // `stale_on_cpu` distinguishes the "thread thinks it's on cpu N but
        // cpu N is running a different thread" pattern (Bug A) from the
        // generic on_cpu==MAX orphan (which has wider race windows with
        // park/wake paths and warrants the age filter).
        let mut stale_on_cpu = false;
        // Threshold for declaring an "ON_CPU_PENDING for so long it must
        // be stuck" orphan.  Normal PENDING windows are sub-millisecond
        // (set by percpu_enqueue, cleared by try_switch on the next tick).
        // Anything past STUCK_PENDING_AGE consecutive sweeps means the
        // wake's IPI was lost / the target CPU's try_switch never picked
        // the thread up (#120 root cause: wake_parked_thread fast path
        // runs but the parking CPU never dispatches).
        // Rescue actually fires at ~10Hz (every 40 cross-CPU ticks ≈ 100ms,
        // per the RESCUE_COUNTER % 40 schedule in tick()), NOT the 1Hz the
        // original comment assumed.  At 16 sweeps × 100ms = 1.6s, false
        // positives fire constantly during normal sleep_ms cycles (e.g.
        // compositor_srv's 1s periodic work) and the rescue dump's
        // serial output then holds PRINT_LOCK CLI for ~100ms per print,
        // starving every other CPU's dispatch latency, triggering MORE
        // rescue fires (positive-feedback observer effect — confirmed
        // boot 27 cli_max_rip=0x17d723 = serial::_print).  Raise to 160
        // sweeps × 100ms = ~16s — only genuine multi-second wedges fire.
        const STUCK_PENDING_AGE: u32 = 160; // ~16s at 10Hz rescue cadence
        // Low-threshold PENDING-stuck diagnostic — independent of the 16s
        // rescue and 30s CALL-TIMEOUT.  Fires once per stuck episode when
        // `pending_set_ns` is older than ~2s in real time.  Cleared via
        // PENDING_LOW_LOGGED when CAS-ok zeroes pending_set_ns (or when the
        // thread leaves Ready below).
        const PENDING_LOW_THRESHOLD_NS: u64 = 2_000_000_000;
        let is_orphan = if on == u32::MAX {
            true
        } else if on == ON_CPU_PENDING {
            // Transient — dequeue_set_pending just set this — UNLESS the
            // age counter says we've seen this for too long.  Use a
            // separate counter so this state's age doesn't conflict with
            // the on_cpu==MAX path (which has its own age semantics).
            RESCUE_PENDING.fetch_add(1, Ordering::Relaxed);

            // Low-threshold one-shot logger.  Multiple ON_CPU_PENDING
            // store sites in the scheduler (wake/release/rescue) do NOT
            // call `dequeue_set_pending`, so pending_set_ns may be 0 even
            // for a genuinely-stuck thread.  In that case, stamp `now`
            // here so the next sweep can compute an age.
            let pset = t.pending_set_ns.load(Ordering::Relaxed);
            // #163 paravirt fix: read/stamp pending_set_ns in
            // vcpu_runtime to match dequeue_set_pending's scale.
            let now_ns = crate::arch::timer::vcpu_runtime_ns();
            if pset == 0 {
                t.pending_set_ns.store(now_ns, Ordering::Relaxed);
            } else {
                let age_ns = now_ns.saturating_sub(pset);
                if age_ns >= PENDING_LOW_THRESHOLD_NS
                    && (tid as usize) < PENDING_LOW_LOGGED.len()
                    && !PENDING_LOW_LOGGED[tid as usize].swap(true, Ordering::Relaxed)
                {
                    PENDING_LOW_FIRES.fetch_add(1, Ordering::Relaxed);
                    let target = t.last_cpu.load(Ordering::Relaxed);
                    let prio = t.prio.load(Ordering::Relaxed);
                    let inq_now = t.in_queue.load(Ordering::Relaxed);
                    let enq_n = t.enqueue_count.load(Ordering::Relaxed);
                    let (tevt, tcpu, tseq) = trace_last(tid as u32);
                    #[cfg(target_arch = "x86_64")]
                    {
                        use crate::arch::x86_64::serial::{put_byte, put_bytes, put_dec_u64};
                        let mut buf = [0u8; 256];
                        let mut k = 0;
                        put_bytes(&mut buf, &mut k, b"PENDING-STUCK-LOW: tid=");
                        put_dec_u64(&mut buf, &mut k, tid as u64);
                        put_bytes(&mut buf, &mut k, b" task=");
                        put_dec_u64(&mut buf, &mut k, t.task_id as u64);
                        put_bytes(&mut buf, &mut k, b" age_ns=");
                        put_dec_u64(&mut buf, &mut k, age_ns);
                        put_bytes(&mut buf, &mut k, b" last_cpu=");
                        put_dec_u64(&mut buf, &mut k, target as u64);
                        put_bytes(&mut buf, &mut k, b" prio=");
                        put_dec_u64(&mut buf, &mut k, prio as u64);
                        put_bytes(&mut buf, &mut k, b" inq=");
                        put_bytes(&mut buf, &mut k, if inq_now { b"true" } else { b"false" });
                        put_bytes(&mut buf, &mut k, b" enq_n=");
                        put_dec_u64(&mut buf, &mut k, enq_n);
                        put_bytes(&mut buf, &mut k, b" trace=(evt=");
                        put_dec_u64(&mut buf, &mut k, tevt as u64);
                        put_bytes(&mut buf, &mut k, b" cpu=");
                        put_dec_u64(&mut buf, &mut k, tcpu as u64);
                        put_bytes(&mut buf, &mut k, b" seq=");
                        put_dec_u64(&mut buf, &mut k, tseq as u64);
                        put_bytes(&mut buf, &mut k, b")\n");
                        crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
                    }
                    #[cfg(not(target_arch = "x86_64"))]
                    crate::println!(
                        "PENDING-STUCK-LOW: tid={} task={} age_ns={} last_cpu={} prio={} inq={} enq_n={} trace=(evt={} cpu={} seq={})",
                        tid, t.task_id, age_ns, target, prio, inq_now, enq_n,
                        tevt, tcpu, tseq
                    );
                    // #135 IPI-to-idle latency probe: dump per-CPU histogram
                    // alongside every PENDING-STUCK-LOW print.  The print
                    // itself is already rate-limited (one per tid per stuck
                    // window via PENDING_LOW_LOGGED), so this dump piggybacks
                    // on that limiter.  The histogram bucketizes
                    // (cas_ok_ns - pending_set_ns) so we can attribute the
                    // residual oscillation's wake-to-dispatch latency to
                    // specific CPUs.
                    {
                        let ncpus = crate::sched::smp::num_cpus().min(8);
                        for c in 0..ncpus {
                            let pc = crate::sched::smp::get(c as u32);
                            let hist = lat_snapshot(pc);
                            let n: u64 = hist.iter().sum();
                            let p50 = lat_percentile_ns(&hist, 5000);
                            let p90 = lat_percentile_ns(&hist, 9000);
                            let p99 = lat_percentile_ns(&hist, 9900);
                            let p999 = lat_percentile_ns(&hist, 9990);
                            let p9999 = lat_percentile_ns(&hist, 9999);
                            // #135 per-CPU IPI accounting: recv = vector
                            // 0xFD entries on this CPU; send_to[0..4] =
                            // IPIs this CPU has sent to each target
                            // (target_cpu indexed); dispatched = total
                            // try_switch picks of non-idle threads on
                            // this CPU (existing dispatch_count).  The
                            // recv/dispatched ratio tells us whether
                            // IPIs are arriving but failing to trigger
                            // a pick; send_to asymmetry tells us if one
                            // CPU is doing all the waking.
                            let recv = pc.ipi_recv_count.load(Ordering::Relaxed);
                            let dispatched = pc.dispatch_count.load(Ordering::Relaxed);
                            let s0 = pc.ipi_send_to[0].load(Ordering::Relaxed);
                            let s1 = pc.ipi_send_to[1].load(Ordering::Relaxed);
                            let s2 = pc.ipi_send_to[2].load(Ordering::Relaxed);
                            let s3 = pc.ipi_send_to[3].load(Ordering::Relaxed);
                            crate::println!(
                                "  IPI-LAT: cpu={} n={} p50={} p90={} p99={} p999={} p9999={} rescue_stuck={} ipi_recv={} disp={} send_to=[{},{},{},{}]",
                                c, n, p50, p90, p99, p999, p9999,
                                pc.rescue_stuck_pending_count.load(Ordering::Relaxed),
                                recv, dispatched, s0, s1, s2, s3,
                            );
                        }
                    }
                    // #135 pick-blindness probe: locate which CPU's runqueue
                    // actually holds the stuck thread, then dump that heap's
                    // entries + scan_start.  rescue_stuck is attributed to
                    // `last_cpu` but a thread woken via sleep_wake or
                    // wake_parked_thread can be enqueued on a *different* CPU
                    // (the wake's `target`).  If the locating CPU's heap shows
                    // tid present alongside other entries but `scan_start`
                    // isn't rotating through its position, we have direct
                    // evidence of pick-rotation breaking down.
                    {
                        let hp = t.eevdf_heap_pos;
                        if hp != super::heap::HEAP_POS_NONE {
                            let ncpus = crate::sched::smp::num_cpus().min(8);
                            let mut located_cpu: i32 = -1;
                            let mut located_n: u32 = 0;
                            let mut located_scan: u32 = 0;
                            let mut located_entries: [(u32, u64, u64, u8); 8] =
                                [(0, 0, 0, 0); 8];
                            let mut located_entries_n: usize = 0;
                            for c in 0..ncpus {
                                if let Some(rq) = percpu_rq()[c].try_lock() {
                                    // rq_contains_tid's heap_pos fast path
                                    // returns true if the thread is in ANY
                                    // CPU's heap (heap_pos is per-thread, not
                                    // per-CPU).  For PICK-LOCATE we need to
                                    // confirm the thread is in *this* CPU's
                                    // heap — walk for_each_entry and capture
                                    // its presence directly.
                                    let mut here = false;
                                    let mut tmp_entries: [(u32, u64, u64, u8); 8] =
                                        [(0, 0, 0, 0); 8];
                                    let mut tmp_n: usize = 0;
                                    rq.eevdf_heap.for_each_entry(|etid, ekey| {
                                        if etid == tid as u32 {
                                            here = true;
                                        }
                                        if tmp_n < 8 {
                                            let tt = thread_ref(etid);
                                            let vrt = tt.eevdf_vruntime;
                                            let st = tt.state as u8;
                                            tmp_entries[tmp_n] = (etid, ekey, vrt, st);
                                            tmp_n += 1;
                                        }
                                    });
                                    if here {
                                        located_cpu = c as i32;
                                        located_n = rq.eevdf_heap.len();
                                        located_scan = rq.eevdf_heap.scan_start_raw();
                                        located_entries = tmp_entries;
                                        located_entries_n = tmp_n;
                                        drop(rq);
                                        break;
                                    }
                                    drop(rq);
                                }
                            }
                            if located_cpu >= 0 {
                                crate::println!(
                                    "  PICK-LOCATE: stuck tid={} (heap_pos={}) in cpu={} eevdf_n={} scan_start={} (scan%n={}) picked_count={} enq_count={}",
                                    tid, hp, located_cpu, located_n, located_scan,
                                    if located_n > 0 {
                                        located_scan % located_n
                                    } else { 0 },
                                    t.picked_count.load(Ordering::Relaxed),
                                    t.enqueue_count.load(Ordering::Relaxed),
                                );
                                for i in 0..located_entries_n {
                                    let (etid, ekey, evrt, est) = located_entries[i];
                                    let marker = if etid == tid as u32 { "  <-- STUCK" } else { "" };
                                    let etpick = thread_ref(etid).picked_count.load(Ordering::Relaxed);
                                    let etenq = thread_ref(etid).enqueue_count.load(Ordering::Relaxed);
                                    crate::println!(
                                        "    HEAP[{}]: tid={} deadline={} vruntime={} state={} picked={} enq={}{}",
                                        i, etid, ekey, evrt, est, etpick, etenq, marker
                                    );
                                }
                            } else {
                                crate::println!(
                                    "  PICK-LOCATE: stuck tid={} (heap_pos={}) NOT FOUND in any cpu runqueue (locks contended or phantom)",
                                    tid, hp
                                );
                            }
                        } else {
                            crate::println!(
                                "  PICK-LOCATE: stuck tid={} eevdf_heap_pos=NONE (not in eevdf heap — check bitmap or just-removed)",
                                tid
                            );
                        }
                    }
                }
            }
            // ----------------------------------------------------------------
            // Fast-rescue path for phantom-pending wedges.
            //
            // Triggered when a thread has been on_cpu=PENDING for >1.5s AND
            // the picking CPU's last_try_switch_ns is stale >500ms.  That
            // combination is the host-vCPU-descheduling signature: the
            // picking CPU was paused by the host between class_pick_next
            // and the try_switch CAS, leaving the thread "leased" to a
            // dormant CPU with no way for work-stealing to help (the
            // thread is out of the runqueue already).
            //
            // Recovery: CAS-flip on_cpu PENDING → MAX so the orphan-rescue
            // path picks it up.  Update last_cpu to a healthy CPU first
            // so the orphan handler re-enqueues somewhere useful.  When
            // the original picking CPU eventually resumes, its try_switch
            // CAS(PENDING → cpu) fails with Err(MAX); the CAS_FAIL handler
            // recognises u32::MAX as "rescue-takeover, benign yield" and
            // does NOT kill the thread.
            //
            // STUCK_PENDING_AGE's 16s threshold below still fires for the
            // (rarer) wedge where the picking CPU is alive but failing to
            // make progress — that path also re-enqueues but uses a more
            // verbose dump + rate-limiting for diagnostic.
            const FAST_RESCUE_PENDING_NS: u64 = 1_500_000_000; // 1.5s (short tier)
            const FAST_RESCUE_LONG_AGE_NS: u64 = 3_000_000_000; // 3s (age-only tier)
            const PICKING_CPU_STALE_MS: u64 = 500;
            const HOST_STEAL_CONFIRM_MS: u64 = 200;
            let pending_age_ns = now_ns.saturating_sub(pset);
            // Boot 544 widening: original gate required `!in_queue` since the
            // intended pattern was "thread was picked (in_queue=false) but
            // try_switch never completed (on_cpu=PENDING)".  The dispatch-
            // starvation pattern surfaced in boot 544 is *different*:
            // in_queue=true ∧ on_cpu=PENDING ∧ thread sits in an idle CPU's
            // heap with no IPI to wake the heap-CPU.  Fix A (percpu_enqueue
            // IPI to remote target) should prevent it on the wake path; this
            // widening is the second-net for any path that enqueues without
            // an IPI (rescue, fork, deferred-requeue drain).
            let in_q = t.in_queue.load(Ordering::Relaxed);
            if pset != 0 && pending_age_ns >= FAST_RESCUE_PENDING_NS {
                let last_cpu_idx = t.last_cpu.load(Ordering::Relaxed);
                let ncpus = crate::sched::smp::num_cpus() as u32;
                let trigger = if last_cpu_idx < ncpus {
                    let pc = crate::sched::smp::get(last_cpu_idx);
                    let lts = pc.last_try_switch_ns.load(Ordering::Relaxed);
                    let wall_now = get_monotonic_ns();
                    let picking_cpu_stale = lts != 0 && wall_now > lts
                        && (wall_now - lts) / 1_000_000 > PICKING_CPU_STALE_MS;
                    // Layer 3 paravirt: positive host-pause confirmation.
                    // Compare current steal on `last_cpu` against the
                    // snapshot taken WHEN THIS THREAD ENTERED PENDING
                    // (dequeue_set_pending stamped t.pending_set_steal_ns).
                    // Delta = "ns the picking CPU was stolen during this
                    // specific pending wait", exactly the right signal.
                    let steal_at_pending =
                        t.pending_set_steal_ns.load(Ordering::Relaxed);
                    let host_stealing = if steal_at_pending == 0 {
                        // No baseline (bare metal or stamp predates
                        // Layer 3) — accept the stale-CPU signal alone.
                        true
                    } else {
                        let steal_now = crate::arch::hypervisor::ops()
                            .steal_time_ns_of_cpu(last_cpu_idx)
                            .unwrap_or(0);
                        steal_now > steal_at_pending
                            && (steal_now - steal_at_pending) / 1_000_000
                                > HOST_STEAL_CONFIRM_MS
                    };
                    // Short-tier (1.5s) requires both confirmations:
                    // picking CPU CURRENTLY stale AND host stealing during
                    // this pending episode.  This catches active pauses
                    // tightly.  But under bursty host pressure the picking
                    // CPU often resumes briefly between pauses, refreshing
                    // last_try_switch and falsifying picking_cpu_stale even
                    // though the thread is genuinely wedged.  Boot 525
                    // showed 7 PENDING-STUCK-LOW events with 0 fast_takeover
                    // because of this miss.
                    //
                    // Long-tier (3s) escape hatch: pending_age in
                    // vcpu_runtime accumulates ONLY when some CPU is
                    // actually running, so 3s of age is hard evidence that
                    // the thread should have dispatched somewhere by now.
                    // CAS_FAIL is benign (any racing dispatch wins), so a
                    // false positive at this tier just costs one redundant
                    // CAS — well worth the wider catch.
                    let short_tier_ok = picking_cpu_stale && host_stealing;
                    let long_tier_ok = pending_age_ns >= FAST_RESCUE_LONG_AGE_NS;
                    short_tier_ok || long_tier_ok
                } else { false };
                if trigger {
                    // CAS PENDING → MAX.  Failure means original CPU
                    // resumed and won the race — benign, leave the
                    // thread alone.
                    if t.on_cpu.compare_exchange(
                        ON_CPU_PENDING, u32::MAX,
                        Ordering::AcqRel, Ordering::Acquire,
                    ).is_ok() {
                        FAST_RESCUE_TAKEOVERS.fetch_add(1, Ordering::Relaxed);
                        // Clear pending_set_ns so the next pending episode
                        // (post-orphan-rescue dispatch) gets a fresh stamp.
                        t.pending_set_ns.store(0, Ordering::Relaxed);
                        if (tid as usize) < PENDING_LOW_LOGGED.len() {
                            PENDING_LOW_LOGGED[tid as usize].store(false, Ordering::Relaxed);
                        }
                        if in_q {
                            // in_queue=true variant (boot 544): the thread
                            // is already sitting in some CPU's heap.  We
                            // don't know which CPU without locking each
                            // run-queue, so broadcast a reschedule IPI —
                            // the heap-owning CPU runs try_switch and
                            // picks it up.  Cheap (~ncpus-1 vmexits) vs
                            // 23-min dispatch starvation.  Do NOT migrate
                            // last_cpu and do NOT enter the orphan re-
                            // enqueue path (would DOUBLE_ENQ-skip and
                            // produce no net progress).
                            let ncpus = crate::sched::smp::num_cpus() as u32;
                            let me = smp::cpu_id();
                            for c in 0..ncpus {
                                if c != me {
                                    crate::arch::irq::send_reschedule_ipi(c);
                                }
                            }
                        } else {
                            // Original (in_queue=false) variant: migrate
                            // last_cpu to the rescuer.  The orphan re-
                            // enqueue path below uses last_cpu as the
                            // enqueue target.
                            t.last_cpu.store(smp::cpu_id(), Ordering::Relaxed);
                        }
                        // Skip the STUCK_PENDING_AGE block this sweep.  Next
                        // sweep will see on_cpu==MAX and run the existing
                        // orphan handler (in_queue=false variant only), which
                        // re-enqueues on last_cpu (now this CPU).
                        continue;
                    }
                }
            }
            // ----------------------------------------------------------------

            let pending_age = if (tid as usize) < ORPHAN_AGE.len() {
                ORPHAN_AGE[tid as usize].fetch_add(1, Ordering::Relaxed)
            } else { 0 };
            if pending_age >= STUCK_PENDING_AGE {
                // Stuck PENDING: treat as orphan.  Re-enqueue path below
                // will check for actual queue membership and DOUBLE_ENQ
                // before doing the percpu_enqueue, so this is safe.
                RESCUE_STUCK_PENDING_FIRES.fetch_add(1, Ordering::Relaxed);
                // #173 Phase 5: split rescue fires by claim-helper gate state.
                // Gate ON closes the dispatch-side phantom-pending window;
                // any rescue fire under gate ON is therefore from an
                // enqueue-side PENDING that aged out (legitimate stuck-rq
                // case, not the bug class this refactor targets).  Tracking
                // the ratio across many stress boots tells us how much of
                // the rescue burden the new protocol actually offloads.
                if DISPATCH_USE_CLAIM_HELPER.load(Ordering::Relaxed) {
                    RESCUE_STUCK_PENDING_FIRES_GATE_ON
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    RESCUE_STUCK_PENDING_FIRES_GATE_OFF
                        .fetch_add(1, Ordering::Relaxed);
                }
                // Per-CPU asymmetry probe (#120 lead from
                // project_120_eevdf_dispatch.md): attribute to the thread's
                // last_cpu, since on_cpu == ON_CPU_PENDING here so the
                // identity of the parking/dispatching CPU lives in
                // last_cpu.  Dumped by the WATCHDOG and CALL-TIMEOUT
                // per-CPU loops below as `rescue_stuck=N`.
                let attrib_cpu = t.last_cpu.load(Ordering::Relaxed);
                let ncpus = crate::sched::smp::num_cpus() as u32;
                if attrib_cpu < ncpus {
                    crate::sched::smp::get(attrib_cpu)
                        .rescue_stuck_pending_count
                        .fetch_add(1, Ordering::Relaxed);
                }
                // Rate-limit the println: only log on first crossing
                // (age == STUCK_PENDING_AGE).  Subsequent stuckness still
                // counts in RESCUE_STUCK_PENDING_FIRES but doesn't flood
                // the serial log every sweep.
                if pending_age == STUCK_PENDING_AGE {
                    // #135: dump stuck thread's runqueue presence facts.
                    // If in_queue=true + heap_pos!=NONE, the thread IS in the
                    // eevdf heap on `last_cpu` and the bug is on the pick side.
                    // If in_queue=true + heap_pos==NONE, phantom enqueue: the
                    // thread was enqueued but lost its heap position (no actual
                    // membership), and percpu_enqueue's in_queue swap will keep
                    // silently skipping all future re-enqueues.
                    let in_q = t.in_queue.load(Ordering::Relaxed);
                    let hp = t.eevdf_heap_pos;
                    let last_cpu = t.last_cpu.load(Ordering::Relaxed);
                    let pri = t.prio.load(Ordering::Relaxed);
                    let enq_n = t.enqueue_count.load(Ordering::Relaxed);
                    let pick_n = t.picked_count.load(Ordering::Relaxed);
                    let now = get_monotonic_ns();
                    let (lts, lirq) = if (last_cpu as usize) < crate::sched::smp::num_cpus() {
                        let pc = crate::sched::smp::get(last_cpu);
                        (
                            pc.last_try_switch_ns.load(Ordering::Relaxed),
                            pc.last_irq_ns.load(Ordering::Relaxed),
                        )
                    } else { (0, 0) };
                    let last_ts_age_ms = if lts != 0 && now > lts {
                        (now - lts) / 1_000_000
                    } else { 0 };
                    let last_irq_age_ms = if lirq != 0 && now > lirq {
                        (now - lirq) / 1_000_000
                    } else { 0 };
                    crate::println!(
                        "RESCUE-STUCK-PENDING: tid={} age={} task={} on_cpu=PENDING - \
                        treating as orphan (#120 IPI/dispatch loss) \
                        in_q={} heap_pos={} last_cpu={} prio={} enq_n={} pick_n={} \
                        last_cpu_ts_ago_ms={} last_irq_ago_ms={}",
                        tid, pending_age, t.task_id,
                        in_q, hp, last_cpu, pri, enq_n, pick_n,
                        last_ts_age_ms, last_irq_age_ms,
                    );
                    // #135 dump the last 4 transitions of the stuck thread.
                    let next_pos = t.trans_pos.load(Ordering::Relaxed) as usize;
                    crate::println!(
                        "  TRANS-RING: tid={} (oldest→newest, format: action/cpu/state/on_cpu@ts32):",
                        tid,
                    );
                    for i in 0..4usize {
                        let slot = (next_pos + i) & 3;
                        let entry = t.trans_ring[slot].load(Ordering::Relaxed);
                        if entry == 0 {
                            continue;
                        }
                        let action = (entry & 0xFF) as u8;
                        let cpu = ((entry >> 8) & 0xFF) as u8;
                        let state = ((entry >> 16) & 0xFF) as u8;
                        let on_cpu_enc = ((entry >> 24) & 0xFF) as u8;
                        let ts = (entry >> 32) as u32;
                        crate::println!(
                            "    [{}]: action={} cpu={} state={} on_cpu={} ts={}",
                            i, action, cpu, state, on_cpu_enc, ts,
                        );
                    }
                    for c in 0..4usize {
                        let pc = crate::sched::smp::get(c as u32);
                        let recv = pc.ipi_recv_count.load(Ordering::Relaxed);
                        let disp = pc.dispatch_count.load(Ordering::Relaxed);
                        let s0 = pc.ipi_send_to[0].load(Ordering::Relaxed);
                        let s1 = pc.ipi_send_to[1].load(Ordering::Relaxed);
                        let s2 = pc.ipi_send_to[2].load(Ordering::Relaxed);
                        let s3 = pc.ipi_send_to[3].load(Ordering::Relaxed);
                        let cur = pc.current_thread.load(Ordering::Relaxed);
                        let dispg = pc.dispatching_tid.load(Ordering::Relaxed);
                        let idle = pc.idle_thread_id.load(Ordering::Relaxed);
                        let cli_total = pc.cli_total_cycles.load(Ordering::Relaxed);
                        let cli_max = pc.cli_max_cycles.load(Ordering::Relaxed);
                        let cli_count = pc.cli_count.load(Ordering::Relaxed);
                        let cli_enter = pc.cli_enter_tsc.load(Ordering::Relaxed);
                        // #135 residual: set_pending vs cas_ok counters
                        // expose per-CPU pick-vs-dispatch asymmetry.
                        // Big gap (set_pend >> cas_ok) means picks land
                        // in dequeue_set_pending but never reach a
                        // successful CAS — the orphaning pattern.
                        let sp = pc.dispatch_set_pending_count.load(Ordering::Relaxed);
                        let ok = pc.dispatch_cas_ok_count.load(Ordering::Relaxed);
                        let cli_max_rip = pc.cli_max_rip.load(Ordering::Relaxed);
                        // Layer 3 paravirt diagnostic: per-CPU steal-time
                        // accumulation since boot, plus "steal since last
                        // successful dispatch" — the latter is the value
                        // the fast-rescue trigger compares against.
                        let steal_now = crate::arch::hypervisor::ops()
                            .steal_time_ns_of_cpu(c as u32)
                            .unwrap_or(0);
                        let steal_at_disp = pc.steal_ns_at_last_dispatch
                            .load(Ordering::Relaxed);
                        let steal_since_disp_ms = if steal_now > steal_at_disp {
                            (steal_now - steal_at_disp) / 1_000_000
                        } else { 0 };
                        crate::println!(
                            "IPI-CNT: cpu={} recv={} disp={} send_to=[{},{},{},{}] \
                             cur={} dispg={} idle={} cli_open={} \
                             cli_total={} cli_max={} cli_max_rip=0x{:x} cli_count={} \
                             set_pend={} cas_ok={} delta={} steal_total_us={} steal_since_disp_ms={}",
                            c, recv, disp, s0, s1, s2, s3,
                            cur, dispg, idle,
                            if cli_enter != 0 { 1 } else { 0 },
                            cli_total, cli_max, cli_max_rip, cli_count,
                            sp, ok, sp.saturating_sub(ok),
                            steal_now / 1000, steal_since_disp_ms,
                        );
                        // #135 cli_max-per-callsite: dump the top-N
                        // distinct CLI offenders by max single-region
                        // duration on this CPU.  Boot 26 showed
                        // cli_max=97ms with a single cli_max_rip; this
                        // surfaces whether that's one path or a family.
                        // Sort indices by cycles desc for readable output.
                        let mut idx: [usize; crate::sched::smp::CLI_TOP_N] = [0usize; crate::sched::smp::CLI_TOP_N];
                        for i in 0..crate::sched::smp::CLI_TOP_N { idx[i] = i; }
                        let cyc: [u64; crate::sched::smp::CLI_TOP_N] = {
                            let mut a = [0u64; crate::sched::smp::CLI_TOP_N];
                            for i in 0..crate::sched::smp::CLI_TOP_N {
                                a[i] = pc.cli_top[i].cycles.load(Ordering::Relaxed);
                            }
                            a
                        };
                        // Selection sort, descending — N=8 so O(N²)=64 is fine.
                        for i in 0..crate::sched::smp::CLI_TOP_N {
                            for j in (i + 1)..crate::sched::smp::CLI_TOP_N {
                                if cyc[idx[j]] > cyc[idx[i]] {
                                    idx.swap(i, j);
                                }
                            }
                        }
                        let mut printed = 0usize;
                        for &i in idx.iter() {
                            let r = pc.cli_top[i].rip.load(Ordering::Relaxed);
                            let cy = pc.cli_top[i].cycles.load(Ordering::Relaxed);
                            let ct = pc.cli_top[i].count.load(Ordering::Relaxed);
                            if r == 0 || cy == 0 { continue; }
                            crate::println!(
                                "CLI-TOP: cpu={} slot={} rip=0x{:x} max={} count={}",
                                c, printed, r, cy, ct,
                            );
                            printed += 1;
                        }
                        // #135 LAPIC probe: each CPU snapshots its own
                        // LAPIC state in the timer-tick handler (vector
                        // 32, which works on every CPU even when 0xFD
                        // doesn't).  Diagnose per-CPU vector-0xFD
                        // blockage modes:
                        //   isr_f bit 29 = vector 0xFD ISR set → missed
                        //     EOI; new 0xFD IPIs queue in IRR but won't
                        //     deliver until ISR clears.
                        //   irr_f bit 29 set persistently → pending IPI
                        //     waiting to deliver but blocked.
                        //   tpr ≥ 0xF0 → task-priority class 0xF blocks
                        //     vector 0xFD (priority class = vec>>4 = 0xF).
                        //   svr bit 8 cleared → LAPIC software-disabled.
                        let isr_f = pc.lapic_isr_f.load(Ordering::Relaxed);
                        let irr_f = pc.lapic_irr_f.load(Ordering::Relaxed);
                        let tpr = pc.lapic_tpr.load(Ordering::Relaxed);
                        let svr = pc.lapic_svr.load(Ordering::Relaxed);
                        let ppr = pc.lapic_ppr.load(Ordering::Relaxed);
                        let esr = pc.lapic_esr.load(Ordering::Relaxed);
                        let isr_lo = pc.lapic_isr_lo_or.load(Ordering::Relaxed);
                        let fd_in_isr = (isr_f >> 29) & 1;
                        let fd_in_irr = (irr_f >> 29) & 1;
                        crate::println!(
                            "LAPIC: cpu={} isr_f=0x{:08x} irr_f=0x{:08x} tpr=0x{:02x} \
                             ppr=0x{:02x} svr=0x{:08x} esr=0x{:08x} isr_lo_or=0x{:08x} \
                             fd_in_isr={} fd_in_irr={}",
                            c, isr_f, irr_f, tpr & 0xff,
                            ppr & 0xff, svr, esr, isr_lo,
                            fd_in_isr, fd_in_irr,
                        );
                    }
                    // #135 Fix A: force-migrate stuck thread away from its
                    // last_cpu if that CPU has stopped scheduling (>1s since
                    // last try_switch).  Without this, future percpu_enqueue
                    // calls are silent no-ops because in_queue=true — the
                    // thread stays in the dead CPU's heap forever.
                    // Migrate threshold = 100ms (was 1000ms): host vCPU
                    // descheduling can blip for a few hundred ms even on a
                    // healthy boot.  100ms catches recurring multi-tick
                    // halts while still allowing one missed tick to slide
                    // (10ms structural diff between irq and try_switch).
                    if in_q && last_ts_age_ms > 100
                        && (last_cpu as usize) < crate::sched::smp::num_cpus()
                    {
                        let here = smp::cpu_id();
                        if last_cpu != here {
                            // try_lock: if contended (shouldn't be on a halted
                            // CPU), retry next rescue tick.
                            if let Some(mut rq) =
                                percpu_rq()[last_cpu as usize].try_lock()
                            {
                                let hp_now = t.eevdf_heap_pos;
                                if hp_now != crate::sched::heap::HEAP_POS_NONE {
                                    rq.eevdf_heap.remove(hp_now as usize);
                                    rq.eevdf_nr_running =
                                        rq.eevdf_nr_running.saturating_sub(1);
                                }
                                drop(rq);
                                t.in_queue.store(false, Ordering::Release);
                                crate::println!(
                                    "RESCUE-MIGRATE: tid={} from cpu={} (stale {}ms) to cpu={}",
                                    tid, last_cpu, last_ts_age_ms, here,
                                );
                                t.last_cpu.store(here, Ordering::Relaxed);
                                set_enq_tag(11); // 11 = rescue-migrate
                                percpu_enqueue(here, pri, tid as ThreadId);
                            }
                        }
                    }
                }
                true
            } else {
                // PENDING but not yet aged enough — do NOT fall through
                // to the "if !is_orphan { reset age }" line below, that
                // would zero the counter and the threshold would never
                // be reached.  Skip this tid for this sweep.
                continue;
            }
        } else if on < ncpus as u32 {
            // Check if the claimed CPU is actually running this thread.
            // Also consult dispatching_tid: the claimed CPU may be in the
            // middle of try_switch's dispatch sequence (CAS done, state and
            // current_thread not yet updated).  In that window cur != tid,
            // but the thread is *not* stale — it's about to be Running.
            let pcpu = smp::get(on);
            let cur = pcpu.current_thread.load(Ordering::Acquire);
            let dispatching = pcpu.dispatching_tid.load(Ordering::Acquire);
            let stale = cur != tid as u32 && dispatching != tid as u32;
            stale_on_cpu = stale;
            stale
        } else {
            false // garbage value — don't touch
        };
        // Phantom-enqueued detection: state=Ready + in_queue=true but the
        // thread is not actually in any heap or bitmap queue on its
        // last_cpu.  This violates the in_queue==membership invariant and
        // makes the thread invisible to all schedulers.  Self-heal by
        // clearing the stale flag and re-enqueueing.
        if inq {
            // Only spend cycles on the lock for plausible phantom candidates:
            // on_cpu must be MAX or stale (same orphan filter as below) AND
            // the thread must be Ready.  The earlier `t.state != Ready`
            // check above the loop already screens out non-Ready threads.
            if is_orphan {
                let target = t.last_cpu.load(Ordering::Relaxed);
                let phantom = if (target as usize) < percpu_rq().len() {
                    if let Some(rq) = percpu_rq()[target as usize].try_lock() {
                        let in_actual = rq_contains_tid(&rq, tid as ThreadId);
                        drop(rq);
                        // Re-validate the orphan predicate after the lock.
                        // If state, in_queue or on_cpu flipped while we
                        // scanned, the thread is no longer phantom and a
                        // legitimate path will handle it.
                        let inq_now = t.in_queue.load(Ordering::Acquire);
                        let on_now = t.on_cpu.load(Ordering::Acquire);
                        let still_ready = t.state == ThreadState::Ready;
                        let still_orphan = on_now == u32::MAX
                            || (on_now < ncpus as u32
                                && smp::get(on_now).current_thread.load(Ordering::Acquire)
                                    != tid as u32);
                        inq_now && !in_actual && still_ready && still_orphan
                    } else {
                        false // contended — reassess next sweep
                    }
                } else {
                    false
                };
                if phantom {
                    // Self-heal: clear the stale flag and re-enqueue normally.
                    // percpu_enqueue's swap(true) will succeed (we just
                    // cleared) and proceed with the heap/bitmap insert.  If
                    // a concurrent path enqueues between our store and
                    // swap, the swap returns true and DOUBLE_ENQ counters
                    // increment — benign.
                    let prio = t.prio.load(Ordering::Relaxed);
                    let park = t.park_state.load(Ordering::Relaxed);
                    let wake = t.wakeup.load(Ordering::Relaxed);
                    let blk = t.blocked_on;
                    let heap_pos = t.eevdf_heap_pos;
                    let (tevt, tcpu, tseq) = trace_last(tid as u32);
                    crate::println!(
                        "RESCUE-PHANTOM: tid={} prio={} cpu={} task={} on_cpu={} trace=(evt={} cpu={} seq={}) park={} wake={} blk={:?} hp={}",
                        tid, prio, target, t.task_id, on, tevt, tcpu, tseq,
                        park, wake, blk, heap_pos
                    );
                    RESCUE_PHANTOM.fetch_add(1, Ordering::Relaxed);
                    rescue_per_tid_inc(tid as u32);
                    t.in_queue.store(false, Ordering::Release);
                    t.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
                    record_trans(tid as u32, 8, t.state, ON_CPU_PENDING);
                    trace_sched(tid as u32, 8); // 8=rescue_enq
                    set_enq_tag(7); // 7=rescue
                    // Layer 3/4 paravirt: rescuing onto `t.last_cpu` re-
                    // pends on the same starved/stolen CPU that orphaned
                    // the thread.  Reroute if so.
                    let target = choose_wake_target_steal_aware(target);
                    percpu_enqueue(target, prio, tid as ThreadId);
                    if (tid as usize) < ORPHAN_AGE.len() {
                        ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed);
                    }
                    continue;
                }
            }
            // Genuine queue membership — reset orphan age and move on.
            if (tid as usize) < ORPHAN_AGE.len() { ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed); }
            continue;
        }
        if !is_orphan {
            if (tid as usize) < ORPHAN_AGE.len() { ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed); }
            continue;
        }
        {
            // Track orphan age: filter false positives from the narrow
            // dequeue window where in_queue=false but on_cpu hasn't been set
            // to ON_CPU_PENDING yet.
            //
            // The stale-on-cpu pattern (state=Ready, on_cpu=cpu_real,
            // !in_queue, cur!=tid) is unambiguous: every legitimate path
            // either keeps the thread Running on that CPU, transitions
            // on_cpu through ON_CPU_PENDING (filtered above), or holds the
            // thread in a deferred slot (checked below).  Skip the age
            // filter for this pattern — the age filter prevents recovery
            // because tid oscillates through transient non-orphan states
            // between 100ms rescue sweeps, resetting the counter (Bug A).
            let age = if (tid as usize) < ORPHAN_AGE.len() {
                ORPHAN_AGE[tid as usize].fetch_add(1, Ordering::Relaxed)
            } else {
                1 // always rescue for high tids (shouldn't happen in practice)
            };
            if !stale_on_cpu && age < 1 {
                continue; // first sighting — wait one more sweep to confirm
            }
            // Just-in-time deferred slot check: read ALL deferred slots NOW,
            // not from a stale snapshot.  The old snapshot approach went stale
            // within one tick (10ms), causing rescue to falsely re-enqueue
            // threads that were legitimately cycling through deferred slots.
            let mut in_deferred = false;
            let mut deferred_cpu = 0u32;
            for c in 0..ncpus.min(16) {
                let dv = deferred_requeue()[c].load(Ordering::Relaxed);
                if dv != 0 && (dv & 0xFFFFFFFF) as u32 == tid as u32 {
                    in_deferred = true;
                    deferred_cpu = c as u32;
                    break;
                }
            }
            if in_deferred {
                // Thread is in a deferred-requeue slot. Can't enqueue directly
                // (the owning CPU may still be on this thread's kernel stack).
                // Send a reschedule IPI to the CPU whose slot holds this thread
                // so its try_switch → drain_deferred_requeue unsticks it.
                if deferred_cpu != smp::cpu_id() {
                    crate::arch::irq::send_reschedule_ipi(deferred_cpu);
                }
            } else {
                // Not in deferred slot. Re-read on_cpu to filter out the
                // narrow drain window (between swap(0) and store(ON_CPU_PENDING)).
                // If drain just handled it, on_cpu will be ON_CPU_PENDING now.
                //
                // Exception: if `on` was already PENDING when we entered this
                // branch (i.e. we got here via the new STUCK_PENDING_AGE path
                // above), seeing PENDING again on re-read is NOT "drain just
                // handled it" — it's "thread has been PENDING for >=16s and
                // is actually stuck."  Continue to the re-enqueue path.
                let was_stuck_pending = on == ON_CPU_PENDING;
                let on2 = t.on_cpu.load(Ordering::Acquire);
                if on2 == ON_CPU_PENDING && !was_stuck_pending {
                    if (tid as usize) < ORPHAN_AGE.len() { ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed); }
                    continue; // drain just handled it
                }
                // Re-read state: the dispatching CPU may have set Running
                // between our initial state read and the on_cpu/deferred checks.
                if t.state != ThreadState::Ready {
                    if (tid as usize) < ORPHAN_AGE.len() { ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed); }
                    continue; // dispatch completed — thread is Running now
                }
                // Also skip if in_queue changed (drain enqueued between our checks).
                if t.in_queue.load(Ordering::Acquire) {
                    if (tid as usize) < ORPHAN_AGE.len() { ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed); }
                    continue;
                }
                let target = t.last_cpu.load(Ordering::Relaxed);
                let prio = t.prio.load(Ordering::Relaxed);
                let (tevt, tcpu, tseq) = trace_last(tid as u32);
                let park = t.park_state.load(Ordering::Relaxed);
                let wake = t.wakeup.load(Ordering::Relaxed);
                let src = t.saved_sp_source;
                let blk = t.blocked_on;
                let heap_pos = t.eevdf_heap_pos;
                // #173 orphan-source probe: on_cpu_set_by identifies which
                // dispatch path last stamped on_cpu (1=try_switch, 2=vol_resched,
                // 3=park_ipc); enq/pick counts show whether the strand was ever
                // dispatched.  Triangulates the Running→Ready strand that fix B
                // mislocated (see project_gate_on_residual_reframed_host_pressure).
                let set_by = t.on_cpu_set_by.load(Ordering::Relaxed);
                let enq_n = t.enqueue_count.load(Ordering::Relaxed);
                let pick_n = t.picked_count.load(Ordering::Relaxed);
                crate::println!(
                    "RESCUE: tid={} prio={} cpu={} task={} on_cpu={} trace=(evt={} cpu={} seq={}) park={} wake={} src={} blk={:?} hp={} set_by={} enq={} pick={}",
                    tid, prio, target, t.task_id, on2, tevt, tcpu, tseq,
                    park, wake, src, blk, heap_pos, set_by, enq_n, pick_n
                );
                if (tid as usize) < ORPHAN_AGE.len() { ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed); }
                // Reset on_cpu so that when this thread is later dispatched,
                // try_switch's CAS (ON_CPU_PENDING -> cpu) succeeds.
                // dequeue_set_pending already does this on the dispatch
                // side, but doing it here closes a window where a concurrent
                // try_switch reads on_cpu as a stale CPU number before
                // dequeue.
                t.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
                record_trans(tid as u32, 8, t.state, ON_CPU_PENDING);
                trace_sched(tid as u32, 8); // 8=rescue_enq
                set_enq_tag(7); // 7=rescue
                // Per-branch rescue counter: the two predicates that lead
                // here are mutually exclusive.  `stale_on_cpu` is the Bug A
                // pattern from commit 712e741; otherwise the orphan was
                // detected via `on == u32::MAX`.
                if stale_on_cpu {
                    RESCUE_STALE_ON_CPU.fetch_add(1, Ordering::Relaxed);
                } else {
                    RESCUE_MAX.fetch_add(1, Ordering::Relaxed);
                }
                rescue_per_tid_inc(tid as u32);
                // Layer 3/4 paravirt: avoid re-pending on the same
                // starved/stolen CPU that orphaned the thread.
                let target = choose_wake_target_steal_aware(target);
                percpu_enqueue(target, prio, tid as ThreadId);
            }
        }
    }

    // Second pass: rescue CallReply-blocked threads stuck in COMMITTED
    // with wakeup=true. Only runs during confirmed IPC stalls, not on
    // periodic sweeps, to avoid prematurely killing legitimate slow calls.
    if !rescue_parked {
        return;
    }
    for tid in 1..max_tid {
        let t = unsafe { &*(THREAD_TABLE.get(tid) as *const Thread) };
        if t.task_id == 0 || t.state != ThreadState::Blocked {
            continue;
        }
        if !matches!(t.blocked_on, BlockReason::CallReply(_)) {
            continue;
        }
        let park = t.park_state.load(Ordering::Acquire);
        let wake = t.wakeup.load(Ordering::Acquire);
        if park == PARK_COMMITTED && wake {
            let (tevt, tcpu, tseq) = trace_last(tid as u32);
            crate::println!(
                "RESCUE-PARK: tid={} task={} blk={:?} trace=(evt={} cpu={} seq={})",
                tid, t.task_id, t.blocked_on, tevt, tcpu, tseq
            );
            let sp = thread_saved_sp(tid as ThreadId);
            if sp != 0 && validate_kstack_inject(tid as ThreadId, sp, "rescue_park") {
                let died_tag = crate::ipc::call_reply::CALL_REPLY_SERVER_DIED;
                unsafe {
                    use crate::arch::trapframe::ExceptionFrame;
                    let frame = &mut *(sp as *mut ExceptionFrame);
                    crate::syscall::handlers::set_return(frame, 0);
                    crate::syscall::handlers::set_reg(frame, 1, died_tag);
                    crate::syscall::handlers::set_reg(frame, 2, 0);
                    crate::syscall::handlers::set_reg(frame, 3, 0);
                    crate::syscall::handlers::set_reg(frame, 4, 0);
                    crate::syscall::handlers::set_reg(frame, 5, 0);
                    crate::syscall::handlers::set_reg(frame, 6, 0);
                    crate::syscall::handlers::set_reg(frame, 7, 0);
                }
            }
            wake_parked_thread(tid as ThreadId);
        }
    }
}

/// Get monotonic time in nanoseconds since boot.
pub fn get_monotonic_ns() -> u64 {
    crate::arch::timer::monotonic_ns()
}

/// Insert a thread into the global sleep queue, sorted by deadline (earliest first).
/// Must be called with the thread already marked Blocked/Sleep and deadline set.
/// Caller must NOT hold SLEEP_QUEUE_LOCK.
fn sleep_queue_insert(tid: ThreadId, deadline_ns: u64) {
    let inserted_at_head;
    {
        let _guard = SLEEP_QUEUE_LOCK.lock();
        let head = SLEEP_QUEUE_HEAD.load(Ordering::Relaxed);

        // Walk the list to find insertion point (sorted by deadline ascending).
        let mut prev: u32 = u32::MAX; // u32::MAX = inserting at head
        let mut cur = head;
        while cur != u32::MAX {
            let ct = unsafe { thread_mut_from_ref(cur) };
            if ct.sleep_deadline_ns > deadline_ns {
                break;
            }
            prev = cur;
            cur = ct.sleep_next;
        }

        let t = unsafe { thread_mut_from_ref(tid) };
        t.sleep_next = cur;

        if prev == u32::MAX {
            // Insert at head.
            SLEEP_QUEUE_HEAD.store(tid, Ordering::Release);
            inserted_at_head = true;
        } else {
            let pt = unsafe { thread_mut_from_ref(prev) };
            pt.sleep_next = tid;
            inserted_at_head = false;
        }
    }

    // If the new deadline is the earliest (inserted at head), reprogram the
    // local CPU's timer so we don't oversleep.
    if inserted_at_head {
        crate::arch::timer::program_oneshot_ns(deadline_ns);
    }
}

/// Remove a thread from the sleep queue (e.g., on signal delivery or cancel).
/// Safe to call even if the thread is not on the queue.
/// Caller must NOT hold SLEEP_QUEUE_LOCK.
fn sleep_queue_remove(tid: ThreadId) {
    let _guard = SLEEP_QUEUE_LOCK.lock();
    let head = SLEEP_QUEUE_HEAD.load(Ordering::Relaxed);
    if head == u32::MAX {
        return;
    }

    // Find and unlink.
    let mut prev: u32 = u32::MAX;
    let mut cur = head;
    while cur != u32::MAX {
        if cur == tid {
            let ct = unsafe { thread_mut_from_ref(cur) };
            let next = ct.sleep_next;
            ct.sleep_next = u32::MAX;
            if prev == u32::MAX {
                SLEEP_QUEUE_HEAD.store(next, Ordering::Release);
            } else {
                let pt = unsafe { thread_mut_from_ref(prev) };
                pt.sleep_next = next;
            }
            return;
        }
        let ct = unsafe { thread_mut_from_ref(cur) };
        prev = cur;
        cur = ct.sleep_next;
    }
}

/// Wake threads whose sleep deadlines have passed.
/// Called from tick() before try_switch. O(1) when no timers expired,
/// O(K) for K expired threads. Only acquires the lock if the head has expired.
fn check_sleep_timers() {
    let now_ns = get_monotonic_ns();

    // Fast path: peek at the head without locking. If the earliest deadline
    // hasn't passed, no work to do.
    let head = SLEEP_QUEUE_HEAD.load(Ordering::Acquire);
    if head == u32::MAX {
        return;
    }
    let head_deadline = unsafe { thread_mut_from_ref(head) }.sleep_deadline_ns;
    if head_deadline > now_ns {
        return;
    }

    // Drain expired entries from the head of the sorted list.
    let mut to_wake: [(ThreadId, u8, u32); 64] = [(0, 0, 0); 64];
    let mut count = 0usize;
    {
        let _guard = SLEEP_QUEUE_LOCK.lock();
        let mut cur = SLEEP_QUEUE_HEAD.load(Ordering::Relaxed);
        while cur != u32::MAX && count < 64 {
            let t = unsafe { thread_mut_from_ref(cur) };
            if t.sleep_deadline_ns > now_ns {
                break;
            } // sorted: rest are later
            let next = t.sleep_next;
            let target = t.last_cpu.load(Ordering::Relaxed);
            to_wake[count] = (cur, t.effective_priority, target);
            t.sleep_next = u32::MAX;
            count += 1;
            cur = next;
        }
        SLEEP_QUEUE_HEAD.store(cur, Ordering::Release);
    }

    let waker_cpu = smp::cpu_id();
    // Wake collected threads (outside the lock).
    for i in 0..count {
        let (tid, prio, mut target) = to_wake[i];
        // Plan A: steal-to-waker for stale targets.  If target CPU's
        // last tick is more than STALE_TICK_THRESHOLD_NS old (KVM
        // virtual-timer dropped, vCPU host-descheduled, etc.), the
        // IPI we'd send won't be processed promptly and the woken
        // thread would sit on target's runqueue for hundreds of ms
        // to seconds.  Re-target to the waker CPU instead — the
        // thread runs immediately at the cost of cache locality.
        // Skip this re-target for the (target == waker) case
        // because last_cpu == self isn't a tail concern.
        // Lowered from 100 ms to 30 ms after Phase 5p flake hunt:
        // when KVM descheduled the host vCPU for >100 ms (we saw 94 s
        // tick gaps), the original 100 ms threshold meant most wakes
        // still went to a CPU that had no recent tick.  Retargeting
        // to the waker CPU much sooner reduces the wake-latency tail.
        //
        // Paravirt Layer 1: compare in vcpu_runtime_ns (not wallclock)
        // so a host-pause that froze ALL guest CPUs for tens of
        // seconds doesn't cause every wake to false-retarget to the
        // waker.  The real signal we want is "target CPU hasn't had
        // vCPU time recently", which excludes host pauses.
        const STALE_TICK_THRESHOLD_NS: u64 = 30_000_000; // 30 ms
        if target != waker_cpu && (target as usize) < smp::MAX_CPUS {
            let target_last = PER_CPU_LAST_TICK_VCPU_NS[target as usize]
                .load(Ordering::Relaxed);
            let now_vcpu = crate::arch::timer::vcpu_runtime_ns();
            if target_last != 0
                && now_vcpu.saturating_sub(target_last) > STALE_TICK_THRESHOLD_NS
            {
                target = waker_cpu;
                STALE_TARGET_RETARGET_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
        // Layer 3/4 paravirt: even after the (older) tick-stale retarget
        // above, the chosen target may be heavily host-stolen or IPI-
        // starved.  Apply choose_wake_target_steal_aware to bring the
        // Stage-1 adaptive IPI-staleness + steal-time checks here.
        target = choose_wake_target_steal_aware(target);
        // Wait for the thread's parking stack switch to complete.
        while thread_ref(tid).stack_switch_pending.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        let t = unsafe { thread_mut_from_ref(tid) };
        t.blocked_on = BlockReason::None;
        t.sleep_deadline_ns = 0;
        // NEW_INV: store ON_CPU_PENDING (was u32::MAX from park_for_sleep)
        // BEFORE state=Ready, so rescue's on==MAX orphan predicate cannot
        // observe (state=Ready ∧ on_cpu=MAX).
        thread_ref(tid).on_cpu.store(ON_CPU_PENDING, Ordering::Release);
        record_trans(tid as u32, 15, ThreadState::Ready, ON_CPU_PENDING);
        // Diagnostic: stamp wake timestamp for the wake-to-dispatch
        // latency histogram.  Set BEFORE state=Ready so try_switch on
        // any CPU that picks up this thread observes a non-zero
        // timestamp.
        thread_ref(tid).wake_pending_ts_ns.store(now_ns, Ordering::Relaxed);
        t.state = ThreadState::Ready;
        trace_sched(tid, 15); // 15=sleep_wake (state=Ready, about to enqueue)
        set_enq_tag(7); // 7=sleep_timer
        percpu_enqueue(target, prio, tid);
        // Force preemption of the target CPU's currently-running thread
        // by setting yield_asap before sending the reschedule IPI.  The
        // IPI's try_switch checks yield_asap and preempts when set,
        // instead of just decrementing quantum by 1 and returning.
        // This exposes latent preemption-unsafety that the previous
        // ~100 ms quantum-cycle masked; the audit-and-fix path is the
        // current strategy for boot-throughput improvement.
        let waker = waker_cpu;
        if target != waker {
            let pcpu_target = smp::get(target);
            let target_cur = pcpu_target.current_thread.load(Ordering::Relaxed);
            let target_idle = pcpu_target.idle_thread_id.load(Ordering::Relaxed);
            if target_cur != target_idle && target_cur != 0 {
                // Use the ART-checked accessor: between loading
                // current_thread and reaching here the thread could have
                // exited and the tid become stale.  thread_ref_opt
                // returns None on a missing ART entry instead of
                // dereferencing a null/garbage pointer.
                if let Some(t) = thread_ref_opt(target_cur) {
                    t.yield_asap.store(true, Ordering::Release);
                    FORCED_PREEMPT_COUNT.fetch_add(1, Ordering::Relaxed);
                }
            }
            crate::arch::irq::send_reschedule_ipi(target);
        }
    }
}

/// Diagnostic: total forced preemptions from sleep-wake.  Surfaced in
/// the WATCHDOG dump alongside other stall counters.
pub static FORCED_PREEMPT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Diagnostic: aggregate wake-to-dispatch latency (ns) for threads
/// woken by check_sleep_timers (or any other code path that stamps
/// `wake_pending_ts_ns`).  Cleared by try_switch when the thread is
/// first dispatched onto a CPU.  WATCHDOG dump derives the running
/// average from these two counters, exposing what the actual sleep_ms
/// wake latency floor looks like under live load.
pub static SLEEP_WAKE_LATENCY_NS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static SLEEP_WAKE_LATENCY_COUNT: AtomicU64 = AtomicU64::new(0);
pub static SLEEP_WAKE_LATENCY_NS_MAX: AtomicU64 = AtomicU64::new(0);

/// Bucketed histogram of wake-to-dispatch latencies, log10-style.
/// Bucket index → upper bound (monotonic ns):
///   0: <  100 us         (sub-tick fast path)
///   1: <    1 ms
///   2: <   10 ms          (one TICK_INTERVAL_NS — expected typical)
///   3: <  100 ms          (10 ticks — IPI loss recovery floor)
///   4: <    1 s
///   5: <   10 s
///   6: >= 10 s            (catastrophic outlier)
pub static SLEEP_WAKE_LATENCY_BUCKETS: [AtomicU64; 7] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Per-CPU last tick timestamp (monotonic ns).  Updated at the top
/// of `tick()`.  A multi-second gap means the LAPIC tick on that CPU
/// stopped firing — the most likely cause of the wake-latency
/// long-tail outliers when target CPU's IPI was lost AND its own
/// tick didn't recover.
pub static PER_CPU_LAST_TICK_NS: [AtomicU64; smp::MAX_CPUS] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; smp::MAX_CPUS]
};
/// Per-CPU last tick timestamp in vcpu_runtime_ns scale.  Paravirt
/// Layer 1 companion to PER_CPU_LAST_TICK_NS: the wallclock stamp
/// above is what the TICK-GAP probe uses to detect host pauses, but
/// scheduler heuristics (e.g. STALE_TICK_THRESHOLD retarget in
/// check_sleep_timers) should not falsely classify a target CPU as
/// "stale" simply because the host descheduled the guest for tens
/// of seconds — that's not the target CPU's fault.  Comparing against
/// vcpu_runtime_ns gives us "the target CPU hasn't had vCPU time
/// recently", which is the actual signal we want.
pub static PER_CPU_LAST_TICK_VCPU_NS: [AtomicU64; smp::MAX_CPUS] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; smp::MAX_CPUS]
};
/// Largest observed gap between consecutive ticks on any CPU (ns).
/// If this stays close to TICK_INTERVAL_NS, ticks are healthy; if it
/// blows up to multi-second values, the tick handler isn't running
/// when expected.
pub static PER_CPU_TICK_MAX_GAP_NS: AtomicU64 = AtomicU64::new(0);

/// Plan A counter: number of sleep wakes that were re-targeted from
/// last_cpu to the waker CPU because last_cpu's tick had gone stale
/// past STALE_TICK_THRESHOLD_NS.  A high ratio (relative to
/// SLEEP_WAKE_LATENCY_COUNT) means the tail mitigation is firing
/// often — i.e., target CPUs are routinely going silent under host
/// load.
pub static STALE_TARGET_RETARGET_COUNT: AtomicU64 = AtomicU64::new(0);

/// Check per-task alarm timers and deliver SIGALRM.
/// Called from tick() before try_switch.
fn check_alarm_timers() {
    let now_ns = get_monotonic_ns();
    let mut fired = [0u32; 64];
    let mut count = 0usize;
    let mut next_earliest: u64 = 0;

    // Lock-free: alarm fields are only written by the owning task (alarm())
    // or by this tick path; no concurrent mutation.
    SCHED_TASK_ART.for_each(|_key, val| {
        let task = unsafe { &mut *(val as *mut Task) };
        if task.active && task.alarm_deadline_ns != 0 {
            if task.alarm_deadline_ns <= now_ns {
                if task.alarm_interval_ns != 0 {
                    task.alarm_deadline_ns = now_ns + task.alarm_interval_ns;
                } else {
                    task.alarm_deadline_ns = 0;
                }
                if count < 64 {
                    fired[count] = task.id;
                    count += 1;
                }
            }
            // Track the next earliest alarm (including rearmed ones).
            if task.alarm_deadline_ns != 0 {
                if next_earliest == 0 || task.alarm_deadline_ns < next_earliest {
                    next_earliest = task.alarm_deadline_ns;
                }
            }
        }
    });

    // Update the cached earliest alarm deadline.
    EARLIEST_ALARM_NS.store(next_earliest, Ordering::Relaxed);

    for i in 0..count {
        send_signal_to_task(fired[i], super::task::SIGALRM);
    }
}

/// Check per-thread interval timers and deliver signals when they fire.
fn check_interval_timers() {
    let now_ns = get_monotonic_ns();
    let mut fired_tid: ThreadId = 0;
    let mut fired_sig: u32 = 0;
    let mut fired_interval: u64 = 0;
    let mut found = false;
    let mut next_earliest: u64 = 0;

    // Lock-free: timer fields are only written by the owning thread
    // (sys_timer_create) or by this tick path.
    SCHED_THREAD_ART.for_each(|key, val| {
        let t = unsafe { &*(val as *const Thread) };
        if t.state != ThreadState::Dead
            && t.stack_base != 0
            && t.timer_signal != 0
            && t.timer_next_ns != 0
        {
            if !found && now_ns >= t.timer_next_ns {
                fired_tid = key as ThreadId;
                fired_sig = t.timer_signal;
                fired_interval = t.timer_interval_ns;
                // Re-arm the timer while we have the pointer.
                let t_mut = unsafe { &mut *(val as *mut Thread) };
                t_mut.timer_next_ns = if fired_interval != 0 {
                    now_ns + fired_interval
                } else {
                    0
                };
                found = true;
            }
            // Track the next earliest interval timer (including rearmed).
            let next = unsafe { &*(val as *const Thread) }.timer_next_ns;
            if next != 0 && (next_earliest == 0 || next < next_earliest) {
                next_earliest = next;
            }
        }
    });

    // Update the cached earliest interval timer deadline.
    EARLIEST_INTERVAL_NS.store(next_earliest, Ordering::Relaxed);

    if found {
        send_signal_to_thread(fired_tid, fired_sig);
    }
}

/// Park the current thread for a timed sleep.
/// Sets the deadline and blocks the thread (off-CPU).
pub fn park_current_for_sleep(deadline_ns: u64) {
    // Disable IRQs for the entire function. Same preemption race as
    // park_current_for_ipc — timer after state=Blocked would let try_switch
    // overwrite state to Ready and re-enqueue.
    let irq_saved = crate::arch::irq::disable();

    let cpu = smp::cpu_id() as usize;
    let cpu_idx = cpu as u32;
    drain_deferred_requeue(cpu_idx);

    let tid_for_sp = smp::get(cpu_idx).current_thread.load(Ordering::Relaxed);
    let frame_sp = unsafe { thread_mut_from_ref(tid_for_sp) }.syscall_frame_sp;

    let pcpu = smp::current();
    let tid = pcpu.current_thread.load(Ordering::Relaxed) as usize;
    let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

    // Set deadline before marking Blocked. Lock-free: we own the running thread.
    let thread = unsafe { thread_mut_from_ref(tid as ThreadId) };
    thread.sleep_deadline_ns = deadline_ns;
    // #208 KEPOCH guard.
    if validate_kstack_inject(tid as ThreadId, frame_sp, "park_sleep") {
        write_saved_sp(thread, frame_sp);
        record_saved_sp_write(tid as ThreadId, frame_sp, 12); // park_for_sleep
        thread.saved_sp_source = 5; // park_for_sleep
    }
    thread.state = ThreadState::Blocked;
    thread.blocked_on = BlockReason::Sleep;

    // Release on_cpu BEFORE inserting into sleep queue. Once the thread is
    // visible in the sleep queue, check_sleep_timers on any CPU may expire it
    // and call percpu_enqueue. If on_cpu still holds the old CPU value, the
    // scheduling CPU's CAS will fail (DOUBLE-SCHED). Same pattern as
    // park_current_for_ipc.
    if (tid as ThreadId) != idle_id {
        thread_ref(tid as ThreadId).on_cpu.store(u32::MAX, Ordering::Release);
        // #135 action=22: park_sleep set on_cpu=MAX.  Sleep-blocking
        // path (sleep_ms / SYS_NANOSLEEP / etc.).  A rescue capturing
        // a tid whose TRANS-RING ends with action=22 saw an orphan that
        // didn't complete its sleep_wake re-enqueue (action=15 would
        // normally follow).
        record_trans(tid as u32, 22, ThreadState::Blocked, u32::MAX);
    }
    trace_sched(tid as u32, 13); // 13=park_sleep (state=Blocked, on_cpu=MAX)

    // Mark per-thread stack_switch_pending BEFORE sleep_queue_insert.
    // Once visible, check_sleep_timers may expire and enqueue us
    // immediately. It spins on this flag before enqueueing.
    thread_ref(tid as ThreadId).stack_switch_pending.store(true, Ordering::Release);
    parked_tid()[cpu].store(tid as u32, Ordering::Release);

    // Insert into sorted sleep queue so check_sleep_timers can find us.
    sleep_queue_insert(tid as ThreadId, deadline_ns);

    // SA notification for the parked thread (lock-free).
    let parked_task_id = thread.task_id;
    let sa_enabled = task_ref(parked_task_id).sa_enabled;

    // Pick next thread from per-CPU queue.
    // #173: gated dispatch — parker is going Blocked (already sleep-queue
    // inserted), so no self-pick concern.  Route through the atomic claim
    // helper when the gate is on so the high-frequency sleep/timer park tail
    // can't strand a PENDING (this was a residual stuck_gate_on source).
    let next_id = if DISPATCH_USE_CLAIM_HELPER.load(Ordering::Relaxed) {
        percpu_pick_next_and_claim(cpu_idx, idle_id, pcpu, 3 /* park */)
    } else {
        percpu_pick_next(cpu_idx, idle_id)
    };
    let prev_task = thread_ref(tid as ThreadId).task_id;
    let next_task = thread_ref(next_id).task_id;
    if prev_task != next_task {
        let next_root = {
            let tptr = TASK_TABLE.get(next_task) as *const Task;
            if !tptr.is_null() {
                unsafe { (*tptr).page_table_root }
            } else {
                0
            }
        };
        if next_root != 0 {
            crate::mm::hat::switch_page_table(next_root);
        } else {
            let kern_root = crate::mm::hat::kernel_pt_root();
            if kern_root != 0 {
                crate::mm::hat::switch_page_table(kern_root);
            }
        }
    }

    crate::arch::trapframe::update_kernel_stack(next_id as u32, thread_ref(next_id).stack_base + kstack_size());

    // Claim on_cpu for next thread (ON_CPU_PENDING → cpu).
    if next_id != idle_id {
        if let Err(other_cpu) = thread_ref(next_id).on_cpu.compare_exchange(
            ON_CPU_PENDING, cpu_idx, Ordering::AcqRel, Ordering::Acquire,
        ) {
            record_trans(next_id as u32, TRANS_CAS_FAIL, thread_ref(next_id).state, other_cpu);
            // See try_switch CAS_FAIL — benign regardless of other_cpu.
            CAS_FAIL_RESCUE_BAILS.fetch_add(1, Ordering::Relaxed);
            // Pick idle instead.
            let idle_sp = thread_ref(idle_id).saved_sp;
            unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
            set_current_thread(pcpu, idle_id);
            pending_switch_sp()[cpu].store(idle_sp, Ordering::Release);
            let _ = irq_saved;
            return;
        }
        record_trans(next_id as u32, TRANS_CAS_OK, ThreadState::Running, cpu_idx);
        thread_ref(next_id).on_cpu_set_by.store(5, Ordering::Relaxed); // 5=park_sleep
        // #120 dispatch-symmetry: clear pending state + bump cas_ok counter.
        dispatch_cas_ok(pcpu, next_id);
        // Set Running IMMEDIATELY after CAS — close TOCTOU window (see try_switch).
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
    } else {
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
    }

    // Safety: next_id was just dequeued, we own it.
    let next_t = unsafe { thread_mut_from_ref(next_id) };
    set_current_thread(pcpu, next_id);
    let next_sp = next_t.saved_sp;

    // Reprogram the one-shot timer so this CPU wakes at the sleep deadline.
    // Without this, the dynamic tick may have the timer set far in the future
    // (up to MAX_IDLE_NS = 1s), causing the sleep to overshoot its deadline.
    // Done here with IRQs disabled so the timer cannot fire before the switch.
    crate::arch::timer::program_oneshot_ns(deadline_ns);

    // Mark park-switch-pending (see park_current_for_ipc for explanation).
    park_switch_pending()[cpu].store(true, Ordering::Release);

    // Store pending_switch before restoring IRQs — see park_current_for_ipc.
    pending_switch_sp()[cpu].store(next_sp, Ordering::Release);

    if sa_enabled {
        let tptr = TASK_TABLE.get(parked_task_id) as *mut Task;
        let task = unsafe { &*tptr };
        let waiter = task.sa_waiter.load(Ordering::Acquire);
        if waiter != u32::MAX && waiter as usize != tid {
            task.sa_event.store(tid as u64, Ordering::Release);
            task.sa_pending.store(true, Ordering::Release);
            wake_thread(waiter);
        }
    }

    // Leave IRQs disabled — exception handler consumes pending_switch.
    let _ = irq_saved;
}

/// Set an alarm timer for the current task.
/// Returns previous remaining time in nanoseconds.
pub fn alarm(initial_ns: u64, interval_ns: u64) -> u64 {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let task_id = thread_ref(tid).task_id;
    // Safe: only the current task modifies its own alarm fields.
    let task = unsafe { task_mut_from_ref(task_id) };

    let now = get_monotonic_ns();
    let prev_remaining = if task.alarm_deadline_ns > now {
        task.alarm_deadline_ns - now
    } else {
        0
    };

    if initial_ns == 0 {
        task.alarm_deadline_ns = 0;
        task.alarm_interval_ns = 0;
    } else {
        let deadline = now + initial_ns;
        task.alarm_deadline_ns = deadline;
        task.alarm_interval_ns = interval_ns;
        // If this alarm is earlier than the cached earliest, update and reprogram.
        let cached = EARLIEST_ALARM_NS.load(Ordering::Relaxed);
        if cached == 0 || deadline < cached {
            EARLIEST_ALARM_NS.store(deadline, Ordering::Relaxed);
            crate::arch::timer::program_oneshot_ns(deadline);
        }
    }
    prev_remaining
}

/// L4-style direct handoff: sender donates its remaining quantum to receiver.
/// Saves sender's SP, loads receiver as current thread, stores receiver's SP
/// in PENDING_SWITCH_SP. Receiver must already have its frame injected.
pub fn handoff_to(receiver_tid: ThreadId) {
    // Disable IRQs for the entire function. Same preemption race as
    // voluntary_reschedule — timer after percpu_enqueue would let try_switch
    // double-enqueue the sender.
    let irq_saved = crate::arch::irq::disable();

    let cpu = smp::cpu_id() as usize;
    let cpu_id = cpu as u32;
    drain_deferred_requeue(cpu_id);

    let sender_tid_for_sp = smp::get(cpu_id).current_thread.load(Ordering::Relaxed);
    let frame_sp = unsafe { thread_mut_from_ref(sender_tid_for_sp) }.syscall_frame_sp;

    let pcpu = smp::current();
    let sender_tid = pcpu.current_thread.load(Ordering::Relaxed) as usize;

    // Safety: sender is Running on this CPU, we own it.
    let (sender_prio, remaining_quantum, sender_task);
    {
        let sender = unsafe { thread_mut_from_ref(sender_tid as ThreadId) };
        // #208 KEPOCH guard.
        if validate_kstack_inject(sender_tid as ThreadId, frame_sp, "handoff") {
            write_saved_sp(sender, frame_sp);
            record_saved_sp_write(sender_tid as ThreadId, frame_sp, 13); // direct-transfer sender
        }
        sender_prio = sender.effective_priority;
        remaining_quantum = sender.quantum;
        sender_task = sender.task_id;
        // NOTE: state stays Running here. Set to Ready AFTER deferred store.
    }
    // Defer re-enqueue of sender. Same pattern as voluntary_reschedule:
    // we're still on the sender's kernel stack, so immediate percpu_enqueue
    // would let another CPU steal the sender and use the same stack.
    // NEW_INV: store ON_CPU_PENDING BEFORE slot fill and BEFORE state=Ready.
    {
        let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);
        if (sender_tid as ThreadId) != idle_id {
            thread_ref(sender_tid as ThreadId)
                .on_cpu
                .store(ON_CPU_PENDING, Ordering::Release);
            record_trans(sender_tid as u32, 16, ThreadState::Running, ON_CPU_PENDING);
            let packed = (sender_tid as u64) | ((sender_prio as u64) << 32)
                | ((cpu_id as u64) << 40);
            let old_deferred = deferred_requeue()[cpu].swap(packed, Ordering::AcqRel);
            if old_deferred != 0 {
                // Defensive: handoff_to entry should have drained this slot.
                // Under NEW_INV, lost tid already has on_cpu=PENDING.
                let lost_tid = (old_deferred & 0xFFFFFFFF) as u32;
                let lost_prio = ((old_deferred >> 32) & 0xFF) as u8;
                let lost_target = ((old_deferred >> 40) & 0xFF) as u32;
                crate::println!(
                    "DEFERRED-OVERWRITE(handoff): cpu={} lost tid={} prio={} replaced by tid={}",
                    cpu, lost_tid, lost_prio, sender_tid
                );
                set_enq_tag(10);
                percpu_enqueue(lost_target, lost_prio, lost_tid);
            }
            unsafe { thread_mut_from_ref(sender_tid as ThreadId) }.state = ThreadState::Ready;
            trace_sched(sender_tid as u32, 1); // 1=deferred_store
        }
    }

    // Donate remaining quantum to receiver.
    // Safety: receiver was Blocked (parked), not on any queue or CPU.
    let receiver = unsafe { thread_mut_from_ref(receiver_tid) };
    receiver.quantum = remaining_quantum;
    let recv_task = receiver.task_id;
    if sender_task != recv_task {
        let next_root = {
            let tptr = TASK_TABLE.get(recv_task) as *const Task;
            if !tptr.is_null() {
                unsafe { (*tptr).page_table_root }
            } else {
                0
            }
        };
        if next_root != 0 {
            crate::mm::hat::switch_page_table(next_root);
        } else {
            let kern_root = crate::mm::hat::kernel_pt_root();
            if kern_root != 0 {
                crate::mm::hat::switch_page_table(kern_root);
            }
        }
    }

    crate::arch::trapframe::update_kernel_stack(receiver_tid as u32, receiver.stack_base + kstack_size());

    // Claim on_cpu for receiver (parked threads have on_cpu=MAX from
    // park_current_for_ipc, so CAS expects MAX).
    {
        let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);
        if receiver_tid != idle_id {
            pcpu.dispatching_tid.store(receiver_tid, Ordering::Release);
            if let Err(_other_cpu) = thread_ref(receiver_tid).on_cpu.compare_exchange(
                u32::MAX, cpu_id, Ordering::AcqRel, Ordering::Acquire,
            ) {
                // CAS_FAIL on the MAX→cpu handoff path: receiver was
                // already claimed by another CPU (e.g. wake_thread set
                // on_cpu=PENDING concurrently).  Mutex-by-CAS still
                // holds — at most one CPU dispatches.  Yield to sender
                // benignly instead of killing the receiver.  See
                // try_switch CAS_FAIL rationale.
                CAS_FAIL_RESCUE_BAILS.fetch_add(1, Ordering::Relaxed);
                pcpu.dispatching_tid.store(0, Ordering::Release);
                // Stay on sender. Clear deferred store and restore on_cpu.
                deferred_requeue()[cpu].store(0, Ordering::Release);
                let sender2 = unsafe { thread_mut_from_ref(sender_tid as ThreadId) };
                sender2.state = ThreadState::Running;
                thread_ref(sender_tid as ThreadId).on_cpu.store(cpu_id, Ordering::Release);
                // #208 ROOT CAUSE FIX: we set TSS.RSP0 = receiver's kstack
                // above (line ~10259), and we're now bailing back to sender.
                // Without restoring TSS.RSP0, the sender returning to user
                // mode would push its next IRQ/syscall iret frame onto the
                // receiver's parked kstack — corrupting whoever is parked
                // there.  Captured by RSP0-MISMATCH boot 1706 (tid=20 sender,
                // tid=13 receiver, alternating CALL/REPLY).
                crate::arch::trapframe::update_kernel_stack(
                    sender_tid as u32,
                    sender2.stack_base + kstack_size(),
                );
                return;
            }
            thread_ref(receiver_tid).on_cpu_set_by.store(4, Ordering::Relaxed); // 4=handoff
        }
    }

    // Activate receiver.
    receiver.state = ThreadState::Running;
    set_current_thread(pcpu, receiver_tid);
    {
        let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);
        if receiver_tid != idle_id {
            pcpu.dispatching_tid.store(0, Ordering::Release);
        }
    }
    let recv_sp = receiver.saved_sp;

    // Sanity check: saved_sp must be within the thread's kstack.
    // Idle threads run on boot stacks (ring 0), not their allocated kstack.
    {
        let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);
        let is_idle = receiver_tid == idle_id;
        let kbase = receiver.stack_base;
        let kend = kbase as u64 + kstack_size() as u64;
        if !is_idle && (recv_sp < kbase as u64 || recv_sp >= kend) {
            #[cfg(target_arch = "x86_64")]
            {
                use crate::arch::x86_64::serial::{put_bytes, put_hex_u64, put_dec_u64};
                let mut buf = [0u8; 192];
                let mut k = 0;
                put_bytes(&mut buf, &mut k, b"BUG: handoff_to: tid=");
                put_dec_u64(&mut buf, &mut k, receiver_tid as u64);
                put_bytes(&mut buf, &mut k, b" saved_sp=");
                put_hex_u64(&mut buf, &mut k, recv_sp);
                put_bytes(&mut buf, &mut k, b" OUTSIDE kstack ");
                put_hex_u64(&mut buf, &mut k, kbase as u64);
                put_bytes(&mut buf, &mut k, b"..");
                put_hex_u64(&mut buf, &mut k, kend);
                put_bytes(&mut buf, &mut k, b" (source=");
                put_dec_u64(&mut buf, &mut k, receiver.saved_sp_source as u64);
                put_bytes(&mut buf, &mut k, b")\n");
                crate::arch::x86_64::serial::handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            #[cfg(not(target_arch = "x86_64"))]
            crate::println!(
                "BUG: handoff_to: tid={} saved_sp={:#x} OUTSIDE kstack {:#x}..{:#x} (source={})",
                receiver_tid, recv_sp, kbase, kend, receiver.saved_sp_source
            );
            // Kill this thread and switch to idle instead.
            thread_ref(receiver_tid).killed.store(true, Ordering::Release);
            let idle_sp = thread_ref(idle_id).saved_sp;
            unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
            set_current_thread(pcpu, idle_id);
            pending_switch_sp()[cpu].store(idle_sp, Ordering::Release);
            return;
        }
    }

    // Reprogram the timer so the deferred slot (holding sender) is drained
    // promptly — same rationale as voluntary_reschedule.
    crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);

    // Store pending_switch before restoring IRQs — see park_current_for_ipc
    // comment for why this ordering is critical with preemptive syscalls.
    pending_switch_sp()[cpu].store(recv_sp, Ordering::Release);
    // Leave IRQs disabled through exception handler return.
    let _ = irq_saved;
}

// --- Scheduler Activations API ---

/// Register the current task for scheduler activations.
pub fn sa_register() {
    let task_id = current_task_id();
    if task_id == 0 {
        return;
    }
    // Safe: only the current task modifies its own sa_enabled.
    unsafe { task_mut_from_ref(task_id) }.sa_enabled = true;
}

/// Block until a scheduler activation event occurs.
/// Returns the blocked kthread's TID, or u64::MAX on error.
pub fn sa_wait() -> u64 {
    let task_id = current_task_id();
    if task_id == 0 {
        return u64::MAX;
    }

    let tptr = TASK_TABLE.get(task_id) as *mut Task;
    if tptr.is_null() {
        return u64::MAX;
    }
    let task = unsafe { &*tptr };

    // Fast path: event already pending.
    if task.sa_pending.swap(false, Ordering::SeqCst) {
        task.sa_waiter.store(u32::MAX, Ordering::Relaxed);
        return task.sa_event.load(Ordering::Relaxed);
    }

    // Register as waiter.
    let tid = current_thread_id();
    clear_wakeup_flag(tid);
    task.sa_waiter.store(tid, Ordering::Release);

    // Double-check after registering (prevents lost wakeup).
    if task.sa_pending.swap(false, Ordering::SeqCst) {
        task.sa_waiter.store(u32::MAX, Ordering::Relaxed);
        return task.sa_event.load(Ordering::Relaxed);
    }

    // Block until woken by SA notification.
    block_current(BlockReason::ActivationWait);
    task.sa_waiter.store(u32::MAX, Ordering::Relaxed);
    task.sa_pending.store(false, Ordering::Relaxed);
    task.sa_event.load(Ordering::Relaxed)
}

/// Get the index (0-based) of the current kthread within its task.
pub fn sa_getid() -> u64 {
    let tid = current_thread_id();
    let task_id = current_task_id();
    let mut idx = 0u64;
    let mut found = false;
    SCHED_THREAD_ART.for_each(|key, val| {
        if found {
            return;
        }
        let t = unsafe { &*(val as *const Thread) };
        if t.task_id == task_id && t.state != ThreadState::Dead && (t.stack_base != 0 || key == 0) {
            if key as u32 == tid {
                found = true;
                return;
            }
            idx += 1;
        }
    });
    if found { idx } else { u64::MAX }
}

/// Set the coscheduling group for the current thread. group=0 removes from any group.
pub fn cosched_set(group: u32) {
    let tid = current_thread_id();
    thread_ref(tid)
        .cosched_group
        .store(group, Ordering::Relaxed);
}

/// Set CPU affinity mask for a thread. Returns true on success.
/// Takes u64 at the syscall ABI boundary; internally converts to CpuMask.
pub fn set_affinity(tid: u32, mask: u64) -> bool {
    if (tid as usize) >= RadixTable::capacity() || mask == 0 {
        return false;
    }
    thread_ref(tid)
        .affinity_mask
        .store_mask(&cpumask::CpuMask::from_u64(mask), Ordering::Relaxed);
    true
}

/// Get CPU affinity mask for a thread.
/// Returns u64 (low 64 bits) for syscall ABI compatibility.
pub fn get_affinity(tid: u32) -> u64 {
    if (tid as usize) >= RadixTable::capacity() {
        return 0;
    }
    thread_ref(tid)
        .affinity_mask
        .load_mask(Ordering::Relaxed)
        .as_u64()
}
