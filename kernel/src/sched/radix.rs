//! Two-level radix page table for lockless entity pointer lookup.
//!
//! L0: one allocation page of atomic pointers to L1 pages.
//! L1: allocation pages of atomic pointers to entities (Task*/Thread*),
//!     allocated on demand.
//!
//! Entries per page = PAGE_SIZE / 8 (RADIX_FANOUT).
//! Two-level capacity = RADIX_FANOUT² (67M at 64K pages, 4M at 16K).
//!
//! Lookup is 2 atomic loads (L0 → L1 → entity), both from pages that
//! are cache-hot on active CPUs. Growth is append-only: L1 pages are
//! allocated under the caller's serializing lock and never freed.

use crate::mm::page;
use crate::mm::phys;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// SET-LOG probe (THREAD_TABLE corruption hunt)
// ---------------------------------------------------------------------------
//
// Boot 1798 caught `thread_ref(tid=4)` returning a kstack VA instead of a
// SLAB_REGION VA — i.e. THREAD_TABLE[4] was OVERWRITTEN with a kstack-VA
// value after a clean initial set.  Three theories:
//   (a) some set() call stored a bad val (set-side bug — unlikely given
//       all 3 sites use freshly-allocated SLAB_REGION pointers)
//   (b) memory aliasing: the L1 page's PA is the same as some kstack /
//       slab page's PA, so writes to that other page scribble L1
//   (c) a wild pointer from elsewhere lands on the L1 slot
//
// To discriminate, log every set() invocation: (tid, val, prev_val,
// caller_loc, l1_va, l1_idx).  At guard-hit time dump all entries
// matching the offending tid.  If prev_val was correct on the most
// recent set, the corruption is post-set (b or c).

#[repr(C)]
#[derive(Clone, Copy)]
struct SetLogEntry {
    seq: u64,
    tid: u32,
    l1_idx: u32,
    val: u64,
    prev_val: u64,
    caller_loc: u64,
    l1_va: u64,
}

const SET_LOG_SIZE: usize = 256;
struct SetLogCell(core::cell::UnsafeCell<SetLogEntry>);
unsafe impl Sync for SetLogCell {}
static SET_LOG: [SetLogCell; SET_LOG_SIZE] = [const {
    SetLogCell(core::cell::UnsafeCell::new(SetLogEntry {
        seq: 0,
        tid: 0,
        l1_idx: 0,
        val: 0,
        prev_val: 0,
        caller_loc: 0,
        l1_va: 0,
    }))
}; SET_LOG_SIZE];
static SET_LOG_HEAD: AtomicU64 = AtomicU64::new(0);

fn record_set(
    tid: u32,
    val: u64,
    prev_val: u64,
    caller_loc: u64,
    l1_va: u64,
    l1_idx: u32,
) {
    let seq = SET_LOG_HEAD.fetch_add(1, Ordering::Relaxed);
    let idx = (seq as usize) % SET_LOG_SIZE;
    unsafe {
        *SET_LOG[idx].0.get() = SetLogEntry {
            seq: seq + 1,
            tid,
            l1_idx,
            val,
            prev_val,
            caller_loc,
            l1_va,
        };
    }
}

/// Dump all SET_LOG entries matching `target_tid`, oldest-first.  Called
/// from VALIDATOR-BAD-TREF and similar paths to reveal the value
/// trajectory of the offending slot.
///
/// Avoids `println!{:#x}` because under deep corruption (boot 1823) the
/// fmt machinery's digit buffer gets scribbled — we observed the
/// VALIDATOR-BAD-TREF integer values come through as raw stack-garbage
/// bytes instead of formatted hex.  Instead, write directly to the UART
/// using a stateless nibble-loop and pre-baked rodata literals.
#[cfg(target_arch = "x86_64")]
pub fn dump_set_log_for_tid(target_tid: u32) {
    let head = SET_LOG_HEAD.load(Ordering::Relaxed);
    let mut hits: u32 = 0;
    let start = if head >= SET_LOG_SIZE as u64 {
        head - SET_LOG_SIZE as u64
    } else {
        0
    };
    direct_uart_dump_set_log_header(target_tid, head, start);
    for seq in start..head {
        let idx = (seq as usize) % SET_LOG_SIZE;
        let entry = unsafe { *SET_LOG[idx].0.get() };
        if entry.tid == target_tid {
            direct_uart_dump_set_log_entry(&entry);
            hits += 1;
        }
    }
    direct_uart_dump_set_log_footer(target_tid, hits);
}

#[cfg(not(target_arch = "x86_64"))]
pub fn dump_set_log_for_tid(target_tid: u32) {
    let head = SET_LOG_HEAD.load(Ordering::Relaxed);
    let mut hits: u32 = 0;
    let start = if head >= SET_LOG_SIZE as u64 {
        head - SET_LOG_SIZE as u64
    } else {
        0
    };
    crate::println!(
        "RADIX-SET-LOG-DUMP-BEGIN: tid={} head={} window=[{}..{})",
        target_tid, head, start, head
    );
    for seq in start..head {
        let idx = (seq as usize) % SET_LOG_SIZE;
        let entry = unsafe { *SET_LOG[idx].0.get() };
        if entry.tid == target_tid {
            crate::println!(
                "RADIX-SET-LOG: seq={} tid={} l1_idx={} val={:#x} \
                 prev_val={:#x} caller_loc={:#x} l1_va={:#x}",
                entry.seq, entry.tid, entry.l1_idx, entry.val,
                entry.prev_val, entry.caller_loc, entry.l1_va
            );
            hits += 1;
        }
    }
    crate::println!(
        "RADIX-SET-LOG-DUMP-END: tid={} hits={}",
        target_tid, hits
    );
}

// ---- direct-UART formatters (x86_64 only) ----
//
// These bypass `fmt::Arguments` entirely so the dump survives even when
// the formatter's stack scratch buffers are corrupted (boot 1823 mode).
// Each writes one nibble at a time straight to COM1 via `Serial.putc`.

#[cfg(target_arch = "x86_64")]
fn uart_putc(c: u8) {
    crate::arch::x86_64::serial::putc(c);
}

#[cfg(target_arch = "x86_64")]
fn uart_write_str(s: &str) {
    for &b in s.as_bytes() {
        if b == b'\n' {
            uart_putc(b'\r');
        }
        uart_putc(b);
    }
}

#[cfg(target_arch = "x86_64")]
fn uart_write_hex64(val: u64) {
    uart_putc(b'0');
    uart_putc(b'x');
    for i in 0..16 {
        let nib = ((val >> (60 - i * 4)) & 0xf) as u8;
        let c = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
        uart_putc(c);
    }
}

#[cfg(target_arch = "x86_64")]
fn uart_write_u32(val: u32) {
    // Decimal, up to 10 digits.  Right-aligned w/o leading zeros.
    let mut digits = [0u8; 10];
    let mut n = val;
    let mut len = 0;
    if n == 0 {
        uart_putc(b'0');
        return;
    }
    while n > 0 {
        digits[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    for i in (0..len).rev() {
        uart_putc(digits[i]);
    }
}

#[cfg(target_arch = "x86_64")]
fn uart_write_u64(val: u64) {
    let mut digits = [0u8; 20];
    let mut n = val;
    let mut len = 0;
    if n == 0 {
        uart_putc(b'0');
        return;
    }
    while n > 0 {
        digits[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    for i in (0..len).rev() {
        uart_putc(digits[i]);
    }
}

#[cfg(target_arch = "x86_64")]
fn direct_uart_dump_set_log_header(tid: u32, head: u64, start: u64) {
    uart_write_str("RADIX-SET-LOG-DUMP-BEGIN: tid=");
    uart_write_u32(tid);
    uart_write_str(" head=");
    uart_write_u64(head);
    uart_write_str(" window=[");
    uart_write_u64(start);
    uart_write_str("..");
    uart_write_u64(head);
    uart_write_str(")\n");
}

#[cfg(target_arch = "x86_64")]
fn direct_uart_dump_set_log_entry(e: &SetLogEntry) {
    uart_write_str("RADIX-SET-LOG: seq=");
    uart_write_u64(e.seq);
    uart_write_str(" tid=");
    uart_write_u32(e.tid);
    uart_write_str(" l1_idx=");
    uart_write_u32(e.l1_idx);
    uart_write_str(" val=");
    uart_write_hex64(e.val);
    uart_write_str(" prev_val=");
    uart_write_hex64(e.prev_val);
    uart_write_str(" caller_loc=");
    uart_write_hex64(e.caller_loc);
    uart_write_str(" l1_va=");
    uart_write_hex64(e.l1_va);
    uart_write_str("\n");
}

#[cfg(target_arch = "x86_64")]
fn arm_thread_table_4_watchpoint(slot_addr: u64, val: u64) {
    // Emit a marker line so we can verify the arm fired and capture the
    // L1 slot address — letting us cross-reference with future DR0 hits.
    uart_write_str("TT4-WATCH-ARM: slot=");
    uart_write_hex64(slot_addr);
    uart_write_str(" val=");
    uart_write_hex64(val);
    uart_write_str("\n");
    // Hijack GLOBAL_SAVED_SP_WATCH_ADDR (used by the existing #DB handler
    // for saved_sp tracking).  Every CPU will lazily arm its own DR0 on
    // this address via dr0_ensure_watching at the next exception entry.
    crate::arch::x86_64::gdt::GLOBAL_SAVED_SP_WATCH_ADDR
        .store(slot_addr, core::sync::atomic::Ordering::Relaxed);
}

#[cfg(target_arch = "x86_64")]
fn trace_set_live(id: u32, val: u64, prev: u64, caller_loc: u64, l1_page: u64) {
    uart_write_str("SET-LIVE: id=");
    uart_write_u32(id);
    uart_write_str(" val=");
    uart_write_hex64(val);
    uart_write_str(" prev=");
    uart_write_hex64(prev);
    uart_write_str(" loc=");
    uart_write_hex64(caller_loc);
    uart_write_str(" l1=");
    uart_write_hex64(l1_page);
    uart_write_str("\n");
}

#[cfg(target_arch = "x86_64")]
fn direct_uart_dump_set_log_footer(tid: u32, hits: u32) {
    uart_write_str("RADIX-SET-LOG-DUMP-END: tid=");
    uart_write_u32(tid);
    uart_write_str(" hits=");
    uart_write_u32(hits);
    uart_write_str("\n");
}

// ---------------------------------------------------------------------------

/// Maximum pointer entries per allocation page (upper bound for const contexts).
#[allow(dead_code)]
pub const RADIX_FANOUT: usize = page::MAX_PAGE_SIZE / core::mem::size_of::<usize>();

/// Runtime pointer entries per allocation page.
#[inline]
fn radix_fanout() -> usize {
    page::page_size() / core::mem::size_of::<usize>()
}

/// Two-level radix page table. Type-erased (stores `*mut u8`).
/// Callers cast to/from the concrete entity type.
pub struct RadixTable {
    /// Pointer to the L0 page: an array of RADIX_FANOUT AtomicPtr<u8>,
    /// where each entry points to an L1 page (or is null).
    l0: AtomicPtr<AtomicPtr<u8>>,
}

impl RadixTable {
    /// Create an uninitialized table. Call `init()` before first use.
    pub const fn new() -> Self {
        Self {
            l0: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// Diagnostic: read L0 page address + L0[0] entry value (the L1 page
    /// pointer for tid=0..fanout-1).  Used at VALIDATOR-BAD-TREF time to
    /// test whether L0[0] was corrupted (would explain why a DR0 watch
    /// on the L1 slot doesn't fire — corruption is upstream).
    pub fn raw_l0_slots(&self) -> (u64, u64, u64) {
        let l0 = self.l0.load(Ordering::Acquire);
        let l0_addr = l0 as u64;
        if l0.is_null() {
            return (0, 0, 0);
        }
        let l0_entry_0 = unsafe { &*l0 }.load(Ordering::Acquire) as u64;
        let l1_4_addr = l0_entry_0.wrapping_add(4 * 8);
        let l1_4_val = if l0_entry_0 != 0 {
            unsafe { core::ptr::read_volatile(l1_4_addr as *const u64) }
        } else {
            0
        };
        (l0_addr, l0_entry_0, l1_4_val)
    }
}

impl RadixTable {

    /// Allocate the L0 page. Must be called once during kernel init,
    /// before any concurrent access.
    pub fn init(&self) {
        let pa = phys::alloc_page().expect("radix L0 alloc");
        crate::sched::scheduler::record_pa_alias_check(pa.as_usize(), "radix-L0");
        let p = pa.as_usize() as *mut u8;
        unsafe {
            ptr::write_bytes(p, 0, page::page_size());
        }
        self.l0.store(p as *mut AtomicPtr<u8>, Ordering::Release);
    }

    /// Look up entry by ID. Returns raw entity pointer (null if unset).
    /// Lockless — uses Acquire ordering on both levels.
    #[inline]
    pub fn get(&self, id: u32) -> *mut u8 {
        let l0 = self.l0.load(Ordering::Acquire);
        if l0.is_null() {
            return ptr::null_mut();
        }

        let fanout = radix_fanout();
        let l0_idx = (id as usize) / fanout;
        let l1_idx = (id as usize) % fanout;

        if l0_idx >= fanout {
            return ptr::null_mut();
        }

        // Load L1 page pointer from L0.
        let l1_page = unsafe { &*l0.add(l0_idx) }.load(Ordering::Acquire);
        if l1_page.is_null() {
            return ptr::null_mut();
        }

        // Load entity pointer from L1.
        let l1 = l1_page as *const AtomicPtr<u8>;
        unsafe { &*l1.add(l1_idx) }.load(Ordering::Acquire)
    }

    /// Store an entity pointer by ID. Caller must have called `ensure_l1(id)`
    /// first (under a serializing lock). Uses Release ordering.
    #[inline]
    #[track_caller]
    pub fn set(&self, id: u32, val: *mut u8) {
        let caller_loc = core::panic::Location::caller() as *const _ as u64;
        let l0 = self.l0.load(Ordering::Relaxed);
        let fanout = radix_fanout();
        let l0_idx = (id as usize) / fanout;
        let l1_idx = (id as usize) % fanout;

        let l1_page = unsafe { &*l0.add(l0_idx) }.load(Ordering::Relaxed);
        let l1 = l1_page as *const AtomicPtr<u8>;
        let slot = unsafe { &*l1.add(l1_idx) };
        let prev = slot.load(Ordering::Relaxed);
        slot.store(val, Ordering::Release);
        // Probe: record this set in the global ring so VALIDATOR-BAD-TREF can
        // dump the value trajectory of any tid.  Cheap (one fetch_add + one
        // 56-byte struct copy); fires for both THREAD_TABLE and TASK_TABLE.
        record_set(
            id,
            val as u64,
            prev as u64,
            caller_loc,
            l1_page as u64,
            l1_idx as u32,
        );
        // Live-trace to UART for low-tid THREAD_TABLE entries (boot 1860
        // showed dump_set_log_for_tid producing zero output — the static
        // SET_LOG ring may itself be getting scribbled).  Emitting per-set
        // straight to UART catches the trail in real time.  Limit to ID<32
        // to avoid log spam (we only care about tid=4 family).
        #[cfg(target_arch = "x86_64")]
        if id < 32 {
            trace_set_live(id, val as u64, prev as u64, caller_loc, l1_page as u64);
        }
        // Boot 1862 SET-LIVE proves THREAD_TABLE[4] is set correctly to a
        // SLAB_REGION VA, then later overwritten with a kstack VA.  Arm
        // global DR0 on the L1 slot address so the next write triggers
        // #DB and logs the writer's RIP.  Restricted to id=4 (only known
        // recurring victim) to avoid interfering with other watches.
        #[cfg(target_arch = "x86_64")]
        if id == 4 && caller_loc != 0 {
            // Caller is at scheduler.rs:2725 (alloc_thread_id THREAD_TABLE.set)
            // i.e. tid=4 freshly created.  We don't filter on table identity
            // because tid=4 in TASK_TABLE also exists, but the L1 PAs differ.
            // L1 slot address = l1_page + l1_idx * 8.
            let slot_addr = (l1_page as u64).wrapping_add((l1_idx as u64) * 8);
            // Skip if the val being written looks like a PA-as-ptr (Task
            // pointer is PA-cast, not SLAB VA) — only arm for SLAB VAs.
            let val_u = val as u64;
            if val_u >= 0xFFFF_FE80_0000_0000 && val_u < 0xFFFF_FF00_0000_0000 {
                arm_thread_table_4_watchpoint(slot_addr, val_u);
            }
        }
    }

    /// Ensure the L1 page covering `id` exists. Allocates if needed.
    /// Call under a lock that serializes entity ID allocation.
    /// Returns false if allocation fails or ID is out of range.
    pub fn ensure_l1(&self, id: u32) -> bool {
        let l0 = self.l0.load(Ordering::Relaxed);
        if l0.is_null() {
            return false;
        }

        let fanout = radix_fanout();
        let l0_idx = (id as usize) / fanout;
        if l0_idx >= fanout {
            return false;
        }

        let entry = unsafe { &*l0.add(l0_idx) };
        if !entry.load(Ordering::Relaxed).is_null() {
            return true; // L1 page already exists.
        }

        // Allocate and zero a new L1 page.
        let pa = match phys::alloc_page() {
            Some(p) => p,
            None => return false,
        };
        // PA-alias probe: check if this PA's 64 KiB slot already owns
        // a kstack.  If so, writes through the kstack VA will scribble
        // this L1 page — the THREAD_TABLE[4] corruption signature.
        crate::sched::scheduler::record_pa_alias_check(pa.as_usize(), "radix-L1");
        let p = pa.as_usize() as *mut u8;
        unsafe {
            ptr::write_bytes(p, 0, page::page_size());
        }
        entry.store(p, Ordering::Release);
        true
    }

    /// Maximum entity ID supported by this two-level table.
    #[inline]
    pub fn capacity() -> usize {
        let f = radix_fanout();
        f * f
    }
}

// Safety: All access is through atomic operations.
unsafe impl Send for RadixTable {}
unsafe impl Sync for RadixTable {}
