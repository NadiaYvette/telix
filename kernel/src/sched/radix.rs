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

    /// Allocate the L0 page. Must be called once during kernel init,
    /// before any concurrent access.
    pub fn init(&self) {
        let pa = phys::alloc_page().expect("radix L0 alloc");
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
