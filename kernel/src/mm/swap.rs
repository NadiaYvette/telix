//! Swap subsystem — back evicted anonymous pages with an external store.
//!
//! # Design
//!
//! Unlike Linux, Telix does not encode swap location in the PTE. Every
//! anonymous page belongs to a [`MemObject`](super::object::MemObject)
//! identified by `(obj_id, page_idx)`. When WSCLOCK evicts a clean or dirty
//! anon page, the PTE becomes not-present and the object records a
//! [`SwapSlot`] in its lazily-allocated `swap_slots` table. On the next
//! fault to that page, `ensure_page` consults `swap_slots[idx]` and, if a
//! slot is recorded, allocates a fresh physical page and asks the backend
//! to read it back in.
//!
//! The PTE itself only ever holds "present" or "not-present"; the existing
//! `SW_ZEROED` hint continues to distinguish "evicted-but-still-resident"
//! from "never-faulted" for the zero-fill fast path. Swap lookup is an
//! *object* concern, not a *page table* concern.
//!
//! # Backends
//!
//! Backends are dispatched through the [`Backend`] enum. Enum dispatch
//! (rather than `dyn SwapBackend`) avoids the fat-pointer atomic storage
//! problem in no-std and keeps the swap hot path branch-free once the
//! backend is chosen. The initial backend is a RAM-backed mock
//! (`Backend::Ram`) that carves a fixed number of pages from phys at
//! boot. A later commit will add `Backend::VirtioBlk`.
//!
//! # Command line
//!
//! `swap=<spec>` selects a backend at boot:
//! - `swap=ram:<mib>` — mock RAM backend with `<mib>` MiB of swap space
//! - `swap=vda2`      — (future) virtio-blk partition backend
//!
//! Absence of the parameter leaves swap disabled; WSCLOCK continues to
//! discard evicted pages as it does today.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::page::{self, PhysAddr};
use super::phys;

/// Opaque identifier for one slot in a swap backend. 0 is reserved as
/// "no slot" so that `swap_slots: [AtomicU32]` can use zero-initialized
/// memory to mean "not swapped". Slot numbering in backends is therefore
/// 1-based externally.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct SwapSlot(pub u32);

impl SwapSlot {
    pub const NONE: SwapSlot = SwapSlot(0);

    #[inline]
    pub fn is_none(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub fn raw(self) -> u32 {
        self.0
    }
}

/// Result of a swap I/O operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SwapIoResult {
    Ok,
    /// Backend is out of free slots.
    Full,
    /// Underlying device returned an error or the backend is not
    /// initialized.
    Io,
}

/// Installed swap backend. Set once at boot; read lock-free thereafter.
/// `None` means swap is disabled.
#[derive(Clone, Copy)]
enum Backend {
    /// RAM-backed mock backend. Slot data lives in phys-allocated pages
    /// carved out at boot; reads and writes are memcpy. Uses no real
    /// I/O, so WSCLOCK can drive it synchronously during development
    /// and tests.
    Ram(&'static RamBackend),
}

/// RAM-backed swap store. Slot N (1-indexed externally) is a single
/// MMU-page-sized buffer at `pages[N-1]`. Free/busy state is tracked in
/// a bitmap of AtomicU64 words; slots are allocated with a CAS on the
/// owning word. Entirely lock-free.
pub struct RamBackend {
    /// Physical pages (one per slot). Indexed 0..total; the external
    /// slot id is `index + 1` so that 0 can stay reserved for
    /// `SwapSlot::NONE`.
    pages: &'static [u64],
    /// Free bitmap: bit set = slot free. Covers `pages.len()` bits.
    bitmap: &'static [AtomicU64],
    total: u32,
    /// Running tally of in-use slots, for reporting.
    used: AtomicU32,
}

impl RamBackend {
    fn alloc_slot(&self) -> SwapSlot {
        let n = self.pages.len();
        if n == 0 {
            return SwapSlot::NONE;
        }
        // Scan the bitmap for a word with at least one free bit.
        for (wi, word) in self.bitmap.iter().enumerate() {
            loop {
                let cur = word.load(Ordering::Relaxed);
                if cur == 0 {
                    break; // word fully used, move on
                }
                let bit = cur.trailing_zeros() as usize;
                let idx = wi * 64 + bit;
                if idx >= n {
                    break; // past the valid range
                }
                let new = cur & !(1u64 << bit);
                if word
                    .compare_exchange(cur, new, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    self.used.fetch_add(1, Ordering::Relaxed);
                    // External slot ids are 1-based.
                    return SwapSlot((idx + 1) as u32);
                }
                // CAS lost, retry this word.
            }
        }
        SwapSlot::NONE
    }

    fn free_slot(&self, slot: SwapSlot) {
        if slot.is_none() {
            return;
        }
        let idx = (slot.0 - 1) as usize;
        if idx >= self.pages.len() {
            return;
        }
        let wi = idx / 64;
        let bit = idx % 64;
        self.bitmap[wi].fetch_or(1u64 << bit, Ordering::Release);
        self.used.fetch_sub(1, Ordering::Relaxed);
    }

    fn slot_pa(&self, slot: SwapSlot) -> Option<u64> {
        if slot.is_none() {
            return None;
        }
        let idx = (slot.0 - 1) as usize;
        self.pages.get(idx).copied()
    }

    fn write_page(&self, slot: SwapSlot, src_pa: PhysAddr) -> SwapIoResult {
        let dst = match self.slot_pa(slot) {
            Some(p) => p,
            None => return SwapIoResult::Io,
        };
        // Safety: both addresses are kernel-identity-mapped phys pages
        // of size page::page_size(); they never overlap (distinct slot
        // allocations).
        unsafe {
            core::ptr::copy_nonoverlapping(
                src_pa.as_usize() as *const u8,
                dst as *mut u8,
                page::page_size(),
            );
        }
        SwapIoResult::Ok
    }

    fn read_page(&self, slot: SwapSlot, dst_pa: PhysAddr) -> SwapIoResult {
        let src = match self.slot_pa(slot) {
            Some(p) => p,
            None => return SwapIoResult::Io,
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                src as *const u8,
                dst_pa.as_usize() as *mut u8,
                page::page_size(),
            );
        }
        SwapIoResult::Ok
    }
}

/// Slot to the active backend. Not an `Option<Backend>` because we want
/// the enabled check to be a single atomic load on the fast path.
static mut BACKEND: Option<Backend> = None;

/// Whether swap is available and should be used by WSCLOCK. Acts as the
/// release/acquire gate for `BACKEND`.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Counters exposed to tests and /proc-like interfaces.
pub static SWAP_OUT_COUNT: AtomicU32 = AtomicU32::new(0);
pub static SWAP_IN_COUNT: AtomicU32 = AtomicU32::new(0);
pub static SWAP_IO_ERRORS: AtomicU32 = AtomicU32::new(0);

/// Install a backend. Called once at boot by the chosen backend's
/// initializer. Subsequent calls are ignored.
fn install(backend: Backend) {
    if ENABLED.load(Ordering::Acquire) {
        return;
    }
    // Safety: single-threaded init path (BSP, pre-SMP), guarded by
    // ENABLED. Future callers read only after observing ENABLED=true.
    unsafe {
        BACKEND = Some(backend);
    }
    ENABLED.store(true, Ordering::Release);
}

/// True if a backend has been registered.
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

#[inline]
fn current() -> Option<Backend> {
    if !enabled() {
        return None;
    }
    // Safety: BACKEND is written exactly once under ENABLED=false → true
    // transition; after that it is stable for the remainder of the boot.
    unsafe { BACKEND }
}

/// Allocate a slot in the active backend. Returns `SwapSlot::NONE` if
/// swap is disabled or the backend is full.
pub fn alloc_slot() -> SwapSlot {
    match current() {
        Some(Backend::Ram(b)) => b.alloc_slot(),
        None => SwapSlot::NONE,
    }
}

/// Release a slot previously returned by `alloc_slot`.
pub fn free_slot(slot: SwapSlot) {
    if slot.is_none() {
        return;
    }
    match current() {
        Some(Backend::Ram(b)) => b.free_slot(slot),
        None => {}
    }
}

/// Write the contents of the physical page at `pa` into `slot`.
pub fn write_page(slot: SwapSlot, pa: PhysAddr) -> SwapIoResult {
    if slot.is_none() {
        return SwapIoResult::Io;
    }
    let r = match current() {
        Some(Backend::Ram(b)) => b.write_page(slot, pa),
        None => SwapIoResult::Io,
    };
    if r == SwapIoResult::Ok {
        SWAP_OUT_COUNT.fetch_add(1, Ordering::Relaxed);
    } else {
        SWAP_IO_ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    r
}

/// Read `slot` into the physical page at `pa`.
pub fn read_page(slot: SwapSlot, pa: PhysAddr) -> SwapIoResult {
    if slot.is_none() {
        return SwapIoResult::Io;
    }
    let r = match current() {
        Some(Backend::Ram(b)) => b.read_page(slot, pa),
        None => SwapIoResult::Io,
    };
    if r == SwapIoResult::Ok {
        SWAP_IN_COUNT.fetch_add(1, Ordering::Relaxed);
    } else {
        SWAP_IO_ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    r
}

/// Initialize a RAM-backed swap backend with `total` slots. Allocates
/// one MMU-page-sized buffer per slot plus metadata. Returns `false` if
/// phys allocation fails partway through (caller logs and leaves swap
/// disabled).
fn init_ram_backend(total: u32) -> bool {
    if total == 0 {
        return false;
    }
    let n = total as usize;
    // Metadata: one u64 phys pointer per slot, one bit per slot in the
    // free bitmap. alloc_static_slice zero-initializes; we then flip
    // bitmap bits to "free" below.
    let pages: &'static mut [u64] = unsafe { phys::alloc_static_slice::<u64>(n) };
    let bmp_words = (n + 63) / 64;
    let bitmap: &'static mut [AtomicU64] =
        unsafe { phys::alloc_static_slice::<AtomicU64>(bmp_words) };

    // Allocate one page per slot. If we run out, shrink to what we got.
    let mut filled = 0usize;
    for i in 0..n {
        match phys::alloc_page() {
            Some(pa) => {
                pages[i] = pa.as_usize() as u64;
                filled += 1;
            }
            None => break,
        }
    }
    if filled == 0 {
        return false;
    }

    // Mark the first `filled` slots as free; leave any shortfall tail
    // as zero (busy → never allocated).
    for i in 0..filled {
        let wi = i / 64;
        let bit = i % 64;
        let cur = bitmap[wi].load(Ordering::Relaxed);
        bitmap[wi].store(cur | (1u64 << bit), Ordering::Relaxed);
    }

    // Shrink the slice view to the filled portion so alloc_slot doesn't
    // hand out unowned entries.
    let pages: &'static [u64] = &pages[..filled];
    let bitmap: &'static [AtomicU64] = &bitmap[..bmp_words];

    // Allocate the RamBackend control block itself from phys so it is
    // `'static`. It fits in well under a page.
    let ctrl_pa = match phys::alloc_page() {
        Some(p) => p,
        None => return false,
    };
    let ctrl_ptr = ctrl_pa.as_usize() as *mut RamBackend;
    unsafe {
        core::ptr::write(
            ctrl_ptr,
            RamBackend {
                pages,
                bitmap,
                total: filled as u32,
                used: AtomicU32::new(0),
            },
        );
    }
    let ctrl: &'static RamBackend = unsafe { &*ctrl_ptr };

    install(Backend::Ram(ctrl));
    crate::println!(
        "  Swap: ram backend online — {} slots ({} KiB)",
        filled,
        (filled * page::page_size()) / 1024
    );
    true
}

/// Parse the `swap=` boot parameter and bring up the matching backend.
/// Called once from `kmain` after `phys::init` and before any workload
/// that might trigger WSCLOCK.
pub fn init() {
    let spec = match crate::boot::cmdline::get_extra(b"swap") {
        Some(s) => s,
        None => {
            crate::println!("  Swap: disabled (no swap= on cmdline)");
            return;
        }
    };

    if let Some(rest) = strip_prefix(spec, b"ram:") {
        let mib = match parse_u32(rest) {
            Some(n) if n > 0 => n,
            _ => {
                crate::println!("  Swap: bad ram spec, disabled");
                return;
            }
        };
        // Slot = one allocation page (page_size()). total = mib * 1M / page_size().
        let total = (mib as usize) * (1024 * 1024 / page::page_size());
        if !init_ram_backend(total as u32) {
            crate::println!("  Swap: ram backend init failed, disabled");
        }
        return;
    }

    crate::println!("  Swap: unknown spec, disabled");
}

fn strip_prefix<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if s.len() >= prefix.len() && &s[..prefix.len()] == prefix {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let mut acc: u32 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(acc)
}
