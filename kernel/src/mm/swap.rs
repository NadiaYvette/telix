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

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::page::PhysAddr;

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
    /// RAM-backed mock backend. Reads/writes go to a phys-allocated
    /// region. Lands in a follow-up commit.
    #[allow(dead_code)]
    Ram,
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
#[allow(dead_code)]
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
        Some(Backend::Ram) => {
            // Stub: ram backend lands in Commit 2.
            SwapSlot::NONE
        }
        None => SwapSlot::NONE,
    }
}

/// Release a slot previously returned by `alloc_slot`.
pub fn free_slot(slot: SwapSlot) {
    if slot.is_none() {
        return;
    }
    match current() {
        Some(Backend::Ram) => {
            // Stub.
        }
        None => {}
    }
}

/// Write the contents of the physical page at `pa` into `slot`.
pub fn write_page(slot: SwapSlot, _pa: PhysAddr) -> SwapIoResult {
    if slot.is_none() {
        return SwapIoResult::Io;
    }
    match current() {
        Some(Backend::Ram) => {
            // Stub.
            SWAP_IO_ERRORS.fetch_add(1, Ordering::Relaxed);
            SwapIoResult::Io
        }
        None => SwapIoResult::Io,
    }
}

/// Read `slot` into the physical page at `pa`.
pub fn read_page(slot: SwapSlot, _pa: PhysAddr) -> SwapIoResult {
    if slot.is_none() {
        return SwapIoResult::Io;
    }
    match current() {
        Some(Backend::Ram) => {
            // Stub.
            SWAP_IO_ERRORS.fetch_add(1, Ordering::Relaxed);
            SwapIoResult::Io
        }
        None => SwapIoResult::Io,
    }
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
        crate::println!(
            "  Swap: ram:{} MiB requested (backend not yet wired)",
            mib
        );
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
