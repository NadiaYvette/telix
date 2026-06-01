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
//! backend is chosen. `Backend::Ram` is a mock that uses phys pages;
//! `Backend::BlkIo` talks to the "blk" service via the generic I/O
//! protocol (IO_READ/IO_WRITE IPC), making it device-agnostic.
//!
//! # Command line
//!
//! `swap=<spec>` selects a backend at boot:
//! - `swap=ram:<mib>` — mock RAM backend with `<mib>` MiB of swap space
//! - `swap=blk:<offset_kb>:<size_kb>` — block I/O backend (disk swap area)
//!
//! Absence of the parameter leaves swap disabled; WSCLOCK continues to
//! discard evicted pages as it does today.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

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
    /// Block I/O backend. Sends IO_READ/IO_WRITE to the name-server-
    /// registered "blk" service via standard IPC. Device-agnostic —
    /// works with any block driver (virtio-blk, NVMe, etc.).
    BlkIo(&'static BlkIoBackend),
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
        // #235: both addresses reach the same RAM via PHYS_DIRECT_MAP
        // (PML4[507]) so the copy survives PML4[0] unmap; distinct slot
        // allocations never overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(
                crate::mm::page::phys_to_kva(src_pa.as_usize()) as *const u8,
                crate::mm::page::phys_to_kva(dst as usize) as *mut u8,
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
                crate::mm::page::phys_to_kva(src as usize) as *const u8,
                crate::mm::page::phys_to_kva(dst_pa.as_usize()) as *mut u8,
                page::page_size(),
            );
        }
        SwapIoResult::Ok
    }
}

// -----------------------------------------------------------------------
// Block I/O backend — talks to the "blk" service via generic IPC
// -----------------------------------------------------------------------

use crate::ipc::Message;
use crate::ipc::port;

/// Block-I/O-backed swap. Sends IO_READ/IO_WRITE to the name-server-
/// registered "blk" service. Slot N (1-indexed) maps to disk byte
/// offset `swap_offset + (N-1) * page_size()`.
pub struct BlkIoBackend {
    /// Port of the "blk" service (resolved at init via name server).
    blk_port: u64,
    /// Dedicated reply port for swap I/O. Only one swap I/O is in
    /// flight at a time (enforced by the object lock or WSCLOCK
    /// single-threadedness).
    reply_port: u64,
    /// Byte offset on the block device where the swap area starts.
    swap_offset: u64,
    /// Free bitmap (same pattern as RamBackend).
    bitmap: &'static [AtomicU64],
    total_slots: u32,
    used: AtomicU32,
}

impl BlkIoBackend {
    fn alloc_slot(&self) -> SwapSlot {
        let n = self.total_slots as usize;
        if n == 0 {
            return SwapSlot::NONE;
        }
        for (wi, word) in self.bitmap.iter().enumerate() {
            loop {
                let cur = word.load(Ordering::Relaxed);
                if cur == 0 {
                    break;
                }
                let bit = cur.trailing_zeros() as usize;
                let idx = wi * 64 + bit;
                if idx >= n {
                    break;
                }
                let new = cur & !(1u64 << bit);
                if word
                    .compare_exchange(cur, new, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    self.used.fetch_add(1, Ordering::Relaxed);
                    return SwapSlot((idx + 1) as u32);
                }
            }
        }
        SwapSlot::NONE
    }

    fn free_slot(&self, slot: SwapSlot) {
        if slot.is_none() {
            return;
        }
        let idx = (slot.0 - 1) as usize;
        if idx >= self.total_slots as usize {
            return;
        }
        let wi = idx / 64;
        let bit = idx % 64;
        self.bitmap[wi].fetch_or(1u64 << bit, Ordering::Release);
        self.used.fetch_sub(1, Ordering::Relaxed);
    }

    /// Disk byte offset for slot N (1-indexed).
    fn slot_byte_offset(&self, slot: SwapSlot) -> u64 {
        self.swap_offset + ((slot.0 - 1) as u64) * (page::page_size() as u64)
    }

    fn write_page(&self, slot: SwapSlot, src_pa: PhysAddr) -> SwapIoResult {
        let offset = self.slot_byte_offset(slot);
        let len = page::page_size() as u64;
        let d2 = (len & 0xFFFF_FFFF) | ((self.reply_port) << 32);
        let msg = Message::new(
            crate::io::protocol::IO_WRITE,
            [0, offset, d2, src_pa.as_usize() as u64, 0, 0],
        );
        if port::send(self.blk_port, msg).is_err() {
            return SwapIoResult::Io;
        }
        match port::recv(self.reply_port) {
            Ok(reply) => {
                if reply.tag == crate::io::protocol::IO_WRITE_OK {
                    SwapIoResult::Ok
                } else {
                    SwapIoResult::Io
                }
            }
            Err(()) => SwapIoResult::Io,
        }
    }

    fn read_page(&self, slot: SwapSlot, dst_pa: PhysAddr) -> SwapIoResult {
        let offset = self.slot_byte_offset(slot);
        let len = page::page_size() as u64;
        let d2 = (len & 0xFFFF_FFFF) | ((self.reply_port) << 32);
        let msg = Message::new(
            crate::io::protocol::IO_READ,
            [0, offset, d2, dst_pa.as_usize() as u64, 0, 0],
        );
        if port::send(self.blk_port, msg).is_err() {
            return SwapIoResult::Io;
        }
        match port::recv(self.reply_port) {
            Ok(reply) => {
                if reply.tag == crate::io::protocol::IO_READ_OK {
                    SwapIoResult::Ok
                } else {
                    SwapIoResult::Io
                }
            }
            Err(()) => SwapIoResult::Io,
        }
    }
}

/// Slot to the active backend. Not an `Option<Backend>` because we want
/// the enabled check to be a single atomic load on the fast path.
static mut BACKEND: Option<Backend> = None;

/// Whether swap is available and should be used by WSCLOCK. Acts as the
/// release/acquire gate for `BACKEND`.
static ENABLED: AtomicBool = AtomicBool::new(false);

// -----------------------------------------------------------------------
// Swap slot refcounting — supports shared slots across COW fork siblings
// -----------------------------------------------------------------------

/// Per-slot reference count array. Indexed by `slot.0 - 1` (0-based).
/// Allocated once during backend init, sized to match total slots.
static mut SLOT_REFCOUNTS: *mut AtomicU8 = core::ptr::null_mut();
static SLOT_REFCOUNT_LEN: AtomicU32 = AtomicU32::new(0);

/// Allocate the refcount array for `total` slots. Called once from each
/// backend's init path, after the backend bitmap is set up.
fn init_refcounts(total: usize) {
    let rc: &'static mut [AtomicU8] = unsafe { phys::alloc_static_slice::<AtomicU8>(total) };
    unsafe {
        SLOT_REFCOUNTS = rc.as_mut_ptr();
    }
    SLOT_REFCOUNT_LEN.store(total as u32, Ordering::Release);
}

/// Get a reference to the refcount for `slot`.
#[inline]
fn refcount_of(slot: SwapSlot) -> Option<&'static AtomicU8> {
    if slot.is_none() {
        return None;
    }
    let idx = (slot.0 - 1) as usize;
    let len = SLOT_REFCOUNT_LEN.load(Ordering::Relaxed) as usize;
    if idx >= len {
        return None;
    }
    unsafe { Some(&*SLOT_REFCOUNTS.add(idx)) }
}

/// Set the refcount to 1 for a freshly allocated slot.
#[inline]
fn refcount_init(slot: SwapSlot) {
    if let Some(rc) = refcount_of(slot) {
        rc.store(1, Ordering::Relaxed);
    }
}

/// Increment the reference count on a swap slot. Called during fork to
/// share a slot between parent and child objects.
pub fn dup_slot(slot: SwapSlot) {
    if let Some(rc) = refcount_of(slot) {
        let old = rc.fetch_add(1, Ordering::Relaxed);
        debug_assert!(old < 255, "swap slot refcount overflow");
        super::stats::SWAP_SLOTS_DUPED.fetch_add(1, Ordering::Relaxed);
    }
}

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

/// Returns true if the active backend is the in-memory RAM backend
/// (synchronous, no IPC). Used to gate kernel-context E2E tests that
/// cannot do blocking IPC to blk_srv.
pub fn is_ram_backend() -> bool {
    matches!(current(), Some(Backend::Ram(_)))
}

/// Number of swap slots currently in use (allocated but not freed).
pub fn slots_in_use() -> u32 {
    match current() {
        Some(Backend::Ram(b)) => b.used.load(Ordering::Relaxed),
        Some(Backend::BlkIo(b)) => b.used.load(Ordering::Relaxed),
        None => 0,
    }
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
/// swap is disabled or the backend is full. The new slot has refcount 1.
pub fn alloc_slot() -> SwapSlot {
    let slot = match current() {
        Some(Backend::Ram(b)) => b.alloc_slot(),
        Some(Backend::BlkIo(b)) => b.alloc_slot(),
        None => SwapSlot::NONE,
    };
    if !slot.is_none() {
        refcount_init(slot);
    }
    slot
}

/// Decrement the refcount on a swap slot. When the refcount reaches
/// zero the slot is returned to the backend's free pool.
pub fn free_slot(slot: SwapSlot) {
    if slot.is_none() {
        return;
    }
    // Decrement refcount. If still > 0, another COW sibling holds the slot.
    if let Some(rc) = refcount_of(slot) {
        let prev = rc.fetch_sub(1, Ordering::Release);
        debug_assert!(prev > 0, "swap slot refcount underflow");
        if prev > 1 {
            return; // other references remain
        }
    }
    // Refcount hit zero (or no refcount tracking) — return to backend.
    match current() {
        Some(Backend::Ram(b)) => b.free_slot(slot),
        Some(Backend::BlkIo(b)) => b.free_slot(slot),
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
        Some(Backend::BlkIo(b)) => b.write_page(slot, pa),
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
        Some(Backend::BlkIo(b)) => b.read_page(slot, pa),
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

    // Per-slot refcount array for COW fork sharing.
    init_refcounts(filled);

    // Allocate the RamBackend control block itself from phys so it is
    // `'static`. It fits in well under a page.
    let ctrl_pa = match phys::alloc_page() {
        Some(p) => p,
        None => return false,
    };
    // #235 Phase 4e: PHYS_DIRECT_MAP kva storage for the long-lived
    // backend control block.
    let ctrl_ptr = crate::mm::page::phys_to_kva(ctrl_pa.as_usize()) as *mut RamBackend;
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

// -----------------------------------------------------------------------
// Block I/O deferred init — the blk service isn't up during swap::init()
// -----------------------------------------------------------------------

/// Pending blk backend parameters (stored during init, applied later).
static PENDING_BLK_OFFSET_KB: AtomicU32 = AtomicU32::new(0);
static PENDING_BLK_SIZE_KB: AtomicU32 = AtomicU32::new(0);
static BLK_PENDING: AtomicBool = AtomicBool::new(false);

/// Resolve the "blk" service port via the kernel service registry.
fn ns_lookup_blk() -> Option<u64> {
    let port = crate::io::namesrv::svc_lookup(b"blk", false);
    if port != 0 { Some(port) } else { None }
}

/// Initialize the block I/O swap backend. Called from `init_blk_deferred`
/// once the blk service is running.
fn init_blk_backend(offset_kb: u32, size_kb: u32) -> bool {
    let blk_port = match ns_lookup_blk() {
        Some(p) => p,
        None => return false,
    };

    let slot_size = page::page_size();
    let total_bytes = (size_kb as usize) * 1024;
    let total_slots = total_bytes / slot_size;
    if total_slots == 0 {
        return false;
    }

    let swap_offset = (offset_kb as u64) * 1024;

    // Allocate free bitmap.
    let bmp_words = (total_slots + 63) / 64;
    let bitmap: &'static mut [AtomicU64] =
        unsafe { phys::alloc_static_slice::<AtomicU64>(bmp_words) };

    // Mark all slots as free.
    for i in 0..total_slots {
        let wi = i / 64;
        let bit = i % 64;
        let cur = bitmap[wi].load(Ordering::Relaxed);
        bitmap[wi].store(cur | (1u64 << bit), Ordering::Relaxed);
    }

    // Per-slot refcount array for COW fork sharing.
    init_refcounts(total_slots);

    // Dedicated reply port for synchronous swap I/O.
    let reply_port = match port::create() {
        Some(p) => p,
        None => return false,
    };

    // Allocate the BlkIoBackend control block from phys.
    let ctrl_pa = match phys::alloc_page() {
        Some(p) => p,
        None => return false,
    };
    let ctrl_ptr = crate::mm::page::phys_to_kva(ctrl_pa.as_usize()) as *mut BlkIoBackend;
    unsafe {
        core::ptr::write(
            ctrl_ptr,
            BlkIoBackend {
                blk_port,
                reply_port,
                swap_offset,
                bitmap: &*bitmap,
                total_slots: total_slots as u32,
                used: AtomicU32::new(0),
            },
        );
    }
    let ctrl: &'static BlkIoBackend = unsafe { &*ctrl_ptr };

    install(Backend::BlkIo(ctrl));
    crate::println!(
        "  Swap: blk backend online — {} slots ({} KiB) at disk offset {} KiB, port={}",
        total_slots,
        (total_slots * slot_size) / 1024,
        offset_kb,
        blk_port,
    );
    true
}

/// Complete deferred blk backend initialization. Called from
/// `startup_thread()` after I/O servers are running and registered
/// with the name server. Retries NS_LOOKUP a few times with yields
/// to give blk_srv time to register.
pub fn init_blk_deferred() {
    if !BLK_PENDING.load(Ordering::Acquire) {
        return;
    }
    let offset_kb = PENDING_BLK_OFFSET_KB.load(Ordering::Relaxed);
    let size_kb = PENDING_BLK_SIZE_KB.load(Ordering::Relaxed);

    // The blk_srv may still be initializing. Retry with yields.
    for attempt in 0..20 {
        if init_blk_backend(offset_kb, size_kb) {
            return;
        }
        if attempt < 19 {
            // Yield to let blk_srv progress.
            let my_tid = crate::sched::current_thread_id();
            crate::sched::scheduler::set_yield_asap(my_tid);
            crate::sched::scheduler::arch_wait_for_irq();
        }
    }
    crate::println!("  Swap: blk backend init failed after retries, swap disabled");
}

// -----------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------

/// Parse the `swap=` boot parameter and bring up the matching backend.
/// Called once from `kmain` after `phys::init` and before any workload
/// that might trigger WSCLOCK.
///
/// For `swap=blk:...`, only stores parameters; actual init is deferred
/// to `init_blk_deferred()` after I/O servers are up.
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

    if let Some(rest) = strip_prefix(spec, b"blk:") {
        // Format: blk:<offset_kb>:<size_kb>
        match parse_blk_spec(rest) {
            Some((offset_kb, size_kb)) => {
                PENDING_BLK_OFFSET_KB.store(offset_kb, Ordering::Relaxed);
                PENDING_BLK_SIZE_KB.store(size_kb, Ordering::Relaxed);
                BLK_PENDING.store(true, Ordering::Release);
                crate::println!(
                    "  Swap: blk backend deferred (offset={}K, size={}K)",
                    offset_kb,
                    size_kb,
                );
            }
            None => crate::println!("  Swap: bad blk spec (expected blk:<offset_kb>:<size_kb>)"),
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

/// Parse `<offset_kb>:<size_kb>` from the blk swap spec.
fn parse_blk_spec(s: &[u8]) -> Option<(u32, u32)> {
    let colon = s.iter().position(|&b| b == b':')?;
    let offset_kb = parse_u32(&s[..colon])?;
    let size_kb = parse_u32(&s[colon + 1..])?;
    if size_kb == 0 {
        return None;
    }
    Some((offset_kb, size_kb))
}
