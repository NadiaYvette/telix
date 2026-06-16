//! Physical memory allocator — Embedded Sparse LLFree.
//!
//! An O(1)-external-memory allocator: per-page bitmaps live in-band inside
//! free pages, and nearly-empty chunks use inline index encoding (option 2).
//!
//! Structure:
//! - N chunk nodes, sized at boot from actual RAM (no compile-time cap)
//! - Per-CPU reservation: each CPU owns one chunk for contention-free alloc
//! - Leaf bitmaps stored inside a free page within each chunk
//! - Chunks with ≤ INLINE_K free pages encode indices directly in the parent node
//! - Multi-page allocation uses a separate lock (rare path)

use super::page::{self, PhysAddr};
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

// ── Per-chunk event ring (option 2 — root-cause double-issue) ────────
//
// Records every chunk allocator event so we can dump filtered events
// at PA-ALIAS time and see the exact race that let two allocators
// claim the same page.
//
// Each entry packs into a u64:
//   bits [0..3]   = action code
//   bits [4..7]   = cpu (4 bits — up to 16 CPUs)
//   bits [8..23]  = chunk_idx
//   bits [24..31] = page_idx (within chunk, 0..63)
//   bits [32..63] = timestamp low 32 bits of monotonic_ns
//
// Ring size 1024 = ~8 KB.  At boot when allocs are heavy we record
// 100s/sec, so 1024 entries gives ~10s of recent history.

const PHYS_EVT_RING: usize = 1024;
static PHYS_EVT: [AtomicU64; PHYS_EVT_RING] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; PHYS_EVT_RING]
};
static PHYS_EVT_POS: AtomicU64 = AtomicU64::new(0);

// Action codes.
const EVT_ALLOC1: u64 = 1;        // chunk_alloc_one — single page from bitmap
const EVT_ALLOC1_FRESH: u64 = 2;  // chunk_alloc_one — all-free chunk transition
const EVT_ALLOC1_INLINE: u64 = 3; // chunk_alloc_one — inline mode pop
const EVT_ALLOCN_FRESH: u64 = 4;  // alloc_pages — all-free chunk
const EVT_ALLOCN_BMP: u64 = 5;    // alloc_pages — bitmap mode
const EVT_ALLOCN_MULTI: u64 = 6;  // alloc_pages — multi-chunk (order > 6)
const EVT_FREE1: u64 = 7;         // chunk_free_one
const EVT_FREEN: u64 = 8;         // free_pages
const EVT_RESERVE: u64 = 9;       // per-CPU reservation grabbed
const EVT_RELEASE: u64 = 10;      // per-CPU reservation released
const EVT_CAS_FAIL_STATE: u64 = 11;  // chunk-state CAS failed (race observed)
const EVT_CAS_FAIL_BMP: u64 = 12;    // cas_bitmap failed (race observed)

#[inline]
fn record_evt(action: u64, chunk_idx: usize, page_idx: u32) {
    let cpu = smp::cpu_id() as u64;
    let ts = (crate::arch::timer::monotonic_ns() & 0xFFFFFFFF) as u64;
    let entry = (action & 0xF)
        | ((cpu & 0xF) << 4)
        | (((chunk_idx as u64) & 0xFFFF) << 8)
        | (((page_idx as u64) & 0xFF) << 24)
        | (ts << 32);
    let i = PHYS_EVT_POS.fetch_add(1, Ordering::Relaxed) as usize % PHYS_EVT_RING;
    PHYS_EVT[i].store(entry, Ordering::Relaxed);
}

/// Dump every event recorded in the ring that matches `target_chunk`.
/// Called from scheduler at PA-ALIAS detection time.
pub fn dump_evt_ring_for_chunk(target_chunk: usize) {
    let head = PHYS_EVT_POS.load(Ordering::Relaxed);
    let start = head.saturating_sub(PHYS_EVT_RING as u64);
    let mut hits = 0u32;
    crate::println!(
        "PHYS-EVT-DUMP-BEGIN: chunk={} head={} window=[{}..{})",
        target_chunk, head, start, head
    );
    for seq in start..head {
        let i = (seq as usize) % PHYS_EVT_RING;
        let e = PHYS_EVT[i].load(Ordering::Relaxed);
        if e == 0 { continue; }
        let chunk_idx = ((e >> 8) & 0xFFFF) as usize;
        if chunk_idx != target_chunk { continue; }
        let action = e & 0xF;
        let cpu = (e >> 4) & 0xF;
        let page_idx = (e >> 24) & 0xFF;
        let ts = (e >> 32) & 0xFFFFFFFF;
        crate::println!(
            "PHYS-EVT: seq={} action={} cpu={} chunk={} page={} ts={}",
            seq, action, cpu, chunk_idx, page_idx, ts
        );
        hits += 1;
    }
    crate::println!(
        "PHYS-EVT-DUMP-END: chunk={} hits={}",
        target_chunk, hits
    );
}

// ── #228 double-issue detector ───────────────────────────────────────
//
// An INDEPENDENT global shadow bitmap that records which physical pages
// are currently handed out to a caller.  It is deliberately separate
// from the allocator's own per-chunk state: the whole point is to catch
// the allocator's accounting being wrong (handing out a page it still
// believes is owned by a previous caller).
//
// Marked only at the public alloc/free boundary so that internal
// per-CPU reservation churn (claiming/releasing whole chunks, bitmap
// materialization) does NOT touch the shadow — only actual caller
// handout (alloc_page/alloc_pages return) and return (free_page/
// free_pages entry) flip a bit here.
//
// Sized for up to 8 GiB of RAM at 4 KiB pages.  256 KiB of static .bss.

/// Master switch — set false to compile the detector out to no-ops.
/// Default OFF: the 2026-06-16 A/B (0 fires / 11 boots incl. heavy host-desched
/// stress) ruled out the single-page double-issue as the #208 Phase-5 wild-RIP
/// cause.  Kept as an opt-in regression guard; flip true to re-arm.
const DOUBLE_ISSUE_DETECT: bool = false;

/// Shadow covers up to this many pages (8 GiB / 4 KiB).
const DI_SHADOW_PAGES: usize = 1 << 21; // 2,097,152
static DI_SHADOW: [AtomicU64; DI_SHADOW_PAGES / 64] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; DI_SHADOW_PAGES / 64]
};

/// Page index into the shadow bitmap for a physical address, or None if
/// the PA is below RAM start or beyond the shadow's coverage (skip safely).
#[inline]
fn di_page_index(pa: usize) -> Option<usize> {
    let base = ALLOC.base;
    if pa < base {
        return None;
    }
    let idx = (pa - base) >> page::page_shift();
    if idx >= DI_SHADOW_PAGES {
        return None;
    }
    Some(idx)
}

/// Mark one page as handed-out.  If the bit was already set, the
/// allocator just gave the same page to two callers — a double-issue.
#[inline]
fn di_mark_alloc(pa: usize) {
    if !DOUBLE_ISSUE_DETECT {
        return;
    }
    let idx = match di_page_index(pa) {
        Some(i) => i,
        None => return,
    };
    let word = idx >> 6;
    let mask = 1u64 << (idx & 63);
    let prev = DI_SHADOW[word].fetch_or(mask, Ordering::Relaxed);
    if prev & mask != 0 {
        crate::println!(
            "PHYS-DOUBLE-ISSUE: pa={:#x} idx={} cpu={} — page handed out while still owned",
            pa,
            idx,
            smp::cpu_id(),
        );
        dump_evt_ring_for_chunk(idx / CHUNK_PAGES);
    }
}

/// Mark one page as returned (no longer handed-out).  The allocator
/// already logs double-frees, so a clear-of-already-clear is silent here.
#[inline]
fn di_mark_free(pa: usize) {
    if !DOUBLE_ISSUE_DETECT {
        return;
    }
    let idx = match di_page_index(pa) {
        Some(i) => i,
        None => return,
    };
    let word = idx >> 6;
    let mask = 1u64 << (idx & 63);
    DI_SHADOW[word].fetch_and(!mask, Ordering::Relaxed);
}

/// Pages per chunk — matches one u64 bitmap.
const CHUNK_PAGES: usize = 64;
const CHUNK_SHIFT: usize = 6;

/// Inline threshold: chunks with ≤ INLINE_K free pages encode indices
/// directly in the node, avoiding a bitmap page. 6 × 6 bits = 36 bits.
const INLINE_K: u32 = 6;

/// Sentinel values.
const NO_CPU: u32 = 0x7F;
const NO_CHUNK: usize = usize::MAX;

use crate::sched::smp;

// ── ChunkNode ────────────────────────────────────────────────────────

/// Packed state for one 64-page chunk, stored in a single AtomicU64.
///
/// Layout (64 bits):
///   [6:0]   free_count   (0..64; 64 = all-free, special-cased)
///   [13:7]  owner_cpu    (0..126 = CPU, 0x7F = unowned)
///   [14]    has_bitmap   (1 = bitmap page materialized)
///   [20:15] bitmap_page  (index within chunk when has_bitmap=1)
///   [63:21] inline_data  (when has_bitmap=0 and free_count in 1..=INLINE_K:
///                          6 indices packed as 6 bits each, low-to-high)
///
/// When free_count=0: chunk fully allocated, no metadata.
/// When free_count=64: chunk fully free, no metadata needed.
/// When has_bitmap=1: a free page at index `bitmap_page` within the chunk
///   holds a u64 bitmap (bit set = page free, bit clear = allocated).
///   The bitmap page itself has its bit CLEAR (it's reserved for metadata).
/// When has_bitmap=0 and 1<=free_count<=INLINE_K: the free page indices
///   are encoded directly in inline_data.
struct ChunkNode {
    state: AtomicU64,
}

// Bit-field accessors.
const FREE_COUNT_MASK: u64 = 0x7F; // bits [6:0]
const OWNER_SHIFT: u32 = 7;
const OWNER_MASK: u64 = 0x7F << 7; // bits [13:7]  (7 bits → 0..126 + sentinel)
const HAS_BITMAP_BIT: u64 = 1 << 14; // bit [14]
const BMP_PAGE_SHIFT: u32 = 15;
const BMP_PAGE_MASK: u64 = 0x3F << 15; // bits [20:15]
const INLINE_SHIFT: u32 = 21;
// #228 inline→bitmap mode-switch lock.  Set by the WINNER of the
// fc==64 → bitmap-mode transition CAS; cleared in the same writer
// when it CASes to the final state.  Other CPUs that observe this
// bit set in `s` must NOT enter the fc==64 path or read the
// bitmap — they treat the chunk as "skip for now" (return None /
// continue to next chunk).  Without this lock, a loser's
// unconditional `write_bitmap(target)` could land after the winner's
// CAS and after a third CPU's `cas_bitmap` modification, clobbering
// that modification and producing single-page double-issue.  Proven
// by `tests/loom-phys-chunk` mode_switch_tests::buggy_fc64_race
// (FAILS) vs fixed_fc64_race (PASS, 3-thread exhaustive in 15.65s).
const STATE_TRANSITIONING_BIT: u64 = 1u64 << 63;
// Each inline index is 6 bits, starting at bit 18.
const INLINE_IDX_BITS: u32 = 6;
const INLINE_IDX_MASK: u64 = 0x3F;

impl ChunkNode {
    #[allow(dead_code)]
    const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
        }
    }

    #[inline]
    fn load(&self) -> u64 {
        self.state.load(Ordering::Acquire)
    }

    #[inline]
    fn cas(&self, old: u64, new: u64) -> Result<u64, u64> {
        self.state
            .compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire)
    }

    fn store(&self, val: u64) {
        self.state.store(val, Ordering::Release);
    }
}

#[inline]
fn free_count(s: u64) -> u32 {
    (s & FREE_COUNT_MASK) as u32
}

#[inline]
fn owner(s: u64) -> u32 {
    ((s & OWNER_MASK) >> OWNER_SHIFT) as u32
}

#[inline]
fn has_bitmap(s: u64) -> bool {
    s & HAS_BITMAP_BIT != 0
}

#[inline]
fn bmp_page(s: u64) -> u32 {
    ((s & BMP_PAGE_MASK) >> BMP_PAGE_SHIFT) as u32
}

/// Get the i-th inline index (0-based) from packed state.
#[inline]
fn inline_idx(s: u64, i: u32) -> u32 {
    ((s >> (INLINE_SHIFT + i * INLINE_IDX_BITS)) & INLINE_IDX_MASK) as u32
}

/// Build a state word.
#[inline]
fn make_state(fc: u32, own: u32, has_bmp: bool, bmp_pg: u32, inline_bits: u64) -> u64 {
    (fc as u64 & FREE_COUNT_MASK)
        | ((own as u64) << OWNER_SHIFT)
        | (if has_bmp { HAS_BITMAP_BIT } else { 0 })
        | ((bmp_pg as u64) << BMP_PAGE_SHIFT)
        | (inline_bits << INLINE_SHIFT)
}

/// Pack up to INLINE_K indices into the inline_bits portion.
fn pack_inline(indices: &[u32]) -> u64 {
    let mut bits: u64 = 0;
    for (i, &idx) in indices.iter().enumerate().take(INLINE_K as usize) {
        bits |= (idx as u64 & INLINE_IDX_MASK) << (i as u32 * INLINE_IDX_BITS);
    }
    bits
}

// ── In-band bitmap access ────────────────────────────────────────────

/// Read the in-band bitmap from a free page. The bitmap is stored as a
/// raw u64 at byte offset 0 of the physical page (identity-mapped).
///
/// Safety: `pa` must be a valid, identity-mapped physical address of a
/// free page that is currently serving as a bitmap page.
unsafe fn read_bitmap(pa: usize) -> u64 {
    unsafe {
        let ptr = crate::mm::page::phys_to_kva(pa) as *const AtomicU64;
        (*ptr).load(Ordering::Acquire)
    }
}

unsafe fn write_bitmap(pa: usize, val: u64) {
    unsafe {
        let ptr = crate::mm::page::phys_to_kva(pa) as *const AtomicU64;
        (*ptr).store(val, Ordering::Release);
    }
}

unsafe fn cas_bitmap(pa: usize, old: u64, new: u64) -> Result<u64, u64> {
    unsafe {
        let ptr = crate::mm::page::phys_to_kva(pa) as *const AtomicU64;
        (*ptr).compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire)
    }
}

// ── Per-CPU reservations ─────────────────────────────────────────────

/// Per-CPU reservation: the chunk index this CPU "owns" for fast allocation.
/// Accessed only by the owning CPU (with IRQs disabled in the allocator path),
/// so no atomics needed. Stored as usize for alignment; NO_CHUNK = no reservation.
///
/// Tier-1 bootstrap: a single-slot static used by the BSP from the moment
/// `phys::init` first calls into the allocator until `init_dynamic_percpu`
/// installs the real per-CPU slice. Necessary because `alloc_static_slice`
/// itself runs through the allocator, which reads CPU_RESERVATION on the
/// fast path. Once swapped, the bootstrap slot is never read again.
static mut CPU_RESERVATION_BOOT: usize = NO_CHUNK;

/// Pointer to the per-CPU reservation array. Initially aliases the
/// Tier-1 bootstrap slot; `init_dynamic_percpu` swaps it for a fully
/// sized dynamic slice (after copying the bootstrap value into slot 0).
static CPU_RESERVATION_PTR: AtomicPtr<usize> =
    AtomicPtr::new(&raw mut CPU_RESERVATION_BOOT);

#[inline]
fn cpu_reservation_at(cpu: usize) -> *mut usize {
    let base = CPU_RESERVATION_PTR.load(Ordering::Relaxed);
    debug_assert!(!base.is_null());
    unsafe { base.add(cpu) }
}

#[inline]
fn my_cpu() -> usize {
    crate::sched::smp::cpu_id() as usize
}

/// Allocate and install the dynamic per-CPU reservation slice. Called from
/// `smp::init_dynamic_percpu` after `phys::init`. Copies the BSP's existing
/// bootstrap reservation into slot 0 of the new slice before publishing.
pub(crate) fn init_dynamic_percpu() {
    let n = smp::num_cpus();
    unsafe {
        let s = alloc_static_slice::<usize>(n);
        for slot in s.iter_mut() {
            *slot = NO_CHUNK;
        }
        s[0] = CPU_RESERVATION_BOOT;
        CPU_RESERVATION_PTR.store(s.as_mut_ptr(), Ordering::Release);
    }
}

// ── Allocator ────────────────────────────────────────────────────────

struct LLFreeAllocator {
    base: usize,
    total_pages: usize,
    total_chunks: usize,
    free_count_global: AtomicUsize,
    /// Pointer to boot-time-carved chunk array. Null until init().
    chunks: *mut ChunkNode,
}

// Safety: chunks pointer is set once at boot (single-threaded) and then only read.
// ChunkNode uses AtomicU64 internally, so concurrent access is safe.
unsafe impl Sync for LLFreeAllocator {}
unsafe impl Send for LLFreeAllocator {}

impl LLFreeAllocator {
    const fn new() -> Self {
        Self {
            base: 0,
            total_pages: 0,
            total_chunks: 0,
            free_count_global: AtomicUsize::new(0),
            chunks: core::ptr::null_mut(),
        }
    }

    /// Access chunk node by index.
    #[inline]
    fn chunk(&self, idx: usize) -> &ChunkNode {
        unsafe { &*self.chunks.add(idx) }
    }
}

static ALLOC: LLFreeAllocator = LLFreeAllocator::new();

/// Bulk lock for multi-page allocation (rare path).
use crate::sync::SpinLock;
static BULK_LOCK: SpinLock<()> = SpinLock::new(());

/// #155 atomicity probe: count of times the alloc_pages bitmap-mode
/// chunk-state CAS lost a race against a concurrent chunk_free_one /
/// chunk_alloc_one and had to fall through to the retry-loop fc-dec.
/// Each fallback used to leak the alloc accounting (`let _ = cas(...)`
/// + unconditional `fetch_sub`) → `free_count_global` undercount by 1
/// per fallback (boot 99amfsq544 surfaced this as drift=-1).  Now the
/// retry loop atomically applies the fc decrement so global and
/// sum_fc remain consistent.
static BITMAP_ALLOC_STATE_CAS_FALLBACKS: AtomicU64 = AtomicU64::new(0);
/// #155 sanity counter: increments when the retry-loop sees `cur_fc <
/// allocated` — should not happen if the chunk was consistent at our
/// bitmap-CAS time.  Non-zero here means deeper allocator state
/// corruption still exists.
static BITMAP_ALLOC_STATE_CAS_SANITY_FAILS: AtomicU64 = AtomicU64::new(0);

pub fn bitmap_alloc_state_cas_counts() -> (u64, u64) {
    (
        BITMAP_ALLOC_STATE_CAS_FALLBACKS.load(Ordering::Relaxed),
        BITMAP_ALLOC_STATE_CAS_SANITY_FAILS.load(Ordering::Relaxed),
    )
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Physical address of page `page_idx` within chunk `chunk_idx`.
#[inline]
fn page_pa(chunk_idx: usize, page_idx: u32) -> usize {
    ALLOC.base + ((chunk_idx * CHUNK_PAGES + page_idx as usize) << page::page_shift())
}

/// Physical address of the bitmap page for a chunk.
#[inline]
fn bitmap_pa(chunk_idx: usize, bmp_pg: u32) -> usize {
    page_pa(chunk_idx, bmp_pg)
}

/// Convert a physical address to (chunk_idx, page_idx).
#[inline]
fn addr_to_chunk_page(pa: usize) -> (usize, u32) {
    let pfn = (pa - ALLOC.base) >> page::page_shift();
    (pfn >> CHUNK_SHIFT, (pfn & (CHUNK_PAGES - 1)) as u32)
}

// ── Allocation from a specific chunk ─────────────────────────────────

/// Try to allocate one page from a chunk. Returns Some(page_idx) on success.
fn chunk_alloc_one(chunk_idx: usize) -> Option<u32> {
    let node = ALLOC.chunk(chunk_idx);

    loop {
        let s = node.load();
        let fc = free_count(s);
        if fc == 0 {
            return None;
        }

        // #228 mode-switch lock: another CPU is mid-transition from
        // inline (fc==64) to bitmap mode.  Skip this chunk — caller
        // will scan onward and the winner's final CAS will publish
        // the new state for subsequent allocs.
        if s & STATE_TRANSITIONING_BIT != 0 {
            return None;
        }

        if fc == 64 {
            // All-free chunk. Transition: pick page 0 as bitmap page,
            // write bitmap with all bits set except bit 0, allocate page 1.
            //
            // #228 fix: do this under a TRANSITIONING marker.  Two-step
            // CAS pattern serializes the bitmap initialization so that
            // (a) only the winner ever writes the bitmap, and (b) no
            // other CPU sees has_bitmap=true while the bitmap content
            // is still being written.  Without this, a CAS-loser's
            // unconditional `write_bitmap(target)` could land AFTER a
            // separate CPU's `cas_bitmap` modification in the bitmap-
            // mode path, clobbering it and producing single-page
            // double-issue.  See [[project_228_chunk_alloc_one_race]]
            // and `tests/loom-phys-chunk` mode_switch_tests.
            let trans_s = s | STATE_TRANSITIONING_BIT;
            match node.cas(s, trans_s) {
                Err(_) => continue,
                Ok(_) => {}
            }
            // Winner.  Bitmap is exclusively ours until the final CAS.
            let bmp_pa = bitmap_pa(chunk_idx, 0);
            // bitmap: all free except page 0 (bitmap) and page 1 (allocated).
            let bmp: u64 = !0u64 & !1u64 & !(1u64 << 1);
            unsafe {
                write_bitmap(bmp_pa, bmp);
            }
            // New state: fc=62, has_bitmap=true, bmp_page=0, owner
            // preserved, TRANSITIONING cleared.  Only THIS thread can
            // clear TRANSITIONING, but other writers (e.g. the alloc_page
            // reservation-clear loop) may CAS the owner field
            // concurrently.  Loop to re-derive the final state if a
            // concurrent writer changes the owner, and also to absorb
            // compare_exchange_weak's spurious failures.
            loop {
                let cur = node.load();
                if cur & STATE_TRANSITIONING_BIT == 0 {
                    // Someone else cleared TRANSITIONING — impossible
                    // under the protocol; bail.
                    crate::println!(
                        "[#228] chunk_alloc_one fc64: TRANSITIONING cleared by other writer (cur={:#x})",
                        cur,
                    );
                    return None;
                }
                let new_s = make_state(62, owner(cur), true, 0, 0);
                if node.cas(cur, new_s).is_ok() {
                    break;
                }
            }
            ALLOC.free_count_global.fetch_sub(2, Ordering::Relaxed); // bitmap page + allocated page
            return Some(1);
        }

        if has_bitmap(s) {
            // Bitmap mode: read the in-band bitmap and pick a free page.
            let bp = bmp_page(s);
            let bpa = bitmap_pa(chunk_idx, bp);

            let bmp = unsafe { read_bitmap(bpa) };
            if bmp == 0 {
                // Bitmap says nothing free (inconsistency, or bitmap page is the only "free" page).
                return None;
            }

            // Find lowest set bit.
            let bit = bmp.trailing_zeros();
            let new_bmp = bmp & !(1u64 << bit);

            // CAS the bitmap.
            unsafe {
                match cas_bitmap(bpa, bmp, new_bmp) {
                    Ok(_) => {}
                    Err(_) => continue,
                }
            }

            let new_fc = fc - 1;

            // Check if we should transition to inline mode.
            //
            // #155 transition accounting fix: the transition has two
            // shapes whose fc/global accounting differs.  Tracked via
            // `transition_with_bp` so the post-transition fc/global
            // updates are correct in each case.
            //
            //   * With-bp (new_fc < INLINE_K): count = new_fc + 1
            //     = old_fc.  Inline indices = surviving bitmap bits + bp.
            //     bp was metadata (not in fc, not in global); now in fc.
            //     Net effect of alloc + transition: chunk fc unchanged,
            //     global unchanged — the alloc and the bp reclassification
            //     cancel.
            //
            //   * No-bp (new_fc == INLINE_K): count = new_fc.  bp is
            //     dropped from inline indices (permanent leak — accepted
            //     trade-off).  Net effect: chunk fc -= 1, global -= 1.
            //
            // Previously the code unconditionally ran a separate fc-dec
            // loop and a fetch_sub(1), which double-decremented in the
            // no-bp case (chunk fc -= 2 but global -= 1, leaving global
            // +1 above sum_fc per transition).  The reconciliation probe
            // observed exactly this drift growing by ~110 over an early-
            // boot window in 91amfsq40.
            //
            // Transition condition: require room for bp.  Without bp, the
            // bp page is permanently leaked from the chunk's tracking
            // (and physically from the free pool).  Boot 41 reached
            // free=18 with my prior fix because no-bp transitions were
            // still consuming bp pages.  By only transitioning when bp
            // fits, chunks stay in bitmap mode at fc==INLINE_K and bp
            // remains as metadata — no leak.
            let mut transitioned = false;
            if new_fc < INLINE_K && new_fc > 0 {
                let remaining_bmp = new_bmp;
                let mut indices = [0u32; INLINE_K as usize];
                let mut count = 0u32;
                let mut b = remaining_bmp;
                while b != 0 && count < INLINE_K - 1 {
                    let idx = b.trailing_zeros();
                    indices[count as usize] = idx;
                    b &= !(1u64 << idx);
                    count += 1;
                }
                // bp always fits because new_fc < INLINE_K → count ≤ new_fc < INLINE_K.
                indices[count as usize] = bp;
                count += 1;

                let inline_bits = pack_inline(&indices[..count as usize]);
                let new_s = make_state(count, owner(s), false, 0, inline_bits);
                // Best-effort CAS. If it fails, the bitmap is still valid
                // and the fall-through fc dec loop handles the alloc.
                if node.cas(
                    (s & !(FREE_COUNT_MASK)) | (fc as u64),
                    new_s,
                ).is_ok() {
                    transitioned = true;
                }
            }

            if !transitioned {
                // Still in bitmap mode (no transition condition or CAS
                // lost).  Decrement fc to reflect the alloc.
                loop {
                    let cur = node.load();
                    let cur_fc = free_count(cur);
                    if cur_fc == 0 {
                        break;
                    }
                    let upd = (cur & !FREE_COUNT_MASK) | ((cur_fc - 1) as u64);
                    if node.cas(cur, upd).is_ok() {
                        break;
                    }
                }
                ALLOC.free_count_global.fetch_sub(1, Ordering::Relaxed);
            } else {
                // Transitioned with bp.  count = new_fc + 1 = old_fc.
                // Inline indices = (new_fc bitmap survivors) + bp.  fc=count.
                // The alloc decrement and bp reclassification (metadata→fc-
                // tracked) cancel out.  Net 0 change to chunk fc or global.
            }
            return Some(bit);
        }

        // Inline mode: free_count in 1..=INLINE_K, indices packed in state.
        if fc > INLINE_K {
            // Shouldn't happen — fc > INLINE_K without bitmap.
            // This would mean a bug. Treat as empty.
            return None;
        }

        // Pick the first inline index.
        let alloc_idx = inline_idx(s, 0);

        // Rebuild inline data without the first index.
        let new_fc = fc - 1;
        let mut new_inline: u64 = 0;
        for i in 1..fc {
            let idx = inline_idx(s, i);
            new_inline |= (idx as u64 & INLINE_IDX_MASK) << ((i - 1) * INLINE_IDX_BITS as u32);
        }
        let new_s = make_state(new_fc, owner(s), false, 0, new_inline);
        match node.cas(s, new_s) {
            Ok(_) => {
                ALLOC.free_count_global.fetch_sub(1, Ordering::Relaxed);
                return Some(alloc_idx);
            }
            Err(_) => continue,
        }
    }
}

// ── Free into a specific chunk ───────────────────────────────────────

fn chunk_free_one(chunk_idx: usize, page_idx: u32) {
    let node = ALLOC.chunk(chunk_idx);

    loop {
        let s = node.load();
        let fc = free_count(s);

        // #155 explicit fc==64 (already all-free) handler.  Without
        // this, the outer loop falls through to the inline-to-bitmap
        // transition code at the bottom which is undefined behavior for
        // fc==64 (assumes fc==INLINE_K).  This path most commonly fires
        // when two CPUs race on the 63→64 all-free transition: CPU A
        // wins the CAS to fc=64, CPU B retries, sees fc=64, and the
        // garbage path corrupts chunk state.  Treat as a no-op
        // double-free: the page is already in the free pool.
        if fc == 64 {
            crate::println!(
                "[phys::free] DOUBLE-FREE (all-free chunk): chunk={} page_idx={} pa={:#x}",
                chunk_idx, page_idx, page_pa(chunk_idx, page_idx),
            );
            return;
        }

        if fc == 0 {
            // First free into a fully-allocated chunk.
            // The freed page becomes an inline entry (fc=1, inline mode).
            let inline_bits = page_idx as u64 & INLINE_IDX_MASK;
            let new_s = make_state(1, owner(s), false, 0, inline_bits);
            match node.cas(s, new_s) {
                Ok(_) => {
                    ALLOC.free_count_global.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(_) => continue,
            }
        }

        if fc == 63 {
            // Was 63 free, now becomes 64 = all-free.
            // If has_bitmap, the bitmap page also becomes free.
            // Transition to all-free state.
            //
            // #155 root-cause fix: VERIFY that page_idx was actually
            // allocated (its bit is CLEAR in the bitmap).  Otherwise this
            // is a double-free, and we must NOT add to global free count.
            // Boot 33 STRESSED observed free_count_global drift to 127
            // with no actual free pages — explained by repeated +2
            // increments here without the page actually being allocated.
            if has_bitmap(s) {
                let bp = bmp_page(s);
                let bpa = bitmap_pa(chunk_idx, bp);
                let bmp = unsafe { read_bitmap(bpa) };
                if (bmp >> page_idx) & 1 != 0 {
                    // page_idx is already free in bitmap — double-free.
                    crate::println!(
                        "[phys::free] DOUBLE-FREE (fc=63, bit-already-set): chunk={} page_idx={} pa={:#x}",
                        chunk_idx, page_idx, page_pa(chunk_idx, page_idx),
                    );
                    return;
                }
            }
            let new_s = make_state(64, owner(s), false, 0, 0);
            match node.cas(s, new_s) {
                Ok(_) => {
                    if has_bitmap(s) {
                        // Bitmap page is released too. Account for +2 (freed page + bitmap page).
                        ALLOC.free_count_global.fetch_add(2, Ordering::Relaxed);
                    } else {
                        ALLOC.free_count_global.fetch_add(1, Ordering::Relaxed);
                    }
                    return;
                }
                Err(_) => continue,
            }
        }

        if has_bitmap(s) {
            // Set the freed page's bit in the bitmap.
            let bp = bmp_page(s);
            let bpa = bitmap_pa(chunk_idx, bp);
            // #155 root-cause fix: distinguish double-free (bit already
            // set) from successful CAS.  Boot 33 STRESSED captured the
            // bug — the prior code incremented fc + free_count_global
            // even when the bit was already set, phantom-adding ~63
            // pages to the global counter over the boot, eventually
            // producing `[alloc_page] FAIL despite free=127
            // tried_with_free=1`.  Double-frees should be a no-op.
            let mut was_double_free = false;
            loop {
                let bmp = unsafe { read_bitmap(bpa) };
                let new_bmp = bmp | (1u64 << page_idx);
                if new_bmp == bmp {
                    was_double_free = true;
                    break;
                }
                unsafe {
                    match cas_bitmap(bpa, bmp, new_bmp) {
                        Ok(_) => break,
                        Err(_) => continue,
                    }
                }
            }
            if was_double_free {
                crate::println!(
                    "[phys::free] DOUBLE-FREE detected: chunk={} page_idx={} pa={:#x}",
                    chunk_idx, page_idx, page_pa(chunk_idx, page_idx),
                );
                return;
            }

            // Increment free_count.
            //
            // #155: cap at 63 in bitmap mode (one bit always reserved
            // for bmp_page).  Without the cap, concurrent frees that
            // race past the fc==63 transition can push fc to 64+ here
            // without transitioning out of bitmap mode, then keep
            // incrementing on each subsequent free up to 127 (the 7-bit
            // field max).  This is the "free_count_global drifts to 127"
            // mechanism observed in boots 33-36.
            let mut bumped = false;
            loop {
                let cur = node.load();
                let cur_fc = free_count(cur);
                if cur_fc >= 63 {
                    // Chunk is at-cap in bitmap mode.  The bitmap CAS
                    // above already recorded our page as free, so don't
                    // bump fc OR global — both would over-count.  This
                    // is a race-narrow recovery: the chunk should
                    // transition to fc==64 (all-free, no bitmap) via the
                    // fc==63 branch on a future free, but a concurrent
                    // racer beat us through 63 already.
                    crate::println!(
                        "[phys::free] OVER-FREE (bitmap fc>=63, page bit set ok): chunk={} page_idx={} pa={:#x}",
                        chunk_idx, page_idx, page_pa(chunk_idx, page_idx),
                    );
                    break;
                }
                let upd = (cur & !FREE_COUNT_MASK) | ((cur_fc + 1) as u64);
                if node.cas(cur, upd).is_ok() {
                    bumped = true;
                    break;
                }
            }

            if bumped {
                ALLOC.free_count_global.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }

        // Inline mode: fc in 1..=INLINE_K legitimately.
        //
        // #155 inline-mode double-free check: if page_idx is already among
        // the inline indices, this is a double-free.  Without this check,
        // the add-or-transition paths below would append/encode page_idx
        // a second time and bump free_count_global, drifting it above the
        // true free count.  Boot 33-36 STRESSED observed exactly this
        // drift (free=127, tried_with_free=1) with no DOUBLE-FREE lines
        // from the bitmap-mode / fc==63 / fc==64 checks.
        //
        // Clamp scan to INLINE_K — if fc > INLINE_K (corrupted state),
        // positions past INLINE_K read into the OWNER/has_bitmap/bmp_page
        // bits via inline_idx, which can false-positive against page_idx.
        let scan_fc = fc.min(INLINE_K);
        for i in 0..scan_fc {
            if inline_idx(s, i) == page_idx {
                crate::println!(
                    "[phys::free] DOUBLE-FREE (inline, fc={}, slot={}): chunk={} page_idx={} pa={:#x}",
                    fc, i, chunk_idx, page_idx, page_pa(chunk_idx, page_idx),
                );
                return;
            }
        }
        if fc > INLINE_K {
            // Corrupted: inline mode with fc > INLINE_K should be impossible
            // (chunk_free_one transitions to bitmap at fc==INLINE_K).  Bail
            // out rather than feed the corruption.
            crate::println!(
                "[phys::free] CORRUPT inline-mode fc={} > INLINE_K={}: chunk={} page_idx={}",
                fc, INLINE_K, chunk_idx, page_idx,
            );
            return;
        }

        if fc < INLINE_K {
            // Room to add another inline index.
            // Append page_idx at position fc.
            let extra = (page_idx as u64 & INLINE_IDX_MASK) << (fc * INLINE_IDX_BITS as u32);
            let old_inline = s >> INLINE_SHIFT;
            let new_inline = old_inline | extra;
            let new_s = make_state(fc + 1, owner(s), false, 0, new_inline);
            match node.cas(s, new_s) {
                Ok(_) => {
                    ALLOC.free_count_global.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(_) => continue,
            }
        }

        // fc == INLINE_K: must transition to bitmap mode.
        // Pick page_idx (the one being freed) as the bitmap page.
        // Collect existing inline indices + page_idx into a bitmap.
        // (Double-free against existing inline indices already filtered
        // above, so we know page_idx is NOT among indices[0..fc].)
        //
        // #228 fix: use the TRANSITIONING-bit lock so concurrent
        // chunk_free_one calls (each potentially choosing a different
        // page_idx as bmp_pg) don't both write_bitmap to their own
        // page_idx and then race on the state CAS — the loser's stale
        // write_bitmap would clobber a future consumer's data after
        // page_idx becomes a regular data page.  Same pattern as the
        // chunk_alloc_one and alloc_pages_inner fc==64 fixes
        // (93be952 / 77cde8e); proof in
        // `tests/loom-phys-chunk` mode_switch_tests.
        let trans_s = s | STATE_TRANSITIONING_BIT;
        match node.cas(s, trans_s) {
            Err(_) => continue,
            Ok(_) => {}
        }
        // Winner.  Bitmap write is exclusively ours until the final CAS.
        let mut bmp: u64 = 0;
        for i in 0..fc {
            bmp |= 1u64 << inline_idx(trans_s, i);
        }
        // page_idx is the bitmap page; its bit is CLEAR (reserved).
        // The existing inline pages are free; their bits are SET.

        let bpa = page_pa(chunk_idx, page_idx);
        unsafe {
            write_bitmap(bpa, bmp);
        }

        // CAS to final state in a retry loop — only this thread can
        // clear TRANSITIONING.  Note: fc stays the same because the
        // freed page becomes the bitmap page (not counted in fc), and
        // the INLINE_K pages remain free.
        loop {
            let cur = node.load();
            if cur & STATE_TRANSITIONING_BIT == 0 {
                crate::println!(
                    "[#228] chunk_free_one INLINE_K: TRANSITIONING cleared by other writer (cur={:#x})",
                    cur,
                );
                return;
            }
            let new_s = make_state(fc, owner(cur), true, page_idx, 0);
            if node.cas(cur, new_s).is_ok() {
                break;
            }
        }
        // No change to free_count_global: the caller's freed page
        // becomes the chunk's bitmap page (metadata), so net change to
        // pages-available-to-callers is zero.
        return;
    }
}

// ── Public API ───────────────────────────────────────────────────────

/// Initialize the allocator. Called once from boot code (single-threaded).
///
/// Metadata (chunk array) is carved from the start of usable RAM at boot,
/// so there is no compile-time cap on managed memory.
pub fn init(ram_start: usize, ram_end: usize, kernel_start: usize, kernel_end: usize) {
    #[cfg(feature = "dumb_phys_alloc")]
    {
        return super::phys_dumb::init(ram_start, ram_end, kernel_start, kernel_end);
    }
    #[allow(unreachable_code)]
    let ps = page::page_size();
    let pshift = page::page_shift();
    let start = PhysAddr::new(ram_start).align_up(ps).as_usize();
    let end = PhysAddr::new(ram_end).align_down(ps).as_usize();
    if end <= start {
        return;
    }

    let total_pages = (end - start) >> pshift;
    let total_chunks = (total_pages + CHUNK_PAGES - 1) / CHUNK_PAGES;

    // Carve the chunk array from the start of usable RAM.
    let chunk_array_bytes = total_chunks * core::mem::size_of::<ChunkNode>();
    let total_metadata_bytes = chunk_array_bytes;
    let metadata_pages = (total_metadata_bytes + ps - 1) >> pshift;
    // #235 Piece C2: route chunk-metadata accesses through PHYS_DIRECT_MAP
    // so they survive the PML4[0] identity-map removal.  `start` is the
    // first usable RAM PA; `chunks` is read on every alloc/free.
    let chunk_kva = crate::mm::page::phys_to_kva(start);
    let chunk_ptr = chunk_kva as *mut ChunkNode;

    // Zero the metadata region (chunk array).
    unsafe {
        core::ptr::write_bytes(chunk_kva as *mut u8, 0, metadata_pages << pshift);
    }

    // Safety: single-threaded at boot; direct stores are fine.
    unsafe {
        let alloc = &ALLOC as *const LLFreeAllocator as *mut LLFreeAllocator;
        (*alloc).base = start;
        (*alloc).total_pages = total_pages;
        (*alloc).total_chunks = total_chunks;
        (*alloc).chunks = chunk_ptr;
    }

    // Initialize chunks as all-free.
    for ci in 0..total_chunks {
        let pages_in_chunk = if (ci + 1) * CHUNK_PAGES <= total_pages {
            64u32
        } else {
            (total_pages - ci * CHUNK_PAGES) as u32
        };
        // All-free: fc = pages_in_chunk, no owner, no bitmap.
        ALLOC
            .chunk(ci)
            .store(make_state(pages_in_chunk, NO_CPU, false, 0, 0));
    }

    let mut total_free = total_pages;

    // Reserve metadata pages (chunk array carved from start of RAM).
    let meta_end_pfn = metadata_pages;

    // Reserve kernel pages.
    let _kern_start_pfn = if kernel_start <= start {
        0
    } else {
        (kernel_start - start) >> pshift
    };
    let kern_end_pfn = if kernel_end <= start {
        0
    } else {
        ((kernel_end - start + ps - 1) >> pshift).min(total_pages)
    };

    // Merge metadata and kernel reservations into a single range
    // (metadata is at the start; kernel may overlap or follow).
    let reserve_start = 0;
    let reserve_end = kern_end_pfn.max(meta_end_pfn);

    // Mark reserved pages (metadata + kernel) as allocated, chunk by chunk.
    for pfn in reserve_start..reserve_end {
        let ci = pfn >> CHUNK_SHIFT;
        let pi = (pfn & (CHUNK_PAGES - 1)) as u32;

        let s = ALLOC.chunk(ci).load();
        let fc = free_count(s);

        if fc == 64 {
            // Transition from all-free. Build a bitmap with all bits set
            // except the reserved page, using page 0 (or the first non-reserved
            // page) as the bitmap page.
            let bmp_pg = if pi == 0 { 1 } else { 0 };
            let mut bmp: u64 = !0u64; // all free
            bmp &= !(1u64 << pi); // mark reserved page allocated
            bmp &= !(1u64 << bmp_pg); // bitmap page not available

            let pages_in_chunk = if (ci + 1) * CHUNK_PAGES <= total_pages {
                64u32
            } else {
                (total_pages - ci * CHUNK_PAGES) as u32
            };

            // Clear bits beyond valid page count.
            if pages_in_chunk < 64 {
                bmp &= (1u64 << pages_in_chunk) - 1;
            }

            let bpa = page_pa(ci, bmp_pg);
            unsafe {
                write_bitmap(bpa, bmp);
            }

            let new_fc = bmp.count_ones();
            ALLOC
                .chunk(ci)
                .store(make_state(new_fc, NO_CPU, true, bmp_pg, 0));
            total_free -= (pages_in_chunk - new_fc) as usize; // reserved page + bitmap page
        } else if has_bitmap(s) {
            // Already has a bitmap; clear the bit for this page.
            let bp = bmp_page(s);
            let bpa = bitmap_pa(ci, bp);
            let bmp = unsafe { read_bitmap(bpa) };
            if bmp & (1u64 << pi) != 0 {
                unsafe {
                    write_bitmap(bpa, bmp & !(1u64 << pi));
                }
                // Decrement free_count.
                let new_fc = fc - 1;
                ALLOC
                    .chunk(ci)
                    .store(make_state(new_fc, NO_CPU, true, bp, 0));
                total_free -= 1;
            }
        }
        // If fc was already 0 or page was already marked, nothing to do.
    }

    ALLOC.free_count_global.store(total_free, Ordering::Release);

    let (total, free) = stats();
    crate::println!(
        "  Physical memory: {} pages total, {} pages free ({} KiB / {} KiB)",
        total,
        free,
        free * (page::page_size() / 1024),
        total * (page::page_size() / 1024),
    );
}

/// #228 probe: register a PA range that must never be returned by
/// alloc_page/alloc_pages.  Used by slab to pin its per-CPU magazine
/// slice — any subsequent alloc landing in that range is a phys
/// allocator double-issue (the C2h corruption signature).
static NO_REALLOC_START: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static NO_REALLOC_END: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static NO_REALLOC_LABEL: core::sync::atomic::AtomicPtr<u8> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

pub fn register_no_realloc_range(start_pa: usize, end_pa: usize, label: &'static str) {
    NO_REALLOC_LABEL.store(label.as_ptr() as *mut u8, Ordering::Relaxed);
    NO_REALLOC_END.store(end_pa, Ordering::Relaxed);
    NO_REALLOC_START.store(start_pa, Ordering::Release);
    crate::println!(
        "[#228 probe] no_realloc range registered: {} pa=[{:#x}..{:#x})",
        label, start_pa, end_pa,
    );
}

#[inline]
fn check_pa_not_reserved(pa: usize, site: &str) {
    let start = NO_REALLOC_START.load(Ordering::Acquire);
    if start == 0 {
        return;
    }
    let end = NO_REALLOC_END.load(Ordering::Relaxed);
    if pa >= start && pa < end {
        panic!(
            "[#228] phys::{} returned reserved PA {:#x} in no_realloc range [{:#x}..{:#x})",
            site, pa, start, end,
        );
    }
}

/// Allocate a single page. Returns its physical address.
pub fn alloc_page() -> Option<PhysAddr> {
    let r = alloc_page_inner();
    if let Some(ref pa) = r {
        check_pa_not_reserved(pa.as_usize(), "alloc_page");
        di_mark_alloc(pa.as_usize());
    }
    r
}

#[cfg_attr(feature = "dumb_phys_alloc", allow(unused))]
fn alloc_page_inner() -> Option<PhysAddr> {
    #[cfg(feature = "dumb_phys_alloc")]
    {
        return super::phys_dumb::alloc_page();
    }
    #[allow(unreachable_code)]
    let free = ALLOC.free_count_global.load(Ordering::Relaxed);
    if free == 0 {
        return None;
    }
    // Wake kswapd if memory is getting low.
    if free < ALLOC.total_pages >> super::kswapd::LOW_WATERMARK_SHIFT {
        super::kswapd::wake_if_needed();
    }

    let cpu = my_cpu();
    // Owner field is 7 bits — CPUs >= NO_CPU skip per-CPU reservation.
    let can_reserve = cpu < NO_CPU as usize;

    // Fast path: try the per-CPU reserved chunk.
    let reserved = if can_reserve {
        unsafe { *cpu_reservation_at(cpu) }
    } else {
        NO_CHUNK
    };
    if reserved != NO_CHUNK {
        if let Some(pi) = chunk_alloc_one(reserved) {
            let pa = page_pa(reserved, pi);
            // If chunk is now empty, release reservation.
            let s = ALLOC.chunk(reserved).load();
            if free_count(s) == 0 {
                unsafe {
                    *cpu_reservation_at(cpu) = NO_CHUNK;
                }
                // Clear owner in chunk node.
                loop {
                    let cur = ALLOC.chunk(reserved).load();
                    let new = (cur & !OWNER_MASK) | ((NO_CPU as u64) << OWNER_SHIFT);
                    if ALLOC.chunk(reserved).cas(cur, new).is_ok() {
                        break;
                    }
                }
            }
            record_evt(EVT_ALLOC1, reserved, pi);
            return Some(PhysAddr::new(pa));
        }
        // Reservation exhausted; release it.
        unsafe {
            *cpu_reservation_at(cpu) = NO_CHUNK;
        }
        loop {
            let cur = ALLOC.chunk(reserved).load();
            let new = (cur & !OWNER_MASK) | ((NO_CPU as u64) << OWNER_SHIFT);
            if ALLOC.chunk(reserved).cas(cur, new).is_ok() {
                break;
            }
        }
    }

    // Slow path: find an unowned chunk with free pages and claim it.
    for ci in 0..ALLOC.total_chunks {
        let s = ALLOC.chunk(ci).load();
        let fc = free_count(s);
        if fc == 0 {
            continue;
        }
        if owner(s) != NO_CPU {
            continue;
        } // owned by another CPU
        // #228: skip chunks under inline→bitmap transition.
        if s & STATE_TRANSITIONING_BIT != 0 {
            continue;
        }

        if !can_reserve {
            // CPU ID doesn't fit in owner field — alloc without reservation.
            if let Some(pi) = chunk_alloc_one(ci) {
                record_evt(EVT_ALLOC1, ci, pi);
                return Some(PhysAddr::new(page_pa(ci, pi)));
            }
            continue;
        }

        // Try to claim ownership.
        let new = (s & !OWNER_MASK) | ((cpu as u64) << OWNER_SHIFT);
        if ALLOC.chunk(ci).cas(s, new).is_err() {
            continue; // someone else claimed it
        }

        unsafe {
            *cpu_reservation_at(cpu) = ci;
        }

        if let Some(pi) = chunk_alloc_one(ci) {
            let pa = page_pa(ci, pi);
            // Check if exhausted.
            let s2 = ALLOC.chunk(ci).load();
            if free_count(s2) == 0 {
                unsafe {
                    *cpu_reservation_at(cpu) = NO_CHUNK;
                }
                loop {
                    let cur = ALLOC.chunk(ci).load();
                    let new = (cur & !OWNER_MASK) | ((NO_CPU as u64) << OWNER_SHIFT);
                    if ALLOC.chunk(ci).cas(cur, new).is_ok() {
                        break;
                    }
                }
            }
            record_evt(EVT_ALLOC1, ci, pi);
            return Some(PhysAddr::new(pa));
        }
    }

    // Final fallback: per-CPU reservations can hoard free pages.  When
    // free_count_global > 0 but the unowned-chunk scan above finds
    // nothing, all remaining free pages sit in other CPUs' reservations.
    // chunk_alloc_one is atomic CAS internally, so allocating from
    // another CPU's reserved chunk without disturbing the ownership
    // record is safe — at worst the owning CPU's next alloc sees one
    // fewer page and falls through to slow-path normally.  Without this
    // fallback, observed phys_free=216/6740 with alloc_task_entry FAILED
    // (boot 24): all 216 pages locked in non-current-CPU reservations.
    let mut tried_with_free = 0usize;
    for ci in 0..ALLOC.total_chunks {
        let s = ALLOC.chunk(ci).load();
        let fc = free_count(s);
        if fc == 0 {
            continue;
        }
        // #228: skip chunks under transition.  chunk_alloc_one would
        // bail with None anyway, but skipping avoids the wasted CAS.
        if s & STATE_TRANSITIONING_BIT != 0 {
            continue;
        }
        tried_with_free += 1;
        if let Some(pi) = chunk_alloc_one(ci) {
            record_evt(EVT_ALLOC1, ci, pi);
            return Some(PhysAddr::new(page_pa(ci, pi)));
        }
    }

    // #155 deep-verify fallback: per-chunk fc fields can drift OUT OF
    // SYNC with the actual bitmap state under concurrent stress (boot
    // 33: free_count_global=127 but tried_with_free=1 — impossible
    // since max 64 pages per chunk).  Bypass the cached fc and read
    // the actual bitmap page contents.  If a bitmap shows set bits
    // (free pages) despite fc==0, the fc is stale — allocate directly
    // from the bitmap and self-heal the chunk state.
    let mut healed = 0usize;
    for ci in 0..ALLOC.total_chunks {
        let s = ALLOC.chunk(ci).load();
        if !has_bitmap(s) {
            // Inline mode — already covered by the fc>0 scan above.
            // No drift mechanism for inline state worth a separate scan.
            continue;
        }
        let bp = bmp_page(s);
        let bpa = bitmap_pa(ci, bp);
        let bmp = unsafe { read_bitmap(bpa) };
        if bmp == 0 {
            continue; // bitmap truly empty
        }
        // Found a chunk with bits set in bitmap.  Try to claim one bit
        // via CAS on the bitmap itself, ignoring fc.
        loop {
            let cur_bmp = unsafe { read_bitmap(bpa) };
            if cur_bmp == 0 { break; }
            let bit = cur_bmp.trailing_zeros();
            let new_bmp = cur_bmp & !(1u64 << bit);
            unsafe {
                match cas_bitmap(bpa, cur_bmp, new_bmp) {
                    Ok(_) => {
                        // Successfully allocated.  We don't update the
                        // chunk's fc here — it's already drifted; let
                        // chunk_free_one / chunk_alloc_one self-correct
                        // on subsequent operations.  Don't touch
                        // free_count_global either — it's also drifted,
                        // and decrementing here would compound the
                        // problem.
                        healed += 1;
                        return Some(PhysAddr::new(page_pa(ci, bit)));
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    // Diagnostic: we found `free_count_global > 0` (the early-exit at
    // line 695 would have returned None otherwise) but no chunk yielded
    // a page even via deep-verify.  Either the global counter is
    // racing ahead of per-chunk counters AND bitmaps, or chunks are
    // entirely empty (global counter is lying).
    crate::println!(
        "[alloc_page] FAIL despite free={} (total_chunks={}, tried_with_free={}, healed={})",
        free, ALLOC.total_chunks, tried_with_free, healed,
    );
    None
}

/// Free a single page.
pub fn free_page(addr: PhysAddr) {
    #[cfg(feature = "dumb_phys_alloc")]
    {
        return super::phys_dumb::free_page(addr);
    }
    #[allow(unreachable_code)]
    let pa = addr.as_usize();
    if pa < ALLOC.base {
        return;
    }
    let (ci, pi) = addr_to_chunk_page(pa);
    if ci >= ALLOC.total_chunks {
        return;
    }
    // #228: page is being returned to the allocator — clear its shadow
    // bit at the public boundary, before internal accounting runs.
    di_mark_free(pa);
    record_evt(EVT_FREE1, ci, pi);
    chunk_free_one(ci, pi);
}

/// Allocate 2^order contiguous pages. Returns physical address.
/// For order=0, delegates to alloc_page(). For larger orders, uses
/// a locked scan path.
#[cfg_attr(feature = "dumb_phys_alloc", allow(unused))]
#[allow(dead_code)]
pub fn alloc_pages(order: usize) -> Option<PhysAddr> {
    let r = alloc_pages_inner(order);
    if let Some(ref pa) = r {
        check_pa_not_reserved(pa.as_usize(), "alloc_pages");
        // order==0 delegates to alloc_page(), which already marked the
        // single page — marking again here would self-trigger a false
        // double-issue.  Only mark the multi-page block here.
        if order > 0 {
            let ps = page::page_size();
            let base = pa.as_usize();
            for k in 0..(1usize << order) {
                di_mark_alloc(base + k * ps);
            }
        }
    }
    r
}

#[cfg_attr(feature = "dumb_phys_alloc", allow(unused))]
#[allow(dead_code)]
fn alloc_pages_inner(order: usize) -> Option<PhysAddr> {
    #[cfg(feature = "dumb_phys_alloc")]
    {
        return super::phys_dumb::alloc_pages(order);
    }
    #[allow(unreachable_code)]
    if order == 0 {
        return alloc_page();
    }

    let need = 1usize << order;
    if ALLOC.free_count_global.load(Ordering::Relaxed) < need {
        return None;
    }

    let _guard = BULK_LOCK.lock();

    // For orders where 2^order <= CHUNK_PAGES (i.e., order <= 6), we can
    // find contiguous free pages within a single chunk by scanning its bitmap.
    //
    // IMPORTANT: alloc_page/chunk_alloc_one uses lock-free CAS on bitmaps
    // without holding BULK_LOCK. We must either skip owned chunks (whose
    // bitmaps may be concurrently modified) or use CAS ourselves.
    if need <= CHUNK_PAGES {
        for ci in 0..ALLOC.total_chunks {
            let s = ALLOC.chunk(ci).load();
            let fc = free_count(s);
            if (fc as usize) < need {
                continue;
            }
            // Skip chunks owned by another CPU — their bitmaps are being
            // modified lock-free by chunk_alloc_one on the owning CPU.
            if owner(s) != NO_CPU {
                continue;
            }
            // #228: skip chunks under inline→bitmap transition.
            if s & STATE_TRANSITIONING_BIT != 0 {
                continue;
            }

            if fc == 64 {
                // All-free chunk. Allocate pages 0..need-1.
                // Need to materialize bitmap with those pages marked allocated.
                let bmp_pg: u32 = need as u32; // first page after the allocated block
                if bmp_pg >= 64 {
                    continue;
                } // shouldn't happen for need<=64

                let mut bmp: u64 = !0u64;
                // Mark pages 0..need-1 as allocated.
                for p in 0..need {
                    bmp &= !(1u64 << p);
                }
                // Mark bitmap page as not available.
                bmp &= !(1u64 << bmp_pg);

                // Handle partial last chunk.
                let pages_in_chunk = if (ci + 1) * CHUNK_PAGES <= ALLOC.total_pages {
                    64u32
                } else {
                    (ALLOC.total_pages - ci * CHUNK_PAGES) as u32
                };
                if pages_in_chunk < 64 {
                    bmp &= (1u64 << pages_in_chunk) - 1;
                }

                // #228 fix: use the TRANSITIONING-bit lock so that
                // (a) only the winner of the state CAS ever writes the
                // bitmap and (b) chunk_alloc_one (lock-free) on the same
                // chunk skips us during the brief transition window.
                //
                // Without this, a CAS-loser's unconditional
                // `write_bitmap(target)` to page `bmp_pg` would land
                // AFTER the winner publishes a different bmp_pg.
                // Once the chunk is in service, page `bmp_pg` is a
                // regular data page; a future allocator hands it to a
                // consumer that fills it with their own data; the
                // loser's stale store then clobbers that data.
                // See `tests/loom-phys-chunk` mode_switch_tests.
                let trans_s = s | STATE_TRANSITIONING_BIT;
                if ALLOC.chunk(ci).cas(s, trans_s).is_err() {
                    continue; // another CPU is mid-transition or stole the chunk
                }
                // Winner.  Bitmap is exclusively ours until the final CAS.
                let bpa = page_pa(ci, bmp_pg);
                unsafe {
                    write_bitmap(bpa, bmp);
                }

                let new_fc = bmp.count_ones();
                // CAS to final state in a retry loop — see analogous
                // chunk_alloc_one fc==64 fix.  Only this thread can
                // clear TRANSITIONING.
                loop {
                    let cur = ALLOC.chunk(ci).load();
                    if cur & STATE_TRANSITIONING_BIT == 0 {
                        crate::println!(
                            "[#228] alloc_pages_inner fc64: TRANSITIONING cleared by other writer (cur={:#x})",
                            cur,
                        );
                        return None;
                    }
                    let new_s = make_state(new_fc, NO_CPU, true, bmp_pg, 0);
                    if ALLOC.chunk(ci).cas(cur, new_s).is_ok() {
                        break;
                    }
                }

                // Subtract: need pages + 1 bitmap page from the 64 that were free.
                let consumed = 64u32 - new_fc;
                ALLOC
                    .free_count_global
                    .fetch_sub(consumed as usize, Ordering::Relaxed);

                record_evt(EVT_ALLOCN_FRESH, ci, 0);
                return Some(PhysAddr::new(page_pa(ci, 0)));
            }

            if !has_bitmap(s) {
                continue;
            } // inline mode, too fragmented

            // Scan bitmap for a contiguous run of `need` set bits.
            // Use CAS on the bitmap to avoid racing with concurrent
            // chunk_alloc_one (which CAS-modifies bitmaps without BULK_LOCK).
            let bp = bmp_page(s);
            let bpa = bitmap_pa(ci, bp);
            let bmp = unsafe { read_bitmap(bpa) };

            if let Some(start_bit) = find_contiguous_bits(bmp, need, bp) {
                // Clear the bits.
                let mut new_bmp = bmp;
                for b in start_bit..(start_bit + need) {
                    new_bmp &= !(1u64 << b);
                }
                // CAS the bitmap — if chunk_alloc_one modified it concurrently,
                // our CAS fails and we skip this chunk rather than restoring
                // freed bits (which would cause double-allocation).
                let cas_ok = unsafe { cas_bitmap(bpa, bmp, new_bmp).is_ok() };
                if !cas_ok {
                    continue; // bitmap was concurrently modified, skip chunk
                }

                let new_fc = new_bmp.count_ones();
                let allocated = (bmp.count_ones() - new_bmp.count_ones()) as u32;

                // Try optimized state transitions first.  All three are
                // best-effort against `s` — they can fail if a concurrent
                // chunk_free_one bumped fc (or chunk_alloc_one ran any
                // bitmap-mode path that re-CAS'd the node).
                let mut state_updated = false;
                // #155 with-bp accounting: when the bitmap→inline
                // transition succeeds AND bp fits in the inline indices,
                // the bp page reclassifies from "metadata (excluded
                // from global+fc)" to "free (counted in global+fc)".
                // Chunk fc effectively goes X → new_fc + 1, while we
                // allocated `need` pages.  Global must dec by
                // `allocated - 1` (mirrors chunk_alloc_one's "net 0"
                // rationale).  Boot 99amfsq546 surfaced drift=-5 from 5
                // such transitions where the prior code dec'd global by
                // `allocated` flat — leak direction.
                let mut transitioned_with_bp = false;
                if new_fc <= INLINE_K && new_fc > 0 {
                    let mut indices = [0u32; INLINE_K as usize];
                    let mut count = 0u32;
                    let mut b = new_bmp;
                    while b != 0 && count < INLINE_K {
                        let idx = b.trailing_zeros();
                        indices[count as usize] = idx;
                        b &= !(1u64 << idx);
                        count += 1;
                    }
                    let with_bp = count < INLINE_K;
                    if with_bp {
                        indices[count as usize] = bp;
                        count += 1;
                    }
                    let inline_bits = pack_inline(&indices[..count as usize]);
                    if ALLOC
                        .chunk(ci)
                        .cas(s, make_state(count, owner(s), false, 0, inline_bits))
                        .is_ok()
                    {
                        state_updated = true;
                        transitioned_with_bp = with_bp;
                    }
                } else if new_fc == 0 {
                    if ALLOC
                        .chunk(ci)
                        .cas(s, make_state(0, NO_CPU, false, 0, 0))
                        .is_ok()
                    {
                        state_updated = true;
                    }
                } else if ALLOC
                    .chunk(ci)
                    .cas(s, (s & !FREE_COUNT_MASK) | (new_fc as u64))
                    .is_ok()
                {
                    state_updated = true;
                }

                // #155 leak-direction drift fix: when the best-effort
                // state CAS lost (concurrent chunk_free_one bumped fc
                // between our load and our CAS), the prior code
                // silently discarded the failure (`let _ = ...`) but
                // still ran `fetch_sub(allocated)` on global below,
                // leaving global undercounted by `allocated` vs
                // sum_fc.  Boot 99amfsq544 reproduced this once under
                // extreme stress (drift=-1).  Retry-loop fc-dec
                // applies the alloc accounting atomically against
                // whatever state the concurrent op left.
                if !state_updated {
                    BITMAP_ALLOC_STATE_CAS_FALLBACKS.fetch_add(1, Ordering::Relaxed);
                    loop {
                        let cur = ALLOC.chunk(ci).load();
                        let cur_fc = free_count(cur);
                        if cur_fc < allocated {
                            // Our bitmap CAS owned `allocated` bits, so
                            // chunk fc at our load was >= allocated.  If
                            // it's less now, a concurrent mode transition
                            // (e.g. bitmap→inline with bp reclassification)
                            // shifted accounting in a way we can't model
                            // here.  Bail rather than risk fc underflow;
                            // a small leak is harmless and the next
                            // free into this chunk will heal it.
                            BITMAP_ALLOC_STATE_CAS_SANITY_FAILS
                                .fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        let upd = (cur & !FREE_COUNT_MASK)
                            | ((cur_fc - allocated) as u64);
                        if ALLOC.chunk(ci).cas(cur, upd).is_ok() {
                            break;
                        }
                    }
                }

                // With-bp transition reclassifies bp page from metadata
                // to free; net global change is `-(allocated - 1)`.
                // Without with-bp transition (no-bp transition, plain fc
                // update, or retry-loop fallback): net change is `-allocated`.
                let global_dec = if transitioned_with_bp {
                    allocated - 1
                } else {
                    allocated
                };
                ALLOC
                    .free_count_global
                    .fetch_sub(global_dec as usize, Ordering::Relaxed);
                record_evt(EVT_ALLOCN_BMP, ci, start_bit as u32);
                return Some(PhysAddr::new(page_pa(ci, start_bit as u32)));
            }
        }
    }

    // For orders where 2^order > CHUNK_PAGES, find consecutive all-free chunks.
    let chunks_needed = (need + CHUNK_PAGES - 1) / CHUNK_PAGES;
    let mut run_start = 0;
    let mut run_len = 0;

    for ci in 0..ALLOC.total_chunks {
        let s = ALLOC.chunk(ci).load();
        if free_count(s) == 64 && owner(s) == NO_CPU
            && s & STATE_TRANSITIONING_BIT == 0
        {
            if run_len == 0 {
                run_start = ci;
            }
            run_len += 1;
            if run_len >= chunks_needed {
                // Found enough consecutive all-free chunks.
                // Mark them all as fully allocated via CAS (another CPU's
                // alloc_page could claim one between our scan and store).
                let mut ok = true;
                for c in run_start..(run_start + chunks_needed) {
                    let cur = ALLOC.chunk(c).load();
                    if free_count(cur) != 64 || owner(cur) != NO_CPU {
                        ok = false;
                        break;
                    }
                    // #228: don't try to claim a chunk under inline→bitmap
                    // transition; the CAS would corrupt the winner's
                    // mid-flight state.
                    if cur & STATE_TRANSITIONING_BIT != 0 {
                        ok = false;
                        break;
                    }
                    if ALLOC.chunk(c).cas(cur, make_state(0, NO_CPU, false, 0, 0)).is_err() {
                        ok = false;
                        break;
                    }
                }
                if !ok {
                    // Race lost — undo any chunks we already claimed and retry.
                    //
                    // #155: use unconditional store here, NOT cas().  cas() is
                    // compare_exchange_weak which can spurious-fail even when
                    // the value matches.  Under BULK_LOCK no other multi-chunk
                    // alloc runs, and single-page alloc_page skips fc==0
                    // chunks, so our fc=0 marking is unchanged — a spurious
                    // CAS failure here would leave the chunk orphaned (fc=0
                    // with all 64 pages physically free), making them
                    // permanently unallocatable.  This is one mechanism for
                    // the boot-33+ "free_count_global=127 tried_with_free=1"
                    // symptom.
                    let mut restored = 0usize;
                    for c in run_start..(run_start + chunks_needed) {
                        let cur = ALLOC.chunk(c).load();
                        if free_count(cur) == 0 && !has_bitmap(cur) {
                            ALLOC.chunk(c).store(make_state(64, NO_CPU, false, 0, 0));
                            restored += 1;
                        }
                    }
                    if restored > 0 {
                        crate::println!(
                            "[alloc_pages] ROLLBACK-RESTORE: chunks_needed={} restored={} run_start={}",
                            chunks_needed, restored, run_start,
                        );
                    }
                    run_len = 0;
                    continue;
                }
                ALLOC
                    .free_count_global
                    .fetch_sub(chunks_needed * CHUNK_PAGES, Ordering::Relaxed);
                return Some(PhysAddr::new(page_pa(run_start, 0)));
            }
        } else {
            run_len = 0;
        }
    }

    None
}

/// Free 2^order contiguous pages.
#[allow(dead_code)]
pub fn free_pages(addr: PhysAddr, order: usize) {
    #[cfg(feature = "dumb_phys_alloc")]
    {
        return super::phys_dumb::free_pages(addr, order);
    }
    #[allow(unreachable_code)]
    let base = addr.as_usize();
    let (ci0, pi0) = addr_to_chunk_page(base);
    record_evt(EVT_FREEN, ci0, pi0);
    let count = 1usize << order;
    for i in 0..count {
        free_page(PhysAddr::new(base + (i << page::page_shift())));
    }
}

/// Allocate `len` zero-initialized elements of `T` from phys and return
/// them as a `&'static mut [T]`. Rounds up to a power-of-two page count
/// and delegates to `alloc_pages`. Only intended for one-shot boot
/// initialization of dynamic per-CPU state — there is no `free_static_slice`.
///
/// Safety:
/// - `T` must be safely initializable from all-zero bytes.
/// - Must only be called from the BSP during single-threaded boot.
/// - The returned reference aliases the physical page (identity mapped);
///   the caller must not free it.
pub unsafe fn alloc_static_slice<T>(len: usize) -> &'static mut [T] {
    if len == 0 {
        return unsafe { core::slice::from_raw_parts_mut(core::ptr::NonNull::<T>::dangling().as_ptr(), 0) };
    }
    let bytes = core::mem::size_of::<T>()
        .checked_mul(len)
        .expect("alloc_static_slice size overflow");
    let align = core::mem::align_of::<T>();
    let page_sz = page::page_size();
    assert!(
        align <= page_sz,
        "alloc_static_slice: T alignment {} exceeds page size {}",
        align,
        page_sz
    );
    let page_count = (bytes + page_sz - 1) / page_sz;
    let order = (page_count.next_power_of_two()).trailing_zeros() as usize;
    let pa = alloc_pages(order).expect("alloc_static_slice: out of memory");
    // #235 Phase 1: route through arch direct/identity map instead of
    // raw PA cast.  On x86_64 this returns a PHYS_DIRECT_MAP VA so the
    // result survives eventual PML4[0] unmapping.  Other arches are
    // identity-mapped and `phys_to_kva` is an identity function.
    let ptr = crate::mm::page::phys_to_kva(pa.as_usize()) as *mut T;
    unsafe {
        core::ptr::write_bytes(ptr, 0, len);
        core::slice::from_raw_parts_mut(ptr, len)
    }
}

/// Get (total_pages, free_pages).
pub fn stats() -> (usize, usize) {
    #[cfg(feature = "dumb_phys_alloc")]
    {
        return super::phys_dumb::stats();
    }
    #[allow(unreachable_code)]
    (
        ALLOC.total_pages,
        ALLOC.free_count_global.load(Ordering::Relaxed),
    )
}

/// #155 reconciliation probe: compare `free_count_global` against the
/// sum of every chunk's per-chunk `fc` field.  The invariant is
/// `global == sum(fc)` — the bitmap page is metadata and not counted
/// in either side.  Any non-zero drift indicates one of the
/// chunk_alloc_one / chunk_free_one paths has miscounted.
///
/// Hooked into `sched::tick` on BSP, rate-limited to one sample per
/// 1024 ticks (~10s at TICK_INTERVAL_NS=10ms).  Prints only when the
/// drift changes from the last sample — this captures both onset and
/// each subsequent step, without spamming the log when steady-state.
pub fn verify_global_counter() {
    static PROBE_TICKS: AtomicUsize = AtomicUsize::new(0);
    static LAST_DRIFT: AtomicUsize = AtomicUsize::new(usize::MAX);

    let n = PROBE_TICKS.fetch_add(1, Ordering::Relaxed);
    if n & 0x3FF != 0 {
        return;
    }
    // Don't run before init (chunks pointer would be null).
    if ALLOC.total_chunks == 0 {
        return;
    }

    let global = ALLOC.free_count_global.load(Ordering::Relaxed);
    let mut sum: usize = 0;
    let mut chunks_fc_gt_0: usize = 0;
    let mut max_fc: u32 = 0;
    let mut bitmap_chunks: usize = 0;
    for ci in 0..ALLOC.total_chunks {
        let s = ALLOC.chunk(ci).load();
        let fc = free_count(s);
        if has_bitmap(s) {
            bitmap_chunks += 1;
        }
        if fc > 0 {
            chunks_fc_gt_0 += 1;
            sum += fc as usize;
            if fc > max_fc {
                max_fc = fc;
            }
        }
    }

    // Encode drift as usize for atomic; bias by 1<<31 to allow negatives.
    let drift_signed = global as isize - sum as isize;
    let drift_encoded = (drift_signed + (1isize << 31)) as usize;
    let prev = LAST_DRIFT.swap(drift_encoded, Ordering::Relaxed);
    if prev == drift_encoded {
        return;
    }

    let (cas_fallbacks, cas_sanity_fails) = bitmap_alloc_state_cas_counts();
    if drift_signed != 0 {
        crate::println!(
            "[phys::verify] DRIFT global={} sum_fc={} drift={} chunks_fc>0={}/{} bitmap={} max_fc={} cas_fb={} cas_sanity={}",
            global, sum, drift_signed, chunks_fc_gt_0, ALLOC.total_chunks, bitmap_chunks, max_fc,
            cas_fallbacks, cas_sanity_fails,
        );
    } else if prev != usize::MAX && prev != drift_encoded {
        // Drift cleared after being non-zero — also worth noting.
        crate::println!(
            "[phys::verify] HEALED global={} sum_fc={} (drift back to 0) cas_fb={} cas_sanity={}",
            global, sum, cas_fallbacks, cas_sanity_fails,
        );
    }
}

// ── Bitmap scanning ──────────────────────────────────────────────────

/// Find `need` contiguous set bits in `bmp`, avoiding `skip_bit` (the bitmap page).
/// Returns the start bit index, or None.
fn find_contiguous_bits(bmp: u64, need: usize, skip_bit: u32) -> Option<usize> {
    // Mask out the bitmap page bit (it's not available).
    let avail = bmp & !(1u64 << skip_bit);
    if avail.count_ones() < need as u32 {
        return None;
    }

    let mut run_start = 0;
    let mut run_len = 0;
    for bit in 0..64u32 {
        if avail & (1u64 << bit) != 0 {
            if run_len == 0 {
                run_start = bit as usize;
            }
            run_len += 1;
            if run_len >= need {
                return Some(run_start);
            }
        } else {
            run_len = 0;
        }
    }
    None
}
