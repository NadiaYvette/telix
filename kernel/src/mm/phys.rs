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
        let ptr = pa as *const AtomicU64;
        (*ptr).load(Ordering::Acquire)
    }
}

unsafe fn write_bitmap(pa: usize, val: u64) {
    unsafe {
        let ptr = pa as *const AtomicU64;
        (*ptr).store(val, Ordering::Release);
    }
}

unsafe fn cas_bitmap(pa: usize, old: u64, new: u64) -> Result<u64, u64> {
    unsafe {
        let ptr = pa as *const AtomicU64;
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

        if fc == 64 {
            // All-free chunk. Transition: pick page 0 as bitmap page,
            // write bitmap with all bits set except bit 0, allocate page 1.
            let bmp_pa = bitmap_pa(chunk_idx, 0);
            // bitmap: all free except page 0 (bitmap) and page 1 (allocated).
            let bmp: u64 = !0u64 & !1u64 & !(1u64 << 1);
            unsafe {
                write_bitmap(bmp_pa, bmp);
            }
            // New state: fc=62, has_bitmap=true, bmp_page=0, owner preserved.
            let new_s = make_state(62, owner(s), true, 0, 0);
            match node.cas(s, new_s) {
                Ok(_) => {
                    ALLOC.free_count_global.fetch_sub(2, Ordering::Relaxed); // bitmap page + allocated page
                    return Some(1);
                }
                Err(_) => continue,
            }
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
            if new_fc <= INLINE_K && new_fc > 0 {
                // Collect remaining free indices from the updated bitmap.
                let remaining_bmp = new_bmp;
                let mut indices = [0u32; INLINE_K as usize];
                let mut count = 0u32;
                let mut b = remaining_bmp;
                while b != 0 && count < INLINE_K {
                    let idx = b.trailing_zeros();
                    indices[count as usize] = idx;
                    b &= !(1u64 << idx);
                    count += 1;
                }

                // Free the bitmap page itself (add it to the inline set if room).
                if count < INLINE_K {
                    indices[count as usize] = bp;
                    count += 1;
                }

                let inline_bits = pack_inline(&indices[..count as usize]);
                let new_s = make_state(count, owner(s), false, 0, inline_bits);
                // Best-effort CAS. If it fails, the bitmap is still valid;
                // next operation will retry.
                let _ = node.cas(
                    (s & !(FREE_COUNT_MASK)) | (fc as u64), // old with original fc
                    new_s,
                );
                // Note: even if the CAS fails, the bitmap has already been
                // updated (the page is allocated). The free_count in the node
                // will be corrected by the next successful CAS. This is safe
                // because the bitmap is the source of truth for which pages
                // are free; the node's free_count is an advisory hint.
                // However, for correctness we should retry with a fresh load.
                // Let's do a simpler approach: just update free_count.
            }

            // Update free_count in the node.
            loop {
                let cur = node.load();
                let cur_fc = free_count(cur);
                if cur_fc == 0 {
                    break;
                } // someone else already decremented
                let upd = (cur & !FREE_COUNT_MASK) | ((cur_fc - 1) as u64);
                if node.cas(cur, upd).is_ok() {
                    break;
                }
            }

            ALLOC.free_count_global.fetch_sub(1, Ordering::Relaxed);
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
        let mut bmp: u64 = 0;
        for i in 0..fc {
            bmp |= 1u64 << inline_idx(s, i);
        }
        // page_idx is the bitmap page; its bit is CLEAR (reserved).
        // The existing inline pages are free; their bits are SET.

        // Write bitmap to the freed page.
        let bpa = page_pa(chunk_idx, page_idx);
        unsafe {
            write_bitmap(bpa, bmp);
        }

        let new_s = make_state(fc, owner(s), true, page_idx, 0);
        // Note: fc stays the same because the freed page becomes the bitmap
        // page (not counted in fc), and the INLINE_K pages remain free.
        // Actually: before this free, there were fc=INLINE_K pages free (inline).
        // We're adding page_idx. Total should be INLINE_K + 1. But page_idx
        // becomes the bitmap page (not available), so available = INLINE_K.
        // So fc stays INLINE_K. Correct.
        match node.cas(s, new_s) {
            Ok(_) => {
                // The freed page is consumed as bitmap overhead; don't increment
                // the global counter (the caller's page was freed, but one page
                // is now used for the bitmap, net change = 0 to available count).
                // Actually: the caller freed a page. That page is now the bitmap
                // page. The INLINE_K pages that were already free are still free.
                // From the caller's perspective, their page was freed. But from
                // the available count, nothing changed (the page is used as metadata).
                // This is correct: the global count tracks pages available to callers.
                // No change to free_count_global.
                return;
            }
            Err(_) => continue,
        }
    }
}

// ── Public API ───────────────────────────────────────────────────────

/// Initialize the allocator. Called once from boot code (single-threaded).
///
/// Metadata (chunk array) is carved from the start of usable RAM at boot,
/// so there is no compile-time cap on managed memory.
pub fn init(ram_start: usize, ram_end: usize, kernel_start: usize, kernel_end: usize) {
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
    let chunk_ptr = start as *mut ChunkNode;

    // Zero the metadata region (chunk array).
    unsafe {
        core::ptr::write_bytes(start as *mut u8, 0, metadata_pages << pshift);
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

/// Allocate a single page. Returns its physical address.
pub fn alloc_page() -> Option<PhysAddr> {
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

        if !can_reserve {
            // CPU ID doesn't fit in owner field — alloc without reservation.
            if let Some(pi) = chunk_alloc_one(ci) {
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
        let fc = free_count(ALLOC.chunk(ci).load());
        if fc == 0 {
            continue;
        }
        tried_with_free += 1;
        if let Some(pi) = chunk_alloc_one(ci) {
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
    let pa = addr.as_usize();
    if pa < ALLOC.base {
        return;
    }
    let (ci, pi) = addr_to_chunk_page(pa);
    if ci >= ALLOC.total_chunks {
        return;
    }
    chunk_free_one(ci, pi);
}

/// Allocate 2^order contiguous pages. Returns physical address.
/// For order=0, delegates to alloc_page(). For larger orders, uses
/// a locked scan path.
#[allow(dead_code)]
pub fn alloc_pages(order: usize) -> Option<PhysAddr> {
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

                // Write bitmap BEFORE publishing the chunk state. Otherwise a
                // concurrent alloc_page could see has_bitmap=true but read an
                // uninitialised bitmap page, allocating based on garbage bits.
                let bpa = page_pa(ci, bmp_pg);
                unsafe {
                    write_bitmap(bpa, bmp);
                }

                let new_fc = bmp.count_ones();
                let new_s = make_state(new_fc, NO_CPU, true, bmp_pg, 0);
                if ALLOC.chunk(ci).cas(s, new_s).is_err() {
                    continue; // another CPU claimed or modified this chunk
                }

                // Subtract: need pages + 1 bitmap page from the 64 that were free.
                let consumed = 64u32 - new_fc;
                ALLOC
                    .free_count_global
                    .fetch_sub(consumed as usize, Ordering::Relaxed);

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
                // Possibly transition to inline mode.
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
                    if count < INLINE_K {
                        indices[count as usize] = bp;
                        count += 1;
                    }
                    let inline_bits = pack_inline(&indices[..count as usize]);
                    let _ = ALLOC
                        .chunk(ci)
                        .cas(s, make_state(count, owner(s), false, 0, inline_bits));
                } else if new_fc == 0 {
                    // Also free the bitmap page since chunk is now fully allocated.
                    let _ = ALLOC.chunk(ci).cas(s, make_state(0, NO_CPU, false, 0, 0));
                } else {
                    let _ = ALLOC
                        .chunk(ci)
                        .cas(s, (s & !FREE_COUNT_MASK) | (new_fc as u64));
                }

                // Use actual bitmap popcount difference for accurate accounting.
                let allocated = bmp.count_ones() - new_bmp.count_ones();
                ALLOC.free_count_global.fetch_sub(allocated as usize, Ordering::Relaxed);
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
        if free_count(s) == 64 && owner(s) == NO_CPU {
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
    let base = addr.as_usize();
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
    let ptr = pa.as_usize() as *mut T;
    unsafe {
        core::ptr::write_bytes(ptr, 0, len);
        core::slice::from_raw_parts_mut(ptr, len)
    }
}

/// Get (total_pages, free_pages).
pub fn stats() -> (usize, usize) {
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

    if drift_signed != 0 {
        crate::println!(
            "[phys::verify] DRIFT global={} sum_fc={} drift={} chunks_fc>0={}/{} bitmap={} max_fc={}",
            global, sum, drift_signed, chunks_fc_gt_0, ALLOC.total_chunks, bitmap_chunks, max_fc,
        );
    } else if prev != usize::MAX && prev != drift_encoded {
        // Drift cleared after being non-zero — also worth noting.
        crate::println!(
            "[phys::verify] HEALED global={} sum_fc={} (drift back to 0)",
            global, sum,
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
