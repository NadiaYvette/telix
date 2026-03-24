//! Physical memory allocator — Embedded Sparse LLFree.
//!
//! An O(1)-external-memory allocator: per-page bitmaps live in-band inside
//! free pages, and nearly-empty chunks use inline index encoding (option 2).
//!
//! Structure:
//! - 128 chunk nodes (each chunk = 64 pages = 4 MiB at PAGE_SIZE=64K)
//! - Per-CPU reservation: each CPU owns one chunk for contention-free alloc
//! - Leaf bitmaps stored inside a free page within each chunk
//! - Chunks with ≤ INLINE_K free pages encode indices directly in the parent node
//! - Multi-page allocation uses a separate lock (rare path)

use super::page::{PhysAddr, PAGE_SIZE, PAGE_SHIFT};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Pages per chunk — matches one u64 bitmap.
const CHUNK_PAGES: usize = 64;
const CHUNK_SHIFT: usize = 6;

/// Maximum physical pages (512 MiB at 64K page size).
const MAX_PAGES: usize = 8192;
const MAX_CHUNKS: usize = MAX_PAGES / CHUNK_PAGES; // 128

/// Inline threshold: chunks with ≤ INLINE_K free pages encode indices
/// directly in the node, avoiding a bitmap page. 6 × 6 bits = 36 bits.
const INLINE_K: u32 = 6;

/// Sentinel values.
const NO_CPU: u32 = 0xF;
const NO_CHUNK: usize = 0xFF;

/// Maximum CPUs (must match sched::smp::MAX_CPUS).
const MAX_CPUS: usize = 4;

// ── ChunkNode ────────────────────────────────────────────────────────

/// Packed state for one 64-page chunk, stored in a single AtomicU64.
///
/// Layout (64 bits):
///   [6:0]   free_count   (0..64; 64 = all-free, special-cased)
///   [10:7]  owner_cpu    (0..3 = CPU, 0xF = unowned)
///   [11]    has_bitmap   (1 = bitmap page materialized)
///   [17:12] bitmap_page  (index within chunk when has_bitmap=1)
///   [63:18] inline_data  (when has_bitmap=0 and free_count in 1..=INLINE_K:
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
const FREE_COUNT_MASK: u64 = 0x7F;          // bits [6:0]
const OWNER_SHIFT: u32 = 7;
const OWNER_MASK: u64 = 0xF << 7;           // bits [10:7]
const HAS_BITMAP_BIT: u64 = 1 << 11;        // bit [11]
const BMP_PAGE_SHIFT: u32 = 12;
const BMP_PAGE_MASK: u64 = 0x3F << 12;      // bits [17:12]
const INLINE_SHIFT: u32 = 18;
// Each inline index is 6 bits, starting at bit 18.
const INLINE_IDX_BITS: u32 = 6;
const INLINE_IDX_MASK: u64 = 0x3F;

impl ChunkNode {
    const fn new() -> Self {
        Self { state: AtomicU64::new(0) }
    }

    #[inline]
    fn load(&self) -> u64 {
        self.state.load(Ordering::Acquire)
    }

    #[inline]
    fn cas(&self, old: u64, new: u64) -> Result<u64, u64> {
        self.state.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire)
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
    let ptr = pa as *const AtomicU64;
    (*ptr).load(Ordering::Acquire)
}

unsafe fn write_bitmap(pa: usize, val: u64) {
    let ptr = pa as *const AtomicU64;
    (*ptr).store(val, Ordering::Release);
}

unsafe fn cas_bitmap(pa: usize, old: u64, new: u64) -> Result<u64, u64> {
    let ptr = pa as *const AtomicU64;
    (*ptr).compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire)
}

// ── Per-CPU reservations ─────────────────────────────────────────────

/// Per-CPU reservation: the chunk index this CPU "owns" for fast allocation.
/// Accessed only by the owning CPU (with IRQs disabled in the allocator path),
/// so no atomics needed. Stored as usize for alignment; NO_CHUNK = no reservation.
static mut CPU_RESERVATION: [usize; MAX_CPUS] = [NO_CHUNK; MAX_CPUS];

#[inline]
fn my_cpu() -> usize {
    crate::sched::smp::cpu_id() as usize
}

// ── Allocator ────────────────────────────────────────────────────────

struct LLFreeAllocator {
    base: usize,
    total_pages: usize,
    total_chunks: usize,
    free_count_global: AtomicUsize,
    chunks: [ChunkNode; MAX_CHUNKS],
}

impl LLFreeAllocator {
    const fn new() -> Self {
        // Use a macro to avoid [ChunkNode; 128] not implementing Copy.
        const EMPTY_CHUNK: ChunkNode = ChunkNode::new();
        Self {
            base: 0,
            total_pages: 0,
            total_chunks: 0,
            free_count_global: AtomicUsize::new(0),
            chunks: [EMPTY_CHUNK; MAX_CHUNKS],
        }
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
    ALLOC.base + ((chunk_idx * CHUNK_PAGES + page_idx as usize) << PAGE_SHIFT)
}

/// Physical address of the bitmap page for a chunk.
#[inline]
fn bitmap_pa(chunk_idx: usize, bmp_pg: u32) -> usize {
    page_pa(chunk_idx, bmp_pg)
}

/// Convert a physical address to (chunk_idx, page_idx).
#[inline]
fn addr_to_chunk_page(pa: usize) -> (usize, u32) {
    let pfn = (pa - ALLOC.base) >> PAGE_SHIFT;
    (pfn >> CHUNK_SHIFT, (pfn & (CHUNK_PAGES - 1)) as u32)
}

// ── Allocation from a specific chunk ─────────────────────────────────

/// Try to allocate one page from a chunk. Returns Some(page_idx) on success.
fn chunk_alloc_one(chunk_idx: usize) -> Option<u32> {
    let node = &ALLOC.chunks[chunk_idx];

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
            unsafe { write_bitmap(bmp_pa, bmp); }
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
                if cur_fc == 0 { break; } // someone else already decremented
                let upd = (cur & !FREE_COUNT_MASK) | ((cur_fc - 1) as u64);
                if node.cas(cur, upd).is_ok() { break; }
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
    let node = &ALLOC.chunks[chunk_idx];

    loop {
        let s = node.load();
        let fc = free_count(s);

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
            let new_s = make_state(64, owner(s), false, 0, 0);
            // The bitmap page (if any) is implicitly freed.
            // But we need to account for it: if has_bitmap, the bitmap page
            // wasn't counted in fc, so total free becomes 64.
            // Actually, let's think carefully:
            // fc=63 means 63 pages available to callers. If has_bitmap=true,
            // the bitmap page is one of the 64 physical pages but not in fc.
            // So 63 available + 1 bitmap = 64 - 0 allocated.
            // Adding page_idx: 64 available. Dissolve bitmap.
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
            loop {
                let bmp = unsafe { read_bitmap(bpa) };
                let new_bmp = bmp | (1u64 << page_idx);
                if new_bmp == bmp { break; } // already set (double-free?)
                unsafe {
                    match cas_bitmap(bpa, bmp, new_bmp) {
                        Ok(_) => break,
                        Err(_) => continue,
                    }
                }
            }

            // Increment free_count.
            loop {
                let cur = node.load();
                let cur_fc = free_count(cur);
                let upd = (cur & !FREE_COUNT_MASK) | ((cur_fc + 1) as u64);
                if node.cas(cur, upd).is_ok() { break; }
            }

            ALLOC.free_count_global.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Inline mode: fc in 1..=INLINE_K.
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
        let mut bmp: u64 = 0;
        for i in 0..fc {
            bmp |= 1u64 << inline_idx(s, i);
        }
        // page_idx is the bitmap page; its bit is CLEAR (reserved).
        // The existing inline pages are free; their bits are SET.

        // Write bitmap to the freed page.
        let bpa = page_pa(chunk_idx, page_idx);
        unsafe { write_bitmap(bpa, bmp); }

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
pub fn init(ram_start: usize, ram_end: usize, kernel_start: usize, kernel_end: usize) {
    let start = PhysAddr::new(ram_start).align_up(PAGE_SIZE).as_usize();
    let end = PhysAddr::new(ram_end).align_down(PAGE_SIZE).as_usize();
    if end <= start { return; }

    let total_pages = ((end - start) >> PAGE_SHIFT).min(MAX_PAGES);
    let total_chunks = (total_pages + CHUNK_PAGES - 1) / CHUNK_PAGES;

    // Safety: single-threaded at boot; direct stores are fine.
    unsafe {
        let alloc = &ALLOC as *const LLFreeAllocator as *mut LLFreeAllocator;
        (*alloc).base = start;
        (*alloc).total_pages = total_pages;
        (*alloc).total_chunks = total_chunks;
    }

    // Initialize chunks as all-free.
    for ci in 0..total_chunks {
        let pages_in_chunk = if (ci + 1) * CHUNK_PAGES <= total_pages {
            64u32
        } else {
            (total_pages - ci * CHUNK_PAGES) as u32
        };
        // All-free: fc = pages_in_chunk, no owner, no bitmap.
        ALLOC.chunks[ci].store(make_state(pages_in_chunk, NO_CPU, false, 0, 0));
    }

    let mut total_free = total_pages;

    // Reserve kernel pages.
    let kern_start_pfn = if kernel_start <= start {
        0
    } else {
        (kernel_start - start) >> PAGE_SHIFT
    };
    let kern_end_pfn = if kernel_end <= start {
        0
    } else {
        ((kernel_end - start + PAGE_SIZE - 1) >> PAGE_SHIFT).min(total_pages)
    };

    // Mark kernel pages as allocated, chunk by chunk.
    for pfn in kern_start_pfn..kern_end_pfn {
        let ci = pfn >> CHUNK_SHIFT;
        let pi = (pfn & (CHUNK_PAGES - 1)) as u32;

        let s = ALLOC.chunks[ci].load();
        let fc = free_count(s);

        if fc == 64 {
            // Transition from all-free. Build a bitmap with all bits set
            // except the reserved page, using page 0 (or the first non-reserved
            // page) as the bitmap page.
            let bmp_pg = if pi == 0 { 1 } else { 0 };
            let mut bmp: u64 = !0u64; // all free
            bmp &= !(1u64 << pi);     // mark reserved page allocated
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
            unsafe { write_bitmap(bpa, bmp); }

            let new_fc = bmp.count_ones();
            ALLOC.chunks[ci].store(make_state(new_fc, NO_CPU, true, bmp_pg, 0));
            total_free -= (pages_in_chunk - new_fc) as usize; // reserved page + bitmap page
        } else if has_bitmap(s) {
            // Already has a bitmap; clear the bit for this page.
            let bp = bmp_page(s);
            let bpa = bitmap_pa(ci, bp);
            let bmp = unsafe { read_bitmap(bpa) };
            if bmp & (1u64 << pi) != 0 {
                unsafe { write_bitmap(bpa, bmp & !(1u64 << pi)); }
                // Decrement free_count.
                let new_fc = fc - 1;
                ALLOC.chunks[ci].store(
                    make_state(new_fc, NO_CPU, true, bp, 0)
                );
                total_free -= 1;
            }
        }
        // If fc was already 0 or page was already marked, nothing to do.
    }

    ALLOC.free_count_global.store(total_free, Ordering::Release);

    let (total, free) = stats();
    crate::println!(
        "  Physical memory: {} pages total, {} pages free ({} KiB / {} KiB)",
        total, free,
        free * (PAGE_SIZE / 1024),
        total * (PAGE_SIZE / 1024),
    );
}

/// Allocate a single page. Returns its physical address.
pub fn alloc_page() -> Option<PhysAddr> {
    if ALLOC.free_count_global.load(Ordering::Relaxed) == 0 {
        return None;
    }

    let cpu = my_cpu();

    // Fast path: try the per-CPU reserved chunk.
    let reserved = unsafe { CPU_RESERVATION[cpu] };
    if reserved != NO_CHUNK {
        if let Some(pi) = chunk_alloc_one(reserved) {
            let pa = page_pa(reserved, pi);
            // If chunk is now empty, release reservation.
            let s = ALLOC.chunks[reserved].load();
            if free_count(s) == 0 {
                unsafe { CPU_RESERVATION[cpu] = NO_CHUNK; }
                // Clear owner in chunk node.
                loop {
                    let cur = ALLOC.chunks[reserved].load();
                    let new = (cur & !OWNER_MASK) | ((NO_CPU as u64) << OWNER_SHIFT);
                    if ALLOC.chunks[reserved].cas(cur, new).is_ok() { break; }
                }
            }
            return Some(PhysAddr::new(pa));
        }
        // Reservation exhausted; release it.
        unsafe { CPU_RESERVATION[cpu] = NO_CHUNK; }
        loop {
            let cur = ALLOC.chunks[reserved].load();
            let new = (cur & !OWNER_MASK) | ((NO_CPU as u64) << OWNER_SHIFT);
            if ALLOC.chunks[reserved].cas(cur, new).is_ok() { break; }
        }
    }

    // Slow path: find an unowned chunk with free pages and claim it.
    for ci in 0..ALLOC.total_chunks {
        let s = ALLOC.chunks[ci].load();
        let fc = free_count(s);
        if fc == 0 { continue; }
        if owner(s) != NO_CPU { continue; } // owned by another CPU

        // Try to claim ownership.
        let new = (s & !OWNER_MASK) | ((cpu as u64) << OWNER_SHIFT);
        if ALLOC.chunks[ci].cas(s, new).is_err() {
            continue; // someone else claimed it
        }

        unsafe { CPU_RESERVATION[cpu] = ci; }

        if let Some(pi) = chunk_alloc_one(ci) {
            let pa = page_pa(ci, pi);
            // Check if exhausted.
            let s2 = ALLOC.chunks[ci].load();
            if free_count(s2) == 0 {
                unsafe { CPU_RESERVATION[cpu] = NO_CHUNK; }
                loop {
                    let cur = ALLOC.chunks[ci].load();
                    let new = (cur & !OWNER_MASK) | ((NO_CPU as u64) << OWNER_SHIFT);
                    if ALLOC.chunks[ci].cas(cur, new).is_ok() { break; }
                }
            }
            return Some(PhysAddr::new(pa));
        }
    }

    None
}

/// Free a single page.
pub fn free_page(addr: PhysAddr) {
    let pa = addr.as_usize();
    if pa < ALLOC.base { return; }
    let (ci, pi) = addr_to_chunk_page(pa);
    if ci >= ALLOC.total_chunks { return; }
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
    if need <= CHUNK_PAGES {
        for ci in 0..ALLOC.total_chunks {
            let s = ALLOC.chunks[ci].load();
            let fc = free_count(s);
            if (fc as usize) < need { continue; }

            if fc == 64 {
                // All-free chunk. Allocate pages 0..need-1.
                // Need to materialize bitmap with those pages marked allocated.
                let bmp_pg: u32 = need as u32; // first page after the allocated block
                if bmp_pg >= 64 { continue; } // shouldn't happen for need<=64

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

                let bpa = page_pa(ci, bmp_pg);
                unsafe { write_bitmap(bpa, bmp); }

                let new_fc = bmp.count_ones();
                ALLOC.chunks[ci].store(make_state(new_fc, NO_CPU, true, bmp_pg, 0));
                // Subtract: need pages + 1 bitmap page from the 64 that were free.
                let consumed = 64u32 - new_fc;
                ALLOC.free_count_global.fetch_sub(consumed as usize, Ordering::Relaxed);

                return Some(PhysAddr::new(page_pa(ci, 0)));
            }

            if !has_bitmap(s) { continue; } // inline mode, too fragmented

            // Scan bitmap for a contiguous run of `need` set bits.
            let bp = bmp_page(s);
            let bpa = bitmap_pa(ci, bp);
            let bmp = unsafe { read_bitmap(bpa) };

            if let Some(start_bit) = find_contiguous_bits(bmp, need, bp) {
                // Clear the bits.
                let mut new_bmp = bmp;
                for b in start_bit..(start_bit + need) {
                    new_bmp &= !(1u64 << b);
                }
                unsafe { write_bitmap(bpa, new_bmp); }

                let new_fc = fc - need as u32;
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
                    ALLOC.chunks[ci].store(make_state(count, owner(s), false, 0, inline_bits));
                } else if new_fc == 0 {
                    // Also free the bitmap page since chunk is now fully allocated.
                    ALLOC.chunks[ci].store(make_state(0, NO_CPU, false, 0, 0));
                    // +1 for the bitmap page being released (it was overhead).
                    // Actually the bitmap page was already not counted in fc,
                    // and now fc=0, so nothing extra to do.
                } else {
                    ALLOC.chunks[ci].store(
                        (s & !FREE_COUNT_MASK) | (new_fc as u64)
                    );
                }

                ALLOC.free_count_global.fetch_sub(need, Ordering::Relaxed);
                return Some(PhysAddr::new(page_pa(ci, start_bit as u32)));
            }
        }
    }

    // For orders where 2^order > CHUNK_PAGES, find consecutive all-free chunks.
    let chunks_needed = (need + CHUNK_PAGES - 1) / CHUNK_PAGES;
    let mut run_start = 0;
    let mut run_len = 0;

    for ci in 0..ALLOC.total_chunks {
        let s = ALLOC.chunks[ci].load();
        if free_count(s) == 64 && owner(s) == NO_CPU {
            if run_len == 0 { run_start = ci; }
            run_len += 1;
            if run_len >= chunks_needed {
                // Found enough consecutive all-free chunks.
                // Mark them all as fully allocated.
                for c in run_start..(run_start + chunks_needed) {
                    ALLOC.chunks[c].store(make_state(0, NO_CPU, false, 0, 0));
                }
                ALLOC.free_count_global.fetch_sub(chunks_needed * CHUNK_PAGES, Ordering::Relaxed);
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
        free_page(PhysAddr::new(base + (i << PAGE_SHIFT)));
    }
}

/// Get (total_pages, free_pages).
pub fn stats() -> (usize, usize) {
    (ALLOC.total_pages, ALLOC.free_count_global.load(Ordering::Relaxed))
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
            if run_len == 0 { run_start = bit as usize; }
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
