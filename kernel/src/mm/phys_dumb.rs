//! Debug-only physical allocator — global-locked bitmap, no per-CPU caches.
//!
//! Gated by the `dumb_phys_alloc` cargo feature.  When enabled, the public
//! entry points in `crate::mm::phys` (init / alloc_page / alloc_pages /
//! free_page / free_pages / stats) route here instead of the LLFree-style
//! per-CPU-chunk allocator.
//!
//! Purpose: A/B test whether the production allocator's concurrency
//! machinery is implicated in the #208 corruption family.  If a build with
//! `--features=dumb_phys_alloc` exhibits the same corruption signatures,
//! the allocator is exonerated.  If the signatures disappear or change,
//! the smart allocator is implicated.
//!
//! Design:
//! - One bit per page; 0 = free, 1 = allocated.
//! - Bitmap carved from the start of usable RAM at init.
//! - Single `SpinLock` protects all state — no per-CPU caches, no
//!   inline-vs-bitmap mode-switching, no atomic-CAS dance.
//! - `alloc_pages(order)`: first-fit linear scan for 2^order contiguous
//!   free bits.  O(total_pages) worst case.  Acceptable for diagnostic.

use super::page::{self, PhysAddr};
use crate::sync::spinlock::SpinLock;
use core::sync::atomic::{AtomicUsize, Ordering};

struct DumbState {
    /// Base physical address of the managed pool.
    base: usize,
    /// Total managed pages (counts pool size, including reserved bits).
    total_pages: usize,
    /// Pointer to the bitmap (one bit per page, 0 = free).
    bitmap: *mut u64,
    /// Number of u64 words in the bitmap = (total_pages + 63) / 64.
    bitmap_words: usize,
}

unsafe impl Send for DumbState {}

static STATE: SpinLock<DumbState> = SpinLock::new(DumbState {
    base: 0,
    total_pages: 0,
    bitmap: core::ptr::null_mut(),
    bitmap_words: 0,
});

/// Cached free-page count for `stats()` — updated under STATE lock on every
/// alloc/free.  Reading is lock-free.
static FREE_COUNT: AtomicUsize = AtomicUsize::new(0);
static TOTAL_PAGES: AtomicUsize = AtomicUsize::new(0);

/// Test bit at index `i` in the bitmap.  Caller must hold STATE lock.
#[inline]
unsafe fn bit_get(state: &DumbState, i: usize) -> bool {
    let word = i / 64;
    let mask = 1u64 << (i % 64);
    unsafe { (*state.bitmap.add(word)) & mask != 0 }
}

/// Set bit `i` (mark allocated).  Caller must hold STATE lock.
#[inline]
unsafe fn bit_set(state: &DumbState, i: usize) {
    let word = i / 64;
    let mask = 1u64 << (i % 64);
    unsafe { *state.bitmap.add(word) |= mask };
}

/// Clear bit `i` (mark free).  Caller must hold STATE lock.
#[inline]
unsafe fn bit_clear(state: &DumbState, i: usize) {
    let word = i / 64;
    let mask = 1u64 << (i % 64);
    unsafe { *state.bitmap.add(word) &= !mask };
}

/// Find a run of `n` contiguous free bits starting at a page index aligned
/// to a multiple of `n` (matches buddy-allocator alignment expectations).
/// Returns None on failure.  Caller must hold STATE lock.
fn find_run(state: &DumbState, n: usize) -> Option<usize> {
    if n == 0 || n > state.total_pages {
        return None;
    }
    // Step by `n` for alignment.  This is what buddy expects (order-N
    // allocations are 2^N-aligned).
    let mut i = 0;
    while i + n <= state.total_pages {
        let mut all_free = true;
        for j in 0..n {
            unsafe {
                if bit_get(state, i + j) {
                    all_free = false;
                    break;
                }
            }
        }
        if all_free {
            return Some(i);
        }
        i += n;
    }
    None
}

/// Public init.  Mirrors `phys::init`'s signature.  Sets up the bitmap at
/// the start of usable RAM and marks metadata + kernel pages as allocated.
pub fn init(
    ram_start: usize,
    ram_end: usize,
    _kernel_start: usize,
    kernel_end: usize,
) {
    let ps = page::page_size();
    let pshift = page::page_shift();
    let start = (ram_start + ps - 1) & !(ps - 1);
    let end = ram_end & !(ps - 1);
    if end <= start {
        return;
    }

    let total_pages = (end - start) >> pshift;
    let bitmap_words = (total_pages + 63) / 64;
    let bitmap_bytes = bitmap_words * 8;
    let bitmap_pages = (bitmap_bytes + ps - 1) >> pshift;

    // Carve bitmap from the start of usable RAM.  Zero it (= all-free).
    let bitmap = start as *mut u64;
    unsafe {
        core::ptr::write_bytes(bitmap as *mut u8, 0, bitmap_pages << pshift);
    }

    let mut state = STATE.lock();
    state.base = start;
    state.total_pages = total_pages;
    state.bitmap = bitmap;
    state.bitmap_words = bitmap_words;

    // Mark bitmap pages as allocated.
    for i in 0..bitmap_pages {
        unsafe { bit_set(&*state, i) };
    }
    // Mark kernel image pages as allocated (start..kernel_end).
    let kern_end_pfn = if kernel_end <= start {
        0
    } else {
        ((kernel_end - start + ps - 1) >> pshift).min(total_pages)
    };
    for i in bitmap_pages..kern_end_pfn {
        unsafe { bit_set(&*state, i) };
    }

    let reserved = bitmap_pages + (kern_end_pfn.saturating_sub(bitmap_pages));
    let free = total_pages - reserved;
    TOTAL_PAGES.store(total_pages, Ordering::Release);
    FREE_COUNT.store(free, Ordering::Release);

    crate::println!(
        "  [DUMB-ALLOC] {} pages total, {} free, bitmap {} bytes at {:#x}",
        total_pages, free, bitmap_bytes, bitmap as usize
    );
}

/// Allocate a single page.
pub fn alloc_page() -> Option<PhysAddr> {
    alloc_pages(0)
}

/// Allocate `2^order` contiguous pages.
pub fn alloc_pages(order: usize) -> Option<PhysAddr> {
    let n = 1usize << order;
    let state = STATE.lock();
    if state.base == 0 {
        return None; // not yet initialized
    }
    let idx = find_run(&state, n)?;
    for j in 0..n {
        unsafe { bit_set(&*state, idx + j) };
    }
    let pa = state.base + (idx << page::page_shift());
    FREE_COUNT.fetch_sub(n, Ordering::Relaxed);
    Some(PhysAddr::new(pa))
}

/// Free a single page.
pub fn free_page(addr: PhysAddr) {
    free_pages(addr, 0);
}

/// Free `2^order` contiguous pages.
pub fn free_pages(addr: PhysAddr, order: usize) {
    let n = 1usize << order;
    let state = STATE.lock();
    if state.base == 0 || addr.as_usize() < state.base {
        return;
    }
    let off = addr.as_usize() - state.base;
    let idx = off >> page::page_shift();
    if idx + n > state.total_pages {
        return;
    }
    for j in 0..n {
        unsafe { bit_clear(&*state, idx + j) };
    }
    FREE_COUNT.fetch_add(n, Ordering::Relaxed);
}

/// Returns (total_pages, free_pages).
pub fn stats() -> (usize, usize) {
    (
        TOTAL_PAGES.load(Ordering::Relaxed),
        FREE_COUNT.load(Ordering::Relaxed),
    )
}
