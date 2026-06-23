//! H14 perf #1 — shared-RO library cache publication race — loom model.
//!
//! linux_srv fills a LIB_CACHE chunk (writes the backing page) then sets the
//! chunk's `chunks_cached` bit; a Linux process that mmaps the library RO gets
//! that physical page mapped SHARED into its address space (personality_map_shared)
//! and reads it — on a different CPU than the filler.  The fill->read is therefore
//! a cross-CPU publication gated by the cached bit.
//!
//!   INVARIANT: a consumer that observed `cached == true` and reads the page sees
//!   the FULLY-FILLED content, never the pre-fill (zero) or a torn page.
//!
//! `release_acquire_publication_is_safe` — fill content (Relaxed), then set the
//! bit Release; consumer loads the bit Acquire and reads only if set.  Safe under
//! every interleaving (the consumer either misses the bit and doesn't map, or sees
//! it and the release/acquire edge makes the filled content visible).
//!
//! `relaxed_publication_torn_read` (#[should_panic]) — a relaxed handshake lets
//! the consumer observe `cached == true` while still reading the pre-fill page.
//! This is the cost of SHARING: with the old per-process COPY the fill+copy ran on
//! one thread (no cross-CPU edge needed), so the fence was incidental; once the
//! reader is a remote process the release/acquire is load-bearing.

#![cfg(loom)]

use loom::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use loom::sync::Arc;
use loom::thread;

/// One filled "word" of the cache page (0 = pre-fill; FILLED = populated).
const FILLED: u32 = 0xA5A5_A5A5;

/// A LIB_CACHE chunk: the backing-page content + its `chunks_cached` bit.
struct Chunk {
    content: AtomicU32, // stand-in for the backing page bytes
    cached: AtomicBool, // the chunks_cached bit gating the shared mapping
}

impl Chunk {
    fn new() -> Self {
        Chunk {
            content: AtomicU32::new(0),
            cached: AtomicBool::new(false),
        }
    }
}

/// Fill ‖ consume race. The cached BIT carries the publication ordering
/// (`store_ord` on set, `load_ord` on check); the page CONTENT is plain Relaxed —
/// exactly the kernel shape, where chunks_cached publishes the backing bytes.
fn run(store_ord: Ordering, load_ord: Ordering) {
    let c = Arc::new(Chunk::new());
    let (cf, cr) = (c.clone(), c.clone());

    // Filler (linux_srv preload / lazy populate): write the page, publish the bit.
    let filler = thread::spawn(move || {
        cf.content.store(FILLED, Ordering::Relaxed);
        cf.cached.store(true, store_ord);
    });

    // Consumer (a process mmap'ing the library RO on another CPU): map + read only
    // a chunk it observed cached.
    let consumer = thread::spawn(move || {
        if cr.cached.load(load_ord) {
            // The shared RO mapping is installed here; reading it must see FILLED.
            assert_eq!(
                cr.content.load(Ordering::Relaxed),
                FILLED,
                "consumer mapped+read a chunk marked cached but saw the pre-fill page (torn shared read)",
            );
        }
    });

    filler.join().unwrap();
    consumer.join().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Intended: Release on set / Acquire on check publishes the fill to the
    /// remote consumer. No torn read under any interleaving.
    #[test]
    fn release_acquire_publication_is_safe() {
        loom::model(|| run(Ordering::Release, Ordering::Acquire));
    }

    /// Cost of sharing: a relaxed handshake lets the consumer see cached==true
    /// while reading the pre-fill page.
    #[test]
    #[should_panic(expected = "torn shared read")]
    fn relaxed_publication_torn_read() {
        loom::model(|| run(Ordering::Relaxed, Ordering::Relaxed));
    }
}
