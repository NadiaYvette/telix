//! SEED — the LLFree per-chunk allocator invariant (telix `mm::phys`, Embedded Sparse LLFree).
//!
//! telix's physical allocator divides RAM into 64-page **chunks**, each a packed `AtomicU64`
//! (`ChunkNode`) that caches a `free_count` [6:0] over a per-page bitmap (bit set = free); nearly
//! empty chunks inline the free indices, full/empty chunks special-case. Each CPU reserves one chunk
//! for contention-free alloc. The defining correctness property — and the one the #228 PA-ALIAS
//! "double-issue" (two allocators handing out the same page) violates — is that the cached
//! `free_count` equals the bitmap's true popcount. telix keeps an independent `DI_SHADOW` bitmap to
//! catch a divergence at runtime; this proves the invariant the alloc/free paths must preserve.
//!
//! This is the allocator analogue of `rmap.rs` (`mapcount == |rmap|`): the cached count must track
//! the true free set, correct alloc/free preserve it, double-free is a provable error, and an
//! allocated page is not handed out again (no double-issue). Modeled on a `Set` of free indices, so
//! the inline/bitmap encoding is abstracted to the logical state it represents. See `CORRESPONDENCE.md`.

use vstd::prelude::*;

verus! {

/// A 64-page chunk's allocation state: the SET of free page indices (the bitmap's set bits) and the
/// cached `free_count` (telix `ChunkNode.free_count`).
pub struct Chunk {
    pub free: Set<nat>,
    pub free_count: int,
}

/// **The chunk invariant**: the cached `free_count` equals the true number of free pages. Diverge
/// and you get either double-issue (count says a page is free that the bitmap allocated) or leaked
/// pages — exactly the #228 PA-ALIAS family.
pub open spec fn wf(c: Chunk) -> bool {
    c.free_count == c.free.len()
}

/// **Allocate page `i`**: clear its bit (remove from the free set) and drop the cached count.
pub open spec fn alloc(c: Chunk, i: nat) -> Chunk {
    Chunk { free: c.free.remove(i), free_count: c.free_count - 1 }
}

/// **Free page `i`**: set its bit (add to the free set) and bump the cached count.
pub open spec fn free_page(c: Chunk, i: nat) -> Chunk {
    Chunk { free: c.free.insert(i), free_count: c.free_count + 1 }
}

/// **Allocating a free page preserves the invariant** (count tracks the bitmap).
pub proof fn alloc_preserves_wf(c: Chunk, i: nat)
    requires
        wf(c),
        c.free.contains(i),
    ensures
        wf(alloc(c, i)),
{
    assert(c.free.remove(i).len() == c.free.len() - 1);
}

/// **Freeing an allocated page preserves the invariant.**
pub proof fn free_preserves_wf(c: Chunk, i: nat)
    requires
        wf(c),
        !c.free.contains(i),
    ensures
        wf(free_page(c, i)),
{
    assert(c.free.insert(i).len() == c.free.len() + 1);
}

/// **No double-issue (the #228 invariant)**: a page just allocated is no longer in the free set, so
/// the allocator cannot hand it out again. The property the per-CPU CAS path must preserve atomically.
pub proof fn alloc_no_double_issue(c: Chunk, i: nat)
    requires
        wf(c),
        c.free.contains(i),
    ensures
        !(alloc(c, i)).free.contains(i),
{
}

/// **Double-free is a provable error**: freeing an already-free page leaves the bitmap unchanged but
/// bumps the cached count, so the count no longer matches the bitmap — `DI_SHADOW` catches exactly
/// this. The allocator analogue of `rmap.rs` `under_remove_breaks_wf`.
pub proof fn double_free_breaks_wf(c: Chunk, i: nat)
    requires
        wf(c),
        c.free.contains(i),
    ensures
        !wf(free_page(c, i)),
{
    assert(c.free.insert(i) =~= c.free);
}

/// **Conservation**: the number of allocated pages is `free_count` fewer than the chunk's free set
/// implies — alloc and free move exactly one page between the free and allocated sides, never
/// losing or duplicating one. (`allocated = |bitmap clear bits|`; here, the count bookkeeping.)
pub open spec fn allocated_count(c: Chunk, total: int) -> int {
    total - c.free_count
}

/// Allocating one page increments the allocated count by exactly one (and frees decrement) — the
/// page is conserved, moved from free to allocated.
pub proof fn alloc_conserves(c: Chunk, i: nat, total: int)
    requires
        wf(c),
        c.free.contains(i),
    ensures
        allocated_count(alloc(c, i), total) == allocated_count(c, total) + 1,
{
}

} // verus!
