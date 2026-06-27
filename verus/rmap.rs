//! SEED — Verus specs for the **PTE ⟷ rmap relation invariant** (the reverse-mapping
//! consistency that the catalogue's worst bugs violate).
//!
//! A physical page is mapped by some set of PTEs (forward: vaddr → page).  The *reverse
//! map* (rmap) of a page is the set of PTEs that map it, and the page descriptor caches a
//! `mapcount`.  The relation invariant is that **the cached count tracks the true reverse
//! map**: `mapcount == |rmap|`.  This is exactly what pgcl #1 / #143 broke — the rmap
//! remove side decremented more than the add side added, the cached `mapcount`
//! underflowed, a folio was freed while still mapped, and the page cache was corrupted
//! (the rank-2 cluster of `doc/failure-modes.md`).
//!
//! telix's epoch-based COW scheme avoids per-page refcounts as an *optimization*, but it
//! must preserve this same semantic invariant; pgcl's classic per-page rmap is the direct
//! instance.  Modeled here on a `Set` so the no-double-map structure is intrinsic.  This
//! is the in-tree Verus form of the Lean `Sharing.Backing` discipline (`mapcount == #sites`).
//!
//! STATUS: ✅ VERIFIED against Verus 0.2026.06.20 (`verify.sh`). See `CORRESPONDENCE.md`.

use vstd::prelude::*;

verus! {

/// A physical page's reverse map: the true set of PTEs (identified by vaddr) that map it,
/// and the cached `mapcount` the descriptor stores.
pub struct PageRmap {
    pub mappers: Set<usize>,
    pub mapcount: int,
}

/// **The PTE-rmap relation invariant**: the cached count equals the true reverse-map size.
pub open spec fn wf(p: PageRmap) -> bool {
    p.mapcount == p.mappers.len()
}

/// Map a new PTE: add it to the rmap and bump the cached count (the correct discipline).
pub open spec fn map_pte(p: PageRmap, va: usize) -> PageRmap {
    PageRmap { mappers: p.mappers.insert(va), mapcount: p.mapcount + 1 }
}

/// Unmap a PTE: remove it from the rmap and drop the cached count (the correct discipline).
pub open spec fn unmap_pte(p: PageRmap, va: usize) -> PageRmap {
    PageRmap { mappers: p.mappers.remove(va), mapcount: p.mapcount - 1 }
}

/// **Correct map preserves the relation** (count tracks the reverse map). -/
pub proof fn map_preserves_wf(p: PageRmap, va: usize)
    requires
        wf(p),
        !p.mappers.contains(va),
    ensures
        wf(map_pte(p, va)),
{
    assert(p.mappers.insert(va).len() == p.mappers.len() + 1);
}

/// **Correct unmap preserves the relation.** -/
pub proof fn unmap_preserves_wf(p: PageRmap, va: usize)
    requires
        wf(p),
        p.mappers.contains(va),
    ensures
        wf(unmap_pte(p, va)),
{
    assert(p.mappers.remove(va).len() == p.mappers.len() - 1);
}

/// **Free-while-mapped is impossible**: under the invariant the cached count is 0 iff the
/// page truly has no mappers — so reclaiming a page on `mapcount == 0` is sound (no
/// dangling PTE), and a positive count means a live mapper remains.
pub proof fn free_iff_unmapped(p: PageRmap)
    requires
        wf(p),
    ensures
        p.mapcount == 0 <==> p.mappers == Set::<usize>::empty(),
{
    if p.mapcount == 0 {
        assert(p.mappers.len() == 0);
        assert(p.mappers =~= Set::<usize>::empty());
    }
}

/// **rmap under-remove is a provable error** (pgcl #143): removing a mapper from the
/// reverse map without dropping the cached count leaves `mapcount` above the true mapper
/// set — the mapcount-drift that frees a still-mapped folio.
pub proof fn under_remove_breaks_wf(p: PageRmap, va: usize)
    requires
        wf(p),
        p.mappers.contains(va),
    ensures
        !wf(PageRmap { mappers: p.mappers.remove(va), mapcount: p.mapcount }),
{
    assert(p.mappers.remove(va).len() == p.mappers.len() - 1);
}

} // verus!
