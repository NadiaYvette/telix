//! SEED — Verus specs for the **cross-mm aggregate-refcount invariant**: pgcl #143's
//! free-while-mapped, at *folio (cluster)* granularity across multiple address spaces.
//!
//! `rmap.rs` proves the relation for ONE page's mappers (`mapcount == |rmap|`).  #143 lives one
//! level up: a PGCL **cluster** (one `struct page` backing `PAGE_MMUCOUNT` hardware sub-PTEs) is
//! shared across **several mms** (the fork parent + children of the live -smp8 reproducer), and
//! carries a single per-cluster **aggregate refcount**.  The bug is that the cluster is FREED
//! (`refcount → 0`) while a sibling mm's sub-PTE still maps it — the deferred `folio_put` in
//! `tlb_finish_mmu` racing a sibling, dropping the aggregate to 0 without seeing the live mapping.
//!
//! This module states the **gate** that rules it out: the aggregate refcount equals the TOTAL
//! live sub-PTE mappings summed over *all* mms, so `refcount == 0 ⟺ !folio_mapped()`.  It is the
//! sequential (∀-state) complement of the concurrent (∀-interleaving) Iris proof in
//! tessera `property2/coq/rmap_defer.v` — together: the runtime `dec_and_test`-on-`folio_mapped`
//! gate is sound in every state (here) and under every thread interleaving (there).
//!
//! STATUS: ✅ VERIFIED against Verus 0.2026.06.20 (`verify.sh`). See `CORRESPONDENCE.md`.

use vstd::prelude::*;

verus! {

/// A shared cluster (folio): the set of live sub-PTE mappings ACROSS ALL mms — each mapping is
/// `(mm_id, sub_pte_index)` — and the per-cluster aggregate refcount the descriptor holds.
pub struct ClusterRmap {
    pub mappers: Set<(nat, nat)>,
    pub refcount: int,
}

/// **The cross-mm aggregate invariant**: the per-cluster refcount equals the TOTAL number of
/// live sub-PTE mappings, summed across every mm that shares the cluster.
pub open spec fn wf(c: ClusterRmap) -> bool {
    c.refcount == c.mappers.len()
}

/// `folio_mapped(folio)`: some mm still holds a live sub-PTE for the cluster.
pub open spec fn folio_mapped(c: ClusterRmap) -> bool {
    c.mappers.len() > 0
}

/// mm `mm` maps the cluster (has at least one live sub-PTE).
pub open spec fn mm_maps(c: ClusterRmap, mm: nat) -> bool {
    exists |s: nat| c.mappers.contains((mm, s))
}

/// **The aggregate gate is sound**: `refcount == 0` iff no mm maps the cluster — so freeing on
/// `refcount == 0` is *exactly* freeing on `!folio_mapped()`.  This is the sequential statement
/// of what the runtime `dec_and_test`-on-`folio_mapped()` gate enforces; the unbounded concurrent
/// version is the Iris `rmap_defer.rmap_defer_spec` / `no_free_while_referenced`.
pub proof fn free_iff_unmapped(c: ClusterRmap)
    requires
        wf(c),
    ensures
        c.refcount == 0 <==> !folio_mapped(c),
{
    broadcast use vstd::set_lib::group_set_properties;
}

/// **Cross-mm safety**: if ANY mm still maps the cluster, the aggregate refcount is positive — so
/// a deferred put cannot free it.  This is the gate #143 violated: a sibling mm's live sub-PTE
/// keeps the cluster pinned.
pub proof fn mapped_implies_refcount_pos(c: ClusterRmap, b: nat)
    requires
        wf(c),
        mm_maps(c, b),
    ensures
        c.refcount > 0,
{
    broadcast use vstd::set_lib::group_set_properties;
    let s = choose |s: nat| c.mappers.contains((b, s));
    assert(c.mappers.contains((b, s)));
}

/// **Two sharers ⟹ refcount ≥ 2**: if two DISTINCT mms map the cluster (the fork parent+child of
/// #143), the aggregate refcount is at least 2 — so a SINGLE deferred put (one decrement)
/// provably cannot reach 0.  The cross-mm safety margin a correct aggregate refcount provides.
pub proof fn two_sharers_refcount_ge2(c: ClusterRmap, a: nat, b: nat)
    requires
        wf(c),
        a != b,
        mm_maps(c, a),
        mm_maps(c, b),
    ensures
        c.refcount >= 2,
{
    broadcast use vstd::set_lib::group_set_properties;
    let sa = choose |s: nat| c.mappers.contains((a, s));
    let sb = choose |s: nat| c.mappers.contains((b, s));
    assert(c.mappers.contains((a, sa)));
    assert(c.mappers.contains((b, sb)));
    assert((a, sa) != (b, sb));
    assert(c.mappers.remove((a, sa)).contains((b, sb)));
    assert(c.mappers.len() == c.mappers.remove((a, sa)).len() + 1);
}

/// **#143 as a provable invariant violation** (the litmus): a cluster that is FREED
/// (`refcount == 0`) while STILL MAPPED (`folio_mapped`) cannot satisfy the aggregate invariant.
/// This is the bad state the bug reaches — an under-counted aggregate refcount (the deferred put
/// dropped it to 0 while a sibling sub-PTE remained) is *exactly* a `wf` violation.  The
/// `verus/rmap.rs` `under_remove_breaks_wf` analogue, lifted to the cross-mm cluster.
pub proof fn freed_while_mapped_breaks_wf(c: ClusterRmap)
    requires
        folio_mapped(c),
        c.refcount == 0,
    ensures
        !wf(c),
{
    broadcast use vstd::set_lib::group_set_properties;
}

} // verus!
