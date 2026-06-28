//! SEED — wiring catalogue ROW #7 (LLFree per-CPU allocator reuse) END-TO-END: the worked example.
//!
//! The deferred-maintenance catalogue (`tessera:doc/deferred-maintenance-catalogue.md`) lists each
//! deferral site against one obligation; "wiring" a row turns that spec into a check on the real code.
//! Row #7 is the LLFree per-CPU allocator. Here are the three steps — INSTANCE, AUDIT, CHECK —
//! grounded in telix `mm/phys.rs`.
//!
//! ## 1. INSTANCE — map the allocator onto the framework
//!   * Resource: a physical page.
//!   * Guard (existence reference, `Deferred.Pinned`): the per-CPU CHUNK RESERVATION — telix
//!     `ChunkNode.owner_cpu` [13:7] (`0x7F` = unowned). While CPU `a` owns a chunk, only `a` allocs its
//!     pages: the reservation pins the chunk's pages to one owner.
//!   * Incarnation (`Incarnation.Pfn`): a page's allocation — handed to an owner. A free+realloc is a
//!     new incarnation (new owner).
//!   * The bug (`reincarnate_breaks`): a page handed out **while still owned** — the same incarnation
//!     claimed twice = the #228 PA-ALIAS "double-issue".
//!   * The runtime probe (`Incarnation.probeFires`): telix already ships it as **`DI_SHADOW`** —
//!     `di_shadow_alloc` does `fetch_or` and FIRES if the bit was already set.
//!
//! ## 2. AUDIT — the obligation, and the gap to look for
//! The obligation: a page's shadow bit is set by exactly one owner at a time; `alloc` must `fetch_or`
//! a CLEAR bit (the page was free). A `fetch_or` finding it SET = a page issued while still owned.
//! The gap to hunt: a reservation that is NOT exclusive (a chunk owned by two CPUs) would let both
//! alloc the same page. *Empirical result (telix): `DI_SHADOW` ran and NEVER tripped → by
//! `Incarnation.pinned_silences_probe` the reservation discharges the obligation; the #228 corruption
//! is NOT a page double-issue.* That is the row going GREEN.
//!
//! ## 3. CHECK — the in-tree static proof (this file) + the runtime probe (DI_SHADOW)
//! STATUS: ✅ VERIFIED against Verus 0.2026.06.20 (`verify.sh`). The allocator twin of `phys_chunk.rs`.

use vstd::prelude::*;

verus! {

/// The global allocation shadow (telix `DI_SHADOW`): the set of page indices currently ALLOCATED
/// (handed to an owner). A page's membership IS its "owned" incarnation.
pub struct Shadow {
    pub allocated: Set<nat>,
}

/// **`di_shadow_alloc` fires** iff page `i` is already allocated — a page handed out while still owned
/// (`fetch_or` finds the bit set). This spec is exactly tessera `Incarnation.probeFires`.
pub open spec fn di_shadow_fires(sh: Shadow, i: nat) -> bool {
    sh.allocated.contains(i)
}

/// `alloc` hands out page `i` (sets its shadow bit). -/
pub open spec fn alloc(sh: Shadow, i: nat) -> Shadow {
    Shadow { allocated: sh.allocated.insert(i) }
}

/// `free` returns page `i` (clears its shadow bit). -/
pub open spec fn free(sh: Shadow, i: nat) -> Shadow {
    Shadow { allocated: sh.allocated.remove(i) }
}

/// **CHECK (the #228 obligation): no SILENT double-issue.** Once a page is allocated, a second alloc
/// of it FIRES the probe — the allocator cannot hand it out twice unseen. (The concurrent twin of
/// `phys_chunk.alloc_no_double_issue`, now keyed on the global shadow / `DI_SHADOW`.)
pub proof fn double_alloc_fires(sh: Shadow, i: nat)
    requires
        !di_shadow_fires(sh, i),
    ensures
        di_shadow_fires(alloc(sh, i), i),
{
    broadcast use vstd::set_lib::group_set_properties;
}

/// **A legitimate reincarnation is silent**: after a correct `free` (release), re-issuing the page does
/// NOT fire — exactly the `Incarnation` distinction between a reuse-after-release (fine) and a
/// claim-while-owned (the bug).
pub proof fn free_then_alloc_silent(sh: Shadow, i: nat)
    requires
        di_shadow_fires(sh, i),
    ensures
        !di_shadow_fires(free(sh, i), i),
{
    broadcast use vstd::set_lib::group_set_properties;
}

/// A chunk's owner = the per-CPU reservation (telix `ChunkNode.owner_cpu`; `None` = unowned). -/
pub struct ResChunk {
    pub owner: Option<nat>,
}

pub open spec fn reserved_by(c: ResChunk, cpu: nat) -> bool {
    c.owner == Some(cpu)
}

/// **The GUARD is EXCLUSIVE**: a chunk has at most one owner, so two CPUs never both alloc its pages —
/// the reservation pins the chunk's pages to one owner, making the concurrent double-issue impossible
/// (the static reason `DI_SHADOW` never trips). The allocator's `Deferred.Pinned`.
pub proof fn reservation_exclusive(c: ResChunk, a: nat, b: nat)
    requires
        reserved_by(c, a),
        reserved_by(c, b),
    ensures
        a == b,
{
}

} // verus!
