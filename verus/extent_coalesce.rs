//! SEED — Verus specs for telix `mm/extent.rs` coalescing (stage 1: pointer-free logic).
//!
//! The struct definitions and method *bodies* are VERBATIM from
//! `kernel/src/mm/extent.rs`; only `PhysAddr` and `page_size` are stubbed (the leaf
//! kernel deps — telix-side, re-point them at `mm::page`). The Verus `ensures`/`proof`
//! clauses encode soundness properties already proved twice in tessera, independently:
//!
//!   * Lean 4: `proof/Tessera/{Frames,ExtentMap}.lean` (the abstract theorems);
//!   * Kani:   `rust/extent-kani/coalesce.rs` harnesses `coalesce_is_sound` /
//!             `union_contains_both_operands` (bounded model-check of the verbatim code).
//!
//! See `CORRESPONDENCE.md` for the clause-by-clause map.
//!
//! STATUS: DRAFT pending verification against a Verus toolchain. The *properties* are
//! independently proven true; what this file validates is the Verus syntax/proof tactics.
//! tessera is installing Verus to bring this to a verifying state before final handoff.

use vstd::prelude::*;

verus! {

// ---- stubbed leaf deps (telix-side: re-point at mm::page::PhysAddr / page::page_size) ----
#[derive(PartialEq, Eq)]
pub struct PhysAddr(pub usize);

impl PhysAddr {
    pub fn new(v: usize) -> (r: Self)
        ensures r.0 == v,
    {
        PhysAddr(v)
    }

    pub fn as_usize(self) -> (r: usize)
        ensures r == self.0,
    {
        self.0
    }
}

pub const PAGE_SIZE: usize = 4096;

// ==================== VERBATIM logic from kernel/src/mm/extent.rs ====================
#[derive(PartialEq, Eq)]
pub struct ExtentFlags(pub u16);

impl ExtentFlags {
    pub fn contains(self, other: Self) -> (r: bool)
        ensures r == ((self.0 & other.0) == other.0),
    {
        (self.0 & other.0) == other.0
    }

    pub fn union(self, other: Self) -> (r: Self)
        ensures r.0 == (self.0 | other.0),
    {
        ExtentFlags(self.0 | other.0)
    }
}

/// `union` is an upper bound: the merged flags contain both operands, so a coalesce
/// never silently drops a flag.  (Kani: `union_contains_both_operands`.)
pub proof fn union_contains_both(a: ExtentFlags, b: ExtentFlags)
    ensures
        ((a.0 | b.0) & a.0) == a.0,
        ((a.0 | b.0) & b.0) == b.0,
{
    assert(((a.0 | b.0) & a.0) == a.0) by (bit_vector);
    assert(((a.0 | b.0) & b.0) == b.0) by (bit_vector);
}

pub struct ExtentEntry {
    pub start: PhysAddr,
    pub page_count: u16,
    pub flags: ExtentFlags,
    pub refcount: u16,
    pub object_id: u64,
    pub object_offset: u32,
}

impl ExtentEntry {
    /// Physical address one past the end of this extent.
    pub fn end(&self) -> (r: PhysAddr)
        requires
            self.start.0 + (self.page_count as usize) * PAGE_SIZE <= usize::MAX,
        ensures
            r.0 == self.start.0 + (self.page_count as usize) * PAGE_SIZE,
    {
        PhysAddr::new(self.start.as_usize() + (self.page_count as usize) * PAGE_SIZE)
    }

    /// Whether this extent can be coalesced with `other` (which must start immediately
    /// after `self`).  The `ensures` is the **soundness obligation** mirroring the Kani
    /// harness `coalesce_is_sound`: a `true` result means the extents are physically
    /// adjacent, same non-zero backing object, and identical state — so collapsing them
    /// into `[self.start, other.end)` is well-formed.
    pub fn can_coalesce(&self, other: &Self) -> (r: bool)
        requires
            self.start.0 + (self.page_count as usize) * PAGE_SIZE <= usize::MAX,
            (self.object_offset as u64) + (self.page_count as u64) <= u32::MAX as u64,
        ensures
            r ==> self.start.0 + (self.page_count as usize) * PAGE_SIZE == other.start.0,
            r ==> self.object_id == other.object_id,
            r ==> self.object_id != 0,
            r ==> self.flags.0 == other.flags.0,
            r ==> self.refcount == other.refcount,
            r ==> self.object_offset + (self.page_count as u32) == other.object_offset,
    {
        self.end() == other.start
            && self.flags == other.flags
            && self.refcount == other.refcount
            && self.object_id == other.object_id
            && self.object_id != 0
            && self.object_offset + self.page_count as u32 == other.object_offset
    }
}

} // verus!
