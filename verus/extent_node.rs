//! SEED — Verus specs for telix `mm/extent.rs` node-through-pointer access (stage 3a:
//! the first raw-pointer rung).
//!
//! This is where the verification meets telix's defining difficulty: the B+-tree nodes
//! live behind raw `*mut` pointers (`alloc_node()` → `*mut u8`, `as_leaf()` →
//! `&'static mut LeafNode`), which is exactly what put the real code outside Aeneas's
//! safe-Rust model.  Verus reasons about such code with a `PointsTo<LeafNode>`
//! *permission* token: holding it makes the otherwise-`unsafe` dereference **sound and
//! checked**.  `leaf_insert_through_ptr` mirrors telix's `let leaf = &mut *leaf_ptr; …`
//! and proves the leaf's sorted invariant is preserved *through the pointer*.
//! `demo_alloc_insert_free` exercises the whole lifecycle — allocate (≈ `alloc_node`),
//! operate through the permission (≈ `as_leaf` + mutate), reclaim (≈ `free_node`) —
//! the slab-allocator-as-a-resource pattern in miniature.
//!
//! STATUS: ✅ VERIFIED against Verus 0.2026.06.20 (`verify.sh`). See `CORRESPONDENCE.md`.

use vstd::prelude::*;
use vstd::simple_pptr::*;

verus! {

pub const LEAF_CAP: usize = 15;

#[derive(Clone, Copy)]
pub struct ExtentEntry {
    pub start: usize,
    pub page_count: u16,
}

pub open spec fn sorted(s: Seq<ExtentEntry>) -> bool {
    forall|i: int, j: int| #![trigger s[i], s[j]]
        0 <= i < j < s.len() ==> s[i].start <= s[j].start
}

pub open spec fn is_insert_pos(s: Seq<ExtentEntry>, pos: int, e: ExtentEntry) -> bool {
    &&& 0 <= pos <= s.len()
    &&& forall|i: int| 0 <= i < pos ==> (#[trigger] s[i]).start <= e.start
    &&& forall|i: int| pos <= i < s.len() ==> e.start <= (#[trigger] s[i]).start
}

pub proof fn insert_preserves_sorted(s: Seq<ExtentEntry>, pos: int, e: ExtentEntry)
    requires
        sorted(s),
        is_insert_pos(s, pos, e),
    ensures
        sorted(s.insert(pos, e)),
{
    let s2 = s.insert(pos, e);
    assert forall|i: int, j: int| 0 <= i < j < s2.len() implies s2[i].start <= s2[j].start by {
        if j < pos {
            assert(s2[i] == s[i]);
            assert(s2[j] == s[j]);
        } else if i < pos && j == pos {
            assert(s2[i] == s[i]);
            assert(s2[j] == e);
        } else if i < pos && j > pos {
            assert(s2[i] == s[i]);
            assert(s2[j] == s[j - 1]);
        } else if i == pos && j > pos {
            assert(s2[i] == e);
            assert(s2[j] == s[j - 1]);
        } else {
            assert(s2[i] == s[i - 1]);
            assert(s2[j] == s[j - 1]);
        }
    }
}

/// A heap-allocated leaf node — its live entries (telix: a fixed `[ExtentEntry;
/// LEAF_CAP]` + `entry_count`; modeled here as the logical content). -/
pub struct LeafNode {
    pub entries: Vec<ExtentEntry>,
}

/// Sorted insert into the leaf's entries (the stage-2 operation, as a node method).
pub fn insert_entry(leaf: &mut LeafNode, pos: usize, entry: ExtentEntry)
    requires
        pos <= old(leaf).entries.len(),
        old(leaf).entries.len() < LEAF_CAP,
        sorted(old(leaf).entries@),
        is_insert_pos(old(leaf).entries@, pos as int, entry),
    ensures
        sorted(final(leaf).entries@),
        final(leaf).entries@ == old(leaf).entries@.insert(pos as int, entry),
{
    let ghost s0 = leaf.entries@;
    proof {
        insert_preserves_sorted(s0, pos as int, entry);
    }
    leaf.entries.insert(pos, entry);
}

/// **The stage-3 result: a leaf operation performed THROUGH A RAW POINTER, sound by a
/// `PointsTo` permission.**  This is the verified form of telix's
/// `let leaf = unsafe { &mut *leaf_ptr }; …` — the sorted invariant is preserved across
/// the (otherwise-unsafe) dereference.
pub fn leaf_insert_through_ptr(
    pptr: PPtr<LeafNode>,
    Tracked(perm): Tracked<&mut PointsTo<LeafNode>>,
    pos: usize,
    entry: ExtentEntry,
)
    requires
        old(perm).pptr() == pptr,
        old(perm).is_init(),
        pos <= old(perm).value().entries.len(),
        old(perm).value().entries.len() < LEAF_CAP,
        sorted(old(perm).value().entries@),
        is_insert_pos(old(perm).value().entries@, pos as int, entry),
    ensures
        final(perm).pptr() == pptr,
        final(perm).is_init(),
        sorted(final(perm).value().entries@),
        final(perm).value().entries@ == old(perm).value().entries@.insert(pos as int, entry),
{
    let mut leaf = pptr.take(Tracked(perm));
    insert_entry(&mut leaf, pos, entry);
    pptr.put(Tracked(perm), leaf);
}

/// **The full node lifecycle, verified**: allocate a leaf, insert one entry through the
/// pointer, then reclaim the node — the `alloc_node` → `as_leaf`+mutate → `free_node`
/// pattern with the allocation modeled as a `PointsTo` resource.
pub fn demo_alloc_insert_free(entry: ExtentEntry) {
    let (pptr, Tracked(mut perm)) = PPtr::new(LeafNode { entries: Vec::new() });
    leaf_insert_through_ptr(pptr, Tracked(&mut perm), 0, entry);
    let leaf = pptr.into_inner(Tracked(perm));
    // `leaf.entries` now holds exactly `[entry]`, sorted; the node is freed.
}

} // verus!
