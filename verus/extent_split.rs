//! SEED — Verus specs for telix `mm/extent.rs` leaf split (stage 3b: multi-node /
//! two-permission reasoning).
//!
//! When a leaf is full, telix's `split_leaf_and_insert` builds the combined sorted
//! sequence (the old entries with the new one inserted = `Seq::insert(pos, entry)`),
//! allocates a *new* sibling leaf, keeps the lower half (`tmp[0..mid]`) in the old leaf,
//! and moves the upper half (`tmp[mid..]`) to the new leaf.  The correctness heart — the
//! place entries get silently lost or duplicated if the index arithmetic is wrong — is
//! the **partition**: the two halves are each sorted and together are exactly the
//! original sequence, with `left.last() <= right.first()` as a valid separator key.
//!
//! `split_sorted` proves that partition (a pure sequence lemma).  `split_leaf` performs
//! it through **two `PointsTo` permissions held at once** — the old node's and the
//! freshly-allocated sibling's — the multi-node step telix's B+-tree growth needs.
//!
//! STATUS: ✅ VERIFIED against Verus 0.2026.06.20 (`verify.sh`). See `CORRESPONDENCE.md`.

use vstd::prelude::*;
use vstd::simple_pptr::*;

verus! {

#[derive(Clone, Copy)]
pub struct ExtentEntry {
    pub start: usize,
    pub page_count: u16,
}

pub open spec fn sorted(s: Seq<ExtentEntry>) -> bool {
    forall|i: int, j: int| #![trigger s[i], s[j]]
        0 <= i < j < s.len() ==> s[i].start <= s[j].start
}

pub struct LeafNode {
    pub entries: Vec<ExtentEntry>,
}

/// **The partition lemma**: splitting a sorted sequence at `mid` yields two sorted
/// halves whose concatenation is the original, with `s[mid-1] <= s[mid]` the separator.
pub proof fn split_sorted(s: Seq<ExtentEntry>, mid: int)
    requires
        sorted(s),
        0 <= mid <= s.len(),
    ensures
        sorted(s.subrange(0, mid)),
        sorted(s.subrange(mid, s.len() as int)),
        s.subrange(0, mid) + s.subrange(mid, s.len() as int) == s,
        0 < mid < s.len() ==> s[mid - 1].start <= s[mid].start,
{
    let left = s.subrange(0, mid);
    let right = s.subrange(mid, s.len() as int);
    assert forall|i: int, j: int| 0 <= i < j < left.len() implies left[i].start <= left[j].start by {
        assert(left[i] == s[i]);
        assert(left[j] == s[j]);
    }
    assert forall|i: int, j: int| 0 <= i < j < right.len() implies right[i].start <= right[j].start by {
        assert(right[i] == s[mid + i]);
        assert(right[j] == s[mid + j]);
    }
    assert(left + right =~= s);
}

/// **Leaf split through two permissions**: keep the lower half in the old leaf, move the
/// upper half into a freshly-allocated sibling.  Verifies that **no entry is lost or
/// duplicated** (the two halves concatenate to the combined input), each half is sorted,
/// and the separator holds — telix's `split_leaf_and_insert` data movement, machine-checked.
pub fn split_leaf(
    old_ptr: PPtr<LeafNode>,
    Tracked(old_perm): Tracked<&mut PointsTo<LeafNode>>,
    combined: Vec<ExtentEntry>,
) -> (new: (PPtr<LeafNode>, Tracked<PointsTo<LeafNode>>))
    requires
        old(old_perm).pptr() == old_ptr,
        old(old_perm).is_init(),
        sorted(combined@),
        combined.len() >= 2,  // a real split needs ≥ 2 entries (telix splits a *full* leaf)
    ensures
        final(old_perm).pptr() == old_ptr,
        final(old_perm).is_init(),
        new.1@.pptr() == new.0,
        new.1@.is_init(),
        // content preserved: lower half ++ upper half == the combined input
        final(old_perm).value().entries@ + new.1@.value().entries@ == combined@,
        // each half sorted
        sorted(final(old_perm).value().entries@),
        sorted(new.1@.value().entries@),
        // both halves non-empty and the separator holds (valid B+-tree split + promote key)
        final(old_perm).value().entries@.len() >= 1,
        new.1@.value().entries@.len() >= 1,
        final(old_perm).value().entries@.last().start <= new.1@.value().entries@[0].start,
{
    let total = combined.len();
    let mid = total / 2;
    proof {
        split_sorted(combined@, mid as int);
    }

    // build the lower half: left = combined[0..mid]
    let mut left: Vec<ExtentEntry> = Vec::new();
    let mut k: usize = 0;
    while k < mid
        invariant
            0 <= k <= mid,
            mid <= combined.len(),
            left@ == combined@.subrange(0, k as int),
        decreases mid - k,
    {
        left.push(combined[k]);
        k += 1;
    }

    // build the upper half: right = combined[mid..total]
    let mut right: Vec<ExtentEntry> = Vec::new();
    let mut k2: usize = mid;
    while k2 < total
        invariant
            mid <= k2 <= total,
            total == combined.len(),
            right@ == combined@.subrange(mid as int, k2 as int),
        decreases total - k2,
    {
        right.push(combined[k2]);
        k2 += 1;
    }

    // write the lower half into the old leaf (through its permission)
    let mut old_leaf = old_ptr.take(Tracked(old_perm));
    old_leaf.entries = left;
    old_ptr.put(Tracked(old_perm), old_leaf);

    // allocate the sibling holding the upper half (≈ alloc_node + fill)
    let (new_ptr, Tracked(new_perm)) = PPtr::new(LeafNode { entries: right });
    (new_ptr, Tracked(new_perm))
}

} // verus!
