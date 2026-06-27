//! SEED — Verus specs for telix `mm/extent.rs` leaf operations (stage 2: leaf-array,
//! no tree-walking).
//!
//! telix's `insert_entry_at(leaf, pos, entry)` shifts `entries[pos..count]` right by one
//! and writes `entry` at `pos`; `remove_entry_at(leaf, pos)` shifts `entries[pos+1..]`
//! left. On the leaf's *logical content* (the `entry_count` live entries) these are
//! exactly `Seq::insert(pos, entry)` and `Seq::remove(pos)`. We model that content as a
//! `Vec<ExtentEntry>` (telix's fixed `[ExtentEntry; LEAF_CAP]` + `entry_count` is the
//! unboxed representation; the telix side proves its manual-shift code meets this spec)
//! and verify the **leaf-level ordering invariant**: inserting at the sorted position
//! preserves sortedness — the per-leaf analogue of Lean `ExtentMap.insert_ordered` and
//! the Kani `insert_preserves_order`.
//!
//! STATUS: ✅ VERIFIED against Verus 0.2026.06.20 (`verify.sh`). See `CORRESPONDENCE.md`.

use vstd::prelude::*;

verus! {

pub const LEAF_CAP: usize = 15;

#[derive(Clone, Copy)]
pub struct ExtentEntry {
    pub start: usize,
    pub page_count: u16,
}

/// The leaf is sorted by start address (telix keeps `entries[0..entry_count]` sorted).
pub open spec fn sorted(s: Seq<ExtentEntry>) -> bool {
    forall|i: int, j: int| #![trigger s[i], s[j]]
        0 <= i < j < s.len() ==> s[i].start <= s[j].start
}

/// `pos` is the sorted insertion position for `e`: everything before it starts at or
/// before `e`, everything from it on starts at or after `e` (exactly telix's
/// position-finding loop in `insert`).
pub open spec fn is_insert_pos(s: Seq<ExtentEntry>, pos: int, e: ExtentEntry) -> bool {
    &&& 0 <= pos <= s.len()
    &&& forall|i: int| 0 <= i < pos ==> (#[trigger] s[i]).start <= e.start
    &&& forall|i: int| pos <= i < s.len() ==> e.start <= (#[trigger] s[i]).start
}

/// **Inserting at the sorted position preserves sortedness** (the leaf-level invariant).
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

/// **Removing preserves sortedness** (a subsequence of a sorted sequence is sorted).
pub proof fn remove_preserves_sorted(s: Seq<ExtentEntry>, pos: int)
    requires
        sorted(s),
        0 <= pos < s.len(),
    ensures
        sorted(s.remove(pos)),
{
    let s2 = s.remove(pos);
    assert forall|i: int, j: int| 0 <= i < j < s2.len() implies s2[i].start <= s2[j].start by {
        let oi = if i < pos { i } else { i + 1 };
        let oj = if j < pos { j } else { j + 1 };
        assert(s2[i] == s[oi]);
        assert(s2[j] == s[oj]);
    }
}

/// `insert_entry_at`: place `entry` at `pos`, shifting the rest right.  On the logical
/// content this is `Seq::insert`; verified to **preserve the leaf ordering invariant**
/// when `pos` is the sorted position, and to leave room (`< LEAF_CAP`).
pub fn insert_entry_at(entries: &mut Vec<ExtentEntry>, pos: usize, entry: ExtentEntry)
    requires
        pos <= old(entries).len(),
        old(entries).len() < LEAF_CAP,
        sorted(old(entries)@),
        is_insert_pos(old(entries)@, pos as int, entry),
    ensures
        sorted(final(entries)@),
        final(entries)@ == old(entries)@.insert(pos as int, entry),
        final(entries).len() == old(entries).len() + 1,
{
    let ghost s0 = entries@;
    proof {
        insert_preserves_sorted(s0, pos as int, entry);
    }
    entries.insert(pos, entry);
}

/// `remove_entry_at`: remove the entry at `pos`, shifting the rest left.  On the logical
/// content this is `Seq::remove`; verified to preserve sortedness and decrement the count.
pub fn remove_entry_at(entries: &mut Vec<ExtentEntry>, pos: usize)
    requires
        pos < old(entries).len(),
        sorted(old(entries)@),
    ensures
        sorted(final(entries)@),
        final(entries)@ == old(entries)@.remove(pos as int),
        final(entries).len() == old(entries).len() - 1,
{
    let ghost s0 = entries@;
    proof {
        remove_preserves_sorted(s0, pos as int);
    }
    entries.remove(pos);
}

} // verus!
