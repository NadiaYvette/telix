//! SEED — Verus specs for the telix `mm/extent.rs` leaf chain (stage 3c: the whole-tree
//! structural invariant).
//!
//! telix's leaves form an ordered chain (`LeafNode::next`), and the B+-tree's entire
//! logical content is the concatenation of the leaves' contents in chain order.  The
//! whole-tree correctness property — the structural analogue of `ExtentMap.Ordered` /
//! Lean `BTree.bst_ordered` (in-order traversal is sorted) — is: if every leaf is sorted
//! and adjacent leaves are separated (`leaf[i].last <= leaf[i+1].first`), then the
//! flattened chain is a single globally-sorted extent map.  `chain_flatten_sorted` proves
//! exactly that, by induction over the chain.  It connects the multi-node B+-tree back to
//! the ordered-map abstraction that stage 1 (`ExtentMap.WFI_imp_WF`) refines to Layer A.
//!
//! STATUS: ✅ VERIFIED against Verus 0.2026.06.20 (`verify.sh`). See `CORRESPONDENCE.md`.

use vstd::prelude::*;

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

/// **Concatenating two sorted segments with a separator is sorted.** The building block:
/// two adjacent leaves whose boundary is ordered form a sorted run.
pub proof fn concat_sorted(a: Seq<ExtentEntry>, b: Seq<ExtentEntry>)
    requires
        sorted(a),
        sorted(b),
        a.len() > 0 && b.len() > 0 ==> a.last().start <= b[0].start,
    ensures
        sorted(a + b),
{
    let c = a + b;
    assert forall|i: int, j: int| 0 <= i < j < c.len() implies c[i].start <= c[j].start by {
        if j < a.len() {
            assert(c[i] == a[i]);
            assert(c[j] == a[j]);
        } else if i >= a.len() {
            assert(c[i] == b[i - a.len()]);
            assert(c[j] == b[j - a.len()]);
        } else {
            // i < a.len() <= j: both segments are non-empty here
            assert(c[i] == a[i]);
            assert(c[j] == b[j - a.len()]);
            assert(a[i].start <= a[a.len() - 1].start);   // sorted(a)
            assert(a.last() == a[a.len() - 1]);
            assert(b[0].start <= b[j - a.len()].start);   // sorted(b)
        }
    }
}

/// The B+-tree's full content: the leaves' contents concatenated in chain order.
pub open spec fn flatten(chain: Seq<Seq<ExtentEntry>>) -> Seq<ExtentEntry>
    decreases chain.len(),
{
    if chain.len() == 0 {
        Seq::<ExtentEntry>::empty()
    } else {
        chain[0] + flatten(chain.subrange(1, chain.len() as int))
    }
}

/// A well-formed leaf chain: every leaf non-empty and sorted, and adjacent leaves
/// separated (the B+-tree key order across leaves).
pub open spec fn chain_wf(chain: Seq<Seq<ExtentEntry>>) -> bool {
    &&& forall|i: int| 0 <= i < chain.len() ==> (#[trigger] chain[i]).len() > 0
    &&& forall|i: int| 0 <= i < chain.len() ==> sorted(#[trigger] chain[i])
    &&& forall|i: int|
            0 <= i < chain.len() - 1 ==> (#[trigger] chain[i]).last().start <= chain[i + 1][0].start
}

/// If a chain is non-empty (with a non-empty first leaf), the flattened content begins
/// with that leaf's first entry.
pub proof fn flatten_first(chain: Seq<Seq<ExtentEntry>>)
    requires
        chain.len() > 0,
        chain[0].len() > 0,
    ensures
        flatten(chain).len() > 0,
        flatten(chain)[0] == chain[0][0],
{
    // flatten(chain) == chain[0] + flatten(rest); chain[0] non-empty ⇒ its head leads.
}

/// **The whole-tree structural invariant**: a well-formed leaf chain flattens to a single
/// globally-sorted extent map — the multi-node analogue of `ExtentMap.Ordered`.
pub proof fn chain_flatten_sorted(chain: Seq<Seq<ExtentEntry>>)
    requires
        chain_wf(chain),
    ensures
        sorted(flatten(chain)),
    decreases chain.len(),
{
    if chain.len() == 0 {
        assert(flatten(chain) == Seq::<ExtentEntry>::empty());
    } else {
        let rest = chain.subrange(1, chain.len() as int);
        // rest is well-formed (shifted-index restriction of chain_wf)
        assert(chain_wf(rest)) by {
            assert forall|i: int| 0 <= i < rest.len() implies (#[trigger] rest[i]).len() > 0 by {
                assert(rest[i] == chain[i + 1]);
            }
            assert forall|i: int| 0 <= i < rest.len() implies sorted(#[trigger] rest[i]) by {
                assert(rest[i] == chain[i + 1]);
            }
            assert forall|i: int|
                0 <= i < rest.len() - 1 implies (#[trigger] rest[i]).last().start <= rest[i + 1][0].start by {
                assert(rest[i] == chain[i + 1]);
                assert(rest[i + 1] == chain[i + 2]);
            }
        }
        chain_flatten_sorted(rest);
        // separator between chain[0] and the rest's flatten (when rest is non-empty)
        if rest.len() > 0 {
            flatten_first(rest);
            assert(rest[0] == chain[1]);
            assert(flatten(rest)[0] == chain[1][0]);
            assert(chain[0].last().start <= chain[1][0].start);
        }
        concat_sorted(chain[0], flatten(rest));
        assert(flatten(chain) == chain[0] + flatten(rest));
    }
}

} // verus!
