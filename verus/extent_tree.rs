//! SEED — Verus specs for the **recursive (unbounded-depth) B+-tree structural
//! invariant** (stage 3d).
//!
//! Stages 3a–3c handled single nodes, the two-node split, and the flat leaf chain.  This
//! is the recursive generalization: an arbitrary-depth search tree whose **in-order
//! traversal is one globally sorted extent map**.  It is the Verus port of Lean
//! `proof/Tessera/BTree.lean` (`ExtentTree`, `bst_ordered`) — the same theorem, the same
//! structural induction, now in the in-tree prover and over unbounded depth.  This is the
//! whole-tree ordered-map invariant the catalogue's split/fold family (telix #9, pgcl
//! #7/#8) must preserve as the tree grows.
//!
//! Modeled as a recursive datatype (the *shape* invariant, decoupled from the pointer
//! representation; stages 3a/3b verified the pointer mechanics for one/two nodes).
//!
//! STATUS: ✅ VERIFIED against Verus 0.2026.06.20 (`verify.sh`). See `CORRESPONDENCE.md`.

use vstd::prelude::*;

verus! {

#[derive(PartialEq, Eq, Structural)]
pub struct Entry {
    pub start: usize,
}

pub open spec fn sorted(s: Seq<Entry>) -> bool {
    forall|i: int, j: int| #![trigger s[i], s[j]]
        0 <= i < j < s.len() ==> s[i].start <= s[j].start
}

/// An arbitrary-depth search tree of extents.
pub enum Tree {
    Leaf,
    Node(Box<Tree>, Entry, Box<Tree>),
}

/// In-order traversal — the ordered extent map the tree represents.
pub open spec fn to_seq(t: Tree) -> Seq<Entry>
    decreases t,
{
    match t {
        Tree::Leaf => Seq::empty(),
        Tree::Node(l, e, r) => to_seq(*l) + seq![e] + to_seq(*r),
    }
}

/// The recursive search-tree invariant: left subtree entirely before the pivot, pivot
/// entirely before the right subtree, recursively.
pub open spec fn bst(t: Tree) -> bool
    decreases t,
{
    match t {
        Tree::Leaf => true,
        Tree::Node(l, e, r) => {
            &&& bst(*l)
            &&& bst(*r)
            &&& forall|x: Entry| to_seq(*l).contains(x) ==> x.start <= e.start
            &&& forall|x: Entry| to_seq(*r).contains(x) ==> e.start <= x.start
        }
    }
}

/// `a[i]` is a member of `a`.
proof fn seq_index_contains(a: Seq<Entry>, i: int)
    requires
        0 <= i < a.len(),
    ensures
        a.contains(a[i]),
{
    assert(a[i] == a[i]);
}

/// **Concatenating two sorted sequences, every element of the first ≤ every element of
/// the second, is sorted.** (Stated with `contains` so the tree's quantified separators
/// plug in directly.)
pub proof fn concat_sorted(a: Seq<Entry>, b: Seq<Entry>)
    requires
        sorted(a),
        sorted(b),
        forall|x: Entry, y: Entry| a.contains(x) && b.contains(y) ==> x.start <= y.start,
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
            assert(c[i] == a[i]);
            assert(c[j] == b[j - a.len()]);
            seq_index_contains(a, i);
            seq_index_contains(b, j - a.len());
        }
    }
}

/// **The recursive whole-tree invariant**: a search tree's in-order traversal is one
/// globally sorted extent map — by structural induction over the tree.  The unbounded
/// analogue of `extent_chain.rs` and the Verus twin of Lean `BTree.bst_ordered`.
pub proof fn bst_sorted(t: Tree)
    requires
        bst(t),
    ensures
        sorted(to_seq(t)),
    decreases t,
{
    match t {
        Tree::Leaf => {
            assert(to_seq(t) == Seq::<Entry>::empty());
        }
        Tree::Node(l, e, r) => {
            bst_sorted(*l);
            bst_sorted(*r);
            // (to_seq(l) + [e]) is sorted: every element of to_seq(l) is <= e
            assert(sorted(seq![e])) by {
                assert(seq![e].len() == 1);
            }
            assert forall|x: Entry, y: Entry|
                to_seq(*l).contains(x) && seq![e].contains(y) implies x.start <= y.start by {
                assert(y == e);
            }
            concat_sorted(to_seq(*l), seq![e]);
            // ((to_seq(l)+[e]) + to_seq(r)) is sorted: every element of the left part <= every of r
            assert forall|x: Entry, y: Entry|
                (to_seq(*l) + seq![e]).contains(x) && to_seq(*r).contains(y) implies x.start <= y.start by {
                if (to_seq(*l) + seq![e]).contains(x) {
                    if to_seq(*l).contains(x) {
                        assert(x.start <= e.start);
                        assert(e.start <= y.start);
                    } else {
                        assert(x == e);
                        assert(e.start <= y.start);
                    }
                }
            }
            concat_sorted(to_seq(*l) + seq![e], to_seq(*r));
            assert(to_seq(t) == (to_seq(*l) + seq![e]) + to_seq(*r));
        }
    }
}

/// Recursive BST insert: descend by key, place the new entry at a leaf.
pub open spec fn insert(t: Tree, ne: Entry) -> Tree
    decreases t,
{
    match t {
        Tree::Leaf => Tree::Node(Box::new(Tree::Leaf), ne, Box::new(Tree::Leaf)),
        Tree::Node(l, e, r) =>
            if ne.start <= e.start {
                Tree::Node(Box::new(insert(*l, ne)), e, r)
            } else {
                Tree::Node(l, e, Box::new(insert(*r, ne)))
            },
    }
}

/// **Insert loses nothing and adds exactly `ne`**: the in-order content afterwards is the
/// old content plus the new entry (the anti-entry-loss property at the recursive level).
pub proof fn insert_contains(t: Tree, ne: Entry, x: Entry)
    ensures
        to_seq(insert(t, ne)).contains(x) <==> (x == ne || to_seq(t).contains(x)),
    decreases t,
{
    broadcast use vstd::seq_lib::group_seq_properties;
    match t {
        Tree::Leaf => {}
        Tree::Node(l, e, r) => {
            if ne.start <= e.start {
                insert_contains(*l, ne, x);
            } else {
                insert_contains(*r, ne, x);
            }
        }
    }
}

/// **Recursive insert preserves the search-tree invariant** — the tree-growth operation
/// keeps the whole-tree ordering (so, with `bst_sorted`, the flattened map stays sorted).
pub proof fn insert_preserves_bst(t: Tree, ne: Entry)
    requires
        bst(t),
    ensures
        bst(insert(t, ne)),
    decreases t,
{
    match t {
        Tree::Leaf => {}
        Tree::Node(l, e, r) => {
            if ne.start <= e.start {
                insert_preserves_bst(*l, ne);
                assert forall|x: Entry|
                    to_seq(insert(*l, ne)).contains(x) implies x.start <= e.start by {
                    insert_contains(*l, ne, x);
                }
            } else {
                insert_preserves_bst(*r, ne);
                assert forall|x: Entry|
                    to_seq(insert(*r, ne)).contains(x) implies e.start <= x.start by {
                    insert_contains(*r, ne, x);
                }
            }
        }
    }
}

} // verus!
