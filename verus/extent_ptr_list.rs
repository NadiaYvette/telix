//! SEED — the UNBOUNDED doubly-linked leaf chain (the piece `extent_link.rs` deferred).
//!
//! `extent_link.rs` verified the *bounded* sibling splice — back-pointer consistency across one
//! adjacency (2–3 `PointsTo` held at once) — and explicitly deferred "an unbounded chain-wide
//! doubly-linked invariant (every node's back-pointer agrees along an arbitrary-length list) …
//! it needs a heap/ghost-map model of all permissions at once."  This module is that piece.
//!
//! The technique (same recursive permission collection as `extent_ptr_tree.rs`): own the chain
//! **forward** recursively — `ListPerm` holds a node's `PointsTo` plus the `ListPerm` for the
//! tail starting at its `next` — and capture the back-pointer by **checking each node's `prev`
//! field against its structural predecessor**, threaded as a parameter.  No `prev` pointer is
//! *owned* (that would alias the forward ownership); it is a value the invariant validates.  So
//! `wf(head, prev)` says: this is `head`'s permission, `head.prev == prev`, and the tail is wf for
//! `head.next` with predecessor `head` — i.e. the full chain-wide `a.next.prev == a`, unbounded.
//!
//! STATUS: foundation + back-pointer extraction; see `verify.sh`.

use vstd::prelude::*;
use vstd::simple_pptr::*;

verus! {

/// A doubly-linked leaf node: forward (`next`) and backward (`prev`) sibling links.
pub struct LeafNode {
    pub next: Option<PPtr<LeafNode>>,
    pub prev: Option<PPtr<LeafNode>>,
}

/// **The recursive permission collection for the whole chain.**  `points_to` is the permission
/// for this node; `tail` is, recursively, the permission collection for the rest of the chain
/// starting at this node's `next`.  (Forward-owning: `prev` is validated, not owned.)
pub tracked struct ListPerm {
    pub points_to: PointsTo<LeafNode>,
    pub tail: Option<Box<ListPerm>>,
}

impl ListPerm {
    /// **The chain-wide doubly-linked invariant.**  `wf(head, prev)`: this permission governs
    /// `head`, the node is initialized, its `prev` field equals the expected predecessor `prev`,
    /// and recursively the tail is wf for `head.next` with predecessor `head`.  Unfolding this all
    /// the way down is exactly `∀ adjacent a→b in the chain: b.prev == a` — for ANY length.
    pub open spec fn wf(self, head: PPtr<LeafNode>, prev: Option<PPtr<LeafNode>>) -> bool
        decreases self,
    {
        &&& self.points_to.pptr() == head
        &&& self.points_to.is_init()
        &&& self.points_to.value().prev == prev
        &&& match (self.points_to.value().next, self.tail) {
            (Some(nptr), Some(tperm)) => tperm.wf(nptr, Some(head)),
            (None, None) => true,
            _ => false,
        }
    }

    /// The sequence of node addresses in chain order (recursive over the permission collection).
    pub open spec fn to_seq(self) -> Seq<PPtr<LeafNode>>
        decreases self,
    {
        match self.tail {
            Some(t) => seq![self.points_to.pptr()].add(t.to_seq()),
            None => seq![self.points_to.pptr()],
        }
    }
}

/// **The back-pointer invariant, extracted from the global `wf`**: at any node of a well-formed
/// chain, if it has a successor, that successor's `prev` points back at it — `a.next.prev == a`.
/// This is the corruption `extent_link.rs` guards against one node at a time, here a consequence
/// of the whole-chain invariant at unbounded depth.
pub proof fn back_pointer_holds(perm: ListPerm, head: PPtr<LeafNode>, prev: Option<PPtr<LeafNode>>)
    requires
        perm.wf(head, prev),
    ensures
        match (perm.points_to.value().next, perm.tail) {
            (Some(nptr), Some(tperm)) => tperm.points_to.value().prev == Some(head),
            _ => true,
        },
{
    match (perm.points_to.value().next, &perm.tail) {
        (Some(nptr), Some(tperm)) => {
            assert(tperm.wf(nptr, Some(head)));
        }
        _ => {}
    }
}

/// A well-formed chain always has at least its head (the abstract order is non-empty).
pub proof fn to_seq_nonempty(perm: ListPerm)
    ensures
        perm.to_seq().len() >= 1,
    decreases perm,
{
}

/// **Recursive traversal of the unbounded chain**, through the raw `next` pointers, each deref
/// sound via its slice of the permission collection: walk to the tail and return the last node's
/// address, proven to equal `to_seq().last()`.  The doubly-linked analogue of the tree's
/// `contains` — a sound walk over an arbitrary-length `*mut` chain.
pub fn last_ptr(
    head: PPtr<LeafNode>,
    Tracked(perm): Tracked<&ListPerm>,
    Ghost(prev): Ghost<Option<PPtr<LeafNode>>>,
) -> (res: PPtr<LeafNode>)
    requires
        perm.wf(head, prev),
    ensures
        res == perm.to_seq().last(),
    decreases perm,
{
    let node = head.borrow(Tracked(&perm.points_to));
    match node.next {
        Some(nptr) => {
            let tracked tperm = perm.tail.tracked_borrow();
            let res = last_ptr(nptr, Tracked(tperm), Ghost(Some(head)));
            proof { to_seq_nonempty(**tperm); }
            res
        }
        None => head,
    }
}

/// **Prepend a node to the chain, maintaining the doubly-linked invariant.**  The corruption
/// point: the new node must point forward at the old head AND the old head's `prev` must be
/// updated to point back at the new node — drop that back-pointer write and the chain silently
/// desynchronizes.  Verified to re-establish `wf` for the whole (unbounded) chain and to prepend
/// exactly the new node to the abstract order.
pub fn push_front(head: PPtr<LeafNode>, Tracked(perm): Tracked<ListPerm>)
    -> (res: (PPtr<LeafNode>, Tracked<ListPerm>))
    requires
        perm.wf(head, None),
    ensures
        res.1@.wf(res.0, None),
        res.1@.to_seq() == seq![res.0].add(perm.to_seq()),
{
    let (new_ptr, Tracked(new_perm)) =
        PPtr::<LeafNode>::new(LeafNode { next: Some(head), prev: None });
    let tracked ListPerm { points_to: mut hpt, tail } = perm;
    // update the OLD head's back-pointer to the new node (the must-not-drop write)
    let mut h = head.take(Tracked(&mut hpt));
    h.prev = Some(new_ptr);
    head.put(Tracked(&mut hpt), h);
    let tracked old_chain = ListPerm { points_to: hpt, tail };
    let tracked res = ListPerm { points_to: new_perm, tail: Some(Box::new(old_chain)) };
    proof {
        assert(hpt.pptr() == head);
        assert(hpt.value().prev == Some(new_ptr));
        assert(hpt.value().next == perm.points_to.value().next);
        assert(old_chain.wf(head, Some(new_ptr)));
        assert(old_chain.to_seq() =~= perm.to_seq());
        assert(res.to_seq() =~= seq![new_ptr].add(perm.to_seq()));
    }
    (new_ptr, Tracked(res))
}

} // verus!
