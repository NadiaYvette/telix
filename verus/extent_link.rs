//! SEED — Verus specs for the telix `mm/extent.rs` leaf-chain LINKING step (stage 3d:
//! the doubly-linked sibling pointers).
//!
//! telix's leaves form a *doubly*-linked list: `LeafNode { next, prev }` raw pointers.
//! When `split_leaf_and_insert` allocates a sibling, it splices it into the chain with
//! exactly three pointer writes:
//!     new_leaf.next = old.next;       // new inherits old's successor
//!     new_leaf.prev = leaf_ptr;       // new points back at old
//!     old.next      = new_leaf;       // old points forward at new
//! This is where a doubly-linked list silently corrupts if a back-pointer is dropped:
//! the forward and backward pointers must stay *mutually consistent* (`a.next == b`
//! `iff` `b.prev == a`).  That consistency is the structural invariant verified here.
//!
//! We model a `LeafNode` carrying the *linked addresses* as `Option<PPtr<LeafNode>>`
//! (`PPtr` is `Copy`, so it sits in an `Option` field fine), and verify the linking
//! step through **two `PointsTo` permissions held at once** (node `a`'s and node `b`'s).
//!
//! WHAT IS VERIFIED (machine-checked, no `assume`/`admit`):
//!   * `link_pair` — splice b in after a (`a.next = Some(b_ptr); b.prev = Some(a_ptr)`),
//!     holding both permissions, establishes **back-pointer consistency**:
//!         final(a).next == Some(b_ptr)  AND  final(b).prev == Some(a_ptr)
//!     plus the **round-trip**: `a.next.unwrap()` is `b`'s own `pptr()` (so following
//!     a's forward link lands exactly on the permission that governs `b`), and the
//!     reachability witness that `b` stays sound/initialised through its permission.
//!   * `splice_after` — the full three-write telix splice on a *fresh* sibling
//!     (`new.next = old.next; new.prev = old_ptr; old.next = new_ptr`) over three nodes
//!     (old, new, succ): proves the new node is consistently double-linked between old
//!     and its inherited successor, and old's forward link now lands on new.
//!   * `linked_consistent` — the relational invariant itself, as a spec predicate,
//!     shown to hold of the post-link state.
//!
//! DEFERRED: an *unbounded* chain-wide doubly-linked invariant (every node's back-pointer
//! agrees along an arbitrary-length list) is not attempted here — it needs a heap/ghost-map
//! model of all permissions at once; the sibling-splice slice above is the bounded core
//! that telix's split actually executes.  The forward-only ordered chain is covered by
//! `extent_chain.rs`.
//!
//! STATUS: ✅ VERIFIED against Verus 0.2026.06.20 (`verify.sh`). See `CORRESPONDENCE.md`.

use vstd::prelude::*;
use vstd::simple_pptr::*;

verus! {

/// A doubly-linked leaf node.  We model only the chain structure (the `next`/`prev`
/// sibling links that telix's split splices); the entry payload lives in the sibling
/// modules (`extent_split.rs`, `extent_chain.rs`).  `PPtr` is `Copy`, so the linked
/// addresses sit directly in `Option` fields.
pub struct LeafNode {
    pub next: Option<PPtr<LeafNode>>,
    pub prev: Option<PPtr<LeafNode>>,
}

/// **The doubly-linked consistency relation** between an ordered pair of permissions
/// `(pa, pb)`: `a`'s forward link points at `b`'s address and `b`'s back link points at
/// `a`'s address — i.e. `a.next == b` *iff* (here, *and*) `b.prev == a`, with the links
/// resolving to the very `pptr()` each permission governs.  This is the structural
/// invariant a doubly-linked list must maintain at every adjacency.
pub open spec fn linked_consistent(pa: PointsTo<LeafNode>, pb: PointsTo<LeafNode>) -> bool {
    &&& pa.is_init()
    &&& pb.is_init()
    &&& pa.value().next == Some(pb.pptr())
    &&& pb.value().prev == Some(pa.pptr())
}

/// **Splice `b` in directly after `a`** — the two mutually-pointing writes at the heart of
/// telix's sibling link (`old.next = new` together with `new.prev = old`), performed while
/// holding **both** `PointsTo` permissions.  Proves the forward and backward links end up
/// mutually consistent and round-trip to each other's address.
pub fn link_pair(
    a_ptr: PPtr<LeafNode>,
    Tracked(a_perm): Tracked<&mut PointsTo<LeafNode>>,
    b_ptr: PPtr<LeafNode>,
    Tracked(b_perm): Tracked<&mut PointsTo<LeafNode>>,
)
    requires
        old(a_perm).pptr() == a_ptr,
        old(a_perm).is_init(),
        old(b_perm).pptr() == b_ptr,
        old(b_perm).is_init(),
    ensures
        // permissions still govern the same addresses, still initialised
        final(a_perm).pptr() == a_ptr,
        final(a_perm).is_init(),
        final(b_perm).pptr() == b_ptr,
        final(b_perm).is_init(),
        // back-pointer consistency: the forward link and back link agree
        final(a_perm).value().next == Some(b_ptr),
        final(b_perm).value().prev == Some(a_ptr),
        // round-trip: following a's forward link lands on the *permission* governing b
        final(a_perm).value().next == Some(final(b_perm).pptr()),
        final(b_perm).value().prev == Some(final(a_perm).pptr()),
        // the relational invariant itself holds of the result
        linked_consistent(*final(a_perm), *final(b_perm)),
{
    // a.next = Some(b_ptr)  (telix: old.next = new_leaf)
    let mut a = a_ptr.take(Tracked(a_perm));
    a.next = Some(b_ptr);
    a_ptr.put(Tracked(a_perm), a);

    // b.prev = Some(a_ptr)  (telix: new_leaf.prev = leaf_ptr)
    let mut b = b_ptr.take(Tracked(b_perm));
    b.prev = Some(a_ptr);
    b_ptr.put(Tracked(b_perm), b);
}

/// **The full three-write sibling splice on a fresh node**, exactly as telix does it:
///     new.next = old.next;   // inherit old's successor (`succ`)
///     new.prev = old_ptr;    // new points back at old
///     old.next = new_ptr;    // old points forward at new
/// over three nodes — `old`, the freshly-allocated `new`, and old's prior successor
/// `succ`.  Verifies the new node is consistently double-linked *between* old and succ:
/// old↔new are mutually consistent, and new's inherited forward link is precisely succ.
pub fn splice_after(
    old_ptr: PPtr<LeafNode>,
    Tracked(old_perm): Tracked<&mut PointsTo<LeafNode>>,
    new_ptr: PPtr<LeafNode>,
    Tracked(new_perm): Tracked<&mut PointsTo<LeafNode>>,
    succ_ptr: PPtr<LeafNode>,
)
    requires
        old(old_perm).pptr() == old_ptr,
        old(old_perm).is_init(),
        // old currently points forward at succ (the link new will inherit)
        old(old_perm).value().next == Some(succ_ptr),
        old(new_perm).pptr() == new_ptr,
        old(new_perm).is_init(),
    ensures
        final(old_perm).pptr() == old_ptr,
        final(old_perm).is_init(),
        final(new_perm).pptr() == new_ptr,
        final(new_perm).is_init(),
        // old now points forward at new ...
        final(old_perm).value().next == Some(new_ptr),
        // ... and old↔new are mutually consistent (back-pointer holds)
        final(new_perm).value().prev == Some(old_ptr),
        linked_consistent(*final(old_perm), *final(new_perm)),
        // new inherited old's old successor as its forward link
        final(new_perm).value().next == Some(succ_ptr),
{
    // read old's current successor before we overwrite the link
    let succ = {
        let old_leaf = old_ptr.take(Tracked(old_perm));
        let s = old_leaf.next;
        old_ptr.put(Tracked(old_perm), old_leaf);
        s
    };
    // succ == Some(succ_ptr) by the precondition

    // new.next = old.next (== Some(succ_ptr));  new.prev = old_ptr
    let mut new_leaf = new_ptr.take(Tracked(new_perm));
    new_leaf.next = succ;
    new_leaf.prev = Some(old_ptr);
    new_ptr.put(Tracked(new_perm), new_leaf);

    // old.next = new_ptr
    let mut old_leaf2 = old_ptr.take(Tracked(old_perm));
    old_leaf2.next = Some(new_ptr);
    old_ptr.put(Tracked(old_perm), old_leaf2);
}

/// **End-to-end demo**: allocate two leaves, link them, and observe the doubly-linked
/// invariant — the `alloc_node` → splice pattern of telix's split, machine-checked through
/// the permissions.
pub fn demo_link_two() {
    let (a_ptr, Tracked(mut a_perm)) = PPtr::new(LeafNode { next: None, prev: None });
    let (b_ptr, Tracked(mut b_perm)) = PPtr::new(LeafNode { next: None, prev: None });

    link_pair(a_ptr, Tracked(&mut a_perm), b_ptr, Tracked(&mut b_perm));

    // the linked invariant now holds; assert it to pin the post-state down.
    assert(a_perm.value().next == Some(b_ptr));
    assert(b_perm.value().prev == Some(a_ptr));
    assert(linked_consistent(a_perm, b_perm));

    let _a = a_ptr.into_inner(Tracked(a_perm));
    let _b = b_ptr.into_inner(Tracked(b_perm));
}

} // verus!
