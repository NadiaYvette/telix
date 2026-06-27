//! SEED — the POINTER recursive tree (stage 3e: the deepest rung).
//!
//! `extent_tree.rs` proved the recursive search tree as a *datatype* (the shape invariant,
//! unbounded depth).  Stages 3a/3b proved *pointer* operations for one node (`leaf_insert_
//! through_ptr`) and two nodes (`split_leaf`).  This module fuses them: an **arbitrary-depth
//! tree of nodes behind raw pointers**, where the permission to dereference the whole tree is a
//! **recursive collection** — each node's `PointsTo` plus, recursively, the permission trees of
//! its children.  This is what telix's real `mm/extent.rs` is (nodes are `*mut`, children are
//! pointers), and the rung Lean/Kani cannot reach (they don't model the heap) and stages 3a/3b
//! only reached for a bounded number of nodes.
//!
//! `TreePerm` is the recursive permission: holding it makes every `unsafe { &*ptr }` down the
//! whole tree sound and checked.  `wf` ties it to a root pointer; `keys`/`bst` are the abstract
//! content and ordering (the pointer analogue of `extent_tree.rs`'s `to_seq`/`bst`).
//!
//! STATUS: foundation (types + recursive specs); see `verify.sh`.

use vstd::prelude::*;
use vstd::simple_pptr::*;

verus! {

/// A heap node of the pointer search tree: a key and raw-pointer children (telix's `*mut`).
pub struct Node {
    pub key: u64,
    pub left: Option<PPtr<Node>>,
    pub right: Option<PPtr<Node>>,
}

/// **The recursive permission collection.**  `points_to` is the permission to dereference THIS
/// node's pointer; `left`/`right` are, recursively, the permission trees for the child pointers.
/// Holding a `TreePerm` that is `wf(root)` is the right to safely walk the entire tree under
/// `root` — the unbounded generalization of stage 3a's single `PointsTo<LeafNode>`.
pub tracked struct TreePerm {
    pub points_to: PointsTo<Node>,
    pub left: Option<Box<TreePerm>>,
    pub right: Option<Box<TreePerm>>,
}

impl TreePerm {
    /// The permission tree is well-formed for `root`: it is the permission for `root`, the node is
    /// initialized, and the child permission trees match the node's child pointers exactly
    /// (present iff the pointer is present, and wf for it).
    pub open spec fn wf(self, root: PPtr<Node>) -> bool
        decreases self,
    {
        &&& self.points_to.pptr() == root
        &&& self.points_to.is_init()
        &&& {
            let node = self.points_to.value();
            &&& match (node.left, self.left) {
                (Some(lp), Some(lperm)) => lperm.wf(lp),
                (None, None) => true,
                _ => false,
            }
            &&& match (node.right, self.right) {
                (Some(rp), Some(rperm)) => rperm.wf(rp),
                (None, None) => true,
                _ => false,
            }
        }
    }

    /// The abstract key set of the whole tree (recursive over the permission collection).
    pub open spec fn keys(self) -> Set<u64>
        decreases self,
    {
        let node = self.points_to.value();
        let lk = match self.left {
            Some(l) => l.keys(),
            None => Set::empty(),
        };
        let rk = match self.right {
            Some(r) => r.keys(),
            None => Set::empty(),
        };
        lk.union(rk).insert(node.key)
    }

    /// The binary-search-tree ordering invariant, recursive over the permission collection:
    /// every key in the left subtree is `< node.key`, every key in the right subtree is `>`.
    pub open spec fn bst(self) -> bool
        decreases self,
    {
        let node = self.points_to.value();
        &&& match self.left {
            Some(l) => l.bst() && (forall|k: u64| l.keys().contains(k) ==> k < node.key),
            None => true,
        }
        &&& match self.right {
            Some(r) => r.bst() && (forall|k: u64| r.keys().contains(k) ==> node.key < k),
            None => true,
        }
    }
}

/// Foundation sanity: the root's own key is always in the tree's key set, at any depth.
pub proof fn keys_contains_root(perm: TreePerm)
    ensures
        perm.keys().contains(perm.points_to.value().key),
{
}

/// **The recursive pointer traversal, verified.**  Walk the arbitrary-depth tree from `root`
/// through the raw-pointer children, dereferencing each node soundly via its slice of the
/// recursive permission collection, and decide membership — proven to agree exactly with the
/// abstract key set (`res == keys().contains(key)`), using the BST ordering to skip the subtree
/// that cannot hold `key`.  This is what stages 3a/3b could only do for one/two nodes: a sound,
/// checked walk over an UNBOUNDED tree of `*mut` nodes.
pub fn contains(root: PPtr<Node>, Tracked(perm): Tracked<&TreePerm>, key: u64) -> (res: bool)
    requires
        perm.wf(root),
        perm.bst(),
    ensures
        res == perm.keys().contains(key),
    decreases perm,
{
    let node: &Node = root.borrow(Tracked(&perm.points_to));
    if key == node.key {
        proof { keys_contains_root(*perm); }
        true
    } else if key < node.key {
        match node.left {
            Some(lp) => {
                let tracked lperm = perm.left.tracked_borrow();
                let res = contains(lp, Tracked(lperm), key);
                proof {
                    match &perm.right {
                        Some(r) => assert(!r.keys().contains(key)),
                        None => {},
                    }
                }
                res
            }
            None => {
                proof {
                    match &perm.right {
                        Some(r) => assert(!r.keys().contains(key)),
                        None => {},
                    }
                }
                false
            }
        }
    } else {
        match node.right {
            Some(rp) => {
                let tracked rperm = perm.right.tracked_borrow();
                let res = contains(rp, Tracked(rperm), key);
                proof {
                    match &perm.left {
                        Some(l) => assert(!l.keys().contains(key)),
                        None => {},
                    }
                }
                res
            }
            None => {
                proof {
                    match &perm.left {
                        Some(l) => assert(!l.keys().contains(key)),
                        None => {},
                    }
                }
                false
            }
        }
    }
}

/// **The summit: recursive INSERT through the pointers.**  Walk to the correct leaf position,
/// allocate a fresh node, and rewire the parent's child pointer — reconstructing the recursive
/// permission collection on the way back up — proven to preserve `wf` and `bst` and to add
/// exactly `key` to the abstract key set (`keys() == old.keys().insert(key)`).  This is the
/// `insert`/`split_leaf_and_insert` heap mutation over the unbounded `PointsTo` tree: what
/// `extent_tree.rs` did for the datatype, now through raw pointers.
pub fn insert(root: PPtr<Node>, Tracked(perm): Tracked<TreePerm>, key: u64) -> (res: Tracked<TreePerm>)
    requires
        perm.wf(root),
        perm.bst(),
    ensures
        res@.wf(root),
        res@.bst(),
        res@.keys() == perm.keys().insert(key),
    decreases perm,
{
    let tracked TreePerm { points_to: mut pt, left, right } = perm;
    let (k, nl, nr) = {
        let node = root.borrow(Tracked(&pt));
        (node.key, node.left, node.right)
    };
    if key == k {
        let tracked res = TreePerm { points_to: pt, left, right };
        proof {
            keys_contains_root(res);
            assert(res.wf(root));
            assert(res.bst());
            assert(res.keys() =~= perm.keys().insert(key));
        }
        Tracked(res)
    } else if key < k {
        match nl {
            Some(lp) => {
                let tracked lperm = left.tracked_unwrap();
                let Tracked(new_lperm) = insert(lp, Tracked(*lperm), key);
                let tracked res = TreePerm { points_to: pt, left: Some(Box::new(new_lperm)), right };
                proof {
                    assert(forall|kk: u64| new_lperm.keys().contains(kk) ==> kk < k);
                    assert(res.wf(root));
                    assert(res.bst());
                    assert(res.keys() =~= perm.keys().insert(key));
                }
                Tracked(res)
            }
            None => {
                let (leaf_ptr, Tracked(leaf_perm)) = PPtr::<Node>::new(Node { key, left: None, right: None });
                let mut n = root.take(Tracked(&mut pt));
                n.left = Some(leaf_ptr);
                root.put(Tracked(&mut pt), n);
                let tracked leaf = TreePerm { points_to: leaf_perm, left: None, right: None };
                let tracked res = TreePerm { points_to: pt, left: Some(Box::new(leaf)), right };
                proof {
                    assert(perm.left is None);
                    assert(pt.value().key == k);
                    assert(pt.value().left == Some(leaf_ptr));
                    assert(pt.value().right == perm.points_to.value().right);
                    assert(leaf.keys() =~= Set::<u64>::empty().insert(key));
                    assert(leaf.wf(leaf_ptr));
                    assert(leaf.bst());
                    assert(forall|kk: u64| leaf.keys().contains(kk) ==> kk < k);
                    assert(res.wf(root));
                    assert(res.bst());
                    assert(res.keys() =~= perm.keys().insert(key));
                }
                Tracked(res)
            }
        }
    } else {
        match nr {
            Some(rp) => {
                let tracked rperm = right.tracked_unwrap();
                let Tracked(new_rperm) = insert(rp, Tracked(*rperm), key);
                let tracked res = TreePerm { points_to: pt, left, right: Some(Box::new(new_rperm)) };
                proof {
                    assert(forall|kk: u64| new_rperm.keys().contains(kk) ==> k < kk);
                    assert(res.wf(root));
                    assert(res.bst());
                    assert(res.keys() =~= perm.keys().insert(key));
                }
                Tracked(res)
            }
            None => {
                let (leaf_ptr, Tracked(leaf_perm)) = PPtr::<Node>::new(Node { key, left: None, right: None });
                let mut n = root.take(Tracked(&mut pt));
                n.right = Some(leaf_ptr);
                root.put(Tracked(&mut pt), n);
                let tracked leaf = TreePerm { points_to: leaf_perm, left: None, right: None };
                let tracked res = TreePerm { points_to: pt, left, right: Some(Box::new(leaf)) };
                proof {
                    assert(perm.right is None);
                    assert(pt.value().key == k);
                    assert(pt.value().left == perm.points_to.value().left);
                    assert(pt.value().right == Some(leaf_ptr));
                    assert(leaf.keys() =~= Set::<u64>::empty().insert(key));
                    assert(leaf.wf(leaf_ptr));
                    assert(leaf.bst());
                    assert(forall|kk: u64| leaf.keys().contains(kk) ==> k < kk);
                    assert(res.wf(root));
                    assert(res.bst());
                    assert(res.keys() =~= perm.keys().insert(key));
                }
                Tracked(res)
            }
        }
    }
}

} // verus!
