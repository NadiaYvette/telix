# Verus ⟷ Kani ⟷ Lean correspondence

Every Verus obligation in `extent_coalesce.rs` is justified by an *independent* proof in
the tessera repo. This is what makes the in-tree Verus spec trustworthy rather than
merely plausible: it is the third of three checks, by three different tools, of the same
property.

tessera: `NadiaYvette/tessera` (public — github / sourcehut / disroot / framagit).

## Stage 1 — `ExtentEntry::can_coalesce`, `end`, `ExtentFlags`

| Verus clause (`extent_coalesce.rs`) | Kani harness (`rust/extent-kani/coalesce.rs`) | Lean theorem (`proof/Tessera/`) |
|---|---|---|
| `can_coalesce` ⟹ `self.end() == other.start` (physical adjacency) | `coalesce_is_sound`: `assert(a.end() == b.start)` | `Frames.grantsF` contiguity / `Basic.Disjoint` adjacency (the `hi == lo` boundary) |
| `can_coalesce` ⟹ `object_id == other.object_id ∧ object_id != 0` (same non-anon object) | `coalesce_is_sound`: `assert(a.object_id == b.object_id ∧ a.object_id != 0)` | `Sharing`/`Cow` backing-object identity (same `Backing` ⇒ coalescible) |
| `can_coalesce` ⟹ `object_offset + page_count == other.object_offset` (offset-contiguous) | `coalesce_is_sound`: the offset assertion | `Frames.grantsF`: the linear `frame + (v − base)` translation across a merge |
| `can_coalesce` ⟹ `flags == other.flags ∧ refcount == other.refcount` (identical state) | `coalesce_is_sound`: the flags/refcount asserts | `Kau.dirty`/inv5 + the refcount discipline (merge preserves the per-extent state) |
| `end` overflow-free (the `requires` bound) | Kani's automatic arithmetic-overflow checks (0 failures) | — (arithmetic; below the Lean granule-unit abstraction) |
| `union` ⟹ `contains(a) ∧ contains(b)` (flag join is an upper bound) | `union_contains_both_operands` | — (bit-level; `bit_vector` in Verus) |

## Stage 2 — leaf-array operations (`extent_leaf.rs`)

| Verus obligation | Kani harness | Lean theorem |
|---|---|---|
| `insert_preserves_sorted`: inserting at the sorted position keeps the leaf sorted | `rust/extent-kani/lib.rs` `insert_preserves_order` (bounded array insert) | `proof/Tessera/ExtentMap.lean` `insert_ordered` (the abstract theorem) |
| `remove_preserves_sorted`: removal keeps the leaf sorted (subsequence of a sorted seq) | — | `ExtentMap`/`Basic` `Pairwise` sublist closure |
| `insert_entry_at` / `remove_entry_at` functional spec (`Seq::insert`/`Seq::remove`) + count | the harness's array-shift semantics | `ExtentMap.insert_mem` (insert adds exactly the element) |

telix's manual shift-right/shift-left over the fixed `[ExtentEntry; LEAF_CAP]` + count
computes exactly `Seq::insert`/`Seq::remove` on the live content; the Verus spec is stated
at that logical level, and the telix side proves its array code meets it.

## Stage 3a — node-through-pointer (`extent_node.rs`)

This is the rung where **Verus does something Lean and Kani cannot**: reason about the
*raw-pointer heap*. The Lean and Kani layers proved the algorithm on pure data; telix's
nodes live behind `*mut` pointers, and the soundness of dereferencing them is the whole
difficulty (it is why Aeneas couldn't model the code).

| Verus obligation | Justified by |
|---|---|
| `leaf_insert_through_ptr`: a leaf insert performed through a `PointsTo<LeafNode>` permission preserves sortedness | the leaf invariant comes from stage 2 (`insert_preserves_sorted`); the *pointer soundness* is Verus-native — no Lean/Kani analogue, because they don't model the heap |
| `demo_alloc_insert_free`: allocate → operate-through-permission → reclaim verifies | the `alloc_node`/`as_leaf`+mutate/`free_node` lifecycle, with the allocation as a `PointsTo` resource |

So the division of labour across the three tools is now sharp: **Lean** = the algorithm is
right; **Kani** = the verbatim code meets it (bounded); **Verus** = it meets it *unbounded
and through the raw pointers*, in mainline, in CI. Stage 3 is Verus's home turf.

## Stage 3b — leaf split, two permissions (`extent_split.rs`)

The multi-node rung: telix's `split_leaf_and_insert` keeps the lower half of a full
leaf's entries and moves the upper half to a freshly-allocated sibling.

| Verus obligation | Justified by |
|---|---|
| `split_sorted`: a sorted sequence splits into two sorted halves, concatenating to the original, with `s[mid-1] <= s[mid]` the separator | pure sequence reasoning; the abstract cousin is Lean `WF_split_at` (split preserves well-formedness / the partition) |
| `split_leaf`: the split **loses and duplicates no entries** (`old' ++ new' == combined`), each half sorted, separator valid — performed across **two `PointsTo` permissions** (the old node and the new sibling) at once | content-preservation is the anti-loss property the catalogue's split/fold family (telix #9, pgcl #7/#8) is about; the two-permission heap reasoning is Verus-native |

Verus caught a real **spec** bug here: with a 1-entry combined sequence `mid = 0` and the
lower half is empty, so the separator and non-emptiness fail — the precondition must be
`>= 2` entries (telix only splits a *full* leaf). A good example of the specs being
exercised, not rubber-stamped.

## Stage 3c — the whole-tree structural invariant (`extent_chain.rs`)

The summit: the B+-tree's entire content is the concatenation of its leaves in chain
order, and the whole-tree correctness property is that this is *one globally sorted map*.

| Verus obligation | Justified by |
|---|---|
| `concat_sorted`: two sorted segments with an ordered boundary concatenate to a sorted run | the two-leaf case; building block |
| `chain_flatten_sorted`: a well-formed leaf chain (each leaf sorted, adjacent leaves separated) flattens to a globally sorted extent map | the multi-node analogue of Lean `BTree.bst_ordered` (in-order traversal of a search tree is sorted) and `ExtentMap.Ordered` — it closes the loop back to the ordered-map abstraction that **stage 1's** `ExtentMap.WFI_imp_WF` refines to Layer A |

So the in-tree Verus development now spans the whole structure: `can_coalesce` (1) →
leaf ops (2) → a node through a pointer (3a) → a two-node split (3b) → the whole-leaf-chain
ordered-map invariant (3c) — and `chain_flatten_sorted` reconnects it to the very Layer-A
ordering invariant the Lean development proves abstractly. The tower closes on itself.

## PTE ⟷ rmap relation invariant (`rmap.rs`)

A different subsystem from the extent B+-tree, but the bug-densest one: the reverse-mapping
consistency. `wf`: a page's cached `mapcount` equals the size of its true reverse map.

| Verus obligation | Justified by |
|---|---|
| `map_preserves_wf` / `unmap_preserves_wf`: correct map/unmap keep `mapcount == |rmap|` | Lean `Sharing.add_wf`/`remove_wf` (the `Backing` mapcount discipline) |
| `free_iff_unmapped`: `mapcount == 0 ⟺ no mappers` (reclaim-on-zero is sound) | Lean `Sharing.free_iff_unmapped` |
| `under_remove_breaks_wf`: removing a mapper without dropping the count is a provable error | the catalogue's **rank-2 cluster** — pgcl #1/#143 (rmap under-remove → mapcount underflow → freed-while-mapped folio → page-cache corruption), telix #2 |

This is the Verus / in-tree form of the Lean `Sharing.Backing` discipline, framed on a `Set`
so no-double-map is intrinsic. It is exactly the property a CBMC check on Linux's
`mm/rmap.c` would target.

## Cross-mm aggregate-refcount invariant (`rmap_cluster.rs`) — pgcl #143 gate

One level up from `rmap.rs`: a PGCL **cluster** (folio) shared across **several mms** (the fork
parent+children of pgcl's live -smp8 reproducer), carrying a single per-cluster aggregate
refcount. This is the home of #143's *free-while-mapped*. The sequential (∀-state) complement of
the concurrent (∀-interleaving) Iris proof `tessera/property2/coq/rmap_defer.v`.

| Verus obligation (`rmap_cluster.rs`) | Justified by |
|---|---|
| `free_iff_unmapped`: `refcount == 0 ⟺ !folio_mapped()` — the aggregate over all mms | the sequential statement the runtime `dec_and_test`-on-`folio_mapped()` gate enforces; the Iris `rmap_defer_spec` is the ∀-interleaving form |
| `mapped_implies_refcount_pos`: a sibling mm's live sub-PTE keeps `refcount > 0` | the cross-mm gate #143 violated; the Coq `no_free_while_referenced` (a reference blocks the free) at folio granularity |
| `two_sharers_refcount_ge2`: two distinct sharing mms ⟹ `refcount ≥ 2` ⟹ a single deferred put cannot reach 0 | the fork-share safety margin; why a *correct* aggregate refcount cannot be raced to free by one put |
| `freed_while_mapped_breaks_wf`: `folio_mapped ∧ refcount == 0 ⟹ ¬wf` | the #143 bad state as an invariant violation — the cross-mm lift of `rmap.rs` `under_remove_breaks_wf` |

So the #143 fix obligation is now machine-checked from both sides: the **gate is sound in every
state** (`rmap_cluster.rs`, Verus) and **under every thread interleaving** (`rmap_defer.v`, Iris),
and `freed_while_mapped_breaks_wf` certifies the bug state is genuinely impossible under `wf`.

## Stage 3d — the recursive (unbounded-depth) tree (`extent_tree.rs`)

The last structural rung: an *arbitrary-depth* search tree, not a flat chain.

| Verus obligation | Justified by |
|---|---|
| `bst_sorted`: a search tree's in-order traversal is one globally sorted extent map, by structural induction over a recursive datatype | the direct Verus port of Lean `proof/Tessera/BTree.lean` `bst_ordered` — same theorem, same induction, now unbounded and in-tree; the recursive generalization of `extent_chain.rs` |
| `insert_preserves_bst`: recursive insert preserves the whole-tree ordering; `insert_contains`: it loses no entry and adds exactly the new one | the recursive tree-growth operation; the anti-entry-loss property (telix #9 / pgcl #7/#8 split-fold family) at unbounded depth — Lean `Refinement`/`Tiling` cousins |

This is the cleanest cross-prover correspondence in the whole effort: the *same recursive
search-tree invariant* is proved in Lean (`BTree.bst_ordered`, axiom-clean) and Verus
(`bst_sorted`) — the abstract and the in-tree proof of one structural fact, over
unbounded depth. (Modeled as a datatype: the *shape* invariant, decoupled from the
pointer representation that stages 3a/3b verified for one/two nodes.)

## Stage 3e — the pointer recursive tree (`extent_ptr_tree.rs`)

The deepest rung, and the one furthest from what Lean/Kani can express: an arbitrary-depth tree
of nodes **behind raw pointers**, where the permission to walk the whole tree is itself a
**recursive collection** — `TreePerm` holds a node's `PointsTo<Node>` plus, recursively, the
`TreePerm`s for its children. This is the real shape of telix's `mm/extent.rs`.

| Verus obligation | Justified by |
|---|---|
| `TreePerm::{wf, keys, bst}`: the recursive permission collection and its abstract content/ordering, by structural recursion over the `Box`-linked permission tree | the pointer realization of Lean `BTree.lean` / `extent_tree.rs`'s `bst`/`to_seq` — the *shape* invariant, now carried by the heap permissions rather than a datatype |
| `contains`: a recursive walk over the unbounded `*mut` tree, each deref sound via its slice of the permission collection, agreeing with `keys()` (BST-pruned) | the unbounded generalization of stage 3a's single-node `leaf_insert_through_ptr`; Lean/Kani cannot state it (no heap model) |
| `insert`: recursive insert — allocate a node, rewire the parent's child pointer (`take`/`put`), reconstruct the permission tree up the spine — preserving `wf`/`bst`, `keys() == old.insert(key)` | the heap-pointer form of `extent_tree.rs` `insert_preserves_bst`/`insert_contains`; the multi-permission split reasoning of stage 3b (`split_leaf`) now propagated recursively |

This closes the tower: stage 1 (pure logic) → 2 (leaf arrays) → 3a/3b (one/two nodes through
pointers) → 3c/3d (whole structure, datatype) → **3e (whole structure, through pointers,
unbounded, with mutation)**. The `bst`/ordered-map invariant the Lean development proves
abstractly is now also proved on the actual heap-pointer representation telix runs.

## The unbounded doubly-linked chain (`extent_ptr_list.rs`)

`extent_link.rs` proved back-pointer consistency for ONE adjacency (the bounded sibling splice)
and deferred the chain-wide version. `extent_ptr_list.rs` closes it with the same recursive-
permission technique as the pointer tree, specialized to a list: own the chain *forward*
(`ListPerm` = a node's `PointsTo` + the tail's `ListPerm`), and validate each node's `prev`
field against its structural predecessor (threaded as a parameter) rather than owning it — which
sidesteps the doubly-linked aliasing.

| Verus obligation | Justified by |
|---|---|
| `ListPerm::wf(head, prev)`: the chain-wide doubly-linked invariant — each node initialized, `prev` equals its predecessor, tail wf for `next` with this node as predecessor | the unbounded generalization of `extent_link.rs` `linked_consistent` (one adjacency → all adjacencies); the recursive-permission analogue used for `extent_ptr_tree.rs` |
| `back_pointer_holds`: from the global `wf`, every successor's `prev` points back — `a.next.prev == a` | the corruption `extent_link.rs` guards one node at a time, here a theorem about the whole unbounded chain |
| `last_ptr`: a recursive walk over the unbounded `*mut` chain (sound per-node via the permission slice), returning `to_seq().last()` | the list analogue of the tree's `contains`; Lean/Kani cannot state it (no heap) |
| `push_front`: prepend, re-establishing `wf` across the old-head back-pointer write, prepending exactly the new node to `to_seq()` | the maintenance operation; the back-pointer write is exactly telix's splice write that silently desynchronizes a doubly-linked list if dropped |

## Why three tools

- **Lean** proves the property *abstractly*, for all inputs, over the idealized model —
  it tells us the spec is the **right** one (it's the invariant the whole refinement
  tower preserves).
- **Kani** proves it on the **verbatim telix code**, bounded — it tells us the spec
  **holds of the actual function** (including real integer overflow).
- **Verus** proves it on the code **in mainline, unbounded, in CI** — it tells us the
  spec **keeps holding as telix evolves.**

Lean says *what* correct is; Kani confirms *this code* meets it now; Verus keeps it met.

## Provenance of each property

The properties trace to the failure catalogue (`tessera/doc/failure-modes-telix.md`):
coalescing the wrong extents (mismatched object, stale offset, non-adjacent, anonymous)
is the telix #14 / overlap-and-merge family. `can_coalesce`'s six conjuncts are exactly
the guards the catalogue says must hold — now machine-checked at the source.
