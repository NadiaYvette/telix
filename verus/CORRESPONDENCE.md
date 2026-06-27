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
